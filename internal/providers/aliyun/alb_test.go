package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/url"
	"slices"
	"testing"

	sdkerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
)

// albFake answers the ALB read actions from a fixed set of load balancers,
// listeners and listener certificates, two items per page.
type albFake struct {
	lbs       map[string][]map[string]any // region -> load balancers
	listeners map[string][]map[string]any // load balancer id -> listeners
	certs     map[string][]string         // listener id -> certificate ids
	caCerts   map[string][]string         // listener id -> CA certificate ids
	extra     map[string][]string         // listener id -> additional server certificate ids
	fail      map[string]string           // region -> error code of ListLoadBalancers
}

func (f *albFake) install(api *fakeAPI) {
	api.on("ListLoadBalancers", func(q url.Values) (int, any) {
		region := q.Get("RegionId")
		if code := f.fail[region]; code != "" {
			status := 400
			if code == "Forbidden.LoadBalancer" {
				status = 403
			}
			return status, apiErr(code, "refused")
		}
		list := f.lbs[region]
		s, e, next := tokenPage(q, len(list), 2)
		return 200, map[string]any{"NextToken": next, "LoadBalancers": list[s:e]}
	})
	api.on("ListListeners", func(q url.Values) (int, any) {
		list := f.listeners[q.Get("LoadBalancerIds.1")]
		s, e, next := tokenPage(q, len(list), 2)
		return 200, map[string]any{"NextToken": next, "Listeners": list[s:e]}
	})
	api.on("GetListenerAttribute", func(q url.Values) (int, any) {
		id := q.Get("ListenerId")
		var certs, ca []map[string]any
		for _, c := range f.certs[id] {
			certs = append(certs, map[string]any{"CertificateId": c, "IsDefault": len(certs) == 0})
		}
		for _, c := range f.caCerts[id] {
			ca = append(ca, map[string]any{"CertificateId": c})
		}
		return 200, map[string]any{"ListenerId": id, "Certificates": certs, "CaCertificates": ca}
	})
	// ListListenerCertificates lists every server certificate of the
	// listener: the default one (the first of certs) and the additional ones.
	api.on("ListListenerCertificates", func(q url.Values) (int, any) {
		id := q.Get("ListenerId")
		var list []map[string]any
		if c := f.certs[id]; len(c) > 0 {
			list = append(list, map[string]any{"CertificateId": c[0], "IsDefault": true, "CertificateType": "Server", "Status": "Associated"})
		}
		for _, c := range f.extra[id] {
			list = append(list, map[string]any{"CertificateId": c, "IsDefault": false, "CertificateType": "Server", "Status": "Associated"})
		}
		s, e, next := tokenPage(q, len(list), 2)
		return 200, map[string]any{"NextToken": next, "Certificates": list[s:e]}
	})
}

// tokenPage pages a list with NextToken "p<start>".
func tokenPage(q url.Values, n, size int) (start, end int, next string) {
	if t := q.Get("NextToken"); t != "" {
		_, _ = fmt.Sscanf(t, "p%d", &start)
	}
	end = min(start+size, n)
	start = min(start, end)
	if end < n {
		next = fmt.Sprintf("p%d", end)
	}
	return start, end, next
}

func TestALBListersFollowPages(t *testing.T) {
	api := newFakeAPI(t)
	f := &albFake{
		lbs: map[string][]map[string]any{"cn-hongkong": {
			{"LoadBalancerId": "alb-1", "LoadBalancerName": "one"},
			{"LoadBalancerId": "alb-2", "LoadBalancerName": "two"},
			{"LoadBalancerId": "alb-3", "LoadBalancerName": "three"},
		}},
		listeners: map[string][]map[string]any{"alb-1": {
			{"ListenerId": "lsn-1", "LoadBalancerId": "alb-1", "ListenerProtocol": "HTTP", "ListenerPort": 80},
			{"ListenerId": "lsn-2", "LoadBalancerId": "alb-1", "ListenerProtocol": "HTTPS", "ListenerPort": 443},
			{"ListenerId": "lsn-3", "LoadBalancerId": "alb-1", "ListenerProtocol": "QUIC", "ListenerPort": 443},
		}},
		certs:   map[string][]string{"lsn-2": {"1234567-ap-southeast-1", "7654321"}},
		caCerts: map[string][]string{"lsn-2": {"555"}},
		extra:   map[string][]string{"lsn-2": {"888-ap-southeast-1", "999-ap-southeast-1"}},
	}
	f.install(api)
	ctx := context.Background()
	a, err := api.client().albClient(ctx, "cn-hongkong")
	if err != nil {
		t.Fatal(err)
	}
	lbs, err := a.listLoadBalancers(ctx)
	if err != nil || len(lbs) != 3 || lbs[2] != (albRef{ID: "alb-3", Name: "three"}) {
		t.Fatalf("load balancers = %+v, %v", lbs, err)
	}
	ls, err := a.listListeners(ctx, "alb-1")
	if err != nil || len(ls) != 3 || ls[1].ID != "lsn-2" || ls[1].Protocol != "HTTPS" || ls[1].Port != 443 {
		t.Fatalf("listeners = %+v, %v", ls, err)
	}
	if q := api.callsFor("ListListeners"); len(q) != 2 || q[0].Get("LoadBalancerIds.1") != "alb-1" || q[0].Get("MaxResults") != "100" {
		t.Errorf("ListListeners calls = %v", q)
	}
	certs, err := a.listenerCertificates(ctx, "lsn-2")
	if err != nil || !slices.Equal(certs, []string{"1234567-ap-southeast-1", "7654321", "555", "888-ap-southeast-1", "999-ap-southeast-1"}) {
		t.Errorf("certificates = %v, %v", certs, err)
	}
	if q := api.callsFor("ListListenerCertificates"); len(q) != 2 || q[0].Get("ListenerId") != "lsn-2" || q[0].Get("MaxResults") != "100" {
		t.Errorf("ListListenerCertificates calls = %v: every page of the additional certificates is read", q)
	}
	if !carriesCertificates("https") || !carriesCertificates("QUIC") || carriesCertificates("HTTP") {
		t.Error("carriesCertificates")
	}
}

func TestIsNoSuchHost(t *testing.T) {
	dns := &net.DNSError{Err: "no such host", Name: "alb.xx-nowhere-1.aliyuncs.com", IsNotFound: true}
	if !isNoSuchHost(dns) || !isNoSuchHost(fmt.Errorf("wrapped: %w", dns)) {
		t.Error("a DNS not-found error is a missing endpoint")
	}
	if !isNoSuchHost(sdkerrors.NewClientError("SDK.ServerUnreachable", "unreachable", dns)) {
		t.Error("the SDK's client error around it too")
	}
	if isNoSuchHost(errors.New("connection refused")) || isNoSuchHost(nil) {
		t.Error("other errors are not")
	}
}
