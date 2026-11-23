package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strings"

	sdkerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alb"
)

// albListenerPageSize is the page size of ListListeners (the API takes up
// to 100).
const albListenerPageSize = 100

// errNoALBEndpoint marks a region whose ALB endpoint has no DNS name: ALB
// is not offered there, so the region holds no load balancer.
var errNoALBEndpoint = errors.New("ALB is not available in this region")

// albRef is a load balancer as ListLoadBalancers lists it.
type albRef struct {
	ID   string
	Name string
}

// albListener is a listener as ListListeners lists it (without its
// certificates: the list does not carry them).
type albListener struct {
	ID             string
	LoadBalancerID string
	Protocol       string
	Port           int
	Status         string
}

// albClient is the ALB client of a region; requests go to the region's
// endpoint (ALB APIs take no RegionId: the endpoint decides the region).
type albClient struct {
	c      *client
	region string
	cl     *alb.Client
}

func (c *client) albClient(ctx context.Context, region string) (*albClient, error) {
	cl, err := alb.NewClientWithOptions(region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return &albClient{c: c, region: region, cl: cl}, nil
}

func (a *albClient) route(r requests.AcsRequest) { a.c.route(r, albEndpoint(a.region)) }

// listLoadBalancers lists every load balancer of the region, page by page
// (NextToken empty or repeated ends the list).
func (a *albClient) listLoadBalancers(ctx context.Context) ([]albRef, error) {
	var out []albRef
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListLoadBalancersRequest()
		a.route(req)
		req.MaxResults = requests.NewInteger(albPageSize)
		req.NextToken = token
		resp, err := a.cl.ListLoadBalancers(req)
		if err != nil {
			if isNoSuchHost(err) {
				return nil, fmt.Errorf("alb ListLoadBalancers %s: %w: %v", a.region, errNoALBEndpoint, err)
			}
			return nil, wrapErr("alb ListLoadBalancers "+a.region, err)
		}
		for _, lb := range resp.LoadBalancers {
			out = append(out, albRef{ID: lb.LoadBalancerId, Name: lb.LoadBalancerName})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.LoadBalancers) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// listListeners lists the listeners of a load balancer, page by page.
func (a *albClient) listListeners(ctx context.Context, lbID string) ([]albListener, error) {
	var out []albListener
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alb.CreateListListenersRequest()
		a.route(req)
		req.LoadBalancerIds = &[]string{lbID}
		req.MaxResults = requests.NewInteger(albListenerPageSize)
		req.NextToken = token
		resp, err := a.cl.ListListeners(req)
		if err != nil {
			return nil, wrapErr("alb ListListeners "+lbID, err)
		}
		for _, l := range resp.Listeners {
			if l.LoadBalancerId != "" && l.LoadBalancerId != lbID {
				continue
			}
			out = append(out, albListener{ID: l.ListenerId, LoadBalancerID: lbID, Protocol: l.ListenerProtocol, Port: l.ListenerPort, Status: l.ListenerStatus})
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.Listeners) == 0 {
			break
		}
		token = resp.NextToken
	}
	return out, nil
}

// listenerCertificates reads the certificate ids of a listener: its server
// certificates and its CA certificates, as the API writes them (a CAS id,
// with or without a region suffix).
func (a *albClient) listenerCertificates(ctx context.Context, listenerID string) ([]string, error) {
	req := alb.CreateGetListenerAttributeRequest()
	a.route(req)
	req.ListenerId = listenerID
	resp, err := a.cl.GetListenerAttribute(req)
	if err != nil {
		return nil, wrapErr("alb GetListenerAttribute "+listenerID, err)
	}
	var ids []string
	for _, group := range [][]alb.Certificate{resp.Certificates, resp.CaCertificates} {
		for _, c := range group {
			ids = appendNew(ids, strings.TrimSpace(c.CertificateId))
		}
	}
	return ids, nil
}

// carriesCertificates reports whether listeners of the protocol hold
// certificates (HTTPS and QUIC do; HTTP does not).
func carriesCertificates(protocol string) bool {
	switch strings.ToUpper(protocol) {
	case "HTTPS", "QUIC":
		return true
	}
	return false
}

// isNoSuchHost reports a request whose endpoint has no DNS name: the
// product does not exist in that region.
func isNoSuchHost(err error) bool {
	for e := err; e != nil; {
		var dns *net.DNSError
		if errors.As(e, &dns) && dns.IsNotFound {
			return true
		}
		var ce *sdkerrors.ClientError
		if !errors.As(e, &ce) {
			break
		}
		e = ce.OriginError()
	}
	return err != nil && strings.Contains(err.Error(), "no such host")
}
