package aliyun

import (
	"context"
	"errors"
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
	ID      string
	Name    string
	Status  string
	VpcID   string
	DNSName string
}

// albListener is a listener as ListListeners lists it (without its
// certificates: the list does not carry them; GetListenerAttribute adds
// the default one).
type albListener struct {
	ID             string `json:"id" yaml:"id"`
	LoadBalancerID string `json:"load_balancer_id" yaml:"load_balancer_id"`
	Protocol       string `json:"protocol" yaml:"protocol"`
	Port           int    `json:"port" yaml:"port"`
	Status         string `json:"status" yaml:"status"`
	// DefaultAction is the type of the first default action (ForwardGroup).
	DefaultAction string `json:"default_action,omitempty" yaml:"default_action,omitempty"`
	// ServerGroups are the server groups the default actions forward to.
	ServerGroups []string `json:"server_groups" yaml:"server_groups"`
	// Certificates are the listener certificate ids, the default first
	// (read by GetListenerAttribute only).
	Certificates []string `json:"certificates,omitempty" yaml:"certificates,omitempty"`
	Region       string   `json:"region" yaml:"region"`
}

// albClient is the ALB client of a region; requests go to the region's
// endpoint (ALB APIs take no RegionId: the endpoint decides the region).
type albClient struct {
	c      *client
	region string
	cl     *alb.Client
}

func (c *client) albClient(ctx context.Context, region string) (*albClient, error) {
	cl, err := alb.NewClientWithOptions(region, sdkConfig(ctx), c.credential())
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
	return a.listLBs(ctx, nil)
}

// listListeners lists the listeners of a load balancer, page by page.
func (a *albClient) listListeners(ctx context.Context, lbID string) ([]albListener, error) {
	return a.listListenersOf(ctx, lbID, "")
}

// listenerCertificates reads the certificate ids of a listener, as the API
// writes them (a CAS id, with or without a region suffix): its default
// server certificate and its CA certificates (GetListenerAttribute), and
// every server certificate associated with it, the additional ones
// included (ListListenerCertificates; GetListenerAttribute carries the
// default certificate only).
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
	token := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		lr := alb.CreateListListenerCertificatesRequest()
		a.route(lr)
		lr.ListenerId = listenerID
		lr.MaxResults = requests.NewInteger(albListenerPageSize)
		lr.NextToken = token
		resp, err := a.cl.ListListenerCertificates(lr)
		if err != nil {
			return nil, wrapErr("alb ListListenerCertificates "+listenerID, err)
		}
		for _, c := range resp.Certificates {
			ids = appendNew(ids, strings.TrimSpace(c.CertificateId))
		}
		if resp.NextToken == "" || resp.NextToken == token || len(resp.Certificates) == 0 {
			break
		}
		token = resp.NextToken
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
