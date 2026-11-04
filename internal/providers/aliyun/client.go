package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/auth/credentials"
	sdkerrors "github.com/aliyun/alibaba-cloud-sdk-go/sdk/errors"
	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/domain"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/sts"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// Public API endpoints. They are pinned so the SDK never has to consult the
// location service. ECS uses the central endpoint with RegionId as a parameter.
// The registrar (domain) API has two sites: the China site serves accounts of
// aliyun.com, the international site serves alibabacloud.com accounts; see
// client.registrarEndpoint.
const (
	endpointDNS        = "alidns.aliyuncs.com"
	endpointDomainCN   = "domain.aliyuncs.com"
	endpointDomainIntl = "domain-intl.aliyuncs.com"
	endpointSTS        = "sts.aliyuncs.com"
	endpointECS        = "ecs.aliyuncs.com"
	domainRegionCN     = "cn-hangzhou"
	domainRegionIntl   = "ap-southeast-1"
	siteCN             = "cn"
	siteIntl           = "intl"
	pageSize           = 100
	requestTimeout     = 60 * time.Second
	defaultRecordTTL   = 600
)

// client is an authenticated Alibaba Cloud session.
type client struct {
	region    string
	keyID     string
	keySecret string
	// site forces the registrar site ("cn" or "intl"); empty derives it from region.
	site string

	// endpoint and scheme override every request's destination (tests).
	endpoint string
	scheme   string
	// transport is the HTTP transport used by every SDK client.
	transport http.RoundTripper
}

var (
	_ platform.Client           = (*client)(nil)
	_ platform.DNSService       = (*client)(nil)
	_ platform.RegistrarService = (*client)(nil)
)

// endpointOverride redirects every request of newly created clients to a
// test server ("host:port" and scheme). Empty in production.
var endpointOverride, schemeOverride string

func newClient(region, keyID, keySecret string) *client {
	return &client{
		region: region, keyID: keyID, keySecret: keySecret,
		endpoint: endpointOverride, scheme: schemeOverride,
		transport: http.DefaultTransport,
	}
}

// ctxTransport propagates a context into the SDK's HTTP requests so that
// cancellation and deadlines are honoured.
type ctxTransport struct {
	ctx  context.Context
	base http.RoundTripper
}

func (t ctxTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	return t.base.RoundTrip(r.WithContext(t.ctx))
}

// sdkConfig returns the SDK configuration shared by all service clients.
func sdkConfig() *sdk.Config {
	return sdk.NewConfig().WithScheme("HTTPS").WithTimeout(requestTimeout).WithAutoRetry(true).WithMaxRetryTime(2)
}

func (c *client) credential() *credentials.AccessKeyCredential {
	return credentials.NewAccessKeyCredential(c.keyID, c.keySecret)
}

// route pins the request to the service endpoint (or the test server).
func (c *client) route(r requests.AcsRequest, endpoint string) {
	if c.endpoint != "" {
		r.SetDomain(c.endpoint)
		r.SetScheme(c.scheme)
		return
	}
	r.SetDomain(endpoint)
	r.SetScheme("https")
}

func (c *client) dnsClient(ctx context.Context) (*alidns.Client, error) {
	cl, err := alidns.NewClientWithOptions(c.region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

// registrarSite returns "cn" or "intl": the explicit site, else derived from
// the profile region (cn-* regions belong to the China site).
func (c *client) registrarSite() string {
	switch c.site {
	case siteCN, siteIntl:
		return c.site
	}
	if strings.HasPrefix(c.region, "cn-") {
		return siteCN
	}
	return siteIntl
}

// registrarEndpoint returns the region id and host of the registrar API for
// the account's site.
func (c *client) registrarEndpoint() (region, host string) {
	if c.registrarSite() == siteIntl {
		return domainRegionIntl, endpointDomainIntl
	}
	return domainRegionCN, endpointDomainCN
}

// routeRegistrar pins a registrar request to the site's endpoint.
func (c *client) routeRegistrar(r requests.AcsRequest) {
	_, host := c.registrarEndpoint()
	c.route(r, host)
}

func (c *client) domainClient(ctx context.Context) (*domain.Client, error) {
	region, _ := c.registrarEndpoint()
	cl, err := domain.NewClientWithOptions(region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

func (c *client) stsClient(ctx context.Context) (*sts.Client, error) {
	cl, err := sts.NewClientWithOptions(c.region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

func (c *client) ecsClient(ctx context.Context, region string) (*ecs.Client, error) {
	if region == "" {
		region = c.region
	}
	cl, err := ecs.NewClientWithOptions(region, sdkConfig(), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

// apiError is an Alibaba Cloud API failure reduced to "action: Code: Message".
// It unwraps to platform.ErrUnauthorized / platform.ErrNotFound when the
// error code (or HTTP status) says so. RAM policy denials (Forbidden.*,
// NoPermission.*, AccessDenied, HTTP 403) are authorization failures of a
// valid key and deliberately carry no sentinel: the CLI must not ask for a
// re-login and a sync must go on with the other resource types.
type apiError struct {
	Action   string
	Code     string
	Message  string
	Status   int
	sentinel error
}

func (e *apiError) Error() string {
	if e.Code == "" {
		return fmt.Sprintf("%s: %s", e.Action, e.Message)
	}
	return fmt.Sprintf("%s: %s: %s", e.Action, e.Code, e.Message)
}

func (e *apiError) Unwrap() error { return e.sentinel }

// wrapErr maps SDK errors to apiError (and the platform sentinels).
func wrapErr(action string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return fmt.Errorf("%s: %w", action, err)
	}
	var se sdkerrors.Error
	if !errors.As(err, &se) {
		if strings.Contains(err.Error(), context.Canceled.Error()) {
			return fmt.Errorf("%s: %w", action, context.Canceled)
		}
		return fmt.Errorf("%s: %w", action, err)
	}
	e := &apiError{Action: action, Code: se.ErrorCode(), Message: strings.TrimSpace(se.Message()), Status: se.HttpStatus()}
	if e.Message == "" {
		e.Message = strings.TrimSpace(err.Error())
	}
	// Client-side SDK errors (timeouts, unmarshal) carry no server code.
	if ce, ok := se.(*sdkerrors.ClientError); ok {
		if oe := ce.OriginError(); oe != nil && (errors.Is(oe, context.Canceled) || errors.Is(oe, context.DeadlineExceeded)) {
			return fmt.Errorf("%s: %w", action, oe)
		}
	}
	switch {
	case isUnauthorizedCode(e.Code, e.Status):
		e.sentinel = platform.ErrUnauthorized
	case isNotFoundCode(e.Code, e.Status):
		e.sentinel = platform.ErrNotFound
	}
	return e
}

// isUnauthorizedCode reports an authentication failure: the key itself is
// unknown, its signature is wrong or its token expired.
func isUnauthorizedCode(code string, status int) bool {
	switch {
	case code == "SignatureDoesNotMatch", code == "InvalidAccessKeySecret", code == "Unauthorized",
		strings.HasPrefix(code, "InvalidAccessKeyId"), strings.HasPrefix(code, "InvalidSecurityToken"):
		return true
	}
	return status == http.StatusUnauthorized
}

func isNotFoundCode(code string, status int) bool {
	switch {
	case strings.Contains(code, "NotFound"), strings.Contains(code, "NoExist"), strings.Contains(code, "NotExist"),
		code == "DomainRecordNotBelongToUser", code == "InvalidDomainName", code == "InvalidInstanceId.NotFound":
		return true
	}
	return status == http.StatusNotFound
}

// Verify calls STS GetCallerIdentity.
func (c *client) Verify(ctx context.Context) (*platform.Identity, error) {
	cl, err := c.stsClient(ctx)
	if err != nil {
		return nil, err
	}
	req := sts.CreateGetCallerIdentityRequest()
	c.route(req, endpointSTS)
	resp, err := cl.GetCallerIdentity(req)
	if err != nil {
		return nil, wrapErr("sts GetCallerIdentity", err)
	}
	extra := map[string]string{"identity_type": resp.IdentityType, "region": c.region}
	if resp.PrincipalId != "" {
		extra["principal_id"] = resp.PrincipalId
	}
	if resp.UserId != "" {
		extra["user_id"] = resp.UserId
	}
	if resp.RoleId != "" {
		extra["role_id"] = resp.RoleId
	}
	return &platform.Identity{Account: resp.AccountId, User: resp.Arn, Extra: extra}, nil
}

// Sync fetches every resource of a type for the inventory.
func (c *client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	switch rt {
	case platform.ResZone:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		return app.ZoneResources(zones), nil
	case platform.ResDNSRecord:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		var out []platform.Resource
		for _, z := range zones {
			recs, err := c.ListRecords(ctx, z.ID)
			if err != nil {
				return nil, err
			}
			out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
		}
		return out, nil
	case platform.ResDomain:
		domains, err := c.ListDomains(ctx)
		if err != nil {
			// A RAM denial is reported as the error of this type; the caller
			// keeps the previously synced domains and syncs the other types.
			return nil, err
		}
		return app.DomainResources(domains), nil
	case platform.ResInstance:
		return c.ListInstances(ctx, "")
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}
