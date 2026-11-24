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
	// account is the account id of the profile (inventory rows carry it).
	account string
	// settings resolves the profile's settings of config.yaml (nil: none).
	settings func(key string) (string, error)

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
	_ platform.ZoneGetter       = (*client)(nil)
	_ platform.SettingsAware    = (*client)(nil)
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

// sendOnceKey marks a context whose SDK clients send each request once.
type sendOnceKey struct{}

// sendOnce marks ctx so that the SDK clients created with it never resend
// a request. The SDK resends a request whose answer timed out or was a 5xx,
// although the platform may have carried out the first one: a write that
// takes no ClientToken (deletes, DNS records, key pairs, certificates,
// start, stop) is created with such a client, so it is sent once and a lost
// answer is an error the caller can check, not a duplicate or a false
// failure. Writes that take a ClientToken keep the retries: the token makes
// the platform answer a resent request with the result of the first.
func sendOnce(ctx context.Context) context.Context {
	return context.WithValue(ctx, sendOnceKey{}, true)
}

// sdkConfig returns the SDK configuration of a service client created with
// ctx: two automatic retries, none when ctx is marked by sendOnce.
func sdkConfig(ctx context.Context) *sdk.Config {
	cfg := sdk.NewConfig().WithScheme("HTTPS").WithTimeout(requestTimeout)
	if once, _ := ctx.Value(sendOnceKey{}).(bool); once {
		return cfg.WithAutoRetry(false).WithMaxRetryTime(0)
	}
	return cfg.WithAutoRetry(true).WithMaxRetryTime(2)
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
	cl, err := alidns.NewClientWithOptions(c.region, sdkConfig(ctx), c.credential())
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
	cl, err := domain.NewClientWithOptions(region, sdkConfig(ctx), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

func (c *client) stsClient(ctx context.Context) (*sts.Client, error) {
	cl, err := sts.NewClientWithOptions(c.region, sdkConfig(ctx), c.credential())
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
	cl, err := ecs.NewClientWithOptions(region, sdkConfig(ctx), c.credential())
	if err != nil {
		return nil, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, nil
}

// apiError is an Alibaba Cloud API failure reduced to "action: Code: Message".
// It unwraps to platform.ErrUnauthorized / platform.ErrNotFound when the
// error code (or HTTP status) says so. RAM policy denials (Forbidden.*,
// NoPermission.*, NotAuthorized, AccessDenied) and account-level refusals
// (basic information not completed, real-name verification missing) are
// failures of a valid key: they unwrap to platform.ErrForbidden, never to
// ErrUnauthorized, so the CLI does not ask for a re-login and a sync goes on
// with the other resource types. HTTP 403 alone decides nothing: ECS answers
// several state errors (IncorrectInstanceStatus.Initializing,
// DependencyViolation, ...) with 403 too.
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
	msg := fmt.Sprintf("%s: %s: %s", e.Action, e.Code, e.Message)
	if hint := accountStateHint(e.Code); hint != "" {
		msg += " (" + hint + ")"
	}
	return msg
}

func (e *apiError) Unwrap() error { return e.sentinel }

// ErrorCode returns the Alibaba Cloud error code (platform.CodedError).
func (e *apiError) ErrorCode() string { return e.Code }

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
	case isForbiddenCode(e.Code):
		e.sentinel = platform.ErrForbidden
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

// isForbiddenCode reports a request a valid key may not make: a RAM denial
// (the codes differ per product: ECS and Alidns 403 Forbidden.RAM, VPC 400
// Forbidden.RAM, ALB 403 Forbidden.LoadBalancer, BSS 400 NotAuthorized,
// ResourceManager 403 NoPermission) or an account the platform refuses to
// serve until its console says so. ALB answers Forbidden.LoadBalancer even
// for an id that does not exist, so a forbidden code is never "not found".
func isForbiddenCode(code string) bool {
	switch {
	case code == "Forbidden", strings.HasPrefix(code, "Forbidden."),
		code == "NoPermission", strings.HasPrefix(code, "NoPermission."),
		code == "NotAuthorized", code == "AccessDenied", strings.HasPrefix(code, "AccessDenied."),
		code == "UnauthorizedRegion",
		code == "IncompleteAccountInfo", code == "OperationFailed.BasicInfoUncompleted",
		code == "BASIC_INFO_UNCOMPLETED", code == "Identity.Uncertified":
		return true
	}
	return false
}

// accountStateHint returns what to do about an account-level refusal, or "".
func accountStateHint(code string) string {
	switch code {
	case "IncompleteAccountInfo", "OperationFailed.BasicInfoUncompleted", "BASIC_INFO_UNCOMPLETED":
		return "complete the account's basic information in the Alibaba Cloud console, then try again"
	case "Identity.Uncertified":
		return "complete the account's real-name verification in the Alibaba Cloud console, then try again"
	}
	return ""
}

// isDryRunPassed reports the answer of a request sent with DryRun=true that
// would have succeeded: Alibaba Cloud returns it as an error (HTTP 400
// DryRunOperation), and it must be treated as success.
func isDryRunPassed(err error) bool { return platform.HasErrorCode(err, "DryRunOperation") }

func isNotFoundCode(code string, status int) bool {
	switch {
	case strings.Contains(code, "NotFound"), strings.Contains(code, "NoExist"), strings.Contains(code, "NotExist"),
		code == "DomainRecordNotBelongToUser", code == "InvalidDomainName", code == "InvalidInstanceId.NotFound":
		return true
	case code == "InvalidSystemDiskSize.LessThanImageSize", code == "HOSTNAME_ILLEGAL":
		// ECS answers these invalid RunInstances parameters with HTTP 404:
		// nothing is missing.
		return false
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
	if c.site != "" {
		extra["site"] = c.site
	}
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
		return c.inEveryRegion(ctx, c.instanceResources)
	case platform.ResLoadBalancer:
		res, err := c.inEveryRegion(ctx, c.albResources)
		if err != nil && platform.AsRegionSyncError(err) == nil && errors.Is(err, platform.ErrForbidden) {
			// A RAM user without ALB permissions: a warning of the sync
			// and an empty list, not a failure of the account (the list
			// command reports the denial itself). Partial: no stored row
			// is kept and the empty set is fresh for its TTL, instead of
			// being synced again on every read.
			return nil, &platform.RegionSyncError{Failures: []platform.RegionError{{Region: "every region (no ALB read permission)", Err: err, Partial: true}}}
		}
		return res, err
	case platform.ResSecurityGroup:
		return c.securityGroupResources(ctx, c.region)
	case platform.ResKeyPair:
		return c.keyPairResources(ctx, c.region)
	case platform.ResEIP:
		return c.inEveryRegion(ctx, c.eipResources)
	case platform.ResCertificate:
		// A RAM denial is the error of this type: the caller keeps the
		// certificates synced before and syncs the other types.
		return c.casResources(ctx, c.account)
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}
