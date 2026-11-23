package aliyun

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/cas"

	"github.com/gofika/polyctl/internal/platform"
)

// Certificate Management Service (CAS), API version 2020-04-07: the
// certificates users upload, which ALB listeners reference by id.
//
// An account sees two separate certificate stores: the one behind
// cas.aliyuncs.com and the one behind cas.ap-southeast-1.aliyuncs.com. A
// certificate uploaded to one is missing from the other (its id is
// NotFound there), so uploading, listing, deleting and referencing a
// certificate from a listener must all use the same store. The store
// follows the CAS region of the account, which casRegionFor derives from
// the profile's region (cn-hongkong uses the Singapore store); config.yaml
// may override both (defaults.aliyun.cas_region, defaults.aliyun.cas_endpoint).
const (
	casEndpointCentral = "cas.aliyuncs.com"
	casRegionIntl      = "ap-southeast-1"
	casRegionCentral   = "cn-hangzhou"
	casOrderUpload     = "UPLOAD"
	casPageSize        = 100

	settingCASRegion   = "cas_region"
	settingCASEndpoint = "cas_endpoint"

	casCodeNameRepeat  = "NameRepeat"
	casCodeKeyMismatch = "NotMatch.CertificateAndPrivateKey"
	casCodeForbidden   = "API.Forbidden"
)

// casNow is the clock of the expiry computations (tests replace it).
var casNow = time.Now

// casRegionFor is the CAS region of an account whose profile region is
// region: ap-southeast-1 for cn-hongkong (whose certificates live in the
// Singapore store), "" (the central store, cn-hangzhou) otherwise. The same
// value decides the CAS endpoint and the region suffix of the certificate
// ids ALB listeners hold, so it is the one place of this rule.
func casRegionFor(region string) string {
	if strings.TrimSpace(region) == "cn-hongkong" {
		return casRegionIntl
	}
	return ""
}

// casCentral reports whether a CAS region names the central store.
func casCentral(casRegion string) bool { return casRegion == "" || casRegion == casRegionCentral }

// casEndpointFor is the CAS endpoint of a CAS region.
func casEndpointFor(casRegion string) string {
	if casCentral(casRegion) {
		return casEndpointCentral
	}
	return "cas." + casRegion + ".aliyuncs.com"
}

// listenerCertID is the certificate id an ALB listener takes for a CAS
// certificate: "<id>-<cas region>" outside the central store (verified for
// cn-hongkong: "<id>-ap-southeast-1"; the bare id is refused there), the
// bare id in the central store (not verified).
func listenerCertID(casRegion string, certID string) string {
	if casCentral(casRegion) {
		return certID
	}
	return certID + "-" + casRegion
}

// casIDOfListenerCert is the CAS certificate id within a listener's
// certificate id: the part before the first "-" ("1234567-ap-southeast-1"
// and "1234567" are both 1234567).
func casIDOfListenerCert(id string) string {
	id = strings.TrimSpace(id)
	if i := strings.IndexByte(id, '-'); i >= 0 {
		return id[:i]
	}
	return id
}

// casCertName is the name callers that upload a certificate for a domain
// give it: upload_<root domain>_<YYYY-MM-DD of NotAfter, UTC>. A renewed
// certificate has another expiry, hence another name, and is uploaded; the
// same certificate uploaded again finds its name and is reused.
func casCertName(rootDomain string, notAfter time.Time) string {
	return "upload_" + strings.ToLower(strings.TrimSpace(rootDomain)) + "_" + notAfter.UTC().Format("2006-01-02")
}

// casScope is the CAS store a client talks to.
type casScope struct {
	Region   string // "" for the central store
	Endpoint string
}

// SetSettings receives the settings of the profile (platform.SettingsAware).
func (c *client) SetSettings(setting func(key string) (string, error)) { c.settings = setting }

// cas resolves the CAS store of the account: defaults.aliyun.cas_region
// (else casRegionFor of the profile region) and defaults.aliyun.cas_endpoint
// (else the endpoint of that region).
func (c *client) cas() (casScope, error) {
	get := func(key string) (string, error) {
		if c.settings == nil {
			return "", nil
		}
		v, err := c.settings(key)
		return strings.TrimSpace(v), err
	}
	region, err := get(settingCASRegion)
	if err != nil {
		return casScope{}, err
	}
	if region == "" {
		region = casRegionFor(c.region)
	}
	endpoint, err := get(settingCASEndpoint)
	if err != nil {
		return casScope{}, err
	}
	if endpoint == "" {
		endpoint = casEndpointFor(region)
	}
	return casScope{Region: region, Endpoint: endpoint}, nil
}

func (c *client) casClient(ctx context.Context) (*cas.Client, casScope, error) {
	s, err := c.cas()
	if err != nil {
		return nil, s, err
	}
	region := s.Region
	if casCentral(region) {
		region = casRegionCentral
	}
	cl, err := cas.NewClientWithOptions(region, sdkConfig(), c.credential())
	if err != nil {
		return nil, s, err
	}
	cl.SetTransport(ctxTransport{ctx: ctx, base: c.transport})
	return cl, s, nil
}

// casErr maps a CAS failure: an endpoint that refuses every call
// (API.Forbidden, as cas.cn-hongkong.aliyuncs.com does) is unsupported, a
// key that does not belong to the certificate is invalid input, and an
// HTTP 403 without a known code is a permission denial. CAS answers a
// missing certificate with NotFound and HTTP 400, which wrapErr maps by
// its code.
func casErr(action string, s casScope, err error) error {
	err = wrapErr(action, err)
	var ae *apiError
	if !errors.As(err, &ae) {
		return err
	}
	switch {
	case ae.Code == casCodeForbidden:
		return fmt.Errorf("%w: the CAS endpoint %s is not available (check defaults.aliyun.cas_endpoint): %v", platform.ErrNotSupported, s.Endpoint, err)
	case ae.Code == casCodeKeyMismatch:
		ae.sentinel = platform.ErrInvalidInput
	case ae.sentinel == nil && ae.Status == 403:
		ae.sentinel = platform.ErrForbidden
	}
	if errors.Is(err, platform.ErrForbidden) {
		return fmt.Errorf("%w (the RAM user needs the yundun-cert:* permissions of Certificate Management Service)", err)
	}
	return err
}

// casCertificate is an uploaded CAS certificate, as the inventory stores
// it. Dates are the UTC dates CAS reports (YYYY-MM-DD).
type casCertificate struct {
	ID          string `json:"id" yaml:"id"`
	Name        string `json:"name" yaml:"name"`
	CommonName  string `json:"common_name" yaml:"common_name"`
	StartDate   string `json:"start_date" yaml:"start_date"`
	EndDate     string `json:"end_date" yaml:"end_date"`
	NotAfter    string `json:"not_after" yaml:"not_after"`
	Fingerprint string `json:"fingerprint_sha1" yaml:"fingerprint_sha1"`
	Sans        string `json:"sans" yaml:"sans"`
	SerialNo    string `json:"serial_no,omitempty" yaml:"serial_no,omitempty"`
	Endpoint    string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Account     string `json:"account,omitempty" yaml:"account,omitempty"`
	Source      string `json:"source" yaml:"source"`
}

func (c casCertificate) resource() platform.Resource {
	name := c.Name
	if name == "" {
		name = c.ID
	}
	return platform.Resource{Type: platform.ResCertificate, ID: c.ID, Name: name, Data: c}
}

// daysToExpire is EndDate minus today (both UTC dates). An empty or
// unreadable EndDate counts as today: 0 days.
func (c casCertificate) daysToExpire(now time.Time) int {
	end, err := time.Parse("2006-01-02", c.EndDate)
	if err != nil {
		return 0
	}
	today := now.UTC().Truncate(24 * time.Hour)
	return int(end.Sub(today).Hours() / 24)
}

// expired reports whether the certificate counts as expired: from 00:00
// UTC of its EndDate on (CAS keeps the date only, so the certificate is
// treated as expired for the whole of its last day), or when EndDate is
// missing.
func (c casCertificate) expired(now time.Time) bool {
	if _, err := time.Parse("2006-01-02", c.EndDate); err != nil {
		return true
	}
	return c.daysToExpire(now) <= 0
}

func casCertificateFrom(it cas.CertificateOrderListItem, endpoint string) casCertificate {
	return casCertificate{ID: strconv.FormatInt(it.CertificateId, 10), Name: it.Name, CommonName: it.CommonName, StartDate: it.StartDate,
		EndDate: it.EndDate, NotAfter: it.EndDate, Fingerprint: it.Fingerprint, Sans: it.Sans, SerialNo: it.SerialNo,
		Endpoint: endpoint, Source: "cas"}
}

// listCASCertificates lists the uploaded certificates (OrderType UPLOAD:
// neither the free nor the bought certificate orders), every page. The
// list stops when the pages cover TotalCount, or at a short or empty page
// (a missing TotalCount never ends it early, nor loops).
func (c *client) listCASCertificates(ctx context.Context) ([]casCertificate, casScope, error) {
	cl, s, err := c.casClient(ctx)
	if err != nil {
		return nil, s, err
	}
	var out []casCertificate
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, s, err
		}
		req := cas.CreateListUserCertificateOrderRequest()
		c.route(req, s.Endpoint)
		req.OrderType = casOrderUpload
		req.CurrentPage = requests.NewInteger(page)
		req.ShowSize = requests.NewInteger(casPageSize)
		resp, err := cl.ListUserCertificateOrder(req)
		if err != nil {
			return nil, s, casErr("cas ListUserCertificateOrder", s, err)
		}
		for _, it := range resp.CertificateOrderList {
			out = append(out, casCertificateFrom(it, s.Endpoint))
		}
		n := len(resp.CertificateOrderList)
		if n < casPageSize || int64(page*casPageSize) >= resp.TotalCount {
			break
		}
	}
	return out, s, nil
}

// uploadCASCertificate uploads a certificate chain and its private key
// (PEM texts) under name and returns its id. The PEM texts go in the form
// body: a chain with its key is too long for a query string.
func (c *client) uploadCASCertificate(ctx context.Context, name, certPEM, keyPEM string) (string, error) {
	cl, s, err := c.casClient(ctx)
	if err != nil {
		return "", err
	}
	req := cas.CreateUploadUserCertificateRequest()
	c.route(req, s.Endpoint)
	req.Name = name
	req.FormParams = map[string]string{"Cert": certPEM, "Key": keyPEM}
	resp, err := cl.UploadUserCertificate(req)
	if err != nil {
		return "", casErr("cas UploadUserCertificate", s, err)
	}
	if resp.CertId == 0 {
		return "", fmt.Errorf("cas UploadUserCertificate: the answer holds no certificate id (request %s)", resp.RequestId)
	}
	return strconv.FormatInt(resp.CertId, 10), nil
}

// deleteCASCertificate deletes an uploaded certificate. CAS does not check
// whether a listener still uses it: callers check first.
func (c *client) deleteCASCertificate(ctx context.Context, id string) error {
	n, err := strconv.ParseInt(id, 10, 64)
	if err != nil {
		return fmt.Errorf("%w: certificate id %q is not an integer", platform.ErrInvalidInput, id)
	}
	cl, s, err := c.casClient(ctx)
	if err != nil {
		return err
	}
	req := cas.CreateDeleteUserCertificateRequest()
	c.route(req, s.Endpoint)
	req.CertId = requests.NewInteger64(n)
	if _, err := cl.DeleteUserCertificate(req); err != nil {
		return casErr("cas DeleteUserCertificate", s, err)
	}
	return nil
}

// casResources lists the uploaded certificates for the inventory.
func (c *client) casResources(ctx context.Context, account string) ([]platform.Resource, error) {
	certs, _, err := c.listCASCertificates(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(certs))
	for _, ct := range certs {
		ct.Account = account
		out = append(out, ct.resource())
	}
	return out, nil
}

// casReference is an ALB listener that holds a CAS certificate.
type casReference struct {
	CertID           string `json:"certificate_id" yaml:"certificate_id"`
	ListenerCertID   string `json:"listener_certificate_id" yaml:"listener_certificate_id"`
	ListenerID       string `json:"listener_id" yaml:"listener_id"`
	Protocol         string `json:"protocol" yaml:"protocol"`
	Port             int    `json:"port" yaml:"port"`
	LoadBalancerID   string `json:"load_balancer_id" yaml:"load_balancer_id"`
	LoadBalancerName string `json:"load_balancer_name" yaml:"load_balancer_name"`
	Region           string `json:"region" yaml:"region"`
}

func (r casReference) String() string {
	lb := r.LoadBalancerName
	if lb == "" {
		lb = r.LoadBalancerID
	}
	return fmt.Sprintf("listener %s of load balancer %s (%s)", r.ListenerID, lb, r.Region)
}

// casReferences are the CAS certificates ALB listeners hold, read once and
// shared by every certificate a command checks.
type casReferences struct {
	byCert  map[string][]casReference
	regions []string
}

// of returns the listeners that hold the certificate id, in a stable order.
func (r *casReferences) of(certID string) []casReference { return r.byCert[certID] }

// casCheckError is a reference check that could not finish: a region whose
// listeners could not be read. A certificate is never taken as unused
// then. It unwraps to platform.ErrForbidden when a region refused the
// reads for lack of permission.
type casCheckError struct {
	Failures []platform.RegionError
}

func (e *casCheckError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, f.Region+": "+f.Err.Error())
	}
	return "cannot tell whether ALB listeners use the certificate: " + strings.Join(parts, "; ") +
		" (pass --region to check fewer regions, or --force to delete without the check)"
}

func (e *casCheckError) Unwrap() error {
	for _, f := range e.Failures {
		if errors.Is(f.Err, platform.ErrForbidden) || errors.Is(f.Err, platform.ErrUnauthorized) {
			return platform.ErrForbidden
		}
	}
	return nil
}

// albRegions are the regions whose ALB listeners a reference check reads:
// the given ones, else every region of the account (ecs DescribeRegions,
// the set find uses).
func (c *client) albRegions(ctx context.Context, only []string) ([]string, error) {
	var out []string
	for _, r := range only {
		if r = strings.TrimSpace(r); r != "" && !containsString(out, r) {
			out = append(out, r)
		}
	}
	if len(out) > 0 {
		sort.Strings(out)
		return out, nil
	}
	return c.enabledRegions(ctx)
}

// casCertificateReferences reads which CAS certificates the ALB listeners
// of the regions hold: every load balancer, every listener, and for each
// HTTPS or QUIC listener its server and CA certificates (ListListeners
// does not carry them). Only read APIs are used. A region whose ALB
// endpoint does not exist has no load balancers; any other failure of a
// region fails the check (*casCheckError).
func (c *client) casCertificateReferences(ctx context.Context, regions []string) (*casReferences, error) {
	type result struct {
		refs []casReference
		err  error
	}
	results := make([]result, len(regions))
	sem := make(chan struct{}, regionConcurrency)
	var wg sync.WaitGroup
	for i, region := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			refs, err := c.regionCertificateReferences(ctx, region)
			results[i] = result{refs: refs, err: err}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	out := &casReferences{byCert: map[string][]casReference{}, regions: regions}
	var failures []platform.RegionError
	for i, r := range results {
		if r.err != nil {
			failures = append(failures, platform.RegionError{Region: regions[i], Err: r.err})
			continue
		}
		for _, ref := range r.refs {
			out.byCert[ref.CertID] = append(out.byCert[ref.CertID], ref)
		}
	}
	if len(failures) > 0 {
		return nil, &casCheckError{Failures: failures}
	}
	return out, nil
}

func (c *client) regionCertificateReferences(ctx context.Context, region string) ([]casReference, error) {
	a, err := c.albClient(ctx, region)
	if err != nil {
		return nil, err
	}
	lbs, err := a.listLoadBalancers(ctx)
	if errors.Is(err, errNoALBEndpoint) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var refs []casReference
	for _, lb := range lbs {
		listeners, err := a.listListeners(ctx, lb.ID)
		if err != nil {
			return nil, err
		}
		for _, l := range listeners {
			if !carriesCertificates(l.Protocol) {
				continue
			}
			ids, err := a.listenerCertificates(ctx, l.ID)
			if err != nil {
				return nil, err
			}
			for _, id := range ids {
				refs = append(refs, casReference{CertID: casIDOfListenerCert(id), ListenerCertID: id, ListenerID: l.ID, Protocol: l.Protocol,
					Port: l.Port, LoadBalancerID: lb.ID, LoadBalancerName: lb.Name, Region: region})
			}
		}
	}
	return refs, nil
}

// casCertificateInUse returns the ALB listeners of the regions (every
// region of the account when none is given) that hold the CAS certificate
// certID. A check that cannot finish is an error, never "unused".
func (c *client) casCertificateInUse(ctx context.Context, certID string, regions []string) ([]casReference, error) {
	regions, err := c.albRegions(ctx, regions)
	if err != nil {
		return nil, err
	}
	refs, err := c.casCertificateReferences(ctx, regions)
	if err != nil {
		return nil, err
	}
	return refs.of(certID), nil
}
