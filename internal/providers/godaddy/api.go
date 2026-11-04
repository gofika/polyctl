package godaddy

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/platform"
)

const (
	envProduction = "production"
	envOTE        = "ote"

	prodBaseURL = "https://api.godaddy.com"
	oteBaseURL  = "https://api.ote-godaddy.com"
	keysURL     = "https://developer.godaddy.com/personal-access-token"

	defaultDomainPageSize = 1000
	defaultRecordPageSize = 500
)

// baseURLFor returns the API endpoint of an environment.
func baseURLFor(env string) string {
	if env == envOTE {
		return oteBaseURL
	}
	return prodBaseURL
}

// api is a thin wrapper over the GoDaddy REST API (v1).
type api struct {
	http           *httpx.Client
	domainPageSize int
	recordPageSize int
}

// newAPI builds the client. A Personal Access Token is sent as
// `Authorization: Bearer <token>`; the legacy key pair as
// `Authorization: sso-key <key>:<secret>`. 429 responses are retried after
// the delay GoDaddy announces in RateLimit-Reset / Retry-After.
func newAPI(baseURL string, cred credentials) *api {
	auth := cred.authorization()
	h := httpx.New(baseURL, func(r *http.Request) {
		r.Header.Set("Authorization", auth)
	})
	h.HTTP.Transport = newRateLimitTransport(h.HTTP.Transport)
	return &api{
		http:           h,
		domainPageSize: defaultDomainPageSize,
		recordPageSize: defaultRecordPageSize,
	}
}

// apiDomain is the GoDaddy domain representation (list and detail views).
type apiDomain struct {
	Domain              string   `json:"domain"`
	DomainID            int64    `json:"domainId,omitempty"`
	Status              string   `json:"status,omitempty"`
	Expires             string   `json:"expires,omitempty"`
	CreatedAt           string   `json:"createdAt,omitempty"`
	NameServers         []string `json:"nameServers,omitempty"`
	RenewAuto           *bool    `json:"renewAuto,omitempty"`
	Renewable           *bool    `json:"renewable,omitempty"`
	Locked              *bool    `json:"locked,omitempty"`
	Privacy             *bool    `json:"privacy,omitempty"`
	ExpirationProtected *bool    `json:"expirationProtected,omitempty"`
	TransferProtected   *bool    `json:"transferProtected,omitempty"`
	HoldRegistrar       *bool    `json:"holdRegistrar,omitempty"`
}

// apiRecord is a GoDaddy DNS record. Name is relative to the domain ("@"
// for the apex). For PUT bodies Type and Name are left empty (omitted).
type apiRecord struct {
	Type     string `json:"type,omitempty"`
	Name     string `json:"name,omitempty"`
	Data     string `json:"data"`
	TTL      int    `json:"ttl,omitempty"`
	Priority *int   `json:"priority,omitempty"`
	Port     *int   `json:"port,omitempty"`
	Weight   *int   `json:"weight,omitempty"`
	Service  string `json:"service,omitempty"`
	Protocol string `json:"protocol,omitempty"`
}

// apiAvailability is the response of GET /v1/domains/available.
type apiAvailability struct {
	Domain     string `json:"domain"`
	Available  bool   `json:"available"`
	Definitive bool   `json:"definitive"`
	Price      int64  `json:"price,omitempty"`
	Currency   string `json:"currency,omitempty"`
	Period     int    `json:"period,omitempty"`
}

// domainPatch is the body of PATCH /v1/domains/{domain}.
type domainPatch struct {
	NameServers []string `json:"nameServers,omitempty"`
	Locked      *bool    `json:"locked,omitempty"`
	RenewAuto   *bool    `json:"renewAuto,omitempty"`
}

// apiError is a decoded GoDaddy error response. It unwraps to the
// underlying httpx.Error (and through it to the platform sentinels).
type apiError struct {
	What    string
	Status  int
	Code    string
	Message string
	Fields  []apiErrorField
	cause   *httpx.Error
}

type apiErrorField struct {
	Path    string `json:"path"`
	Code    string `json:"code"`
	Message string `json:"message"`
}

func (e *apiError) Error() string {
	var b strings.Builder
	fmt.Fprintf(&b, "godaddy: %s: HTTP %d", e.What, e.Status)
	if e.Code != "" {
		b.WriteString(" " + e.Code)
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
	}
	for _, f := range e.Fields {
		fmt.Fprintf(&b, "; %s: %s", f.Path, f.Message)
	}
	if e.Status == http.StatusForbidden && e.Code == "ACCESS_DENIED" {
		b.WriteString(". GoDaddy denied access: " + accessRequirement + "; for development use an OTE credential (`polyctl auth login godaddy --set env=ote`)")
	}
	return b.String()
}

func (e *apiError) Unwrap() error { return e.cause }

// wrapErr turns an httpx.Error into an apiError with the decoded GoDaddy
// code/message; other errors are annotated with what.
func wrapErr(err error, what string) error {
	if err == nil {
		return nil
	}
	var he *httpx.Error
	if !errors.As(err, &he) {
		if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
			return err
		}
		return fmt.Errorf("godaddy: %s: %w", what, err)
	}
	ae := &apiError{What: what, Status: he.Status, cause: he}
	var body struct {
		Code    string          `json:"code"`
		Message string          `json:"message"`
		Fields  []apiErrorField `json:"fields"`
	}
	if json.Unmarshal([]byte(he.Body), &body) == nil {
		ae.Code, ae.Message, ae.Fields = body.Code, body.Message, body.Fields
	}
	return ae
}

func domainPath(domain string) string {
	return "/v1/domains/" + url.PathEscape(domain)
}

func recordSetPath(domain, typ, name string) string {
	return domainPath(domain) + "/records/" + url.PathEscape(strings.ToUpper(typ)) + "/" + url.PathEscape(name)
}

// listDomainsPage fetches one page of domains.
func (a *api) listDomainsPage(ctx context.Context, limit int, marker string, statuses []string) ([]apiDomain, error) {
	q := url.Values{}
	q.Set("limit", strconv.Itoa(limit))
	q.Set("includes", "nameServers")
	if marker != "" {
		q.Set("marker", marker)
	}
	if len(statuses) > 0 {
		q.Set("statuses", strings.Join(statuses, ","))
	}
	var out []apiDomain
	if err := a.http.Get(ctx, "/v1/domains", q, &out); err != nil {
		return nil, wrapErr(err, "list domains")
	}
	return out, nil
}

// listDomains returns every domain of the account, following the marker
// pagination until a short page is returned.
func (a *api) listDomains(ctx context.Context, statuses []string) ([]apiDomain, error) {
	limit := a.domainPageSize
	if limit <= 0 {
		limit = defaultDomainPageSize
	}
	var out []apiDomain
	seen := map[string]bool{}
	marker := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		page, err := a.listDomainsPage(ctx, limit, marker, statuses)
		if err != nil {
			return nil, err
		}
		added := 0
		for _, d := range page {
			name := platform.NormalizeDomain(d.Domain)
			if name == "" || seen[name] {
				continue
			}
			seen[name] = true
			d.Domain = name
			out = append(out, d)
			added++
		}
		if len(page) < limit || added == 0 {
			return out, nil
		}
		marker = page[len(page)-1].Domain
	}
}

func (a *api) getDomain(ctx context.Context, domain string) (*apiDomain, error) {
	var out apiDomain
	if err := a.http.Get(ctx, domainPath(domain), nil, &out); err != nil {
		return nil, wrapErr(err, "get domain "+domain)
	}
	out.Domain = platform.NormalizeDomain(out.Domain)
	if out.Domain == "" {
		out.Domain = domain
	}
	return &out, nil
}

func (a *api) patchDomain(ctx context.Context, domain string, p domainPatch) error {
	return wrapErr(a.http.Do(ctx, http.MethodPatch, domainPath(domain), nil, p, nil), "update domain "+domain)
}

func (a *api) available(ctx context.Context, domain string) (*apiAvailability, error) {
	q := url.Values{}
	q.Set("domain", domain)
	q.Set("checkType", "FAST")
	q.Set("forTransfer", "false")
	var out apiAvailability
	if err := a.http.Get(ctx, "/v1/domains/available", q, &out); err != nil {
		return nil, wrapErr(err, "check availability of "+domain)
	}
	if out.Domain == "" {
		out.Domain = domain
	}
	return &out, nil
}

// listRecordsAt pages through a records endpoint with limit/offset.
func (a *api) listRecordsAt(ctx context.Context, path, what string) ([]apiRecord, error) {
	limit := a.recordPageSize
	if limit <= 0 {
		limit = defaultRecordPageSize
	}
	var out []apiRecord
	offset := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("limit", strconv.Itoa(limit))
		q.Set("offset", strconv.Itoa(offset))
		var page []apiRecord
		if err := a.http.Get(ctx, path, q, &page); err != nil {
			return nil, wrapErr(err, what)
		}
		out = append(out, page...)
		if len(page) < limit {
			return out, nil
		}
		offset += len(page)
	}
}

// listRecords returns all DNS records of a domain.
func (a *api) listRecords(ctx context.Context, domain string) ([]apiRecord, error) {
	return a.listRecordsAt(ctx, domainPath(domain)+"/records", "list records of "+domain)
}

// recordSet returns the records of one type+name. A 404 is treated as an
// empty set.
func (a *api) recordSet(ctx context.Context, domain, typ, name string) ([]apiRecord, error) {
	recs, err := a.listRecordsAt(ctx, recordSetPath(domain, typ, name), fmt.Sprintf("get %s %s records of %s", strings.ToUpper(typ), name, domain))
	if err != nil {
		var ae *apiError
		if errors.As(err, &ae) && ae.Status == http.StatusNotFound && ae.Code != "UNKNOWN_DOMAIN" {
			return nil, nil
		}
		return nil, err
	}
	return recs, nil
}

// addRecords appends records (PATCH /records).
func (a *api) addRecords(ctx context.Context, domain string, recs []apiRecord) error {
	return wrapErr(a.http.Do(ctx, http.MethodPatch, domainPath(domain)+"/records", nil, recs, nil), "add records to "+domain)
}

// replaceRecordSet replaces every record of type+name (PUT). GoDaddy
// rejects an empty body, so callers delete the set instead when needed.
func (a *api) replaceRecordSet(ctx context.Context, domain, typ, name string, recs []apiRecord) error {
	body := make([]apiRecord, 0, len(recs))
	for _, r := range recs {
		r.Type, r.Name = "", ""
		body = append(body, r)
	}
	return wrapErr(a.http.Do(ctx, http.MethodPut, recordSetPath(domain, typ, name), nil, body, nil), fmt.Sprintf("replace %s %s records of %s", strings.ToUpper(typ), name, domain))
}

// deleteRecordSet deletes every record of type+name.
func (a *api) deleteRecordSet(ctx context.Context, domain, typ, name string) error {
	return wrapErr(a.http.Do(ctx, http.MethodDelete, recordSetPath(domain, typ, name), nil, nil, nil), fmt.Sprintf("delete %s %s records of %s", strings.ToUpper(typ), name, domain))
}
