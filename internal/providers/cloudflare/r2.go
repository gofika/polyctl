package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
)

// R2: the buckets of an account and the custom domains bound to them.
//
// The custom domain endpoints use camelCase JSON keys (zoneId, zoneName,
// minTLS) in requests and responses. A snake_case key in a request is
// silently ignored by the API, so requests are only ever written in
// camelCase.

const (
	// r2PublicHost is the target of the CNAME record Cloudflare creates in
	// the zone when a custom domain is bound to a bucket.
	r2PublicHost = "public.r2.dev"
	// r2BucketsPerPage is the page size of the bucket listing.
	r2BucketsPerPage = 1000
	// jurisdictionHeader selects the R2 jurisdiction (eu, fedramp) of a
	// request; without it the default jurisdiction is addressed.
	jurisdictionHeader = "cf-r2-jurisdiction"
)

// Cloudflare error codes of the R2 endpoints.
const (
	codeR2NoSuchBucket   = 10006 // The specified bucket does not exist. (404)
	codeR2DomainInUse    = 10052 // Domain already in use. (409)
	codeR2DomainNotFound = 10053 // Domain not found. (404)
	codeR2InvalidZone    = 10051 // The specified zone id is not valid. (400)
	codeR2ZoneNotFound   = 10057 // The zone for this domain was not found ... (400)
)

// minTLSValues are the minimum TLS versions the API accepts.
var minTLSValues = []string{"1.0", "1.1", "1.2", "1.3"}

type r2Bucket struct {
	Name         string `json:"name"`
	CreationDate string `json:"creation_date,omitempty"`
	// Location, StorageClass and Jurisdiction are only returned when one
	// bucket is read, not by the listing.
	Location     string `json:"location,omitempty"`
	StorageClass string `json:"storage_class,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty"`
}

type r2DomainStatus struct {
	Ownership string `json:"ownership,omitempty"`
	SSL       string `json:"ssl,omitempty"`
}

// r2CustomDomain is a custom domain as the API returns it. MinTLS and
// Ciphers are only present once they have been set; the creation answer
// has no status and no zoneName.
type r2CustomDomain struct {
	Domain   string          `json:"domain"`
	Enabled  bool            `json:"enabled"`
	ZoneID   string          `json:"zoneId,omitempty"`
	ZoneName string          `json:"zoneName,omitempty"`
	MinTLS   string          `json:"minTLS,omitempty"`
	Ciphers  []string        `json:"ciphers,omitempty"`
	Status   *r2DomainStatus `json:"status,omitempty"`
}

// r2AttachBody is the body of the creation of a custom domain; the API
// requires zoneId.
type r2AttachBody struct {
	Domain  string `json:"domain"`
	Enabled bool   `json:"enabled"`
	ZoneID  string `json:"zoneId"`
	MinTLS  string `json:"minTLS,omitempty"`
}

// r2UpdateBody is a partial update: the fields left out keep their value.
type r2UpdateBody struct {
	Enabled *bool  `json:"enabled,omitempty"`
	MinTLS  string `json:"minTLS,omitempty"`
}

// withJurisdiction returns the API with every request scoped to an R2
// jurisdiction; "" returns a unchanged.
func (a *api) withJurisdiction(j string) *api {
	if j == "" {
		return a
	}
	h := *a.http
	prepare := h.Prepare
	h.Prepare = func(r *http.Request) {
		if prepare != nil {
			prepare(r)
		}
		r.Header.Set(jurisdictionHeader, j)
	}
	c := *a
	c.http = &h
	return &c
}

func r2BucketsPath(accountID string) string {
	return "/accounts/" + url.PathEscape(accountID) + "/r2/buckets"
}

func r2DomainsPath(accountID, bucket string) string {
	return r2BucketsPath(accountID) + "/" + url.PathEscape(bucket) + "/domains/custom"
}

// listBuckets reads every page of the bucket listing (cursor paging: the
// last page carries no cursor). nameContains narrows the listing to names
// containing it.
func (a *api) listBuckets(ctx context.Context, accountID, nameContains string) ([]r2Bucket, error) {
	var all []r2Bucket
	cursor := ""
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{}
		q.Set("per_page", strconv.Itoa(r2BucketsPerPage))
		if nameContains != "" {
			q.Set("name_contains", nameContains)
		}
		if cursor != "" {
			q.Set("cursor", cursor)
		}
		var res struct {
			Buckets []r2Bucket `json:"buckets"`
		}
		info, err := a.do(ctx, http.MethodGet, r2BucketsPath(accountID), q, nil, &res)
		if err != nil {
			return nil, err
		}
		all = append(all, res.Buckets...)
		if info == nil || info.Cursor == "" || info.Cursor == cursor || len(res.Buckets) == 0 {
			return all, nil
		}
		cursor = info.Cursor
	}
}

func (a *api) getBucket(ctx context.Context, accountID, bucket string) (*r2Bucket, error) {
	var b r2Bucket
	if _, err := a.do(ctx, http.MethodGet, r2BucketsPath(accountID)+"/"+url.PathEscape(bucket), nil, nil, &b); err != nil {
		return nil, err
	}
	return &b, nil
}

func (a *api) listCustomDomains(ctx context.Context, accountID, bucket string) ([]r2CustomDomain, error) {
	var res struct {
		Domains []r2CustomDomain `json:"domains"`
	}
	if _, err := a.do(ctx, http.MethodGet, r2DomainsPath(accountID, bucket), nil, nil, &res); err != nil {
		return nil, err
	}
	return res.Domains, nil
}

func (a *api) getCustomDomain(ctx context.Context, accountID, bucket, domain string) (*r2CustomDomain, error) {
	var d r2CustomDomain
	if _, err := a.do(ctx, http.MethodGet, r2DomainsPath(accountID, bucket)+"/"+url.PathEscape(domain), nil, nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (a *api) attachCustomDomain(ctx context.Context, accountID, bucket string, body r2AttachBody) (*r2CustomDomain, error) {
	var d r2CustomDomain
	if _, err := a.do(ctx, http.MethodPost, r2DomainsPath(accountID, bucket), nil, body, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

func (a *api) updateCustomDomain(ctx context.Context, accountID, bucket, domain string, body r2UpdateBody) (*r2CustomDomain, error) {
	var d r2CustomDomain
	if _, err := a.do(ctx, http.MethodPut, r2DomainsPath(accountID, bucket)+"/"+url.PathEscape(domain), nil, body, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// removeCustomDomain unbinds a domain. The API answers 200 also when the
// domain is not bound to the bucket; only a missing bucket is an error.
func (a *api) removeCustomDomain(ctx context.Context, accountID, bucket, domain string) error {
	_, err := a.do(ctx, http.MethodDelete, r2DomainsPath(accountID, bucket)+"/"+url.PathEscape(domain), nil, nil, nil)
	return err
}

// hasCode reports whether err is a Cloudflare API error carrying code.
func hasCode(err error, code int) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	for _, m := range e.Errors {
		if m.Code == code {
			return true
		}
	}
	return false
}

// --- client level ----------------------------------------------------------

// SetPeers implements platform.PeerAware: the other Cloudflare accounts, for
// an R2 bucket that is not in the account of the zone.
func (c *Client) SetPeers(peers func(ctx context.Context) ([]platform.Peer, error)) { c.peers = peers }

// r2Account returns the account R2 requests go to: the pinned account, or
// the only account the credentials see.
func (c *Client) r2Account(ctx context.Context) (string, error) {
	if c.api.accountID != "" {
		return c.api.accountID, nil
	}
	if c.r2AccountID != "" {
		return c.r2AccountID, nil
	}
	accounts, err := c.api.listAccounts(ctx)
	if err != nil {
		return "", fmt.Errorf("cloudflare profile %q pins no account and cannot list its accounts: %w", c.profile.Name, err)
	}
	switch len(accounts) {
	case 0:
		return "", fmt.Errorf("%w: cloudflare profile %q sees no account", platform.ErrNotFound, c.profile.Name)
	case 1:
		c.r2AccountID = accounts[0].ID
		return c.r2AccountID, nil
	}
	return "", fmt.Errorf("%w: cloudflare profile %q sees %d accounts (%s); pin one with `polyctl auth login cloudflare --profile %s --set account_id=<id>`",
		platform.ErrAmbiguous, c.profile.Name, len(accounts), accountNames(accounts), c.profile.Name)
}

// IsR2Record reports whether rec looks like the CNAME of an R2 custom
// domain: a proxied CNAME whose target is an r2.dev host. The bucket is
// named by rec.Meta["r2_bucket"] when Cloudflare created the record.
func IsR2Record(rec platform.Record) bool {
	return strings.EqualFold(rec.Type, "CNAME") && rec.Proxied != nil && *rec.Proxied &&
		strings.Contains(strings.ToLower(rec.Value), "r2.dev")
}

// R2Bucket returns the bucket named in the meta of a record ("" if none).
func R2Bucket(rec platform.Record) string {
	if rec.Meta == nil {
		return ""
	}
	b, _ := rec.Meta["r2_bucket"].(string)
	return strings.TrimSpace(b)
}

var _ platform.RecordUnbinder = (*Client)(nil)
var _ platform.PeerAware = (*Client)(nil)

// Match implements platform.RecordUnbinder for the CNAME records of R2
// custom domains.
func (c *Client) Match(_ platform.Zone, rec platform.Record) (string, bool) {
	if !IsR2Record(rec) {
		return "", false
	}
	if b := R2Bucket(rec); b != "" {
		return "r2 bucket " + b, true
	}
	return "r2 custom domain", true
}

// errR2Managed is the explanation of a record that is left in place.
const errR2Managed = "the CNAME is managed by R2 and cannot be deleted through the DNS API (code 1052)"

// Unbind implements platform.RecordUnbinder: it unbinds the custom domain
// rec.Name from the bucket named in the record's meta, which makes
// Cloudflare delete the record. The account of the zone is tried first. A
// permission failure there stops (it is no sign of the bucket being
// elsewhere); a missing bucket, or another failure, moves on to the other
// Cloudflare accounts, where the domain is unbound only from a bucket that
// lists it (the API reports success for a domain that is not bound).
func (c *Client) Unbind(ctx context.Context, zone platform.Zone, rec platform.Record) (bool, error) {
	bucket := R2Bucket(rec)
	if bucket == "" && zone.ID != "" && rec.ID != "" {
		// A record served from an inventory written before record metadata
		// was kept: read it again for the bucket.
		if cur, err := c.api.getRecord(ctx, zone.ID, rec.ID); err == nil {
			bucket = R2Bucket(toRecord(*cur))
		}
	}
	if bucket == "" {
		return false, fmt.Errorf("no R2 bucket is named in the record (meta.r2_bucket); %s: unbind it in the R2 settings of its bucket", errR2Managed)
	}
	domain := platform.NormalizeDomain(rec.Name)
	acc := ""
	if zone.Extra != nil {
		acc, _ = zone.Extra["account_id"].(string)
	}
	if acc == "" && zone.ID != "" {
		// The zone names no account (the neutral dns commands only know its
		// id): the account that owns the zone is the one to try first.
		if z, err := c.api.getZone(ctx, zone.ID); err == nil {
			acc = z.Account.ID
		}
	}
	if acc == "" {
		var err error
		if acc, err = c.r2Account(ctx); err != nil {
			return false, fmt.Errorf("R2 unbind failed (%v); %s", err, errR2Managed)
		}
	}
	err := c.api.removeCustomDomain(ctx, acc, bucket, domain)
	if err == nil {
		return true, nil
	}
	if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrForbidden) {
		return false, fmt.Errorf("R2 unbind failed: the API token of cloudflare/%s has no R2 permission (%w); %s", c.profile.Name, err, errR2Managed)
	}
	if errors.Is(err, platform.ErrNotSupported) {
		return false, fmt.Errorf("R2 unbind failed: R2 is not enabled on the account of cloudflare/%s (%w); %s", c.profile.Name, err, errR2Managed)
	}
	last := err
	if c.peers != nil {
		peers, perr := c.peers(ctx)
		if perr != nil {
			last = perr
		}
		for _, p := range peers {
			pc, ok := p.Client.(*Client)
			if !ok {
				continue
			}
			pacc, err := pc.r2Account(ctx)
			if err != nil || pacc == acc {
				continue
			}
			domains, err := pc.api.listCustomDomains(ctx, pacc, bucket)
			if err != nil {
				if !errors.Is(err, platform.ErrNotFound) {
					last = err
				}
				continue
			}
			if !slices.ContainsFunc(domains, func(d r2CustomDomain) bool { return platform.NormalizeDomain(d.Domain) == domain }) {
				continue
			}
			if err := pc.api.removeCustomDomain(ctx, pacc, bucket, domain); err != nil {
				last = err
				continue
			}
			return true, nil
		}
	}
	if errors.Is(last, platform.ErrNotFound) {
		return false, fmt.Errorf("R2 unbind failed: bucket %q was not found in any cloudflare profile (%w); %s", bucket, last, errR2Managed)
	}
	return false, fmt.Errorf("R2 unbind failed (%w); %s", last, errR2Managed)
}

// --- validation -------------------------------------------------------------

// NormalizeR2Domain checks and normalizes the <domain> of an R2 custom
// domain: lower case, no trailing dot, at least two labels, no wildcard
// (the API fails with an internal error on one) and no spaces.
func NormalizeR2Domain(s string) (string, error) {
	d := platform.NormalizeDomain(s)
	switch {
	case d == "":
		return "", errors.New("the domain is empty")
	case strings.Contains(d, "*"):
		return "", fmt.Errorf("wildcard domains cannot be bound to an R2 bucket: %q", s)
	case strings.ContainsFunc(d, func(r rune) bool { return r == ' ' || r == '\t' || r == '\n' || r == '/' }):
		return "", fmt.Errorf("invalid domain %q", s)
	case !strings.Contains(d, "."):
		return "", fmt.Errorf("%q is not a fully qualified domain name (cdn.example.com)", s)
	}
	for _, l := range strings.Split(d, ".") {
		if l == "" {
			return "", fmt.Errorf("invalid domain %q", s)
		}
	}
	return d, nil
}

// ValidMinTLS reports whether v is a minimum TLS version the API accepts.
func ValidMinTLS(v string) bool { return slices.Contains(minTLSValues, v) }

// zoneCandidates lists the names a zone of domain may have, longest first,
// down to two labels: cdn.a.example.com, a.example.com, example.com.
func zoneCandidates(domain string) []string {
	labels := strings.Split(domain, ".")
	var out []string
	for i := 0; i+2 <= len(labels); i++ {
		out = append(out, strings.Join(labels[i:], "."))
	}
	return out
}

// underZone reports whether domain is zone or a name in it.
func underZone(domain, zone string) bool {
	return domain == zone || strings.HasSuffix(domain, "."+zone)
}
