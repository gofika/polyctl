package namecom

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/platform"
)

// Environments of the name.com Core API v4.
const (
	envProduction = "production"
	envTest       = "test"
)

// baseURLs maps an environment to its API endpoint. Tests override entries
// to point at a fake server.
var baseURLs = map[string]string{
	envProduction: "https://api.name.com",
	envTest:       "https://api.dev.name.com",
}

// apiTokenURL is where API tokens are created in the name.com account UI.
const apiTokenURL = "https://www.name.com/account/settings/api"

// perPage is the maximum page size accepted by the list endpoints.
const perPage = 1000

// normalizeEnv maps user-supplied environment names onto the two known
// environments; "" is the default production environment.
func normalizeEnv(s string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", envProduction, "prod":
		return envProduction, nil
	case envTest, "dev", "development":
		return envTest, nil
	}
	return "", fmt.Errorf("unknown name.com environment %q (expected production or test)", s)
}

// Client is an authenticated name.com Core API v4 session. It implements
// platform.Client, platform.DNSService and platform.RegistrarService.
type Client struct {
	api      *httpx.Client
	username string
	env      string
	now      func() time.Time
}

var (
	_ platform.Client           = (*Client)(nil)
	_ platform.DNSService       = (*Client)(nil)
	_ platform.RegistrarService = (*Client)(nil)
)

// newClient builds a client bound to baseURL using HTTP Basic auth.
func newClient(baseURL, env, username, token string) *Client {
	api := httpx.New(baseURL, func(r *http.Request) {
		r.SetBasicAuth(username, token)
	})
	return &Client{api: api, username: username, env: env, now: time.Now}
}

// --- wire types -----------------------------------------------------------

type helloResponse struct {
	ServerName string `json:"serverName"`
	Motd       string `json:"motd"`
	Username   string `json:"username"`
	ServerTime string `json:"serverTime"`
}

type apiDomain struct {
	DomainName       string   `json:"domainName"`
	Nameservers      []string `json:"nameservers"`
	PrivacyEnabled   bool     `json:"privacyEnabled"`
	Locked           bool     `json:"locked"`
	AutorenewEnabled bool     `json:"autorenewEnabled"`
	ExpireDate       string   `json:"expireDate"`
	CreateDate       string   `json:"createDate"`
	RenewalPrice     float64  `json:"renewalPrice"`
}

type domainsPage struct {
	Domains  []apiDomain `json:"domains"`
	NextPage int         `json:"nextPage"`
	LastPage int         `json:"lastPage"`
}

type apiRecord struct {
	ID         int64  `json:"id"`
	DomainName string `json:"domainName"`
	Host       string `json:"host"`
	FQDN       string `json:"fqdn"`
	Type       string `json:"type"`
	Answer     string `json:"answer"`
	TTL        int    `json:"ttl"`
	Priority   *int   `json:"priority,omitempty"`
}

// apiRecordWrite is the body of record create/update calls. Host is sent
// even when empty because an empty host designates the apex.
type apiRecordWrite struct {
	Host     string `json:"host"`
	Type     string `json:"type"`
	Answer   string `json:"answer"`
	TTL      int    `json:"ttl,omitempty"`
	Priority *int   `json:"priority,omitempty"`
}

type recordsPage struct {
	Records  []apiRecord `json:"records"`
	NextPage int         `json:"nextPage"`
	LastPage int         `json:"lastPage"`
}

// Availability is one entry of a checkAvailability response.
type Availability struct {
	DomainName    string  `json:"domain_name" yaml:"domain_name"`
	SLD           string  `json:"sld,omitempty" yaml:"sld,omitempty"`
	TLD           string  `json:"tld,omitempty" yaml:"tld,omitempty"`
	Purchasable   bool    `json:"purchasable" yaml:"purchasable"`
	Premium       bool    `json:"premium" yaml:"premium"`
	PurchasePrice float64 `json:"purchase_price,omitempty" yaml:"purchase_price,omitempty"`
	PurchaseType  string  `json:"purchase_type,omitempty" yaml:"purchase_type,omitempty"`
	RenewalPrice  float64 `json:"renewal_price,omitempty" yaml:"renewal_price,omitempty"`
}

type availabilityResponse struct {
	Results []struct {
		DomainName    string  `json:"domainName"`
		SLD           string  `json:"sld"`
		TLD           string  `json:"tld"`
		Purchasable   bool    `json:"purchasable"`
		Premium       bool    `json:"premium"`
		PurchasePrice float64 `json:"purchasePrice"`
		PurchaseType  string  `json:"purchaseType"`
		RenewalPrice  float64 `json:"renewalPrice"`
	} `json:"results"`
}

// --- conversions ------------------------------------------------------------

// toDomain maps a name.com domain onto the neutral Domain type. now is used
// to derive the status from the expiry date.
func toDomain(d apiDomain, now time.Time) platform.Domain {
	auto, locked, privacy := d.AutorenewEnabled, d.Locked, d.PrivacyEnabled
	out := platform.Domain{
		Name:        platform.NormalizeDomain(d.DomainName),
		Nameservers: d.Nameservers,
		Status:      "active",
		ExpiresAt:   d.ExpireDate,
		AutoRenew:   &auto,
		Locked:      &locked,
		Privacy:     &privacy,
		Extra:       map[string]any{},
	}
	if t, err := time.Parse(time.RFC3339, d.ExpireDate); err == nil && t.Before(now) {
		out.Status = "expired"
	}
	if d.CreateDate != "" {
		out.Extra["createDate"] = d.CreateDate
	}
	if d.RenewalPrice != 0 {
		out.Extra["renewalPrice"] = d.RenewalPrice
	}
	if len(out.Extra) == 0 {
		out.Extra = nil
	}
	return out
}

// Zone statuses. A registered domain is only an "active" zone when name.com
// actually serves its DNS; otherwise the records name.com keeps for it are
// dormant and the domain must not be routed to name.com for DNS operations.
const (
	zoneActive   = "active"
	zoneInactive = "inactive"
)

// nameComNSSuffix matches name.com's own nameservers (ns1..ns4.name.com and
// the per-account ns1xxx.name.com hosts).
const nameComNSSuffix = ".name.com"

// hostedAtNameCom reports whether at least one nameserver is a name.com host,
// i.e. whether name.com serves the DNS of the domain.
func hostedAtNameCom(nameservers []string) bool {
	for _, ns := range nameservers {
		if strings.HasSuffix(platform.NormalizeDomain(ns), nameComNSSuffix) {
			return true
		}
	}
	return false
}

// zoneFromDomain views a registered domain as the zone name.com serves for
// it. Domains whose DNS is hosted elsewhere are marked inactive.
func zoneFromDomain(name string, nameservers []string) platform.Zone {
	name = platform.NormalizeDomain(name)
	z := platform.Zone{ID: name, Name: name, Nameservers: nameservers, Status: zoneActive}
	if !hostedAtNameCom(nameservers) {
		z.Status = zoneInactive
	}
	return z
}

// toZone views a name.com domain as the DNS zone it serves.
func toZone(d apiDomain) platform.Zone {
	return zoneFromDomain(d.DomainName, d.Nameservers)
}

// activeZones drops the zones whose DNS is not hosted at name.com.
func activeZones(zones []platform.Zone) []platform.Zone {
	out := zones[:0:0]
	for _, z := range zones {
		if z.Status == zoneActive {
			out = append(out, z)
		}
	}
	return out
}

// hasPriority reports whether a record type carries a priority on name.com.
func hasPriority(typ string) bool {
	switch strings.ToUpper(typ) {
	case "MX", "SRV":
		return true
	}
	return false
}

// toRecord maps a name.com record onto the neutral Record type. Name is the
// FQDN without trailing dot; an empty host means the zone apex.
func toRecord(r apiRecord, domain string) platform.Record {
	domain = platform.NormalizeDomain(domain)
	name := platform.NormalizeDomain(r.FQDN)
	if name == "" {
		name = platform.FQDN(r.Host, domain)
	}
	rec := platform.Record{
		ID:      strconv.FormatInt(r.ID, 10),
		ZoneID:  domain,
		Name:    name,
		Type:    strings.ToUpper(r.Type),
		Content: r.Answer,
		TTL:     r.TTL,
	}
	if r.Priority != nil && hasPriority(rec.Type) {
		p := *r.Priority
		rec.Priority = &p
	}
	return rec
}

// fromRecord builds the write body for a neutral record. The name must be
// the apex or lie inside the zone; the apex is written as an empty host.
func fromRecord(r platform.Record, domain string) (apiRecordWrite, error) {
	domain = platform.NormalizeDomain(domain)
	name := platform.NormalizeDomain(r.Name)
	if name == "" || name == "@" {
		name = domain
	}
	if name != domain && !strings.HasSuffix(name, "."+domain) {
		return apiRecordWrite{}, fmt.Errorf("record name %q is not inside zone %q", r.Name, domain)
	}
	host := platform.RelativeName(name, domain)
	if host == "@" {
		host = ""
	}
	w := apiRecordWrite{Host: host, Type: strings.ToUpper(r.Type), Answer: r.Content, TTL: r.TTL}
	if r.Priority != nil && hasPriority(w.Type) {
		p := *r.Priority
		w.Priority = &p
	}
	return w, nil
}

// parseRecordID validates a record id (name.com ids are integers).
func parseRecordID(id string) (int64, error) {
	n, err := strconv.ParseInt(strings.TrimSpace(id), 10, 64)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("%w: invalid name.com record id %q (expected a positive integer)", platform.ErrNotFound, id)
	}
	return n, nil
}

func domainPath(name string) string {
	return "/v4/domains/" + url.PathEscape(platform.NormalizeDomain(name))
}

// --- platform.Client --------------------------------------------------------

// hello calls GET /v4/hello, the cheapest authenticated endpoint.
func (c *Client) hello(ctx context.Context) (*helloResponse, error) {
	var out helloResponse
	if err := c.api.Get(ctx, "/v4/hello", nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// Verify checks the credentials against GET /v4/hello.
func (c *Client) Verify(ctx context.Context) (*platform.Identity, error) {
	h, err := c.hello(ctx)
	if err != nil {
		return nil, err
	}
	user := h.Username
	if user == "" {
		user = c.username
	}
	extra := map[string]string{"env": c.env}
	if h.ServerTime != "" {
		extra["server_time"] = h.ServerTime
	}
	if h.ServerName != "" {
		extra["server_name"] = h.ServerName
	}
	return &platform.Identity{Account: user, User: user, Extra: extra}, nil
}

// Sync fetches every resource of a type for the inventory.
func (c *Client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	switch rt {
	case platform.ResDomain:
		domains, err := c.ListDomains(ctx)
		if err != nil {
			return nil, err
		}
		return app.DomainResources(domains), nil
	case platform.ResZone:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		// Only zones name.com actually serves are indexed, so that neutral
		// domain routing does not see a second owner for domains whose DNS
		// lives elsewhere.
		return app.ZoneResources(activeZones(zones)), nil
	case platform.ResDNSRecord:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		var out []platform.Resource
		for _, z := range activeZones(zones) {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			recs, err := c.ListRecords(ctx, z.ID)
			if err != nil {
				return nil, fmt.Errorf("records of %s: %w", z.Name, err)
			}
			out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}

// --- registrar --------------------------------------------------------------

// listDomains pages through GET /v4/domains.
func (c *Client) listDomains(ctx context.Context) ([]apiDomain, error) {
	var out []apiDomain
	page := 1
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "perPage": {strconv.Itoa(perPage)}}
		var resp domainsPage
		if err := c.api.Get(ctx, "/v4/domains", q, &resp); err != nil {
			return nil, err
		}
		out = append(out, resp.Domains...)
		if resp.NextPage <= page || len(resp.Domains) == 0 {
			return out, nil
		}
		page = resp.NextPage
	}
}

// ListDomains returns every registered domain of the account.
func (c *Client) ListDomains(ctx context.Context) ([]platform.Domain, error) {
	raw, err := c.listDomains(ctx)
	if err != nil {
		return nil, err
	}
	now := c.now()
	out := make([]platform.Domain, 0, len(raw))
	for _, d := range raw {
		out = append(out, toDomain(d, now))
	}
	return out, nil
}

// getDomain fetches one domain.
func (c *Client) getDomain(ctx context.Context, name string) (*apiDomain, error) {
	var d apiDomain
	if err := c.api.Get(ctx, domainPath(name), nil, &d); err != nil {
		return nil, err
	}
	return &d, nil
}

// GetDomain returns one registered domain.
func (c *Client) GetDomain(ctx context.Context, name string) (*platform.Domain, error) {
	d, err := c.getDomain(ctx, name)
	if err != nil {
		return nil, err
	}
	out := toDomain(*d, c.now())
	return &out, nil
}

// domainAction POSTs to /v4/domains/{name}:<action> and returns the updated domain.
func (c *Client) domainAction(ctx context.Context, name, action string, body any) (*platform.Domain, error) {
	var d apiDomain
	if err := c.api.Do(ctx, http.MethodPost, domainPath(name)+":"+action, nil, body, &d); err != nil {
		return nil, err
	}
	if d.DomainName == "" {
		// Some actions return an empty body; re-read the domain.
		return c.GetDomain(ctx, name)
	}
	out := toDomain(d, c.now())
	return &out, nil
}

// SetNameservers replaces the nameservers of a domain.
func (c *Client) SetNameservers(ctx context.Context, name string, ns []string) error {
	clean := make([]string, 0, len(ns))
	for _, n := range ns {
		if n = platform.NormalizeDomain(n); n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 {
		return errors.New("at least one nameserver is required")
	}
	_, err := c.domainAction(ctx, name, "setNameservers", map[string][]string{"nameservers": clean})
	return err
}

// SetNameserversDomain is SetNameservers that also returns the updated domain.
func (c *Client) SetNameserversDomain(ctx context.Context, name string, ns []string) (*platform.Domain, error) {
	if err := c.SetNameservers(ctx, name, ns); err != nil {
		return nil, err
	}
	return c.GetDomain(ctx, name)
}

// SetLock locks or unlocks a domain against transfers.
func (c *Client) SetLock(ctx context.Context, name string, locked bool) (*platform.Domain, error) {
	action := "unlock"
	if locked {
		action = "lock"
	}
	return c.domainAction(ctx, name, action, struct{}{})
}

// SetAutorenew enables or disables automatic renewal.
func (c *Client) SetAutorenew(ctx context.Context, name string, enabled bool) (*platform.Domain, error) {
	action := "disableAutorenew"
	if enabled {
		action = "enableAutorenew"
	}
	return c.domainAction(ctx, name, action, struct{}{})
}

// maxAvailabilityNames is the most domain names one checkAvailability call
// accepts ("A Maximum of 50 domains can be specified").
const maxAvailabilityNames = 50

// CheckAvailability reports whether domains can be purchased and at what
// price. Names are checked in batches of maxAvailabilityNames; results keep
// the input order.
func (c *Client) CheckAvailability(ctx context.Context, names []string) ([]Availability, error) {
	clean := make([]string, 0, len(names))
	for _, n := range names {
		if n = platform.NormalizeDomain(n); n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) == 0 {
		return nil, errors.New("at least one domain name is required")
	}
	out := make([]Availability, 0, len(clean))
	for start := 0; start < len(clean); start += maxAvailabilityNames {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		end := min(start+maxAvailabilityNames, len(clean))
		var resp availabilityResponse
		if err := c.api.Do(ctx, http.MethodPost, "/v4/domains:checkAvailability", nil, map[string][]string{"domainNames": clean[start:end]}, &resp); err != nil {
			return nil, err
		}
		for _, r := range resp.Results {
			out = append(out, Availability{
				DomainName: platform.NormalizeDomain(r.DomainName), SLD: r.SLD, TLD: r.TLD,
				Purchasable: r.Purchasable, Premium: r.Premium,
				PurchasePrice: r.PurchasePrice, PurchaseType: r.PurchaseType, RenewalPrice: r.RenewalPrice,
			})
		}
	}
	return out, nil
}

// --- DNS ------------------------------------------------------------------

// ListZones views each registered domain as a zone. Domains whose
// nameservers are not name.com's are returned with Status "inactive":
// name.com keeps records for them but does not serve them, and Sync leaves
// them out of the inventory.
func (c *Client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	raw, err := c.listDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Zone, 0, len(raw))
	for _, d := range raw {
		out = append(out, toZone(d))
	}
	return out, nil
}

// ListRecords pages through the records of a domain (zoneID = domain name).
func (c *Client) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	domain := platform.NormalizeDomain(zoneID)
	var out []platform.Record
	page := 1
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		q := url.Values{"page": {strconv.Itoa(page)}, "perPage": {strconv.Itoa(perPage)}}
		var resp recordsPage
		if err := c.api.Get(ctx, domainPath(domain)+"/records", q, &resp); err != nil {
			return nil, err
		}
		for _, r := range resp.Records {
			out = append(out, toRecord(r, domain))
		}
		if resp.NextPage <= page || len(resp.Records) == 0 {
			return out, nil
		}
		page = resp.NextPage
	}
}

// CreateRecord creates a record in the zone.
func (c *Client) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	domain := platform.NormalizeDomain(zoneID)
	body, err := fromRecord(r, domain)
	if err != nil {
		return nil, err
	}
	var resp apiRecord
	if err := c.api.Do(ctx, http.MethodPost, domainPath(domain)+"/records", nil, body, &resp); err != nil {
		return nil, err
	}
	out := toRecord(resp, domain)
	return &out, nil
}

// UpdateRecord replaces the record identified by r.ID.
func (c *Client) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	domain := platform.NormalizeDomain(zoneID)
	id, err := parseRecordID(r.ID)
	if err != nil {
		return nil, err
	}
	body, err := fromRecord(r, domain)
	if err != nil {
		return nil, err
	}
	var resp apiRecord
	if err := c.api.Do(ctx, http.MethodPut, domainPath(domain)+"/records/"+strconv.FormatInt(id, 10), nil, body, &resp); err != nil {
		return nil, err
	}
	out := toRecord(resp, domain)
	return &out, nil
}

// GetRecord fetches one record by id.
func (c *Client) GetRecord(ctx context.Context, zoneID, recordID string) (*platform.Record, error) {
	domain := platform.NormalizeDomain(zoneID)
	id, err := parseRecordID(recordID)
	if err != nil {
		return nil, err
	}
	var resp apiRecord
	if err := c.api.Get(ctx, domainPath(domain)+"/records/"+strconv.FormatInt(id, 10), nil, &resp); err != nil {
		return nil, err
	}
	out := toRecord(resp, domain)
	return &out, nil
}

// DeleteRecord deletes a record by id.
func (c *Client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	domain := platform.NormalizeDomain(zoneID)
	id, err := parseRecordID(recordID)
	if err != nil {
		return err
	}
	return c.api.Do(ctx, http.MethodDelete, domainPath(domain)+"/records/"+strconv.FormatInt(id, 10), nil, nil, nil)
}
