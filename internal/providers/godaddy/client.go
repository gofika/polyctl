package godaddy

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// client is an authenticated GoDaddy session. It implements
// platform.Client, platform.DNSService and platform.RegistrarService.
type client struct {
	api  *api
	env  string
	cred credentials
	// pace is the delay between per-domain requests in Sync (see syncPace).
	pace time.Duration
}

var (
	_ platform.Client           = (*client)(nil)
	_ platform.DNSService       = (*client)(nil)
	_ platform.RegistrarService = (*client)(nil)
)

func newClient(baseURL, env string, cred credentials) *client {
	if baseURL == "" {
		baseURL = baseURLFor(env)
	}
	return &client{api: newAPI(baseURL, cred), env: env, cred: cred, pace: syncPace}
}

// Verify checks the credentials with a one-domain listing (GoDaddy has no
// "who am I" endpoint usable with API credentials).
func (c *client) Verify(ctx context.Context) (*platform.Identity, error) {
	page, err := c.api.listDomainsPage(ctx, 1, "", nil)
	if err != nil {
		return nil, err
	}
	id := &platform.Identity{
		Account: c.cred.label(),
		Extra:   map[string]string{"env": c.env, "method": c.cred.method()},
	}
	if len(page) > 0 {
		id.Extra["first_domain"] = page[0].Domain
	} else {
		id.Extra["domains"] = "none"
	}
	return id, nil
}

// Sync fetches all resources of a type.
func (c *client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
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
		return app.ZoneResources(zones), nil
	case platform.ResDNSRecord:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		var out []platform.Resource
		for i, z := range zones {
			// One request per domain: stay under GoDaddy's per-minute limit.
			if i > 0 && c.pace > 0 {
				timer := time.NewTimer(c.pace)
				select {
				case <-ctx.Done():
					timer.Stop()
					return nil, ctx.Err()
				case <-timer.C:
				}
			}
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			recs, err := c.ListRecords(ctx, z.ID)
			if err != nil {
				// Domains without a GoDaddy-hosted zone answer 404; skip them.
				if errors.Is(err, platform.ErrNotFound) {
					continue
				}
				return nil, err
			}
			out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
		}
		return out, nil
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}

// ---- RegistrarService ----

// ListDomains returns every domain of the account (all statuses).
func (c *client) ListDomains(ctx context.Context) ([]platform.Domain, error) {
	return c.listDomains(ctx, nil)
}

func (c *client) listDomains(ctx context.Context, statuses []string) ([]platform.Domain, error) {
	raw, err := c.api.listDomains(ctx, statuses)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Domain, 0, len(raw))
	for _, d := range raw {
		out = append(out, domainFromAPI(d))
	}
	return out, nil
}

// GetDomain returns the registrar view of one domain.
func (c *client) GetDomain(ctx context.Context, name string) (*platform.Domain, error) {
	raw, err := c.api.getDomain(ctx, platform.NormalizeDomain(name))
	if err != nil {
		return nil, err
	}
	d := domainFromAPI(*raw)
	return &d, nil
}

// SetNameservers replaces the nameservers of a domain.
func (c *client) SetNameservers(ctx context.Context, name string, ns []string) error {
	var clean []string
	for _, n := range ns {
		if n = platform.NormalizeDomain(n); n != "" {
			clean = append(clean, n)
		}
	}
	if len(clean) < 2 {
		return fmt.Errorf("at least two nameservers are required")
	}
	return c.api.patchDomain(ctx, platform.NormalizeDomain(name), domainPatch{NameServers: clean})
}

// SetLocked enables or disables the registrar transfer lock.
func (c *client) SetLocked(ctx context.Context, name string, locked bool) error {
	return c.api.patchDomain(ctx, platform.NormalizeDomain(name), domainPatch{Locked: &locked})
}

// SetAutoRenew enables or disables automatic renewal.
func (c *client) SetAutoRenew(ctx context.Context, name string, on bool) error {
	return c.api.patchDomain(ctx, platform.NormalizeDomain(name), domainPatch{RenewAuto: &on})
}

// Availability is the result of a domain availability check.
type Availability struct {
	Domain     string `json:"domain" yaml:"domain"`
	Available  bool   `json:"available" yaml:"available"`
	Definitive bool   `json:"definitive" yaml:"definitive"`
	// Price is in micro-units of Currency (GoDaddy returns 1,000,000 = 1.00).
	Price    int64  `json:"price,omitempty" yaml:"price,omitempty"`
	Currency string `json:"currency,omitempty" yaml:"currency,omitempty"`
	Period   int    `json:"period,omitempty" yaml:"period,omitempty"`
}

// CheckAvailable queries whether a domain can be registered.
func (c *client) CheckAvailable(ctx context.Context, name string) (*Availability, error) {
	raw, err := c.api.available(ctx, platform.NormalizeDomain(name))
	if err != nil {
		return nil, err
	}
	return &Availability{Domain: platform.NormalizeDomain(raw.Domain), Available: raw.Available, Definitive: raw.Definitive, Price: raw.Price, Currency: raw.Currency, Period: raw.Period}, nil
}

// ---- DNSService ----

// ListZones exposes every domain as a zone (Zone.ID == Zone.Name == domain).
func (c *client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	domains, err := c.ListDomains(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Zone, 0, len(domains))
	for _, d := range domains {
		out = append(out, zoneFromDomain(d))
	}
	return out, nil
}

// ListRecords returns the records of a zone with FQDN names.
func (c *client) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	zone := platform.NormalizeDomain(zoneID)
	raw, err := c.api.listRecords(ctx, zone)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Record, 0, len(raw))
	for _, r := range raw {
		out = append(out, recordFromAPI(zone, r))
	}
	return out, nil
}

// CreateRecord adds a record (PATCH /records keeps existing ones).
func (c *client) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	zone := platform.NormalizeDomain(zoneID)
	ar, err := recordToAPI(zone, r)
	if err != nil {
		return nil, err
	}
	if err := c.api.addRecords(ctx, zone, []apiRecord{ar}); err != nil {
		return nil, err
	}
	out := recordFromAPI(zone, ar)
	return &out, nil
}

// UpdateRecord replaces the record identified by r.ID with r. When the
// type or name changes, the new record is added to its (different) set
// first and the old one removed afterwards, so a failed add leaves the
// original untouched; otherwise the entry is swapped inside its type+name
// set. Because GoDaddy ids are derived from the record values, the
// returned record has a new ID whenever the content changes.
func (c *client) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	zone := platform.NormalizeDomain(zoneID)
	oldType, oldName, oldData, err := DecodeRecordID(r.ID)
	if err != nil {
		return nil, err
	}
	ar, err := recordToAPI(zone, r)
	if err != nil {
		return nil, err
	}
	if ar.Type != oldType || ar.Name != oldName {
		// Make sure the old record exists before touching anything.
		set, err := c.api.recordSet(ctx, zone, oldType, oldName)
		if err != nil {
			return nil, err
		}
		if indexOfData(set, oldData) < 0 {
			return nil, fmt.Errorf("%w: %s %s %q in zone %s", platform.ErrNotFound, oldType, oldName, oldData, zone)
		}
		if err := c.api.addRecords(ctx, zone, []apiRecord{ar}); err != nil {
			return nil, err
		}
		out := recordFromAPI(zone, ar)
		if err := c.removeFromSet(ctx, zone, oldType, oldName, oldData); err != nil {
			return nil, fmt.Errorf("new record %s was added but the old record could not be removed (delete it with `polyctl dns delete %s --id %q`): %w", out.ID, zone, r.ID, err)
		}
		return &out, nil
	}
	set, err := c.api.recordSet(ctx, zone, oldType, oldName)
	if err != nil {
		return nil, err
	}
	idx := indexOfData(set, oldData)
	if idx < 0 {
		return nil, fmt.Errorf("%w: %s %s %q in zone %s", platform.ErrNotFound, oldType, oldName, oldData, zone)
	}
	set[idx] = ar
	if err := c.api.replaceRecordSet(ctx, zone, oldType, oldName, set); err != nil {
		return nil, err
	}
	out := recordFromAPI(zone, ar)
	return &out, nil
}

// DeleteRecord removes one record. The rest of its type+name set is kept.
func (c *client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	zone := platform.NormalizeDomain(zoneID)
	typ, name, data, err := DecodeRecordID(recordID)
	if err != nil {
		return err
	}
	return c.removeFromSet(ctx, zone, typ, name, data)
}

// removeFromSet deletes the entry with data from the type+name set: DELETE
// when it is the only entry, PUT with the remaining entries otherwise.
func (c *client) removeFromSet(ctx context.Context, zone, typ, name, data string) error {
	set, err := c.api.recordSet(ctx, zone, typ, name)
	if err != nil {
		return err
	}
	idx := indexOfData(set, data)
	if idx < 0 {
		return fmt.Errorf("%w: %s %s %q in zone %s", platform.ErrNotFound, typ, name, data, zone)
	}
	if len(set) == 1 {
		return c.api.deleteRecordSet(ctx, zone, typ, name)
	}
	rest := append(append([]apiRecord(nil), set[:idx]...), set[idx+1:]...)
	return c.api.replaceRecordSet(ctx, zone, typ, name, rest)
}

// ReplaceRecords replaces the whole type+name set with recs. An empty recs
// deletes the set. Names of recs are ignored; relName ("@" for the apex)
// decides the owner. Returns the new records.
func (c *client) ReplaceRecords(ctx context.Context, zoneID, typ, relName string, recs []platform.Record) ([]platform.Record, error) {
	zone := platform.NormalizeDomain(zoneID)
	typ = strings.ToUpper(typ)
	if relName == "" {
		relName = "@"
	}
	if len(recs) == 0 {
		return nil, c.api.deleteRecordSet(ctx, zone, typ, relName)
	}
	body := make([]apiRecord, 0, len(recs))
	out := make([]platform.Record, 0, len(recs))
	for _, r := range recs {
		r.Type = typ
		r.Name = platform.FQDN(relName, zone)
		ar, err := recordToAPI(zone, r)
		if err != nil {
			return nil, err
		}
		body = append(body, ar)
		out = append(out, recordFromAPI(zone, ar))
	}
	if err := c.api.replaceRecordSet(ctx, zone, typ, relName, body); err != nil {
		return nil, err
	}
	return out, nil
}

// DeleteRecordSet deletes every record of type+name.
func (c *client) DeleteRecordSet(ctx context.Context, zoneID, typ, relName string) error {
	if relName == "" {
		relName = "@"
	}
	return c.api.deleteRecordSet(ctx, platform.NormalizeDomain(zoneID), strings.ToUpper(typ), relName)
}

func indexOfData(set []apiRecord, data string) int {
	for i, r := range set {
		if r.Data == data {
			return i
		}
	}
	return -1
}
