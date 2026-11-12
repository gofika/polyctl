package app_test

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// The fake providers are registered once per test binary under the
// name.com and GoDaddy ids; the app package does not import the real
// providers, so nothing else claims those ids here.
var (
	registerOnce sync.Once
	fakeMu       sync.Mutex
	fakeClients  = map[string]*fakeClient{}
)

func registerFakes() {
	registerOnce.Do(func() {
		platform.Register(&fakeProvider{id: platform.NameCom, name: "fake name.com"})
		platform.Register(&fakeProvider{id: platform.GoDaddy, name: "fake GoDaddy"})
	})
}

func resetFakes() {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	fakeClients = map[string]*fakeClient{}
}

// clientFor returns the fake client backing a profile's account on a
// platform, creating it on demand. Clients are keyed by account, so one
// profile holding both fake platforms gets two independent clients.
func clientFor(profile string, id platform.ID) *fakeClient {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	key := profile + "/" + string(id)
	c := fakeClients[key]
	if c == nil {
		c = &fakeClient{id: id, records: map[string][]platform.Record{}}
		fakeClients[key] = c
	}
	return c
}

type fakeProvider struct {
	id   platform.ID
	name string
}

func (p *fakeProvider) ID() platform.ID        { return p.id }
func (p *fakeProvider) DisplayName() string    { return p.name }
func (p *fakeProvider) LoginHelp() string      { return "fake login" }
func (p *fakeProvider) LoginOptions() []string { return nil }
func (p *fakeProvider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResDomain}
}

func (p *fakeProvider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	return &platform.LoginResult{Secret: map[string]string{"token": "fake"}, Metadata: map[string]string{"account": in.ProfileName}, Label: in.ProfileName}, nil
}

func (p *fakeProvider) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	if prof.Secret["token"] == "" {
		return nil, fmt.Errorf("%w: missing token", platform.ErrUnauthorized)
	}
	c := clientFor(prof.Name, p.id)
	c.record("Open")
	if c.noDNS {
		return &plainClient{c: c}, nil
	}
	return c, nil
}

// fakeClient is an in-memory platform with zones, records and domains. It
// records every call so tests can assert what reached the "network".
type fakeClient struct {
	id      platform.ID
	mu      sync.Mutex
	zones   []platform.Zone
	records map[string][]platform.Record
	domains []platform.Domain
	calls   []string
	nextID  int
	noDNS   bool
	syncErr error
}

func (c *fakeClient) record(call string) {
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
}

// count returns how many recorded calls start with prefix.
func (c *fakeClient) count(prefix string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	n := 0
	for _, x := range c.calls {
		if strings.HasPrefix(x, prefix) {
			n++
		}
	}
	return n
}

func (c *fakeClient) Verify(ctx context.Context) (*platform.Identity, error) {
	c.record("Verify")
	return &platform.Identity{Account: "fake-account-" + string(c.id)}, nil
}

func (c *fakeClient) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	c.record("Sync:" + string(rt))
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.syncErr != nil {
		return nil, c.syncErr
	}
	switch rt {
	case platform.ResZone:
		return app.ZoneResources(c.zones), nil
	case platform.ResDNSRecord:
		var out []platform.Resource
		for _, z := range c.zones {
			out = append(out, app.RecordResources(z.ID, z.Name, c.records[z.ID])...)
		}
		return out, nil
	case platform.ResDomain:
		return app.DomainResources(c.domains), nil
	}
	return nil, platform.ErrNotSupported
}

func (c *fakeClient) ListZones(ctx context.Context) ([]platform.Zone, error) {
	c.record("ListZones")
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]platform.Zone(nil), c.zones...), nil
}

func (c *fakeClient) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	c.record("ListRecords:" + zoneID)
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]platform.Record(nil), c.records[zoneID]...), nil
}

func (c *fakeClient) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	c.record("CreateRecord:" + r.Name + ":" + r.Type)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.nextID++
	r.ID = fmt.Sprintf("r%d", c.nextID)
	r.ZoneID = zoneID
	c.records[zoneID] = append(c.records[zoneID], r)
	out := r
	return &out, nil
}

func (c *fakeClient) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	c.record("UpdateRecord:" + r.ID)
	c.mu.Lock()
	defer c.mu.Unlock()
	for i, x := range c.records[zoneID] {
		if x.ID == r.ID {
			r.ZoneID = zoneID
			c.records[zoneID][i] = r
			out := r
			return &out, nil
		}
	}
	return nil, platform.ErrNotFound
}

func (c *fakeClient) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	c.record("DeleteRecord:" + recordID)
	c.mu.Lock()
	defer c.mu.Unlock()
	recs := c.records[zoneID]
	for i, x := range recs {
		if x.ID == recordID {
			c.records[zoneID] = append(recs[:i:i], recs[i+1:]...)
			return nil
		}
	}
	return platform.ErrNotFound
}

func (c *fakeClient) ListDomains(ctx context.Context) ([]platform.Domain, error) {
	c.record("ListDomains")
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]platform.Domain(nil), c.domains...), nil
}

func (c *fakeClient) GetDomain(ctx context.Context, name string) (*platform.Domain, error) {
	c.record("GetDomain:" + name)
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, d := range c.domains {
		if d.Name == platform.NormalizeDomain(name) {
			out := d
			return &out, nil
		}
	}
	return nil, platform.ErrNotFound
}

func (c *fakeClient) SetNameservers(ctx context.Context, name string, ns []string) error {
	c.record("SetNameservers:" + name)
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := range c.domains {
		if c.domains[i].Name == platform.NormalizeDomain(name) {
			c.domains[i].Nameservers = append([]string(nil), ns...)
			return nil
		}
	}
	return platform.ErrNotFound
}

// plainClient implements only platform.Client (no DNS or registrar service).
type plainClient struct{ c *fakeClient }

func (p *plainClient) Verify(ctx context.Context) (*platform.Identity, error) { return p.c.Verify(ctx) }
func (p *plainClient) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	return p.c.Sync(ctx, rt)
}

var (
	_ platform.Provider         = (*fakeProvider)(nil)
	_ platform.Client           = (*fakeClient)(nil)
	_ platform.DNSService       = (*fakeClient)(nil)
	_ platform.RegistrarService = (*fakeClient)(nil)
	_ platform.Client           = (*plainClient)(nil)
)
