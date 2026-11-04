package cli

import (
	"context"
	"fmt"
	"strings"
	"sync"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// fakePlatform is the id the fake provider is installed under. The cli
// package links the real providers, so the fake replaces the real Cloudflare
// provider through platform.Override for the duration of the test binary.
const fakePlatform = platform.Cloudflare

var (
	registerOnce sync.Once
	fakeMu       sync.Mutex
	fakeClients  = map[string]*fakeClient{}
)

func registerFake() {
	registerOnce.Do(func() { platform.Override(&fakeProvider{}) })
}

func resetFake() {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	fakeClients = map[string]*fakeClient{}
}

// client returns the fake client backing a profile, creating it on demand.
func client(profile string) *fakeClient {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	c := fakeClients[profile]
	if c == nil {
		c = &fakeClient{records: map[string][]platform.Record{}}
		fakeClients[profile] = c
	}
	return c
}

type fakeProvider struct{}

func (*fakeProvider) ID() platform.ID     { return fakePlatform }
func (*fakeProvider) DisplayName() string { return "Fake DNS" }
func (*fakeProvider) LoginHelp() string   { return "fake login" }
func (*fakeProvider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResDomain}
}

func (*fakeProvider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	return &platform.LoginResult{Secret: map[string]string{"token": "fake"}, Label: in.ProfileName}, nil
}

func (*fakeProvider) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	if prof.Secret["token"] == "" {
		return nil, fmt.Errorf("%w: missing token", platform.ErrUnauthorized)
	}
	c := client(prof.Name)
	c.record("Open")
	return c, nil
}

// fakeClient is an in-memory DNS platform that records every call.
type fakeClient struct {
	mu      sync.Mutex
	zones   []platform.Zone
	records map[string][]platform.Record
	domains []platform.Domain
	calls   []string
	nextID  int
}

func (c *fakeClient) record(call string) {
	c.mu.Lock()
	c.calls = append(c.calls, call)
	c.mu.Unlock()
}

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
	return &platform.Identity{Account: "fake-account"}, nil
}

func (c *fakeClient) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	c.record("Sync:" + string(rt))
	c.mu.Lock()
	defer c.mu.Unlock()
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

var (
	_ platform.Provider         = (*fakeProvider)(nil)
	_ platform.DNSService       = (*fakeClient)(nil)
	_ platform.RegistrarService = (*fakeClient)(nil)
)
