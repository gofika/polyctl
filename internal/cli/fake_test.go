package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// fakePlatform is the id the fake provider is installed under. The cli
// package links the real providers, so the fake replaces the real Cloudflare
// provider through platform.Override for the duration of the test binary.
const fakePlatform = platform.Cloudflare

// fakePlatform2 is a second fake platform, installed over the real GoDaddy
// provider, for tests of profiles that hold several accounts.
const fakePlatform2 = platform.GoDaddy

var (
	registerOnce sync.Once
	fakeMu       sync.Mutex
	fakeClients  = map[string]*fakeClient{}
	// fakeLogins counts the calls of the fake providers' Login.
	fakeLogins int
	// fakeLoginHook, when set, runs inside Login: what another polyctl
	// process does while a login flow is waiting for the user.
	fakeLoginHook func()
	// fakeRevoked lists the grants the fake providers were asked to revoke
	// ("<profile>/<platform>:<grant>"); fakeRevokeErr fails those calls.
	fakeRevoked   []string
	fakeRevokeErr error
	// fakeRecordTypes, when set, are the record types the fake providers
	// can write (nil: any).
	fakeRecordTypes []string
)

func registerFake() {
	registerOnce.Do(func() {
		platform.Override(&fakeProvider{id: fakePlatform, name: "Fake DNS"})
		platform.Override(&fakeProvider{id: fakePlatform2, name: "Fake Registrar"})
	})
}

func resetFake() {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	fakeClients = map[string]*fakeClient{}
	fakeLogins = 0
	fakeLoginHook = nil
	fakeRevoked = nil
	fakeRevokeErr = nil
	fakeRecordTypes = nil
	fakeCoverage = false
}

// fakeCoverage makes the fake providers report a change of what an account
// covers when a re-login changes its "account" metadata: the old account
// is the tree dropped (platform.CoverageChanger).
var fakeCoverage bool

func (p *fakeProvider) CoverageChange(before, after map[string]string) ([]string, bool) {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	if !fakeCoverage || before["account"] == after["account"] {
		return nil, false
	}
	return []string{before["account"]}, true
}

// RecordTypes returns fakeRecordTypes.
func (p *fakeProvider) RecordTypes() []string {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	return fakeRecordTypes
}

// revokedGrants returns what the fake providers were asked to revoke since
// the last reset.
func revokedGrants() []string {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	return append([]string(nil), fakeRevoked...)
}

// CanRevoke: an account whose secret holds a "grant" has an authorization
// on the platform, like a browser login.
func (p *fakeProvider) CanRevoke(prof platform.Profile) bool { return prof.Secret["grant"] != "" }

// Revoke records the call and fails with fakeRevokeErr when that is set.
func (p *fakeProvider) Revoke(ctx context.Context, prof platform.Profile) error {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	fakeRevoked = append(fakeRevoked, prof.Name+"/"+string(p.id)+":"+prof.Secret["grant"])
	return fakeRevokeErr
}

// loginCalls returns how often a fake provider's Login ran since the last
// reset.
func loginCalls() int {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	return fakeLogins
}

// client returns the fake client backing a profile's account on
// fakePlatform, creating it on demand.
func client(profile string) *fakeClient { return clientOn(profile, fakePlatform) }

// clientOn returns the fake client backing a profile's account on a
// platform, creating it on demand.
func clientOn(profile string, id platform.ID) *fakeClient {
	fakeMu.Lock()
	defer fakeMu.Unlock()
	key := profile + "/" + string(id)
	c := fakeClients[key]
	if c == nil {
		c = &fakeClient{records: map[string][]platform.Record{}}
		fakeClients[key] = c
	}
	return c
}

type fakeProvider struct {
	id   platform.ID
	name string
}

func (p *fakeProvider) ID() platform.ID     { return p.id }
func (p *fakeProvider) DisplayName() string { return p.name }
func (*fakeProvider) LoginHelp() string     { return "fake login" }
func (*fakeProvider) LoginOptions() []string {
	return []string{"token", "account", "api_key", "api_secret"}
}
func (*fakeProvider) ResourceTypes() []platform.ResourceType {
	return []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResDomain}
}

// Login stores the token option (default "fake") as the secret and records
// the account option, falling back to the account of a previous login.
func (p *fakeProvider) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	fakeMu.Lock()
	fakeLogins++
	hook := fakeLoginHook
	fakeMu.Unlock()
	if hook != nil {
		hook()
	}
	token := in.Options["token"]
	if token == "" {
		token = "fake"
	}
	account := in.Options["account"]
	if account == "" {
		account = in.Existing["account"]
	}
	res := &platform.LoginResult{Secret: map[string]string{"token": token}, Label: in.ProfileName}
	if account != "" {
		res.Metadata = map[string]string{"account": account}
	}
	return res, nil
}

func (p *fakeProvider) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	if prof.Secret["token"] == "" {
		return nil, fmt.Errorf("%w: missing token", platform.ErrUnauthorized)
	}
	c := clientOn(prof.Name, p.id)
	c.record("Open:" + prof.Secret["token"])
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
	// newIDOnUpdate makes UpdateRecord hand back a fresh id, like platforms
	// whose record ids encode the value (Route 53, Cloud DNS, GoDaddy).
	newIDOnUpdate bool
	// syncErrs fails Sync for the given resource types.
	syncErrs map[platform.ResourceType]error
	// failCreate fails CreateRecord for this record name with errFakeCreate.
	failCreate string
	// failDelete fails DeleteRecord for this record id with errFakeDelete.
	failDelete string
	// zoneErr fails GetZone; domainErr fails GetDomain.
	zoneErr, domainErr error
	// verifyErr fails Verify.
	verifyErr error
	// ownNSSuffix, when set, makes the client a registrar that hosts the
	// DNS of a domain only while its nameservers are its own (GoDaddy,
	// name.com): SetNameservers to others drops the domain's zone.
	ownNSSuffix string
}

var (
	errFakeCreate = errors.New("fake create failure")
	errFakeDelete = errors.New("fake delete failure")
)

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
	if c.verifyErr != nil {
		return nil, c.verifyErr
	}
	return &platform.Identity{Account: "fake-account"}, nil
}

func (c *fakeClient) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	c.record("Sync:" + string(rt))
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := c.syncErrs[rt]; err != nil {
		return nil, err
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

func (c *fakeClient) GetZone(ctx context.Context, id string) (*platform.Zone, error) {
	c.record("GetZone:" + id)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.zoneErr != nil {
		return nil, c.zoneErr
	}
	for _, z := range c.zones {
		if z.ID == id {
			out := z
			return &out, nil
		}
	}
	return nil, platform.ErrNotFound
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
	if c.failCreate != "" && r.Name == c.failCreate {
		return nil, errFakeCreate
	}
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
			if c.newIDOnUpdate {
				c.nextID++
				r.ID = fmt.Sprintf("r%d", c.nextID)
			}
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
	if c.failDelete != "" && recordID == c.failDelete {
		return errFakeDelete
	}
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
	if c.domainErr != nil {
		return nil, c.domainErr
	}
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
			if c.ownNSSuffix != "" && !slices.ContainsFunc(ns, func(n string) bool { return strings.HasSuffix(n, c.ownNSSuffix) }) {
				c.zones = slices.DeleteFunc(c.zones, func(z platform.Zone) bool { return z.Name == c.domains[i].Name })
			}
			return nil
		}
	}
	return platform.ErrNotFound
}

var (
	_ platform.Provider         = (*fakeProvider)(nil)
	_ platform.Revoker          = (*fakeProvider)(nil)
	_ platform.DNSService       = (*fakeClient)(nil)
	_ platform.RegistrarService = (*fakeClient)(nil)
	_ platform.ZoneGetter       = (*fakeClient)(nil)
)
