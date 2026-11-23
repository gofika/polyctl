package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// ipFake is a provider whose inventory rows carry addresses, installed over
// the real AWS and GCP providers for the find tests.
type ipFake struct{ id platform.ID }

// ipFakeState is what the fake accounts hold and what they were asked.
type ipFakeState struct {
	mu        sync.Mutex
	resources map[string]map[platform.ResourceType][]platform.Resource // by profile/platform
	syncErrs  map[string]error                                         // by profile/platform
	partial   map[string]error                                         // by profile/platform: region failure
	detailErr error
	calls     []string
}

var ipState *ipFakeState

func (s *ipFakeState) record(call string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.calls = append(s.calls, call)
}

func (s *ipFakeState) callList() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.calls...)
}

func (p *ipFake) ID() platform.ID                    { return p.id }
func (p *ipFake) DisplayName() string                { return "Fake " + string(p.id) }
func (*ipFake) LoginHelp() string                    { return "fake" }
func (*ipFake) LoginOptions() []string               { return []string{"token"} }
func (p *ipFake) FindTypes() []platform.ResourceType { return app.FindTypes }
func (p *ipFake) ResourceTypes() []platform.ResourceType {
	return app.FindTypes
}

func (p *ipFake) Login(ctx context.Context, in platform.LoginInput) (*platform.LoginResult, error) {
	return &platform.LoginResult{Secret: map[string]string{"token": "x"}}, nil
}

func (p *ipFake) Open(ctx context.Context, prof platform.Profile) (platform.Client, error) {
	ipState.record("Open:" + prof.Name + "/" + string(p.id))
	return &ipFakeClient{key: prof.Name + "/" + string(p.id)}, nil
}

// fakeIPData is the stored data of a fake resource.
type fakeIPData struct {
	Region   string   `json:"region"`
	State    string   `json:"state"`
	Internal []string `json:"internal"`
	External []string `json:"external"`
	Network  string   `json:"network"`
	Holders  []string `json:"holders,omitempty"`
}

func (p *ipFake) DescribeMatch(meta map[string]string, m *platform.FindMatch) error {
	var d fakeIPData
	if err := json.Unmarshal(m.Data, &d); err != nil {
		return err
	}
	m.Region, m.State, m.InternalIPs, m.ExternalIPs, m.Network = d.Region, d.State, d.Internal, d.External, d.Network
	m.Holders = d.Holders
	return nil
}

func (p *ipFake) ConsoleURL(meta map[string]string, m *platform.FindMatch) string {
	return fmt.Sprintf("https://console.example/%s/%s/%s?account=%s", p.id, m.Type, m.ID, meta["account"])
}

type ipFakeClient struct{ key string }

func (c *ipFakeClient) Verify(ctx context.Context) (*platform.Identity, error) {
	return &platform.Identity{}, nil
}

func (c *ipFakeClient) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	ipState.record("Sync:" + c.key + ":" + string(rt))
	ipState.mu.Lock()
	defer ipState.mu.Unlock()
	if err := ipState.syncErrs[c.key]; err != nil {
		return nil, err
	}
	res := ipState.resources[c.key][rt]
	if err := ipState.partial[c.key]; err != nil && rt == platform.ResInstance {
		return res, &platform.RegionSyncError{Failures: []platform.RegionError{{Region: "ap-south-2", Err: err}}}
	}
	return res, nil
}

func (c *ipFakeClient) NetworkDetail(ctx context.Context, m *platform.FindMatch) (*platform.NetworkDetail, error) {
	ipState.record("Detail:" + c.key + ":" + m.ID)
	if ipState.detailErr != nil {
		return nil, ipState.detailErr
	}
	return &platform.NetworkDetail{Subnet: "sub-1", SubnetCIDR: "10.0.0.0/20", SubnetGateway: "10.0.0.1"}, nil
}

// fakeIPRes builds a fake resource holding the given addresses.
func fakeIPRes(rt platform.ResourceType, id string, internal, external []string, dns ...string) platform.Resource {
	var s platform.IPSet
	s.Add(platform.IPInternal, internal...)
	s.Add(platform.IPExternal, external...)
	s.AddDNS(dns...)
	return platform.Resource{Type: rt, ID: id, Name: "name-" + id,
		Data: fakeIPData{Region: "r1", State: "running", Internal: internal, External: external, Network: "net-" + id}, IPs: s.Refs()}
}

// setupFind installs the fakes over AWS and GCP and writes a config with
// two profiles: acme (aws, gcp) and lab (aws).
func setupFind(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir, cfgPath = setup(t, false)
	ipState = &ipFakeState{resources: map[string]map[platform.ResourceType][]platform.Resource{}, syncErrs: map[string]error{}, partial: map[string]error{}}
	for _, id := range []platform.ID{platform.AWS, platform.GCP} {
		restore := platform.Override(&ipFake{id: id})
		t.Cleanup(restore)
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CredentialStore = "file"
	cfg.Profiles["acme"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.AWS: {CredentialBackend: "file", Metadata: map[string]string{"account": "111"}},
		platform.GCP: {CredentialBackend: "file", Metadata: map[string]string{"account": "proj"}},
	}}
	cfg.Profiles["lab"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		platform.AWS: {CredentialBackend: "file", Metadata: map[string]string{"account": "222"}},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{creds.Key("acme", "aws"), creds.Key("acme", "gcp"), creds.Key("lab", "aws")} {
		if err := creds.NewFile(dir).Set(k, map[string]string{"token": "x"}); err != nil {
			t.Fatal(err)
		}
	}
	return dir, cfgPath
}

// seedFind stores resources as a completed sync of every find type would,
// with the given age.
func seedFind(t *testing.T, dir string, id platform.ID, profile string, age time.Duration, res ...platform.Resource) {
	t.Helper()
	db := openInventory(t, dir)
	defer db.Close()
	by := map[platform.ResourceType][]platform.Resource{}
	for _, r := range res {
		by[r.Type] = append(by[r.Type], r)
	}
	for _, rt := range app.FindTypes {
		if err := db.Replace(context.Background(), inventory.Set{Platform: id, Profile: profile, Type: rt}, by[rt], time.Hour-age); err != nil {
			t.Fatal(err)
		}
	}
}

type findJSON struct {
	Query    string               `json:"query"`
	Kind     string               `json:"kind"`
	Cached   bool                 `json:"cached"`
	SyncedAt *time.Time           `json:"synced_at"`
	Matches  []platform.FindMatch `json:"matches"`
	Errors   []app.FindError      `json:"errors"`
	Hint     string               `json:"hint"`
}

func decodeFind(t *testing.T, stdout string) findJSON {
	t.Helper()
	var r findJSON
	if err := json.Unmarshal([]byte(stdout), &r); err != nil {
		t.Fatalf("json %q: %v", stdout, err)
	}
	return r
}

func TestFindFromInventoryOnly(t *testing.T) {
	dir, cfgPath := setupFind(t)
	seedFind(t, dir, platform.AWS, "acme", 0,
		fakeIPRes(platform.ResInstance, "i-1", []string{"10.0.1.100"}, []string{"203.0.113.10"}))
	seedFind(t, dir, platform.AWS, "lab", 0,
		fakeIPRes(platform.ResInstance, "i-2", []string{"10.0.1.100"}, nil))
	seedFind(t, dir, platform.GCP, "acme", 0,
		fakeIPRes(platform.ResLoadBalancer, "fr-1", nil, []string{"203.0.113.10"}))

	stdout, stderr, err := run(t, cfgPath, "find", "10.0.1.100", "-o", "json")
	if err != nil {
		t.Fatalf("find: %v (%s)", err, stderr)
	}
	r := decodeFind(t, stdout)
	if r.Kind != "ip" || !r.Cached || r.SyncedAt == nil || len(r.Matches) != 2 || len(r.Errors) != 0 || r.Hint != "" {
		t.Fatalf("result = %+v", r)
	}
	if m := r.Matches[0]; m.Profile != "acme" || m.ID != "i-1" || m.MatchedField != "internal_ip" || m.Network != "net-i-1" ||
		m.URL != "https://console.example/aws/instance/i-1?account=111" || m.Detail != nil {
		t.Errorf("match 0 = %+v", m)
	}
	if m := r.Matches[1]; m.Profile != "lab" || m.ID != "i-2" {
		t.Errorf("match 1 = %+v", m)
	}
	if !strings.Contains(stderr, "matched 2 resource(s) (local inventory, synced") {
		t.Errorf("stderr = %q", stderr)
	}
	if calls := ipState.callList(); len(calls) != 0 {
		t.Errorf("find used the network: %v", calls)
	}

	// Several platforms, a public address; the table lists them all.
	stdout, _, err = run(t, cfgPath, "find", "203.0.113.10")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "REGION/ZONE") || !strings.Contains(stdout, "name-fr-1") || !strings.Contains(stdout, "name-i-1") || strings.Contains(stdout, "URL") {
		t.Errorf("table = %q", stdout)
	}
	stdout, _, _ = run(t, cfgPath, "find", "203.0.113.10", "-v")
	if !strings.Contains(stdout, "https://console.example/gcp/load_balancer/fr-1") {
		t.Errorf("verbose table = %q", stdout)
	}

	// --platform and --profile narrow the search.
	stdout, _, err = run(t, cfgPath, "find", "203.0.113.10", "--platform", "gcp", "-o", "json")
	if r := decodeFind(t, stdout); err != nil || len(r.Matches) != 1 || r.Matches[0].Platform != platform.GCP {
		t.Errorf("--platform = %+v, %v", r, err)
	}
	stdout, _, err = run(t, cfgPath, "find", "10.0.1.100", "--profile", "lab", "-o", "json")
	if r := decodeFind(t, stdout); err != nil || len(r.Matches) != 1 || r.Matches[0].Profile != "lab" {
		t.Errorf("--profile = %+v, %v", r, err)
	}
	// --offline changes nothing for find; --dry-run is ignored.
	if _, _, err := run(t, cfgPath, "find", "10.0.1.100", "--offline", "--dry-run"); err != nil {
		t.Errorf("--offline: %v", err)
	}
	if calls := ipState.callList(); len(calls) != 0 {
		t.Errorf("find used the network: %v", calls)
	}
}

func TestFindDNSAndIPv6(t *testing.T) {
	dir, cfgPath := setupFind(t)
	seedFind(t, dir, platform.AWS, "acme", 0,
		fakeIPRes(platform.ResDBInstance, "db-1", nil, nil, "mydb.abc123.ap-east-1.rds.amazonaws.com"),
		fakeIPRes(platform.ResInstance, "i-6", []string{"2001:db8::10"}, nil))
	stdout, _, err := run(t, cfgPath, "find", "MyDB.abc123.ap-east-1.RDS.amazonaws.com.", "-o", "json")
	r := decodeFind(t, stdout)
	if err != nil || r.Kind != "dns" || r.Query != "mydb.abc123.ap-east-1.rds.amazonaws.com" || len(r.Matches) != 1 || r.Matches[0].MatchedField != "endpoint" {
		t.Errorf("dns = %+v, %v", r, err)
	}
	stdout, _, err = run(t, cfgPath, "find", "2001:DB8:0:0::10", "-o", "json")
	if r := decodeFind(t, stdout); err != nil || len(r.Matches) != 1 || r.Matches[0].ID != "i-6" {
		t.Errorf("ipv6 = %+v, %v", r, err)
	}
}

func TestFindNoMatch(t *testing.T) {
	dir, cfgPath := setupFind(t)
	seedFind(t, dir, platform.AWS, "acme", 0, fakeIPRes(platform.ResInstance, "i-1", []string{"10.0.0.1"}, nil))
	stdout, stderr, err := run(t, cfgPath, "find", "203.0.113.99", "-o", "json")
	if ExitCodeFor(err) != ExitNotFound {
		t.Fatalf("exit = %d (%v)", ExitCodeFor(err), err)
	}
	r := decodeFind(t, stdout)
	if len(r.Matches) != 0 || r.Hint != app.FindHintRefresh || r.Matches == nil {
		t.Errorf("result = %+v", r)
	}
	for _, want := range []string{"no resource found for 203.0.113.99 in the local inventory (3 account(s), last synced", "polyctl find 203.0.113.99 --refresh", "polyctl sync --type instance,load_balancer,eip,db_instance"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q lacks %q (stderr %q)", err, want, stderr)
		}
	}
	if calls := ipState.callList(); len(calls) != 0 {
		t.Errorf("find used the network: %v", calls)
	}
	// An empty table still prints its header.
	stdout, _, _ = run(t, cfgPath, "find", "203.0.113.99")
	if !strings.HasPrefix(stdout, "PLATFORM") {
		t.Errorf("table = %q", stdout)
	}
}

func TestFindNeverSynced(t *testing.T) {
	_, cfgPath := setupFind(t)
	stdout, _, err := run(t, cfgPath, "find", "10.0.0.1", "-o", "json")
	if ExitCodeFor(err) != ExitNotFound || !strings.Contains(err.Error(), "never been synced") || !strings.Contains(err.Error(), "polyctl sync") {
		t.Fatalf("err = %v", err)
	}
	if r := decodeFind(t, stdout); r.Hint != app.FindHintNeverSynced || r.SyncedAt != nil {
		t.Errorf("result = %+v", r)
	}
	if calls := ipState.callList(); len(calls) != 0 {
		t.Errorf("find used the network: %v", calls)
	}
}

func TestFindStaleStillMatches(t *testing.T) {
	dir, cfgPath := setupFind(t)
	seedFind(t, dir, platform.AWS, "acme", 3*time.Hour, fakeIPRes(platform.ResInstance, "i-1", []string{"10.0.0.1"}, nil))
	stdout, stderr, err := run(t, cfgPath, "find", "10.0.0.1", "-o", "json")
	if err != nil || len(decodeFind(t, stdout).Matches) != 1 {
		t.Fatalf("stale = %q, %v", stdout, err)
	}
	if !strings.Contains(stderr, "may be stale") || !strings.Contains(stderr, "--refresh") {
		t.Errorf("stderr = %q", stderr)
	}
	if calls := ipState.callList(); len(calls) != 0 {
		t.Errorf("find used the network: %v", calls)
	}
}

func TestFindRefresh(t *testing.T) {
	_, cfgPath := setupFind(t)
	ipState.resources["acme/aws"] = map[platform.ResourceType][]platform.Resource{
		platform.ResInstance: {fakeIPRes(platform.ResInstance, "i-1", []string{"10.0.0.1"}, nil)},
	}
	ipState.resources["acme/gcp"] = map[platform.ResourceType][]platform.Resource{
		platform.ResEIP: {fakeIPRes(platform.ResEIP, "addr-1", []string{"10.0.0.1"}, nil)},
	}
	ipState.syncErrs["lab/aws"] = fmt.Errorf("%w: expired token", platform.ErrUnauthorized)
	ipState.partial["acme/aws"] = errors.New("dial tcp: no such host")

	stdout, stderr, err := run(t, cfgPath, "find", "10.0.0.1", "--refresh", "-o", "json")
	if err != nil {
		t.Fatalf("refresh: %v (%s)", err, stderr)
	}
	r := decodeFind(t, stdout)
	if r.Cached || len(r.Matches) != 2 {
		t.Fatalf("result = %+v", r)
	}
	var region, auth bool
	for _, e := range r.Errors {
		if e.Profile == "acme" && e.Region == "ap-south-2" && e.Type == platform.ResInstance {
			region = true
		}
		if e.Profile == "lab" && strings.Contains(e.Error, "expired token") {
			auth = true
		}
	}
	if !region || !auth {
		t.Errorf("errors = %+v", r.Errors)
	}
	if !strings.Contains(stderr, "polyctl auth status") || !strings.Contains(stderr, "warning: aws/acme instance in ap-south-2") {
		t.Errorf("stderr = %q", stderr)
	}
	if n := len(ipState.callList()); n == 0 {
		t.Error("no sync")
	}
}

func TestFindRefreshAllFailed(t *testing.T) {
	_, cfgPath := setupFind(t)
	for _, k := range []string{"acme/aws", "acme/gcp", "lab/aws"} {
		ipState.syncErrs[k] = errors.New("boom")
	}
	stdout, _, err := run(t, cfgPath, "find", "10.0.0.1", "--refresh", "-o", "json")
	if ExitCodeFor(err) != ExitError {
		t.Fatalf("exit = %d (%v)", ExitCodeFor(err), err)
	}
	if r := decodeFind(t, stdout); len(r.Errors) != 12 {
		t.Errorf("errors = %+v", r.Errors)
	}
}

func TestFindDetail(t *testing.T) {
	dir, cfgPath := setupFind(t)
	seedFind(t, dir, platform.AWS, "acme", 0,
		fakeIPRes(platform.ResInstance, "i-1", []string{"10.0.0.1"}, nil),
		fakeIPRes(platform.ResEIP, "eip-1", []string{"10.0.0.1"}, nil))
	stdout, _, err := run(t, cfgPath, "find", "10.0.0.1", "--detail", "-o", "json")
	r := decodeFind(t, stdout)
	if err != nil || len(r.Matches) != 2 {
		t.Fatalf("detail = %+v, %v", r, err)
	}
	for _, m := range r.Matches {
		if (m.Type == platform.ResInstance) != (m.Detail != nil) {
			t.Errorf("match %s detail = %+v", m.ID, m.Detail)
		}
	}
	stdout, _, _ = run(t, cfgPath, "find", "10.0.0.1", "--detail")
	if !strings.Contains(stdout, "10.0.0.0/20") || !strings.Contains(stdout, "URL") {
		t.Errorf("table = %q", stdout)
	}

	// A failed lookup keeps the match and is reported.
	ipState.detailErr = errors.New("throttled")
	stdout, stderr, err := run(t, cfgPath, "find", "10.0.0.1", "--detail", "-o", "json")
	r = decodeFind(t, stdout)
	if err != nil || len(r.Matches) != 2 || len(r.Errors) != 1 || !strings.Contains(r.Errors[0].Error, "throttled") || r.Errors[0].Resource != "i-1" {
		t.Errorf("failed detail = %+v, %v (%s)", r, err, stderr)
	}
}

func TestFindUsage(t *testing.T) {
	dir, cfgPath := setupFind(t)
	seedFind(t, dir, platform.AWS, "acme", 0)
	for _, args := range [][]string{
		{"find"},
		{"find", "a", "b"},
		{"find", "not a host"},
		{"find", "https://example.com/"},
		{"find", "10.0.0.1", "--refresh", "--offline"},
		{"find", "10.0.0.1", "--detail", "--offline"},
		{"find", "10.0.0.1", "--platform", "nope"},
	} {
		if _, _, err := run(t, cfgPath, args...); ExitCodeFor(err) != ExitUsage {
			t.Errorf("%v: exit %d (%v)", args, ExitCodeFor(err), err)
		}
	}
	if _, _, err := run(t, cfgPath, "find", "10.0.0.1", "--profile", "nobody"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("unknown profile: %v", err)
	}
}

func TestFindReservedAddressAnnotates(t *testing.T) {
	dir, cfgPath := setupFind(t)
	inst := fakeIPRes(platform.ResInstance, "i-1", nil, []string{"203.0.113.5"})
	addr := platform.Resource{Type: platform.ResEIP, ID: "addr-1", Name: "web-ip", Data: fakeIPData{}, IPs: []platform.IPRef{{Value: "203.0.113.5", Kind: platform.IPReserved}}}
	lone := platform.Resource{Type: platform.ResEIP, ID: "addr-2", Name: "spare-ip", Data: fakeIPData{}, IPs: []platform.IPRef{{Value: "203.0.113.6", Kind: platform.IPReserved}}}
	seedFind(t, dir, platform.GCP, "acme", 0, inst, addr, lone)
	stdout, _, err := run(t, cfgPath, "find", "203.0.113.5", "-o", "json")
	r := decodeFind(t, stdout)
	if err != nil || len(r.Matches) != 1 || r.Matches[0].ID != "i-1" || len(r.Matches[0].Addresses) != 1 || r.Matches[0].Addresses[0] != "web-ip" {
		t.Errorf("annotated = %+v, %v", r, err)
	}
	stdout, _, err = run(t, cfgPath, "find", "203.0.113.6", "-o", "json")
	if r := decodeFind(t, stdout); err != nil || len(r.Matches) != 1 || r.Matches[0].ID != "addr-2" {
		t.Errorf("alone = %+v, %v", r, err)
	}
}

// A reserved address that names its user annotates that match only, not
// another resource of the account holding the same private address in
// another network.
func TestFindReservedAddressAnnotatesItsUser(t *testing.T) {
	dir, cfgPath := setupFind(t)
	a := fakeIPRes(platform.ResInstance, "i-1", []string{"10.0.0.5"}, nil)
	b := fakeIPRes(platform.ResInstance, "i-2", []string{"10.0.0.5"}, nil)
	addr := platform.Resource{Type: platform.ResEIP, ID: "addr-1", Name: "db-ip", Data: fakeIPData{Holders: []string{"name-i-2"}},
		IPs: []platform.IPRef{{Value: "10.0.0.5", Kind: platform.IPReserved}}}
	seedFind(t, dir, platform.GCP, "acme", 0, a, b, addr)
	stdout, _, err := run(t, cfgPath, "find", "10.0.0.5", "-o", "json")
	r := decodeFind(t, stdout)
	if err != nil || len(r.Matches) != 2 {
		t.Fatalf("matches = %+v, %v", r, err)
	}
	for _, m := range r.Matches {
		if want := m.ID == "i-2"; (len(m.Addresses) == 1) != want {
			t.Errorf("match %s addresses = %v", m.ID, m.Addresses)
		}
	}
}
