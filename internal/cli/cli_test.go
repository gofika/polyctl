package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// setup prepares an isolated config dir. With profiles=true it writes a
// config with profile "a" on the fake platform and its credentials.
func setup(t *testing.T, profiles bool) (dir, cfgPath string) {
	t.Helper()
	registerFake()
	resetFake()
	dir = t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	cfgPath = filepath.Join(dir, "config.yaml")
	if !profiles {
		return dir, cfgPath
	}
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	cfg.CredentialStore = "file"
	cfg.Profiles["a"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		fakePlatform: {CredentialBackend: "file", Metadata: map[string]string{"account": "acct-a"}},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(dir).Set(creds.Key("a", string(fakePlatform)), map[string]string{"token": "secret"}); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath
}

func openInventory(t *testing.T, dir string) *inventory.DB {
	t.Helper()
	db, err := inventory.Open(filepath.Join(dir, "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	return db
}

// seed writes zones (and their records) for profile a into the inventory,
// as a completed sync would.
func seed(t *testing.T, dir string, zones []platform.Zone, records map[string][]platform.Record) {
	t.Helper()
	db := openInventory(t, dir)
	defer db.Close()
	ctx := context.Background()
	if err := db.Replace(ctx, inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResZone}, app.ZoneResources(zones), time.Hour); err != nil {
		t.Fatal(err)
	}
	var recs []platform.Resource
	for _, z := range zones {
		recs = append(recs, app.RecordResources(z.ID, z.Name, records[z.ID])...)
	}
	if err := db.Replace(ctx, inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResDNSRecord}, recs, time.Hour); err != nil {
		t.Fatal(err)
	}
}

// run executes the command tree the way Main does, with captured streams.
func run(t *testing.T, cfgPath string, args ...string) (stdout, stderr string, err error) {
	t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
	root := NewRoot(rt)
	root.SetArgs(append([]string{"--config", cfgPath}, args...))
	root.SetIn(strings.NewReader(""))
	root.SetOut(&out)
	root.SetErr(&errb)
	err = root.ExecuteContext(context.Background())
	_ = rt.Close()
	return out.String(), errb.String(), err
}

func TestAuthListNoConfig(t *testing.T) {
	_, cfgPath := setup(t, false)
	var out, errb bytes.Buffer
	code := Main([]string{"--config", cfgPath, "auth", "list"}, strings.NewReader(""), &out, &errb)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	if !strings.Contains(out.String(), "no accounts configured") || !strings.Contains(out.String(), "auth login") {
		t.Errorf("table stdout = %q", out.String())
	}

	out.Reset()
	errb.Reset()
	code = Main([]string{"--config", cfgPath, "auth", "list", "-o", "json"}, strings.NewReader(""), &out, &errb)
	if code != ExitOK {
		t.Fatalf("exit %d, stderr %q", code, errb.String())
	}
	var rows []map[string]any
	if err := json.Unmarshal(out.Bytes(), &rows); err != nil {
		t.Fatalf("json stdout %q: %v", out.String(), err)
	}
	if len(rows) != 0 {
		t.Errorf("json rows = %v, want none", rows)
	}
	if errb.Len() != 0 {
		t.Errorf("unexpected stderr %q", errb.String())
	}
}

func TestAuthListWithProfiles(t *testing.T) {
	_, cfgPath := setup(t, true)
	stdout, _, err := run(t, cfgPath, "auth", "list")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || !strings.Contains(lines[0], "PROFILE") {
		t.Fatalf("table = %q", stdout)
	}
	if !strings.Contains(lines[1], "a") || !strings.Contains(lines[1], string(fakePlatform)) || !strings.Contains(lines[1], "account=acct-a") {
		t.Errorf("row = %q", lines[1])
	}

	stdout, _, err = run(t, cfgPath, "auth", "list", "--output", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []profileRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("json %q: %v", stdout, err)
	}
	if len(rows) != 1 || rows[0].Name != "a" || rows[0].Platform != fakePlatform || rows[0].Backend != "file" || rows[0].Current {
		t.Errorf("rows = %+v", rows)
	}
}

func TestAuthUseAndLogout(t *testing.T) {
	dir, cfgPath := setup(t, true)
	if _, _, err := run(t, cfgPath, "auth", "use", "nope"); ExitCodeFor(err) != ExitNotFound {
		t.Fatalf("auth use nope = %v", err)
	}
	if _, stderr, err := run(t, cfgPath, "auth", "use", "a"); err != nil || !strings.Contains(stderr, `current profile set to "a"`) {
		t.Fatalf("auth use a: %v %q", err, stderr)
	}
	cfg, _ := config.Load(cfgPath)
	if cfg.CurrentProfile != "a" {
		t.Errorf("current_profile = %q", cfg.CurrentProfile)
	}

	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)
	if _, _, err := run(t, cfgPath, "auth", "logout"); ExitCodeFor(err) != ExitUsage {
		t.Fatalf("logout without --profile = %v", err)
	}
	if _, _, err := run(t, cfgPath, "auth", "logout", "--profile", "a"); err != nil {
		t.Fatalf("logout: %v", err)
	}
	cfg, _ = config.Load(cfgPath)
	if len(cfg.Profiles) != 0 || cfg.CurrentProfile != "" {
		t.Errorf("config after logout = %+v", cfg)
	}
	if _, err := creds.NewFile(dir).Get(creds.Key("a", string(fakePlatform))); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("credentials survived logout: %v", err)
	}
	db := openInventory(t, dir)
	defer db.Close()
	if rows, _ := db.List(context.Background(), inventory.Query{Profile: "a"}); len(rows) != 0 {
		t.Errorf("inventory survived logout: %+v", rows)
	}
}

func TestDNSListOfflineFromInventory(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{
		"z1": {
			{ID: "r1", Name: "www.example.com", Type: "A", Content: "1.2.3.4", TTL: 300},
			{ID: "r2", Name: "example.com", Type: "MX", Content: "mx.example.com", TTL: 3600, Priority: intp(10)},
		},
	})

	stdout, stderr, err := run(t, cfgPath, "dns", "list", "www.example.com", "--offline")
	if err != nil {
		t.Fatalf("dns list: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stdout, "www.example.com") || !strings.Contains(stdout, "1.2.3.4") || !strings.Contains(stdout, "10 mx.example.com") {
		t.Errorf("table = %q", stdout)
	}
	if !strings.Contains(stderr, "zone example.com via cloudflare/a (local inventory)") {
		t.Errorf("stderr = %q", stderr)
	}
	if client("a").count("Open") != 0 {
		t.Error("--offline must not open the platform client")
	}

	stdout, _, err = run(t, cfgPath, "dns", "list", "www.example.com", "--offline", "-o", "json", "--name", "www", "--type", "a")
	if err != nil {
		t.Fatal(err)
	}
	var res dnsResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil {
		t.Fatalf("json %q: %v", stdout, err)
	}
	if !res.Cached || res.Target == nil || res.Target.Profile != "a" || res.Target.Platform != fakePlatform || res.Target.ResourceID != "z1" {
		t.Errorf("result = %+v", res)
	}
	if len(res.Records) != 1 || res.Records[0].ID != "r1" {
		t.Errorf("filtered records = %+v", res.Records)
	}

	// Unknown domains cannot be indexed offline.
	_, _, err = run(t, cfgPath, "dns", "list", "nothere.org", "--offline")
	if !errors.Is(err, app.ErrDomainUnknown) || ExitCodeFor(err) != ExitNotFound {
		t.Errorf("unknown offline = %v (exit %d)", err, ExitCodeFor(err))
	}
}

func intp(i int) *int { return &i }

func TestDNSUpdateCreatesRecord(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}

	stdout, stderr, err := run(t, cfgPath, "dns", "update", "example.com", "--type", "A", "--name", "www", "--value", "1.2.3.4")
	if err != nil {
		t.Fatalf("dns update: %v (stderr %q)", err, stderr)
	}
	if fc.count("ListRecords:z1") != 1 || fc.count("CreateRecord:www.example.com:A") != 1 || fc.count("UpdateRecord") != 0 {
		t.Errorf("calls = %v", fc.calls)
	}
	if got := fc.records["z1"]; len(got) != 1 || got[0].Content != "1.2.3.4" || got[0].Name != "www.example.com" {
		t.Errorf("platform records = %+v", got)
	}
	if !strings.Contains(stderr, "created www.example.com A -> 1.2.3.4 via cloudflare/a") {
		t.Errorf("stderr = %q", stderr)
	}
	if !strings.Contains(stdout, "www.example.com") || !strings.Contains(stdout, "1.2.3.4") {
		t.Errorf("stdout = %q", stdout)
	}

	db := openInventory(t, dir)
	defer db.Close()
	rows, err := db.List(context.Background(), inventory.Query{Type: platform.ResDNSRecord, Name: "www.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("inventory rows = %+v, want the created record", rows)
	}
	r := rows[0]
	if r.Platform != fakePlatform || r.Profile != "a" || r.ParentID != "z1" || r.Domain != "example.com" || r.ID != "r1" {
		t.Errorf("row = %+v", r)
	}
	var rec platform.Record
	if err := r.Decode(&rec); err != nil || rec.Content != "1.2.3.4" || rec.Type != "A" || rec.ZoneID != "z1" {
		t.Errorf("decoded = %+v, %v", rec, err)
	}
	// Records never enter the domain index.
	if entries, _ := db.IndexEntries(context.Background()); len(entries) != 1 || entries[0].Type != platform.ResZone {
		t.Errorf("index = %+v", entries)
	}
}

func TestDNSUpdateExistingRecord(t *testing.T) {
	dir, cfgPath := setup(t, true)
	existing := platform.Record{ID: "r7", ZoneID: "z1", Name: "www.example.com", Type: "A", Content: "9.9.9.9", TTL: 600}
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{"z1": {existing}})
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.records["z1"] = []platform.Record{existing}

	_, stderr, err := run(t, cfgPath, "dns", "update", "www.example.com", "--type", "a", "--value", "1.2.3.4")
	if err != nil {
		t.Fatalf("dns update: %v (stderr %q)", err, stderr)
	}
	if fc.count("UpdateRecord:r7") != 1 || fc.count("CreateRecord") != 0 {
		t.Errorf("calls = %v", fc.calls)
	}
	got := fc.records["z1"][0]
	if got.Content != "1.2.3.4" || got.TTL != 600 || got.Type != "A" {
		t.Errorf("updated record = %+v (TTL must be kept)", got)
	}
	if !strings.Contains(stderr, "updated www.example.com A -> 1.2.3.4") {
		t.Errorf("stderr = %q", stderr)
	}
	db := openInventory(t, dir)
	defer db.Close()
	r, err := db.Get(context.Background(), inventory.Set{Platform: fakePlatform, Profile: "a"}, platform.ResDNSRecord, "r7")
	if err != nil {
		t.Fatal(err)
	}
	var rec platform.Record
	if err := r.Decode(&rec); err != nil || rec.Content != "1.2.3.4" {
		t.Errorf("inventory record = %+v, %v", rec, err)
	}

	// Several matches refuse to guess unless --add is given.
	fc.records["z1"] = append(fc.records["z1"], platform.Record{ID: "r8", Name: "www.example.com", Type: "A", Content: "8.8.8.8"})
	_, _, err = run(t, cfgPath, "dns", "update", "example.com", "--type", "A", "--name", "www", "--value", "1.1.1.1")
	if err == nil || !strings.Contains(err.Error(), "--add") {
		t.Errorf("multiple matches = %v", err)
	}
	_, _, err = run(t, cfgPath, "dns", "update", "example.com", "--type", "A", "--name", "www", "--value", "1.1.1.1", "--add")
	if err != nil || fc.count("CreateRecord") != 1 {
		t.Errorf("--add: %v calls=%v", err, fc.calls)
	}
}

func TestDNSUpdateUsageAndOffline(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)

	_, _, err := run(t, cfgPath, "dns", "update", "example.com", "--name", "www")
	if ExitCodeFor(err) != ExitUsage {
		t.Errorf("missing --type/--value = %v (exit %d)", err, ExitCodeFor(err))
	}
	_, _, err = run(t, cfgPath, "dns", "update", "example.com", "--type", "A", "--value", "1.2.3.4", "--offline")
	if !errors.Is(err, app.ErrOffline) || ExitCodeFor(err) != ExitOffline {
		t.Errorf("--offline mutation = %v (exit %d)", err, ExitCodeFor(err))
	}
	_, _, err = run(t, cfgPath, "dns", "delete", "example.com", "--type", "A", "--name", "www", "--offline")
	if !errors.Is(err, app.ErrOffline) {
		t.Errorf("--offline delete = %v", err)
	}
	if client("a").count("Open") != 0 {
		t.Error("platform client opened despite --offline")
	}
}

func TestDNSDeleteRecord(t *testing.T) {
	dir, cfgPath := setup(t, true)
	rec := platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Content: "1.2.3.4"}
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{"z1": {rec}})
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.records["z1"] = []platform.Record{rec}

	_, _, err := run(t, cfgPath, "dns", "delete", "example.com", "--type", "A", "--name", "nope")
	if !errors.Is(err, platform.ErrNotFound) || ExitCodeFor(err) != ExitNotFound {
		t.Errorf("no match = %v", err)
	}
	_, stderr, err := run(t, cfgPath, "dns", "delete", "example.com", "--type", "A", "--name", "www")
	if err != nil {
		t.Fatalf("dns delete: %v (%q)", err, stderr)
	}
	if fc.count("DeleteRecord:r1") != 1 || len(fc.records["z1"]) != 0 {
		t.Errorf("calls = %v records = %+v", fc.calls, fc.records["z1"])
	}
	db := openInventory(t, dir)
	defer db.Close()
	if rows, _ := db.List(context.Background(), inventory.Query{Type: platform.ResDNSRecord}); len(rows) != 0 {
		t.Errorf("inventory still holds the deleted record: %+v", rows)
	}
}

func TestExitCodeFor(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want int
	}{
		{"nil", nil, ExitOK},
		{"nothing to do", nothingToDo("no %s configured", "accounts"), ExitOK},
		{"nothing to do wrapped", fmt.Errorf("ctx: %w", nothingToDo("x")), ExitOK},
		{"plain", errors.New("boom"), ExitError},
		{"usage", usageErr("bad flag"), ExitUsage},
		{"usage wrapped", fmt.Errorf("ctx: %w", usageErr("bad")), ExitUsage},
		{"unauthorized", platform.ErrUnauthorized, ExitAuth},
		{"unauthorized wrapped", fmt.Errorf("open: %w", platform.ErrUnauthorized), ExitAuth},
		{"not found", platform.ErrNotFound, ExitNotFound},
		{"domain unknown", fmt.Errorf("%w: x", app.ErrDomainUnknown), ExitNotFound},
		{"never synced", inventory.ErrNeverSynced, ExitNotFound},
		{"offline", app.ErrOffline, ExitOffline},
		{"not supported", fmt.Errorf("dns %w", platform.ErrNotSupported), ExitNotSupported},
		{"ambiguous", &app.AmbiguousError{What: "x", Candidates: []string{"a", "b"}}, ExitAmbiguous},
		{"ambiguous wrapped", fmt.Errorf("resolve: %w", &app.AmbiguousError{What: "x"}), ExitAmbiguous},
		{"context", context.Canceled, ExitError},
	}
	for _, c := range cases {
		if got := ExitCodeFor(c.err); got != c.want {
			t.Errorf("%s: ExitCodeFor(%v) = %d, want %d", c.name, c.err, got, c.want)
		}
	}
}

func TestRefreshAndOfflineAreExclusive(t *testing.T) {
	_, cfgPath := setup(t, false)
	var out, errb bytes.Buffer
	code := Main([]string{"--config", cfgPath, "--refresh", "--offline", "auth", "list"}, strings.NewReader(""), &out, &errb)
	if code != ExitUsage {
		t.Fatalf("exit %d, want %d (stderr %q)", code, ExitUsage, errb.String())
	}
	if !strings.Contains(errb.String(), "mutually exclusive") || !strings.HasPrefix(errb.String(), "error:") {
		t.Errorf("stderr = %q", errb.String())
	}
	if out.Len() != 0 {
		t.Errorf("stdout must stay empty on usage errors: %q", out.String())
	}
	// A bad output format is a usage error as well.
	errb.Reset()
	if code := Main([]string{"--config", cfgPath, "-o", "xml", "auth", "list"}, strings.NewReader(""), &out, &errb); code != ExitUsage {
		t.Errorf("-o xml exit %d, want %d (%q)", code, ExitUsage, errb.String())
	}
}

func TestDomainWhichAndListOffline(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)

	stdout, _, err := run(t, cfgPath, "domain", "which", "www.example.com", "--offline")
	if err != nil {
		t.Fatalf("domain which: %v", err)
	}
	if !strings.Contains(stdout, "example.com") || !strings.Contains(stdout, "zone") || !strings.Contains(stdout, "cloudflare") {
		t.Errorf("which = %q", stdout)
	}
	_, _, err = run(t, cfgPath, "domain", "which", "nothere.org", "--offline")
	if !errors.Is(err, app.ErrDomainUnknown) {
		t.Errorf("which unknown = %v", err)
	}
	stdout, _, err = run(t, cfgPath, "domain", "list", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var entries []inventory.IndexEntry
	if err := json.Unmarshal([]byte(stdout), &entries); err != nil || len(entries) != 1 || entries[0].Domain != "example.com" {
		t.Errorf("domain list = %+v, %v", entries, err)
	}
	if _, _, err := run(t, cfgPath, "domain", "index", "--offline"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("domain index --offline = %v", err)
	}
	if _, _, err := run(t, cfgPath, "sync", "--offline"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("sync --offline = %v", err)
	}
}

func TestSyncCommand(t *testing.T) {
	dir, cfgPath := setup(t, true)
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.domains = []platform.Domain{{Name: "example.com"}}

	stdout, _, err := run(t, cfgPath, "sync", "-o", "json")
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	var reports []app.SyncReport
	if err := json.Unmarshal([]byte(stdout), &reports); err != nil || len(reports) != 3 {
		t.Fatalf("reports = %+v, %v (%q)", reports, err, stdout)
	}
	db := openInventory(t, dir)
	defer db.Close()
	stats, _ := db.Stats(context.Background())
	if len(stats) != 3 {
		t.Errorf("stats = %+v", stats)
	}
	if _, _, err := run(t, cfgPath, "sync", "--platform", "nope"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("sync --platform nope = %v", err)
	}
	// A platform nobody is logged in to: nothing to do, which is not an error.
	if _, _, err := run(t, cfgPath, "sync", "--platform", "aws"); !errors.Is(err, errNothingToDo) || ExitCodeFor(err) != ExitOK {
		t.Errorf("sync with no matching account = %v (exit %d)", err, ExitCodeFor(err))
	}
	stdout, _, err = run(t, cfgPath, "inventory", "stats")
	if err != nil || !strings.Contains(stdout, "cloudflare") {
		t.Errorf("inventory stats = %q, %v", stdout, err)
	}
}

func TestDNSUpdateDropsOldInventoryRowWhenIDChanges(t *testing.T) {
	dir, cfgPath := setup(t, true)
	existing := platform.Record{ID: "r7", ZoneID: "z1", Name: "www.example.com", Type: "A", Content: "9.9.9.9", TTL: 600}
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{"z1": {existing}})
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.records["z1"] = []platform.Record{existing}
	fc.nextID = 7
	fc.newIDOnUpdate = true

	_, stderr, err := run(t, cfgPath, "dns", "update", "www.example.com", "--type", "A", "--value", "1.2.3.4")
	if err != nil {
		t.Fatalf("dns update: %v (stderr %q)", err, stderr)
	}
	if fc.count("UpdateRecord:r7") != 1 || fc.records["z1"][0].ID != "r8" {
		t.Fatalf("calls = %v records = %+v", fc.calls, fc.records["z1"])
	}
	db := openInventory(t, dir)
	defer db.Close()
	rows, err := db.List(context.Background(), inventory.Query{Type: platform.ResDNSRecord})
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "r8" {
		t.Fatalf("inventory rows = %+v, want only the record under its new id", rows)
	}
	// The cached listing (zone state is fresh) must not show the old row.
	stdout, _, err := run(t, cfgPath, "dns", "list", "example.com", "--offline", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var res dnsResult
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || len(res.Records) != 1 || res.Records[0].ID != "r8" || res.Records[0].Content != "1.2.3.4" {
		t.Errorf("cached list = %+v, %v", res.Records, err)
	}
}

func TestCobraErrorsAreUsageErrors(t *testing.T) {
	_, cfgPath := setup(t, true)
	cases := [][]string{
		{"dns", "list"},                       // missing argument
		{"dns", "list", "a.com", "b.com"},     // too many arguments
		{"auth", "use"},                       // missing argument
		{"auth", "list", "--bogus"},           // unknown flag
		{"nosuchcmd"},                         // unknown command
		{"auth", "login", "cloudflare", "-x"}, // unknown shorthand
	}
	for _, args := range cases {
		var out, errb bytes.Buffer
		code := Main(append([]string{"--config", cfgPath}, args...), strings.NewReader(""), &out, &errb)
		if code != ExitUsage {
			t.Errorf("%v: exit %d, want %d (stderr %q)", args, code, ExitUsage, errb.String())
		}
		if !strings.HasPrefix(errb.String(), "error: usage error:") {
			t.Errorf("%v: stderr = %q", args, errb.String())
		}
	}
	// Platform-specific trees get the same treatment.
	_, _, err := run(t, cfgPath, "cf", "dns", "list")
	if ExitCodeFor(err) != ExitUsage {
		t.Errorf("cf dns list without zone = %v (exit %d)", err, ExitCodeFor(err))
	}
	// The global -p shorthand works on auth login/logout.
	if _, _, err := run(t, cfgPath, "auth", "logout", "-p", "nope"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("auth logout -p nope = %v (exit %d)", err, ExitCodeFor(err))
	}
}

func TestHelpGroupsAndFlagUsages(t *testing.T) {
	_, cfgPath := setup(t, false)
	stdout, _, err := run(t, cfgPath, "--help")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "Additional Commands:") {
		t.Errorf("core commands fell into cobra's fallback group:\n%s", stdout)
	}
	core := strings.Index(stdout, "Commands:")
	plat := strings.Index(stdout, "Platform-specific Commands:")
	if core < 0 || plat < 0 || core > plat {
		t.Errorf("group order wrong (core %d, platform %d):\n%s", core, plat, stdout)
	}
	// pflag reads text between backticks as the value placeholder, so no
	// flag usage anywhere in the tree may contain one.
	rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		c.LocalFlags().VisitAll(func(f *pflag.Flag) {
			if strings.Contains(f.Usage, "`") {
				t.Errorf("%s --%s: usage contains backticks: %q", c.CommandPath(), f.Name, f.Usage)
			}
		})
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(NewRoot(rt))
}

func TestSyncFailureExitsNonZero(t *testing.T) {
	_, cfgPath := setup(t, true)
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.syncErrs = map[platform.ResourceType]error{platform.ResDomain: errors.New("registrar unavailable")}

	stdout, _, err := run(t, cfgPath, "sync", "-o", "json")
	if err == nil || !strings.Contains(err.Error(), "1 resource set(s) failed") {
		t.Fatalf("sync with a failing set = %v, want an error", err)
	}
	var reports []app.SyncReport
	if json.Unmarshal([]byte(stdout), &reports) != nil || len(reports) != 3 {
		t.Fatalf("reports = %q", stdout)
	}
	if _, _, err := run(t, cfgPath, "domain", "index"); err == nil {
		t.Error("domain index with a failing set must not exit 0")
	}
}

func TestInventoryPathHonoursEnv(t *testing.T) {
	dir, cfgPath := setup(t, false)
	stdout, _, err := run(t, cfgPath, "inventory", "path")
	if err != nil || strings.TrimSpace(stdout) != filepath.Join(dir, "inventory.db") {
		t.Errorf("default path = %q, %v", stdout, err)
	}
	custom := filepath.Join(t.TempDir(), "x.db")
	t.Setenv("POLYCTL_INVENTORY_DB", custom)
	stdout, _, err = run(t, cfgPath, "inventory", "path")
	if err != nil || strings.TrimSpace(stdout) != custom {
		t.Errorf("env path = %q, %v", stdout, err)
	}
}

func TestDomainInfoErrors(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)
	// Both lookups miss: one message, exit 4.
	_, _, err := run(t, cfgPath, "domain", "info", "nothere.org", "--offline")
	if !errors.Is(err, app.ErrDomainUnknown) || ExitCodeFor(err) != ExitNotFound {
		t.Fatalf("double miss = %v (exit %d)", err, ExitCodeFor(err))
	}
	if n := strings.Count(err.Error(), app.ErrDomainUnknown.Error()); n != 1 || !strings.Contains(err.Error(), "neither a registered domain nor a DNS zone") {
		t.Errorf("double miss message = %q", err)
	}
	// An ambiguous zone keeps its own exit code even when the registrar misses.
	db := openInventory(t, dir)
	if err := db.Replace(context.Background(), inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResZone},
		app.ZoneResources([]platform.Zone{{ID: "z1", Name: "example.com"}, {ID: "z2", Name: "example.com"}}), time.Hour); err != nil {
		t.Fatal(err)
	}
	db.Close()
	_, _, err = run(t, cfgPath, "domain", "info", "example.com", "--offline")
	var amb *app.AmbiguousError
	if !errors.As(err, &amb) || ExitCodeFor(err) != ExitAmbiguous {
		t.Errorf("ambiguous zone = %v (exit %d)", err, ExitCodeFor(err))
	}
}

func TestAuthStatusOfflineReportsUnverified(t *testing.T) {
	_, cfgPath := setup(t, true)
	stdout, _, err := run(t, cfgPath, "auth", "status", "--offline", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []statusRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil || len(rows) != 1 {
		t.Fatalf("rows = %q, %v", stdout, err)
	}
	if !rows[0].OK || rows[0].Verified || rows[0].Identity != nil {
		t.Errorf("row = %+v, want ok, unverified, no identity", rows[0])
	}
	stdout, _, err = run(t, cfgPath, "auth", "status", "--offline")
	if err != nil || !strings.Contains(stdout, "present (not verified)") {
		t.Errorf("table = %q, %v", stdout, err)
	}
}

func TestAuthLoginSecretOptionFromStdin(t *testing.T) {
	_, cfgPath := setup(t, false)
	var out, errb bytes.Buffer
	code := Main([]string{"--config", cfgPath, "auth", "login", string(fakePlatform), "--set", "token=-"}, strings.NewReader("from-stdin\n"), &out, &errb)
	if code != ExitOK {
		t.Fatalf("exit %d: %s", code, errb.String())
	}
	if strings.Contains(errb.String(), "process listings") {
		t.Errorf("stdin value must not trigger the argv warning: %s", errb.String())
	}
	errb.Reset()
	code = Main([]string{"--config", cfgPath, "auth", "login", string(fakePlatform), "--set", "token=plain"}, strings.NewReader(""), &out, &errb)
	if code != ExitOK || !strings.Contains(errb.String(), "process listings") {
		t.Errorf("exit %d, stderr %q: --set token=... must warn", code, errb.String())
	}
}
