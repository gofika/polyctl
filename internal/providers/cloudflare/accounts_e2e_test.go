package cloudflare_test

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// loginBoth logs the profile "both" in with the token that sees acc1 and
// acc2, and stores the selection: def is the default account.
func (e *r2Env) loginBoth(def string, accounts ...string) {
	e.t.Helper()
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id="+def); code != cli.ExitOK {
		e.t.Fatalf("login both: exit %d, %s", code, stderr)
	}
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
	if len(accounts) > 0 {
		meta["accounts"] = strings.Join(accounts, ",")
	} else {
		delete(meta, "accounts")
	}
	if err := cfg.Save(); err != nil {
		e.t.Fatal(err)
	}
	e.f.reset()
}

// rows lists "id parent" of the cached rows of a type of a profile, sorted.
func (e *r2Env) rows(profile string, typ platform.ResourceType) []string {
	e.t.Helper()
	db, err := inventory.Open(filepath.Join(e.dir, "inventory.db"))
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: typ})
	if err != nil {
		e.t.Fatal(err)
	}
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.ID+" "+r.ParentID)
	}
	sort.Strings(out)
	return out
}

// dropZone removes a zone of the fake.
func (f *r2Fake) dropZone(id string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	var kept []r2Zone
	for _, z := range f.zones {
		if z.id != id {
			kept = append(kept, z)
		}
	}
	f.zones = kept
}

func (f *r2Fake) addRecord(zoneID, id, name, typ, content string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.records[zoneID] = append(f.records[zoneID], map[string]any{"id": id, "name": name, "type": typ, "content": content, "ttl": 1, "proxied": false})
}

// The inventory of a login holds the zones and the records of every
// selected account, and a sync that fails for one of them keeps what is
// stored for it.
func TestSyncSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1", "acc1", "acc2")

	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	wantZones := []string{"zone-a acc1", "zone-beta acc2", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}
	if got := e.rows("both", platform.ResZone); !reflect.DeepEqual(got, wantZones) {
		t.Fatalf("zones: %v", got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-beta zone-beta", "rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records: %v", got)
	}

	// acc2 stops answering, and acc1 loses a zone: the rows of acc2 (its
	// zone, and the records under it) are kept, those of acc1 replaced.
	e.f.failZones["acc2"] = 400
	e.f.dropZone("zone-pend")
	e.f.dropZone("zone-ex")
	code, stdout, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare", "-o", "json")
	if code == cli.ExitOK {
		t.Fatalf("a sync with a failed account must not exit 0: %s", stderr)
	}
	if want := "polyctl cloudflare account remove acc2"; !strings.Contains(stdout+stderr, want) {
		t.Errorf("the failure of acc2 is not reported with %q: %s%s", want, stdout, stderr)
	}
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-beta acc2", "zone-couk acc1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zones after the failure: %v", got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-beta zone-beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records after the failure: %v", got)
	}

	// The native zone list goes through the same sync.
	e.f.failZones["acc2"] = 0
	code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--refresh", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "a.example.com") {
		t.Fatalf("zone list: exit %d, %s%s", code, stdout, stderr)
	}
	e.f.failZones["acc2"] = 400
	code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--refresh", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || !strings.Contains(stderr, "warning") {
		t.Fatalf("zone list with a failed account: exit %d, %s%s", code, stdout, stderr)
	}
}

// The neutral commands reach a zone of every selected account.
func TestDomainRoutingSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1", "acc1", "acc2")
	for domain, want := range map[string]string{"example.com": "192.0.2.1", "example.net": "192.0.2.2"} {
		code, stdout, stderr := e.run("dns", "list", domain, "--profile", "both", "-o", "json")
		if code != cli.ExitOK || !strings.Contains(stdout, want) {
			t.Fatalf("dns list %s: exit %d, %s%s", domain, code, stdout, stderr)
		}
	}
	// A login of one account does not see the zone of the other.
	e.loginBoth("acc1")
	if code, _, stderr := e.run("dns", "list", "example.net", "--profile", "both", "--refresh"); code != cli.ExitNotFound {
		t.Fatalf("one account: exit %d, %s", code, stderr)
	}
}

// The name of an R2 bucket is unique in its account only: the rows of two
// selected accounts holding the same name do not replace each other.
func TestSyncBucketsSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "logs"}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.loginBoth("acc1", "acc1", "acc2")

	sync := func(profile string) (int, string) {
		code, stdout, stderr := e.run("sync", "--profile", profile, "--platform", "cloudflare", "--type", "r2_bucket")
		return code, stdout + stderr
	}
	if code, out := sync("both"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, out)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1", "acc2/assets acc2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets: %v", got)
	}
	// A login of one account keys its rows the same way.
	if code, out := sync("acme"); code != cli.ExitOK {
		t.Fatalf("sync acme: exit %d, %s", code, out)
	}
	if got, want := e.rows("acme", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets of one account: %v", got)
	}
	// The listing shows the buckets of both accounts of the login.
	code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || strings.Count(stdout, `"name": "assets"`) != 2 || !strings.Contains(stdout, `"account_id": "acc2"`) {
		t.Fatalf("bucket list: exit %d, %s%s", code, stdout, stderr)
	}

	// An account without R2 holds no bucket: the sync does not fail for
	// it (it warns on the standard error of the process).
	e.f.accounts["acc2"].r2Disabled = true
	code, out := sync("both")
	if code != cli.ExitOK {
		t.Fatalf("sync without R2 in acc2: exit %d, %s", code, out)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets without R2 in acc2: %v", got)
	}
	// ... and so does the listing; only when no account of the login can
	// be used for R2 is that its answer (exit code 7).
	code, stdout, stderr = e.run("--refresh", "cloudflare", "r2", "bucket", "list", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "logs") {
		t.Fatalf("bucket list without R2 in acc2: exit %d, %s%s", code, stdout, stderr)
	}
	e.f.accounts["acc1"].r2Disabled = true
	if code, _, stderr = e.run("--refresh", "cloudflare", "r2", "bucket", "list", "--profile", "both"); code != cli.ExitNotSupported {
		t.Fatalf("bucket list without R2 at all: exit %d, %s", code, stderr)
	}
	if code, out := sync("both"); code != cli.ExitOK {
		t.Fatalf("sync without R2 at all: exit %d, %s", code, out)
	}
}

// A domain two selected accounts of one login hold a zone of is ambiguous
// for the neutral commands (exit code 5), and the hint names what tells
// the zones apart.
func TestDomainRoutingAmbiguousAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.zones = append(e.f.zones, r2Zone{"zone-dup", "example.com", "pending", "acc2"})
	e.loginBoth("acc1", "acc1", "acc2")
	code, _, stderr := e.run("dns", "list", "example.com", "--profile", "both")
	if code != cli.ExitAmbiguous {
		t.Fatalf("exit %d, %s", code, stderr)
	}
	for _, want := range []string{"zone-ex", "zone-dup", "--account <id or name>", "zone id"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the ambiguity lacks %q: %s", want, stderr)
		}
	}
	if strings.Contains(stderr, "--profile <name>") {
		t.Errorf("--profile does not tell the zones apart: %s", stderr)
	}
}

// The zone list of a login covers its selected accounts and says which
// account a zone is of; --account, by id or by name, narrows it to one.
func TestZoneListSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1", "acc1", "acc2")
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both")
	if code != cli.ExitOK {
		t.Fatalf("list: exit %d, %s", code, stderr)
	}
	for _, want := range []string{"ACCOUNT", "Acme", "Beta", "example.com", "example.net"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the list of two accounts lacks %q:\n%s", want, stdout)
		}
	}
	// One account: the list is what it always was.
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "acme"); code != cli.ExitOK || strings.Contains(stdout, "ACCOUNT") {
		t.Errorf("list of one account: exit %d, %s%s", code, stdout, stderr)
	}
	// "beta" is a name the cached zones of the login carry: no request.
	for _, ref := range []string{"acc2", "beta"} {
		e.f.reset()
		code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--account", ref)
		if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || strings.Contains(stdout, "example.com") || strings.Contains(stdout, "ACCOUNT") {
			t.Errorf("--account %s: exit %d, %s%s", ref, code, stdout, stderr)
		}
		if n := e.f.count(""); n != 0 {
			t.Errorf("--account %s of a selected account made %d requests", ref, n)
		}
	}
	// An account the credentials do not see is not found; a name the
	// login cannot look up offline is refused.
	if code, _, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--account", "nope"); code != cli.ExitNotFound || !strings.Contains(stderr, "not visible") {
		t.Errorf("--account nope: exit %d, %s", code, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--account", "nope", "--offline"); code != cli.ExitOffline {
		t.Errorf("--account nope --offline: exit %d, %s", code, stderr)
	}
	// The zone id of another account than --account is a usage error.
	code, _, stderr = e.run("cloudflare", "zone", "get", "zone-beta", "--profile", "both", "--account", "acc1")
	if code != cli.ExitUsage || !strings.Contains(stderr, "is of account acc2, not of --account acc1") {
		t.Errorf("zone id of another account: exit %d, %s", code, stderr)
	}
}

// An account outside the selection is read live with --account, by id or
// by name, and nothing of it reaches the inventory; without the flag its
// zones are not found, and the answer says where they are.
func TestUnselectedAccountIsReadLive(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1")

	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || strings.Contains(stdout, "example.com") {
		t.Fatalf("zone list: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "zone", "get", "example.net", "--profile", "both", "--account", "Beta", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "zone-beta"`) {
		t.Fatalf("zone get: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "dns", "list", "zone-beta", "--profile", "both", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "192.0.2.2") || !strings.Contains(stdout, `"cached": false`) {
		t.Fatalf("dns list: exit %d, %s%s", code, stdout, stderr)
	}
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResDNSRecord} {
		for _, row := range e.rows("both", typ) {
			if strings.Contains(row, "beta") {
				t.Errorf("a row of the unselected account was stored: %s", row)
			}
		}
	}
	// Offline there is nothing to read it from.
	if code, _, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--account", "acc2", "--offline"); code != cli.ExitOffline {
		t.Errorf("--offline: exit %d, %s", code, stderr)
	}
	// Without --account the zone is not one of the login.
	for _, ref := range []string{"example.net", "zone-beta"} {
		code, _, stderr = e.run("cloudflare", "zone", "get", ref, "--profile", "both")
		if code != cli.ExitNotFound || !strings.Contains(stderr, "polyctl cloudflare account add acc2") || !strings.Contains(stderr, "--account acc2") {
			t.Errorf("zone get %s without --account: exit %d, %s", ref, code, stderr)
		}
	}
	// A zone of the selected account, named by id with the --account of
	// the other one.
	code, _, stderr = e.run("cloudflare", "zone", "get", "zone-ex", "--profile", "both", "--account", "acc2")
	if code != cli.ExitUsage || !strings.Contains(stderr, "not of --account acc2") {
		t.Errorf("zone id of the selected account: exit %d, %s", code, stderr)
	}
}

// A cached zone of an account that left the selection is not one of the
// login any more, although the set that holds it is still fresh.
func TestDeselectedAccountRowsAreOutOfScope(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1", "acc1", "acc2")
	if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("list: exit %d, %s", code, stderr)
	}
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	delete(cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata, "accounts")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both", "--offline")
	if code != cli.ExitOK || strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "example.com") {
		t.Errorf("list after the deselection: exit %d, %s%s", code, stdout, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "zone", "get", "example.net", "--profile", "both", "--offline"); code != cli.ExitNotFound {
		t.Errorf("get after the deselection: exit %d, %s", code, stderr)
	}
}

// A zone name two selected accounts hold a zone of is ambiguous (exit code
// 5) for the commands of one profile, a pick on a terminal, and --account
// chooses.
func TestZoneNameInTwoAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.zones = append(e.f.zones, r2Zone{"zone-dup", "example.com", "pending", "acc2"})
	e.loginBoth("acc1", "acc1", "acc2")
	for _, args := range [][]string{{"zone", "get", "example.com"}, {"dns", "list", "example.com"}, {"ssl-mode", "example.com"}} {
		code, _, stderr := e.run(append(append([]string{"cloudflare"}, args...), "--profile", "both")...)
		if code != cli.ExitAmbiguous {
			t.Fatalf("%v: exit %d, %s", args, code, stderr)
		}
		for _, want := range []string{"account acc1 (Acme) zone zone-ex active", "account acc2 (Beta) zone zone-dup pending", "pass --account <id or name>, or the zone id, to choose"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%v: the ambiguity lacks %q: %s", args, want, stderr)
			}
		}
		if strings.Contains(stderr, "--profile <name>") {
			t.Errorf("%v: --profile does not tell the zones apart: %s", args, stderr)
		}
	}
	// The same before the inventory knows the zones.
	e.loginBoth("acc1", "acc1", "acc2")
	if err := os.Remove(filepath.Join(e.dir, "inventory.db")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "get", "example.com", "--profile", "both", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "zone-dup"`) {
		t.Errorf("--account acc2: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "zone", "get", "zone-dup", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "zone-dup"`) {
		t.Errorf("by id: exit %d, %s%s", code, stdout, stderr)
	}
	// On a terminal the zones are offered with their accounts.
	p := prompttest.New(t, prompttest.Label("zone-dup"))
	code, stdout, stderr = e.runPick(p, "cloudflare", "zone", "get", "example.com", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "zone-dup"`) {
		t.Errorf("pick: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find(`Ambiguous zone "example.com"; use which one?`); a == nil || len(a.Options) != 2 || !strings.Contains(prompttest.Labels(a.Options), "account acc2 (Beta)") {
		t.Errorf("questions asked: %v", p.Titles())
	}
	p.Done()
	// A pick without a name shows the account of each zone.
	p = prompttest.New(t, "zone-dup")
	code, stdout, stderr = e.runPick(p, "cloudflare", "zone", "get", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "zone-dup"`) {
		t.Errorf("pick without a name: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find("Zone"); a == nil || !strings.Contains(prompttest.Labels(a.Options), "account Beta") || !strings.Contains(prompttest.Labels(a.Options), "account Acme") {
		t.Errorf("zone options: %+v", a)
	}
}
