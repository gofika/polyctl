package cloudflare_test

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"

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

// loginBoth logs the profile "both" in with the token that sees acc1 and
// acc2, and stores the selection: def is the default account.
func (e *zoneEnv) loginBoth(def string, accounts ...string) {
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

// zoneRows lists the ids of the cached zones of a profile.
func (e *zoneEnv) zoneRows(profile string) string {
	e.t.Helper()
	var ids []string
	for _, r := range e.inventory(platform.ResZone) {
		if r.Profile == profile {
			ids = append(ids, r.ID)
		}
	}
	sort.Strings(ids)
	return strings.Join(ids, " ")
}

// The commands that find their zone among the logins (zone setting, zone
// delete, the rules) find it in every selected account of a login; a name
// two of them hold a zone of is ambiguous (exit code 5), a pick on a
// terminal, and --account, by id or by name, chooses.
func TestRoutedZoneSeveralAccounts(t *testing.T) {
	e := newZoneEnv(t)
	ex := e.f.addZone("example.com", "acc1", "free", "active")
	dup := e.f.addZone("example.com", "acc2", "free", "pending")
	net := e.f.addZone("example.net", "acc2", "free", "active")
	dup.settings["ssl"].value = "strict"
	e.loginBoth("acc1", "acc1", "acc2")

	// A zone of the account that is not the default one.
	code, stdout, stderr := e.run("cloudflare", "zone", "setting", "get", "example.net", "ssl", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "full"`) {
		t.Fatalf("setting get in acc2: exit %d, %s%s", code, stdout, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "cache", "rule", "list", "example.net", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("rule list in acc2: exit %d, %s", code, stderr)
	}

	for _, args := range [][]string{
		{"zone", "setting", "get", "example.com", "ssl"},
		{"zone", "delete", "example.com", "--yes"},
		{"cache", "rule", "list", "example.com"},
	} {
		code, _, stderr = e.run(append(append([]string{"cloudflare"}, args...), "--profile", "both")...)
		if code != cli.ExitAmbiguous {
			t.Fatalf("%v: exit %d, %s", args, code, stderr)
		}
		for _, want := range []string{"account acc1 (Account acc1) zone " + ex.id + " active", "account acc2 (Account acc2) zone " + dup.id + " pending",
			"pass --account <id or name>, or the zone id, to choose"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%v: the ambiguity lacks %q: %s", args, want, stderr)
			}
		}
		if strings.Contains(stderr, "--profile <name>") {
			t.Errorf("%v: --profile does not tell the zones apart: %s", args, stderr)
		}
	}
	if ex.deleted || dup.deleted {
		t.Fatal("an ambiguous zone delete deleted a zone")
	}
	for _, ref := range []string{"acc2", "account ACC2"} {
		code, stdout, stderr = e.run("cloudflare", "zone", "setting", "get", "example.com", "ssl", "--profile", "both", "--account", ref, "-o", "json")
		if code != cli.ExitOK || !strings.Contains(stdout, `"value": "strict"`) {
			t.Errorf("--account %q: exit %d, %s%s", ref, code, stdout, stderr)
		}
	}
	// The zone id chooses too; with the --account of the other account
	// it is a usage error.
	code, stdout, stderr = e.run("cloudflare", "zone", "setting", "get", dup.id, "ssl", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "strict"`) {
		t.Errorf("by id: exit %d, %s%s", code, stdout, stderr)
	}
	code, _, stderr = e.run("cloudflare", "zone", "setting", "get", dup.id, "ssl", "--profile", "both", "--account", "acc1")
	if code != cli.ExitUsage || !strings.Contains(stderr, "is of account acc2, not of --account acc1") {
		t.Errorf("zone id with the other --account: exit %d, %s", code, stderr)
	}
	// On a terminal: the two zones with their accounts.
	p := prompttest.New(t, prompttest.Label(dup.id))
	code, stdout, stderr = e.runPick(p, "cloudflare", "zone", "setting", "get", "example.com", "ssl", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "strict"`) {
		t.Errorf("pick: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find(`Ambiguous cloudflare zone "example.com"; use which one?`); a == nil || len(a.Options) != 2 || !strings.Contains(prompttest.Labels(a.Options), "account acc2 (Account acc2)") {
		t.Errorf("questions asked: %v", p.Titles())
	}
	p.Done()
	// A pick without a name shows the account of the zones of the login.
	p = prompttest.New(t, net.id, "ssl")
	if code, _, stderr = e.runPick(p, "cloudflare", "zone", "setting", "get", "--profile", "both"); code != cli.ExitOK {
		t.Errorf("pick without a name: exit %d, %s", code, stderr)
	}
	if a := p.Find("Zone"); a == nil || len(a.Options) != 3 || !strings.Contains(prompttest.Labels(a.Options), "account Account acc2") {
		t.Errorf("zone options: %+v", a)
	}
	p.Done()

	// zone delete with --account deletes the zone of that account only,
	// and the inventory keeps the zone of the same name of the other one.
	code, _, stderr = e.run("cloudflare", "zone", "delete", "example.com", "--profile", "both", "--account", "acc2", "--yes")
	if code != cli.ExitOK || !dup.deleted || ex.deleted {
		t.Fatalf("delete --account acc2: exit %d, dup %v, ex %v, %s", code, dup.deleted, ex.deleted, stderr)
	}
	if got, want := e.zoneRows("both"), strings.Join(sortedIDs(ex.id, net.id), " "); got != want {
		t.Errorf("zones of both after the delete: %s, want %s", got, want)
	}
}

func sortedIDs(ids ...string) []string {
	sort.Strings(ids)
	return ids
}

// The same commands read the zones of an account outside the selection
// live with --account and store nothing of it; without --profile the flag
// finds the login that selects the account.
func TestRoutedZoneUnselectedAccount(t *testing.T) {
	e := newZoneEnv(t)
	ex := e.f.addZone("example.com", "acc1", "free", "active")
	net := e.f.addZone("example.net", "acc2", "free", "active")
	e.loginBoth("acc1")

	code, _, stderr := e.run("cloudflare", "zone", "setting", "get", "example.net", "ssl", "--profile", "both")
	if code != cli.ExitNotFound {
		t.Fatalf("without --account: exit %d, %s", code, stderr)
	}
	for _, ref := range []string{"acc2", "Account acc2"} {
		code, stdout, stderr := e.run("cloudflare", "zone", "setting", "get", "example.net", "ssl", "--profile", "both", "--account", ref, "-o", "json")
		if code != cli.ExitOK || !strings.Contains(stdout, `"value": "full"`) {
			t.Fatalf("--account %q: exit %d, %s%s", ref, code, stdout, stderr)
		}
	}
	code, _, stderr = e.run("cloudflare", "zone", "setting", "set", net.id, "ssl", "strict", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || net.settings["ssl"].value != "strict" {
		t.Fatalf("setting set: exit %d, %s", code, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "redirect", "rule", "list", "example.net", "--profile", "both", "--account", "acc2"); code != cli.ExitOK {
		t.Fatalf("rule list: exit %d, %s", code, stderr)
	}
	if got := e.zoneRows("both"); got != ex.id {
		t.Errorf("zones stored for both: %q, want only %s", got, ex.id)
	}
	// A zone id of the selected account with the --account of the other.
	code, _, stderr = e.run("cloudflare", "zone", "setting", "get", ex.id, "ssl", "--profile", "both", "--account", "acc2")
	if code != cli.ExitUsage || !strings.Contains(stderr, "not of --account acc2") {
		t.Errorf("zone id of acc1 with --account acc2: exit %d, %s", code, stderr)
	}
	// On a terminal the zone is asked for among those read from the account.
	p := prompttest.New(t, net.id, "ssl")
	code, stdout, stderr := e.runPick(p, "cloudflare", "zone", "setting", "get", "--profile", "both", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "strict"`) {
		t.Errorf("pick in the unselected account: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find("Zone"); a == nil || len(a.Options) != 1 || !strings.Contains(a.Options[0].Label, "example.net") {
		t.Errorf("zone options: %+v", a)
	}
	p.Done()
	// Without --profile the login that selects the account is used: beta.
	code, stdout, stderr = e.run("cloudflare", "zone", "setting", "get", "example.net", "ssl", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "strict"`) {
		t.Errorf("--account without --profile: exit %d, %s%s", code, stdout, stderr)
	}
	if got := e.zoneRows("beta"); got != net.id {
		t.Errorf("zones stored for beta: %q", got)
	}
	if code, _, stderr = e.run("cloudflare", "zone", "setting", "get", "example.com", "ssl", "--account", "acc2"); code != cli.ExitNotFound {
		t.Errorf("a zone of acc1 with --account acc2: exit %d, %s", code, stderr)
	}
}

// createdIn is the account id of the last zone creation sent to the fake.
func (e *zoneEnv) createdIn() string {
	account, _ := e.f.body("POST /zones")["account"].(map[string]any)
	id, _ := account["id"].(string)
	return id
}

// zone create and zone ensure of a login with several accounts: a new zone
// goes to --account, else to the default account; an existing zone is
// looked for in every selected account and reused where it is.
func TestZoneEnsureSeveralAccounts(t *testing.T) {
	e := newZoneEnv(t)
	net := e.f.addZone("example.net", "acc2", "free", "active")
	e.loginBoth("acc1", "acc1", "acc2")

	// The zone of the account that is not the default one is reused.
	code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "example.net", "--profile", "both", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("ensure: exit %d, %s", code, stderr)
	}
	if rep := e.report(stdout); rep.Zone.ID != net.id || rep.Target.AccountID != "acc2" || len(e.f.writes()) != 0 {
		t.Errorf("ensure reused %s in %s, writes %v", rep.Zone.ID, rep.Target.AccountID, e.f.writes())
	}
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.net", "--profile", "both")
	if code != cli.ExitError || !strings.Contains(stderr, "already exists in account acc2 of profile both") || len(e.f.writes()) != 0 {
		t.Errorf("create of an existing zone: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}

	// A new zone goes to the default account, or to --account (by id or
	// by name).
	code, stdout, stderr = e.run("cloudflare", "zone", "create", "example.org", "--profile", "both", "--foundation-dns=false", "-o", "json")
	if code != cli.ExitOK || e.createdIn() != "acc1" || e.report(stdout).Target.AccountID != "acc1" {
		t.Errorf("create: exit %d, in %q, %s%s", code, e.createdIn(), stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "zone", "create", "example.info", "--profile", "both", "--account", "Account acc2", "--foundation-dns=false", "-o", "json")
	if code != cli.ExitOK || e.createdIn() != "acc2" || e.report(stdout).Target.AccountID != "acc2" {
		t.Errorf("create --account: exit %d, in %q, %s%s", code, e.createdIn(), stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "zone", "ensure", "example.dev", "--profile", "both", "--account", "acc2", "--dry-run", "-o", "json")
	if code != cli.ExitOK || changeMap(e.report(stdout).Changes)["zone/example.dev"] != "would_create account=acc2 type=full" {
		t.Errorf("ensure --account --dry-run: exit %d, %s%s", code, stdout, stderr)
	}
	// With --account only that account is looked in: the zone of the
	// other one is not found there, and Cloudflare refuses a second one.
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "ensure", "example.net", "--profile", "both", "--account", "acc1")
	if code != cli.ExitError || !strings.Contains(stderr, "pass --account or --profile to target the account that holds it") {
		t.Errorf("ensure in the other account: exit %d, %s", code, stderr)
	}

	// A domain with a zone in two selected accounts.
	one := e.f.addZone("example.com", "acc1", "free", "active")
	two := e.f.addZone("example.com", "acc2", "free", "pending")
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "ensure", "example.com", "--profile", "both")
	if code != cli.ExitAmbiguous || !strings.Contains(stderr, one.id) || !strings.Contains(stderr, two.id) || !strings.Contains(stderr, "pass --account <id or name>, or the zone id, to choose") {
		t.Errorf("ensure of a name in two accounts: exit %d, %s", code, stderr)
	}
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.com", "--profile", "both")
	if code != cli.ExitError || !strings.Contains(stderr, "already exists in 2 accounts of profile both") || !strings.Contains(stderr, "--account") {
		t.Errorf("create of a name in two accounts: exit %d, %s", code, stderr)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("ambiguous runs wrote: %v", w)
	}
	if code, _, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--refresh"); code != cli.ExitOK {
		t.Fatalf("zone list: exit %d, %s", code, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "zone", "ensure", "example.com", "--profile", "both", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || e.report(stdout).Zone.ID != two.id {
		t.Errorf("ensure --account acc2: exit %d, %s%s", code, stdout, stderr)
	}
	p := prompttest.New(t, prompttest.Label(two.id))
	code, stdout, stderr = e.runPick(p, "cloudflare", "zone", "ensure", "example.com", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || e.report(stdout).Zone.ID != two.id || e.report(stdout).Target.AccountID != "acc2" {
		t.Errorf("ensure pick: exit %d, %s%s", code, stdout, stderr)
	}
	p.Done()
	// Both zones stay in the inventory, each under its account.
	if got := e.zoneRows("both"); !strings.Contains(got, one.id) || !strings.Contains(got, two.id) {
		t.Errorf("zones of both: %s, want %s and %s among them", got, one.id, two.id)
	}
}

// A zone created in an account outside the selection is not stored, and a
// login without an account asks for one or takes --account.
func TestZoneCreateOutsideTheSelection(t *testing.T) {
	e := newZoneEnv(t)
	e.loginBoth("acc1")
	code, _, stderr := e.run("cloudflare", "zone", "create", "example.io", "--profile", "both", "--account", "acc2", "--foundation-dns=false")
	if code != cli.ExitOK || e.createdIn() != "acc2" {
		t.Fatalf("create in the unselected account: exit %d, in %q, %s", code, e.createdIn(), stderr)
	}
	if !strings.Contains(stderr, "account acc2 is not selected, so the new zone is not in the inventory (polyctl cloudflare account add acc2)") {
		t.Errorf("no note about the inventory: %s", stderr)
	}
	if got := e.zoneRows("both"); got != "" {
		t.Errorf("zones stored for both: %q", got)
	}

	// A login without an account.
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
	delete(meta, "account_id")
	delete(meta, "account_name")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.dev", "--profile", "both")
	if code != cli.ExitUsage || !strings.Contains(stderr, `pass --account <id or name>, or select the accounts of the login with "polyctl cloudflare account use <id>"`) || len(e.f.writes()) != 0 {
		t.Errorf("several accounts and none named: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
	if strings.Contains(stderr, "--set account_id") {
		t.Errorf("the old way to pin an account is still named: %s", stderr)
	}
	p := prompttest.New(t, "acc2")
	code, _, stderr = e.runPick(p, "cloudflare", "zone", "create", "example.dev", "--profile", "both", "--foundation-dns=false")
	if code != cli.ExitOK || e.createdIn() != "acc2" || !strings.Contains(stderr, "pass --account acc2, or make it the default account: polyctl cloudflare account use acc2") {
		t.Errorf("asked account: exit %d, in %q, %s", code, e.createdIn(), stderr)
	}
	p.Done()
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.app", "--profile", "both", "--account", "acc1", "--foundation-dns=false")
	if code != cli.ExitOK || e.createdIn() != "acc1" {
		t.Errorf("--account of a login without an account: exit %d, in %q, %s", code, e.createdIn(), stderr)
	}
	// Such a login covers what its credentials see: the zone is stored.
	if got := e.zoneRows("both"); got == "" {
		t.Errorf("the zone of a login without an account was not stored")
	}
}

// The R2 buckets of a login with several accounts: the listing shows those
// of every selected account with their account, --account narrows it, and
// an account outside the selection is read live and not cached.
func TestR2BucketListSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "logs"}
	e.f.accounts["acc2"].buckets = []string{"assets", "media"}
	e.loginBoth("acc1", "acc1", "acc2")

	code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "ACCOUNT") || !strings.Contains(stderr, "4 bucket(s) in 2 account(s)") {
		t.Fatalf("bucket list: exit %d, %s%s", code, stdout, stderr)
	}
	for _, want := range [][]string{{"both", "acc1", "assets"}, {"both", "acc2", "assets"}, {"both", "acc1", "logs"}, {"both", "acc2", "media"}} {
		found := false
		for _, line := range strings.Split(stdout, "\n") {
			found = found || reflect.DeepEqual(strings.Fields(line)[:min(3, len(strings.Fields(line)))], want)
		}
		if !found {
			t.Errorf("no line %v in %s", want, stdout)
		}
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1", "acc2/assets acc2", "acc2/media acc2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("cached buckets: %v", got)
	}
	// --account narrows the cached listing, by id or by name, and --wide
	// reads each bucket in its own account.
	e.f.reset()
	code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || strings.Contains(stdout, "ACCOUNT") || strings.Contains(stdout, "logs") || !strings.Contains(stdout, "media") || len(e.f.requests) != 0 {
		t.Errorf("--account acc2: exit %d, %s%s, requests %v", code, stdout, stderr, e.f.requests)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "Beta", "--wide", "-o", "json")
	if code != cli.ExitOK || strings.Contains(stdout, `"account_id": "acc1"`) || strings.Count(stdout, `"location": "APAC"`) != 2 ||
		e.f.count("GET /accounts/acc2/r2/buckets/media") != 1 || e.f.count("GET /accounts/acc1/r2/buckets/") != 0 {
		t.Errorf("--account Beta --wide: exit %d, %s%s, requests %v", code, stdout, stderr, e.f.requests)
	}
	// A profile of one account says nothing of accounts; an account one
	// profile listed is not listed again by another.
	code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list")
	if code != cli.ExitOK || strings.Contains(stdout, "ACCOUNT") || strings.Contains(stdout, "both") || !strings.Contains(stderr, "4 bucket(s) in 2 account(s)") {
		t.Errorf("every profile: exit %d, %s%s", code, stdout, stderr)
	}
	// Another jurisdiction is read live in every selected account.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--jurisdiction", "eu"); code != cli.ExitOK ||
		e.f.count("GET /accounts/acc1/r2/buckets?") != 1 || e.f.count("GET /accounts/acc2/r2/buckets?") != 1 {
		t.Errorf("--jurisdiction: exit %d, %s, requests %v", code, stderr, e.f.requests)
	}

	// An account outside the selection is read live and not cached.
	e.loginBoth("acc1")
	if code, _, stderr := e.run("--refresh", "cloudflare", "r2", "bucket", "list", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("list of one account: exit %d, %s", code, stderr)
	}
	for range 2 {
		e.f.reset()
		code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "acc2")
		if code != cli.ExitOK || !strings.Contains(stdout, "media") || strings.Contains(stdout, "logs") || e.f.count("GET /accounts/acc2/r2/buckets?") != 1 {
			t.Errorf("unselected account: exit %d, %s%s, requests %v", code, stdout, stderr, e.f.requests)
		}
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("an unselected account was cached: %v", got)
	}
	if code, _, _ := e.run("--offline", "cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "acc2"); code != cli.ExitOffline {
		t.Errorf("unselected account offline: exit %d", code)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("listings wrote: %v", w)
	}
}

// A bucket name two selected accounts of one login hold a bucket of is
// ambiguous (exit code 5) with the flag that chooses, --account settles
// it, and a terminal asks.
func TestR2BucketNameInTwoAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.bind("acc2", "assets", "cdn.example.net", "zone-beta", true, "")
	e.loginBoth("acc1", "acc1", "acc2")

	// With and without the inventory knowing the buckets.
	for _, sync := range []bool{false, true} {
		if sync {
			if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare", "--type", "r2_bucket"); code != cli.ExitOK {
				t.Fatalf("sync: exit %d, %s", code, stderr)
			}
		}
		code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "assets", "--profile", "both")
		if code != cli.ExitAmbiguous {
			t.Fatalf("synced %t: exit %d, %s", sync, code, stderr)
		}
		for _, want := range []string{"cloudflare/both account acc1", "cloudflare/both account acc2", "pass --account <id or name> to choose"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("synced %t: the ambiguity lacks %q: %s", sync, want, stderr)
			}
		}
		if strings.Contains(stderr, "--profile <name>") {
			t.Errorf("synced %t: --profile does not tell the buckets apart: %s", sync, stderr)
		}
	}
	// --account names the one: no bucket is listed for it.
	e.f.reset()
	code, stdout, stderr := e.run("cloudflare", "r2", "domain", "list", "assets", "--profile", "both", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "cdn.example.net") || !strings.Contains(stdout, `"account_id": "acc2"`) ||
		!strings.Contains(stderr, "bucket assets via account acc2 of cloudflare/both") || e.f.count("GET /accounts/acc2/r2/buckets?") != 0 {
		t.Errorf("--account acc2: exit %d, %s%s, requests %v", code, stdout, stderr, e.f.requests)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "list", "assets", "--profile", "both", "--account", "acc1", "-o", "json")
	if code != cli.ExitOK || strings.Contains(stdout, "cdn.example.net") {
		t.Errorf("--account acc1: exit %d, %s%s", code, stdout, stderr)
	}
	// A write does not go out for an ambiguous bucket.
	if code, _, _ := e.run("cloudflare", "r2", "domain", "detach", "assets", "cdn.example.net", "--profile", "both", "--yes"); code != cli.ExitAmbiguous || len(e.f.writes()) != 0 {
		t.Errorf("ambiguous detach: exit %d, writes %v", code, e.f.writes())
	}

	// On a terminal the accounts are offered.
	p := prompttest.New(t, prompttest.Label("account acc2"))
	code, stdout, stderr = e.runPick(p, "cloudflare", "r2", "domain", "list", "assets", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "cdn.example.net") {
		t.Errorf("pick: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find(`Ambiguous R2 bucket "assets" (several accounts hold a bucket of that name); use which one?`); a == nil || len(a.Options) != 2 ||
		!strings.Contains(prompttest.Labels(a.Options), "cloudflare/both account acc1") {
		t.Errorf("questions asked: %v", p.Titles())
	}
	p.Done()
	// A pick of the bucket shows each with its account, and the one
	// picked is not asked for again.
	p = prompttest.New(t, "acc2/assets")
	code, stdout, stderr = e.runPick(p, "cloudflare", "r2", "domain", "list", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "cdn.example.net") {
		t.Errorf("pick without a name: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find("R2 bucket"); a == nil || prompttest.Values(a.Options) != "acc1/assets acc2/assets" || !strings.Contains(prompttest.Labels(a.Options), "assets  cloudflare/both  account acc2") {
		t.Errorf("bucket options: %v", p.Titles())
	}
	p.Done()
}

// A bucket of the second selected account of a login is found live and
// through the inventory, and a custom domain is bound in its account.
func TestR2DomainInTheSecondAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.loginBoth("acc1", "acc1", "acc2")

	code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stderr, "bucket media via account acc2 of cloudflare/both") || e.f.count("GET /accounts/acc2/r2/buckets?") != 1 {
		t.Fatalf("live: exit %d, %s, requests %v", code, stderr, e.f.requests)
	}
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare", "--type", "r2_bucket"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stderr, "bucket media via account acc2 of cloudflare/both (local inventory)") || e.f.count("GET /accounts/acc1/r2/buckets?")+e.f.count("GET /accounts/acc2/r2/buckets?") != 0 {
		t.Errorf("inventory: exit %d, %s, requests %v", code, stderr, e.f.requests)
	}
	// A bucket of neither account: the accounts searched are named.
	code, _, stderr = e.run("cloudflare", "r2", "domain", "list", "nosuch", "--profile", "both")
	if code != cli.ExitNotFound || !strings.Contains(stderr, "bucket nosuch not found in the selected accounts of cloudflare/both (acc1, acc2)") {
		t.Errorf("missing bucket: exit %d, %s", code, stderr)
	}
	// An account without R2 is skipped and named.
	e.f.accounts["acc1"].r2Disabled = true
	code, _, stderr = e.run("cloudflare", "r2", "domain", "list", "nosuch", "--profile", "both")
	if code != cli.ExitNotFound || !strings.Contains(stderr, "these accounts were skipped: both account acc1 (R2 is not enabled)") {
		t.Errorf("missing bucket, acc1 without R2: exit %d, %s", code, stderr)
	}
	e.f.accounts["acc1"].r2Disabled = false

	// The zone of a binding is one of the account of the bucket.
	code, stdout, stderr := e.run("cloudflare", "r2", "domain", "attach", "media", "cdn.example.net", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stderr, "bound cdn.example.net to bucket media via account acc2 of cloudflare/both") {
		t.Fatalf("attach: exit %d, %s%s", code, stdout, stderr)
	}
	if body := e.f.body("POST /accounts/acc2/r2/buckets/media/domains/custom"); body["zoneId"] != "zone-beta" {
		t.Errorf("attach body: %v", body)
	}
	if rows := e.cachedRecords("cdn.example.net"); len(rows) != 1 || rows[0].Profile != "both" {
		t.Errorf("the CNAME record of the binding is not cached: %v", rows)
	}
	// A zone of the other account does not hold the domain of the bucket.
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "media", "cdn.example.com", "--profile", "both")
	if code != cli.ExitNotFound || !strings.Contains(stderr, "no zone for cdn.example.com found in account acc2 of cloudflare/both") {
		t.Errorf("zone of the other account: exit %d, %s", code, stderr)
	}
	code, _, stderr = e.run("cloudflare", "r2", "domain", "detach", "media", "cdn.example.net", "--profile", "both", "--yes")
	if w := e.f.writes(); code != cli.ExitOK || w[len(w)-1] != "DELETE /accounts/acc2/r2/buckets/media/domains/custom/cdn.example.net" {
		t.Errorf("detach: exit %d, %s, writes %v", code, stderr, w)
	}

	// A bucket of an account outside the selection: --account reaches it,
	// and nothing of the binding is cached.
	e.loginBoth("acc1")
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both"); code != cli.ExitNotFound {
		t.Errorf("unselected account without --account: exit %d, %s", code, stderr)
	}
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "media", "cdn.example.net", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stderr, "via account acc2 of cloudflare/both") {
		t.Fatalf("attach in an unselected account: exit %d, %s", code, stderr)
	}
	for _, r := range e.cachedRecords("cdn.example.net") {
		if r.Profile == "both" {
			t.Errorf("a record of an unselected account was cached: %v", r)
		}
	}
}

// Deleting the CNAME record of an R2 custom domain unbinds it from a
// bucket in another selected account of the same login, without the other
// logins being asked.
func TestDNSDeleteUnbindsInAnotherSelectedAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.bind("acc2", "assets", "cdn.example.com", "zone-ex", true, "")
	recID := e.f.records["zone-ex"][0]["id"].(string)
	e.loginBoth("acc1", "acc1", "acc2")

	code, _, stderr := e.run("cloudflare", "dns", "delete", "example.com", recID, "--profile", "both")
	if code != cli.ExitOK {
		t.Fatalf("delete: exit %d, %s", code, stderr)
	}
	want := []string{"DELETE /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com", "DELETE /accounts/acc2/r2/buckets/assets/domains/custom/cdn.example.com"}
	if w := e.f.writes(); !reflect.DeepEqual(w, want) {
		t.Errorf("writes = %v", w)
	}
	if n := len(e.f.accounts["acc2"].domains["assets"]); n != 0 {
		t.Errorf("the domain is still bound: %v", e.f.accounts["acc2"].domains["assets"])
	}
}

// A login without an account whose credentials see several accounts names
// --account as the way to say which one an R2 command works on.
func TestR2LoginWithoutAnAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"logs"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.f.bind("acc2", "media", "cdn.example.net", "zone-beta", true, "")
	e.loginBoth("acc1")
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
	delete(meta, "account_id")
	delete(meta, "account_name")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}

	for _, args := range [][]string{{"r2", "bucket", "list"}, {"r2", "domain", "list", "media"}} {
		code, _, stderr := e.run(append(append([]string{"cloudflare"}, args...), "--profile", "both")...)
		if code != cli.ExitAmbiguous || !strings.Contains(stderr, `sees 2 accounts (acc1=Acme, acc2=Beta): pass --account <id or name>, or select the accounts of the login with "polyctl cloudflare account use <id>"`) {
			t.Errorf("%v: exit %d, %s", args, code, stderr)
		}
	}
	code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "Beta")
	if code != cli.ExitOK || !strings.Contains(stdout, "media") || strings.Contains(stdout, "logs") {
		t.Errorf("bucket list --account: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stdout, "cdn.example.net") {
		t.Errorf("domain list --account: exit %d, %s%s", code, stdout, stderr)
	}
}

// domains lists the domains the index holds for a profile, sorted.
func (e *r2Env) domains(profile string) []string {
	e.t.Helper()
	db, err := inventory.Open(filepath.Join(e.dir, "inventory.db"))
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	entries, err := db.IndexEntries(context.Background())
	if err != nil {
		e.t.Fatal(err)
	}
	var out []string
	for _, en := range entries {
		if en.Platform == platform.Cloudflare && en.Profile == profile && !slices.Contains(out, en.Domain) {
			out = append(out, en.Domain)
		}
	}
	sort.Strings(out)
	return out
}

// A new login that no longer selects an account drops what the inventory
// holds of it at once: its zones, their records, its buckets and its
// domains in the index, which would otherwise keep routing to it.
func TestReloginDropsADeselectedAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	login := func(set ...string) {
		t.Helper()
		args := []string{"auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both"}
		for _, s := range set {
			args = append(args, "--set", s)
		}
		if code, _, stderr := e.run(args...); code != cli.ExitOK {
			t.Fatalf("login %v: exit %d, %s", set, code, stderr)
		}
	}
	login("accounts=acc1,acc2")
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	if got := e.domains("both"); !slices.Contains(got, "example.net") || !slices.Contains(got, "example.com") {
		t.Fatalf("domains: %v", got)
	}

	// The same selection with another default: nothing is dropped and the
	// sets stay fresh.
	login("accounts=acc1,acc2", "account_id=acc2")
	e.f.reset()
	if code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both"); code != cli.ExitOK || !strings.Contains(stdout, "example.net") {
		t.Fatalf("list: exit %d, %s%s", code, stdout, stderr)
	}
	if n := e.f.count(""); n != 0 {
		t.Errorf("a login with the same accounts made the zone set due (%d requests)", n)
	}

	login("accounts=acc1")
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zones: %v", got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		t.Errorf("records: %v", got)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("buckets: %v", got)
	}
	if got := e.domains("both"); slices.Contains(got, "example.net") || !slices.Contains(got, "example.com") {
		t.Errorf("domains: %v", got)
	}
	// The sets are due: the next read asks Cloudflare.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("list: exit %d, %s", code, stderr)
	}
	if n := e.f.count(""); n == 0 {
		t.Errorf("the zone set of a changed selection was served from the cache")
	}
}

// setAccounts rewrites the selection of the profile "both" in the config,
// as an edit by hand would.
func (e *r2Env) setAccounts(def string, accounts ...string) {
	e.t.Helper()
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
	meta["account_id"] = def
	if len(accounts) > 0 {
		meta["accounts"] = strings.Join(accounts, ",")
	} else {
		delete(meta, "accounts")
	}
	if err := cfg.Save(); err != nil {
		e.t.Fatal(err)
	}
}

// account list marks the selected accounts and the default one, and keeps
// the envelope and the fields it always had.
func TestAccountListMarksSelection(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc2", "acc2", "acc1")
	type row struct {
		ID, Name, Type    string
		Selected, Default bool
	}
	list := func(profile string) (rows []row, stderr string) {
		t.Helper()
		code, stdout, stderr := e.run("cloudflare", "account", "list", "--profile", profile, "-o", "json")
		if code != cli.ExitOK {
			t.Fatalf("account list: exit %d, %s", code, stderr)
		}
		var res struct {
			Profile  string
			Accounts []row
		}
		if err := json.Unmarshal([]byte(stdout), &res); err != nil || res.Profile != profile {
			t.Fatalf("account list: %v: %s", err, stdout)
		}
		return res.Accounts, stderr
	}
	rows, stderr := list("both")
	want := []row{{"acc1", "Acme", "standard", true, false}, {"acc2", "Beta", "standard", true, true}}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %+v", rows)
	}
	if !strings.Contains(stderr, "2 account(s) via cloudflare/both, 2 selected") {
		t.Errorf("stderr = %q", stderr)
	}
	code, stdout, _ := e.run("cloudflare", "account", "list", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "SELECTED") || strings.Contains(stdout, "PINNED") {
		t.Fatalf("table: exit %d, %s", code, stdout)
	}
	for _, line := range strings.Split(stdout, "\n") {
		switch {
		case strings.Contains(line, "acc2"):
			if !strings.Contains(line, "Beta *") || !strings.Contains(line, "yes") {
				t.Errorf("the default account: %q", line)
			}
		case strings.Contains(line, "acc1"):
			if strings.Contains(line, "*") || !strings.Contains(line, "yes") {
				t.Errorf("a selected account: %q", line)
			}
		}
	}

	// A login of one account, as every login before the selection stored
	// it: that account is the selection and the default.
	e.loginBoth("acc1")
	if rows, _ = list("both"); !reflect.DeepEqual(rows, []row{{"acc1", "Acme", "standard", true, true}, {"acc2", "Beta", "standard", false, false}}) {
		t.Errorf("one account: %+v", rows)
	}
	// A token that sees one account lists that one.
	if rows, _ = list("beta"); !reflect.DeepEqual(rows, []row{{"acc2", "Beta", "standard", true, true}}) {
		t.Errorf("beta: %+v", rows)
	}

	// A selected account the credentials do not list is shown, and said.
	e.setAccounts("acc1", "acc1", "acc9")
	rows, stderr = list("both")
	if len(rows) != 3 || !reflect.DeepEqual(rows[2], row{ID: "acc9", Selected: true}) {
		t.Errorf("unseen account: %+v", rows)
	}
	if !strings.Contains(stderr, "selected account acc9 is not visible to the credentials (to take it out: polyctl cloudflare account remove acc9)") ||
		!strings.Contains(stderr, "3 account(s) via cloudflare/both, 2 selected") {
		t.Errorf("unseen account: stderr %q", stderr)
	}
	if code, _, _ := e.run("cloudflare", "account", "list", "--profile", "both", "--offline"); code != cli.ExitOffline {
		t.Errorf("offline: exit %d", code)
	}
}

// loginAll adds a third account and logs the profile "all" in with a token
// that sees the three, selecting acc1 alone.
func (e *r2Env) loginAll() {
	e.t.Helper()
	e.f.accounts["acc3"] = &r2Account{id: "acc3", name: "Gamma", domains: map[string][]map[string]any{}}
	e.f.tokens["tok-all"] = "acc1,acc2,acc3"
	e.f.zones = append(e.f.zones, r2Zone{"zone-gamma", "example.org", "active", "acc3"})
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "all", "--set", "token=tok-all", "--set", "account_id=acc1"); code != cli.ExitOK {
		e.t.Fatalf("login all: exit %d, %s", code, stderr)
	}
	e.f.reset()
}

// selection reads "default|name|accounts" of a profile's Cloudflare login.
func (e *r2Env) selection(profile string) string {
	e.t.Helper()
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	m := cfg.Profiles[profile].Platforms[platform.Cloudflare].Metadata
	return m["account_id"] + "|" + m["account_name"] + "|" + m["accounts"]
}

// account use, add and remove change the selection of a login without a
// new login, check what they select, drop what the inventory holds of an
// account that leaves and make the cached sets due.
func TestAccountUseAddRemove(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc2"].buckets = []string{"media"}
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...)
		return code, stdout + stderr
	}
	sync := func() {
		t.Helper()
		if code, _, stderr := e.run("sync", "--profile", "all", "--platform", "cloudflare"); code != cli.ExitOK {
			t.Fatalf("sync: exit %d, %s", code, stderr)
		}
		e.f.reset()
	}
	// due reports whether the zone set is asked for again.
	due := func() bool {
		t.Helper()
		e.f.reset()
		if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "all"); code != cli.ExitOK {
			t.Fatalf("zone list: exit %d, %s", code, stderr)
		}
		return e.f.count("GET /zones") > 0
	}
	sync()
	if due() {
		t.Fatal("the zone set must be fresh after the sync")
	}

	// add: by name and by id, after the credentials were asked for them.
	code, out := acct("add", "beta", "acc3")
	if code != cli.ExitOK || e.selection("all") != "acc1|Acme|acc1,acc2,acc3" || !strings.Contains(out, "added acc2, acc3 to the accounts of cloudflare/all") {
		t.Fatalf("add: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if !due() {
		t.Error("add must make the cached sets due")
	}
	// One that is selected already is nothing to do.
	if code, out = acct("add", "acc2"); code != cli.ExitOK || !strings.Contains(out, "acc2: already selected for cloudflare/all") {
		t.Errorf("add again: exit %d, %s", code, out)
	}
	// One the credentials do not see is not found, unless nothing can be
	// checked, which is said.
	if code, out = acct("add", "acc9"); code != cli.ExitNotFound || !strings.Contains(out, "is not visible to the credentials of cloudflare/all (visible: acc1=Acme, acc2=Beta, acc3=Gamma)") {
		t.Errorf("add of an account that is not visible: exit %d, %s", code, out)
	}
	if code, out = acct("add", "acc9", "--offline"); code != cli.ExitOK || !strings.Contains(out, "--offline: access to acc9 was not checked") || e.selection("all") != "acc1|Acme|acc1,acc2,acc3,acc9" {
		t.Errorf("add --offline: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if code, out = acct("add", "No Such Name", "--offline"); code != cli.ExitOffline {
		t.Errorf("add of an unknown name --offline: exit %d, %s", code, out)
	}
	if code, out = acct("add"); code != cli.ExitUsage {
		t.Errorf("add without an account: exit %d, %s", code, out)
	}

	// use: a selected account becomes the default, with its name.
	if code, out = acct("use", "Gamma"); code != cli.ExitOK || e.selection("all") != "acc3|Gamma|acc3,acc1,acc2,acc9" || !strings.Contains(out, "account acc3 is now the default account of cloudflare/all") {
		t.Fatalf("use: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if code, out = acct("use", "acc3"); code != cli.ExitOK || !strings.Contains(out, "account acc3 is already the default account of cloudflare/all") {
		t.Errorf("use of the default: exit %d, %s", code, out)
	}
	if code, out = acct("use", "acc8"); code != cli.ExitNotFound || !strings.HasPrefix(e.selection("all"), "acc3|") {
		t.Errorf("use of an account that is not visible: exit %d, %s", code, out)
	}
	if code, out = acct("use"); code != cli.ExitUsage {
		t.Errorf("use without an account: exit %d, %s", code, out)
	}

	// current shows it without a request.
	e.f.reset()
	code, stdout, stderr := e.run("cloudflare", "account", "current", "--profile", "all", "--offline", "-o", "json")
	var cur struct {
		Profile     string
		AccountID   string `json:"account_id"`
		AccountName string `json:"account_name"`
		Accounts    []string
		Method      string
	}
	if err := json.Unmarshal([]byte(stdout), &cur); code != cli.ExitOK || err != nil {
		t.Fatalf("current: exit %d, %v, %s%s", code, err, stdout, stderr)
	}
	if cur.Profile != "all" || cur.AccountID != "acc3" || cur.AccountName != "Gamma" || cur.Method != "api_token" || !reflect.DeepEqual(cur.Accounts, []string{"acc3", "acc1", "acc2", "acc9"}) {
		t.Errorf("current = %+v", cur)
	}
	if e.f.count("") != 0 {
		t.Errorf("current asked Cloudflare")
	}

	// remove: not selected is not found; the default needs --default; all
	// of them is a usage error.
	sync()
	if got := e.rows("all", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-gamma acc3") {
		t.Fatalf("zones: %v", got)
	}
	if code, out = acct("remove", "nosuch"); code != cli.ExitNotFound || !strings.Contains(out, "nosuch is not selected for cloudflare/all (selected: acc3, acc1, acc2, acc9)") {
		t.Errorf("remove of an unselected account: exit %d, %s", code, out)
	}
	if code, out = acct("remove", "acc3"); code != cli.ExitUsage || !strings.Contains(out, "--default <id>") || !strings.Contains(out, "one of: acc1, acc2, acc9") {
		t.Errorf("remove of the default: exit %d, %s", code, out)
	}
	if code, out = acct("remove", "acc3", "--default", "acc3"); code != cli.ExitUsage || !strings.Contains(out, "not one of the accounts that stay selected") {
		t.Errorf("--default of a removed account: exit %d, %s", code, out)
	}
	// Works offline, and by a name the cached zones carry.
	if code, out = acct("remove", "acc3", "beta", "acc9", "--default", "Acme", "--offline"); code != cli.ExitOK || e.selection("all") != "acc1|Acme|" ||
		!strings.Contains(out, "removed acc3, acc2, acc9 from the accounts of cloudflare/all") || !strings.Contains(out, "account acc1 is now the default account of cloudflare/all") {
		t.Fatalf("remove with --default: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if e.f.count("") != 0 {
		t.Errorf("remove --offline asked Cloudflare")
	}
	// What the inventory held of the accounts that left is gone.
	if got, want := e.rows("all", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zones after the removal: %v", got)
	}
	if got := e.rows("all", platform.ResDNSRecord); len(got) != 0 {
		t.Errorf("records after the removal: %v", got)
	}
	if got := e.rows("all", platform.ResR2Bucket); len(got) != 0 {
		t.Errorf("buckets after the removal: %v", got)
	}
	if got := e.domains("all"); slices.Contains(got, "example.net") || slices.Contains(got, "example.org") || !slices.Contains(got, "example.com") {
		t.Errorf("domains after the removal: %v", got)
	}
	if !due() {
		t.Error("remove must make the cached sets due")
	}
	if code, out = acct("remove", "acc1"); code != cli.ExitUsage || !strings.Contains(out, "polyctl auth logout cloudflare --profile all") {
		t.Errorf("remove of every account: exit %d, %s", code, out)
	}
	// The other logins were not touched.
	if e.selection("acme") != "acc1|Acme|" || e.selection("beta") != "acc2|Beta|" {
		t.Errorf("other logins: %s, %s", e.selection("acme"), e.selection("beta"))
	}
}

// The rows of a zone and of a bucket stored before the rows had their
// account as parent leave the inventory with their account too.
func TestAccountRemoveDropsRowsWithoutAParent(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.loginBoth("acc1", "acc1", "acc2")
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	// Store the zone and the bucket of acc2 again as they were stored then.
	db, err := inventory.Open(filepath.Join(e.dir, "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResR2Bucket} {
		set := inventory.Set{Platform: platform.Cloudflare, Profile: "both", Type: typ}
		rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: "both", Type: typ})
		if err != nil {
			t.Fatal(err)
		}
		var res []platform.Resource
		for _, r := range rows {
			pr := platform.Resource{Type: typ, ID: r.ID, Name: r.Name, ParentID: r.ParentID, Domain: r.Domain, Data: json.RawMessage(r.Data)}
			if r.ParentID == "acc2" {
				pr.ParentID = ""
				if typ == platform.ResR2Bucket {
					pr.ID = r.Name
				}
			}
			res = append(res, pr)
		}
		if err := db.Replace(ctx, set, res, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	db.Close()
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-beta ") {
		t.Fatalf("zones: %v", got)
	}
	if got := e.rows("both", platform.ResR2Bucket); !reflect.DeepEqual(got, []string{"media "}) {
		t.Fatalf("buckets: %v", got)
	}

	if code, _, stderr := e.run("cloudflare", "account", "remove", "acc2", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("remove: exit %d, %s", code, stderr)
	}
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zones: %v", got)
	}
	if got := e.rows("both", platform.ResDNSRecord); len(got) != 0 {
		t.Errorf("records: %v", got)
	}
	if got := e.rows("both", platform.ResR2Bucket); len(got) != 0 {
		t.Errorf("buckets: %v", got)
	}
	if got := e.domains("both"); slices.Contains(got, "example.net") {
		t.Errorf("domains: %v", got)
	}
}

// On a terminal use, add and remove offer the accounts when none is named:
// the visible ones, those not selected yet, the selected ones; remove of
// the default account asks for the new default.
func TestAccountCommandsPick(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	if code, _, stderr := e.run("cloudflare", "account", "add", "acc2", "--profile", "all"); code != cli.ExitOK {
		t.Fatalf("add: exit %d, %s", code, stderr)
	}

	p := prompttest.New(t, "acc3")
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "use", "--profile", "all"); code != cli.ExitOK || e.selection("all") != "acc3|Gamma|acc3,acc1,acc2" {
		t.Fatalf("use: exit %d, %s, %s", code, e.selection("all"), stderr)
	}
	p.Done()
	if a := p.Asked[0]; a.Title != "Default account" || a.Default != "acc1" || prompttest.Values(a.Options) != "acc1 acc2 acc3" ||
		!strings.Contains(prompttest.Labels(a.Options), "Acme (acc1)  default") || !strings.Contains(prompttest.Labels(a.Options), "Beta (acc2)  selected") ||
		!strings.Contains(prompttest.Labels(a.Options), "Gamma (acc3)\n") && !strings.HasSuffix(prompttest.Labels(a.Options), "Gamma (acc3)") {
		t.Errorf("use asked %+v", a)
	}

	if code, _, stderr := e.run("cloudflare", "account", "remove", "acc2", "--profile", "all"); code != cli.ExitOK {
		t.Fatalf("remove: exit %d, %s", code, stderr)
	}
	p = prompttest.New(t, []string{"acc2"})
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "add", "--profile", "all"); code != cli.ExitOK || e.selection("all") != "acc3|Gamma|acc3,acc1,acc2" {
		t.Fatalf("add: exit %d, %s, %s", code, e.selection("all"), stderr)
	}
	p.Done()
	if a := p.Asked[0]; a.Kind != "multi" || a.Title != "Accounts to add" || prompttest.Values(a.Options) != "acc2" {
		t.Errorf("add offered %+v", a)
	}

	p = prompttest.New(t, []string{"acc3"}, "acc2")
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "remove", "--profile", "all"); code != cli.ExitOK || e.selection("all") != "acc2|Beta|acc2,acc1" {
		t.Fatalf("remove: exit %d, %s, %s", code, e.selection("all"), stderr)
	}
	p.Done()
	if a := p.Asked[0]; a.Title != "Accounts to remove" || prompttest.Values(a.Options) != "acc3 acc1 acc2" || !strings.Contains(prompttest.Labels(a.Options), "Gamma (acc3)  default") {
		t.Errorf("remove offered %+v", a)
	}
	if a := p.Asked[1]; a.Title != "New default account" || prompttest.Values(a.Options) != "acc1 acc2" {
		t.Errorf("new default asked %+v", a)
	}

	// With one account left there is nothing to ask.
	p = prompttest.New(t)
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "remove", "acc2", "--profile", "all"); code != cli.ExitOK || e.selection("all") != "acc1|Acme|" {
		t.Fatalf("remove of the default with one left: exit %d, %s, %s", code, e.selection("all"), stderr)
	}
	p.Done()
}

// A login that is not bound to an account gets one with use or add: it
// becomes the default, and the login works on it alone from then on.
func TestAccountUseOnALoginWithoutAnAccount(t *testing.T) {
	e := newR2Env(t)
	unbind := func() {
		t.Helper()
		e.loginBoth("acc1")
		cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
		delete(meta, "account_id")
		delete(meta, "account_name")
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}
	}
	unbind()
	code, stdout, stderr := e.run("cloudflare", "account", "current", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "(none: every account the credentials see)") {
		t.Errorf("current: exit %d, %s%s", code, stdout, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "account", "remove", "acc1", "--profile", "both"); code != cli.ExitNotFound || !strings.Contains(stderr, "(selected: none)") {
		t.Errorf("remove: exit %d, %s", code, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "account", "add", "Beta", "acc1", "--profile", "both"); code != cli.ExitOK || e.selection("both") != "acc2|Beta|acc2,acc1" ||
		!strings.Contains(stderr, "account acc2 is now the default account of cloudflare/both") {
		t.Errorf("add: exit %d, %s, %s", code, e.selection("both"), stderr)
	}
	unbind()
	if code, _, stderr = e.run("cloudflare", "account", "use", "acc2", "--profile", "both"); code != cli.ExitOK || e.selection("both") != "acc2|Beta|" {
		t.Errorf("use: exit %d, %s, %s", code, e.selection("both"), stderr)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "example.net") || strings.Contains(stdout, "example.com") {
		t.Errorf("zone list: exit %d, %s%s", code, stdout, stderr)
	}
}
