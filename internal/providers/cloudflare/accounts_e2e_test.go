package cloudflare_test

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/providers/cloudflare"
)

// loginBoth logs the profile "both" in with the token that sees acc1 and
// acc2: def is the default account, and disabled the accounts kept out.
func (e *r2Env) loginBoth(def string, disabled ...string) {
	e.t.Helper()
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id="+def,
		"--set", "disabled_accounts="+strings.Join(disabled, ",")); code != cli.ExitOK {
		e.t.Fatalf("login both: exit %d, %s", code, stderr)
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
// account its credentials see, and a sync that fails for one of them
// keeps what is stored for it.
func TestSyncSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1")

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
	// One zone listing for the zones and the records of every account,
	// without an account filter.
	if n := e.f.count("GET /zones?"); n != 1 {
		t.Errorf("%d zone listings in one sync, want 1: %v", n, e.f.requests)
	}
	for _, r := range e.f.requests {
		if strings.Contains(r, "account.id") {
			t.Errorf("a request of the sync filters by account: %s", r)
		}
	}

	// The records of acc2 stop answering, and acc1 loses a zone: the
	// records of acc2 are kept, the rows of acc1 replaced.
	e.f.failRecords = map[string]int{"zone-beta": 400}
	e.f.dropZone("zone-pend")
	e.f.dropZone("zone-ex")
	code, stdout, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare", "-o", "json")
	if code == cli.ExitOK {
		t.Fatalf("a sync with a failed account must not exit 0: %s", stderr)
	}
	if want := "polyctl cloudflare account disable acc2"; !strings.Contains(stdout+stderr, want) {
		t.Errorf("the failure of acc2 is not reported with %q: %s%s", want, stdout, stderr)
	}
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-beta acc2", "zone-couk acc1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zones after the failure: %v", got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-beta zone-beta"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records after the failure: %v", got)
	}

	// The native zone list goes through the same sync. The zone listing
	// is one request for every account: when it fails nothing is replaced,
	// and the cached zones are still there.
	e.f.failRecords = nil
	code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--refresh", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "a.example.com") {
		t.Fatalf("zone list: exit %d, %s%s", code, stdout, stderr)
	}
	e.f.failZones[""] = 400
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--refresh", "-o", "json"); code == cli.ExitOK {
		t.Fatalf("zone list with a failed listing: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--offline", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "a.example.com") {
		t.Fatalf("zone list after a failed listing: exit %d, %s%s", code, stdout, stderr)
	}
}

// A login made by an earlier release, which stored the accounts selected
// for it, works on every account its credentials see: the stored
// selection is not read, and it leaves the configuration the next time the
// login is written.
func TestLoginOfAnEarlierReleaseCoversEveryAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.loginBoth("acc1")
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata["accounts"] = "acc1"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-ex acc1") {
		t.Errorf("zones: %v", got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-beta zone-beta"}; !reflect.DeepEqual(got, want) {
		t.Errorf("records: %v", got)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc2/media acc2"}; !reflect.DeepEqual(got, want) {
		t.Errorf("buckets: %v", got)
	}
	if n, m := e.f.count("GET /zones?"), e.f.count("GET /accounts?"); n != 1 || m != 1 {
		t.Errorf("%d zone listings and %d account listings in one sync, want 1 and 1: %v", n, m, e.f.requests)
	}
	// The neutral commands reach the zone of the other account.
	if code, stdout, stderr := e.run("dns", "list", "example.net", "--profile", "both", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "192.0.2.2") {
		t.Errorf("dns list: exit %d, %s%s", code, stdout, stderr)
	}
	// Any command that writes the login drops the selection.
	if code, _, stderr := e.run("cloudflare", "account", "use", "acc2", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("use: exit %d, %s", code, stderr)
	}
	if cfg, err = config.Load(filepath.Join(e.dir, "config.yaml")); err != nil {
		t.Fatal(err)
	}
	if _, kept := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata["accounts"]; kept || e.stored("both") != "acc2|Beta|" {
		t.Errorf("the login after account use: %v", cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata)
	}
}

// A token without Account:Read cannot tell which accounts it sees: the
// zones of every account it sees are synced all the same (their listing
// needs no account), and R2, which is asked per account, covers the
// default account alone.
func TestSyncWithoutAccountRead(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.loginBoth("acc1")
	e.f.accountsStatus = http.StatusForbidden
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-ex acc1") {
		t.Errorf("zones: %v", got)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("buckets: %v", got)
	}
	// The bucket of the other account is reached with --account.
	code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stdout, "media") {
		t.Errorf("bucket list --account: exit %d, %s%s", code, stdout, stderr)
	}
}

// The neutral commands reach a zone of every enabled account.
func TestDomainRoutingSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1")
	for domain, want := range map[string]string{"example.com": "192.0.2.1", "example.net": "192.0.2.2"} {
		code, stdout, stderr := e.run("dns", "list", domain, "--profile", "both", "-o", "json")
		if code != cli.ExitOK || !strings.Contains(stdout, want) {
			t.Fatalf("dns list %s: exit %d, %s%s", domain, code, stdout, stderr)
		}
	}
	// A login does not see the zone of an account that is disabled for it.
	e.loginBoth("acc1", "acc2")
	if code, _, stderr := e.run("dns", "list", "example.net", "--profile", "both", "--refresh"); code != cli.ExitNotFound {
		t.Fatalf("a disabled account: exit %d, %s", code, stderr)
	}
}

// The name of an R2 bucket is unique in its account only: the rows of two
// accounts holding the same name do not replace each other.
func TestSyncBucketsSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "logs"}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.loginBoth("acc1")
	warned := cloudflare.CaptureWarnings(t)

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
	// The accounts are asked of the credentials once.
	if n := e.f.count("GET /accounts?"); n != 1 {
		t.Errorf("%d account listings in one sync: %v", n, e.f.requests)
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
	if len(*warned) != 0 {
		t.Errorf("warnings: %v", *warned)
	}

	// An account without R2 holds no bucket: the sync does not fail for
	// it, and one note names the accounts that were left out.
	e.f.accounts["acc2"].r2Disabled = true
	code, out := sync("both")
	if code != cli.ExitOK {
		t.Fatalf("sync without R2 in acc2: exit %d, %s", code, out)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets without R2 in acc2: %v", got)
	}
	if want := []string{"note: cloudflare/both: R2 is not usable in 1 account(s): acc2 (R2 is not enabled)"}; !reflect.DeepEqual(*warned, want) {
		t.Errorf("warnings: %q", *warned)
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
	*warned = nil
	if code, out := sync("both"); code != cli.ExitOK {
		t.Fatalf("sync without R2 at all: exit %d, %s", code, out)
	}
	// One line for all of them.
	if want := []string{"note: cloudflare/both: R2 is not usable in 2 account(s): acc1 (R2 is not enabled), acc2 (R2 is not enabled)"}; !reflect.DeepEqual(*warned, want) {
		t.Errorf("warnings: %q", *warned)
	}
}

// A domain two enabled accounts of one login hold a zone of is ambiguous
// for the neutral commands (exit code 5), and the hint names what tells
// the zones apart.
func TestDomainRoutingAmbiguousAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.zones = append(e.f.zones, r2Zone{"zone-dup", "example.com", "pending", "acc2"})
	e.loginBoth("acc1")
	code, _, stderr := e.run("dns", "list", "example.com", "--profile", "both")
	if code != cli.ExitAmbiguous {
		t.Fatalf("exit %d, %s", code, stderr)
	}
	for _, want := range []string{"cloudflare/both account acc1 (Acme) zone zone-ex active", "cloudflare/both account acc2 (Beta) zone zone-dup pending",
		"`polyctl cloudflare` commands", "--account <id or name>", "zone id"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the ambiguity lacks %q: %s", want, stderr)
		}
	}
	if strings.Contains(stderr, "--profile <name>") {
		t.Errorf("--profile does not tell the zones apart: %s", stderr)
	}
	// On a terminal the question shows the account and the status of each.
	p := prompttest.New(t, "1")
	if code, stdout, stderr := e.runPick(p, "dns", "list", "example.com", "--profile", "both", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, `"resource_id": "zone-ex"`) {
		t.Fatalf("pick: exit %d, %s%s", code, stdout, stderr)
	}
	p.Done()
	if got, want := prompttest.Labels(p.Asked[0].Options), "cloudflare/both  Beta  pending  account acc2  zone-dup\ncloudflare/both  Acme  active  account acc1  zone-ex"; got != want {
		t.Errorf("options:\n%s", got)
	}
}

// The zone list of a login covers its enabled accounts and says which
// account a zone is of; --account, by id or by name, narrows it to one.
func TestZoneListSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1")
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
			t.Errorf("--account %s of an enabled account made %d requests", ref, n)
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

// A disabled account is left out of every sync, list and lookup. It is
// read live with --account, by id or by name, and nothing of it reaches
// the inventory; without the flag its zones are not found, and the answer
// says where they are.
func TestDisabledAccountIsReadLive(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1", "acc2")

	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zones: %v", got)
	}
	if n := e.f.count("GET /zones/zone-beta/"); n != 0 {
		t.Errorf("the sync asked a zone of the disabled account %d time(s)", n)
	}
	if code, _, stderr := e.run("dns", "list", "example.net", "--profile", "both"); code != cli.ExitNotFound {
		t.Errorf("neutral dns list of a zone of the disabled account: exit %d, %s", code, stderr)
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both")
	if code != cli.ExitOK || strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "example.com") {
		t.Fatalf("zone list: exit %d, %s%s", code, stdout, stderr)
	}

	code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || strings.Contains(stdout, "example.com") {
		t.Fatalf("zone list --account: exit %d, %s%s", code, stdout, stderr)
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
				t.Errorf("a row of the disabled account was stored: %s", row)
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
		if code != cli.ExitNotFound || !strings.Contains(stderr, "which is disabled") || !strings.Contains(stderr, "polyctl cloudflare account enable acc2") || !strings.Contains(stderr, "--account acc2") {
			t.Errorf("zone get %s without --account: exit %d, %s", ref, code, stderr)
		}
	}
	// A zone of an enabled account, named by id with the --account of
	// the other one.
	code, _, stderr = e.run("cloudflare", "zone", "get", "zone-ex", "--profile", "both", "--account", "acc2")
	if code != cli.ExitUsage || !strings.Contains(stderr, "not of --account acc2") {
		t.Errorf("zone id of the enabled account: exit %d, %s", code, stderr)
	}
}

// A cached zone of an account that was disabled is not one of the login
// any more, although the set that holds it is still fresh.
func TestDisabledAccountRowsAreOutOfScope(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1")
	if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("list: exit %d, %s", code, stderr)
	}
	e.setDisabled("acc1", "acc2")
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both", "--offline")
	if code != cli.ExitOK || strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "example.com") {
		t.Errorf("list after the account was disabled: exit %d, %s%s", code, stdout, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "zone", "get", "example.net", "--profile", "both", "--offline"); code != cli.ExitNotFound {
		t.Errorf("get after the account was disabled: exit %d, %s", code, stderr)
	}
}

// A zone name two enabled accounts hold a zone of is ambiguous (exit code
// 5) for the commands of one profile, a pick on a terminal, and --account
// chooses; so does disabling one of the two accounts.
func TestZoneNameInTwoAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.zones = append(e.f.zones, r2Zone{"zone-dup", "example.com", "pending", "acc2"})
	e.loginBoth("acc1")
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
	e.loginBoth("acc1")
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
	if a := p.Find(`Ambiguous zone "example.com"; use which one?`); a == nil || len(a.Options) != 2 || !strings.Contains(prompttest.Labels(a.Options), "cloudflare/both  Beta  pending  account acc2  zone-dup") {
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
	p.Done()
	// Disabling one of the two accounts leaves one zone of the name.
	e.loginBoth("acc1", "acc2")
	code, stdout, stderr = e.run("cloudflare", "zone", "get", "example.com", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "zone-ex"`) {
		t.Errorf("after disabling acc2: exit %d, %s%s", code, stdout, stderr)
	}
}

// loginBoth logs the profile "both" in with the token that sees acc1 and
// acc2: def is the default account, and disabled the accounts kept out.
func (e *zoneEnv) loginBoth(def string, disabled ...string) {
	e.t.Helper()
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id="+def,
		"--set", "disabled_accounts="+strings.Join(disabled, ",")); code != cli.ExitOK {
		e.t.Fatalf("login both: exit %d, %s", code, stderr)
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
// delete, the rules) find it in every enabled account of a login; a name
// two of them hold a zone of is ambiguous (exit code 5), a pick on a
// terminal, and --account, by id or by name, chooses.
func TestRoutedZoneSeveralAccounts(t *testing.T) {
	e := newZoneEnv(t)
	ex := e.f.addZone("example.com", "acc1", "free", "active")
	dup := e.f.addZone("example.com", "acc2", "free", "pending")
	net := e.f.addZone("example.net", "acc2", "free", "active")
	dup.settings["ssl"].value = "strict"
	e.loginBoth("acc1")

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
	if a := p.Find(`Ambiguous cloudflare zone "example.com"; use which one?`); a == nil || len(a.Options) != 2 || !strings.Contains(prompttest.Labels(a.Options), "  Account acc2  pending  account acc2  "+dup.id) {
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

// The same commands read the zones of a disabled account live with
// --account and store nothing of it; without --profile the flag finds the
// login that works on the account.
func TestRoutedZoneDisabledAccount(t *testing.T) {
	e := newZoneEnv(t)
	ex := e.f.addZone("example.com", "acc1", "free", "active")
	net := e.f.addZone("example.net", "acc2", "free", "active")
	e.loginBoth("acc1", "acc2")

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
	// A zone id of the enabled account with the --account of the other.
	code, _, stderr = e.run("cloudflare", "zone", "setting", "get", ex.id, "ssl", "--profile", "both", "--account", "acc2")
	if code != cli.ExitUsage || !strings.Contains(stderr, "not of --account acc2") {
		t.Errorf("zone id of acc1 with --account acc2: exit %d, %s", code, stderr)
	}
	// On a terminal the zone is asked for among those read from the account.
	p := prompttest.New(t, net.id, "ssl")
	code, stdout, stderr := e.runPick(p, "cloudflare", "zone", "setting", "get", "--profile", "both", "--account", "acc2", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "strict"`) {
		t.Errorf("pick in the disabled account: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find("Zone"); a == nil || len(a.Options) != 1 || !strings.Contains(a.Options[0].Label, "example.net") {
		t.Errorf("zone options: %+v", a)
	}
	p.Done()
	// Without --profile the login that works on the account is used: beta.
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
// looked for in every enabled account and reused where it is.
func TestZoneEnsureSeveralAccounts(t *testing.T) {
	e := newZoneEnv(t)
	net := e.f.addZone("example.net", "acc2", "free", "active")
	e.loginBoth("acc1")

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

	// A domain with a zone in two enabled accounts.
	one := e.f.addZone("example.com", "acc1", "free", "active")
	two := e.f.addZone("example.com", "acc2", "free", "pending")
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "ensure", "example.com", "--profile", "both")
	if code != cli.ExitAmbiguous || !strings.Contains(stderr, one.id) || !strings.Contains(stderr, two.id) || !strings.Contains(stderr, "pass --account <id or name> to choose") {
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

// A zone created in a disabled account is not stored, and a login without
// a default account asks for one or takes --account.
func TestZoneCreateInADisabledAccount(t *testing.T) {
	e := newZoneEnv(t)
	e.loginBoth("acc1", "acc2")
	code, _, stderr := e.run("cloudflare", "zone", "create", "example.io", "--profile", "both", "--account", "acc2", "--foundation-dns=false")
	if code != cli.ExitOK || e.createdIn() != "acc2" {
		t.Fatalf("create in the disabled account: exit %d, in %q, %s", code, e.createdIn(), stderr)
	}
	if !strings.Contains(stderr, "account acc2 is disabled, so the new zone is not in the inventory (polyctl cloudflare account enable acc2)") {
		t.Errorf("no note about the inventory: %s", stderr)
	}
	if got := e.zoneRows("both"); got != "" {
		t.Errorf("zones stored for both: %q", got)
	}

	// A login without a default account.
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
	delete(meta, "account_id")
	delete(meta, "account_name")
	delete(meta, "disabled_accounts")
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.dev", "--profile", "both")
	if code != cli.ExitUsage || !strings.Contains(stderr, `pass --account <id or name>, or name the default account with "polyctl cloudflare account use <id>"`) || len(e.f.writes()) != 0 {
		t.Errorf("several accounts and none named: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
	if strings.Contains(stderr, "--set account_id") || strings.Contains(stderr, "select") {
		t.Errorf("the old ways to name an account are still named: %s", stderr)
	}
	p := prompttest.New(t, "acc2")
	code, _, stderr = e.runPick(p, "cloudflare", "zone", "create", "example.dev", "--profile", "both", "--foundation-dns=false")
	if code != cli.ExitOK || e.createdIn() != "acc2" || !strings.Contains(stderr, "pass --account acc2, or make it the default account: polyctl cloudflare account use acc2") {
		t.Errorf("asked account: exit %d, in %q, %s", code, e.createdIn(), stderr)
	}
	p.Done()
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.app", "--profile", "both", "--account", "acc1", "--foundation-dns=false")
	if code != cli.ExitOK || e.createdIn() != "acc1" {
		t.Errorf("--account of a login without a default account: exit %d, in %q, %s", code, e.createdIn(), stderr)
	}
	// Such a login covers what its credentials see: the zones are stored.
	if got := e.zoneRows("both"); got == "" {
		t.Errorf("the zone of a login without a default account was not stored")
	}
}

// The status line of r2 bucket list counts the accounts that were read,
// also the enabled ones that hold no bucket. The inventory does not tell
// them, so a listing it answered counts the buckets alone.
func TestR2BucketListCountsAccountsWithoutABucket(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.loginBoth("acc1")
	list := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "r2", "bucket", "list", "--profile", "both"}, args...)...)
		if code != cli.ExitOK {
			t.Fatalf("bucket list %v: exit %d, %s%s", args, code, stdout, stderr)
		}
		return stderr
	}
	if got := list(); !strings.Contains(got, "1 bucket(s) in 2 account(s)") || e.f.count("GET /accounts/acc2/r2/buckets?") != 1 {
		t.Errorf("first listing: %s, requests %v", got, e.f.requests)
	}
	e.f.reset()
	if got := list(); !strings.Contains(got, "1 bucket(s) (local inventory)") || strings.Contains(got, "account(s)") || len(e.f.requests) != 0 {
		t.Errorf("cached listing: %s, requests %v", got, e.f.requests)
	}
	if got := list("--account", "acc2"); !strings.Contains(got, "0 bucket(s) in 1 account(s)") {
		t.Errorf("--account: %s", got)
	}
	if got := list("--jurisdiction", "eu"); !strings.Contains(got, "in 2 account(s)") {
		t.Errorf("--jurisdiction: %s", got)
	}
	// A login without a default account and without a bucket.
	e.f.accounts["acc1"].buckets = nil
	e.unbind("both")
	if got := list("--refresh"); !strings.Contains(got, "0 bucket(s) in 2 account(s)") {
		t.Errorf("no default account, no bucket: %s", got)
	}
}

// The R2 buckets of a login with several accounts: the listing shows those
// of every enabled account with their account, --account narrows it, and
// a disabled account is read live and not cached.
func TestR2BucketListSeveralAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "logs"}
	e.f.accounts["acc2"].buckets = []string{"assets", "media"}
	e.loginBoth("acc1")

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
	if code != cli.ExitOK || strings.Contains(stdout, "ACCOUNT") || strings.Contains(stdout, "both") || !strings.Contains(stderr, "4 bucket(s) (local inventory)") {
		t.Errorf("every profile: exit %d, %s%s", code, stdout, stderr)
	}
	// Another jurisdiction is read live in every enabled account.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--jurisdiction", "eu"); code != cli.ExitOK ||
		e.f.count("GET /accounts/acc1/r2/buckets?") != 1 || e.f.count("GET /accounts/acc2/r2/buckets?") != 1 {
		t.Errorf("--jurisdiction: exit %d, %s, requests %v", code, stderr, e.f.requests)
	}

	// A disabled account is read live and not cached.
	e.loginBoth("acc1", "acc2")
	if code, _, stderr := e.run("--refresh", "cloudflare", "r2", "bucket", "list", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("list of one account: exit %d, %s", code, stderr)
	}
	for range 2 {
		e.f.reset()
		code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "acc2")
		if code != cli.ExitOK || !strings.Contains(stdout, "media") || strings.Contains(stdout, "logs") || e.f.count("GET /accounts/acc2/r2/buckets?") != 1 {
			t.Errorf("disabled account: exit %d, %s%s, requests %v", code, stdout, stderr, e.f.requests)
		}
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc1/logs acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("a disabled account was cached: %v", got)
	}
	if code, _, _ := e.run("--offline", "cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "acc2"); code != cli.ExitOffline {
		t.Errorf("disabled account offline: exit %d", code)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("listings wrote: %v", w)
	}
}

// A bucket name two enabled accounts of one login hold a bucket of is
// ambiguous (exit code 5) with the flag that chooses, --account settles
// it, and a terminal asks.
func TestR2BucketNameInTwoAccounts(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.bind("acc2", "assets", "cdn.example.net", "zone-beta", true, "")
	e.loginBoth("acc1")

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
		!strings.Contains(prompttest.Labels(a.Options), "cloudflare/both  account acc1") {
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

// A bucket of the second enabled account of a login is found live and
// through the inventory, and a custom domain is bound in its account.
func TestR2DomainInTheSecondAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.loginBoth("acc1")

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
	if code != cli.ExitNotFound || !strings.Contains(stderr, "bucket nosuch not found in the enabled accounts of cloudflare/both (acc1, acc2)") {
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

	// A bucket of a disabled account: --account reaches it, and nothing of
	// the binding is cached.
	e.loginBoth("acc1", "acc2")
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both"); code != cli.ExitNotFound {
		t.Errorf("disabled account without --account: exit %d, %s", code, stderr)
	}
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "media", "cdn.example.net", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stderr, "via account acc2 of cloudflare/both") {
		t.Fatalf("attach in a disabled account: exit %d, %s", code, stderr)
	}
	for _, r := range e.cachedRecords("cdn.example.net") {
		if r.Profile == "both" {
			t.Errorf("a record of a disabled account was cached: %v", r)
		}
	}
}

// Deleting the CNAME record of an R2 custom domain unbinds it from a
// bucket in another enabled account of the same login, without the other
// logins being asked.
func TestDNSDeleteUnbindsInAnotherEnabledAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.bind("acc2", "assets", "cdn.example.com", "zone-ex", true, "")
	recID := e.f.records["zone-ex"][0]["id"].(string)
	e.loginBoth("acc1")

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

// A login without a default account covers every account its credentials
// see for R2 too: the buckets of all of them are listed and found, and
// --account narrows the commands to one.
func TestR2LoginWithoutAnAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"logs"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.f.bind("acc2", "media", "cdn.example.net", "zone-beta", true, "")
	e.loginBoth("acc1")
	e.unbind("both")

	code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "media") || !strings.Contains(stdout, "logs") || !strings.Contains(stdout, "ACCOUNT") {
		t.Errorf("bucket list: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "cdn.example.net") || !strings.Contains(stderr, "bucket media via account acc2 of cloudflare/both") {
		t.Errorf("domain list: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "both", "--account", "Beta")
	if code != cli.ExitOK || !strings.Contains(stdout, "media") || strings.Contains(stdout, "logs") {
		t.Errorf("bucket list --account: exit %d, %s%s", code, stdout, stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "list", "media", "--profile", "both", "--account", "acc2")
	if code != cli.ExitOK || !strings.Contains(stdout, "cdn.example.net") {
		t.Errorf("domain list --account: exit %d, %s%s", code, stdout, stderr)
	}
	// It may disable an account all the same.
	if code, _, stderr = e.run("cloudflare", "account", "disable", "acc1", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "||acc1" {
		t.Fatalf("disable: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "media") || strings.Contains(stdout, "logs") {
		t.Errorf("bucket list after the disable: exit %d, %s%s", code, stdout, stderr)
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

// A new login that disables an account drops what the inventory holds of
// it at once: its zones, their records, its buckets and its domains in the
// index, which would otherwise keep routing to it.
func TestReloginDropsADisabledAccount(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	login := func(set ...string) (int, string) {
		t.Helper()
		args := []string{"auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both"}
		for _, s := range set {
			args = append(args, "--set", s)
		}
		code, _, stderr := e.run(args...)
		return code, stderr
	}
	// The selection of an earlier release is not a login option any more.
	if code, stderr := login("accounts=acc1,acc2"); code != cli.ExitUsage || !strings.Contains(stderr, "accounts") {
		t.Fatalf("--set accounts: exit %d, %s", code, stderr)
	}
	if code, stderr := login("account_id=acc1"); code != cli.ExitOK {
		t.Fatalf("login: exit %d, %s", code, stderr)
	}
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	if got := e.domains("both"); !slices.Contains(got, "example.net") || !slices.Contains(got, "example.com") {
		t.Fatalf("domains: %v", got)
	}

	// Another default account: nothing is dropped and the sets stay fresh.
	if code, stderr := login("account_id=acc2"); code != cli.ExitOK || e.stored("both") != "acc2|Beta|" {
		t.Fatalf("login with another default: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	e.f.reset()
	if code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both"); code != cli.ExitOK || !strings.Contains(stdout, "example.net") {
		t.Fatalf("list: exit %d, %s%s", code, stdout, stderr)
	}
	if n := e.f.count(""); n != 0 {
		t.Errorf("a login with the same accounts made the zone set due (%d requests)", n)
	}

	// The default account cannot be disabled.
	if code, stderr := login("disabled_accounts=acc2"); code != cli.ExitUsage || !strings.Contains(stderr, "the default account, which is always enabled") {
		t.Fatalf("the default disabled: exit %d, %s", code, stderr)
	}
	if code, stderr := login("account_id=acc1", "disabled_accounts=acc2"); code != cli.ExitOK || e.stored("both") != "acc1|Acme|acc2" {
		t.Fatalf("login that disables acc2: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
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
	// A later login that names nothing keeps the default and the disabled
	// accounts.
	if code, stderr := login(); code != cli.ExitOK || e.stored("both") != "acc1|Acme|acc2" {
		t.Fatalf("login that names nothing: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	// One that enables the account again makes the sets due: the next read
	// asks Cloudflare.
	if code, stderr := login("disabled_accounts="); code != cli.ExitOK || e.stored("both") != "acc1|Acme|" {
		t.Fatalf("login that disables nothing: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	e.f.reset()
	if code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both"); code != cli.ExitOK || !strings.Contains(stdout, "example.net") {
		t.Fatalf("list: exit %d, %s%s", code, stdout, stderr)
	}
	if n := e.f.count(""); n == 0 {
		t.Errorf("the zone set of a login that covers more was served from the cache")
	}
}

// setDisabled rewrites the default account and the disabled accounts of
// the profile "both" in the config, as an edit by hand would.
func (e *r2Env) setDisabled(def string, disabled ...string) {
	e.t.Helper()
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	meta := cfg.Profiles["both"].Platforms[platform.Cloudflare].Metadata
	meta["account_id"] = def
	if len(disabled) > 0 {
		meta["disabled_accounts"] = strings.Join(disabled, ",")
	} else {
		delete(meta, "disabled_accounts")
	}
	if err := cfg.Save(); err != nil {
		e.t.Fatal(err)
	}
}

// account list marks the enabled accounts and the default one, and keeps
// the envelope and the fields it always had.
func TestAccountListMarksEnabled(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc2")
	type row struct {
		ID, Name, Type   string
		Enabled, Default bool
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
		if strings.Contains(stdout, "selected") {
			t.Errorf("account list names a selection: %s", stdout)
		}
		return res.Accounts, stderr
	}
	// Every account the credentials see is enabled.
	rows, stderr := list("both")
	want := []row{{"acc1", "Acme", "standard", true, false}, {"acc2", "Beta", "standard", true, true}}
	if !reflect.DeepEqual(rows, want) {
		t.Errorf("rows = %+v", rows)
	}
	if !strings.Contains(stderr, "2 account(s) via cloudflare/both, 2 enabled, 0 disabled") {
		t.Errorf("stderr = %q", stderr)
	}
	code, stdout, _ := e.run("cloudflare", "account", "list", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "ENABLED") || strings.Contains(stdout, "SELECTED") {
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
				t.Errorf("an enabled account: %q", line)
			}
		}
	}

	// A disabled account says so.
	e.loginBoth("acc1", "acc2")
	rows, stderr = list("both")
	if !reflect.DeepEqual(rows, []row{{"acc1", "Acme", "standard", true, true}, {"acc2", "Beta", "standard", false, false}}) {
		t.Errorf("one disabled: %+v", rows)
	}
	if !strings.Contains(stderr, "2 account(s) via cloudflare/both, 1 enabled, 1 disabled") {
		t.Errorf("one disabled: stderr %q", stderr)
	}
	_, stdout, _ = e.run("cloudflare", "account", "list", "--profile", "both")
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "acc2") && !strings.HasSuffix(strings.TrimSpace(line), "no") {
			t.Errorf("a disabled account: %q", line)
		}
	}
	// A token that sees one account lists that one.
	if rows, _ = list("beta"); !reflect.DeepEqual(rows, []row{{"acc2", "Beta", "standard", true, true}}) {
		t.Errorf("beta: %+v", rows)
	}

	// A disabled account the credentials do not list is shown, and said;
	// enabling it forgets it.
	e.setDisabled("acc1", "acc9")
	rows, stderr = list("both")
	if len(rows) != 3 || !reflect.DeepEqual(rows[2], row{ID: "acc9"}) {
		t.Errorf("unseen account: %+v", rows)
	}
	if !strings.Contains(stderr, "note: disabled account acc9 is not visible to the credentials (to forget it: polyctl cloudflare account enable acc9)") ||
		!strings.Contains(stderr, "3 account(s) via cloudflare/both, 2 enabled, 1 disabled") {
		t.Errorf("unseen account: stderr %q", stderr)
	}
	if code, _, stderr := e.run("cloudflare", "account", "enable", "acc9", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "acc1|Acme|" {
		t.Errorf("enable of an unseen account: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	if code, _, _ := e.run("cloudflare", "account", "list", "--profile", "both", "--offline"); code != cli.ExitOffline {
		t.Errorf("offline: exit %d", code)
	}
}

// loginAll adds a third account and logs the profile "all" in with a token
// that sees the three, acc1 being the default account.
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

// stored reads "default|name|disabled" of a profile's Cloudflare login.
func (e *r2Env) stored(profile string) string {
	e.t.Helper()
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	m := cfg.Profiles[profile].Platforms[platform.Cloudflare].Metadata
	return m["account_id"] + "|" + m["account_name"] + "|" + m["disabled_accounts"]
}

// account use, enable and disable change the accounts of a login without a
// new login, check what they are given, drop what the inventory holds of
// an account that is disabled and make the cached sets due when an account
// is enabled again.
func TestAccountUseEnableDisable(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	// The account that stays holds a record and a bucket too: they must
	// survive the others being disabled.
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc1"].buckets = []string{"assets"}
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
	// Everything the credentials see was synced, without a word about it
	// in the configuration.
	if got := e.rows("all", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-gamma acc3") || e.stored("all") != "acc1|Acme|" {
		t.Fatalf("zones: %v, login %s", got, e.stored("all"))
	}
	if got, want := e.rows("all", platform.ResDNSRecord), []string{"rec-beta zone-beta", "rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records: %v", got)
	}
	if got, want := e.rows("all", platform.ResR2Bucket), []string{"acc1/assets acc1", "acc2/media acc2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("buckets: %v", got)
	}

	// disable: by name and by id, after the credentials were asked for them.
	code, out := acct("disable", "beta", "acc3")
	if code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2,acc3" || !strings.Contains(out, "disabled acc2, acc3 for cloudflare/all") {
		t.Fatalf("disable: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// What the inventory held of them is gone.
	if got, want := e.rows("all", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zones after the disable: %v", got)
	}
	if got, want := e.rows("all", platform.ResDNSRecord), []string{"rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		t.Errorf("records after the disable: %v", got)
	}
	if got, want := e.rows("all", platform.ResR2Bucket), []string{"acc1/assets acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("buckets after the disable: %v", got)
	}
	if got := e.domains("all"); slices.Contains(got, "example.net") || slices.Contains(got, "example.org") || !slices.Contains(got, "example.com") {
		t.Errorf("domains after the disable: %v", got)
	}
	// Nothing has to be synced again for it.
	if due() {
		t.Error("disable must not make the cached sets due")
	}
	// One that is disabled already is nothing to do.
	if code, out = acct("disable", "acc2"); code != cli.ExitOK || !strings.Contains(out, "acc2: already disabled for cloudflare/all") {
		t.Errorf("disable again: exit %d, %s", code, out)
	}
	// One the credentials do not see is not found, unless nothing can be
	// checked, which is said.
	if code, out = acct("disable", "acc9"); code != cli.ExitNotFound || !strings.Contains(out, "is not visible to the credentials of cloudflare/all (visible: acc1=Acme, acc2=Beta, acc3=Gamma)") {
		t.Errorf("disable of an account that is not visible: exit %d, %s", code, out)
	}
	if code, out = acct("disable", "acc9", "--offline"); code != cli.ExitOK || !strings.Contains(out, "--offline: access to acc9 was not checked") || e.stored("all") != "acc1|Acme|acc2,acc3,acc9" {
		t.Errorf("disable --offline: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out = acct("disable", "No Such Name", "--offline"); code != cli.ExitOffline {
		t.Errorf("disable of an unknown name --offline: exit %d, %s", code, out)
	}
	for _, sub := range []string{"disable", "remove"} {
		if code, out = acct(sub); code != cli.ExitUsage || !strings.Contains(out, noAccountsToDisable) {
			t.Errorf("%s without an account: exit %d, %s", sub, code, out)
		}
	}
	// --dry-run is not taken yet.
	if code, out = acct("disable", "acc1", "--default", "acc2", "--dry-run"); code != cli.ExitUsage || e.stored("all") != "acc1|Acme|acc2,acc3,acc9" {
		t.Errorf("disable --dry-run: exit %d, %s, %s", code, e.stored("all"), out)
	}

	// enable: by name, as the credentials list it, and by id.
	if code, out = acct("enable", "beta"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc3,acc9" || !strings.Contains(out, "enabled acc2 for cloudflare/all") {
		t.Fatalf("enable: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if !due() {
		t.Error("enable must make the cached sets due")
	}
	if got := e.rows("all", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || slices.Contains(got, "zone-gamma acc3") {
		t.Errorf("zones after the enable: %v", got)
	}
	// One that is enabled already is nothing to do.
	if code, out = acct("enable", "acc2", "acc1"); code != cli.ExitOK || !strings.Contains(out, "acc2, acc1: already enabled for cloudflare/all") {
		t.Errorf("enable again: exit %d, %s", code, out)
	}
	// One that is neither disabled nor visible is not found.
	if code, out = acct("enable", "acc8"); code != cli.ExitNotFound || !strings.Contains(out, "nothing to enable") || !strings.Contains(out, "polyctl cloudflare account use <id>") {
		t.Errorf("enable of an account that is not visible: exit %d, %s", code, out)
	}
	// A disabled account that is not visible is forgotten.
	if code, out = acct("enable", "acc9"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc3" {
		t.Errorf("enable of a disabled account that is not visible: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out = acct("enable"); code != cli.ExitUsage {
		t.Errorf("enable without an account: exit %d, %s", code, out)
	}
	// The names the two commands had are kept.
	if code, out = acct("add", "acc3"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|" || !strings.Contains(out, "enabled acc3 for cloudflare/all") {
		t.Errorf("add: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out = acct("remove", "acc3"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc3" || !strings.Contains(out, "disabled acc3 for cloudflare/all") {
		t.Errorf("remove: exit %d, %s, %s", code, e.stored("all"), out)
	}

	// use: a disabled account that becomes the default is enabled again.
	sync()
	if code, out = acct("use", "Gamma"); code != cli.ExitOK || e.stored("all") != "acc3|Gamma|" || !strings.Contains(out, "account acc3 is now the default account of cloudflare/all") ||
		!strings.Contains(out, "account acc3 was disabled and is enabled again") {
		t.Fatalf("use: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if !due() {
		t.Error("use of a disabled account must make the cached sets due")
	}
	if code, out = acct("use", "acc3"); code != cli.ExitOK || !strings.Contains(out, "account acc3 is already the default account of cloudflare/all") {
		t.Errorf("use of the default: exit %d, %s", code, out)
	}
	if code, out = acct("use", "acc8"); code != cli.ExitNotFound || !strings.HasPrefix(e.stored("all"), "acc3|") {
		t.Errorf("use of an account that is not visible: exit %d, %s", code, out)
	}
	if code, out = acct("use"); code != cli.ExitUsage {
		t.Errorf("use without an account: exit %d, %s", code, out)
	}
	// Another default among the enabled accounts changes nothing of what
	// the login covers: nothing is dropped and nothing is due.
	if code, out = acct("use", "acc1"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|" || strings.Contains(out, "enabled again") {
		t.Fatalf("use of an enabled account: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if due() {
		t.Error("use of an enabled account must not make the cached sets due")
	}
	if got := e.rows("all", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-gamma acc3") {
		t.Errorf("zones after use: %v", got)
	}

	// current shows the login without a request.
	if code, out = acct("disable", "acc2"); code != cli.ExitOK {
		t.Fatalf("disable: exit %d, %s", code, out)
	}
	e.f.reset()
	code, stdout, stderr := e.run("cloudflare", "account", "current", "--profile", "all", "--offline", "-o", "json")
	var cur struct {
		Profile     string
		AccountID   string         `json:"account_id"`
		AccountName string         `json:"account_name"`
		Disabled    []string       `json:"disabled_accounts"`
		Accounts    map[string]any `json:"accounts"`
		Method      string
	}
	if err := json.Unmarshal([]byte(stdout), &cur); code != cli.ExitOK || err != nil {
		t.Fatalf("current: exit %d, %v, %s%s", code, err, stdout, stderr)
	}
	if cur.Profile != "all" || cur.AccountID != "acc1" || cur.AccountName != "Acme" || cur.Method != "api_token" || !reflect.DeepEqual(cur.Disabled, []string{"acc2"}) || strings.Contains(stdout, `"accounts"`) {
		t.Errorf("current = %+v: %s", cur, stdout)
	}
	if e.f.count("") != 0 {
		t.Errorf("current asked Cloudflare")
	}

	// The default account needs --default to be disabled.
	if code, out = acct("disable", "acc1"); code != cli.ExitUsage || !strings.Contains(out, "--default <id>") || !strings.Contains(out, "one of: acc3") {
		t.Errorf("disable of the default: exit %d, %s", code, out)
	}
	for _, def := range []string{"acc1", "acc2"} {
		if code, out = acct("disable", "acc1", "--default", def); code != cli.ExitUsage || !strings.Contains(out, "not one of the accounts that stay enabled (acc3)") {
			t.Errorf("--default %s: exit %d, %s", def, code, out)
		}
	}
	if code, out = acct("disable", "acc1", "--default", "Gamma"); code != cli.ExitOK || e.stored("all") != "acc3|Gamma|acc1,acc2" ||
		!strings.Contains(out, "disabled acc1 for cloudflare/all") || !strings.Contains(out, "account acc3 is now the default account of cloudflare/all") {
		t.Fatalf("disable with --default: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// Disabling every account is refused.
	if code, out = acct("disable", "acc3"); code != cli.ExitUsage || !strings.Contains(out, "this would disable every account of cloudflare/all") || !strings.Contains(out, "polyctl auth logout cloudflare --profile all") {
		t.Errorf("disable of every account: exit %d, %s", code, out)
	}
	// Both work offline, by id and by a name the cached zones carry.
	e.f.reset()
	if code, out = acct("enable", "acc1", "acc2", "--offline"); code != cli.ExitOK || e.stored("all") != "acc3|Gamma|" {
		t.Fatalf("enable --offline: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if e.f.count("") != 0 {
		t.Errorf("enable --offline asked Cloudflare")
	}
	sync()
	if code, out = acct("disable", "acc1", "beta", "--offline"); code != cli.ExitOK || e.stored("all") != "acc3|Gamma|acc1,acc2" {
		t.Fatalf("disable --offline: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if e.f.count("") != 0 {
		t.Errorf("disable --offline asked Cloudflare")
	}
	if got, want := e.rows("all", platform.ResZone), []string{"zone-gamma acc3"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zones after the offline disable: %v", got)
	}
	// The other logins were not touched: the account disabled here is
	// still worked on through them.
	if e.stored("acme") != "acc1|Acme|" || e.stored("beta") != "acc2|Beta|" {
		t.Errorf("other logins: %s, %s", e.stored("acme"), e.stored("beta"))
	}
	if code, stdout, stderr = e.run("dns", "list", "example.net", "--refresh", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "192.0.2.2") || !strings.Contains(stdout+stderr, "beta") {
		t.Errorf("dns list of a zone disabled in one login: exit %d, %s%s", code, stdout, stderr)
	}
}

// The rows of a zone and of a bucket stored before the rows had their
// account as parent leave the inventory with their account too.
func TestAccountDisableDropsRowsWithoutAParent(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.loginBoth("acc1")
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	// Store the zone and the bucket of acc2 again as they were stored then.
	e.unparent("both", "acc2")
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-beta ") {
		t.Fatalf("zones: %v", got)
	}
	if got := e.rows("both", platform.ResR2Bucket); !reflect.DeepEqual(got, []string{"acc1/assets acc1", "media "}) {
		t.Fatalf("buckets: %v", got)
	}
	if got := e.rows("both", platform.ResDNSRecord); !reflect.DeepEqual(got, []string{"rec-beta zone-beta", "rec-ex zone-ex"}) {
		t.Fatalf("records: %v", got)
	}

	if code, _, stderr := e.run("cloudflare", "account", "disable", "acc2", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("disable: exit %d, %s", code, stderr)
	}
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("zones: %v", got)
	}
	// What is of the account that stays is still there.
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		t.Errorf("records: %v", got)
	}
	if got, want := e.rows("both", platform.ResR2Bucket), []string{"acc1/assets acc1"}; !reflect.DeepEqual(got, want) {
		t.Errorf("buckets: %v", got)
	}
	if got := e.domains("both"); slices.Contains(got, "example.net") {
		t.Errorf("domains: %v", got)
	}
}

// noAccountsToDisable is the usage error of disable without an account.
const noAccountsToDisable = `name the accounts to disable, or choose from the list with "polyctl cloudflare account enable"`

// On a terminal use offers the visible accounts when none is named, and
// enable opens one list of every account with the enabled ones ticked: what
// is ticked at the end is enabled and the rest disabled. A default account
// that was unticked is replaced by the answer to a question, by --default
// or by the only account left. disable never opens the list: without an
// account it is a usage error that names the list of enable.
func TestAccountCommandsPick(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	const title = "Enabled accounts of cloudflare/all (ticked: synced and searched)"
	pick := func(sub string, answers ...any) (*prompttest.Picker, int, string) {
		t.Helper()
		p := prompttest.New(t, answers...)
		code, _, stderr := e.runPick(p, "cloudflare", "account", sub, "--profile", "all")
		p.Done()
		return p, code, stderr
	}
	// Nothing is disabled: every account is ticked, and leaving the list as
	// it is changes nothing.
	p, code, stderr := pick("enable", []string{"acc1", "acc2", "acc3"})
	if code != cli.ExitOK || e.stored("all") != "acc1|Acme|" || !strings.Contains(stderr, "the enabled accounts and the default account of cloudflare/all are unchanged") {
		t.Fatalf("unchanged pick: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	if a := p.Asked[0]; a.Kind != "multi" || a.Title != title || prompttest.Values(a.Options) != "acc1 acc2 acc3" ||
		prompttest.Labels(a.Options) != "Acme  acc1  default\nBeta  acc2\nGamma  acc3" || !reflect.DeepEqual(a.Preset, []string{"acc1", "acc2", "acc3"}) {
		t.Errorf("enable offered %+v", a)
	}
	// Unticking disables.
	if _, code, stderr = pick("enable", []string{"acc1", "acc3"}); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2" || !strings.Contains(stderr, "disabled acc2 for cloudflare/all") {
		t.Fatalf("untick in enable: exit %d, %s, %s", code, e.stored("all"), stderr)
	}

	p = prompttest.New(t, "acc3")
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "use", "--profile", "all"); code != cli.ExitOK || e.stored("all") != "acc3|Gamma|acc2" {
		t.Fatalf("use: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	p.Done()
	if a := p.Asked[0]; a.Title != "Default account" || a.Default != "acc1" || prompttest.Values(a.Options) != "acc1 acc2 acc3" ||
		!strings.Contains(prompttest.Labels(a.Options), "Acme  acc1  default") || !strings.Contains(prompttest.Labels(a.Options), "Beta  acc2  disabled") ||
		!strings.HasSuffix(prompttest.Labels(a.Options), "Gamma  acc3") {
		t.Errorf("use asked %+v", a)
	}

	// Both directions at once: acc2 is ticked again and acc1 unticked. The
	// ticks shown are the enabled accounts.
	p, code, stderr = pick("enable", []string{"acc2", "acc3"})
	if code != cli.ExitOK || e.stored("all") != "acc3|Gamma|acc1" || !strings.Contains(stderr, "disabled acc1 for cloudflare/all") || !strings.Contains(stderr, "enabled acc2 for cloudflare/all") {
		t.Fatalf("both directions: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	if a := p.Asked[0]; a.Kind != "multi" || a.Title != title || prompttest.Labels(a.Options) != "Acme  acc1\nBeta  acc2\nGamma  acc3  default" || !reflect.DeepEqual(a.Preset, []string{"acc1", "acc3"}) {
		t.Errorf("both directions offered %+v", a)
	}

	// The default account unticked: the new one is asked among the ticked.
	p, code, stderr = pick("enable", []string{"acc1", "acc2"}, "acc2")
	if code != cli.ExitOK || e.stored("all") != "acc2|Beta|acc3" || !strings.Contains(stderr, "account acc2 is now the default account of cloudflare/all") {
		t.Fatalf("default unticked: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	if a := p.Asked[1]; a.Title != "New default account" || prompttest.Values(a.Options) != "acc1 acc2" || !strings.Contains(prompttest.Labels(a.Options), "Acme  acc1") {
		t.Errorf("new default asked %+v", a)
	}
	// --default answers it, by id or name; it must be ticked.
	p = prompttest.New(t, []string{"acc1", "acc3"})
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "enable", "--profile", "all", "--default", "acc2"); code != cli.ExitUsage ||
		!strings.Contains(stderr, "--default acc2: not one of the accounts that stay enabled (acc1, acc3)") || e.stored("all") != "acc2|Beta|acc3" {
		t.Errorf("--default of an unticked account: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	p.Done()
	p = prompttest.New(t, []string{"acc1", "acc3"})
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "enable", "--profile", "all", "--default", "Gamma"); code != cli.ExitOK || e.stored("all") != "acc3|Gamma|acc2" {
		t.Fatalf("--default in the pick: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	p.Done()
	// With one account left ticked it is taken without a question.
	if _, code, stderr = pick("enable", []string{"acc1"}); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2,acc3" {
		t.Fatalf("one left: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	// Ticking nothing writes nothing.
	if _, code, stderr = pick("enable", []string{}); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2,acc3" {
		t.Errorf("nothing ticked: exit %d, %s, %s", code, e.stored("all"), stderr)
	}

	// A disabled account the credentials no longer see is offered as such.
	// Ticking it forgets it, and it is no candidate for the default: with
	// nothing else ticked every account would be disabled.
	e.f.tokens["tok-all"] = "acc1,acc2"
	p, code, stderr = pick("enable", []string{"acc3"})
	if code != cli.ExitUsage || !strings.Contains(stderr, "this would disable every account of cloudflare/all") || e.stored("all") != "acc1|Acme|acc2,acc3" {
		t.Errorf("only an account that is not visible ticked: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	if a := p.Asked[0]; prompttest.Labels(a.Options) != "Acme  acc1  default\nBeta  acc2\n-  acc3  not visible" || !reflect.DeepEqual(a.Preset, []string{"acc1"}) {
		t.Errorf("list with an account that is not visible: %+v", a)
	}
	if _, code, stderr = pick("enable", []string{"acc1", "acc3"}); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2" || !strings.Contains(stderr, "enabled acc3 for cloudflare/all") {
		t.Errorf("forget an account that is not visible: exit %d, %s, %s", code, e.stored("all"), stderr)
	}

	// disable, and remove, its hidden former name, never open the list:
	// without an account they are a usage error on a terminal and away
	// from one, which says where the list is. Nothing is asked or stored.
	for _, sub := range []string{"disable", "remove"} {
		for _, more := range [][]string{nil, {"--default", "acc1"}, {"--offline"}} {
			args := append([]string{"cloudflare", "account", sub, "--profile", "all"}, more...)
			p = prompttest.New(t)
			if code, _, stderr := e.runPick(p, args...); code != cli.ExitUsage || !strings.Contains(stderr, noAccountsToDisable) || e.stored("all") != "acc1|Acme|acc2" {
				t.Errorf("%s %v without an account on a terminal: exit %d, %s, %s", sub, more, code, e.stored("all"), stderr)
			}
			p.Done()
			if len(p.Asked) != 0 {
				t.Errorf("%s %v without an account asked %+v", sub, more, p.Asked)
			}
			if code, _, stderr := e.run(args...); code != cli.ExitUsage || !strings.Contains(stderr, noAccountsToDisable) {
				t.Errorf("%s %v without an account, non-interactive: exit %d, %s", sub, more, code, stderr)
			}
		}
	}

	// The list needs Cloudflare, and credentials that can list accounts.
	for _, sub := range []string{"enable", "add"} {
		p = prompttest.New(t)
		if code, _, stderr := e.runPick(p, "cloudflare", "account", sub, "--profile", "all", "--offline"); code != cli.ExitOffline {
			t.Errorf("%s --offline without an account: exit %d, %s", sub, code, stderr)
		}
		p.Done()
		// Away from a terminal an account must be named.
		if code, _, stderr := e.run("cloudflare", "account", sub, "--profile", "all"); code != cli.ExitUsage {
			t.Errorf("%s without an account, non-interactive: exit %d, %s", sub, code, stderr)
		}
	}
	zones := e.f.zones
	e.f.accountsStatus, e.f.zones = http.StatusForbidden, nil
	if _, code, stderr = pick("enable"); code != cli.ExitUsage || !strings.Contains(stderr, "the credentials of cloudflare/all cannot list accounts: pass the account id") {
		t.Errorf("enable with credentials that cannot list accounts: exit %d, %s", code, stderr)
	}
	// A list read off the zones is not complete, but it is a list.
	e.f.zones = zones
	if _, code, stderr = pick("enable", []string{"acc1"}); code != cli.ExitOK || !strings.Contains(stderr, "are unchanged") || e.stored("all") != "acc1|Acme|acc2" {
		t.Errorf("pick over the accounts of the zones: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
}

// enable and disable, and add and remove, their hidden former names,
// report with --dry-run what they would change: nothing is written, purged
// or made due.
func TestAccountEnableDisableDryRun(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	if code, _, stderr := e.run("cloudflare", "account", "disable", "acc3", "--profile", "all"); code != cli.ExitOK {
		t.Fatalf("disable: exit %d, %s", code, stderr)
	}
	if code, _, stderr := e.run("sync", "--profile", "all", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	zones := e.rows("all", platform.ResZone)
	e.f.reset()
	check := func(what, stdout string, code int, want ...string) {
		t.Helper()
		if code != cli.ExitOK {
			t.Fatalf("%s: exit %d, %s", what, code, stdout)
		}
		rep := e.report(stdout)
		var got []string
		for _, c := range rep.Changes {
			got = append(got, c.Resource+" "+string(c.Action)+" "+c.Detail)
		}
		if !rep.DryRun || rep.Target.Platform != platform.Cloudflare || rep.Target.Profile != "all" || !reflect.DeepEqual(got, want) {
			t.Errorf("%s reported %+v %v, want %v", what, rep.Target, got, want)
		}
		if e.stored("all") != "acc1|Acme|acc3" || !reflect.DeepEqual(e.rows("all", platform.ResZone), zones) {
			t.Errorf("%s changed the login: %s, zones %v", what, e.stored("all"), e.rows("all", platform.ResZone))
		}
	}
	acct := func(args ...string) (int, string, string) {
		return e.run(append([]string{"cloudflare", "account"}, append(args, "--profile", "all", "--dry-run", "-o", "json")...)...)
	}
	for _, sub := range []string{"disable", "remove"} {
		code, stdout, _ := acct(sub, "Beta")
		check(sub, stdout, code, "account/acc2 would_update disabled")
		code, stdout, _ = acct(sub, "acc1", "--default", "acc2")
		check(sub+" of the default", stdout, code, "account/acc1 would_update disabled", "account/acc2 would_update default")
	}
	for _, sub := range []string{"enable", "add"} {
		code, stdout, stderr := acct(sub, "acc3")
		check(sub, stdout, code, "account/acc3 would_update enabled")
		if !strings.Contains(stderr, "dry run: would update account/acc3 (enabled)") {
			t.Errorf("%s stderr = %q", sub, stderr)
		}
	}
	// Nothing to do stays nothing to do, a usage error a usage error, and
	// use has nothing to preview.
	if code, stdout, stderr := acct("disable", "acc3"); code != cli.ExitOK || stdout != "" || !strings.Contains(stderr, "already disabled") {
		t.Errorf("dry run of a disabled account: exit %d, %s%s", code, stdout, stderr)
	}
	if code, _, stderr := acct("disable", "acc1"); code != cli.ExitUsage || !strings.Contains(stderr, "--default <id>") {
		t.Errorf("dry run of the default without --default: exit %d, %s", code, stderr)
	}
	if code, _, stderr := acct("use", "acc2"); code != cli.ExitUsage || !strings.Contains(stderr, "does not support --dry-run") {
		t.Errorf("use --dry-run: exit %d, %s", code, stderr)
	}
	// The pick reports what its ticks would change, in both directions.
	p := prompttest.New(t, []string{"acc2", "acc3"}, "acc3")
	code, stdout, stderr := e.runPick(p, "cloudflare", "account", "enable", "--profile", "all", "--dry-run", "-o", "json")
	p.Done()
	check("pick", stdout, code, "account/acc1 would_update disabled", "account/acc3 would_update enabled", "account/acc3 would_update default")
	_ = stderr
	// The cached sets were not made due: the next list asks nothing.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "all"); code != cli.ExitOK || e.f.count("") != 0 {
		t.Errorf("zone list after the dry runs: exit %d, %d request(s), %s", code, e.f.count(""), stderr)
	}
	// The table of the report.
	code, stdout, _ = e.run("cloudflare", "account", "disable", "acc2", "--profile", "all", "--dry-run")
	if out := strings.Join(strings.Fields(stdout), " "); code != cli.ExitOK || !strings.Contains(out, "RESOURCE ACTION DETAIL account/acc2 would update disabled") || e.stored("all") != "acc1|Acme|acc3" {
		t.Errorf("table: exit %d, %q, %s", code, out, e.stored("all"))
	}
}

// A login that is not bound to an account works on every account its
// credentials see. It may disable some of them, and account use gives it a
// default account without taking anything from what it covers.
func TestAccountUseOnALoginWithoutAnAccount(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1")
	e.unbind("both")
	code, stdout, stderr := e.run("cloudflare", "account", "current", "--profile", "both")
	if code != cli.ExitOK || !strings.Contains(stdout, "(none: every account the credentials see)") {
		t.Errorf("current: exit %d, %s%s", code, stdout, stderr)
	}
	// Nothing needs to be enabled.
	if code, _, stderr = e.run("cloudflare", "account", "enable", "Beta", "acc1", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "||" ||
		!strings.Contains(stderr, "already enabled for cloudflare/both") {
		t.Errorf("enable: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	// Disabling an account needs no default account.
	if code, _, stderr = e.run("cloudflare", "account", "disable", "Acme", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "||acc1" ||
		strings.Contains(stderr, "default account of") {
		t.Errorf("disable: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "example.net") || strings.Contains(stdout, "example.com") {
		t.Errorf("zone list after the disable: exit %d, %s%s", code, stdout, stderr)
	}
	if code, _, stderr = e.run("cloudflare", "account", "enable", "acc1", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "||" {
		t.Errorf("enable of the disabled account: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	// A default account: the login still lists the zones of both.
	if code, _, stderr = e.run("cloudflare", "account", "use", "acc2", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "acc2|Beta|" {
		t.Errorf("use: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "both", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "example.com") {
		t.Errorf("zone list: exit %d, %s%s", code, stdout, stderr)
	}
}

// A login whose token sees an account without an R2 permission in it does
// not hide that account from the login that can use it: the bucket is
// found through the second login, and the bucket listing shows its
// buckets, in the run that synced as in the one served from the
// inventory. The status line counts the accounts that answered.
func TestR2AccountALoginCannotUseIsReadThroughAnother(t *testing.T) {
	e := newR2Env(t)
	cloudflare.CaptureWarnings(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.f.r2Denied = map[string]bool{"acc1,acc2/acc2": true}
	// The profile sorts before beta, the login of acc2.
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "aaa", "--set", "token=tok-both", "--set", "account_id=acc1"); code != cli.ExitOK {
		t.Fatalf("login aaa: exit %d, %s", code, stderr)
	}
	e.f.reset()

	// The lookup of a bucket, before anything is in the inventory.
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "media"); code != cli.ExitOK || !strings.Contains(stderr, "beta") {
		t.Fatalf("domain list media: exit %d, %s", code, stderr)
	}
	// A bucket no account holds names the login that was skipped only
	// for an account nobody could read.
	code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "nowhere")
	if code != cli.ExitNotFound || strings.Contains(stderr, "were skipped") {
		t.Errorf("domain list nowhere: exit %d, %s", code, stderr)
	}

	for _, run := range []string{"synced", "inventory"} {
		code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "-o", "json")
		if code != cli.ExitOK || !strings.Contains(stdout, `"name": "assets"`) || !strings.Contains(stdout, `"name": "media"`) {
			t.Errorf("%s: bucket list: exit %d, %s%s", run, code, stdout, stderr)
		}
		if run == "synced" && !strings.Contains(stderr, "2 bucket(s) in 2 account(s)") {
			t.Errorf("%s: status line: %s", run, stderr)
		}
	}
	// The login alone lists the one account that answered.
	code, stdout, stderr := e.run("--refresh", "cloudflare", "r2", "bucket", "list", "--profile", "aaa")
	if code != cli.ExitOK || !strings.Contains(stdout, "assets") || strings.Contains(stdout, "media") || !strings.Contains(stderr, "1 bucket(s) in 1 account(s)") {
		t.Errorf("bucket list --profile aaa: exit %d, %s%s", code, stdout, stderr)
	}
}
