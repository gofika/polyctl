package cloudflare_test

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// unbind takes the account and the selection off the stored login of a
// profile: the login of credentials that could not list their accounts.
func (e *r2Env) unbind(profile string) {
	e.t.Helper()
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	meta := cfg.Profiles[profile].Platforms[platform.Cloudflare].Metadata
	delete(meta, "account_id")
	delete(meta, "account_name")
	delete(meta, "accounts")
	if err := cfg.Save(); err != nil {
		e.t.Fatal(err)
	}
}

// syncedUnbound is the profile "both" as a login without an account whose
// inventory holds the zones and the records of acc1 and acc2 (the buckets
// of such a login are not synced when its credentials see several
// accounts).
func syncedUnbound(t *testing.T) *r2Env {
	t.Helper()
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.addRecord("zone-beta", "rec-beta", "www.example.net", "A", "192.0.2.2")
	e.loginBoth("acc1")
	e.unbind("both")
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-ex acc1") {
		t.Fatalf("zones: %v", got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-beta zone-beta", "rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("records: %v", got)
	}
	e.f.reset()
	return e
}

// onlyAcc1 checks that the inventory of the profile "both" holds what is
// of acc1 and nothing of acc2, and that a name of a zone of acc2 is no
// longer routed to it.
func (e *r2Env) onlyAcc1(what string) {
	e.t.Helper()
	if got, want := e.rows("both", platform.ResZone), []string{"zone-a acc1", "zone-couk acc1", "zone-ex acc1", "zone-pend acc1"}; !reflect.DeepEqual(got, want) {
		e.t.Errorf("%s: zones: %v", what, got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		e.t.Errorf("%s: records: %v", what, got)
	}
	for _, b := range e.rows("both", platform.ResR2Bucket) {
		if !strings.HasSuffix(b, " acc1") {
			e.t.Errorf("%s: bucket %s", what, b)
		}
	}
	if got := e.domains("both"); slices.Contains(got, "example.net") || !slices.Contains(got, "example.com") {
		e.t.Errorf("%s: domains: %v", what, got)
	}
	e.f.reset()
	code, stdout, stderr := e.run("dns", "list", "example.net", "--profile", "both", "-o", "json")
	if code == cli.ExitOK || strings.Contains(stdout, "rec-beta") || e.f.count("GET /zones/zone-beta/") != 0 {
		e.t.Errorf("%s: dns list of a zone of acc2: exit %d, %s%s", what, code, stdout, stderr)
	}
}

// A login without an account that is narrowed to a selection with account
// use or add drops what its inventory holds of every other account: the
// neutral commands would otherwise keep routing the names of their zones
// to accounts the login no longer works on.
func TestAccountUseNarrowsALoginWithoutAnAccount(t *testing.T) {
	for _, verb := range []string{"use", "add"} {
		t.Run(verb, func(t *testing.T) {
			e := syncedUnbound(t)
			if code, _, stderr := e.run("cloudflare", "account", verb, "acc1", "--profile", "both"); code != cli.ExitOK || e.selection("both") != "acc1|Acme|" {
				t.Fatalf("account %s: exit %d, %s, %s", verb, code, e.selection("both"), stderr)
			}
			e.onlyAcc1("account " + verb)
		})
	}
}

// unparent stores the zone and bucket rows of an account of a profile again
// as they were stored before the rows had their account as parent: without
// a parent, the bucket under its bare name.
func (e *r2Env) unparent(profile, account string) {
	e.t.Helper()
	db, err := inventory.Open(filepath.Join(e.dir, "inventory.db"))
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResR2Bucket} {
		rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: typ})
		if err != nil {
			e.t.Fatal(err)
		}
		var res []platform.Resource
		for _, r := range rows {
			pr := platform.Resource{Type: typ, ID: r.ID, Name: r.Name, ParentID: r.ParentID, Domain: r.Domain, Data: json.RawMessage(r.Data)}
			if r.ParentID == account {
				pr.ParentID = ""
				if typ == platform.ResR2Bucket {
					pr.ID = r.Name
				}
			}
			res = append(res, pr)
		}
		if err := db.Replace(ctx, inventory.Set{Platform: platform.Cloudflare, Profile: profile, Type: typ}, res, time.Hour); err != nil {
			e.t.Fatal(err)
		}
	}
}

// A new login that binds a login without an account to a selection drops
// what the inventory holds of every account outside it, as account use
// does.
func TestReloginNarrowsALoginWithoutAnAccount(t *testing.T) {
	e := syncedUnbound(t)
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id=acc1"); code != cli.ExitOK || e.selection("both") != "acc1|Acme|" {
		t.Fatalf("login: exit %d, %s, %s", code, e.selection("both"), stderr)
	}
	e.onlyAcc1("login")
}

// A new login that no longer selects the account an earlier release stored
// rows for drops those rows too, although they have no parent: the neutral
// commands would otherwise keep routing the names of its zones to it.
func TestReloginDropsRowsWithoutAParent(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.loginBoth("acc1")
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	e.unparent("both", "acc1")
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-ex ") {
		t.Fatalf("zones: %v", got)
	}
	if got := e.rows("both", platform.ResR2Bucket); !reflect.DeepEqual(got, []string{"assets "}) {
		t.Fatalf("buckets: %v", got)
	}
	if got := e.rows("both", platform.ResDNSRecord); !reflect.DeepEqual(got, []string{"rec-ex zone-ex"}) {
		t.Fatalf("records: %v", got)
	}

	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "accounts=acc2", "--set", "account_id=acc2"); code != cli.ExitOK || e.selection("both") != "acc2|Beta|" {
		t.Fatalf("login: exit %d, %s, %s", code, e.selection("both"), stderr)
	}
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResR2Bucket} {
		if got := e.rows("both", typ); len(got) != 0 {
			t.Errorf("%s rows of the account that left: %v", typ, got)
		}
	}
	if got := e.domains("both"); slices.Contains(got, "example.com") {
		t.Errorf("domains: %v", got)
	}
	e.f.reset()
	if code, stdout, stderr := e.run("dns", "list", "example.com", "--profile", "both", "-o", "json"); code == cli.ExitOK || e.f.count("GET /zones/zone-ex/") != 0 {
		t.Errorf("dns list of a zone of the account that left: exit %d, %s%s", code, stdout, stderr)
	}
}

// account remove takes the name of a selected account, also of one the
// profile knows no name of (no zone of it is cached, and it is not the
// default): the credentials are asked.
func TestAccountRemoveByNameAsksTheCredentials(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...)
		return code, stdout + stderr
	}
	if code, out := acct("add", "Beta", "Gamma"); code != cli.ExitOK || e.selection("all") != "acc1|Acme|acc1,acc2,acc3" {
		t.Fatalf("add: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if code, out := acct("remove", "Gamma"); code != cli.ExitOK || e.selection("all") != "acc1|Acme|acc1,acc2" || !strings.Contains(out, "removed acc3 from the accounts of cloudflare/all") {
		t.Fatalf("remove by name: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if code, out := acct("remove", "acc1", "--default", "beta"); code != cli.ExitOK || e.selection("all") != "acc2|Beta|" {
		t.Fatalf("remove with --default by name: exit %d, %s, %s", code, e.selection("all"), out)
	}
	// A name no selected account carries is still "not selected", also when
	// a visible account carries it.
	if code, out := acct("remove", "Acme"); code != cli.ExitNotFound || !strings.Contains(out, "Acme is not selected for cloudflare/all (selected: acc2)") {
		t.Errorf("remove of an unselected name: exit %d, %s", code, out)
	}
	// Credentials that fail do not keep an account from being removed by id.
	if code, out := acct("add", "acc1"); code != cli.ExitOK {
		t.Fatalf("add: exit %d, %s", code, out)
	}
	delete(e.f.tokens, "tok-all")
	if code, out := acct("remove", "acc1"); code != cli.ExitOK || e.selection("all") != "acc2|Beta|" {
		t.Errorf("remove with failing credentials: exit %d, %s, %s", code, e.selection("all"), out)
	}
}

// An account listing that fails is an error of the command, not the sign
// of credentials that cannot list their accounts: nothing is selected
// unchecked, and the failure keeps its exit code.
func TestAccountListingThatFails(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...)
		return code, stdout + stderr
	}
	e.f.accountsStatus = http.StatusBadRequest
	for _, verb := range []string{"add", "use"} {
		if code, out := acct(verb, "acc-typo"); code != cli.ExitError || strings.Contains(out, "was not checked") || e.selection("all") != "acc1|Acme|" {
			t.Errorf("account %s while the listing fails: exit %d, %s, %s", verb, code, e.selection("all"), out)
		}
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "Beta Inc")
	if code != cli.ExitError || strings.Contains(stderr, "cannot list accounts") {
		t.Errorf("--account while the listing fails: exit %d, %s%s", code, stdout, stderr)
	}
	// Credentials that are refused altogether are an authentication error.
	e.f.accountsStatus = 0
	delete(e.f.tokens, "tok-all")
	if code, out := acct("add", "acc-typo"); code != cli.ExitAuth || e.selection("all") != "acc1|Acme|" {
		t.Errorf("account add with refused credentials: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "Beta Inc"); code != cli.ExitAuth {
		t.Errorf("--account with refused credentials: exit %d, %s%s", code, stdout, stderr)
	}
}

// Credentials that may not list their accounts (a token without
// Account:Read) have them read off their zones: a name is one of an account
// with a zone, and an id that list does not hold is taken unchecked, which
// is said.
func TestAccountsOfCredentialsThatCannotListThem(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	e.f.accountsStatus = http.StatusForbidden
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...)
		return code, stdout + stderr
	}
	// A name the zones carry needs no note: the account was seen.
	if code, out := acct("add", "Beta"); code != cli.ExitOK || e.selection("all") != "acc1|Acme|acc1,acc2" || strings.Contains(out, "was not checked") {
		t.Fatalf("add by a name of the zones: exit %d, %s, %s", code, e.selection("all"), out)
	}
	// An id the zones do not show may be an account without a zone.
	if code, out := acct("add", "acc7"); code != cli.ExitOK || e.selection("all") != "acc1|Acme|acc1,acc2,acc7" ||
		!strings.Contains(out, "note: the credentials of cloudflare/all cannot list accounts: access to acc7 was not checked") {
		t.Fatalf("add of an id that cannot be checked: exit %d, %s, %s", code, e.selection("all"), out)
	}
	if code, out := acct("use", "acc8"); code != cli.ExitOK || !strings.HasPrefix(e.selection("all"), "acc8||acc8,") ||
		!strings.Contains(out, "access to acc8 was not checked") {
		t.Fatalf("use of an id that cannot be checked: exit %d, %s, %s", code, e.selection("all"), out)
	}
	// What cannot be an id is not found among the accounts of the zones.
	if code, out := acct("add", "No Such Name"); code != cli.ExitNotFound || !strings.Contains(out, `account "No Such Name" is not visible to the credentials of cloudflare/all`) {
		t.Errorf("add of an unknown name: exit %d, %s", code, out)
	}
	// --account: an account of the zones by its name, read live when it is
	// not selected.
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "Gamma", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.org") || strings.Contains(stdout, "example.com") {
		t.Errorf("--account by a name of the zones: exit %d, %s%s", code, stdout, stderr)
	}
	if got := e.rows("all", platform.ResZone); slices.Contains(got, "zone-gamma acc3") {
		t.Errorf("the zones of an unselected account were cached: %v", got)
	}
}

// Credentials that see no account at all (no Account:Read and no zone)
// take an account id as it is, with a note; a name cannot be looked up
// (exit code 2), and nothing can be offered on a terminal.
func TestAccountsOfCredentialsThatSeeNone(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc4"] = &r2Account{id: "acc4", name: "Delta", domains: map[string][]map[string]any{}}
	e.f.tokens["tok-none"] = "acc4"
	e.f.accountsStatus = http.StatusForbidden
	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "none", "--set", "token=tok-none"); code != cli.ExitOK ||
		!strings.Contains(stderr, "the token cannot list accounts") || e.selection("none") != "||" {
		t.Fatalf("login: exit %d, %s, %s", code, e.selection("none"), stderr)
	}
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "none"}, args...)...)
		return code, stdout + stderr
	}
	if code, out := acct("add", "Delta Inc"); code != cli.ExitUsage || !strings.Contains(out, "the credentials of cloudflare/none cannot list accounts, so an account name cannot be looked up: pass the account id") {
		t.Errorf("add by name: exit %d, %s", code, out)
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "none", "--account", "Delta Inc")
	if code != cli.ExitUsage || !strings.Contains(stderr, "--account: the credentials of cloudflare/none cannot list accounts, so an account name cannot be looked up: pass the account id") {
		t.Errorf("--account by name: exit %d, %s%s", code, stdout, stderr)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "none", "--account", "acc4"); code != cli.ExitOK {
		t.Errorf("--account by id: exit %d, %s%s", code, stdout, stderr)
	}
	p := prompttest.New(t)
	if code, _, stderr = e.runPick(p, "cloudflare", "account", "use", "--profile", "none"); code != cli.ExitUsage ||
		!strings.Contains(stderr, "the credentials of cloudflare/none cannot list accounts: pass the account id") {
		t.Errorf("use on a terminal: exit %d, %s", code, stderr)
	}
	p.Done()
	if code, out := acct("use", "acc4"); code != cli.ExitOK || e.selection("none") != "acc4||" ||
		!strings.Contains(out, "note: the credentials of cloudflare/none cannot list accounts: access to acc4 was not checked") {
		t.Errorf("use by id: exit %d, %s, %s", code, e.selection("none"), out)
	}
}

// --account filters what a login without an account cached, by the id of
// an account as well as by its name: nothing is asked, so it works with
// --offline.
func TestAccountFlagByIDOnALoginWithoutAnAccount(t *testing.T) {
	e := syncedUnbound(t)
	for _, ref := range []string{"Acme", "acc1"} {
		for _, offline := range []bool{true, false} {
			args := []string{"cloudflare", "zone", "list", "--profile", "both", "--account", ref, "-o", "json"}
			if offline {
				args = append(args, "--offline")
			}
			e.f.reset()
			code, stdout, stderr := e.run(args...)
			if code != cli.ExitOK || !strings.Contains(stdout, "example.com") || strings.Contains(stdout, "example.net") {
				t.Errorf("--account %s (offline %v): exit %d, %s%s", ref, offline, code, stdout, stderr)
			}
			if n := e.f.count(""); n != 0 {
				t.Errorf("--account %s (offline %v) asked Cloudflare %d time(s)", ref, offline, n)
			}
		}
	}
	// An id the cache does not know still cannot be looked up offline.
	if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "both", "--account", "acc9", "--offline"); code != cli.ExitOffline {
		t.Errorf("--account of an unknown id --offline: exit %d, %s", code, stderr)
	}
}
