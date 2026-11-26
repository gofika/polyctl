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

// unbind takes the default account and the disabled accounts off the
// stored login of a profile: the login of credentials that could not list
// their accounts.
func (e *r2Env) unbind(profile string) {
	e.t.Helper()
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		e.t.Fatal(err)
	}
	meta := cfg.Profiles[profile].Platforms[platform.Cloudflare].Metadata
	delete(meta, "account_id")
	delete(meta, "account_name")
	delete(meta, "disabled_accounts")
	if err := cfg.Save(); err != nil {
		e.t.Fatal(err)
	}
}

// syncedUnbound is the profile "both" as a login without a default account
// whose inventory holds the zones and the records of acc1 and acc2.
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

// bothAccounts checks that the inventory of the profile "both" still holds
// what is of acc1 and of acc2, that its zone set is fresh, and that a name
// of a zone of acc2 is still routed to it.
func (e *r2Env) bothAccounts(what string) {
	e.t.Helper()
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-beta acc2") || !slices.Contains(got, "zone-ex acc1") {
		e.t.Errorf("%s: zones: %v", what, got)
	}
	if got, want := e.rows("both", platform.ResDNSRecord), []string{"rec-beta zone-beta", "rec-ex zone-ex"}; !reflect.DeepEqual(got, want) {
		e.t.Errorf("%s: records: %v", what, got)
	}
	e.f.reset()
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "both", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || !strings.Contains(stdout, "example.com") || e.f.count("GET /zones") != 0 {
		e.t.Errorf("%s: zone list: exit %d, %d listing(s), %s%s", what, code, e.f.count("GET /zones"), stdout, stderr)
	}
	if code, stdout, stderr = e.run("dns", "list", "example.net", "--profile", "both", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "192.0.2.2") {
		e.t.Errorf("%s: dns list of a zone of acc2: exit %d, %s%s", what, code, stdout, stderr)
	}
}

// A login without a default account that gets one, with account use or a
// new login, keeps working on every account its credentials see: nothing
// of its inventory is dropped, and nothing has to be synced again.
func TestDefaultAccountNarrowsNothing(t *testing.T) {
	t.Run("account use", func(t *testing.T) {
		e := syncedUnbound(t)
		if code, _, stderr := e.run("cloudflare", "account", "use", "acc1", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "acc1|Acme|" {
			t.Fatalf("account use: exit %d, %s, %s", code, e.stored("both"), stderr)
		}
		e.bothAccounts("account use")
	})
	t.Run("login", func(t *testing.T) {
		e := syncedUnbound(t)
		if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id=acc1"); code != cli.ExitOK || e.stored("both") != "acc1|Acme|" {
			t.Fatalf("login: exit %d, %s, %s", code, e.stored("both"), stderr)
		}
		e.bothAccounts("login")
	})
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

// A login without a default account that disables an account, with
// account disable or a new login, drops what its inventory holds of it:
// the neutral commands would otherwise keep routing the names of its
// zones to an account the login no longer works on.
func TestDisableOnALoginWithoutAnAccount(t *testing.T) {
	t.Run("account disable", func(t *testing.T) {
		e := syncedUnbound(t)
		if code, _, stderr := e.run("cloudflare", "account", "disable", "acc2", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "||acc2" {
			t.Fatalf("account disable: exit %d, %s, %s", code, e.stored("both"), stderr)
		}
		e.onlyAcc1("account disable")
	})
	t.Run("login", func(t *testing.T) {
		e := syncedUnbound(t)
		if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id=acc1", "--set", "disabled_accounts=acc2"); code != cli.ExitOK || e.stored("both") != "acc1|Acme|acc2" {
			t.Fatalf("login: exit %d, %s, %s", code, e.stored("both"), stderr)
		}
		e.onlyAcc1("login")
	})
}

// A login without a default account cannot disable every account its
// credentials list either: it would cover nothing. Nothing is stored and
// nothing of the inventory is dropped.
func TestDisableEveryAccountWithoutADefault(t *testing.T) {
	e := syncedUnbound(t)
	for _, args := range [][]string{{"acc1", "acc2"}, {"acc1", "acc2", "--default", "acc1"}} {
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "disable", "--profile", "both"}, args...)...)
		if code != cli.ExitUsage || !strings.Contains(stderr, "this would disable every account of cloudflare/both") || e.stored("both") != "||" {
			t.Errorf("disable %v: exit %d, %s, %s%s", args, code, e.stored("both"), stdout, stderr)
		}
	}
	// One after the other: the last one is refused.
	if code, _, stderr := e.run("cloudflare", "account", "disable", "acc2", "--profile", "both"); code != cli.ExitOK || e.stored("both") != "||acc2" {
		t.Fatalf("disable acc2: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	if code, _, stderr := e.run("cloudflare", "account", "disable", "acc1", "--profile", "both"); code != cli.ExitUsage ||
		!strings.Contains(stderr, "this would disable every account of cloudflare/both") || e.stored("both") != "||acc2" {
		t.Errorf("disable of the last account: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	if got := e.rows("both", platform.ResZone); !slices.Contains(got, "zone-ex acc1") {
		t.Errorf("zones: %v", got)
	}
}

// A new login that disables the account an earlier release stored rows for
// drops those rows too, although they have no parent: the neutral commands
// would otherwise keep routing the names of its zones to it.
func TestReloginDropsRowsWithoutAParent(t *testing.T) {
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "rec-ex", "www.example.com", "A", "192.0.2.1")
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.loginBoth("acc1", "acc2")
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

	if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", "both", "--set", "token=tok-both", "--set", "account_id=acc2", "--set", "disabled_accounts=acc1"); code != cli.ExitOK || e.stored("both") != "acc2|Beta|acc1" {
		t.Fatalf("login: exit %d, %s, %s", code, e.stored("both"), stderr)
	}
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResDNSRecord, platform.ResR2Bucket} {
		if got := e.rows("both", typ); len(got) != 0 {
			t.Errorf("%s rows of the account that was disabled: %v", typ, got)
		}
	}
	if got := e.domains("both"); slices.Contains(got, "example.com") {
		t.Errorf("domains: %v", got)
	}
	e.f.reset()
	if code, stdout, stderr := e.run("dns", "list", "example.com", "--profile", "both", "-o", "json"); code == cli.ExitOK || e.f.count("GET /zones/zone-ex/") != 0 {
		t.Errorf("dns list of a zone of the account that was disabled: exit %d, %s%s", code, stdout, stderr)
	}
}

// account disable and enable take the name of an account, also of one the
// profile knows no name of (no zone of it is cached, and it is not the
// default): the credentials are asked.
func TestAccountDisableByNameAsksTheCredentials(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...)
		return code, stdout + stderr
	}
	if code, out := acct("disable", "Gamma"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc3" || !strings.Contains(out, "disabled acc3 for cloudflare/all") {
		t.Fatalf("disable by name: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out := acct("disable", "acc1", "--default", "beta"); code != cli.ExitOK || e.stored("all") != "acc2|Beta|acc1,acc3" {
		t.Fatalf("disable with --default by name: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out := acct("enable", "acme"); code != cli.ExitOK || e.stored("all") != "acc2|Beta|acc3" || !strings.Contains(out, "enabled acc1 for cloudflare/all") {
		t.Fatalf("enable by name: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// A name no visible account carries is not found.
	if code, out := acct("disable", "Nobody"); code != cli.ExitNotFound || !strings.Contains(out, `account "Nobody" is not visible to the credentials of cloudflare/all`) {
		t.Errorf("disable of an unknown name: exit %d, %s", code, out)
	}
	// Credentials that fail do not keep a disabled account from being
	// enabled by id: the login names it. An account it does not name has
	// to be looked up, which fails, unless --offline says not to.
	delete(e.f.tokens, "tok-all")
	if code, out := acct("enable", "acc3"); code != cli.ExitOK || e.stored("all") != "acc2|Beta|" {
		t.Errorf("enable with failing credentials: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out := acct("disable", "acc1"); code != cli.ExitAuth || e.stored("all") != "acc2|Beta|" {
		t.Errorf("disable with failing credentials: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out := acct("disable", "acc1", "--offline"); code != cli.ExitOK || e.stored("all") != "acc2|Beta|acc1" {
		t.Errorf("disable --offline with failing credentials: exit %d, %s, %s", code, e.stored("all"), out)
	}
}

// An account listing that fails is an error of the command, not the sign
// of credentials that cannot list their accounts: nothing is taken
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
	for _, verb := range []string{"disable", "enable", "use"} {
		if code, out := acct(verb, "acc-typo"); code != cli.ExitError || strings.Contains(out, "was not checked") || e.stored("all") != "acc1|Acme|" {
			t.Errorf("account %s while the listing fails: exit %d, %s, %s", verb, code, e.stored("all"), out)
		}
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "Beta Inc")
	if code != cli.ExitError || strings.Contains(stderr, "cannot list accounts") {
		t.Errorf("--account while the listing fails: exit %d, %s%s", code, stdout, stderr)
	}
	// The bucket sync asks which accounts there are: it fails as a whole,
	// and the zones are synced all the same.
	e.f.accounts["acc1"].buckets = []string{"assets"}
	if code, stdout, stderr = e.run("sync", "--profile", "all", "--platform", "cloudflare"); code == cli.ExitOK || !strings.Contains(stdout+stderr, "list the accounts of cloudflare/all") {
		t.Errorf("sync while the listing fails: exit %d, %s%s", code, stdout, stderr)
	}
	if got := e.rows("all", platform.ResZone); !slices.Contains(got, "zone-gamma acc3") {
		t.Errorf("zones while the listing fails: %v", got)
	}
	// Credentials that are refused altogether are an authentication error.
	e.f.accountsStatus = 0
	delete(e.f.tokens, "tok-all")
	if code, out := acct("disable", "acc-typo"); code != cli.ExitAuth || e.stored("all") != "acc1|Acme|" {
		t.Errorf("account disable with refused credentials: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "Beta Inc"); code != cli.ExitAuth {
		t.Errorf("--account with refused credentials: exit %d, %s%s", code, stdout, stderr)
	}
}

// Credentials that may not list their accounts (a token without
// Account:Read) have them read off their zones: a name is one of an account
// with a zone, and an id that list does not hold is taken unchecked, which
// is said. That list does not tell every account, so it cannot say that
// every account would be disabled.
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
	if code, out := acct("disable", "Beta"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2" || strings.Contains(out, "was not checked") {
		t.Fatalf("disable by a name of the zones: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// An id the zones do not show may be an account without a zone.
	if code, out := acct("disable", "acc7"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2,acc7" ||
		!strings.Contains(out, "note: the credentials of cloudflare/all cannot list accounts: access to acc7 was not checked") {
		t.Fatalf("disable of an id that cannot be checked: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out := acct("use", "acc8"); code != cli.ExitOK || e.stored("all") != "acc8||acc2,acc7" ||
		!strings.Contains(out, "access to acc8 was not checked") {
		t.Fatalf("use of an id that cannot be checked: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// What cannot be an id is not found among the accounts of the zones.
	if code, out := acct("disable", "No Such Name"); code != cli.ExitNotFound || !strings.Contains(out, `account "No Such Name" is not visible to the credentials of cloudflare/all`) {
		t.Errorf("disable of an unknown name: exit %d, %s", code, out)
	}
	// The default account: --default names any account that is not
	// disabled; without it the accounts of the zones are the candidates.
	if code, out := acct("disable", "acc8"); code != cli.ExitUsage || !strings.Contains(out, "pass --default <id>") || !strings.Contains(out, "one of: acc1, acc3") {
		t.Errorf("disable of the default: exit %d, %s", code, out)
	}
	if code, out := acct("disable", "acc8", "--default", "acc2"); code != cli.ExitUsage || !strings.Contains(out, "not one of the accounts that stay enabled") {
		t.Errorf("--default of a disabled account: exit %d, %s", code, out)
	}
	if code, out := acct("disable", "acc8", "--default", "acc6"); code != cli.ExitOK || e.stored("all") != "acc6||acc2,acc7,acc8" {
		t.Fatalf("disable of the default with --default: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// Every account the zones show, and the default: the login may still
	// see others, so this is asked for a new default like any other.
	if code, out := acct("disable", "acc1", "acc3", "acc6"); code != cli.ExitUsage || strings.Contains(out, "would disable every account") || !strings.Contains(out, "pass --default <id>") {
		t.Errorf("disable of every account of the zones: exit %d, %s", code, out)
	}
	// --account: an account of the zones by its name, read live when it is
	// disabled.
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "Beta", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.net") || strings.Contains(stdout, "example.com") {
		t.Errorf("--account by a name of the zones: exit %d, %s%s", code, stdout, stderr)
	}
	if got := e.rows("all", platform.ResZone); slices.Contains(got, "zone-beta acc2") {
		t.Errorf("the zones of a disabled account were cached: %v", got)
	}
	// The zones of the enabled accounts are synced without the account
	// list.
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "all", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, "example.org") || !strings.Contains(stdout, "example.com") || strings.Contains(stdout, "example.net") {
		t.Errorf("zone list: exit %d, %s%s", code, stdout, stderr)
	}
}

// Enabling or disabling an account by its id asks Cloudflare nothing for
// the name of a default account that does not change, also when the login
// stored none and the credentials cannot list their accounts.
func TestAccountEnableAsksNothingForTheDefaultName(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	e.f.accountsStatus = http.StatusForbidden
	for _, args := range [][]string{{"use", "acc8"}, {"disable", "acc2"}} {
		if code, _, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...); code != cli.ExitOK {
			t.Fatalf("account %v: exit %d, %s", args, code, stderr)
		}
	}
	if e.stored("all") != "acc8||acc2" {
		t.Fatalf("stored %s", e.stored("all"))
	}
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "account", "enable", "acc2", "--profile", "all"); code != cli.ExitOK || e.stored("all") != "acc8||" || len(e.f.requests) != 0 {
		t.Errorf("enable: exit %d, %s, requests %v, %s", code, e.stored("all"), e.f.requests, stderr)
	}
}

// A token without Account:Read that sees zones is offered the accounts of
// those zones by enable on a terminal, and an id nobody can check counts
// as enabled already; the help of enable says so.
func TestAccountListOfCredentialsThatCannotListThem(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	e.f.accountsStatus = http.StatusForbidden
	p := prompttest.New(t, []string{"acc1", "acc3"})
	code, _, stderr := e.runPick(p, "cloudflare", "account", "enable", "--profile", "all")
	p.Done()
	if code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc2" {
		t.Fatalf("pick: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	if a := p.Asked[0]; a.Kind != "multi" || prompttest.Values(a.Options) != "acc1 acc2 acc3" || !strings.Contains(prompttest.Labels(a.Options), "Beta  acc2") {
		t.Errorf("offered %+v", a)
	}
	if code, _, stderr := e.run("cloudflare", "account", "enable", "acc9", "--profile", "all"); code != cli.ExitOK || !strings.Contains(stderr, "acc9: already enabled for cloudflare/all") {
		t.Errorf("enable of an id that cannot be checked: exit %d, %s", code, stderr)
	}
	_, stdout, stderr := e.run("cloudflare", "account", "enable", "--help")
	help := strings.Join(strings.Fields(stdout+stderr), " ")
	if strings.Contains(help, "and credentials that can list their accounts") || !strings.Contains(help, "are offered the accounts of their zones") {
		t.Errorf("help of account enable: %s", help)
	}
	// disable has no list: its help sends to the one of enable.
	_, stdout, stderr = e.run("cloudflare", "account", "disable", "--help")
	help = strings.Join(strings.Fields(stdout+stderr), " ")
	if strings.Contains(help, "are offered the accounts of their zones") || !strings.Contains(help, `run "polyctl cloudflare account enable" without arguments`) {
		t.Errorf("help of account disable: %s", help)
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
		!strings.Contains(stderr, "the token cannot list accounts") || e.stored("none") != "||" {
		t.Fatalf("login: exit %d, %s, %s", code, e.stored("none"), stderr)
	}
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "none"}, args...)...)
		return code, stdout + stderr
	}
	if code, out := acct("disable", "Delta Inc"); code != cli.ExitUsage || !strings.Contains(out, "the credentials of cloudflare/none cannot list accounts, so an account name cannot be looked up: pass the account id") {
		t.Errorf("disable by name: exit %d, %s", code, out)
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "list", "--profile", "none", "--account", "Delta Inc")
	if code != cli.ExitUsage || !strings.Contains(stderr, "--account: the credentials of cloudflare/none cannot list accounts, so an account name cannot be looked up: pass the account id") {
		t.Errorf("--account by name: exit %d, %s%s", code, stdout, stderr)
	}
	if code, stdout, stderr = e.run("cloudflare", "zone", "list", "--profile", "none", "--account", "acc4"); code != cli.ExitOK {
		t.Errorf("--account by id: exit %d, %s%s", code, stdout, stderr)
	}
	// A new zone needs its account named: there is none to default to, and
	// none can be listed to choose from.
	e.f.reset()
	if code, _, stderr = e.run("cloudflare", "zone", "create", "new.example", "--profile", "none", "--dry-run"); code != cli.ExitAuth ||
		!strings.Contains(stderr, "profile none has no default account and its accounts cannot be listed (pass --account <id>)") || len(e.f.writes()) != 0 {
		t.Errorf("zone create without an account: exit %d, %s", code, stderr)
	}
	p := prompttest.New(t)
	if code, _, stderr = e.runPick(p, "cloudflare", "zone", "create", "new.example", "--profile", "none", "--dry-run"); code != cli.ExitAuth {
		t.Errorf("zone create without an account on a terminal: exit %d, %s", code, stderr)
	}
	p.Done()
	p = prompttest.New(t)
	if code, _, stderr = e.runPick(p, "cloudflare", "account", "use", "--profile", "none"); code != cli.ExitUsage ||
		!strings.Contains(stderr, "the credentials of cloudflare/none cannot list accounts: pass the account id") {
		t.Errorf("use on a terminal: exit %d, %s", code, stderr)
	}
	p.Done()
	if code, out := acct("use", "acc4"); code != cli.ExitOK || e.stored("none") != "acc4||" ||
		!strings.Contains(out, "note: the credentials of cloudflare/none cannot list accounts: access to acc4 was not checked") {
		t.Errorf("use by id: exit %d, %s, %s", code, e.stored("none"), out)
	}
	// An account is disabled by its id, unchecked; the default account
	// needs --default, since no other account can be told.
	if code, out := acct("disable", "acc5"); code != cli.ExitOK || e.stored("none") != "acc4||acc5" || !strings.Contains(out, "access to acc5 was not checked") {
		t.Errorf("disable by id: exit %d, %s, %s", code, e.stored("none"), out)
	}
	if code, out := acct("disable", "acc4"); code != cli.ExitUsage || !strings.Contains(out, "acc4 is the default account of cloudflare/none: pass --default <id> to name the one that replaces it") {
		t.Errorf("disable of the default: exit %d, %s", code, out)
	}
	if code, out := acct("disable", "acc4", "--default", "acc6"); code != cli.ExitOK || e.stored("none") != "acc6||acc4,acc5" {
		t.Errorf("disable of the default with --default: exit %d, %s, %s", code, e.stored("none"), out)
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

// A name two visible accounts carry is ambiguous in account use, disable
// and enable (exit code 5), also when one of them is the default account,
// whose name the profile knows; the id chooses.
func TestAccountNameOfTwoAccounts(t *testing.T) {
	e := newR2Env(t)
	e.loginAll()
	e.f.accounts["acc3"].name = "Acme"
	acct := func(args ...string) (int, string) {
		t.Helper()
		code, stdout, stderr := e.run(append([]string{"cloudflare", "account", "--profile", "all"}, args...)...)
		return code, stdout + stderr
	}
	for _, verb := range []string{"disable", "use", "enable"} {
		code, out := acct(verb, "acme")
		if code != cli.ExitAmbiguous || !strings.Contains(out, "Acme (acc1)") || !strings.Contains(out, "Acme (acc3)") || !strings.Contains(out, "pass the account id to choose") || e.stored("all") != "acc1|Acme|" {
			t.Errorf("account %s by a name of two accounts: exit %d, %s, %s", verb, code, e.stored("all"), out)
		}
	}
	if code, out := acct("disable", "acc3"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc3" {
		t.Fatalf("disable by id: exit %d, %s, %s", code, e.stored("all"), out)
	}
	// The name is still that of two accounts the credentials see.
	if code, out := acct("enable", "Acme"); code != cli.ExitAmbiguous || e.stored("all") != "acc1|Acme|acc3" {
		t.Errorf("enable by a name of two accounts: exit %d, %s, %s", code, e.stored("all"), out)
	}
	if code, out := acct("enable", "acc3"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|" {
		t.Errorf("enable by id: exit %d, %s, %s", code, e.stored("all"), out)
	}

	// On a terminal the accounts of the name are a list to choose from, in
	// the account commands and for --account.
	asked := func(p *prompttest.Picker) {
		t.Helper()
		a := p.Find(`Ambiguous account "acme"; use which one?`)
		if a == nil || prompttest.Values(a.Options) != "acc1 acc3" || !strings.Contains(prompttest.Labels(a.Options), "Acme  acc3") {
			t.Errorf("questions asked: %v", p.Titles())
		}
		p.Done()
	}
	p := prompttest.New(t, "acc3")
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "--profile", "all", "disable", "acme"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|acc3" {
		t.Errorf("disable picked on a terminal: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	asked(p)
	p = prompttest.New(t, "acc3")
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "--profile", "all", "enable", "acme"); code != cli.ExitOK || e.stored("all") != "acc1|Acme|" {
		t.Errorf("enable picked on a terminal: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	asked(p)
	p = prompttest.New(t, "acc3")
	if code, _, stderr := e.runPick(p, "cloudflare", "account", "--profile", "all", "use", "acme"); code != cli.ExitOK || !strings.HasPrefix(e.stored("all"), "acc3|") {
		t.Errorf("use picked on a terminal: exit %d, %s, %s", code, e.stored("all"), stderr)
	}
	asked(p)
	// --account: a name the profile does not know is looked up among the
	// visible accounts.
	e.f.accounts["acc2"].name = "Twin"
	e.f.accounts["acc3"].name = "Twin"
	p = prompttest.New(t, "acc2")
	if code, stdout, stderr := e.runPick(p, "cloudflare", "zone", "list", "--profile", "all", "--account", "twin", "-o", "json"); code != cli.ExitOK {
		t.Errorf("--account picked on a terminal: exit %d, %s%s", code, stdout, stderr)
	}
	if a := p.Find(`Ambiguous account "twin"; use which one?`); a == nil || prompttest.Values(a.Options) != "acc2 acc3" {
		t.Errorf("questions asked: %v", p.Titles())
	}
	p.Done()
	if code, _, stderr := e.run("cloudflare", "zone", "list", "--profile", "all", "--account", "twin"); code != cli.ExitAmbiguous || !strings.Contains(stderr, "pass the account id to choose") {
		t.Errorf("--account, non-interactive: exit %d, %s", code, stderr)
	}
}

// After an account was enabled, the commands that find their zone through
// the inventory (zone delete, zone setting, the rules) sync the due zone
// set before they answer, as the others do: a zone of the same name in the
// account that was enabled makes the name ambiguous (exit code 5) instead
// of the command acting on the one zone the stale inventory knows.
func TestRoutedZoneAfterAccountEnable(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1", "acc2")
	if code, _, stderr := e.run("sync", "--profile", "both", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	e.f.zones = append(e.f.zones, r2Zone{"zone-dup", "example.com", "pending", "acc2"})
	if code, _, stderr := e.run("cloudflare", "account", "enable", "acc2", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("enable: exit %d, %s", code, stderr)
	}
	e.f.reset()
	code, stdout, stderr := e.run("cloudflare", "zone", "delete", "example.com", "--profile", "both", "--yes")
	if code != cli.ExitAmbiguous || !strings.Contains(stderr, "zone-dup") || !strings.Contains(stderr, "zone-ex") || !strings.Contains(stderr, "--account <id or name>") {
		t.Errorf("zone delete: exit %d, %s%s", code, stdout, stderr)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("zone delete wrote %v", w)
	}
	// A fresh set is not synced again.
	e.f.reset()
	if code, _, stderr = e.run("cloudflare", "zone", "delete", "example.net", "--profile", "both", "--dry-run"); code != cli.ExitOK || e.f.count("GET /zones?") != 0 {
		t.Errorf("zone delete of a fresh set: exit %d, %d listing(s), %s", code, e.f.count("GET /zones?"), stderr)
	}
}

// One zone seen through two logins has one id: only --profile chooses, and
// the hint does not offer the zone id, which would be ambiguous again.
// Disabling its account in one of the logins leaves the other.
func TestRoutedZoneOfTwoLoginsIsNotChosenByItsID(t *testing.T) {
	e := newR2Env(t)
	e.loginBoth("acc1")
	if code, _, stderr := e.run("sync", "--platform", "cloudflare"); code != cli.ExitOK {
		t.Fatalf("sync: exit %d, %s", code, stderr)
	}
	for _, ref := range []string{"example.net", "zone-beta"} {
		code, _, stderr := e.run("cloudflare", "zone", "delete", ref, "--yes")
		if code != cli.ExitAmbiguous || !strings.Contains(stderr, "cloudflare/beta") || !strings.Contains(stderr, "cloudflare/both") ||
			!strings.Contains(stderr, "pass --profile <name> to choose") || strings.Contains(stderr, "zone id") {
			t.Errorf("zone delete %s: exit %d, %s", ref, code, stderr)
		}
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("wrote %v", w)
	}
	if code, _, stderr := e.run("cloudflare", "account", "disable", "acc2", "--profile", "both"); code != cli.ExitOK {
		t.Fatalf("disable: exit %d, %s", code, stderr)
	}
	for _, ref := range []string{"example.net", "zone-beta"} {
		if code, stdout, stderr := e.run("cloudflare", "zone", "delete", ref, "--dry-run", "-o", "json"); code != cli.ExitOK || !strings.Contains(stdout, `"profile": "beta"`) {
			t.Errorf("zone delete %s after the disable: exit %d, %s%s", ref, code, stdout, stderr)
		}
	}
	if e.stored("beta") != "acc2|Beta|" {
		t.Errorf("the other login: %s", e.stored("beta"))
	}
}
