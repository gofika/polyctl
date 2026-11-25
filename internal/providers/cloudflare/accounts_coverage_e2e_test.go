package cloudflare_test

import (
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
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
