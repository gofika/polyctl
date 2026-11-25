package cloudflare_test

import (
	"context"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
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
