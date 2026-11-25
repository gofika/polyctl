package cli

import (
	"context"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// A re-login that changes what the account covers (the projects of a Google
// Cloud account that are not disabled) drops the rows cached for what it no longer
// covers at once, with their domain index, and makes the cached sets due:
// a set that is still fresh must not keep routing a domain to a zone the
// account was taken off. A re-login that changes nothing leaves the cache.
func TestReloginForgetsWhatTheAccountNoLongerCovers(t *testing.T) {
	dir, cfgPath := setup(t, true)
	fakeMu.Lock()
	fakeCoverage = true
	fakeMu.Unlock()
	ctx := context.Background()
	set := inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResZone}
	seedZones := func() {
		t.Helper()
		db := openInventory(t, dir)
		defer db.Close()
		if err := db.Replace(ctx, set, []platform.Resource{
			{Type: platform.ResZone, ID: "acct-a/z1", Name: "old.example", ParentID: "acct-a", Domain: "old.example"},
			{Type: platform.ResZone, ID: "acct-a/r/z2", Name: "deep.example", ParentID: "acct-a/r", Domain: "deep.example"},
			{Type: platform.ResZone, ID: "acct-ab/z3", Name: "kept.example", ParentID: "acct-ab", Domain: "kept.example"},
		}, time.Hour); err != nil {
			t.Fatal(err)
		}
	}
	state := func() (ids string, domains string, fresh bool) {
		t.Helper()
		db := openInventory(t, dir)
		defer db.Close()
		rows, err := db.List(ctx, inventory.Query{Platform: fakePlatform, Profile: "a"})
		if err != nil {
			t.Fatal(err)
		}
		var got []string
		for _, r := range rows {
			got = append(got, r.ID)
		}
		sort.Strings(got)
		idx, err := db.IndexEntries(ctx)
		if err != nil {
			t.Fatal(err)
		}
		var doms []string
		for _, e := range idx {
			doms = append(doms, e.Domain)
		}
		sort.Strings(doms)
		st, err := db.GetState(ctx, set)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(got, " "), strings.Join(doms, " "), st != nil && st.ExpiresAt.After(time.Now())
	}

	// The same account again: nothing is touched.
	seedZones()
	if code, _, stderr := mainRun(cfgPath, "auth", "login", p1, "--profile", "a"); code != ExitOK {
		t.Fatalf("re-login: exit %d (%s)", code, stderr)
	}
	if ids, doms, fresh := state(); ids != "acct-a/r/z2 acct-a/z1 acct-ab/z3" || doms != "deep.example kept.example old.example" || !fresh {
		t.Fatalf("unchanged re-login: rows %q, domains %q, fresh %v", ids, doms, fresh)
	}

	// Another account: the tree of the old one goes, the set is due.
	if code, _, stderr := mainRun(cfgPath, "auth", "login", p1, "--profile", "a", "--set", "account=acct-b"); code != ExitOK {
		t.Fatalf("re-login: exit %d (%s)", code, stderr)
	}
	if ids, doms, fresh := state(); ids != "acct-ab/z3" || doms != "kept.example" || fresh {
		t.Errorf("after the change: rows %q, domains %q, fresh %v; want only acct-ab/z3, its domain, and a due set", ids, doms, fresh)
	}
}
