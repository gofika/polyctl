package cli

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// After the cached sets of an account were marked due (an upgrade, a login
// or an enable / disable / use that changed what the account covers), the
// commands that route by domain index them before the lookup: a zone the
// account covers since then is routed without --refresh. --offline makes
// no request and keeps its message, and the next online run indexes.
func TestRoutingIndexesSetsMarkedDue(t *testing.T) {
	dir, cfgPath := setup(t, true)
	old := platform.Zone{ID: "z1", Name: "example.com"}
	added := platform.Zone{ID: "z2", Name: "newlycovered.io"}
	seed(t, dir, []platform.Zone{old}, nil)
	fc := client("a")
	fc.zones = []platform.Zone{old, added}
	fc.records = map[string][]platform.Record{"z2": {{ID: "r1", Name: "www.newlycovered.io", Type: "A", Value: "192.0.2.1"}}}

	// A set that is fresh, or past its TTL, is not indexed by a miss.
	if _, _, err := run(t, cfgPath, "dns", "list", "newlycovered.io"); ExitCodeFor(err) != ExitNotFound {
		t.Fatalf("before the mark = %v", err)
	}
	if n := fc.count("Sync"); n != 0 {
		t.Fatalf("a miss synced %d times", n)
	}

	db := openInventory(t, dir)
	zoneSet := inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResZone}
	if err := db.Replace(context.Background(), zoneSet, app.ZoneResources([]platform.Zone{old}), -time.Hour); err != nil {
		t.Fatal(err)
	}
	if st, err := db.GetState(context.Background(), zoneSet); err != nil || st.Fresh(time.Now()) || app.ForcedDue(st) {
		t.Fatalf("state = %+v, %v; want past its TTL", st, err)
	}
	db.Close()
	if _, stderr, err := run(t, cfgPath, "dns", "list", "newlycovered.io"); ExitCodeFor(err) != ExitNotFound || strings.Contains(stderr, "indexing") {
		t.Fatalf("past the TTL = %v (%s)", err, stderr)
	}
	if n := fc.count("Sync"); n != 0 {
		t.Fatalf("a miss in a set past its TTL synced %d times", n)
	}

	db = openInventory(t, dir)
	if err := db.Expire(context.Background(), fakePlatform, "a"); err != nil {
		t.Fatal(err)
	}
	db.Close()

	_, stderr, err := run(t, cfgPath, "dns", "list", "newlycovered.io", "--offline")
	if ExitCodeFor(err) != ExitNotFound || !strings.Contains(err.Error(), "when online") || strings.Contains(stderr, "indexing") {
		t.Fatalf("offline = %v (%s)", err, stderr)
	}
	if n := len(fc.calls); n != 0 {
		t.Fatalf("--offline reached the platform: %v", fc.calls)
	}

	out, stderr, err := run(t, cfgPath, "dns", "list", "newlycovered.io", "-o", "json")
	if err != nil || !strings.Contains(out, "www.newlycovered.io") {
		t.Fatalf("dns list = %q, %v (%s)", out, err, stderr)
	}
	if !strings.Contains(stderr, "whose cached inventory was marked due") {
		t.Errorf("stderr = %q", stderr)
	}
	if n := fc.count("Sync:zone"); n != 1 {
		t.Errorf("zone sync count = %d, want 1", n)
	}
	// The set is fresh again: the next run asks nobody.
	if _, _, err := run(t, cfgPath, "dns", "list", "nosuch.org"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("unknown domain = %v", err)
	}
	if n := fc.count("Sync:zone"); n != 1 {
		t.Errorf("zone sync count after a second run = %d, want 1", n)
	}
}

// domain which indexes the sets marked due before it reads the index, so
// that it lists the owner an account covers since then.
func TestDomainWhichIndexesSetsMarkedDue(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	zones := []platform.Zone{{ID: "z1", Name: "example.com"}}
	seed(t, dir, zones, nil)
	db := openInventory(t, dir)
	if err := db.Expire(context.Background(), fakePlatform, "a"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	client("a").zones = []platform.Zone{{ID: "z1", Name: "example.com"}, {ID: "z2", Name: "example.com"}}

	out, stderr, err := run(t, cfgPath, "domain", "which", "example.com", "-o", "json")
	if err != nil || !strings.Contains(out, `"resource_id": "z2"`) {
		t.Fatalf("which = %q, %v (%s)", out, err, stderr)
	}
	// The accounts that were never indexed are not swept for it.
	if n := clientOn("b", fakePlatform2).count("Sync"); n != 0 {
		t.Errorf("an account without a set marked due synced %d times", n)
	}
}

// domain which --refresh indexes before it reads the index, as routing
// does, also when the index already holds the domain: the flag does not
// leave a set marked due unread, and each account is asked once.
func TestDomainWhichRefreshIndexesSetsMarkedDue(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)
	db := openInventory(t, dir)
	if err := db.Expire(context.Background(), fakePlatform, "a"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	client("a").zones = []platform.Zone{{ID: "z1", Name: "example.com"}, {ID: "z2", Name: "example.com"}}

	out, stderr, err := run(t, cfgPath, "domain", "which", "example.com", "--refresh", "-o", "json")
	if err != nil || !strings.Contains(out, `"resource_id": "z2"`) {
		t.Fatalf("which --refresh = %q, %v (%s)", out, err, stderr)
	}
	if n := client("a").count("Sync:zone"); n != 1 {
		t.Errorf("zone sync count = %d, want 1", n)
	}
}
