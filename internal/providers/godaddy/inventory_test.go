package godaddy

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// GoDaddy creates the same apex NS records for every domain. Their ids
// carry the zone, so the cache keeps one row per domain through a full
// sync and a later refresh of one zone.
func TestSameRecordInTwoZonesKeepsTwoCachedRows(t *testing.T) {
	f, c := newTestClient(t)
	for _, d := range []string{"a.com", "b.com"} {
		f.addDomain(d)
		f.setRecords(d, apiRecord{Type: "NS", Name: "@", Data: "ns51.domaincontrol.com", TTL: 3600})
	}
	ctx := context.Background()
	db, err := inventory.Open(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	all, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil {
		t.Fatal(err)
	}
	full := inventory.Set{Platform: platform.GoDaddy, Profile: "p", Type: platform.ResDNSRecord}
	if err := db.Replace(ctx, full, all, time.Hour); err != nil {
		t.Fatal(err)
	}
	count := func(zone string) int {
		rows, err := db.List(ctx, inventory.Query{Platform: platform.GoDaddy, Type: platform.ResDNSRecord, ParentID: zone})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if count("a.com") != 1 || count("b.com") != 1 {
		t.Fatalf("after a full sync: a.com %d, b.com %d rows", count("a.com"), count("b.com"))
	}
	recs, err := c.ListRecords(ctx, "a.com")
	if err != nil {
		t.Fatal(err)
	}
	scope := full
	scope.Scope = "a.com"
	if err := db.Replace(ctx, scope, app.RecordResources("a.com", "a.com", recs), time.Hour); err != nil {
		t.Fatal(err)
	}
	if count("a.com") != 1 || count("b.com") != 1 {
		t.Fatalf("after refreshing a.com: a.com %d, b.com %d rows", count("a.com"), count("b.com"))
	}
}
