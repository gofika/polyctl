package inventory_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

var ctx = context.Background()

func openDB(t *testing.T) (*inventory.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.db")
	db, err := inventory.Open(path)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, path
}

func zoneRes(id, name string) platform.Resource {
	n := platform.NormalizeDomain(name)
	return platform.Resource{Type: platform.ResZone, ID: id, Name: n, Domain: n, Data: platform.Zone{ID: id, Name: n}}
}

func domainRes(name string) platform.Resource {
	n := platform.NormalizeDomain(name)
	return platform.Resource{Type: platform.ResDomain, ID: n, Name: n, Domain: n, Data: platform.Domain{Name: n}}
}

func recRes(id, zoneID, zoneName, name, content string) platform.Resource {
	r := platform.Record{ID: id, ZoneID: zoneID, Name: name, Type: "A", Value: content, TTL: 300}
	return platform.Resource{Type: platform.ResDNSRecord, ID: id, Name: name, ParentID: zoneID, Domain: zoneName, Data: r}
}

func set(profile string, rt platform.ResourceType) inventory.Set {
	return inventory.Set{Platform: platform.NameCom, Profile: profile, Type: rt}
}

func scoped(profile string, rt platform.ResourceType, scope string) inventory.Set {
	s := set(profile, rt)
	s.Scope = scope
	return s
}

func mustReplace(t *testing.T, db *inventory.DB, s inventory.Set, ttl time.Duration, rs ...platform.Resource) {
	t.Helper()
	if err := db.Replace(ctx, s, rs, ttl); err != nil {
		t.Fatalf("Replace %+v: %v", s, err)
	}
}

func mustList(t *testing.T, db *inventory.DB, q inventory.Query) []inventory.Resource {
	t.Helper()
	rows, err := db.List(ctx, q)
	if err != nil {
		t.Fatalf("List %+v: %v", q, err)
	}
	return rows
}

func names(rows []inventory.Resource) []string {
	out := make([]string, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.Name)
	}
	return out
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func TestOpenCreatesSchema(t *testing.T) {
	db, path := openDB(t)
	// A fresh database is empty but queryable.
	if rows := mustList(t, db, inventory.Query{}); len(rows) != 0 {
		t.Fatalf("fresh db has %d rows", len(rows))
	}
	stats, err := db.Stats(ctx)
	if err != nil || len(stats) != 0 {
		t.Fatalf("Stats on fresh db = %v, %v", stats, err)
	}
	if st, err := db.GetState(ctx, set("a", platform.ResZone)); err != nil || st != nil {
		t.Fatalf("GetState on fresh db = %v, %v; want nil, nil", st, err)
	}
	if st := (*inventory.State)(nil); st.Fresh(time.Now()) {
		t.Fatal("nil State must not be fresh")
	}

	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	rows, err := raw.Query(`SELECT name FROM sqlite_master WHERE type='table'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	tables := map[string]bool{}
	for rows.Next() {
		var n string
		if err := rows.Scan(&n); err != nil {
			t.Fatal(err)
		}
		tables[n] = true
	}
	for _, want := range []string{"resources", "domain_index", "sync_state"} {
		if !tables[want] {
			t.Errorf("table %q missing; have %v", want, tables)
		}
	}

	// Opening twice is idempotent (CREATE IF NOT EXISTS).
	again, err := inventory.Open(path)
	if err != nil {
		t.Fatalf("second Open: %v", err)
	}
	_ = again.Close()
}

func TestReplaceUnscopedThenList(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z2", "Other.COM."), zoneRes("z1", "example.com"))

	rows := mustList(t, db, inventory.Query{Platform: platform.NameCom, Profile: "a", Type: platform.ResZone})
	if got := names(rows); !equalStrings(got, []string{"example.com", "other.com"}) {
		t.Fatalf("List = %v, want sorted by name", got)
	}
	r := rows[1]
	if r.Platform != platform.NameCom || r.Profile != "a" || r.Type != platform.ResZone || r.ID != "z2" || r.Domain != "other.com" {
		t.Errorf("row = %+v", r)
	}
	var z platform.Zone
	if err := r.Decode(&z); err != nil || z.ID != "z2" || z.Name != "other.com" {
		t.Errorf("Decode = %+v, %v", z, err)
	}
	if r.UpdatedAt.IsZero() || !r.ExpiresAt.After(r.UpdatedAt) {
		t.Errorf("timestamps: updated %v expires %v", r.UpdatedAt, r.ExpiresAt)
	}

	// Filters by domain and name.
	if got := mustList(t, db, inventory.Query{Domain: "EXAMPLE.com"}); len(got) != 1 || got[0].ID != "z1" {
		t.Errorf("List by domain = %+v", got)
	}
	if got := mustList(t, db, inventory.Query{Name: "other.com"}); len(got) != 1 || got[0].ID != "z2" {
		t.Errorf("List by name = %+v", got)
	}
	if got := mustList(t, db, inventory.Query{Profile: "b"}); len(got) != 0 {
		t.Errorf("List other profile = %+v", got)
	}

	// Replacing again drops rows that disappeared upstream.
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z2", "other.com"))
	rows = mustList(t, db, inventory.Query{Profile: "a", Type: platform.ResZone})
	if got := names(rows); !equalStrings(got, []string{"other.com"}) {
		t.Fatalf("after second Replace List = %v", got)
	}
	entries, err := db.LookupDomain(ctx, []string{"example.com"}, "")
	if err != nil || len(entries) != 0 {
		t.Fatalf("stale index entry survived Replace: %v, %v", entries, err)
	}

	// Get finds by id and reports ErrNotFound otherwise.
	if got, err := db.Get(ctx, set("a", platform.ResZone), platform.ResZone, "z2"); err != nil || got.Name != "other.com" {
		t.Errorf("Get = %+v, %v", got, err)
	}
	if _, err := db.Get(ctx, set("a", platform.ResZone), platform.ResZone, "z1"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Get(missing) = %v, want ErrNotFound", err)
	}

	// An empty replace is allowed and keeps the sync state.
	mustReplace(t, db, set("a", platform.ResZone), time.Hour)
	if got := mustList(t, db, inventory.Query{Profile: "a"}); len(got) != 0 {
		t.Errorf("empty Replace left rows: %+v", got)
	}
	if st, err := db.GetState(ctx, set("a", platform.ResZone)); err != nil || st == nil {
		t.Errorf("state after empty Replace = %v, %v", st, err)
	}
}

func TestReplaceScopedOnlyTouchesThatZone(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour,
		recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"),
		recRes("r2", "z2", "other.com", "api.other.com", "2.2.2.2"),
	)
	mustReplace(t, db, scoped("a", platform.ResDNSRecord, "z1"), time.Hour,
		recRes("r3", "z1", "example.com", "mail.example.com", "3.3.3.3"),
	)

	z1 := mustList(t, db, inventory.Query{Profile: "a", Type: platform.ResDNSRecord, ParentID: "z1"})
	if got := names(z1); !equalStrings(got, []string{"mail.example.com"}) {
		t.Errorf("zone z1 records = %v, want only the scoped replacement", got)
	}
	z2 := mustList(t, db, inventory.Query{Profile: "a", Type: platform.ResDNSRecord, ParentID: "z2"})
	if got := names(z2); !equalStrings(got, []string{"api.other.com"}) {
		t.Errorf("zone z2 records = %v, must be untouched by a z1 scoped replace", got)
	}
	// The unscoped state and the other zone's state survive; z1's is refreshed.
	for _, scope := range []string{"", "z1", "z2"} {
		st, err := db.GetState(ctx, scoped("a", platform.ResDNSRecord, scope))
		if err != nil || st == nil {
			t.Errorf("state for scope %q = %v, %v", scope, st, err)
		}
	}
	// A scoped replace of another profile does not leak across profiles.
	mustReplace(t, db, scoped("b", platform.ResDNSRecord, "z1"), time.Hour,
		recRes("r9", "z1", "example.com", "b.example.com", "9.9.9.9"),
	)
	if got := names(mustList(t, db, inventory.Query{Profile: "a", Type: platform.ResDNSRecord, ParentID: "z1"})); !equalStrings(got, []string{"mail.example.com"}) {
		t.Errorf("profile a records changed by a profile b replace: %v", got)
	}
}

func TestUnscopedSyncMarksEveryScopeFresh(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour,
		recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"),
		recRes("r2", "z1", "example.com", "ftp.example.com", "1.1.1.2"),
		recRes("r3", "z2", "other.com", "api.other.com", "2.2.2.2"),
	)
	now := time.Now()
	for _, scope := range []string{"", "z1", "z2"} {
		st, err := db.GetState(ctx, scoped("a", platform.ResDNSRecord, scope))
		if err != nil {
			t.Fatal(err)
		}
		if !st.Fresh(now) {
			t.Errorf("scope %q must be fresh right after an unscoped sync: %+v", scope, st)
		}
	}
	if st, err := db.GetState(ctx, scoped("a", platform.ResDNSRecord, "z9")); err != nil || st != nil {
		t.Errorf("unknown scope state = %v, %v; want nil", st, err)
	}
	if st, err := db.GetState(ctx, scoped("b", platform.ResDNSRecord, "z1")); err != nil || st != nil {
		t.Errorf("other profile scope state = %v, %v; want nil", st, err)
	}

	// A later unscoped sync that no longer contains z2 clears its scope state.
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour,
		recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"),
	)
	if st, err := db.GetState(ctx, scoped("a", platform.ResDNSRecord, "z2")); err != nil || st != nil {
		t.Errorf("z2 scope state should be cleared by the unscoped resync: %v, %v", st, err)
	}
	if st, err := db.GetState(ctx, scoped("a", platform.ResDNSRecord, "z1")); err != nil || st == nil {
		t.Errorf("z1 scope state missing after resync: %v, %v", st, err)
	}
}

func TestUpsertAndDelete(t *testing.T) {
	db, _ := openDB(t)
	s := set("a", platform.ResZone)
	if err := db.Upsert(ctx, s, zoneRes("z1", "Example.com"), time.Hour); err != nil {
		t.Fatalf("Upsert: %v", err)
	}
	rows := mustList(t, db, inventory.Query{Profile: "a"})
	if len(rows) != 1 || rows[0].ID != "z1" || rows[0].Domain != "example.com" {
		t.Fatalf("after Upsert List = %+v", rows)
	}
	entries, err := db.LookupDomain(ctx, []string{"example.com"}, platform.ResZone)
	if err != nil || len(entries) != 1 || entries[0].ResourceID != "z1" {
		t.Fatalf("Upsert did not index the domain: %v, %v", entries, err)
	}
	// Upsert never touches sync state.
	if st, err := db.GetState(ctx, s); err != nil || st != nil {
		t.Errorf("Upsert must not create sync state: %v, %v", st, err)
	}

	// Upserting the same id replaces the row.
	if err := db.Upsert(ctx, s, zoneRes("z1", "renamed.com"), time.Hour); err != nil {
		t.Fatal(err)
	}
	rows = mustList(t, db, inventory.Query{Profile: "a"})
	if len(rows) != 1 || rows[0].Name != "renamed.com" {
		t.Fatalf("after second Upsert List = %+v", rows)
	}

	// A record upsert populates resources but not the domain index.
	if err := db.Upsert(ctx, set("a", platform.ResDNSRecord), recRes("r1", "z1", "renamed.com", "www.renamed.com", "1.1.1.1"), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := mustList(t, db, inventory.Query{Type: platform.ResDNSRecord}); len(got) != 1 || got[0].ParentID != "z1" {
		t.Errorf("record upsert = %+v", got)
	}
	if entries, _ := db.LookupDomain(ctx, []string{"renamed.com"}, platform.ResDNSRecord); len(entries) != 0 {
		t.Errorf("records must not appear in the domain index: %v", entries)
	}

	if err := db.Delete(ctx, s, platform.ResZone, "z1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if got := mustList(t, db, inventory.Query{Type: platform.ResZone}); len(got) != 0 {
		t.Errorf("zone still listed after Delete: %+v", got)
	}
	if entries, _ := db.LookupDomain(ctx, []string{"renamed.com"}, ""); len(entries) != 0 {
		t.Errorf("index entry survived Delete: %v", entries)
	}
	if got := mustList(t, db, inventory.Query{Type: platform.ResDNSRecord}); len(got) != 1 {
		t.Errorf("Delete removed an unrelated record: %+v", got)
	}
	// Deleting something that does not exist is not an error.
	if err := db.Delete(ctx, s, platform.ResZone, "nope"); err != nil {
		t.Errorf("Delete(missing) = %v", err)
	}
}

func TestLookupDomainOrderingAndTypeFilter(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z1", "example.com"))
	mustReplace(t, db, set("b", platform.ResZone), time.Hour, zoneRes("z2", "sub.example.com"))
	mustReplace(t, db, set("a", platform.ResDomain), time.Hour, domainRes("example.com"))

	cands := platform.Candidates("www.sub.example.com")
	entries, err := db.LookupDomain(ctx, cands, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 3 {
		t.Fatalf("LookupDomain = %+v, want 3 entries", entries)
	}
	if entries[0].Domain != "sub.example.com" || entries[0].Profile != "b" || entries[0].Type != platform.ResZone || entries[0].ResourceID != "z2" {
		t.Errorf("longest match must come first: %+v", entries[0])
	}
	for _, e := range entries[1:] {
		if e.Domain != "example.com" || e.Profile != "a" {
			t.Errorf("unexpected entry %+v", e)
		}
	}

	zones, err := db.LookupDomain(ctx, cands, platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].ResourceID != "z2" || zones[1].ResourceID != "z1" {
		t.Errorf("zone filter = %+v", zones)
	}
	domains, err := db.LookupDomain(ctx, cands, platform.ResDomain)
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 1 || domains[0].Type != platform.ResDomain || domains[0].ResourceID != "example.com" {
		t.Errorf("domain filter = %+v", domains)
	}

	// Lookups are exact matches on the given candidates, case-insensitive.
	if got, _ := db.LookupDomain(ctx, []string{"EXAMPLE.COM."}, platform.ResZone); len(got) != 1 {
		t.Errorf("case-insensitive lookup = %+v", got)
	}
	if got, _ := db.LookupDomain(ctx, []string{"www.sub.example.com"}, ""); len(got) != 0 {
		t.Errorf("non-indexed name must not match: %+v", got)
	}
	if got, err := db.LookupDomain(ctx, nil, ""); err != nil || got != nil {
		t.Errorf("empty candidates = %v, %v", got, err)
	}

	all, err := db.IndexEntries(ctx)
	if err != nil || len(all) != 3 {
		t.Fatalf("IndexEntries = %+v, %v", all, err)
	}
	if all[0].Domain != "example.com" || all[2].Domain != "sub.example.com" {
		t.Errorf("IndexEntries must be ordered by domain: %+v", all)
	}
}

func TestDomainIndexExcludesRecords(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour,
		recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"),
		recRes("r2", "z1", "example.com", "example.com", "1.1.1.2"),
	)
	entries, err := db.IndexEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 0 {
		t.Fatalf("dns_record rows must not be indexed: %+v", entries)
	}
	// They are still stored under their zone domain for filtering.
	if got := mustList(t, db, inventory.Query{Domain: "example.com"}); len(got) != 2 {
		t.Errorf("records stored with domain = %+v", got)
	}
	// Zones without a domain are stored but not indexed either.
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, platform.Resource{Type: platform.ResZone, ID: "z0", Name: "nodomain", Data: nil})
	if entries, _ := db.IndexEntries(ctx); len(entries) != 0 {
		t.Errorf("resource without Domain must not be indexed: %+v", entries)
	}
}

func TestPurge(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z1", "example.com"))
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour, recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"))
	mustReplace(t, db, set("b", platform.ResZone), time.Hour, zoneRes("z2", "other.com"))

	if err := db.Purge(ctx, platform.NameCom, "a"); err != nil {
		t.Fatalf("Purge: %v", err)
	}
	if got := mustList(t, db, inventory.Query{Profile: "a"}); len(got) != 0 {
		t.Errorf("rows of purged profile remain: %+v", got)
	}
	if entries, _ := db.LookupDomain(ctx, []string{"example.com"}, ""); len(entries) != 0 {
		t.Errorf("index of purged profile remains: %+v", entries)
	}
	for _, scope := range []string{"", "z1"} {
		if st, _ := db.GetState(ctx, scoped("a", platform.ResDNSRecord, scope)); st != nil {
			t.Errorf("sync state of purged profile remains for scope %q", scope)
		}
	}
	if got := mustList(t, db, inventory.Query{Profile: "b"}); len(got) != 1 {
		t.Errorf("Purge touched another profile: %+v", got)
	}
	stats, err := db.Stats(ctx)
	if err != nil || len(stats) != 1 || stats[0].Profile != "b" {
		t.Errorf("Stats after Purge = %+v, %v", stats, err)
	}
	// Purging a profile on a different platform with the same name is a no-op.
	if err := db.Purge(ctx, platform.GoDaddy, "b"); err != nil {
		t.Fatal(err)
	}
	if got := mustList(t, db, inventory.Query{Profile: "b"}); len(got) != 1 {
		t.Errorf("Purge keyed only by name: %+v", got)
	}
}

func TestStats(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z1", "example.com"), zoneRes("z2", "other.com"))
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour,
		recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"),
		recRes("r2", "z1", "example.com", "ftp.example.com", "1.1.1.2"),
		recRes("r3", "z2", "other.com", "api.other.com", "2.2.2.2"),
	)
	// A scoped-only set has no unscoped state and must not appear.
	mustReplace(t, db, scoped("b", platform.ResDNSRecord, "z5"), time.Hour, recRes("r5", "z5", "x.com", "x.com", "5.5.5.5"))

	stats, err := db.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(stats) != 2 {
		t.Fatalf("Stats = %+v, want 2 unscoped sets", stats)
	}
	byType := map[platform.ResourceType]inventory.Stat{}
	for _, s := range stats {
		if s.Profile != "a" || s.Platform != platform.NameCom {
			t.Errorf("unexpected stat %+v", s)
		}
		byType[s.Type] = s
	}
	if byType[platform.ResZone].Count != 2 {
		t.Errorf("zone count = %d", byType[platform.ResZone].Count)
	}
	if byType[platform.ResDNSRecord].Count != 3 {
		t.Errorf("record count = %d", byType[platform.ResDNSRecord].Count)
	}
	for _, s := range stats {
		if s.SyncedAt.IsZero() || !s.ExpiresAt.After(s.SyncedAt) {
			t.Errorf("stat timestamps: %+v", s)
		}
	}
}

func TestExpiry(t *testing.T) {
	db, _ := openDB(t)
	// A zero TTL is stale immediately.
	mustReplace(t, db, set("a", platform.ResZone), 0, zoneRes("z1", "example.com"))
	st, err := db.GetState(ctx, set("a", platform.ResZone))
	if err != nil || st == nil {
		t.Fatalf("GetState = %v, %v", st, err)
	}
	if st.Fresh(time.Now()) {
		t.Errorf("ttl 0 must be stale immediately: %+v", st)
	}
	if st.ExpiresAt.Before(st.SyncedAt) {
		t.Errorf("expires %v before synced %v", st.ExpiresAt, st.SyncedAt)
	}

	// Timestamps are stored with second precision (truncated), so a sync
	// late in a second can lose almost a whole second of its window: a 1s
	// TTL may already be stale when read back. 2s is the smallest window
	// that is reliably fresh right after the sync.
	mustReplace(t, db, set("a", platform.ResDomain), 2*time.Second, domainRes("example.com"))
	st, err = db.GetState(ctx, set("a", platform.ResDomain))
	if err != nil || st == nil {
		t.Fatalf("GetState = %v, %v", st, err)
	}
	if !st.Fresh(time.Now()) {
		t.Fatalf("2s ttl must be fresh right after sync: %+v (now %v)", st, time.Now())
	}
	if got := st.ExpiresAt.Sub(st.SyncedAt); got != 2*time.Second {
		t.Errorf("window = %v, want 2s", got)
	}
	rows := mustList(t, db, inventory.Query{Type: platform.ResDomain})
	if len(rows) != 1 || !rows[0].ExpiresAt.Equal(st.ExpiresAt) {
		t.Errorf("row expiry %v does not match set expiry %v", rows, st.ExpiresAt)
	}
	if st.Fresh(st.ExpiresAt.Add(100 * time.Millisecond)) {
		t.Errorf("2s ttl must be stale after its window: %+v", st)
	}
	// Freshness is a pure function of the stored window.
	if !st.Fresh(st.SyncedAt) || st.Fresh(st.ExpiresAt) {
		t.Errorf("Fresh boundaries wrong: %+v", st)
	}
}

func TestReplaceScopedClearsIndexRowsOfThatScope(t *testing.T) {
	db, _ := openDB(t)
	// Zones indexed under a parent (any indexed type with a scope).
	parented := func(id, name, parent string) platform.Resource {
		r := zoneRes(id, name)
		r.ParentID = parent
		return r
	}
	mustReplace(t, db, scoped("a", platform.ResZone, "acct1"), time.Hour, parented("z1", "old.com", "acct1"))
	mustReplace(t, db, scoped("a", platform.ResZone, "acct2"), time.Hour, parented("z2", "other.com", "acct2"))
	mustReplace(t, db, scoped("a", platform.ResZone, "acct1"), time.Hour, parented("z3", "new.com", "acct1"))

	if entries, _ := db.LookupDomain(ctx, []string{"old.com"}, platform.ResZone); len(entries) != 0 {
		t.Errorf("stale index row survived the scoped replace: %+v", entries)
	}
	if entries, _ := db.LookupDomain(ctx, []string{"new.com"}, platform.ResZone); len(entries) != 1 {
		t.Errorf("new index row missing: %+v", entries)
	}
	if entries, _ := db.LookupDomain(ctx, []string{"other.com"}, platform.ResZone); len(entries) != 1 {
		t.Errorf("another scope's index row was removed: %+v", entries)
	}
}

func TestRenameProfile(t *testing.T) {
	db, _ := openDB(t)
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z1", "example.com"))
	mustReplace(t, db, set("a", platform.ResDNSRecord), time.Hour, recRes("r1", "z1", "example.com", "www.example.com", "1.1.1.1"))
	mustReplace(t, db, set("b", platform.ResZone), time.Hour, zoneRes("z2", "other.com"))
	// Stale rows already stored under the new name, on the same platform.
	mustReplace(t, db, set("c", platform.ResZone), time.Hour, zoneRes("z9", "stale.com"))
	mustReplace(t, db, set("c", platform.ResDomain), time.Hour, domainRes("stale.com"))
	// The same profile name on another platform must not be touched.
	other := inventory.Set{Platform: platform.GoDaddy, Profile: "a", Type: platform.ResZone}
	mustReplace(t, db, other, time.Hour, zoneRes("g1", "godaddy.example"))

	if err := db.RenameProfile(ctx, platform.NameCom, "a", "c"); err != nil {
		t.Fatalf("RenameProfile: %v", err)
	}

	if got := mustList(t, db, inventory.Query{Platform: platform.NameCom, Profile: "a"}); len(got) != 0 {
		t.Errorf("rows left under the old name: %+v", got)
	}
	got := mustList(t, db, inventory.Query{Platform: platform.NameCom, Profile: "c"})
	var ids []string
	for _, r := range got {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] != "r1" || ids[1] != "z1" {
		t.Errorf("rows under the new name = %v, want the moved r1 and z1 without the stale ones", ids)
	}
	entries, err := db.IndexEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	var index []string
	for _, e := range entries {
		index = append(index, e.Domain+"="+string(e.Platform)+"/"+e.Profile)
	}
	want := []string{"example.com=namecom/c", "godaddy.example=godaddy/a", "other.com=namecom/b"}
	if len(index) != len(want) {
		t.Fatalf("index = %v, want %v", index, want)
	}
	for i := range want {
		if index[i] != want[i] {
			t.Errorf("index = %v, want %v", index, want)
			break
		}
	}
	for _, scope := range []string{"", "z1"} {
		if st, _ := db.GetState(ctx, scoped("a", platform.ResDNSRecord, scope)); st != nil {
			t.Errorf("sync state left under the old name for scope %q", scope)
		}
		if st, _ := db.GetState(ctx, scoped("c", platform.ResDNSRecord, scope)); st == nil {
			t.Errorf("sync state not moved for scope %q", scope)
		}
	}
	if st, _ := db.GetState(ctx, set("c", platform.ResDomain)); st != nil {
		t.Error("stale sync state under the new name survived")
	}
	if st, _ := db.GetState(ctx, other); st == nil {
		t.Error("the other platform lost its sync state")
	}
	if got := mustList(t, db, inventory.Query{Profile: "b"}); len(got) != 1 {
		t.Errorf("another profile was touched: %+v", got)
	}

	// Renaming to the same name, or a profile without rows, changes nothing.
	if err := db.RenameProfile(ctx, platform.NameCom, "c", "c"); err != nil {
		t.Fatal(err)
	}
	if err := db.RenameProfile(ctx, platform.NameCom, "missing", "d"); err != nil {
		t.Fatal(err)
	}
	if got := mustList(t, db, inventory.Query{Platform: platform.NameCom}); len(got) != 3 {
		t.Errorf("rows after the no-op renames = %d, want 3", len(got))
	}
}

func TestRenameProfileIsAtomic(t *testing.T) {
	db, path := openDB(t)
	mustReplace(t, db, set("a", platform.ResZone), time.Hour, zoneRes("z1", "example.com"))
	mustReplace(t, db, set("c", platform.ResZone), time.Hour, zoneRes("z9", "stale.com"))
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	// resources is renamed first; the failure comes at the second table.
	if _, err := raw.Exec(`CREATE TRIGGER block_rename BEFORE UPDATE ON domain_index BEGIN SELECT RAISE(ABORT, 'rename blocked'); END`); err != nil {
		t.Fatal(err)
	}
	if err := db.RenameProfile(ctx, platform.NameCom, "a", "c"); err == nil {
		t.Fatal("RenameProfile succeeded despite the failing table")
	}
	if got := mustList(t, db, inventory.Query{Profile: "a"}); len(got) != 1 || got[0].ID != "z1" {
		t.Errorf("rows of the old name after the failure = %+v", got)
	}
	if got := mustList(t, db, inventory.Query{Profile: "c"}); len(got) != 1 || got[0].ID != "z9" {
		t.Errorf("rows of the new name after the failure = %+v", got)
	}
}

// A database written by polyctl 0.1.x stores a DNS record's data under
// "content". Opening it renames the field once, so cached records keep
// their value instead of decoding to an empty one.
func TestOpenRenamesLegacyRecordContent(t *testing.T) {
	db, path := openDB(t)
	mustReplace(t, db, scoped("p", platform.ResDNSRecord, "z1"), time.Hour,
		recRes("r1", "z1", "example.com", "www.example.com", "1.2.3.4"),
		recRes("r2", "z1", "example.com", "api.example.com", "5.6.7.8"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}

	// Put the database back into the 0.1.x state: r1 in the old layout,
	// r2 untouched, and no data version.
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`UPDATE resources SET data = '{"id":"r1","zone_id":"z1","name":"www.example.com","type":"A","content":"1.2.3.4","ttl":300}' WHERE resource_id = 'r1'`,
		`PRAGMA user_version = 0`,
	} {
		if _, err := raw.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}

	for pass := 1; pass <= 2; pass++ { // the second open must change nothing
		db, err = inventory.Open(path)
		if err != nil {
			t.Fatalf("Open (pass %d): %v", pass, err)
		}
		rows, err := db.List(ctx, inventory.Query{Type: platform.ResDNSRecord})
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]string{}
		for _, r := range rows {
			var rec platform.Record
			if err := r.Decode(&rec); err != nil {
				t.Fatal(err)
			}
			got[rec.ID] = rec.Value
			if strings.Contains(string(r.Data), `"content"`) {
				t.Errorf("pass %d: %s still stores the old field: %s", pass, r.ID, r.Data)
			}
		}
		if got["r1"] != "1.2.3.4" || got["r2"] != "5.6.7.8" || len(got) != 2 {
			t.Errorf("pass %d: values = %v", pass, got)
		}
		if err := db.Close(); err != nil {
			t.Fatal(err)
		}
	}

	// A polyctl 0.1.x sharing the directory writes the old layout into a
	// database that is already at the current data version. The next open
	// rewrites that row too, and a row read before any rewrite still
	// decodes to its value.
	const legacy = `{"id":"r3","zone_id":"z1","name":"old.example.com","type":"A","content":"9.9.9.9","ttl":300}`
	var rec platform.Record
	if err := json.Unmarshal([]byte(legacy), &rec); err != nil || rec.Value != "9.9.9.9" {
		t.Errorf("legacy row decodes to %+v, %v; want the value 9.9.9.9", rec, err)
	}
	raw, err = sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	var version int
	if err := raw.QueryRow(`PRAGMA user_version`).Scan(&version); err != nil || version < 1 {
		t.Fatalf("user_version = %d, %v; want it set by the first open", version, err)
	}
	if _, err := raw.Exec(`UPDATE resources SET resource_id = 'r3', data = ? WHERE resource_id = 'r2'`, legacy); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.List(ctx, inventory.Query{Type: platform.ResDNSRecord})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, r := range rows {
		if r.ID != "r3" {
			continue
		}
		found = true
		var rec platform.Record
		if err := r.Decode(&rec); err != nil || rec.Value != "9.9.9.9" || strings.Contains(string(r.Data), `"content"`) {
			t.Errorf("row written after the migration: %+v, %v, data %s", rec, err, r.Data)
		}
	}
	if !found {
		t.Errorf("r3 not listed: %+v", rows)
	}
}

// GoDaddy record ids did not carry the zone before data version 2, so the
// same record in two domains shared one row. Opening an older database
// drops the cached GoDaddy records and their sync state, and nothing else.
func TestOpenForgetsGoDaddyRecordsOfVersion1(t *testing.T) {
	db, path := openDB(t)
	gd := inventory.Set{Platform: platform.GoDaddy, Profile: "p", Type: platform.ResDNSRecord, Scope: "a.com"}
	mustReplace(t, db, gd, time.Hour, recRes("A|@|1.2.3.4", "a.com", "a.com", "a.com", "1.2.3.4"))
	gdZones := inventory.Set{Platform: platform.GoDaddy, Profile: "p", Type: platform.ResZone}
	mustReplace(t, db, gdZones, time.Hour, zoneRes("a.com", "a.com"))
	mustReplace(t, db, scoped("p", platform.ResDNSRecord, "z1"), time.Hour, recRes("r1", "z1", "example.com", "www.example.com", "5.6.7.8"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 1`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.GoDaddy, Type: platform.ResDNSRecord}); err != nil || len(rows) != 0 {
		t.Errorf("GoDaddy records after the upgrade: %+v, %v", rows, err)
	}
	if st, err := db.GetState(ctx, gd); err != nil || st != nil {
		t.Errorf("GoDaddy record sync state after the upgrade: %+v, %v", st, err)
	}
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.GoDaddy, Type: platform.ResZone}); err != nil || len(rows) != 1 {
		t.Errorf("GoDaddy zones must stay: %+v, %v", rows, err)
	}
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.NameCom, Type: platform.ResDNSRecord}); err != nil || len(rows) != 1 {
		t.Errorf("records of other platforms must stay: %+v, %v", rows, err)
	}
}

// Rows of Google Cloud did not carry their project before data version 3
// (zone ids were bare managed zone names, parents bare zones). Opening an
// older database drops everything cached for gcp, sync state included, and
// keeps the other platforms and the instance secrets.
func TestOpenForgetsGCPRowsOfVersion2(t *testing.T) {
	db, path := openDB(t)
	zones := inventory.Set{Platform: platform.GCP, Profile: "p", Type: platform.ResZone}
	mustReplace(t, db, zones, time.Hour, zoneRes("example-zone", "example.com"))
	insts := inventory.Set{Platform: platform.GCP, Profile: "p", Type: platform.ResInstance}
	mustReplace(t, db, insts, time.Hour, ipRes(platform.ResInstance, "42", "us-central1-a", ref(platform.IPInternal, "10.0.0.1")))
	mustReplace(t, db, scoped("p", platform.ResDNSRecord, "z1"), time.Hour, recRes("r1", "z1", "example.org", "www.example.org", "5.6.7.8"))
	secret := inventory.SecretRow{SecretKey: inventory.SecretKey{Platform: platform.GCP, Profile: "p", Location: "us-central1-a", InstanceID: "42"},
		Name: "web", User: "admin", Nonce: []byte{1}, Sealed: []byte{2}}
	if err := db.PutSecret(ctx, secret); err != nil {
		t.Fatal(err)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 2`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.GCP}); err != nil || len(rows) != 0 {
		t.Errorf("gcp rows after the upgrade: %+v, %v", rows, err)
	}
	for _, s := range []inventory.Set{zones, insts} {
		if st, err := db.GetState(ctx, s); err != nil || st != nil {
			t.Errorf("gcp sync state of %s after the upgrade: %+v, %v", s.Type, st, err)
		}
	}
	if es, err := db.LookupDomain(ctx, []string{"example.com"}, ""); err != nil || len(es) != 0 {
		t.Errorf("gcp domain index after the upgrade: %+v, %v", es, err)
	}
	if hits, err := db.LookupIP(ctx, netip.MustParseAddr("10.0.0.1")); err != nil || len(hits) != 0 {
		t.Errorf("gcp ip index after the upgrade: %+v, %v", hits, err)
	}
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.NameCom, Type: platform.ResDNSRecord}); err != nil || len(rows) != 1 {
		t.Errorf("records of other platforms must stay: %+v, %v", rows, err)
	}
	if got, err := db.GetSecret(ctx, secret.SecretKey); err != nil || got == nil {
		t.Errorf("the instance secret must stay: %+v, %v", got, err)
	}
}

// A Google Cloud account covers every project its credentials see since
// data version 4, and no longer the projects selected for it. Opening an
// older database keeps what is cached for gcp and makes its sets due, so
// that the next read syncs the projects that were not selected; the other
// platforms stay fresh.
func TestOpenExpiresGCPSetsOfVersion3(t *testing.T) {
	db, path := openDB(t)
	zones := inventory.Set{Platform: platform.GCP, Profile: "p", Type: platform.ResZone}
	mustReplace(t, db, zones, time.Hour, zoneRes("p1/example-zone", "example.com"))
	recs := scoped("p", platform.ResDNSRecord, "p1/example-zone")
	recs.Platform = platform.GCP
	mustReplace(t, db, recs, time.Hour, recRes("r1", "p1/example-zone", "example.com", "www.example.com", "5.6.7.8"))
	other := inventory.Set{Platform: platform.NameCom, Profile: "p", Type: platform.ResZone}
	mustReplace(t, db, other, time.Hour, zoneRes("example.org", "example.org"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 3`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.GCP}); err != nil || len(rows) != 2 {
		t.Errorf("gcp rows after the upgrade: %+v, %v", rows, err)
	}
	if es, err := db.LookupDomain(ctx, []string{"example.com"}, ""); err != nil || len(es) == 0 {
		t.Errorf("gcp domain index after the upgrade: %+v, %v", es, err)
	}
	for _, s := range []inventory.Set{zones, recs} {
		if st, err := db.GetState(ctx, s); err != nil || st == nil || st.Fresh(now) {
			t.Errorf("gcp set %s %q must be due after the upgrade: %+v, %v", s.Type, s.Scope, st, err)
		}
	}
	if st, err := db.GetState(ctx, other); err != nil || !st.Fresh(now) {
		t.Errorf("the sets of other platforms must stay fresh: %+v, %v", st, err)
	}
	// The step runs once: a set synced after it stays fresh at the next open.
	mustReplace(t, db, zones, time.Hour, zoneRes("p1/example-zone", "example.com"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if st, err := db.GetState(ctx, zones); err != nil || !st.Fresh(now) {
		t.Errorf("a set synced after the upgrade must stay fresh: %+v, %v", st, err)
	}
}

// A Cloudflare login covers every account its credentials see since data
// version 5, and no longer the accounts selected for it. Opening an older
// database keeps what is cached for cloudflare and makes its sets due, so
// that the next read syncs the accounts that were not selected; the other
// platforms stay fresh.
func TestOpenExpiresCloudflareSetsOfVersion4(t *testing.T) {
	db, path := openDB(t)
	zones := inventory.Set{Platform: platform.Cloudflare, Profile: "p", Type: platform.ResZone}
	mustReplace(t, db, zones, time.Hour, zoneRes("z1", "example.com"))
	recs := scoped("p", platform.ResDNSRecord, "z1")
	recs.Platform = platform.Cloudflare
	mustReplace(t, db, recs, time.Hour, recRes("r1", "z1", "example.com", "www.example.com", "5.6.7.8"))
	buckets := inventory.Set{Platform: platform.Cloudflare, Profile: "p", Type: platform.ResR2Bucket}
	mustReplace(t, db, buckets, time.Hour, platform.Resource{Type: platform.ResR2Bucket, ID: "acc1/assets", Name: "assets", ParentID: "acc1"})
	other := inventory.Set{Platform: platform.GCP, Profile: "p", Type: platform.ResZone}
	mustReplace(t, db, other, time.Hour, zoneRes("p1/example-zone", "example.org"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := raw.Exec(`PRAGMA user_version = 4`); err != nil {
		t.Fatal(err)
	}
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare}); err != nil || len(rows) != 3 {
		t.Errorf("cloudflare rows after the upgrade: %+v, %v", rows, err)
	}
	if es, err := db.LookupDomain(ctx, []string{"example.com"}, ""); err != nil || len(es) == 0 {
		t.Errorf("cloudflare domain index after the upgrade: %+v, %v", es, err)
	}
	for _, s := range []inventory.Set{zones, recs, buckets} {
		if st, err := db.GetState(ctx, s); err != nil || st == nil || st.Fresh(now) {
			t.Errorf("cloudflare set %s %q must be due after the upgrade: %+v, %v", s.Type, s.Scope, st, err)
		}
	}
	if st, err := db.GetState(ctx, other); err != nil || !st.Fresh(now) {
		t.Errorf("the sets of other platforms must stay fresh: %+v, %v", st, err)
	}
	// The step runs once: a set synced after it stays fresh at the next open.
	mustReplace(t, db, zones, time.Hour, zoneRes("z1", "example.com"))
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
	if db, err = inventory.Open(path); err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if st, err := db.GetState(ctx, zones); err != nil || !st.Fresh(now) {
		t.Errorf("a set synced after the upgrade must stay fresh: %+v, %v", st, err)
	}
}
