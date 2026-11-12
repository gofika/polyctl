package inventory_test

import (
	"context"
	"database/sql"
	"errors"
	"path/filepath"
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
	r := platform.Record{ID: id, ZoneID: zoneID, Name: name, Type: "A", Content: content, TTL: 300}
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

	// Timestamps are stored with second precision, so a 1s TTL is the
	// smallest window that is reliably fresh right after the sync.
	mustReplace(t, db, set("a", platform.ResDomain), time.Second, domainRes("example.com"))
	st, err = db.GetState(ctx, set("a", platform.ResDomain))
	if err != nil || st == nil {
		t.Fatalf("GetState = %v, %v", st, err)
	}
	if !st.Fresh(time.Now()) {
		t.Fatalf("1s ttl must be fresh right after sync: %+v (now %v)", st, time.Now())
	}
	rows := mustList(t, db, inventory.Query{Type: platform.ResDomain})
	if len(rows) != 1 || !rows[0].ExpiresAt.Equal(st.ExpiresAt) {
		t.Errorf("row expiry %v does not match set expiry %v", rows, st.ExpiresAt)
	}
	time.Sleep(1100 * time.Millisecond)
	if st.Fresh(time.Now()) {
		t.Errorf("1s ttl must be stale after 1.1s: %+v (now %v)", st, time.Now())
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
