package inventory_test

import (
	"net/netip"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

func ipRes(rt platform.ResourceType, id, parent string, refs ...platform.IPRef) platform.Resource {
	return platform.Resource{Type: rt, ID: id, Name: id, ParentID: parent, Data: map[string]string{"id": id}, IPs: refs}
}

func ref(kind platform.IPKind, v string) platform.IPRef {
	if kind == platform.IPDNS {
		r, _ := platform.DNSRef(v)
		return r
	}
	r, ok := platform.IPAddr(kind, v)
	if !ok {
		panic(v)
	}
	return r
}

func hitIDs(hits []inventory.IPHit) []string {
	var out []string
	for _, h := range hits {
		out = append(out, h.Profile+"/"+string(h.Type)+"/"+h.ResourceID+"/"+string(h.Kind))
	}
	return out
}

func TestIPIndexReplaceAndLookup(t *testing.T) {
	db, _ := openDB(t)
	awsSet := func(profile string, rt platform.ResourceType) inventory.Set {
		return inventory.Set{Platform: platform.AWS, Profile: profile, Type: rt}
	}
	if err := db.Replace(ctx, awsSet("a", platform.ResInstance), []platform.Resource{
		ipRes(platform.ResInstance, "i-1", "", ref(platform.IPInternal, "10.0.0.5"), ref(platform.IPExternal, "203.0.113.10"), ref(platform.IPInternal, "2001:DB8::1")),
		ipRes(platform.ResInstance, "i-2", "", ref(platform.IPInternal, "10.0.0.6"), ref(platform.IPInternal, "10.1.2.0/24")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.Replace(ctx, awsSet("b", platform.ResInstance), []platform.Resource{
		ipRes(platform.ResInstance, "i-9", "", ref(platform.IPInternal, "10.0.0.5")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.Replace(ctx, awsSet("a", platform.ResDBInstance), []platform.Resource{
		ipRes(platform.ResDBInstance, "db1", "", ref(platform.IPDNS, "MyDB.abc.ap-east-1.rds.amazonaws.com.")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}

	look := func(s string) []string {
		t.Helper()
		hits, err := db.LookupIP(ctx, netip.MustParseAddr(s))
		if err != nil {
			t.Fatal(err)
		}
		return hitIDs(hits)
	}
	if got := look("10.0.0.5"); len(got) != 2 || got[0] != "a/instance/i-1/internal" || got[1] != "b/instance/i-9/internal" {
		t.Errorf("10.0.0.5 = %v", got)
	}
	if got := look("2001:db8:0:0::1"); len(got) != 1 || got[0] != "a/instance/i-1/internal" {
		t.Errorf("ipv6 spelling = %v", got)
	}
	if got := look("::ffff:203.0.113.10"); len(got) != 1 || got[0] != "a/instance/i-1/external" {
		t.Errorf("mapped = %v", got)
	}
	if got := look("10.1.2.77"); len(got) != 1 || got[0] != "a/instance/i-2/internal" {
		t.Errorf("prefix = %v", got)
	}
	if got := look("10.1.3.1"); len(got) != 0 {
		t.Errorf("outside prefix = %v", got)
	}
	hits, err := db.LookupDNS(ctx, "mydb.ABC.ap-east-1.rds.amazonaws.com.")
	if err != nil || len(hits) != 1 || hits[0].ResourceID != "db1" || hits[0].Kind != platform.IPDNS {
		t.Errorf("dns = %v, %v", hits, err)
	}

	// Replacing the set rebuilds its index rows only.
	if err := db.Replace(ctx, awsSet("a", platform.ResInstance), []platform.Resource{
		ipRes(platform.ResInstance, "i-1", "", ref(platform.IPInternal, "10.0.0.7")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := look("10.0.0.5"); len(got) != 1 || got[0] != "b/instance/i-9/internal" {
		t.Errorf("after replace = %v", got)
	}
	if got := look("10.1.2.77"); len(got) != 0 {
		t.Errorf("prefix after replace = %v", got)
	}

	// Upsert replaces the rows of one resource, Delete removes them.
	if err := db.Upsert(ctx, awsSet("a", platform.ResInstance), ipRes(platform.ResInstance, "i-1", "", ref(platform.IPExternal, "198.51.100.1")), time.Hour); err != nil {
		t.Fatal(err)
	}
	if got := look("10.0.0.7"); len(got) != 0 {
		t.Errorf("after upsert = %v", got)
	}
	if got := look("198.51.100.1"); len(got) != 1 {
		t.Errorf("upserted = %v", got)
	}
	if err := db.Delete(ctx, awsSet("a", platform.ResInstance), platform.ResInstance, "i-1"); err != nil {
		t.Fatal(err)
	}
	if got := look("198.51.100.1"); len(got) != 0 {
		t.Errorf("after delete = %v", got)
	}

	// Purge and RenameProfile carry the index along.
	if err := db.RenameProfile(ctx, platform.AWS, "b", "c"); err != nil {
		t.Fatal(err)
	}
	if got := look("10.0.0.5"); len(got) != 1 || got[0] != "c/instance/i-9/internal" {
		t.Errorf("after rename = %v", got)
	}
	if err := db.Purge(ctx, platform.AWS, "c"); err != nil {
		t.Fatal(err)
	}
	if got := look("10.0.0.5"); len(got) != 0 {
		t.Errorf("after purge = %v", got)
	}
}

func TestIPIndexScopedReplace(t *testing.T) {
	db, _ := openDB(t)
	s := inventory.Set{Platform: platform.Aliyun, Profile: "a", Type: platform.ResEIP}
	if err := db.Replace(ctx, s, []platform.Resource{
		ipRes(platform.ResEIP, "eip-1", "cn-hongkong", ref(platform.IPExternal, "203.0.113.1")),
		ipRes(platform.ResEIP, "eip-2", "ap-southeast-1", ref(platform.IPExternal, "203.0.113.2")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	scoped := s
	scoped.Scope = "cn-hongkong"
	if err := db.Replace(ctx, scoped, nil, time.Hour); err != nil {
		t.Fatal(err)
	}
	if hits, _ := db.LookupIP(ctx, netip.MustParseAddr("203.0.113.1")); len(hits) != 0 {
		t.Errorf("scoped replace kept %v", hits)
	}
	if hits, _ := db.LookupIP(ctx, netip.MustParseAddr("203.0.113.2")); len(hits) != 1 {
		t.Errorf("other scope = %v", hits)
	}
}

// A sync that failed in some regions keeps the stored rows of those regions
// (and their index entries); the rows of the other regions are replaced.
func TestReplaceKeepingFailedRegions(t *testing.T) {
	db, _ := openDB(t)
	set := inventory.Set{Platform: platform.AWS, Profile: "a", Type: platform.ResInstance}
	if err := db.Replace(ctx, set, []platform.Resource{
		ipRes(platform.ResInstance, "i-east", "us-east-1", ref(platform.IPInternal, "10.0.0.1")),
		ipRes(platform.ResInstance, "i-west", "us-west-2", ref(platform.IPInternal, "10.0.0.2")),
		ipRes(platform.ResInstance, "i-gone", "eu-west-1", ref(platform.IPInternal, "10.0.0.3")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// us-west-2 failed: i-west stays; eu-west-1 worked and no longer has
	// i-gone; us-east-1 worked and i-east moved to another address.
	if err := db.ReplaceKeeping(ctx, set, []platform.Resource{
		ipRes(platform.ResInstance, "i-east", "us-east-1", ref(platform.IPInternal, "10.0.0.9")),
	}, time.Hour, []string{"us-west-2"}); err != nil {
		t.Fatal(err)
	}
	// The set holds old rows of us-west-2: it is not fresh, so the next
	// read syncs again; the parents that worked are.
	if st, err := db.GetState(ctx, set); err != nil || st == nil || st.Fresh(time.Now()) {
		t.Errorf("state after a partial sync = %+v, %v; want stale", st, err)
	}
	east := set
	east.Scope = "us-east-1"
	if st, err := db.GetState(ctx, east); err != nil || !st.Fresh(time.Now()) {
		t.Errorf("state of us-east-1 = %+v, %v; want fresh", st, err)
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: "a", Type: platform.ResInstance})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	if len(ids) != 2 || ids[0] != "i-east" || ids[1] != "i-west" {
		t.Fatalf("rows = %v, want i-east and i-west", ids)
	}
	for ip, want := range map[string]int{"10.0.0.1": 0, "10.0.0.9": 1, "10.0.0.2": 1, "10.0.0.3": 0} {
		hits, err := db.LookupIP(ctx, netip.MustParseAddr(ip))
		if err != nil {
			t.Fatal(err)
		}
		if len(hits) != want {
			t.Errorf("LookupIP(%s) = %v, want %d hit(s)", ip, hitIDs(hits), want)
		}
	}
}

// A failed tree keeps the rows of the parent itself and of every parent
// below it; rows of the trees that worked are replaced.
func TestReplaceKeepingTrees(t *testing.T) {
	db, _ := openDB(t)
	set := inventory.Set{Platform: platform.GCP, Profile: "a", Type: platform.ResInstance}
	if err := db.Replace(ctx, set, []platform.Resource{
		ipRes(platform.ResInstance, "1", "p1/us-a", ref(platform.IPInternal, "10.0.0.1")),
		ipRes(platform.ResInstance, "2", "p1/us-b", ref(platform.IPInternal, "10.0.0.2")),
		ipRes(platform.ResInstance, "3", "p2", ref(platform.IPInternal, "10.0.0.3")),
		ipRes(platform.ResInstance, "4", "p2/eu-a", ref(platform.IPInternal, "10.0.0.4")),
		ipRes(platform.ResInstance, "5", "p22/eu-a", ref(platform.IPInternal, "10.0.0.5")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// p2 failed as a whole; p1 answered with one instance, p22 with none.
	if err := db.ReplaceKeepingTrees(ctx, set, []platform.Resource{
		ipRes(platform.ResInstance, "1", "p1/us-a", ref(platform.IPInternal, "10.0.0.9")),
	}, time.Hour, nil, []string{"p2"}); err != nil {
		t.Fatal(err)
	}
	if st, err := db.GetState(ctx, set); err != nil || st == nil || st.Fresh(time.Now()) {
		t.Errorf("state after a partial sync = %+v, %v; want stale", st, err)
	}
	if got := rowIDs(t, db, set); strings.Join(got, ",") != "1,3,4" {
		t.Fatalf("rows = %v, want 1 (replaced), 3 and 4 (kept); 2 and 5 are gone", got)
	}
	for ip, want := range map[string]int{"10.0.0.1": 0, "10.0.0.9": 1, "10.0.0.2": 0, "10.0.0.3": 1, "10.0.0.4": 1, "10.0.0.5": 0} {
		hits, err := db.LookupIP(ctx, netip.MustParseAddr(ip))
		if err != nil || len(hits) != want {
			t.Errorf("LookupIP(%s) = %d hit(s), %v; want %d", ip, len(hits), err, want)
		}
	}
}

func rowIDs(t *testing.T, db *inventory.DB, set inventory.Set) []string {
	t.Helper()
	rows, err := db.List(ctx, inventory.Query{Platform: set.Platform, Profile: set.Profile, Type: set.Type})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, r := range rows {
		ids = append(ids, r.ID)
	}
	sort.Strings(ids)
	return ids
}

// PurgeTree drops the rows, index entries and scopes of one tree only;
// Expire makes every set of the profile due without dropping a row.
func TestPurgeTreeAndExpire(t *testing.T) {
	db, _ := openDB(t)
	set := inventory.Set{Platform: platform.GCP, Profile: "a", Type: platform.ResInstance}
	zones := inventory.Set{Platform: platform.GCP, Profile: "a", Type: platform.ResZone}
	if err := db.Replace(ctx, set, []platform.Resource{
		ipRes(platform.ResInstance, "1", "p1/us-a", ref(platform.IPInternal, "10.0.0.1")),
		ipRes(platform.ResInstance, "2", "p2/us-a", ref(platform.IPInternal, "10.0.0.2")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.Replace(ctx, zones, []platform.Resource{
		{Type: platform.ResZone, ID: "p1/z", Name: "a.example", ParentID: "p1", Domain: "a.example", Data: map[string]string{}},
		{Type: platform.ResZone, ID: "p2/z", Name: "b.example", ParentID: "p2", Domain: "b.example", Data: map[string]string{}},
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.PurgeTree(ctx, platform.GCP, "a", "p2"); err != nil {
		t.Fatal(err)
	}
	if got := rowIDs(t, db, set); strings.Join(got, ",") != "1" {
		t.Errorf("instances after PurgeTree = %v, want 1", got)
	}
	if got := rowIDs(t, db, zones); strings.Join(got, ",") != "p1/z" {
		t.Errorf("zones after PurgeTree = %v, want p1/z", got)
	}
	if hits, err := db.LookupIP(ctx, netip.MustParseAddr("10.0.0.2")); err != nil || len(hits) != 0 {
		t.Errorf("ip of the purged tree: %d hit(s), %v", len(hits), err)
	}
	for dom, want := range map[string]int{"a.example": 1, "b.example": 0} {
		if es, err := db.LookupDomain(ctx, []string{dom}, platform.ResZone); err != nil || len(es) != want {
			t.Errorf("LookupDomain(%s) = %d, %v; want %d", dom, len(es), err, want)
		}
	}
	scope := set
	scope.Scope = "p2/us-a"
	if st, err := db.GetState(ctx, scope); err != nil || st != nil {
		t.Errorf("scope of the purged tree = %+v, %v; want none", st, err)
	}
	if st, err := db.GetState(ctx, set); err != nil || !st.Fresh(time.Now()) {
		t.Fatalf("set before Expire = %+v, %v; want fresh", st, err)
	}
	if err := db.Expire(ctx, platform.GCP, "a"); err != nil {
		t.Fatal(err)
	}
	if st, err := db.GetState(ctx, set); err != nil || st == nil || st.Fresh(time.Now()) {
		t.Errorf("set after Expire = %+v, %v; want stale", st, err)
	}
	if got := rowIDs(t, db, set); strings.Join(got, ",") != "1" {
		t.Errorf("Expire dropped rows: %v", got)
	}
}

// cfZone is a zone row the way Cloudflare stores it: the id is the zone
// id and the parent the account.
func cfZone(id, account, domain string) platform.Resource {
	return platform.Resource{Type: platform.ResZone, ID: id, Name: domain, ParentID: account, Domain: domain, Data: map[string]string{}}
}

// A failed tree also keeps the rows whose parent is a row of the tree: the
// records of the zones of a Cloudflare account, which have the zone id as
// their parent and nothing of the account in it.
func TestReplaceKeepingTreesChildRows(t *testing.T) {
	db, _ := openDB(t)
	zones := inventory.Set{Platform: platform.Cloudflare, Profile: "a", Type: platform.ResZone}
	recs := inventory.Set{Platform: platform.Cloudflare, Profile: "a", Type: platform.ResDNSRecord}
	other := inventory.Set{Platform: platform.Cloudflare, Profile: "b", Type: platform.ResZone}
	if err := db.Replace(ctx, zones, []platform.Resource{
		cfZone("z1", "acc1", "one.example"),
		cfZone("z2", "acc2", "two.example"),
		cfZone("z3", "acc2", "three.example"),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// Another profile holds a zone of the failed account under the id of a
	// zone that answered here: it must not keep the records of that zone.
	if err := db.Replace(ctx, other, []platform.Resource{cfZone("z1", "acc2", "one.example")}, time.Hour); err != nil {
		t.Fatal(err)
	}
	if err := db.Replace(ctx, recs, []platform.Resource{
		ipRes(platform.ResDNSRecord, "r1", "z1", ref(platform.IPInternal, "10.0.0.1")),
		ipRes(platform.ResDNSRecord, "r1-gone", "z1", ref(platform.IPInternal, "10.0.0.5")),
		ipRes(platform.ResDNSRecord, "r2", "z2", ref(platform.IPInternal, "10.0.0.2")),
		ipRes(platform.ResDNSRecord, "r3", "z3", ref(platform.IPInternal, "10.0.0.3")),
		ipRes(platform.ResDNSRecord, "r4", "z-unknown", ref(platform.IPInternal, "10.0.0.4")),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	// acc2 failed as a whole; acc1 answered with one record of z1.
	if err := db.ReplaceKeepingTrees(ctx, recs, []platform.Resource{
		ipRes(platform.ResDNSRecord, "r1", "z1", ref(platform.IPInternal, "10.0.0.9")),
	}, time.Hour, nil, []string{"acc2"}); err != nil {
		t.Fatal(err)
	}
	if st, err := db.GetState(ctx, recs); err != nil || st == nil || st.Fresh(time.Now()) {
		t.Errorf("state after a partial sync = %+v, %v; want stale", st, err)
	}
	if got := rowIDs(t, db, recs); strings.Join(got, ",") != "r1,r2,r3" {
		t.Fatalf("records = %v, want r1 (replaced), r2 and r3 (kept); r1-gone and r4 are gone", got)
	}
	if got := rowIDs(t, db, zones); strings.Join(got, ",") != "z1,z2,z3" {
		t.Errorf("zones = %v; a sync of the records must leave them", got)
	}
	for ip, want := range map[string]int{"10.0.0.1": 0, "10.0.0.9": 1, "10.0.0.2": 1, "10.0.0.3": 1, "10.0.0.4": 0, "10.0.0.5": 0} {
		hits, err := db.LookupIP(ctx, netip.MustParseAddr(ip))
		if err != nil || len(hits) != want {
			t.Errorf("LookupIP(%s) = %d hit(s), %v; want %d", ip, len(hits), err, want)
		}
	}
	// The same sync of the zones keeps the zone rows of the failed account.
	if err := db.ReplaceKeepingTrees(ctx, zones, []platform.Resource{cfZone("z1", "acc1", "one.example")}, time.Hour, nil, []string{"acc2"}); err != nil {
		t.Fatal(err)
	}
	if got := rowIDs(t, db, zones); strings.Join(got, ",") != "z1,z2,z3" {
		t.Errorf("zones after their partial sync = %v, want all three", got)
	}
	// Later syncs find no leftover of the temporary table of the trees.
	if err := db.ReplaceKeepingTrees(ctx, recs, nil, time.Hour, nil, []string{"acc1"}); err != nil {
		t.Fatal(err)
	}
	if got := rowIDs(t, db, recs); strings.Join(got, ",") != "r1" {
		t.Errorf("records with acc1 kept = %v, want r1", got)
	}
}

// PurgeTree drops the rows under the rows of the tree as well, with their
// index entries and the state of the scopes named after those rows.
func TestPurgeTreeChildRows(t *testing.T) {
	db, _ := openDB(t)
	zones := inventory.Set{Platform: platform.Cloudflare, Profile: "a", Type: platform.ResZone}
	recs := inventory.Set{Platform: platform.Cloudflare, Profile: "a", Type: platform.ResDNSRecord}
	other := inventory.Set{Platform: platform.Cloudflare, Profile: "b", Type: platform.ResDNSRecord}
	if err := db.Replace(ctx, zones, []platform.Resource{
		cfZone("z1", "acc1", "one.example"),
		cfZone("z2", "acc2", "two.example"),
	}, time.Hour); err != nil {
		t.Fatal(err)
	}
	scoped := func(set inventory.Set, zone, id, ip string) inventory.Set {
		t.Helper()
		set.Scope = zone
		if err := db.Replace(ctx, set, []platform.Resource{ipRes(platform.ResDNSRecord, id, zone, ref(platform.IPInternal, ip))}, time.Hour); err != nil {
			t.Fatal(err)
		}
		return set
	}
	s1 := scoped(recs, "z1", "r1", "10.0.0.1")
	s2 := scoped(recs, "z2", "r2", "10.0.0.2")
	// The same zone id under another profile is not of this tree.
	sb := scoped(other, "z2", "rb", "10.0.0.3")
	if err := db.PurgeTree(ctx, platform.Cloudflare, "a", "acc2"); err != nil {
		t.Fatal(err)
	}
	if got := rowIDs(t, db, zones); strings.Join(got, ",") != "z1" {
		t.Errorf("zones after PurgeTree = %v, want z1", got)
	}
	if got := rowIDs(t, db, recs); strings.Join(got, ",") != "r1" {
		t.Errorf("records after PurgeTree = %v, want r1", got)
	}
	if got := rowIDs(t, db, other); strings.Join(got, ",") != "rb" {
		t.Errorf("records of the other profile = %v, want rb", got)
	}
	for ip, want := range map[string]int{"10.0.0.1": 1, "10.0.0.2": 0, "10.0.0.3": 1} {
		hits, err := db.LookupIP(ctx, netip.MustParseAddr(ip))
		if err != nil || len(hits) != want {
			t.Errorf("LookupIP(%s) = %d hit(s), %v; want %d", ip, len(hits), err, want)
		}
	}
	for dom, want := range map[string]int{"one.example": 1, "two.example": 0} {
		if es, err := db.LookupDomain(ctx, []string{dom}, platform.ResZone); err != nil || len(es) != want {
			t.Errorf("LookupDomain(%s) = %d, %v; want %d", dom, len(es), err, want)
		}
	}
	if st, err := db.GetState(ctx, s2); err != nil || st != nil {
		t.Errorf("scope of a zone of the purged account = %+v, %v; want none", st, err)
	}
	for _, s := range []inventory.Set{s1, sb, zones} {
		if st, err := db.GetState(ctx, s); err != nil || st == nil {
			t.Errorf("state of %+v = %+v, %v; want kept", s, st, err)
		}
	}
	// A second purge finds no leftover of the temporary table.
	if err := db.PurgeTree(ctx, platform.Cloudflare, "a", "acc1"); err != nil {
		t.Fatal(err)
	}
	if got := rowIDs(t, db, recs); len(got) != 0 {
		t.Errorf("records after the second PurgeTree = %v, want none", got)
	}
}
