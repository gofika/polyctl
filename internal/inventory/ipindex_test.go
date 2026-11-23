package inventory_test

import (
	"net/netip"
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
