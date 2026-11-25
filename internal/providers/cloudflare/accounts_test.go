package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// openSelection opens an API-token profile whose metadata is meta.
func openSelection(t *testing.T, srv *httptest.Server, meta map[string]string) *Client {
	t.Helper()
	p := &provider{baseURL: srv.URL}
	m := map[string]string{metaMethod: storedToken}
	for k, v := range meta {
		m[k] = v
	}
	c, err := p.Open(context.Background(), platform.Profile{Name: "cf", Platform: platform.Cloudflare, Metadata: m, Secret: map[string]string{secretToken: "good-token"}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return c.(*Client)
}

// addZone adds a zone to the fake.
func (f *fakeCF) addZone(id, name, status, account, accountName string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zones = append(f.zones, map[string]any{"id": id, "name": name, "status": status, "paused": false,
		"name_servers": []string{"a.ns.cloudflare.com"},
		"account":      map[string]any{"id": account, "name": accountName}, "plan": map[string]any{"name": "Free Website"}})
}

// reqs returns the requests made so far and forgets them.
func (f *fakeCF) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := f.requests
	f.requests = nil
	return out
}

func TestSelectedAccounts(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
		want []string
	}{
		{"unscoped", map[string]string{}, nil},
		{"a login before the selection", map[string]string{metaAccountID: "acc1"}, []string{"acc1"}},
		{"the default account first", map[string]string{metaAccountID: "acc2", metaAccounts: "acc1,acc2,acc3"}, []string{"acc2", "acc1", "acc3"}},
		{"a default account outside the list", map[string]string{metaAccountID: "acc9", metaAccounts: "acc1"}, []string{"acc9", "acc1"}},
		{"blanks and repeats", map[string]string{metaAccountID: " acc1 ", metaAccounts: " acc2, ,acc2,acc1,"}, []string{"acc1", "acc2"}},
		{"a selection without a default", map[string]string{metaAccounts: "acc2,acc1"}, []string{"acc2", "acc1"}},
	}
	for _, c := range cases {
		if got := selectedAccounts(c.meta); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSetSelection(t *testing.T) {
	meta := map[string]string{metaMethod: storedToken, metaAccountID: "acc1", metaAccountName: "Acme"}
	setSelection(meta, account{ID: "acc2", Name: "Beta"}, []string{"acc1", "acc2", "acc1"})
	if meta[metaAccountID] != "acc2" || meta[metaAccountName] != "Beta" || meta[metaAccounts] != "acc2,acc1" || meta[metaMethod] != storedToken {
		t.Fatalf("several: %v", meta)
	}
	// The default account alone is stored as a login before the selection
	// existed stored it; an unknown name does not keep the old one.
	setSelection(meta, account{ID: "acc1"}, []string{"acc1"})
	if _, ok := meta[metaAccounts]; ok || meta[metaAccountID] != "acc1" {
		t.Fatalf("one: %v", meta)
	}
	if _, ok := meta[metaAccountName]; ok {
		t.Fatalf("the name of another account was kept: %v", meta)
	}
	// The default account is part of the selection also when it is not
	// named in it.
	setSelection(meta, account{ID: "acc3", Name: "Gamma"}, []string{"acc1"})
	if meta[metaAccounts] != "acc3,acc1" {
		t.Fatalf("default outside: %v", meta)
	}
}

func TestCheckAccountID(t *testing.T) {
	for _, id := range []string{"acc1", "0123456789abcdef0123456789abcdef"} {
		if err := checkAccountID(id); err != nil {
			t.Errorf("%q: %v", id, err)
		}
	}
	for _, id := range []string{"", "a,b", "a b", "a/b", "a|b", "a\n"} {
		if err := checkAccountID(id); err == nil || !strings.Contains(err.Error(), "is not an account id") {
			t.Errorf("%q: %v", id, err)
		}
	}
}

func TestAPIScope(t *testing.T) {
	a := newAPI("http://unused", "tok", "")
	if !a.unscoped() || !reflect.DeepEqual(a.scopeIDs(), []string{""}) || !a.covers("anything") {
		t.Fatalf("unscoped: %v", a.scopeIDs())
	}
	a = newAPI("http://unused", "tok", "acc1")
	a.accounts = []string{"acc1", "acc2"}
	if a.unscoped() || !reflect.DeepEqual(a.scopeIDs(), []string{"acc1", "acc2"}) || !a.covers("acc2") || a.covers("acc3") || !a.covers("") {
		t.Fatalf("selection: %v", a.scopeIDs())
	}
	in := a.inAccount("acc2")
	if in.accountID != "acc2" || !reflect.DeepEqual(in.scopeIDs(), []string{"acc1", "acc2"}) || a.accountID != "acc1" {
		t.Fatalf("inAccount: %+v", in)
	}
	pin := a.pin("acc3")
	if !reflect.DeepEqual(pin.scopeIDs(), []string{"acc3"}) || !pin.covers("acc3") || pin.covers("acc1") || a.pinned {
		t.Fatalf("pin: %+v", pin)
	}
	// A pin on a login without an account is a scope all the same.
	if p := newAPI("http://unused", "tok", "").pin("acc1"); p.unscoped() || p.covers("acc2") {
		t.Fatalf("pin of an unscoped login: %+v", p)
	}
}

// A login stored before the selection existed sends the requests it always
// sent.
func TestLegacyLoginRequests(t *testing.T) {
	f, srv := newFake(t)
	c := openClient(t, srv, "good-token", "acc2")
	ctx := context.Background()
	if _, err := c.ListZones(ctx); err != nil {
		t.Fatal(err)
	}
	if z, err := c.GetZone(ctx, "Example.ORG."); err != nil || z.ID != "zone2" {
		t.Fatalf("by name: %v %v", z, err)
	}
	if z, err := c.GetZone(ctx, "zone2"); err != nil || z.ID != "zone2" {
		t.Fatalf("by id: %v %v", z, err)
	}
	want := []string{
		"GET /zones?account.id=acc2&page=1&per_page=50",
		"GET /zones?account.id=acc2&name=example.org&page=1&per_page=50",
		"GET /zones/zone2",
	}
	if got := f.reqs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests:\n got %q\nwant %q", got, want)
	}
	// A login without an account filters nothing.
	c = openClient(t, srv, "good-token", "")
	if _, err := c.ListZones(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := f.reqs(), []string{"GET /zones?page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("unscoped requests: %q", got)
	}
}

func TestListZonesOfTheSelection(t *testing.T) {
	f, srv := newFake(t)
	f.addZone("zone3", "example.net", "active", "acc3", "Gamma")
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc2", metaAccounts: "acc1,acc2"})
	zones, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// The default account first, no zone of an account that is not selected.
	if len(zones) != 2 || zones[0].ID != "zone2" || zones[1].ID != "zone1" {
		t.Fatalf("zones: %+v", zones)
	}
	want := []string{"GET /zones?account.id=acc2&page=1&per_page=50", "GET /zones?account.id=acc1&page=1&per_page=50"}
	if got := f.reqs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
	// --account reads that account alone, selected or not.
	zones, err = c.pin("acc3").ListZones(context.Background())
	if err != nil || len(zones) != 1 || zones[0].ID != "zone3" {
		t.Fatalf("pinned: %+v %v", zones, err)
	}
}

func TestGetZoneAmongTheSelection(t *testing.T) {
	f, srv := newFake(t)
	f.addZone("zone3", "example.com", "pending", "acc2", "Beta")
	f.addZone("zone4", "example.net", "active", "acc3", "Gamma")
	ctx := context.Background()
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaAccounts: "acc1,acc2"})

	// A name of the second account is found.
	if z, err := c.GetZone(ctx, "example.org"); err != nil || z.ID != "zone2" {
		t.Fatalf("second account: %v %v", z, err)
	}
	// A name held by two selected accounts is ambiguous (exit code 5).
	_, err := c.GetZone(ctx, "example.com")
	if !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
	for _, want := range []string{"zone example.com is held by 2 of the selected accounts", "zone1 in account acc1 (Acme)", "zone3 in account acc2 (Beta)", "zone id", "--account <id or name>"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("ambiguity %q lacks %q", err, want)
		}
	}
	// ... and one zone with --account, or by its id.
	if z, err := c.pin("acc2").GetZone(ctx, "example.com"); err != nil || z.ID != "zone3" {
		t.Fatalf("pinned: %v %v", z, err)
	}
	if z, err := c.GetZone(ctx, "zone3"); err != nil || z.ID != "zone3" {
		t.Fatalf("by id: %v %v", z, err)
	}

	// A zone of an account that is not selected is not found (exit code
	// 4), by name and by id, and the id says where it is.
	if _, err := c.GetZone(ctx, "example.net"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("unselected by name: %v", err)
	}
	_, err = c.GetZone(ctx, "zone4")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("unselected by id: %v", err)
	}
	for _, want := range []string{"zone example.net (zone4) is in account acc3, which is not selected", "polyctl cloudflare account add acc3", "--account acc3"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("not found %q lacks %q", err, want)
		}
	}
	if z, err := c.pin("acc3").GetZone(ctx, "zone4"); err != nil || z.ID != "zone4" {
		t.Fatalf("pinned by id: %v %v", z, err)
	}
	// --account does not take the zone of another account by its id.
	if _, err := c.pin("acc3").GetZone(ctx, "zone1"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("pinned elsewhere: %v", err)
	}

	// A login without an account takes any zone by id; a name two of its
	// accounts hold is ambiguous as well.
	u := openClient(t, srv, "good-token", "")
	if z, err := u.GetZone(ctx, "zone4"); err != nil || z.ID != "zone4" {
		t.Fatalf("unscoped by id: %v %v", z, err)
	}
	if _, err := u.GetZone(ctx, "example.com"); !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "2 of the accounts of this login") {
		t.Fatalf("unscoped by name: %v", err)
	}
}

// An account-owned token verifies at the account that owns it, also when
// that is not the default account of the selection.
func TestVerifyTokenTriesTheSelection(t *testing.T) {
	f, srv := newFake(t)
	f.accountOwned = "acc2"
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaAccounts: "acc1,acc2"})
	tok, err := c.api.verifyToken(context.Background())
	if err != nil || tok.AccountID != "acc2" {
		t.Fatalf("verify: %+v %v", tok, err)
	}
	want := []string{"GET /user/tokens/verify", "GET /accounts/acc1/tokens/verify", "GET /accounts/acc2/tokens/verify"}
	if got := f.reqs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
}

// captureWarnings collects what the sync warns about.
func captureWarnings(t *testing.T) *[]string {
	t.Helper()
	var warned []string
	orig := warnf
	warnf = func(format string, args ...any) { warned = append(warned, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { warnf = orig })
	return &warned
}

// rowIDs lists "id parent" of resources, sorted.
func rowIDs(res []platform.Resource) []string {
	out := make([]string, 0, len(res))
	for _, r := range res {
		out = append(out, r.ID+" "+r.ParentID)
	}
	sort.Strings(out)
	return out
}

func TestSyncOfTheSelection(t *testing.T) {
	f, srv := newFake(t)
	f.addZone("zone3", "example.net", "active", "acc3", "Gamma")
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaAccounts: "acc1,acc2"})
	ctx := context.Background()

	// The zones of both accounts, each under its account; none of an
	// account that is not selected.
	zones, err := c.Sync(ctx, platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	if got, want := rowIDs(zones), []string{"zone1 acc1", "zone2 acc2"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("zones: %v", got)
	}
	// The records keep their zone as parent.
	recs, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil {
		t.Fatal(err)
	}
	byZone := map[string]int{}
	for _, r := range recs {
		byZone[r.ParentID]++
	}
	if len(recs) != 9 || byZone["zone1"] != 8 || byZone["zone2"] != 1 {
		t.Fatalf("records: %v", byZone)
	}

	// A login stored before the selection reads its one account, with the
	// requests it always made.
	f.reqs()
	old := openClient(t, srv, "good-token", "acc2")
	zones, err = old.Sync(ctx, platform.ResZone)
	if err != nil || !reflect.DeepEqual(rowIDs(zones), []string{"zone2 acc2"}) {
		t.Fatalf("one account: %v %v", rowIDs(zones), err)
	}
	if got, want := f.reqs(), []string{"GET /zones?account.id=acc2&page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
}

func TestSyncKeepsAFailedAccount(t *testing.T) {
	f, srv := newFake(t)
	f.failZones = map[string]int{"acc2": 400}
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaAccounts: "acc1,acc2"})
	ctx := context.Background()

	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResDNSRecord} {
		res, err := c.Sync(ctx, typ)
		rse := platform.AsRegionSyncError(err)
		if rse == nil {
			t.Fatalf("%s: want a RegionSyncError, got %v", typ, err)
		}
		if len(rse.Failures) != 1 || rse.Failures[0].Region != "acc2" || !rse.Failures[0].Tree || rse.Noun != "account" {
			t.Fatalf("%s: failures: %+v", typ, rse)
		}
		if !strings.Contains(err.Error(), "polyctl cloudflare account remove acc2") {
			t.Errorf("%s: the failure does not say how to drop the account: %v", typ, err)
		}
		// The rows of the account that answered are returned.
		for _, r := range res {
			if (typ == platform.ResZone && r.ParentID != "acc1") || (typ == platform.ResDNSRecord && r.ParentID != "zone1") {
				t.Fatalf("%s: row of the failed account: %+v", typ, r)
			}
		}
		if len(res) == 0 {
			t.Fatalf("%s: no rows of the other account", typ)
		}
	}

	// Every account failing is a plain error with the cause (and so the
	// exit code) of the first.
	f.failZones = map[string]int{"acc1": 403, "acc2": 400}
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResDNSRecord} {
		res, err := c.Sync(ctx, typ)
		if err == nil || platform.AsRegionSyncError(err) != nil || !errors.Is(err, platform.ErrUnauthorized) || res != nil {
			t.Fatalf("%s: every account failed: %v %v", typ, res, err)
		}
		if !strings.Contains(err.Error(), "every selected account failed") {
			t.Errorf("%s: %v", typ, err)
		}
	}

	// One account alone fails as it always did.
	f.failZones = map[string]int{"acc2": 400}
	if _, err := openClient(t, srv, "good-token", "acc2").Sync(ctx, platform.ResZone); err == nil || platform.AsRegionSyncError(err) != nil {
		t.Fatalf("one account: %v", err)
	}
}

// The zones whose records the token cannot read are skipped across the
// accounts: an account without any readable zone is no failure while
// another account has one.
func TestSyncRecordsSkipsAcrossAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.forbidRecords["zone2"] = true
	warned := captureWarnings(t)
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaAccounts: "acc1,acc2"})
	ctx := context.Background()

	recs, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil || len(recs) != 8 {
		t.Fatalf("want the 8 records of zone1 and no error, got %d, %v", len(recs), err)
	}
	if len(*warned) != 1 || !strings.Contains((*warned)[0], "example.org") {
		t.Fatalf("warnings: %v", *warned)
	}
	f.forbidRecords["zone1"] = true
	if _, err := c.Sync(ctx, platform.ResDNSRecord); !errors.Is(err, platform.ErrUnauthorized) || platform.AsRegionSyncError(err) != nil {
		t.Fatalf("no readable zone at all: %v", err)
	}
}

// whoami reports the default account, and the selection when the login
// works on several accounts.
func TestVerifyReportsTheSelection(t *testing.T) {
	_, srv := newFake(t)
	ctx := context.Background()
	id, err := openSelection(t, srv, map[string]string{metaAccountID: "acc2", metaAccountName: "Beta", metaAccounts: "acc1,acc2"}).Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != "acc2" || id.Extra["account_name"] != "Beta" || id.Extra["accounts"] != "acc2,acc1" {
		t.Fatalf("identity: %+v", id)
	}
	id, err = openClient(t, srv, "good-token", "acc1").Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := id.Extra["accounts"]; has || id.Account != "acc1" {
		t.Fatalf("one account: %+v", id)
	}
	if id, err = openClient(t, srv, "good-token", "").Verify(ctx); err != nil || id.Account != "" {
		t.Fatalf("no account: %+v %v", id, err)
	}
}

func TestOwnerHint(t *testing.T) {
	p := &provider{}
	if h := p.OwnerHint(platform.ResZone, []string{"zone1", "zone3"}); !strings.Contains(h, "--account <id or name>") || !strings.Contains(h, "zone id") {
		t.Fatalf("zone hint: %q", h)
	}
	if h := p.OwnerHint(platform.ResR2Bucket, nil); h != "" {
		t.Fatalf("another type: %q", h)
	}
}

func TestCoverageChange(t *testing.T) {
	p := &provider{}
	meta := func(def, accounts string) map[string]string {
		m := map[string]string{}
		if def != "" {
			m[metaAccountID] = def
		}
		if accounts != "" {
			m[metaAccounts] = accounts
		}
		return m
	}
	for _, tc := range []struct {
		name          string
		before, after map[string]string
		dropped       []string
		changed       bool
	}{
		{"the same account", meta("acc1", ""), meta("acc1", ""), nil, false},
		{"another default of the same selection", meta("acc1", "acc1,acc2"), meta("acc2", "acc2,acc1"), nil, false},
		{"an account added", meta("acc1", ""), meta("acc1", "acc1,acc2"), nil, true},
		{"an account removed", meta("acc1", "acc1,acc2"), meta("acc1", ""), []string{"acc2"}, true},
		{"another account", meta("acc1", ""), meta("acc2", ""), []string{"acc1"}, true},
		{"the default removed", meta("acc1", "acc1,acc2,acc3"), meta("acc3", "acc3,acc2"), []string{"acc1"}, true},
		{"a login without an account gets one", meta("", ""), meta("acc1", ""), nil, true},
		{"a login loses its account", meta("acc1", ""), meta("", ""), []string{"acc1"}, true},
		{"no account before or after", meta("", ""), meta("", ""), nil, false},
	} {
		dropped, changed := p.CoverageChange(tc.before, tc.after)
		if !reflect.DeepEqual(dropped, tc.dropped) || changed != tc.changed {
			t.Errorf("%s: dropped %v changed %v, want %v %v", tc.name, dropped, changed, tc.dropped, tc.changed)
		}
	}
}

// The hint of an ambiguous zone names what tells the candidates apart: the
// flags whose value differs among them, and the zone id only when the ids
// differ (the same zone seen through two logins has one id).
func TestZoneHint(t *testing.T) {
	a := zoneCand{profile: "both", account: "acc1", id: "z1"}
	b := zoneCand{profile: "both", account: "acc2", id: "z2"}
	c := zoneCand{profile: "beta", account: "acc2", id: "z2"}
	d := zoneCand{profile: "beta", account: "acc3", id: "z3"}
	for _, tc := range []struct {
		name  string
		cands []zoneCand
		want  string
	}{
		{"two accounts of one login", []zoneCand{a, b}, "pass --account <id or name>, or the zone id, to choose"},
		{"one zone through two logins", []zoneCand{b, c}, "pass --profile <name> to choose"},
		{"two logins and two accounts", []zoneCand{a, d}, "pass --profile <name> or --account <id or name>, or the zone id, to choose"},
		{"nothing but the id differs", []zoneCand{a, {profile: "both", account: "acc1", id: "z9"}}, "pass the zone id to choose"},
	} {
		if got := zoneHint(tc.cands); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}
