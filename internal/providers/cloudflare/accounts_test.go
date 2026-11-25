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

func TestDisabledAccounts(t *testing.T) {
	cases := []struct {
		name string
		meta map[string]string
		want []string
	}{
		{"nothing stored", map[string]string{}, nil},
		{"a login bound to one account", map[string]string{metaAccountID: "acc1"}, nil},
		{"stored order", map[string]string{metaAccountID: "acc1", metaDisabledAccounts: "acc3,acc2"}, []string{"acc3", "acc2"}},
		{"blanks and repeats", map[string]string{metaAccountID: "acc1", metaDisabledAccounts: " acc2, ,acc2,acc3,"}, []string{"acc2", "acc3"}},
		{"the default account cannot be disabled", map[string]string{metaAccountID: " acc1 ", metaDisabledAccounts: "acc1,acc2"}, []string{"acc2"}},
		{"a login without a default account", map[string]string{metaDisabledAccounts: "acc2"}, []string{"acc2"}},
		// The selection of a login made before is not read any more.
		{"the former selection", map[string]string{metaAccountID: "acc1", legacyAccounts: "acc1,acc2"}, nil},
	}
	for _, c := range cases {
		if got := disabledAccounts(c.meta); !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

func TestSetAccounts(t *testing.T) {
	meta := map[string]string{metaMethod: storedToken, metaAccountID: "acc1", metaAccountName: "Acme", legacyAccounts: "acc1,acc2"}
	setAccounts(meta, account{ID: "acc2", Name: "Beta"}, []string{"acc3", "acc1", "acc3", "acc2"})
	// Sorted, without repeats and without the default; the former
	// selection is dropped.
	if meta[metaAccountID] != "acc2" || meta[metaAccountName] != "Beta" || meta[metaDisabledAccounts] != "acc1,acc3" || meta[metaMethod] != storedToken {
		t.Fatalf("several: %v", meta)
	}
	if _, ok := meta[legacyAccounts]; ok {
		t.Fatalf("the former selection was kept: %v", meta)
	}
	// Nothing disabled is stored without the key; an unknown name does not
	// keep the old one.
	setAccounts(meta, account{ID: "acc1"}, nil)
	if _, ok := meta[metaDisabledAccounts]; ok || meta[metaAccountID] != "acc1" {
		t.Fatalf("none disabled: %v", meta)
	}
	if _, ok := meta[metaAccountName]; ok {
		t.Fatalf("the name of another account was kept: %v", meta)
	}
	// A login without a default account stores its disabled accounts
	// alone.
	setAccounts(meta, account{Name: "ignored"}, []string{"acc9"})
	if _, ok := meta[metaAccountID]; ok || meta[metaDisabledAccounts] != "acc9" {
		t.Fatalf("no default: %v", meta)
	}
	if _, ok := meta[metaAccountName]; ok {
		t.Fatalf("a name without an account: %v", meta)
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

func TestAPICovers(t *testing.T) {
	a := newAPI("http://unused", "tok", "")
	if !a.unbound() || !a.covers("anything") || !a.covers("") {
		t.Fatalf("a login without a default account: %+v", a)
	}
	a = newAPI("http://unused", "tok", "acc1")
	a.disabled = []string{"acc3"}
	if a.unbound() || !a.covers("acc1") || !a.covers("acc2") || a.covers("acc3") || !a.covers("") {
		t.Fatalf("disabled: %+v", a)
	}
	in := a.inAccount("acc2")
	if in.accountID != "acc2" || in.covers("acc3") || a.accountID != "acc1" {
		t.Fatalf("inAccount: %+v", in)
	}
	// --account covers its account alone, disabled or not.
	pin := a.pin("acc3")
	if !pin.covers("acc3") || pin.covers("acc1") || a.pinned {
		t.Fatalf("pin: %+v", pin)
	}
	if p := newAPI("http://unused", "tok", "").pin("acc1"); p.unbound() || p.covers("acc2") {
		t.Fatalf("pin of a login without a default account: %+v", p)
	}
}

// A login bound to one account, as every login before polyctl 0.5 was,
// works on every account its credentials see: its lists and lookups make
// one request each, without an account filter.
func TestBoundLoginRequests(t *testing.T) {
	f, srv := newFake(t)
	c := openClient(t, srv, "good-token", "acc2")
	ctx := context.Background()
	zones, err := c.ListZones(ctx)
	if err != nil || len(zones) != 2 {
		t.Fatalf("zones: %+v %v", zones, err)
	}
	if z, err := c.GetZone(ctx, "Example.ORG."); err != nil || z.ID != "zone2" {
		t.Fatalf("by name: %v %v", z, err)
	}
	if z, err := c.GetZone(ctx, "example.com"); err != nil || z.ID != "zone1" {
		t.Fatalf("by name, in another account than the default: %v %v", z, err)
	}
	if z, err := c.GetZone(ctx, "zone2"); err != nil || z.ID != "zone2" {
		t.Fatalf("by id: %v %v", z, err)
	}
	want := []string{
		"GET /zones?page=1&per_page=50",
		"GET /zones?name=example.org&page=1&per_page=50",
		"GET /zones?name=example.com&page=1&per_page=50",
		"GET /zones/zone2",
	}
	if got := f.reqs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests:\n got %q\nwant %q", got, want)
	}
	// A login without a default account makes the same requests.
	c = openClient(t, srv, "good-token", "")
	if _, err := c.ListZones(ctx); err != nil {
		t.Fatal(err)
	}
	if got, want := f.reqs(), []string{"GET /zones?page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests without a default account: %q", got)
	}
}

func TestListZonesOfTheEnabledAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.addZone("zone3", "example.net", "active", "acc3", "Gamma")
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc2", metaDisabledAccounts: "acc3"})
	zones, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	// One listing of everything, without the zones of a disabled account.
	if len(zones) != 2 || zones[0].ID != "zone1" || zones[1].ID != "zone2" {
		t.Fatalf("zones: %+v", zones)
	}
	if got, want := f.reqs(), []string{"GET /zones?page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
	// --account reads that account alone, disabled or not, with the filter
	// of the API.
	zones, err = c.pin("acc3").ListZones(context.Background())
	if err != nil || len(zones) != 1 || zones[0].ID != "zone3" {
		t.Fatalf("pinned: %+v %v", zones, err)
	}
	if got, want := f.reqs(), []string{"GET /zones?account.id=acc3&page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("pinned requests: %q", got)
	}
}

func TestGetZoneAmongTheEnabledAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.addZone("zone3", "example.com", "pending", "acc2", "Beta")
	f.addZone("zone4", "example.net", "active", "acc3", "Gamma")
	ctx := context.Background()
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaDisabledAccounts: "acc3"})

	// A name of another account than the default is found.
	if z, err := c.GetZone(ctx, "example.org"); err != nil || z.ID != "zone2" {
		t.Fatalf("second account: %v %v", z, err)
	}
	// A name held by two enabled accounts is ambiguous (exit code 5), with
	// one request.
	f.reqs()
	_, err := c.GetZone(ctx, "example.com")
	if !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("want ErrAmbiguous, got %v", err)
	}
	if got, want := f.reqs(), []string{"GET /zones?name=example.com&page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
	for _, want := range []string{"zone example.com is held by 2 of the enabled accounts", "zone1 in account acc1 (Acme)", "zone3 in account acc2 (Beta)", "zone id", "--account <id or name>"} {
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
	// Disabling one of the two accounts leaves one zone of the name.
	d := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaDisabledAccounts: "acc2,acc3"})
	if z, err := d.GetZone(ctx, "example.com"); err != nil || z.ID != "zone1" {
		t.Fatalf("after disabling the other account: %v %v", z, err)
	}

	// A zone of a disabled account is not found (exit code 4), by name and
	// by id, and the id says where it is.
	if _, err := c.GetZone(ctx, "example.net"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("disabled by name: %v", err)
	}
	_, err = c.GetZone(ctx, "zone4")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("disabled by id: %v", err)
	}
	for _, want := range []string{"zone example.net (zone4) is in account acc3, which is disabled for this login", "polyctl cloudflare account enable acc3", "--account acc3"} {
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

	// A login without a default account works the same way.
	u := openClient(t, srv, "good-token", "")
	if z, err := u.GetZone(ctx, "zone4"); err != nil || z.ID != "zone4" {
		t.Fatalf("no default, by id: %v %v", z, err)
	}
	if _, err := u.GetZone(ctx, "example.com"); !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "2 of the enabled accounts of this login") {
		t.Fatalf("no default, by name: %v", err)
	}
}

// An account-owned token verifies at the account that owns it: the default
// account is tried first, then the accounts the token lists.
func TestVerifyTokenTriesTheVisibleAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.accountOwned = "acc2"
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1"})
	tok, err := c.api.verifyToken(context.Background())
	if err != nil || tok.AccountID != "acc2" {
		t.Fatalf("verify: %+v %v", tok, err)
	}
	want := []string{"GET /user/tokens/verify", "GET /accounts/acc1/tokens/verify", "GET /accounts?page=1&per_page=50", "GET /accounts/acc2/tokens/verify"}
	if got := f.reqs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
	// The token of the default account needs no listing.
	c = openSelection(t, srv, map[string]string{metaAccountID: "acc2"})
	if tok, err = c.api.verifyToken(context.Background()); err != nil || tok.AccountID != "acc2" {
		t.Fatalf("verify at the default account: %+v %v", tok, err)
	}
	want = []string{"GET /user/tokens/verify", "GET /accounts/acc2/tokens/verify"}
	if got := f.reqs(); !reflect.DeepEqual(got, want) {
		t.Fatalf("requests at the default account: %q", got)
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

// A sync covers every account the credentials see, minus the disabled
// ones: one zone listing without an account filter, which the record sync
// of the same run reuses.
func TestSyncOfTheEnabledAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.addZone("zone3", "example.net", "active", "acc3", "Gamma")
	// A login of polyctl 0.4.0: bound to one account, nothing else stored.
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1"})
	ctx := context.Background()

	zones, err := c.Sync(ctx, platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	// Each zone under its account.
	if got, want := rowIDs(zones), []string{"zone1 acc1", "zone2 acc2", "zone3 acc3"}; !reflect.DeepEqual(got, want) {
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
	// One /zones request for both syncs, none with an account filter, and
	// one record listing (three pages for zone1) per zone.
	var zoneLists, recordLists int
	for _, r := range f.reqs() {
		switch {
		case strings.Contains(r, "account.id"):
			t.Errorf("a request filters by account: %s", r)
		case strings.HasPrefix(r, "GET /zones?"):
			zoneLists++
		case strings.Contains(r, "/dns_records"):
			recordLists++
		}
	}
	if zoneLists != 1 || recordLists != 5 {
		t.Fatalf("%d zone listings and %d record listings, want 1 and 5", zoneLists, recordLists)
	}
	// The listing is reused once: a record sync on its own lists the zones.
	if _, err := c.Sync(ctx, platform.ResDNSRecord); err != nil {
		t.Fatal(err)
	}
	if got := f.reqs(); len(got) == 0 || got[0] != "GET /zones?page=1&per_page=50" {
		t.Fatalf("a record sync alone: %q", got)
	}

	// A disabled account is left out of both, and its zones are not asked
	// for their records.
	d := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaDisabledAccounts: "acc2"})
	if zones, err = d.Sync(ctx, platform.ResZone); err != nil || !reflect.DeepEqual(rowIDs(zones), []string{"zone1 acc1", "zone3 acc3"}) {
		t.Fatalf("with a disabled account: %v %v", rowIDs(zones), err)
	}
	f.reqs()
	if recs, err = d.Sync(ctx, platform.ResDNSRecord); err != nil || len(recs) != 8 {
		t.Fatalf("records with a disabled account: %d %v", len(recs), err)
	}
	for _, r := range f.reqs() {
		if strings.Contains(r, "/zones/zone2/") || strings.HasPrefix(r, "GET /zones?") {
			t.Errorf("unexpected request: %s", r)
		}
	}
}

// A token without Account:Read syncs the zones of everything it sees all
// the same: the zone listing needs no account list.
func TestSyncZonesWithoutAccountRead(t *testing.T) {
	f, srv := newFake(t)
	f.forbidAccounts = true
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1"})
	zones, err := c.Sync(context.Background(), platform.ResZone)
	if err != nil || !reflect.DeepEqual(rowIDs(zones), []string{"zone1 acc1", "zone2 acc2"}) {
		t.Fatalf("zones: %v %v", rowIDs(zones), err)
	}
	if got, want := f.reqs(), []string{"GET /zones?page=1&per_page=50"}; !reflect.DeepEqual(got, want) {
		t.Fatalf("requests: %q", got)
	}
}

func TestSyncKeepsAFailedAccount(t *testing.T) {
	f, srv := newFake(t)
	f.failRecords = map[string]int{"zone2": 400}
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1"})
	ctx := context.Background()

	// A zone whose records fail makes its account a failed tree: the rows
	// of the other account are returned.
	res, err := c.Sync(ctx, platform.ResDNSRecord)
	rse := platform.AsRegionSyncError(err)
	if rse == nil {
		t.Fatalf("want a RegionSyncError, got %v", err)
	}
	if len(rse.Failures) != 1 || rse.Failures[0].Region != "acc2" || !rse.Failures[0].Tree || rse.Noun != "account" {
		t.Fatalf("failures: %+v", rse)
	}
	if !strings.Contains(err.Error(), "polyctl cloudflare account disable acc2") {
		t.Errorf("the failure does not say how to keep the account out: %v", err)
	}
	if len(res) != 8 {
		t.Fatalf("rows of the other account: %d", len(res))
	}
	for _, r := range res {
		if r.ParentID != "zone1" {
			t.Fatalf("row of the failed account: %+v", r)
		}
	}

	// Every account failing is a plain error with the cause (and so the
	// exit code) of the first.
	f.failRecords = map[string]int{"zone1": 500, "zone2": 400}
	res, err = c.Sync(ctx, platform.ResDNSRecord)
	if err == nil || platform.AsRegionSyncError(err) != nil || res != nil {
		t.Fatalf("every account failed: %v %v", res, err)
	}
	if !strings.Contains(err.Error(), "every enabled account failed") {
		t.Errorf("%v", err)
	}

	// Zones of one account alone fail as a plain error.
	f.failRecords = map[string]int{"zone1": 400}
	one := openSelection(t, srv, map[string]string{metaAccountID: "acc1", metaDisabledAccounts: "acc2"})
	if _, err := one.Sync(ctx, platform.ResDNSRecord); err == nil || platform.AsRegionSyncError(err) != nil || strings.Contains(err.Error(), "account disable") {
		t.Fatalf("one account: %v", err)
	}

	// The zone listing is one request for every account: when it fails,
	// the zone sync and the record sync fail as a whole, and nothing is
	// replaced.
	f.failRecords = nil
	f.failZones = map[string]int{"": 400}
	for _, typ := range []platform.ResourceType{platform.ResZone, platform.ResDNSRecord} {
		res, err := c.Sync(ctx, typ)
		if err == nil || platform.AsRegionSyncError(err) != nil || res != nil {
			t.Fatalf("%s: a failed listing: %v %v", typ, res, err)
		}
	}
}

// The zones whose records the token cannot read are skipped across the
// accounts: an account without any readable zone is no failure while
// another account has one.
func TestSyncRecordsSkipsAcrossAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.forbidRecords["zone2"] = true
	warned := captureWarnings(t)
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc1"})
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

// The accounts the per-account requests (R2) cover are asked of the
// credentials once per opened client.
func TestEnabledAccounts(t *testing.T) {
	f, srv := newFake(t)
	f.accounts = append(f.accounts, map[string]any{"id": "acc0", "name": "Zero", "type": "standard"}, map[string]any{"id": "acc3", "name": "Gamma", "type": "standard"})
	ctx := context.Background()
	c := openSelection(t, srv, map[string]string{metaAccountID: "acc2", metaDisabledAccounts: "acc3"})
	for i := 0; i < 2; i++ {
		ids, err := c.inAccount("acc1").enabledAccounts(ctx)
		// The default account first, the others by id, none disabled.
		if err != nil || !reflect.DeepEqual(ids, []string{"acc2", "acc0", "acc1"}) {
			t.Fatalf("enabled: %v %v", ids, err)
		}
	}
	if n := f.count("GET /accounts"); n != 2 { // two pages, once
		t.Fatalf("%d account listings, want one of two pages", n)
	}
	// --account is that account, without a request.
	f.reqs()
	if ids, err := c.pin("acc3").enabledAccounts(ctx); err != nil || !reflect.DeepEqual(ids, []string{"acc3"}) || len(f.reqs()) != 0 {
		t.Fatalf("pinned: %v %v", ids, err)
	}
	// A login without a default account covers what its credentials list.
	u := openSelection(t, srv, map[string]string{metaDisabledAccounts: "acc0"})
	if ids, err := u.enabledAccounts(ctx); err != nil || !reflect.DeepEqual(ids, []string{"acc1", "acc2", "acc3"}) {
		t.Fatalf("no default: %v %v", ids, err)
	}
	// Credentials that cannot list accounts work on the default account
	// alone; without one that is an error that can be skipped.
	f.forbidAccounts = true
	c = openSelection(t, srv, map[string]string{metaAccountID: "acc2"})
	if ids, err := c.enabledAccounts(ctx); err != nil || !reflect.DeepEqual(ids, []string{"acc2"}) {
		t.Fatalf("cannot list: %v %v", ids, err)
	}
	_, err := openSelection(t, srv, nil).enabledAccounts(ctx)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "has no default account and cannot list its accounts") {
		t.Fatalf("cannot list, no default: %v", err)
	}
	// Credentials that list none: the default alone.
	f.forbidAccounts, f.accounts = false, nil
	if ids, err := openSelection(t, srv, map[string]string{metaAccountID: "acc2"}).enabledAccounts(ctx); err != nil || !reflect.DeepEqual(ids, []string{"acc2"}) {
		t.Fatalf("lists none: %v %v", ids, err)
	}
}

// whoami reports the default account, and the disabled accounts when the
// login has any.
func TestVerifyReportsTheDisabledAccounts(t *testing.T) {
	_, srv := newFake(t)
	ctx := context.Background()
	id, err := openSelection(t, srv, map[string]string{metaAccountID: "acc2", metaAccountName: "Beta", metaDisabledAccounts: "acc3,acc1", legacyAccounts: "acc1,acc2"}).Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != "acc2" || id.Extra["account_name"] != "Beta" || id.Extra["disabled_accounts"] != "acc3,acc1" {
		t.Fatalf("identity: %+v", id)
	}
	if _, has := id.Extra["accounts"]; has {
		t.Fatalf("the former selection is reported: %+v", id)
	}
	id, err = openClient(t, srv, "good-token", "acc1").Verify(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, has := id.Extra["disabled_accounts"]; has || id.Account != "acc1" {
		t.Fatalf("nothing disabled: %+v", id)
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
	meta := func(def, disabled, legacy string) map[string]string {
		m := map[string]string{}
		if def != "" {
			m[metaAccountID] = def
		}
		if disabled != "" {
			m[metaDisabledAccounts] = disabled
		}
		if legacy != "" {
			m[legacyAccounts] = legacy
		}
		return m
	}
	for _, tc := range []struct {
		name          string
		before, after map[string]string
		dropped       []string
		changed       bool
	}{
		{"the same account", meta("acc1", "", ""), meta("acc1", "", ""), nil, false},
		{"another default account", meta("acc1", "", ""), meta("acc2", "", ""), nil, false},
		{"an account disabled", meta("acc1", "", ""), meta("acc1", "acc2", ""), []string{"acc2"}, true},
		{"an account enabled again", meta("acc1", "acc2,acc3", ""), meta("acc1", "acc3", ""), nil, true},
		{"one disabled, another enabled", meta("acc1", "acc2", ""), meta("acc1", "acc3", ""), []string{"acc3"}, true},
		{"the same disabled accounts in another order", meta("acc1", "acc2,acc3", ""), meta("acc1", "acc3,acc2", ""), nil, false},
		{"the default was disabled before", meta("acc1", "acc2", ""), meta("acc2", "", ""), nil, true},
		{"a login without an account gets one", meta("", "", ""), meta("acc1", "", ""), nil, false},
		{"a login loses its account", meta("acc1", "", ""), meta("", "", ""), nil, false},
		// A login made while it held a selection covers more now.
		{"the former selection goes", meta("acc1", "", "acc1,acc2"), meta("acc1", "", ""), nil, true},
	} {
		dropped, changed := p.CoverageChange(tc.before, tc.after)
		if !reflect.DeepEqual(dropped, tc.dropped) || changed != tc.changed {
			t.Errorf("%s: dropped %v changed %v, want %v %v", tc.name, dropped, changed, tc.dropped, tc.changed)
		}
	}
}

// The hint of an ambiguous zone names what tells the candidates apart: the
// flags whose value differs among them, and the zone id only when the ids
// differ (the same zone seen through two logins has one id) and the
// command takes one.
func TestZoneHint(t *testing.T) {
	a := zoneCand{profile: "both", account: "acc1", id: "z1"}
	b := zoneCand{profile: "both", account: "acc2", id: "z2"}
	c := zoneCand{profile: "beta", account: "acc2", id: "z2"}
	d := zoneCand{profile: "beta", account: "acc3", id: "z3"}
	for _, tc := range []struct {
		name  string
		cands []zoneCand
		byID  bool
		want  string
	}{
		{"two accounts of one login", []zoneCand{a, b}, true, "pass --account <id or name>, or the zone id, to choose"},
		{"two accounts, a command without zone ids", []zoneCand{a, b}, false, "pass --account <id or name> to choose"},
		{"one zone through two logins", []zoneCand{b, c}, true, "pass --profile <name> to choose"},
		{"two logins and two accounts", []zoneCand{a, d}, true, "pass --profile <name> or --account <id or name>, or the zone id, to choose"},
		{"nothing but the id differs", []zoneCand{a, {profile: "both", account: "acc1", id: "z9"}}, true, "pass the zone id to choose"},
	} {
		if got := zoneHint(tc.cands, tc.byID); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
}

// The login help states what a login has to name: only a first
// non-interactive login of credentials that see several accounts needs the
// default account; a later one keeps what is stored.
func TestLoginHelpNamesTheAccountRule(t *testing.T) {
	h := strings.Join(strings.Fields((&provider{}).LoginHelp()), " ")
	for _, want := range []string{"The login works on every account the credentials see", "a first non-interactive login requires it when the credentials see several",
		"later login keeps the stored one", "--set disabled_accounts=<id>,<id>,...", "without it a later login keeps the stored list"} {
		if !strings.Contains(h, want) {
			t.Errorf("the login help lacks %q: %s", want, h)
		}
	}
	if strings.Contains(h, "--set accounts=") {
		t.Errorf("the login help names the former option: %s", h)
	}
}
