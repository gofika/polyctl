package godaddy

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

const (
	testKey, testSecret = "key123456789", "secretABC"
	testToken           = "pat_token_0123456789"
)

var (
	legacyCred = credentials{key: testKey, secret: testSecret}
	patCred    = credentials{token: testToken}
)

// newTestClient returns a PAT-authenticated client against the fake with
// Sync pacing and generic retries disabled.
func newTestClient(t *testing.T) (*fakeGoDaddy, *client) {
	t.Helper()
	f, srv := newFake(t, testKey, testSecret)
	c := newClient(srv.URL, envOTE, patCred)
	c.api.http.MaxRetries = 0
	c.pace = 0
	return f, c
}

func TestAuthorizationHeaders(t *testing.T) {
	ctx := context.Background()
	if got := patCred.authorization(); got != "Bearer "+testToken {
		t.Errorf("pat header: %q", got)
	}
	if got := legacyCred.authorization(); got != "sso-key "+testKey+":"+testSecret {
		t.Errorf("legacy header: %q", got)
	}
	for _, tc := range []struct {
		name   string
		cred   credentials
		method string
	}{{"pat", patCred, methodPAT}, {"legacy", legacyCred, methodAPIKey}} {
		f, srv := newFake(t, testKey, testSecret)
		f.addDomain("example.com")
		c := newClient(srv.URL, envOTE, tc.cred)
		c.api.http.MaxRetries = 0
		id, err := c.Verify(ctx)
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if id.Extra["method"] != tc.method || !strings.Contains(id.Account, tc.cred.prefix()) {
			t.Errorf("%s identity: %+v", tc.name, id)
		}
		if strings.Contains(id.Account, testToken) || strings.Contains(id.Account, testSecret) || strings.Contains(id.Account, testToken[:6]) {
			t.Errorf("%s identity leaks the credential: %+v", tc.name, id)
		}
	}
	// A token wins over a key pair; a key pair without a token is legacy.
	both := credentials{token: testToken, key: "k", secret: "s"}
	if both.method() != methodPAT || len(both.secretMap()) != 1 || both.secretMap()["token"] != testToken {
		t.Errorf("token must take precedence: %+v", both.secretMap())
	}
	if (credentials{key: "k"}).complete() || !(credentials{key: "k", secret: "s"}).complete() {
		t.Error("completeness")
	}
}

func TestListDomainsPagination(t *testing.T) {
	f, c := newTestClient(t)
	for i := 0; i < 7; i++ {
		f.addDomain(fmt.Sprintf("d%02d.example", i), "ns1.test", "ns2.test")
	}
	c.api.domainPageSize = 3
	domains, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 7 {
		t.Fatalf("expected 7 unique domains, got %d: %+v", len(domains), domains)
	}
	seen := map[string]bool{}
	for _, d := range domains {
		if seen[d.Name] {
			t.Errorf("duplicate domain %s", d.Name)
		}
		seen[d.Name] = true
		if len(d.Nameservers) != 2 {
			t.Errorf("%s: nameservers missing (includes=nameServers not sent?)", d.Name)
		}
	}
	calls := f.callsMatching("GET /v1/domains?")
	if len(calls) < 3 {
		t.Fatalf("expected at least 3 paged calls, got %v", calls)
	}
	if !strings.Contains(calls[1], "marker=d02.example") {
		t.Errorf("second page must carry the marker of the last domain: %v", calls)
	}

	zones, err := c.ListZones(context.Background())
	if err != nil || len(zones) != 7 || zones[0].ID != zones[0].Name {
		t.Errorf("zones: %v %+v", err, zones)
	}
}

func TestListRecordsPaginationAndNames(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com", "ns1.test", "ns2.test")
	var recs []apiRecord
	for i := 0; i < 5; i++ {
		recs = append(recs, apiRecord{Type: "A", Name: fmt.Sprintf("h%d", i), Data: fmt.Sprintf("10.0.0.%d", i), TTL: 600})
	}
	recs = append(recs, apiRecord{Type: "MX", Name: "@", Data: "mail.example.com", TTL: 3600, Priority: intp(10)})
	f.setRecords("example.com", recs...)
	c.api.recordPageSize = 2

	got, err := c.ListRecords(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 6 {
		t.Fatalf("expected 6 records, got %d", len(got))
	}
	if got[0].Name != "h0.example.com" || got[0].ID != "A|h0|10.0.0.0" {
		t.Errorf("record 0: %+v", got[0])
	}
	mx := got[5]
	if mx.Name != "example.com" || mx.Priority == nil || *mx.Priority != 10 || mx.Value != "mail.example.com" {
		t.Errorf("mx: %+v", mx)
	}
	// 6 records at 2 per page: three full pages plus the empty page that
	// signals the end.
	if n := len(f.callsMatching("GET /v1/domains/example.com/records?")); n != 4 {
		t.Errorf("expected 4 page requests, got %d", n)
	}
}

func TestSync(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("a.example", "ns1.test", "ns2.test")
	f.addDomain("b.example", "ns1.test", "ns2.test")
	f.setRecords("a.example", apiRecord{Type: "A", Name: "@", Data: "1.1.1.1"}, apiRecord{Type: "A", Name: "www", Data: "1.1.1.2"})
	f.setRecords("b.example", apiRecord{Type: "TXT", Name: "@", Data: "hi"})
	ctx := context.Background()

	dom, err := c.Sync(ctx, platform.ResDomain)
	if err != nil || len(dom) != 2 || dom[0].Type != platform.ResDomain || dom[0].Domain != "a.example" || dom[0].ID != "a.example" {
		t.Errorf("sync domains: %v %+v", err, dom)
	}
	zones, err := c.Sync(ctx, platform.ResZone)
	if err != nil || len(zones) != 2 || zones[1].Type != platform.ResZone || zones[1].Domain != "b.example" {
		t.Errorf("sync zones: %v %+v", err, zones)
	}
	recs, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil || len(recs) != 3 {
		t.Fatalf("sync records: %v %+v", err, recs)
	}
	for _, r := range recs {
		if r.ParentID == "" || r.Domain == "" || r.ParentID != r.Domain {
			t.Errorf("record resource must carry zone id and domain: %+v", r)
		}
		rec, ok := r.Data.(platform.Record)
		if !ok || rec.ZoneID != r.ParentID || !strings.HasSuffix(rec.Name, r.Domain) {
			t.Errorf("record data: %+v", r.Data)
		}
	}
	if _, err := c.Sync(ctx, platform.ResInstance); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("unsupported type: %v", err)
	}
}

func TestSyncHonoursRateLimitReset(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("a.example", "ns1.test", "ns2.test")
	f.addDomain("b.example", "ns1.test", "ns2.test")
	f.setRecords("a.example", apiRecord{Type: "A", Name: "@", Data: "1.1.1.1"})
	f.setRecords("b.example", apiRecord{Type: "A", Name: "@", Data: "2.2.2.2"})
	// The second domain's listing is rate limited once; the generic httpx
	// retries are off, so the retry must come from the RateLimit-Reset wait.
	f.rateLimitOnce = "GET /v1/domains/b.example/records"

	start := time.Now()
	recs, err := c.Sync(context.Background(), platform.ResDNSRecord)
	if err != nil {
		t.Fatalf("sync must survive a 429 with RateLimit-Reset: %v", err)
	}
	if len(recs) != 2 {
		t.Fatalf("expected 2 records, got %+v", recs)
	}
	if f.rateLimited != 1 {
		t.Errorf("expected one 429, got %d", f.rateLimited)
	}
	if n := len(f.callsMatching("GET /v1/domains/b.example/records")); n != 2 {
		t.Errorf("expected the limited request to be retried once, got %d calls", n)
	}
	if time.Since(start) < 900*time.Millisecond {
		t.Errorf("client did not wait for RateLimit-Reset (took %s)", time.Since(start))
	}
}

func TestSyncPacesRequests(t *testing.T) {
	f, c := newTestClient(t)
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		f.addDomain(d, "ns1.test", "ns2.test")
		f.setRecords(d, apiRecord{Type: "A", Name: "@", Data: "1.1.1.1"})
	}
	c.pace = 50 * time.Millisecond
	start := time.Now()
	if _, err := c.Sync(context.Background(), platform.ResDNSRecord); err != nil {
		t.Fatal(err)
	}
	if el := time.Since(start); el < 100*time.Millisecond {
		t.Errorf("three domains at 50ms pace should take >=100ms, took %s", el)
	}
	// Cancellation during the pace wait is honoured.
	ctx, cancel := context.WithCancel(context.Background())
	c.pace = time.Hour
	go func() { time.Sleep(20 * time.Millisecond); cancel() }()
	if _, err := c.Sync(ctx, platform.ResDNSRecord); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled while pacing, got %v", err)
	}
}

func TestRetryDelay(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := http.Header{}
	if d := retryDelay(h, now); d != 0 {
		t.Errorf("no header: %s", d)
	}
	h.Set("RateLimit-Reset", "7")
	if d := retryDelay(h, now); d != 7*time.Second {
		t.Errorf("RateLimit-Reset: %s", d)
	}
	h.Set("RateLimit-Reset", "0")
	if d := retryDelay(h, now); d != time.Second {
		t.Errorf("zero rounds up: %s", d)
	}
	h = http.Header{}
	h.Set("Retry-After", now.Add(90*time.Second).UTC().Format(http.TimeFormat))
	if d := retryDelay(h, now); d != 90*time.Second {
		t.Errorf("Retry-After date: %s", d)
	}
	h.Set("Retry-After", "garbage")
	h.Set("RateLimit-Reset", "3")
	if d := retryDelay(h, now); d != 3*time.Second {
		t.Errorf("fallback to RateLimit-Reset: %s", d)
	}
}

func TestUpdateRecordRenameFailures(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com", "ns1.test", "ns2.test")
	f.setRecords("example.com", apiRecord{Type: "A", Name: "www", Data: "1.1.1.1", TTL: 600})
	ctx := context.Background()

	// The add (PATCH) fails: the original record must survive untouched.
	f.failPatch = true
	_, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: "A|www|1.1.1.1", Name: "api.example.com", Type: "A", Value: "1.1.1.1", TTL: 600})
	if err == nil {
		t.Fatal("expected the failed PATCH to be reported")
	}
	if got := f.getRecords("example.com"); len(got) != 1 || got[0].Name != "www" || got[0].Data != "1.1.1.1" {
		t.Fatalf("old record lost after a failed add: %+v", got)
	}
	if n := len(f.callsMatching("DELETE ")) + len(f.callsMatching("PUT ")); n != 0 {
		t.Errorf("nothing may be removed before the add succeeds: %v %v", f.callsMatching("DELETE "), f.callsMatching("PUT "))
	}

	// A missing source record is reported before anything is written.
	f.failPatch = false
	if _, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: "A|www|9.9.9.9", Name: "api.example.com", Type: "A", Value: "9.9.9.9"}); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("stale id on rename: %v", err)
	}
	if n := len(f.callsMatching("PATCH /v1/domains/example.com/records")); n != 1 {
		t.Errorf("no PATCH for a missing source record, got %d", n)
	}

	// The add succeeds but the removal fails: both records exist and the
	// error tells the user how to delete the old one.
	f.setRecords("example.com", apiRecord{Type: "A", Name: "www", Data: "1.1.1.1", TTL: 600}, apiRecord{Type: "A", Name: "www", Data: "1.1.1.2", TTL: 600})
	f.failPut = true
	_, err = c.UpdateRecord(ctx, "example.com", platform.Record{ID: "A|www|1.1.1.1", Name: "api.example.com", Type: "A", Value: "1.1.1.1", TTL: 600})
	if err == nil || !strings.Contains(err.Error(), "A|api|1.1.1.1") || !strings.Contains(err.Error(), `--id "A|www|1.1.1.1"`) {
		t.Fatalf("removal failure must name both records: %v", err)
	}
	if got := f.getRecords("example.com"); len(got) != 3 {
		t.Fatalf("expected old and new records to coexist: %+v", got)
	}
}

func TestCreateUpdateDeleteRecord(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com", "ns1.test", "ns2.test")
	f.setRecords("example.com", apiRecord{Type: "A", Name: "www", Data: "1.1.1.1", TTL: 600})
	ctx := context.Background()

	// Create: PATCH add, existing record kept.
	created, err := c.CreateRecord(ctx, "example.com", platform.Record{Name: "www.example.com", Type: "a", Value: "2.2.2.2", TTL: 600})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "A|www|2.2.2.2" || created.Name != "www.example.com" {
		t.Errorf("created: %+v", created)
	}
	if got := f.getRecords("example.com"); len(got) != 2 {
		t.Fatalf("after create: %+v", got)
	}

	// Update in place (same type+name): PUT with the entry swapped.
	updated, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: created.ID, Name: "www.example.com", Type: "A", Value: "3.3.3.3", TTL: 900})
	if err != nil {
		t.Fatal(err)
	}
	if updated.ID != "A|www|3.3.3.3" || updated.TTL != 900 {
		t.Errorf("updated: %+v", updated)
	}
	got := f.getRecords("example.com")
	if len(got) != 2 || got[0].Data != "1.1.1.1" || got[1].Data != "3.3.3.3" || got[1].TTL != 900 {
		t.Fatalf("after update: %+v", got)
	}
	if n := len(f.callsMatching("PUT /v1/domains/example.com/records/A/www")); n != 1 {
		t.Errorf("expected one PUT, got %d", n)
	}

	// Update with a name change: old removed from its set, new added.
	moved, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: updated.ID, Name: "api.example.com", Type: "A", Value: "3.3.3.3", TTL: 900})
	if err != nil {
		t.Fatal(err)
	}
	if moved.ID != "A|api|3.3.3.3" {
		t.Errorf("moved: %+v", moved)
	}
	got = f.getRecords("example.com")
	names := map[string]string{}
	for _, r := range got {
		names[r.Name] = r.Data
	}
	if len(got) != 2 || names["www"] != "1.1.1.1" || names["api"] != "3.3.3.3" {
		t.Fatalf("after move: %+v", got)
	}

	// Update of an id whose data no longer exists.
	if _, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: "A|www|9.9.9.9", Name: "www.example.com", Type: "A", Value: "1.1.1.1"}); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("stale id: expected ErrNotFound, got %v", err)
	}
	if _, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: "garbage", Name: "www.example.com", Type: "A", Value: "1.1.1.1"}); !errors.Is(err, ErrBadRecordID) {
		t.Errorf("bad id: %v", err)
	}

	// Delete one value of a multi-value set -> PUT remaining.
	f.setRecords("example.com", apiRecord{Type: "A", Name: "www", Data: "1.1.1.1"}, apiRecord{Type: "A", Name: "www", Data: "2.2.2.2"}, apiRecord{Type: "TXT", Name: "@", Data: "keep"})
	if err := c.DeleteRecord(ctx, "example.com", "A|www|1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	got = f.getRecords("example.com")
	if len(got) != 2 || got[1].Data != "2.2.2.2" || got[0].Data != "keep" {
		t.Fatalf("after partial delete: %+v", got)
	}
	// Delete the last value -> DELETE of the set.
	if err := c.DeleteRecord(ctx, "example.com", "A|www|2.2.2.2"); err != nil {
		t.Fatal(err)
	}
	got = f.getRecords("example.com")
	if len(got) != 1 || got[0].Type != "TXT" {
		t.Fatalf("after full delete: %+v", got)
	}
	if n := len(f.callsMatching("DELETE /v1/domains/example.com/records/A/www")); n != 1 {
		t.Errorf("expected one DELETE, got %d", n)
	}
	if err := c.DeleteRecord(ctx, "example.com", "A|www|2.2.2.2"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("deleting a missing record: %v", err)
	}
}

func TestReplaceAndDeleteSet(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com", "ns1.test", "ns2.test")
	f.setRecords("example.com", apiRecord{Type: "A", Name: "www", Data: "1.1.1.1"}, apiRecord{Type: "A", Name: "@", Data: "5.5.5.5"})
	ctx := context.Background()

	out, err := c.ReplaceRecords(ctx, "example.com", "a", "www", []platform.Record{{Value: "2.2.2.2", TTL: 600}, {Value: "3.3.3.3", TTL: 600}})
	if err != nil {
		t.Fatal(err)
	}
	if len(out) != 2 || out[0].Name != "www.example.com" || out[1].ID != "A|www|3.3.3.3" {
		t.Errorf("replace result: %+v", out)
	}
	got := f.getRecords("example.com")
	if len(got) != 3 || got[0].Data != "5.5.5.5" || got[1].Data != "2.2.2.2" || got[2].Data != "3.3.3.3" {
		t.Fatalf("after replace: %+v", got)
	}
	if err := c.DeleteRecordSet(ctx, "example.com", "A", "www"); err != nil {
		t.Fatal(err)
	}
	if got := f.getRecords("example.com"); len(got) != 1 || got[0].Name != "@" {
		t.Fatalf("after delete set: %+v", got)
	}
	// Apex: "@" must be used in the path.
	if _, err := c.ReplaceRecords(ctx, "example.com", "TXT", "@", []platform.Record{{Value: "v=spf1 -all"}}); err != nil {
		t.Fatal(err)
	}
	if n := len(f.callsMatching("PUT /v1/domains/example.com/records/TXT/@")); n != 1 {
		t.Errorf("apex PUT path: %v", f.callsMatching("PUT "))
	}
}

func TestRegistrarOperations(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com", "ns1.test", "ns2.test")
	ctx := context.Background()

	d, err := c.GetDomain(ctx, "Example.COM")
	if err != nil || d.Name != "example.com" || d.Status != "ACTIVE" || d.Locked == nil || !*d.Locked {
		t.Fatalf("get: %v %+v", err, d)
	}
	if _, err := c.GetDomain(ctx, "missing.example"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing domain: %v", err)
	}
	if err := c.SetNameservers(ctx, "example.com", []string{"NS1.new.", "ns2.new"}); err != nil {
		t.Fatal(err)
	}
	if err := c.SetNameservers(ctx, "example.com", []string{"only.one"}); err == nil {
		t.Error("a single nameserver must be rejected")
	}
	if err := c.SetLocked(ctx, "example.com", false); err != nil {
		t.Fatal(err)
	}
	if err := c.SetAutoRenew(ctx, "example.com", true); err != nil {
		t.Fatal(err)
	}
	d, _ = c.GetDomain(ctx, "example.com")
	if strings.Join(d.Nameservers, ",") != "ns1.new,ns2.new" || *d.Locked || !*d.AutoRenew {
		t.Errorf("after patches: %+v", d)
	}
	a, err := c.CheckAvailable(ctx, "free-name.example")
	if err != nil || !a.Available || a.Price != 12990000 || a.Currency != "USD" {
		t.Errorf("available: %v %+v", err, a)
	}
}

func TestErrorMapping(t *testing.T) {
	f, srv := newFake(t, testKey, testSecret)
	f.addDomain("example.com")
	ctx := context.Background()

	bad := newClient(srv.URL, envOTE, credentials{key: testKey, secret: "wrong"})
	bad.api.http.MaxRetries = 0
	_, err := bad.ListDomains(ctx)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("401 must map to ErrUnauthorized, got %v", err)
	}
	if !strings.Contains(err.Error(), "UNABLE_TO_AUTHENTICATE") {
		t.Errorf("error should carry the GoDaddy code: %v", err)
	}
	if strings.Contains(err.Error(), "wrong") || strings.Contains(err.Error(), testKey) {
		t.Errorf("error must not contain credentials: %v", err)
	}

	good := newClient(srv.URL, envOTE, legacyCred)
	good.api.http.MaxRetries = 0
	if _, err := good.ListRecords(ctx, "nope.example"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("404 must map to ErrNotFound, got %v", err)
	}

	f.accessDenied = true
	_, err = good.ListDomains(ctx)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("403 must map to ErrUnauthorized, got %v", err)
	}
	if !strings.Contains(err.Error(), "at least one domain") || !strings.Contains(err.Error(), "env=ote") {
		t.Errorf("ACCESS_DENIED should explain the documented requirement: %v", err)
	}
	if strings.Contains(err.Error(), "Discount Domain Club") || strings.Contains(err.Error(), "10 domains") {
		t.Errorf("ACCESS_DENIED must not state the outdated policy: %v", err)
	}
	var ae *apiError
	if !errors.As(err, &ae) || ae.Code != "ACCESS_DENIED" {
		t.Errorf("expected apiError with code, got %#v", err)
	}
}

func TestContextCancellation(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListDomains(ctx); !errors.Is(err, context.Canceled) {
		t.Errorf("expected context.Canceled, got %v", err)
	}
}
