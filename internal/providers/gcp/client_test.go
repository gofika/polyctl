package gcp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"golang.org/x/oauth2"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/platform"
)

// fakeGoogle emulates the slices of Cloud DNS, Compute Engine, Resource
// Manager, the userinfo endpoint and the OAuth token endpoint that the
// provider talks to.
type fakeGoogle struct {
	t   *testing.T
	srv *httptest.Server

	mu       sync.Mutex
	zones    []*dns.ManagedZone
	rrsets   map[string][]*dns.ResourceRecordSet // keyed by managed zone name
	changes  []*dns.Change
	requests []string
	// status forces an HTTP error for paths containing the key.
	status map[string]int
	// pageSize controls list pagination.
	pageSize int
	tokens   int
}

func newFake(t *testing.T) *fakeGoogle {
	f := &fakeGoogle{t: t, rrsets: map[string][]*dns.ResourceRecordSet{}, status: map[string]int{}, pageSize: 2}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	f.zones = []*dns.ManagedZone{
		{Name: "example-zone", DnsName: "example.com.", Id: 1, Visibility: "public", NameServers: []string{"ns-cloud-a1.googledomains.com."}},
		{Name: "internal-zone", DnsName: "corp.internal.", Id: 2, Visibility: "private"},
		{Name: "third-zone", DnsName: "third.example.", Id: 3, Visibility: "public"},
		// Split-horizon: a private zone with the same dnsName as example-zone.
		{Name: "example-private", DnsName: "example.com.", Id: 4, Visibility: "private"},
	}
	f.rrsets["example-zone"] = []*dns.ResourceRecordSet{
		{Name: "example.com.", Type: "NS", Ttl: 21600, Rrdatas: []string{"ns-cloud-a1.googledomains.com."}},
		{Name: "example.com.", Type: "SOA", Ttl: 21600, Rrdatas: []string{"ns-cloud-a1.googledomains.com. dns-admin.google.com. 1 21600 3600 259200 300"}},
		{Name: "www.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"1.1.1.1", "2.2.2.2"}},
		{Name: "example.com.", Type: "MX", Ttl: 3600, Rrdatas: []string{"10 mail.example.com."}},
		{Name: "example.com.", Type: "TXT", Ttl: 300, Rrdatas: []string{`"v=spf1 -all"`}},
		// Geo-routed set: no rrdatas, only a routing policy.
		{Name: "geo.example.com.", Type: "A", Ttl: 60, RoutingPolicy: &dns.RRSetRoutingPolicy{Geo: &dns.RRSetRoutingPolicyGeoPolicy{
			Items: []*dns.RRSetRoutingPolicyGeoPolicyGeoPolicyItem{{Location: "us-central1", Rrdatas: []string{"10.1.1.1"}}}}}},
	}
	f.rrsets["example-private"] = []*dns.ResourceRecordSet{
		{Name: "www.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"1.1.1.1", "10.0.0.1"}},
	}
	return f
}

func (f *fakeGoogle) options() []option.ClientOption {
	return []option.ClientOption{option.WithEndpoint(f.srv.URL + "/")}
}

func (f *fakeGoogle) client(t *testing.T) *client {
	c, err := newClient(context.Background(), "proj", "me@example.com", methodADC,
		append(f.options(), option.WithTokenSource(oauth2.StaticTokenSource(&oauth2.Token{AccessToken: "test-token"})))...)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

func (f *fakeGoogle) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	path := r.URL.Path
	for key, code := range f.status {
		if (strings.HasPrefix(key, "/") && path == key) || (!strings.HasPrefix(key, "/") && strings.Contains(path, key)) {
			w.WriteHeader(code)
			fmt.Fprintf(w, `{"error":{"code":%d,"message":"forced %s","status":"FORCED"}}`, code, key)
			return
		}
	}
	if path == "/token" {
		f.tokens++
		writeJSON(w, map[string]any{"access_token": "sa-token", "token_type": "Bearer", "expires_in": 3600})
		return
	}
	if r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		fmt.Fprint(w, `{"error":{"code":401,"message":"missing bearer token"}}`)
		return
	}
	switch {
	case path == "/oauth2/v2/userinfo":
		writeJSON(w, map[string]any{"email": "me@example.com", "id": "1"})
	case path == "/v1/projects":
		writeJSON(w, map[string]any{"projects": []map[string]any{
			{"projectId": "proj", "name": "Project", "projectNumber": "123", "lifecycleState": "ACTIVE"},
			{"projectId": "other", "name": "Other", "projectNumber": "456", "lifecycleState": "ACTIVE"},
		}})
	case path == "/v1/projects/proj":
		writeJSON(w, map[string]any{"projectId": "proj", "name": "Project", "projectNumber": "123", "lifecycleState": "ACTIVE"})
	case path == "/dns/v1/projects/proj/managedZones":
		f.page(w, r, len(f.zones), func(i, j int) any { return map[string]any{"managedZones": f.zones[i:j]} })
	case strings.HasPrefix(path, "/dns/v1/projects/proj/managedZones/"):
		rest := strings.TrimPrefix(path, "/dns/v1/projects/proj/managedZones/")
		parts := strings.Split(rest, "/")
		zone := parts[0]
		var mz *dns.ManagedZone
		for _, z := range f.zones {
			if z.Name == zone {
				mz = z
			}
		}
		if mz == nil {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"error":{"code":404,"message":"zone not found"}}`)
			return
		}
		switch {
		case len(parts) == 1:
			writeJSON(w, mz)
		case parts[1] == "rrsets" && r.Method == http.MethodGet:
			q := r.URL.Query()
			var sets []*dns.ResourceRecordSet
			for _, rs := range f.rrsets[zone] {
				if n := q.Get("name"); n != "" && !strings.EqualFold(n, rs.Name) {
					continue
				}
				if ty := q.Get("type"); ty != "" && !strings.EqualFold(ty, rs.Type) {
					continue
				}
				sets = append(sets, rs)
			}
			f.page(w, r, len(sets), func(i, j int) any { return map[string]any{"rrsets": sets[i:j]} })
		case parts[1] == "changes" && r.Method == http.MethodPost:
			var ch dns.Change
			if err := json.NewDecoder(r.Body).Decode(&ch); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			if err := f.applyChange(zone, &ch); err != nil {
				w.WriteHeader(http.StatusConflict)
				fmt.Fprintf(w, `{"error":{"code":409,"message":%q}}`, err.Error())
				return
			}
			f.changes = append(f.changes, &ch)
			ch.Status = "done"
			writeJSON(w, ch)
		default:
			http.NotFound(w, r)
		}
	case path == "/projects/proj/aggregated/instances":
		inst := func(id int, name, zone, ip string) map[string]any {
			return map[string]any{"id": fmt.Sprint(id), "name": name, "status": "RUNNING",
				"zone":              "https://www.googleapis.com/compute/v1/projects/proj/zones/" + zone,
				"machineType":       "https://www.googleapis.com/compute/v1/projects/proj/zones/" + zone + "/machineTypes/e2-small",
				"networkInterfaces": []map[string]any{{"networkIP": ip, "accessConfigs": []map[string]any{{"natIP": "34." + ip}}}}}
		}
		if r.URL.Query().Get("pageToken") == "" {
			writeJSON(w, map[string]any{"nextPageToken": "p2", "items": map[string]any{
				"zones/us-central1-a": map[string]any{"instances": []any{inst(1, "web-1", "us-central1-a", "10.0.0.1")}},
				"zones/us-east1-b":    map[string]any{"warning": map[string]any{"code": "NO_RESULTS_ON_PAGE"}},
			}})
		} else {
			writeJSON(w, map[string]any{"items": map[string]any{
				"zones/europe-west1-b": map[string]any{"instances": []any{inst(2, "db-1", "europe-west1-b", "10.0.0.2")}},
			}})
		}
	case path == "/projects/proj/zones":
		writeJSON(w, map[string]any{"items": []map[string]any{{"name": "us-central1-a"}}})
	case path == "/projects/proj/zones/us-central1-a/instances/web-1/start":
		writeJSON(w, map[string]any{"name": "op-1", "status": "RUNNING", "operationType": "start"})
	case path == "/projects/proj/zones/us-central1-a/operations/op-1/wait":
		writeJSON(w, map[string]any{"name": "op-1", "status": "DONE", "operationType": "start"})
	default:
		http.NotFound(w, r)
	}
}

// page serves items[i:j] with nextPageToken "<j>" while more remain.
func (f *fakeGoogle) page(w http.ResponseWriter, r *http.Request, n int, body func(i, j int) any) {
	start := 0
	if tok := r.URL.Query().Get("pageToken"); tok != "" {
		fmt.Sscan(tok, &start)
	}
	end := start + f.pageSize
	if end > n {
		end = n
	}
	resp := body(start, end).(map[string]any)
	if end < n {
		resp["nextPageToken"] = fmt.Sprint(end)
	}
	writeJSON(w, resp)
}

func (f *fakeGoogle) applyChange(zone string, ch *dns.Change) error {
	sets := f.rrsets[zone]
	find := func(name, typ string) int {
		for i, rs := range sets {
			if rs.Name == name && rs.Type == typ {
				return i
			}
		}
		return -1
	}
	for _, d := range ch.Deletions {
		i := find(d.Name, d.Type)
		if i < 0 {
			return fmt.Errorf("deletion of missing rrset %s %s", d.Name, d.Type)
		}
		if strings.Join(sets[i].Rrdatas, ",") != strings.Join(d.Rrdatas, ",") || sets[i].Ttl != d.Ttl {
			return fmt.Errorf("deletion does not match current rrset %s %s", d.Name, d.Type)
		}
		sets = append(sets[:i], sets[i+1:]...)
	}
	for _, a := range ch.Additions {
		if find(a.Name, a.Type) >= 0 {
			return fmt.Errorf("addition of existing rrset %s %s", a.Name, a.Type)
		}
		if !strings.HasSuffix(a.Name, ".") {
			return fmt.Errorf("rrset name %q lacks trailing dot", a.Name)
		}
		sets = append(sets, &dns.ResourceRecordSet{Name: a.Name, Type: a.Type, Ttl: a.Ttl, Rrdatas: append([]string(nil), a.Rrdatas...)})
	}
	f.rrsets[zone] = sets
	return nil
}

func (f *fakeGoogle) countRequests(substr string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.Contains(r, substr) {
			n++
		}
	}
	return n
}

func (f *fakeGoogle) lastChange() *dns.Change {
	f.mu.Lock()
	defer f.mu.Unlock()
	if len(f.changes) == 0 {
		return nil
	}
	return f.changes[len(f.changes)-1]
}

func (f *fakeGoogle) rrset(zone, name, typ string) *dns.ResourceRecordSet {
	f.mu.Lock()
	defer f.mu.Unlock()
	for _, rs := range f.rrsets[zone] {
		if rs.Name == name && rs.Type == typ {
			return rs
		}
	}
	return nil
}

func TestListZonesPaginates(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	zones, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 4 {
		t.Fatalf("got %d zones: %+v", len(zones), zones)
	}
	if f.countRequests("managedZones?") != 2 || f.countRequests("pageToken=2") != 1 {
		t.Errorf("pagination requests: %v", f.requests)
	}
	// Sorted by DNS name then managed zone name, trailing dot stripped, ID
	// is the managed zone name.
	if zones[0].Name != "corp.internal" || zones[0].ID != "internal-zone" || zones[0].Status != "private" {
		t.Errorf("zone[0]: %+v", zones[0])
	}
	if zones[1].Name != "example.com" || zones[1].ID != "example-private" || zones[1].Extra["id"] != "4" {
		t.Errorf("zone[1]: %+v", zones[1])
	}
	if zones[2].Name != "example.com" || zones[2].ID != "example-zone" || zones[2].Extra["id"] != "1" {
		t.Errorf("zone[2]: %+v", zones[2])
	}

	res, err := c.Sync(context.Background(), platform.ResZone)
	if err != nil || len(res) != 4 {
		t.Fatalf("sync zones: %v %+v", err, res)
	}
	// Only public zones are indexed for domain routing; private ones stay in
	// the inventory without a Domain so `polyctl dns ...` never picks them.
	domains := map[string]string{}
	for _, r := range res {
		if r.Type != platform.ResZone {
			t.Errorf("sync zone type: %+v", r)
		}
		domains[r.ID] = r.Domain
	}
	want := map[string]string{"example-zone": "example.com", "third-zone": "third.example", "internal-zone": "", "example-private": ""}
	for id, d := range want {
		if got, ok := domains[id]; !ok || got != d {
			t.Errorf("zone %s domain = %q (present %v), want %q", id, got, ok, d)
		}
	}
}

func TestListRecordsAndSync(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	recs, err := c.ListRecords(context.Background(), "example-zone")
	if err != nil {
		t.Fatal(err)
	}
	// 6 rrsets, 7 records (www A has two values, the geo set yields one
	// read-only record); served in 3 pages of 2.
	if len(recs) != 7 {
		t.Fatalf("got %d records", len(recs))
	}
	if f.countRequests("/rrsets") != 3 {
		t.Errorf("expected 3 paged rrset requests, got %v", f.requests)
	}
	byID := map[string]platform.Record{}
	for _, r := range recs {
		if strings.HasSuffix(r.Name, ".") {
			t.Errorf("record name has trailing dot: %q", r.Name)
		}
		if r.ZoneID != "example-zone" {
			t.Errorf("zone id: %q", r.ZoneID)
		}
		byID[r.ID] = r
	}
	mx := byID["example-zone|MX|example.com|10+mail.example.com."]
	if mx.Content != "mail.example.com" || mx.Priority == nil || *mx.Priority != 10 || mx.TTL != 3600 {
		t.Errorf("MX: %+v", mx)
	}
	// TXT content is shown the way a user would type it; the raw quoted
	// rrdata stays in Extra and in the id.
	txt := byID[`example-zone|TXT|example.com|%22v%3Dspf1+-all%22`]
	if txt.Content != `v=spf1 -all` || txt.Extra["rrdata"] != `"v=spf1 -all"` {
		t.Errorf("TXT: %+v", txt)
	}
	geo := byID["example-zone|A|geo.example.com|routing-policy"]
	if geo.Name != "geo.example.com" || geo.Content != routingPolicyContent || geo.TTL != 60 || geo.Extra["routing_policy"] == nil {
		t.Errorf("geo: %+v", geo)
	}

	res, err := c.Sync(context.Background(), platform.ResDNSRecord)
	if err != nil {
		t.Fatal(err)
	}
	// 7 from example-zone, 2 from example-private, none elsewhere.
	if len(res) != 9 {
		t.Fatalf("sync records: %d", len(res))
	}
	ids := map[string]platform.Resource{}
	for _, r := range res {
		if r.Type != platform.ResDNSRecord || r.ParentID == "" || r.Domain != "example.com" {
			t.Errorf("sync resource: %+v", r)
		}
		if _, dup := ids[r.ID]; dup {
			t.Errorf("duplicate record id across zones: %s", r.ID)
		}
		ids[r.ID] = r
	}
	// Split-horizon: the same www A 1.1.1.1 exists in both zones and must
	// keep two distinct inventory rows, each pointing at its own zone.
	pub, ok1 := ids["example-zone|A|www.example.com|1.1.1.1"]
	priv, ok2 := ids["example-private|A|www.example.com|1.1.1.1"]
	if !ok1 || !ok2 || pub.ParentID != "example-zone" || priv.ParentID != "example-private" {
		t.Errorf("split-horizon rows: %v %+v / %v %+v", ok1, pub, ok2, priv)
	}
	if _, err := c.Sync(context.Background(), platform.ResDomain); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("unsupported type: %v", err)
	}
}

func TestCreateUpdateDeleteRecord(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ctx := context.Background()

	// Create adds a value to the existing set, keeping the others and the TTL.
	created, err := c.CreateRecord(ctx, "example-zone", platform.Record{Name: "www.example.com", Type: "a", Content: "3.3.3.3"})
	if err != nil {
		t.Fatal(err)
	}
	if created.ID != "example-zone|A|www.example.com|3.3.3.3" || created.Content != "3.3.3.3" || created.TTL != 300 {
		t.Errorf("created: %+v", created)
	}
	ch := f.lastChange()
	if len(ch.Deletions) != 1 || len(ch.Additions) != 1 || strings.Join(ch.Additions[0].Rrdatas, ",") != "1.1.1.1,2.2.2.2,3.3.3.3" {
		t.Errorf("create change: %+v", ch)
	}

	// Create of a brand-new set uses the default TTL and no deletion.
	cn, err := c.CreateRecord(ctx, "example-zone", platform.Record{Name: "blog.example.com", Type: "CNAME", Content: "example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if cn.Content != "example.com" || cn.TTL != defaultTTL {
		t.Errorf("cname: %+v", cn)
	}
	ch = f.lastChange()
	if len(ch.Deletions) != 0 || ch.Additions[0].Rrdatas[0] != "example.com." || ch.Additions[0].Name != "blog.example.com." || ch.Additions[0].Ttl != defaultTTL {
		t.Errorf("cname change: %+v", ch.Additions[0])
	}

	// Creating an already-present value is a no-op.
	before := f.countRequests("/changes")
	if _, err := c.CreateRecord(ctx, "example-zone", platform.Record{Name: "www.example.com", Type: "A", Content: "1.1.1.1"}); err != nil {
		t.Fatal(err)
	}
	if f.countRequests("/changes") != before {
		t.Error("duplicate create should not submit a change")
	}

	// Update replaces one value in place and can change the TTL.
	upd, err := c.UpdateRecord(ctx, "example-zone", platform.Record{ID: "example-zone|A|www.example.com|2.2.2.2", Name: "www.example.com", Type: "A", Content: "9.9.9.9", TTL: 60})
	if err != nil {
		t.Fatal(err)
	}
	if upd.ID != "example-zone|A|www.example.com|9.9.9.9" || upd.TTL != 60 {
		t.Errorf("updated: %+v", upd)
	}
	if rs := f.rrset("example-zone", "www.example.com.", "A"); strings.Join(rs.Rrdatas, ",") != "1.1.1.1,3.3.3.3,9.9.9.9" || rs.Ttl != 60 {
		t.Errorf("rrset after update: %+v", rs)
	}

	// Update with a priority change on MX rewrites the rrdata.
	mx, err := c.UpdateRecord(ctx, "example-zone", platform.Record{ID: "example-zone|MX|example.com|10+mail.example.com.", Name: "example.com", Type: "MX", Content: "mail.example.com", Priority: intp(20)})
	if err != nil {
		t.Fatal(err)
	}
	if *mx.Priority != 20 || mx.ID != "example-zone|MX|example.com|20+mail.example.com." {
		t.Errorf("mx update: %+v", mx)
	}

	// Update moving a value to another name creates a two-set change.
	moved, err := c.UpdateRecord(ctx, "example-zone", platform.Record{ID: "example-zone|A|www.example.com|9.9.9.9", Name: "api.example.com", Type: "A", Content: "9.9.9.9"})
	if err != nil {
		t.Fatal(err)
	}
	if moved.Name != "api.example.com" {
		t.Errorf("moved: %+v", moved)
	}
	if rs := f.rrset("example-zone", "www.example.com.", "A"); strings.Join(rs.Rrdatas, ",") != "1.1.1.1,3.3.3.3" {
		t.Errorf("source after move: %+v", rs)
	}

	// Delete removes one value; deleting the last value deletes the set.
	if err := c.DeleteRecord(ctx, "example-zone", "example-zone|A|www.example.com|1.1.1.1"); err != nil {
		t.Fatal(err)
	}
	if rs := f.rrset("example-zone", "www.example.com.", "A"); strings.Join(rs.Rrdatas, ",") != "3.3.3.3" {
		t.Errorf("after delete: %+v", rs)
	}
	if err := c.DeleteRecord(ctx, "example-zone", "example-zone|A|www.example.com|3.3.3.3"); err != nil {
		t.Fatal(err)
	}
	if f.rrset("example-zone", "www.example.com.", "A") != nil {
		t.Error("set should be gone after deleting the last value")
	}
	ch = f.lastChange()
	if len(ch.Additions) != 0 || len(ch.Deletions) != 1 {
		t.Errorf("last delete change: %+v", ch)
	}
	if err := c.DeleteRecord(ctx, "example-zone", "example-zone|A|www.example.com|3.3.3.3"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("deleting a missing value: %v", err)
	}
	if err := c.DeleteRecord(ctx, "example-zone", "garbage"); err == nil {
		t.Error("bad id should fail")
	}

	// An id from another managed zone is refused instead of being applied
	// to the zone given as argument (split-horizon safety).
	before = f.countRequests("/changes")
	if err := c.DeleteRecord(ctx, "example-zone", "example-private|A|www.example.com|10.0.0.1"); err == nil || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("cross-zone delete: %v", err)
	}
	if _, err := c.UpdateRecord(ctx, "example-zone", platform.Record{ID: "example-private|A|www.example.com|10.0.0.1", Content: "10.0.0.2"}); err == nil {
		t.Error("cross-zone update should fail")
	}
	if f.countRequests("/changes") != before {
		t.Error("cross-zone ids must not submit a change")
	}
	if rs := f.rrset("example-private", "www.example.com.", "A"); strings.Join(rs.Rrdatas, ",") != "1.1.1.1,10.0.0.1" {
		t.Errorf("private zone touched: %+v", rs)
	}

	// Record sets driven by a routing policy are never rewritten: a create
	// would replace the geo policy with a plain rrdata set.
	before = f.countRequests("/changes")
	if _, err := c.CreateRecord(ctx, "example-zone", platform.Record{Name: "geo.example.com", Type: "A", Content: "1.2.3.4"}); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("create on routing policy set: %v", err)
	}
	if err := c.SetRRSet(ctx, "example-zone", "geo.example.com", "A", 0, []string{"1.2.3.4"}); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("upsert on routing policy set: %v", err)
	}
	if err := c.DeleteRecord(ctx, "example-zone", "example-zone|A|geo.example.com|routing-policy"); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("delete of routing policy record: %v", err)
	}
	if _, err := c.UpdateRecord(ctx, "example-zone", platform.Record{ID: "example-zone|A|geo.example.com|routing-policy", Content: "1.2.3.4"}); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("update of routing policy record: %v", err)
	}
	if f.countRequests("/changes") != before {
		t.Error("routing policy sets must not submit a change")
	}
	if rs := f.rrset("example-zone", "geo.example.com.", "A"); rs == nil || rs.RoutingPolicy == nil || len(rs.Rrdatas) != 0 {
		t.Errorf("geo set altered: %+v", rs)
	}

	// TXT: a user-typed value (unquoted) deletes the quoted rrdata it maps to.
	if err := c.DeleteRecord(ctx, "example-zone", encodeRecordID("example-zone", "TXT", "example.com", quoteTXT("v=spf1 -all"))); err != nil {
		t.Fatalf("delete txt by user value: %v", err)
	}
	if f.rrset("example-zone", "example.com.", "TXT") != nil {
		t.Error("txt set should be gone")
	}

	// Native upsert replaces the whole set; TXT gets quoted.
	if err := c.SetRRSet(ctx, "example-zone", "example.com", "TXT", 0, []string{`"v=spf1 include:x -all"`, quoteTXT("hello world")}); err != nil {
		t.Fatal(err)
	}
	if rs := f.rrset("example-zone", "example.com.", "TXT"); len(rs.Rrdatas) != 2 || rs.Rrdatas[1] != `"hello world"` || rs.Ttl != 300 {
		t.Errorf("txt upsert: %+v", rs)
	}
	if err := c.DeleteRRSet(ctx, "example-zone", "example.com", "txt"); err != nil {
		t.Fatal(err)
	}
	if f.rrset("example-zone", "example.com.", "TXT") != nil {
		t.Error("txt set should be deleted")
	}
	if err := c.DeleteRRSet(ctx, "example-zone", "example.com", "TXT"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("delete missing set: %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ctx := context.Background()

	if _, err := c.ListRecords(ctx, "no-such-zone"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing zone: %v", err)
	}
	if _, err := c.GetZone(ctx, "no-such-zone"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("get missing zone: %v", err)
	}
	f.mu.Lock()
	f.status["managedZones"] = http.StatusForbidden
	f.mu.Unlock()
	if _, err := c.ListZones(ctx); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("403: %v", err)
	}
	f.mu.Lock()
	f.status["managedZones"] = http.StatusUnauthorized
	f.mu.Unlock()
	if _, err := c.ListZones(ctx); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("401: %v", err)
	}
	f.mu.Lock()
	delete(f.status, "managedZones")
	f.mu.Unlock()

	// A client without a bearer token is rejected by the fake, which proves
	// the token source is wired into the API services.
	anon, err := newClient(ctx, "proj", "", methodADC, append(f.options(), option.WithoutAuthentication())...)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := anon.ListZones(ctx); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("anonymous: %v", err)
	}
	if mapErr(nil) != nil || !errors.Is(mapErr(&oauth2.RetrieveError{}), platform.ErrUnauthorized) {
		t.Error("mapErr sentinels")
	}
}

func TestVerify(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	id, err := c.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != "proj" || id.User != "me@example.com" || id.Extra["project_number"] != "123" {
		t.Errorf("identity: %+v", id)
	}
	// Without Resource Manager access, Cloud DNS visibility is enough.
	f.mu.Lock()
	f.status["/v1/projects/proj"] = http.StatusForbidden
	f.mu.Unlock()
	if id, err := c.Verify(context.Background()); err != nil || id.Account != "proj" || id.Extra["note"] == "" {
		t.Errorf("fallback verify: %v %+v", err, id)
	}
	f.mu.Lock()
	f.status["managedZones"] = http.StatusForbidden
	f.mu.Unlock()
	if _, err := c.Verify(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("verify denied: %v", err)
	}
}

func TestListInstancesAndOperations(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ctx := context.Background()
	res, err := c.Sync(ctx, platform.ResInstance)
	if err != nil {
		t.Fatal(err)
	}
	if len(res) != 2 || f.countRequests("aggregated/instances") != 2 {
		t.Fatalf("instances: %d, requests %v", len(res), f.requests)
	}
	in, ok := res[0].Data.(Instance)
	if !ok || in.Name != "web-1" || in.Zone != "us-central1-a" || in.MachineType != "e2-small" || in.ExternalIP != "34.10.0.0.1" || res[0].ID != "1" {
		t.Errorf("instance: %+v", res[0])
	}
	op, err := c.StartInstance(ctx, "us-central1-a", "web-1", true)
	if err != nil {
		t.Fatal(err)
	}
	if op.Status != "DONE" || op.Operation != "op-1" || f.countRequests("operations/op-1/wait") != 1 {
		t.Errorf("start: %+v %v", op, f.requests)
	}
	if _, err := c.StopInstance(ctx, "us-central1-a", "nope", false); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("stop missing: %v", err)
	}
}

func TestListProjects(t *testing.T) {
	f := newFake(t)
	c := f.client(t)
	ps, err := c.ListProjects(context.Background())
	if err != nil || len(ps) != 2 || ps[0].ProjectId != "other" {
		t.Errorf("projects: %v %+v", err, ps)
	}
}

// writeServiceAccountKey creates a throwaway RSA key file pointing its
// token_uri at the fake server.
func writeServiceAccountKey(t *testing.T, f *fakeGoogle, projectID string) string {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	pemKey := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	key := map[string]string{
		"type":         "service_account",
		"project_id":   projectID,
		"private_key":  string(pemKey),
		"client_email": "sa@proj.iam.gserviceaccount.com",
		"client_id":    "1234",
		"token_uri":    f.srv.URL + "/token",
	}
	b, _ := json.Marshal(key)
	path := filepath.Join(t.TempDir(), "key.json")
	if err := os.WriteFile(path, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

func withFakeEndpoints(t *testing.T, f *fakeGoogle) {
	t.Helper()
	old := extraOptions
	extraOptions = f.options()
	t.Cleanup(func() { extraOptions = old })
}

func loginInput(stdin string, opts map[string]string) (platform.LoginInput, *bytes.Buffer) {
	var errBuf bytes.Buffer
	return platform.LoginInput{
		ProfileName: "test",
		Options:     opts,
		Stdin:       strings.NewReader(stdin),
		Stdout:      &bytes.Buffer{},
		Stderr:      &errBuf,
		NoBrowser:   true,
		OpenBrowser: func(string) error { return errors.New("no browser in tests") },
	}, &errBuf
}

func TestLoginServiceAccount(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	keyPath := writeServiceAccountKey(t, f, "proj")
	p := &provider{}

	in, _ := loginInput("", map[string]string{"method": "service-account", "key_file": keyPath})
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata["method"] != methodServiceAccount || res.Metadata["project"] != "proj" || res.Metadata["client_email"] != "sa@proj.iam.gserviceaccount.com" {
		t.Errorf("metadata: %+v", res.Metadata)
	}
	if !strings.Contains(res.Secret["service_account_json"], "RSA PRIVATE KEY") || len(res.Secret) != 1 {
		t.Error("secret should hold only the key JSON")
	}
	for k, v := range res.Metadata {
		if strings.Contains(v, "PRIVATE KEY") {
			t.Errorf("metadata %s leaks the key", k)
		}
	}
	if res.Label != "sa@proj.iam.gserviceaccount.com (project proj)" {
		t.Errorf("label: %q", res.Label)
	}
	if f.tokens == 0 || f.countRequests("managedZones") == 0 {
		t.Errorf("login must fetch a token and verify against Cloud DNS: %v", f.requests)
	}

	// The project prompt is used when the key has none; input comes from stdin.
	noProj := writeServiceAccountKey(t, f, "")
	in, errBuf := loginInput("proj\n", map[string]string{"method": "sa", "key_file": noProj})
	res, err = p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata["project"] != "proj" || !strings.Contains(errBuf.String(), "project id") {
		t.Errorf("prompted project: %+v / %s", res.Metadata, errBuf.String())
	}

	// Verification failure surfaces as unauthorized.
	f.mu.Lock()
	f.status["managedZones"] = http.StatusForbidden
	f.status["/projects/proj/zones"] = http.StatusForbidden
	f.status["/v1/projects/proj"] = http.StatusForbidden
	f.mu.Unlock()
	in, _ = loginInput("", map[string]string{"method": "service-account", "key_file": keyPath})
	if _, err := p.Login(context.Background(), in); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("denied login: %v", err)
	}

	// Bad key file.
	bad := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(bad, []byte(`{"type":"authorized_user"}`), 0o600)
	in, _ = loginInput("", map[string]string{"method": "service-account", "key_file": bad})
	if _, err := p.Login(context.Background(), in); err == nil {
		t.Error("bad key file should fail")
	}
	in, _ = loginInput("", map[string]string{"method": "bogus"})
	if _, err := p.Login(context.Background(), in); err == nil {
		t.Error("unknown method should fail")
	}
}

func TestLoginADC(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	keyPath := writeServiceAccountKey(t, f, "adc-proj")
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", keyPath)
	p := &provider{}

	// Project chosen from the Resource Manager list by number.
	in, errBuf := loginInput("2\n", nil)
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata["method"] != methodADC || res.Metadata["project"] != "proj" || res.Metadata["email"] != "me@example.com" {
		t.Errorf("metadata: %+v / %s", res.Metadata, errBuf.String())
	}
	if len(res.Secret) != 0 {
		t.Errorf("adc must not store secrets: %v", res.Secret)
	}
	if !strings.Contains(errBuf.String(), "1) other") || !strings.Contains(errBuf.String(), "2) proj") {
		t.Errorf("project list prompt: %s", errBuf.String())
	}

	// --set project skips the prompt entirely.
	in, _ = loginInput("", map[string]string{"project": "proj"})
	if res, err := p.Login(context.Background(), in); err != nil || res.Metadata["project"] != "proj" || res.Label != "me@example.com (project proj)" {
		t.Errorf("explicit project: %v %+v", err, res)
	}

	// Missing ADC prints the gcloud command and fails with unauthorized.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
	in, errBuf = loginInput("", nil)
	_, err = p.Login(context.Background(), in)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(errBuf.String(), "gcloud auth application-default login") {
		t.Errorf("missing adc: %v / %s", err, errBuf.String())
	}
}

func TestOpenProfiles(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	keyPath := writeServiceAccountKey(t, f, "proj")
	raw, _ := os.ReadFile(keyPath)
	p := &provider{}
	ctx := context.Background()

	c, err := p.Open(ctx, platform.Profile{Name: "sa", Platform: platform.GCP,
		Metadata: map[string]string{"method": methodServiceAccount, "project": "proj", "client_email": "sa@proj.iam.gserviceaccount.com"},
		Secret:   map[string]string{"service_account_json": string(raw)}})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := c.(platform.DNSService); !ok {
		t.Error("client must implement DNSService")
	}
	if id, err := c.Verify(ctx); err != nil || id.User != "sa@proj.iam.gserviceaccount.com" {
		t.Errorf("verify sa: %v %+v", err, id)
	}

	if _, err := p.Open(ctx, platform.Profile{Name: "x", Metadata: map[string]string{"method": methodServiceAccount, "project": "proj"}, Secret: map[string]string{}}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("missing key: %v", err)
	}
	if _, err := p.Open(ctx, platform.Profile{Name: "x", Metadata: map[string]string{"method": methodOAuth, "project": "proj"}, Secret: map[string]string{"client_id": "a"}}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("incomplete oauth: %v", err)
	}
	if _, err := p.Open(ctx, platform.Profile{Name: "x", Metadata: map[string]string{"method": "adc"}}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("missing project: %v", err)
	}
	if _, err := p.Open(ctx, platform.Profile{Name: "x", Metadata: map[string]string{"method": "weird", "project": "proj"}}); err == nil {
		t.Error("unknown method should fail")
	}

	// An oauth profile builds a refreshing token source from the stored secret.
	cfg, tok, err := oauthFromSecret(map[string]string{"client_id": "id", "client_secret": "s", "refresh_token": "rt"})
	if err != nil || cfg.ClientID != "id" || tok.RefreshToken != "rt" || len(cfg.Scopes) != 2 {
		t.Errorf("oauthFromSecret: %v %+v", err, cfg)
	}
}

func TestProviderRegistration(t *testing.T) {
	prov, err := platform.Get(platform.GCP)
	if err != nil {
		t.Fatal(err)
	}
	if prov.DisplayName() != "Google Cloud" || !platform.Supports(prov, platform.ResDNSRecord) || !platform.Supports(prov, platform.ResInstance) || platform.Supports(prov, platform.ResDomain) {
		t.Error("provider registration")
	}
	if !strings.Contains(prov.LoginHelp(), "adc") {
		t.Error("login help")
	}
}
