package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// fakeCF is a minimal Cloudflare v4 API with two zones and paginated listings.
type fakeCF struct {
	t        *testing.T
	token    string
	mu       sync.Mutex
	zones    []map[string]any
	accounts []map[string]any
	records  map[string][]map[string]any // zone id -> records
	requests []string                    // "METHOD path?query"
	lastBody map[string]any
	nextID   int
	// maxPerPage caps the client's per_page like the real API does; 0 means
	// no cap. newFake sets it to fakePerPage so small fixtures still paginate.
	maxPerPage int
	// noTotalPages drops total_pages from result_info (as /accounts does).
	noTotalPages bool
	// accountOwned, when set, makes the token behave like an account-owned
	// token of that account: the /user endpoints reject it and only the
	// owning account is visible.
	accountOwned string
	// forbidRecords answers 403 for the record listing of these zone ids.
	forbidRecords map[string]bool
}

func newFake(t *testing.T) (*fakeCF, *httptest.Server) {
	f := &fakeCF{t: t, token: "good-token", records: map[string][]map[string]any{}, maxPerPage: fakePerPage, forbidRecords: map[string]bool{}}
	f.accounts = []map[string]any{{"id": "acc1", "name": "Acme", "type": "standard"}, {"id": "acc2", "name": "Beta", "type": "standard"}}
	f.zones = []map[string]any{
		{"id": "zone1", "name": "example.com", "status": "active", "paused": false,
			"name_servers": []string{"a.ns.cloudflare.com", "b.ns.cloudflare.com"},
			"account":      map[string]any{"id": "acc1", "name": "Acme"}, "plan": map[string]any{"name": "Free Website"}},
		{"id": "zone2", "name": "example.org", "status": "pending", "paused": true,
			"name_servers": []string{"c.ns.cloudflare.com"},
			"account":      map[string]any{"id": "acc2", "name": "Beta"}, "plan": map[string]any{"name": "Pro Website"}},
	}
	// zone1 gets more records than one page (per_page is forced small by the fake).
	for i := 0; i < 7; i++ {
		f.records["zone1"] = append(f.records["zone1"], map[string]any{
			"id": fmt.Sprintf("rec%d", i), "zone_id": "zone1", "zone_name": "example.com",
			"name": fmt.Sprintf("host%d.example.com", i), "type": "A", "content": fmt.Sprintf("10.0.0.%d", i),
			"ttl": 1, "proxied": i%2 == 0, "proxiable": true,
		})
	}
	f.records["zone1"] = append(f.records["zone1"], map[string]any{
		"id": "mx1", "zone_id": "zone1", "zone_name": "example.com", "name": "example.com", "type": "MX",
		"content": "mail.example.com", "ttl": 3600, "priority": 10, "proxied": false, "proxiable": false,
		"comment": "primary mail", "tags": []string{"mail"},
	})
	f.records["zone2"] = []map[string]any{{
		"id": "r2", "zone_id": "zone2", "zone_name": "example.org", "name": "www.example.org", "type": "CNAME",
		"content": "example.org", "ttl": 300, "proxied": true, "proxiable": true,
	}}
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	return f, srv
}

const fakePerPage = 3

func (f *fakeCF) write(w http.ResponseWriter, status int, env map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(env)
}

func (f *fakeCF) ok(w http.ResponseWriter, result any) {
	f.write(w, 200, map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result})
}

func (f *fakeCF) fail(w http.ResponseWriter, status, code int, msg string) {
	f.write(w, status, map[string]any{"success": false, "errors": []map[string]any{{"code": code, "message": msg}}, "messages": []any{}, "result": nil})
}

// page honours the client's per_page (capped by maxPerPage) and page query
// parameters, like the real list endpoints.
func (f *fakeCF) page(w http.ResponseWriter, r *http.Request, items []map[string]any) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	perPage, _ := strconv.Atoi(r.URL.Query().Get("per_page"))
	if perPage < 1 {
		perPage = 20
	}
	if f.maxPerPage > 0 && perPage > f.maxPerPage {
		perPage = f.maxPerPage
	}
	total := (len(items) + perPage - 1) / perPage
	start := (page - 1) * perPage
	end := start + perPage
	if start > len(items) {
		start = len(items)
	}
	if end > len(items) {
		end = len(items)
	}
	if items == nil {
		items = []map[string]any{}
	}
	info := map[string]any{"page": page, "per_page": perPage, "count": end - start, "total_count": len(items)}
	if !f.noTotalPages {
		info["total_pages"] = total
	}
	f.write(w, 200, map[string]any{
		"success": true, "errors": []any{}, "messages": []any{}, "result": items[start:end],
		"result_info": info,
	})
}

func (f *fakeCF) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	if r.Header.Get("Authorization") != "Bearer "+f.token {
		f.fail(w, 400, 10000, "Authentication error")
		return
	}
	var body map[string]any
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&body)
	}
	f.lastBody = body
	p := r.URL.Path
	switch {
	case f.accountOwned != "" && (p == "/user/tokens/verify" || p == "/user"):
		f.fail(w, 401, 1000, "Invalid API Token")
	case f.accountOwned != "" && strings.HasPrefix(p, "/accounts/") && strings.HasSuffix(p, "/tokens/verify"):
		if p != "/accounts/"+f.accountOwned+"/tokens/verify" {
			f.fail(w, 401, 1000, "Invalid API Token")
			return
		}
		f.ok(w, map[string]any{"id": "acctok1", "status": "active"})
	case f.accountOwned != "" && p == "/accounts":
		var own []map[string]any
		for _, a := range f.accounts {
			if a["id"] == f.accountOwned {
				own = append(own, a)
			}
		}
		f.page(w, r, own)
	case p == "/user/tokens/verify":
		f.ok(w, map[string]any{"id": "tok123", "status": "active"})
	case p == "/user":
		f.ok(w, map[string]any{"id": "u1", "email": "ops@example.com"})
	case p == "/accounts":
		f.page(w, r, f.accounts)
	case p == "/zones":
		items := f.zones
		if acc := r.URL.Query().Get("account.id"); acc != "" {
			items = nil
			for _, z := range f.zones {
				if z["account"].(map[string]any)["id"] == acc {
					items = append(items, z)
				}
			}
		}
		if name := r.URL.Query().Get("name"); name != "" {
			var m []map[string]any
			for _, z := range items {
				if z["name"] == name {
					m = append(m, z)
				}
			}
			items = m
		}
		f.page(w, r, items)
	case strings.HasPrefix(p, "/zones/"):
		rest := strings.TrimPrefix(p, "/zones/")
		parts := strings.Split(rest, "/")
		zoneID := parts[0]
		var zone map[string]any
		for _, z := range f.zones {
			if z["id"] == zoneID {
				zone = z
			}
		}
		if zone == nil {
			f.fail(w, 404, 7003, "Could not route to /zones/"+zoneID+", perhaps your object identifier is invalid?")
			return
		}
		switch {
		case len(parts) == 1:
			f.ok(w, zone)
		case parts[1] == "dns_records" && len(parts) == 2 && r.Method == http.MethodGet:
			if f.forbidRecords[zoneID] {
				f.fail(w, 403, 10000, "Authentication error")
				return
			}
			f.page(w, r, f.records[zoneID])
		case parts[1] == "dns_records" && len(parts) == 2 && r.Method == http.MethodPost:
			f.nextID++
			rec := map[string]any{"id": fmt.Sprintf("new%d", f.nextID), "zone_id": zoneID, "zone_name": zone["name"], "proxiable": true}
			for k, v := range body {
				rec[k] = v
			}
			if _, ok := rec["proxied"]; !ok {
				rec["proxied"] = false
			}
			f.records[zoneID] = append(f.records[zoneID], rec)
			f.ok(w, rec)
		case parts[1] == "dns_records" && len(parts) == 3:
			idx := -1
			for i, rec := range f.records[zoneID] {
				if rec["id"] == parts[2] {
					idx = i
				}
			}
			if idx < 0 {
				f.fail(w, 404, 81044, "Record does not exist.")
				return
			}
			switch r.Method {
			case http.MethodPut:
				// "Overwrite DNS Record": the body replaces the record; only
				// the immutable fields survive.
				old := f.records[zoneID][idx]
				rec := map[string]any{"id": old["id"], "zone_id": old["zone_id"], "zone_name": old["zone_name"], "proxiable": old["proxiable"]}
				for k, v := range body {
					rec[k] = v
				}
				if _, ok := rec["proxied"]; !ok {
					rec["proxied"] = false
				}
				f.records[zoneID][idx] = rec
				f.ok(w, rec)
			case http.MethodDelete:
				f.records[zoneID] = append(f.records[zoneID][:idx], f.records[zoneID][idx+1:]...)
				f.ok(w, map[string]any{"id": parts[2]})
			default:
				http.Error(w, "method", 405)
			}
		case parts[1] == "purge_cache":
			f.ok(w, map[string]any{"id": zoneID})
		case parts[1] == "settings" && len(parts) == 3:
			val := "full"
			if parts[2] == "development_mode" {
				val = "off"
			}
			if r.Method == http.MethodPatch {
				val = body["value"].(string)
			}
			f.ok(w, map[string]any{"id": parts[2], "value": val, "editable": true})
		default:
			http.NotFound(w, r)
		}
	default:
		http.NotFound(w, r)
	}
}

func (f *fakeCF) count(prefix string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, r := range f.requests {
		if strings.HasPrefix(r, prefix) {
			n++
		}
	}
	return n
}

func openClient(t *testing.T, srv *httptest.Server, token, accountID string) *Client {
	t.Helper()
	p := &provider{baseURL: srv.URL}
	meta := map[string]string{metaMethod: "api_token"}
	if accountID != "" {
		meta[metaAccountID] = accountID
	}
	c, err := p.Open(context.Background(), platform.Profile{Name: "cf", Platform: platform.Cloudflare, Metadata: meta, Secret: map[string]string{secretToken: token}})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return c.(*Client)
}

func TestListZonesPaginatesAndMaps(t *testing.T) {
	f, srv := newFake(t)
	// 7 zones -> 3 pages with the fake's page size.
	for i := 0; i < 5; i++ {
		f.zones = append(f.zones, map[string]any{"id": fmt.Sprintf("z%d", i), "name": fmt.Sprintf("extra%d.net", i), "status": "active",
			"account": map[string]any{"id": "acc1", "name": "Acme"}, "plan": map[string]any{"name": "Free Website"}})
	}
	c := openClient(t, srv, "good-token", "")
	zones, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 7 {
		t.Fatalf("want 7 zones, got %d", len(zones))
	}
	if n := f.count("GET /zones?"); n != 3 {
		t.Fatalf("want 3 page requests, got %d: %v", n, f.requests)
	}
	z := zones[0]
	if z.ID != "zone1" || z.Name != "example.com" || z.Status != "active" {
		t.Fatalf("unexpected zone %+v", z)
	}
	if len(z.Nameservers) != 2 || z.Nameservers[0] != "a.ns.cloudflare.com" {
		t.Fatalf("nameservers: %v", z.Nameservers)
	}
	if z.Extra["plan"] != "Free Website" || z.Extra["paused"] != false || z.Extra["account_id"] != "acc1" {
		t.Fatalf("extra: %v", z.Extra)
	}
}

func TestListZonesPinnedAccount(t *testing.T) {
	f, srv := newFake(t)
	c := openClient(t, srv, "good-token", "acc2")
	zones, err := c.ListZones(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 1 || zones[0].ID != "zone2" {
		t.Fatalf("want only zone2, got %+v", zones)
	}
	if !strings.Contains(f.requests[0], "account.id=acc2") {
		t.Fatalf("account filter missing: %s", f.requests[0])
	}
}

func TestListRecordsMapping(t *testing.T) {
	f, srv := newFake(t)
	c := openClient(t, srv, "good-token", "")
	recs, err := c.ListRecords(context.Background(), "zone1")
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 8 {
		t.Fatalf("want 8 records, got %d", len(recs))
	}
	if n := f.count("GET /zones/zone1/dns_records?"); n != 3 {
		t.Fatalf("want 3 page requests, got %d", n)
	}
	var mx *platform.Record
	for i := range recs {
		if recs[i].Type == "MX" {
			mx = &recs[i]
		}
	}
	if mx == nil {
		t.Fatal("MX record missing")
	}
	if mx.Name != "example.com" || mx.Value != "mail.example.com" || mx.TTL != 3600 {
		t.Fatalf("mx: %+v", *mx)
	}
	if mx.Priority == nil || *mx.Priority != 10 {
		t.Fatalf("priority: %v", mx.Priority)
	}
	if mx.Proxied == nil || *mx.Proxied {
		t.Fatalf("proxied: %v", mx.Proxied)
	}
	if mx.Extra["comment"] != "primary mail" || mx.Extra["proxiable"] != false {
		t.Fatalf("extra: %v", mx.Extra)
	}
	if tags, ok := mx.Extra["tags"].([]string); !ok || len(tags) != 1 || tags[0] != "mail" {
		t.Fatalf("tags: %v", mx.Extra["tags"])
	}
	a := recs[0]
	if a.ID != "rec0" || a.ZoneID != "zone1" || a.TTL != 1 || a.Proxied == nil || !*a.Proxied {
		t.Fatalf("a: %+v", a)
	}
}

func TestCreateUpdateDeleteRecord(t *testing.T) {
	f, srv := newFake(t)
	c := openClient(t, srv, "good-token", "")
	ctx := context.Background()

	prio := 20
	px := true
	in := platform.Record{Name: "www.example.com", Type: "a", Value: "1.2.3.4", TTL: 0, Priority: &prio, Proxied: &px, Extra: map[string]any{"comment": "hello", "tags": []any{"x"}}}
	out, err := c.CreateRecord(ctx, "zone1", in)
	if err != nil {
		t.Fatal(err)
	}
	if f.lastBody["ttl"] != float64(1) {
		t.Fatalf("ttl 0 must be sent as 1, body: %v", f.lastBody)
	}
	if f.lastBody["name"] != "www.example.com" || f.lastBody["type"] != "A" || f.lastBody["content"] != "1.2.3.4" {
		t.Fatalf("body: %v", f.lastBody)
	}
	if f.lastBody["priority"] != float64(20) || f.lastBody["proxied"] != true || f.lastBody["comment"] != "hello" {
		t.Fatalf("body: %v", f.lastBody)
	}
	if out.ID == "" || out.Name != "www.example.com" || out.Type != "A" {
		t.Fatalf("out: %+v", *out)
	}

	// Round trip: a record listed from the API and sent back through
	// UpdateRecord keeps proxied/comment/tags across the overwrite.
	listed, err := c.ListRecords(ctx, "zone1")
	if err != nil {
		t.Fatal(err)
	}
	var cur *platform.Record
	for i := range listed {
		if listed[i].ID == out.ID {
			cur = &listed[i]
		}
	}
	if cur == nil {
		t.Fatal("created record not listed")
	}
	rt := *cur
	rt.Value = "9.9.9.9"
	out1, err := c.UpdateRecord(ctx, "zone1", rt)
	if err != nil {
		t.Fatal(err)
	}
	if out1.Value != "9.9.9.9" || out1.Proxied == nil || !*out1.Proxied || out1.Extra["comment"] != "hello" {
		t.Fatalf("round trip lost fields: %+v", *out1)
	}
	if tags, ok := out1.Extra["tags"].([]string); !ok || len(tags) != 1 || tags[0] != "x" {
		t.Fatalf("round trip lost tags: %v", out1.Extra["tags"])
	}
	if f.lastBody["proxied"] != true || f.lastBody["comment"] != "hello" || f.lastBody["priority"] != float64(20) {
		t.Fatalf("update body: %v", f.lastBody)
	}

	// Update without optional fields: priority/proxied/comment are omitted
	// and, since PUT overwrites, the record loses them.
	up := platform.Record{ID: out.ID, Name: "www.example.com", Type: "A", Value: "5.6.7.8", TTL: 120}
	out2, err := c.UpdateRecord(ctx, "zone1", up)
	if err != nil {
		t.Fatal(err)
	}
	if out2.Value != "5.6.7.8" || out2.TTL != 120 || out2.Priority != nil || out2.Extra["comment"] != nil {
		t.Fatalf("out2: %+v", *out2)
	}
	for _, k := range []string{"priority", "proxied", "comment", "tags", "data"} {
		if _, ok := f.lastBody[k]; ok {
			t.Fatalf("%s must be omitted when unset: %v", k, f.lastBody)
		}
	}
	if _, err := c.UpdateRecord(ctx, "zone1", platform.Record{Name: "x"}); err == nil {
		t.Fatal("update without id must fail")
	}

	// SRV: the components travel in `data`; `content` is not sent.
	srvData := map[string]any{"priority": 10, "weight": 5, "port": 5060, "target": "sip.example.com"}
	srvRec, err := c.CreateRecord(ctx, "zone1", platform.Record{Name: "_sip._tcp.example.com", Type: "SRV", TTL: 300, Extra: map[string]any{"data": srvData}})
	if err != nil {
		t.Fatal(err)
	}
	if d, ok := f.lastBody["data"].(map[string]any); !ok || d["target"] != "sip.example.com" || d["port"] != float64(5060) {
		t.Fatalf("create body must carry data: %v", f.lastBody)
	}
	if _, ok := f.lastBody["content"]; ok {
		t.Fatalf("content must be omitted when data is sent: %v", f.lastBody)
	}
	// Simulate the inventory JSON round-trip of Extra before updating.
	raw, _ := json.Marshal(srvRec.Extra)
	var extra map[string]any
	_ = json.Unmarshal(raw, &extra)
	extra["data"].(map[string]any)["port"] = float64(5061)
	srvUp := platform.Record{ID: srvRec.ID, Name: srvRec.Name, Type: srvRec.Type, TTL: srvRec.TTL, Extra: extra}
	srv2, err := c.UpdateRecord(ctx, "zone1", srvUp)
	if err != nil {
		t.Fatal(err)
	}
	d, ok := f.lastBody["data"].(map[string]any)
	if !ok || d["port"] != float64(5061) || d["target"] != "sip.example.com" {
		t.Fatalf("update body must carry data: %v", f.lastBody)
	}
	if _, ok := f.lastBody["content"]; ok {
		t.Fatalf("content must be omitted when data is sent: %v", f.lastBody)
	}
	if d2, ok := srv2.Extra["data"].(map[string]any); !ok || d2["port"] != float64(5061) {
		t.Fatalf("data lost on round trip: %+v", srv2.Extra)
	}

	if err := c.DeleteRecord(ctx, "zone1", out.ID); err != nil {
		t.Fatal(err)
	}
	err = c.DeleteRecord(ctx, "zone1", out.ID)
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("second delete: want ErrNotFound, got %v", err)
	}
}

func TestErrorMapping(t *testing.T) {
	_, srv := newFake(t)
	ctx := context.Background()

	bad := openClient(t, srv, "wrong", "")
	_, err := bad.ListZones(ctx)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("code 10000 must map to ErrUnauthorized, got %v", err)
	}
	if !strings.Contains(err.Error(), "Authentication error") || !strings.Contains(err.Error(), "10000") {
		t.Fatalf("error must surface the Cloudflare message: %v", err)
	}

	good := openClient(t, srv, "good-token", "")
	_, err = good.ListRecords(ctx, "nope")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("404 must map to ErrNotFound, got %v", err)
	}
	_, err = good.GetZone(ctx, "nope.example")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("unknown zone name must map to ErrNotFound, got %v", err)
	}

	// success:false with HTTP 200 and a 403 with a plain body.
	raw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/user/tokens/verify":
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Invalid access token"}],"result":null}`))
		case "/zones":
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`forbidden`))
		default:
			w.WriteHeader(200)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":1004,"message":"DNS Validation Error"}],"result":null}`))
		}
	}))
	defer raw.Close()
	c := openClient(t, raw, "t", "")
	if _, err := c.Verify(ctx); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("code 9109: %v", err)
	}
	if _, err := c.ListZones(ctx); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("403: %v", err)
	}
	_, err = c.CreateRecord(ctx, "z", platform.Record{Name: "a", Type: "A"})
	if err == nil || errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("validation error must be a plain error: %v", err)
	}
	if !strings.Contains(err.Error(), "DNS Validation Error (code 1004)") {
		t.Fatalf("message: %v", err)
	}
}

func TestSync(t *testing.T) {
	_, srv := newFake(t)
	c := openClient(t, srv, "good-token", "")
	ctx := context.Background()

	zones, err := c.Sync(ctx, platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(zones) != 2 || zones[0].Type != platform.ResZone || zones[0].Domain != "example.com" || zones[0].ID != "zone1" {
		t.Fatalf("zones: %+v", zones)
	}

	recs, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 9 {
		t.Fatalf("want 9 records across zones, got %d", len(recs))
	}
	byZone := map[string]int{}
	for _, r := range recs {
		if r.Type != platform.ResDNSRecord {
			t.Fatalf("type: %s", r.Type)
		}
		byZone[r.ParentID]++
		if (r.ParentID == "zone1" && r.Domain != "example.com") || (r.ParentID == "zone2" && r.Domain != "example.org") {
			t.Fatalf("domain mismatch: %+v", r)
		}
		rec, ok := r.Data.(platform.Record)
		if !ok || rec.ZoneID != r.ParentID || rec.ID != r.ID {
			t.Fatalf("data: %+v", r)
		}
	}
	if byZone["zone1"] != 8 || byZone["zone2"] != 1 {
		t.Fatalf("per zone: %v", byZone)
	}

	if _, err := c.Sync(ctx, platform.ResInstance); !errors.Is(err, platform.ErrNotSupported) {
		t.Fatalf("instance: %v", err)
	}
}

func TestSyncSkipsZonesWithoutDNSPermission(t *testing.T) {
	f, srv := newFake(t)
	f.forbidRecords["zone2"] = true
	c := openClient(t, srv, "good-token", "")
	ctx := context.Background()

	var warned []string
	orig := warnf
	warnf = func(format string, args ...any) { warned = append(warned, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { warnf = orig })

	recs, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil {
		t.Fatalf("a 403 on one zone must not fail the sync: %v", err)
	}
	if len(recs) != 8 {
		t.Fatalf("want zone1's 8 records, got %d", len(recs))
	}
	for _, r := range recs {
		if r.ParentID != "zone1" {
			t.Fatalf("unexpected record from %s", r.ParentID)
		}
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "example.org") || !strings.Contains(warned[0], "cf") {
		t.Fatalf("want one warning naming the skipped zone and profile, got %v", warned)
	}

	// Every zone forbidden: the error is returned and unwraps to ErrUnauthorized.
	f.forbidRecords["zone1"] = true
	_, err = c.Sync(ctx, platform.ResDNSRecord)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("all zones forbidden: want ErrUnauthorized, got %v", err)
	}
	if !strings.Contains(err.Error(), "example.com") || !strings.Contains(err.Error(), "example.org") {
		t.Fatalf("error must name both zones: %v", err)
	}
}

func TestListAccountsWithoutTotalPages(t *testing.T) {
	f, srv := newFake(t)
	// /accounts does not report total_pages; the client must stop on a short
	// page. 101 accounts at per_page=50 -> 3 requests.
	f.noTotalPages = true
	f.maxPerPage = 0
	f.accounts = nil
	for i := 0; i < 101; i++ {
		f.accounts = append(f.accounts, map[string]any{"id": fmt.Sprintf("a%d", i), "name": fmt.Sprintf("Account %d", i)})
	}
	c := openClient(t, srv, "good-token", "")
	accs, err := c.api.listAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accs) != 101 {
		t.Fatalf("want 101 accounts, got %d", len(accs))
	}
	if n := f.count("GET /accounts?"); n != 3 {
		t.Fatalf("want 3 page requests, got %d: %v", n, f.requests)
	}
	if !strings.Contains(f.requests[0], "per_page=50") {
		t.Fatalf("client per_page must be sent: %s", f.requests[0])
	}

	// An exact multiple of the page size costs one extra (empty) request.
	f.requests = nil
	f.accounts = f.accounts[:100]
	accs, err = c.api.listAccounts(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(accs) != 100 || f.count("GET /accounts?") != 3 {
		t.Fatalf("want 100 accounts in 3 requests, got %d in %d", len(accs), f.count("GET /accounts?"))
	}
}

func TestVerify(t *testing.T) {
	_, srv := newFake(t)
	c := openClient(t, srv, "good-token", "acc1")
	c.profile.Metadata[metaEmail] = "ops@example.com"
	id, err := c.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != "acc1" || id.User != "ops@example.com" || id.Extra["token_id"] != "tok123" || id.Extra["token_status"] != "active" {
		t.Fatalf("identity: %+v", *id)
	}
}

func TestLoginWithTokenOption(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	var stderr bytes.Buffer
	opened := ""
	in := platform.LoginInput{
		ProfileName: "cf",
		Options:     map[string]string{"token": "good-token", "account_id": "acc2"},
		Stdin:       strings.NewReader(""),
		Stdout:      &bytes.Buffer{},
		Stderr:      &stderr,
		OpenBrowser: func(u string) error { opened = u; return nil },
	}
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "" {
		t.Fatalf("browser must not open when a token is supplied")
	}
	if res.Secret[secretToken] != "good-token" {
		t.Fatalf("secret: %v", res.Secret)
	}
	want := map[string]string{metaMethod: "api_token", metaAccountID: "acc2", metaAccountName: "Beta", metaEmail: "ops@example.com", metaTokenID: "tok123"}
	for k, v := range want {
		if res.Metadata[k] != v {
			t.Fatalf("metadata[%s] = %q, want %q (all: %v)", k, res.Metadata[k], v, res.Metadata)
		}
	}
	if _, leaked := res.Metadata[secretToken]; leaked {
		t.Fatal("token must never be in metadata")
	}
	if res.Label != "ops@example.com" {
		t.Fatalf("label: %q", res.Label)
	}
	if strings.Contains(stderr.String(), "good-token") {
		t.Fatal("token printed to stderr")
	}
}

func TestLoginAccountOwnedToken(t *testing.T) {
	f, srv := newFake(t)
	f.accountOwned = "acc2"
	p := &provider{baseURL: srv.URL}
	in := platform.LoginInput{
		ProfileName: "cf",
		Options:     map[string]string{"token": "good-token"},
		Stdin:       strings.NewReader(""),
		Stdout:      &bytes.Buffer{},
		Stderr:      &bytes.Buffer{},
	}
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatalf("account-owned token must log in: %v", err)
	}
	want := map[string]string{metaAccountID: "acc2", metaAccountName: "Beta", metaTokenID: "acctok1"}
	for k, v := range want {
		if res.Metadata[k] != v {
			t.Fatalf("metadata[%s] = %q, want %q (all: %v)", k, res.Metadata[k], v, res.Metadata)
		}
	}
	if res.Label != "Beta" {
		t.Fatalf("label: %q", res.Label)
	}

	// A client with the account pinned verifies without listing accounts.
	f.requests = nil
	id, err := openClient(t, srv, "good-token", "acc2").Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Extra["token_id"] != "acctok1" || id.Extra["token_status"] != "active" {
		t.Fatalf("identity: %+v", *id)
	}
	if n := f.count("GET /accounts?"); n != 0 {
		t.Fatalf("pinned account must not list accounts, got %d requests", n)
	}

	// A wrong token still fails with ErrUnauthorized.
	if _, err := openClient(t, srv, "bad-token", "acc2").Verify(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("bad token: want ErrUnauthorized, got %v", err)
	}
}

func TestLoginReadsTokenFromEnv(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	t.Setenv(tokenEnv, " good-token ")
	var stderr bytes.Buffer
	opened := ""
	in := platform.LoginInput{
		ProfileName: "cf",
		Options:     map[string]string{"account_id": "acc1"},
		Stdin:       strings.NewReader(""),
		Stdout:      &bytes.Buffer{},
		Stderr:      &stderr,
		OpenBrowser: func(u string) error { opened = u; return nil },
	}
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "" {
		t.Fatal("browser must not open when the env token is used")
	}
	if res.Secret[secretToken] != "good-token" || res.Metadata[metaAccountID] != "acc1" {
		t.Fatalf("result: %v %v", res.Secret, res.Metadata)
	}
	if strings.Contains(stderr.String(), "good-token") {
		t.Fatalf("stderr: %s", stderr.String())
	}
	if !strings.Contains(stderr.String(), tokenEnv) {
		t.Fatalf("must say the token came from the environment: %s", stderr.String())
	}
	// The help names the variable and the stdin form, never a token on the
	// command line, and no longer promises a token piped without --set.
	help := p.LoginHelp()
	if !strings.Contains(help, tokenEnv) || !strings.Contains(help, "--set token=-") ||
		strings.Contains(strings.ReplaceAll(help, "token=-", ""), "token=") || strings.Contains(help, "pipe the token") {
		t.Fatalf("help must advertise the env var and --set token=-, not --set token=<value>: %s", help)
	}
}

func TestLoginPromptsAndVerifies(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	var stderr bytes.Buffer
	opened := ""
	in := platform.LoginInput{
		ProfileName: "cf",
		Options:     map[string]string{"account_id": "acc1"},
		Interactive: true,
		Stdin:       strings.NewReader("good-token\n"),
		Stdout:      &bytes.Buffer{},
		Stderr:      &stderr,
		OpenBrowser: func(u string) error { opened = u; return errors.New("no browser") },
	}
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if opened != tokenPageURL {
		t.Fatalf("browser url: %q", opened)
	}
	if !strings.Contains(stderr.String(), tokenPageURL) || !strings.Contains(stderr.String(), "API token") {
		t.Fatalf("guidance and prompt must go to stderr, got: %s", stderr.String())
	}
	if res.Secret[secretToken] != "good-token" || res.Metadata[metaAccountID] != "acc1" || res.Metadata[metaAccountName] != "Acme" {
		t.Fatalf("result: %v", res.Metadata)
	}

	// --no-browser: the URL is printed, the browser is not launched.
	opened = ""
	in.NoBrowser = true
	in.Stdin = strings.NewReader("good-token\n")
	if _, err := p.Login(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if opened != "" {
		t.Fatal("browser launched despite NoBrowser")
	}
}

func TestLoginRejectsBadToken(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	in := platform.LoginInput{
		Options: map[string]string{"token": "bad"},
		Stdin:   strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		NoBrowser: true,
	}
	_, err := p.Login(context.Background(), in)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("want ErrUnauthorized, got %v", err)
	}
}

func TestLoginAmbiguousAccountsNonInteractive(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	in := platform.LoginInput{
		Options: map[string]string{"token": "good-token"},
		Stdin:   strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{},
		NoBrowser: true,
	}
	_, err := p.Login(context.Background(), in)
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set account_id=<id>") {
		t.Fatalf("want a usage error naming --set account_id, got %v", err)
	}
	for _, cand := range []string{"acc1=Acme", "acc2=Beta"} {
		if !strings.Contains(err.Error(), cand) {
			t.Errorf("the error must list the candidate %q: %v", cand, err)
		}
	}
	// Previous metadata resolves the ambiguity on re-login.
	in.Existing = map[string]string{metaAccountID: "acc1"}
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata[metaAccountID] != "acc1" || res.Metadata[metaAccountName] != "Acme" {
		t.Fatalf("metadata: %v", res.Metadata)
	}
}

func TestLoginToleratesMissingAccountRead(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/user/tokens/verify":
			_, _ = w.Write([]byte(`{"success":true,"errors":[],"result":{"id":"tokX","status":"active"}}`))
		default:
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"success":false,"errors":[{"code":9109,"message":"Unauthorized to access requested resource"}],"result":null}`))
		}
	}))
	defer srv.Close()
	p := &provider{baseURL: srv.URL}
	var stderr bytes.Buffer
	in := platform.LoginInput{
		Options: map[string]string{"token": "t"},
		Stdin:   strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr,
		NoBrowser: true,
	}
	res, err := p.Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata[metaAccountID] != "" || res.Metadata[metaTokenID] != "tokX" || res.Label != "token tokX" {
		t.Fatalf("metadata/label: %v %q", res.Metadata, res.Label)
	}
	if !strings.Contains(stderr.String(), "cannot list accounts") {
		t.Fatalf("expected note about accounts, got: %s", stderr.String())
	}
}

func TestToBodyAndToRecord(t *testing.T) {
	px := false
	b := toBody(platform.Record{Name: "Sub.Example.COM.", Type: "txt", Value: "v=spf1", TTL: 0, Proxied: &px, Extra: map[string]any{"tags": []string{"a", "b"}}})
	if b.Name != "sub.example.com" || b.Type != "TXT" || b.TTL != 1 || b.Proxied == nil || *b.Proxied || len(b.Tags) != 2 || b.Comment != nil {
		t.Fatalf("body: %+v", b)
	}
	b = toBody(platform.Record{Name: "a.example.com", Type: "A", Value: "1.1.1.1", TTL: 300})
	if b.TTL != 300 || b.Priority != nil || b.Proxied != nil {
		t.Fatalf("body: %+v", b)
	}
	if got, _ := json.Marshal(b); strings.Contains(string(got), "priority") || strings.Contains(string(got), "proxied") {
		t.Fatalf("unset fields must be omitted: %s", got)
	}

	r := toRecord(apiRecord{ID: "x", Name: "Example.com.", Type: "a", Content: "1.1.1.1", TTL: 1, Data: map[string]any{"k": "v"}})
	if r.Name != "example.com" || r.Type != "A" || r.Priority != nil || r.Extra["data"] == nil {
		t.Fatalf("record: %+v", r)
	}

	// data is only sent for the types whose components live there; an A
	// record with a stray data map keeps its content.
	b = toBody(r)
	if b.Data != nil || b.Content != "1.1.1.1" {
		t.Fatalf("A record must not send data: %+v", b)
	}
	caa := toBody(platform.Record{Name: "example.com", Type: "caa", Value: "0 issue letsencrypt.org", TTL: 1, Extra: map[string]any{"data": map[string]any{"flags": 0, "tag": "issue", "value": "letsencrypt.org"}}})
	got, _ := json.Marshal(caa)
	if caa.Content != "" || caa.Data["tag"] != "issue" || strings.Contains(string(got), `"content"`) || !strings.Contains(string(got), `"data"`) {
		t.Fatalf("CAA body: %s", got)
	}
	// Without data the formatted content is sent as before.
	caa = toBody(platform.Record{Name: "example.com", Type: "CAA", Value: "0 issue letsencrypt.org", TTL: 1})
	if caa.Content != "0 issue letsencrypt.org" || caa.Data != nil {
		t.Fatalf("CAA body without data: %+v", caa)
	}
}

func TestClassifyCodes(t *testing.T) {
	if err := classify(0, []message{{Code: 1061, Message: "Zone already exists"}}); err != nil {
		t.Fatalf("1061 is a conflict, not not-found: %v", err)
	}
	if err := classify(0, []message{{Code: 1001, Message: "Invalid zone identifier"}}); err != nil {
		t.Fatalf("1001 is unverified and must stay a plain error: %v", err)
	}
	if err := classify(0, []message{{Code: 7003, Message: "Could not route"}}); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("7003: %v", err)
	}
	if err := classify(0, []message{{Code: 81044, Message: "Record does not exist."}}); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("81044: %v", err)
	}
	if err := classify(0, []message{{Code: 9109, Message: "Invalid access token"}}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("9109: %v", err)
	}
}

func TestFQDNConversionForNativeCommands(t *testing.T) {
	z := "example.com"
	cases := map[string]string{"www": "www.example.com", "@": "example.com", "": "example.com", "www.example.com": "www.example.com", "a.b": "a.b.example.com"}
	for in, want := range cases {
		if got := platform.FQDN(in, z); got != want {
			t.Errorf("FQDN(%q) = %q, want %q", in, got, want)
		}
	}
	if platform.RelativeName("www.example.com", z) != "www" || platform.RelativeName("example.com", z) != "@" {
		t.Error("RelativeName")
	}
}

func TestMatchZone(t *testing.T) {
	zones := []platform.Zone{{ID: "zone1", Name: "example.com"}, {ID: "zone2", Name: "example.org"}}
	if z := matchZone(zones, "Example.COM."); z == nil || z.ID != "zone1" {
		t.Fatalf("by name: %+v", z)
	}
	if z := matchZone(zones, "zone2"); z == nil || z.Name != "example.org" {
		t.Fatalf("by id: %+v", z)
	}
	if matchZone(zones, "nope.com") != nil {
		t.Fatal("unexpected match")
	}
}

func TestCommandTree(t *testing.T) {
	cmd := Command(nil)
	// The tree is named after the platform id; cf stays as its one alias.
	if cmd.Use != "cloudflare" || !reflect.DeepEqual(cmd.Aliases, []string{"cf"}) {
		t.Fatalf("use: %s, aliases: %v", cmd.Use, cmd.Aliases)
	}
	want := []string{"whoami", "zone list", "zone get", "dns list", "dns create", "dns update", "dns delete", "cache purge", "dev-mode", "ssl-mode", "account list"}
	for _, w := range want {
		c, _, err := cmd.Find(strings.Fields(w))
		if err != nil || c == nil || c == cmd {
			t.Errorf("missing command %q: %v", w, err)
			continue
		}
		if strings.Fields(w)[len(strings.Fields(w))-1] != c.Name() {
			t.Errorf("command %q resolved to %q", w, c.Name())
		}
	}
	for _, flag := range []string{"type", "name", "value", "ttl", "priority", "proxied"} {
		c, _, _ := cmd.Find([]string{"dns", "create"})
		if c.Flags().Lookup(flag) == nil {
			t.Errorf("dns create lacks --%s", flag)
		}
	}
	// The record id is a required argument of update and delete, not a flag.
	for _, verb := range []string{"update", "delete"} {
		c, _, _ := cmd.Find([]string{"dns", verb})
		if c.Flags().Lookup("id") != nil || c.Use != verb+" <zone> <record-id>" {
			t.Errorf("dns %s: use %q, --id %v", verb, c.Use, c.Flags().Lookup("id") != nil)
		}
		if err := c.Args(c, []string{"example.com"}); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "record id is required") {
			t.Errorf("dns %s without the id = %v", verb, err)
		}
		if err := c.Args(c, []string{"example.com", "rec1"}); err != nil {
			t.Errorf("dns %s <zone> <record-id> = %v", verb, err)
		}
	}
	// --proxied is a boolean on create and update.
	for _, verb := range []string{"create", "update"} {
		c, _, _ := cmd.Find([]string{"dns", verb})
		if f := c.Flags().Lookup("proxied"); f == nil || f.Value.Type() != "bool" {
			t.Errorf("dns %s --proxied = %+v, want a boolean flag", verb, f)
		}
	}
	if c, _, _ := cmd.Find([]string{"token"}); c != cmd {
		t.Errorf("`token` still exists: %s", c.CommandPath())
	}
}

func TestContextCancellation(t *testing.T) {
	_, srv := newFake(t)
	c := openClient(t, srv, "good-token", "")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := c.ListZones(ctx); err == nil {
		t.Fatal("cancelled context must fail")
	}
}

// refusingReader fails the test when the login reads stdin.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

// The non-interactive flow never asks: the token comes from --set or the
// environment, without guidance, label or browser. A missing token is a
// usage error raised without reading stdin, so an idle pipe cannot block it.
func TestLoginNonInteractive(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	t.Setenv(tokenEnv, "")
	run := func(stdin io.Reader, opts map[string]string) (*platform.LoginResult, string, int, error) {
		var stderr bytes.Buffer
		opened := 0
		res, err := p.Login(context.Background(), platform.LoginInput{
			Options: opts, Stdin: stdin, Stdout: &bytes.Buffer{}, Stderr: &stderr,
			// NoBrowser is left unset on purpose: the provider itself must
			// not reach the browser when it is not interactive.
			OpenBrowser: func(string) error { opened++; return nil },
		})
		return res, stderr.String(), opened, err
	}

	// No token: a usage error that names every way to pass it. stdin is not
	// read, whatever it holds: it is data, and it may never deliver a line.
	_, stderr, opened, err := run(refusingReader{t}, map[string]string{"account_id": "acc1"})
	if !errors.Is(err, app.ErrUsage) {
		t.Fatalf("no token = %v, want a usage error", err)
	}
	for _, want := range []string{tokenEnv, "--set token=-", "stdin"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the usage error does not name %q: %v", want, err)
		}
	}
	if opened != 0 || stderr != "" {
		t.Errorf("no token: browser opened %d time(s), stderr %q; want neither", opened, stderr)
	}

	// The environment variable supplies it, again without touching stdin.
	t.Setenv(tokenEnv, " good-token ")
	res, _, opened, err := run(refusingReader{t}, map[string]string{"account_id": "acc1"})
	if err != nil || res.Secret[secretToken] != "good-token" || opened != 0 {
		t.Fatalf("token from %s: %v %+v, browser opened %d time(s)", tokenEnv, err, res, opened)
	}
	t.Setenv(tokenEnv, "")

	// With the token given, stdin is not touched; several accounts are a
	// usage error and not a question.
	_, stderr, opened, err = run(refusingReader{t}, map[string]string{"token": "good-token"})
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set account_id=<id>") {
		t.Errorf("several accounts = %v, want a usage error naming --set account_id", err)
	}
	if opened != 0 || strings.Contains(stderr, "Account") {
		t.Errorf("several accounts: browser opened %d time(s), stderr %q", opened, stderr)
	}
	if res, _, _, err := run(refusingReader{t}, map[string]string{"token": "good-token", "account_id": "acc2"}); err != nil || res.Metadata[metaAccountID] != "acc2" {
		t.Errorf("with --set account_id: %v %+v", err, res)
	}
}

// The interactive flow asks which account to use when the token sees several.
func TestLoginInteractiveChoosesAccount(t *testing.T) {
	_, srv := newFake(t)
	p := &provider{baseURL: srv.URL}
	var stderr bytes.Buffer
	res, err := p.Login(context.Background(), platform.LoginInput{
		Interactive: true, NoBrowser: true,
		Options: map[string]string{"token": "good-token"},
		Stdin:   strings.NewReader("2\n"), Stdout: &bytes.Buffer{}, Stderr: &stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Metadata[metaAccountID] != "acc2" || !strings.Contains(stderr.String(), "Account") {
		t.Errorf("chosen account: %+v (stderr %q)", res.Metadata, stderr.String())
	}
}
