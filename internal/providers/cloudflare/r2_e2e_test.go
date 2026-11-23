package cloudflare_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/providers/cloudflare"
)

// r2Account is an account of the fake R2 API.
type r2Account struct {
	id         string
	name       string
	r2Disabled bool // R2 endpoints answer 403 / code 10042
	buckets    []string
	domains    map[string][]map[string]any // bucket -> custom domains
}

type r2Zone struct {
	id, name, status, account string
}

// r2Fake is the part of the Cloudflare v4 API the R2 commands use: tokens,
// accounts, zones, DNS records and the R2 bucket and custom domain
// endpoints, with the behaviour observed on the real API (the update and
// the removal of a domain that is not bound answer 200, the creation
// answers 409 / 10052 for a domain in use, 400 / 10051 for a zone that does
// not fit, and creates a read-only CNAME record).
type r2Fake struct {
	t        *testing.T
	mu       sync.Mutex
	tokens   map[string]string // token -> account id
	accounts map[string]*r2Account
	zones    []r2Zone
	records  map[string][]map[string]any // zone id -> records
	requests []string
	bodies   map[string]string // "METHOD path" -> last body
	pageSize int               // bucket page size the fake enforces
	postErr  int               // when set, the creation of a domain fails with this code (HTTP 400)
	nextID   int
	headers  []string // cf-r2-jurisdiction values seen
}

func newR2Fake(t *testing.T) *r2Fake {
	return &r2Fake{
		t:      t,
		tokens: map[string]string{"tok-acme": "acc1", "tok-beta": "acc2"},
		accounts: map[string]*r2Account{
			"acc1": {id: "acc1", name: "Acme", domains: map[string][]map[string]any{}},
			"acc2": {id: "acc2", name: "Beta", domains: map[string][]map[string]any{}},
		},
		zones: []r2Zone{
			{"zone-ex", "example.com", "active", "acc1"},
			{"zone-a", "a.example.com", "active", "acc1"},
			{"zone-couk", "example.co.uk", "active", "acc1"},
			{"zone-pend", "pending.test", "pending", "acc1"},
			{"zone-beta", "example.net", "active", "acc2"},
		},
		records:  map[string][]map[string]any{},
		bodies:   map[string]string{},
		pageSize: 1000,
	}
}

func (f *r2Fake) ok(w http.ResponseWriter, result any, info map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
	if info != nil {
		body["result_info"] = info
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *r2Fake) fail(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": msg}}, "messages": []any{}, "result": nil})
}

// writes lists the requests that are not reads.
func (f *r2Fake) writes() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.requests {
		if !strings.HasPrefix(r, "GET ") {
			out = append(out, r)
		}
	}
	return out
}

func (f *r2Fake) count(prefix string) int {
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

func (f *r2Fake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
	f.bodies = map[string]string{}
	f.headers = nil
}

func (f *r2Fake) body(key string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var m map[string]any
	_ = json.Unmarshal([]byte(f.bodies[key]), &m)
	return m
}

func (f *r2Fake) zoneByID(id string) *r2Zone {
	for i := range f.zones {
		if f.zones[i].id == id {
			return &f.zones[i]
		}
	}
	return nil
}

func (f *r2Fake) zoneJSON(z r2Zone) map[string]any {
	return map[string]any{"id": z.id, "name": z.name, "status": z.status, "account": map[string]any{"id": z.account, "name": f.accounts[z.account].name}}
}

// bind records a custom domain and the CNAME record Cloudflare creates.
func (f *r2Fake) bind(acc, bucket, domain, zoneID string, enabled bool, minTLS string) {
	z := f.zoneByID(zoneID)
	d := map[string]any{"domain": domain, "enabled": enabled, "zoneId": zoneID, "zoneName": z.name,
		"status": map[string]any{"ownership": "pending", "ssl": "initializing"}}
	if minTLS != "" {
		d["minTLS"] = minTLS
	}
	a := f.accounts[acc]
	a.domains[bucket] = append(a.domains[bucket], d)
	f.nextID++
	f.records[zoneID] = append(f.records[zoneID], map[string]any{
		"id": fmt.Sprintf("cname%d", f.nextID), "zone_id": zoneID, "zone_name": z.name, "name": domain, "type": "CNAME",
		"content": "public.r2.dev", "ttl": 1, "proxied": true, "proxiable": true,
		"meta": map[string]any{"r2_bucket": bucket, "read_only": true},
	})
}

func (f *r2Fake) unbind(acc, bucket, domain string) {
	a := f.accounts[acc]
	var keep []map[string]any
	for _, d := range a.domains[bucket] {
		if d["domain"] != domain {
			keep = append(keep, d)
		}
	}
	a.domains[bucket] = keep
	for zid, recs := range f.records {
		var rest []map[string]any
		for _, r := range recs {
			if r["name"] == domain && r["type"] == "CNAME" && r["meta"] != nil {
				continue
			}
			rest = append(rest, r)
		}
		f.records[zid] = rest
	}
}

func (f *r2Fake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.bodies[r.Method+" "+r.URL.Path] = string(b)
	if j := r.Header.Get("cf-r2-jurisdiction"); j != "" {
		f.headers = append(f.headers, j)
	}
	acc, known := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !known {
		f.fail(w, http.StatusForbidden, 9109, "Invalid access token")
		return
	}
	p := r.URL.Path
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/user/tokens/verify":
		f.ok(w, map[string]any{"id": "tok-id", "status": "active"}, nil)
	case p == "/user":
		f.ok(w, map[string]any{"id": "user", "email": "ops@example.com"}, nil)
	case p == "/accounts":
		a := f.accounts[acc]
		f.ok(w, []any{map[string]any{"id": a.id, "name": a.name}}, map[string]any{"page": 1, "per_page": 50, "count": 1, "total_count": 1})
	case p == "/zones":
		var out []any
		for _, z := range f.zones {
			if z.account != acc {
				continue
			}
			if want := r.URL.Query().Get("account.id"); want != "" && want != z.account {
				continue
			}
			if want := r.URL.Query().Get("name"); want != "" && want != z.name {
				continue
			}
			out = append(out, f.zoneJSON(z))
		}
		f.ok(w, out, map[string]any{"page": 1, "per_page": 50, "count": len(out), "total_count": len(out), "total_pages": 1})
	case parts[0] == "zones" && len(parts) == 2:
		z := f.zoneByID(parts[1])
		if z == nil || z.account != acc {
			f.fail(w, http.StatusNotFound, 7003, "Could not route")
			return
		}
		f.ok(w, f.zoneJSON(*z), nil)
	case parts[0] == "zones" && len(parts) >= 3 && parts[2] == "dns_records":
		z := f.zoneByID(parts[1])
		if z == nil || z.account != acc {
			f.fail(w, http.StatusNotFound, 7003, "Could not route")
			return
		}
		if len(parts) == 3 {
			var out []any
			for _, rec := range f.records[z.id] {
				if n := r.URL.Query().Get("name"); n != "" && rec["name"] != n {
					continue
				}
				if t := r.URL.Query().Get("type"); t != "" && rec["type"] != t {
					continue
				}
				out = append(out, rec)
			}
			f.ok(w, out, map[string]any{"page": 1, "per_page": 100, "count": len(out), "total_count": len(out), "total_pages": 1})
			return
		}
		for i, rec := range f.records[z.id] {
			if rec["id"] != parts[3] {
				continue
			}
			switch r.Method {
			case http.MethodGet:
				f.ok(w, rec, nil)
			case http.MethodDelete:
				if m, _ := rec["meta"].(map[string]any); m != nil && m["read_only"] == true {
					f.fail(w, http.StatusBadRequest, 1052, "Unable to edit this record. It was generated by Cloudflare and can be modified in your R2 configuration")
					return
				}
				f.records[z.id] = append(f.records[z.id][:i:i], f.records[z.id][i+1:]...)
				f.ok(w, map[string]any{"id": parts[3]}, nil)
			}
			return
		}
		f.fail(w, http.StatusNotFound, 81044, "Record does not exist")
	case parts[0] == "accounts" && len(parts) >= 4 && parts[2] == "r2" && parts[3] == "buckets":
		f.serveR2(w, r, acc, parts, b)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		f.fail(w, http.StatusNotFound, 7000, "No route")
	}
}

func (f *r2Fake) serveR2(w http.ResponseWriter, r *http.Request, tokenAcc string, parts []string, body []byte) {
	if parts[1] != tokenAcc {
		f.fail(w, http.StatusForbidden, 10000, "Authentication error")
		return
	}
	a := f.accounts[tokenAcc]
	if a.r2Disabled {
		f.fail(w, http.StatusForbidden, 10042, "Please enable R2 through the Cloudflare Dashboard.")
		return
	}
	if r.Header.Get("cf-r2-jurisdiction") != "" {
		// No bucket of another jurisdiction exists in the fake.
		if len(parts) == 4 {
			f.ok(w, map[string]any{"buckets": []any{}}, map[string]any{"total_count": 0, "per_page": 1000})
		} else {
			f.fail(w, http.StatusNotFound, 10006, "The specified bucket does not exist.")
		}
		return
	}
	if len(parts) == 4 {
		// The bucket listing: cursor paging, the last page has no cursor.
		var names []string
		for _, n := range a.buckets {
			if strings.Contains(n, r.URL.Query().Get("name_contains")) {
				names = append(names, n)
			}
		}
		sort.Strings(names)
		start := 0
		if c := r.URL.Query().Get("cursor"); c != "" {
			start, _ = strconv.Atoi(strings.TrimPrefix(c, "cur-"))
		}
		end := min(start+f.pageSize, len(names))
		var out []any
		for _, n := range names[start:end] {
			out = append(out, map[string]any{"name": n, "creation_date": "2024-05-01T08:00:00Z"})
		}
		info := map[string]any{"total_count": len(a.buckets), "per_page": f.pageSize}
		if end < len(names) {
			info["cursor"] = fmt.Sprintf("cur-%d", end)
		}
		f.ok(w, map[string]any{"buckets": out}, info)
		return
	}
	bucket := parts[4]
	exists := false
	for _, n := range a.buckets {
		exists = exists || n == bucket
	}
	if !exists {
		f.fail(w, http.StatusNotFound, 10006, "The specified bucket does not exist.")
		return
	}
	if len(parts) == 5 {
		f.ok(w, map[string]any{"name": bucket, "creation_date": "2024-05-01T08:00:00Z", "location": "APAC", "storage_class": "Standard", "jurisdiction": "default"}, nil)
		return
	}
	find := func(domain string) map[string]any {
		for _, d := range a.domains[bucket] {
			if d["domain"] == domain {
				return d
			}
		}
		return nil
	}
	if len(parts) == 7 {
		switch r.Method {
		case http.MethodGet:
			f.ok(w, map[string]any{"domains": append([]map[string]any{}, a.domains[bucket]...)}, nil)
		case http.MethodPost:
			var in map[string]any
			_ = json.Unmarshal(body, &in)
			domain, _ := in["domain"].(string)
			zoneID, _ := in["zoneId"].(string)
			if zoneID == "" {
				f.fail(w, http.StatusBadRequest, 10040, "The JSON you provided was not well formed.")
				return
			}
			if f.postErr != 0 {
				f.fail(w, http.StatusBadRequest, f.postErr, "The specified zone id is not valid.")
				return
			}
			for _, acct := range f.accounts {
				for _, ds := range acct.domains {
					for _, d := range ds {
						if d["domain"] == domain {
							f.fail(w, http.StatusConflict, 10052, "Domain already in use.")
							return
						}
					}
				}
			}
			z := f.zoneByID(zoneID)
			if z == nil || z.account != tokenAcc {
				f.fail(w, http.StatusBadRequest, 10057, "The zone for this domain was not found or has not finished being added to Cloudflare.")
				return
			}
			if z.status != "active" || !(domain == z.name || strings.HasSuffix(domain, "."+z.name)) {
				f.fail(w, http.StatusBadRequest, 10051, "The specified zone id is not valid.")
				return
			}
			for _, rec := range f.records[zoneID] {
				if rec["name"] == domain && (rec["type"] == "A" || rec["type"] == "AAAA" || rec["type"] == "CNAME") {
					f.fail(w, http.StatusBadRequest, 10051, "The specified zone id is not valid.")
					return
				}
			}
			enabled, _ := in["enabled"].(bool)
			minTLS, _ := in["minTLS"].(string)
			f.bind(tokenAcc, bucket, domain, zoneID, enabled, minTLS)
			echo := map[string]any{"domain": domain, "enabled": enabled, "zoneId": zoneID}
			if minTLS != "" {
				echo["minTLS"] = minTLS
			}
			f.ok(w, echo, nil)
		}
		return
	}
	domain := parts[7]
	d := find(domain)
	switch r.Method {
	case http.MethodGet:
		if d == nil {
			f.fail(w, http.StatusNotFound, 10053, "Domain not found.")
			return
		}
		f.ok(w, d, nil)
	case http.MethodPut:
		var in map[string]any
		_ = json.Unmarshal(body, &in)
		if d == nil {
			// The real API answers 200 and creates nothing.
			f.ok(w, map[string]any{"domain": domain, "enabled": false}, nil)
			return
		}
		if v, ok := in["enabled"]; ok {
			d["enabled"] = v
		}
		if v, ok := in["minTLS"]; ok {
			d["minTLS"] = v
		}
		f.ok(w, map[string]any{"domain": domain, "enabled": d["enabled"]}, nil)
	case http.MethodDelete:
		// 200 whether or not the domain is bound.
		f.unbind(tokenAcc, bucket, domain)
		f.ok(w, map[string]any{"domain": domain}, nil)
	}
}

// r2Env runs the command line against the fake, with the profiles acme
// (account acc1) and beta (account acc2) logged in.
type r2Env struct {
	t   *testing.T
	dir string
	f   *r2Fake
}

func newR2Env(t *testing.T) *r2Env {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	t.Setenv(app.EnvNonInteractive, "")
	f := newR2Fake(t)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cloudflare.UseBaseURL(t, srv.URL)
	e := &r2Env{t: t, dir: dir, f: f}
	for _, p := range []string{"acme", "beta"} {
		if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", p, "--set", "token=tok-"+p); code != cli.ExitOK {
			t.Fatalf("login %s: exit %d, %s", p, code, stderr)
		}
	}
	f.reset()
	return e
}

func (e *r2Env) run(args ...string) (int, string, string) {
	e.t.Helper()
	return e.runIn(nil, "", args...)
}

// runIn runs the command line; a picker makes the run interactive, and
// answers are the lines a person types.
func (e *r2Env) runIn(picker *terminal, answers string, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(answers), &out, &errb)
	if picker != nil {
		rt.Picker = *picker
	}
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
	root.SetIn(strings.NewReader(answers))
	root.SetOut(&out)
	root.SetErr(&errb)
	err := root.ExecuteContext(context.Background())
	_ = rt.Close()
	text := errb.String()
	if err != nil {
		text += "error: " + err.Error() + "\n"
	}
	return cli.ExitCodeFor(err), out.String(), text
}

func (e *r2Env) report(stdout string) platform.Report {
	e.t.Helper()
	var rep platform.Report
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		e.t.Fatalf("not a report: %q (%v)", stdout, err)
	}
	return rep
}

// cachedRecords lists the DNS records of the inventory named name.
func (e *r2Env) cachedRecords(name string) []inventory.Resource {
	e.t.Helper()
	db, err := inventory.Open(e.dir + "/inventory.db")
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.Cloudflare, Type: platform.ResDNSRecord, Name: name})
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

func actions(rep platform.Report) []string {
	var out []string
	for _, c := range rep.Changes {
		out = append(out, c.Resource+" "+string(c.Action))
	}
	return out
}

func TestR2BucketList(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "backups", "c1", "c2", "c3", "c4", "c5"}
	e.f.accounts["acc2"].buckets = []string{"media"}
	e.f.pageSize = 3

	code, stdout, stderr := e.run("cloudflare", "r2", "bucket", "list", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var rows []map[string]any
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil || len(rows) != 8 {
		t.Fatalf("rows = %s (%v)", stdout, err)
	}
	if rows[0]["profile"] != "acme" || rows[0]["account_id"] != "acc1" || rows[0]["name"] != "assets" || rows[0]["creation_date"] == "" || rows[7]["profile"] != "beta" {
		t.Errorf("rows = %v", rows)
	}
	if _, has := rows[0]["location"]; has {
		t.Errorf("the listing has no location without --wide: %v", rows[0])
	}
	// Three pages for acme: the cursor of each page is passed on.
	if n := e.f.count("GET /accounts/acc1/r2/buckets?"); n != 3 || e.f.count("GET /accounts/acc1/r2/buckets?cursor=cur-6") != 1 {
		t.Errorf("acme listing took %d requests: %v", n, e.f.requests)
	}

	// --profile lists one account; --wide reads each bucket.
	e.f.pageSize = 1000
	code, stdout, _ = e.run("cloudflare", "r2", "bucket", "list", "--profile", "beta", "--wide")
	if code != cli.ExitOK || !strings.Contains(stdout, "LOCATION") || !strings.Contains(stdout, "media") || !strings.Contains(stdout, "APAC") || strings.Contains(stdout, "assets") {
		t.Errorf("beta --wide: exit %d, %q", code, stdout)
	}

	// An account without R2 is skipped silently; the other one is listed.
	e.f.accounts["acc1"].r2Disabled = true
	code, stdout, stderr = e.run("cloudflare", "r2", "bucket", "list")
	if code != cli.ExitOK || !strings.Contains(stdout, "media") || strings.Contains(stderr, "warning") {
		t.Errorf("acme without R2: exit %d, %q, %q", code, stdout, stderr)
	}
	// With --profile it is not supported (exit code 7).
	code, _, stderr = e.run("cloudflare", "r2", "bucket", "list", "--profile", "acme")
	if code != cli.ExitNotSupported || !strings.Contains(stderr, "R2 is not enabled") {
		t.Errorf("--profile acme without R2: exit %d, %q", code, stderr)
	}
	// No bucket at all: an empty list and exit code 0.
	e.f.accounts["acc2"].buckets = nil
	code, stdout, _ = e.run("cloudflare", "r2", "bucket", "list", "-o", "json")
	if code != cli.ExitOK || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("no buckets: exit %d, %q", code, stdout)
	}
	// --jurisdiction goes with every R2 request as a header.
	e.f.accounts["acc1"].r2Disabled = false
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "r2", "bucket", "list", "--jurisdiction", "eu"); code != cli.ExitOK || len(e.f.headers) != 2 || e.f.headers[0] != "eu" {
		t.Errorf("--jurisdiction: exit %d, headers %v, %s", code, e.f.headers, stderr)
	}
	// Offline: R2 is not cached.
	if code, _, _ := e.run("--offline", "cloudflare", "r2", "bucket", "list"); code != cli.ExitOffline {
		t.Errorf("--offline: exit %d", code)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("a listing wrote: %v", w)
	}
}

func TestR2DomainRouting(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.bind("acc2", "assets", "cdn.example.net", "zone-beta", true, "")

	// The bucket is in beta only.
	code, stdout, stderr := e.run("cloudflare", "r2", "domain", "list", "assets", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stderr, "bucket assets via cloudflare/beta") {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var res struct {
		Bucket  string           `json:"bucket"`
		Profile string           `json:"profile"`
		Domains []map[string]any `json:"domains"`
	}
	if err := json.Unmarshal([]byte(stdout), &res); err != nil || res.Profile != "beta" || len(res.Domains) != 1 {
		t.Fatalf("list = %s (%v)", stdout, err)
	}
	d := res.Domains[0]
	if d["domain"] != "cdn.example.net" || d["zone_id"] != "zone-beta" || d["zone_name"] != "example.net" || d["min_tls"] != nil || d["enabled"] != true {
		t.Errorf("domain = %v", d)
	}
	if st, _ := d["status"].(map[string]any); st["ownership"] != "pending" || st["ssl"] != "initializing" {
		t.Errorf("status = %v", d["status"])
	}
	// Table: MIN_TLS is "-" when never set.
	code, stdout, _ = e.run("cloudflare", "r2", "domain", "list", "assets")
	if code != cli.ExitOK || !strings.Contains(stdout, "MIN_TLS") || !strings.Contains(stdout, "example.net") || !strings.Contains(stdout, " - ") {
		t.Errorf("table: %q", stdout)
	}

	// acme without R2 is skipped, beta still found.
	e.f.accounts["acc1"].r2Disabled = true
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "assets"); code != cli.ExitOK {
		t.Errorf("acme skipped: exit %d, %s", code, stderr)
	}
	// Nowhere: not found, naming the skipped profile.
	code, _, stderr = e.run("cloudflare", "r2", "domain", "list", "nosuch")
	if code != cli.ExitNotFound || !strings.Contains(stderr, "bucket nosuch not found in any cloudflare profile") || !strings.Contains(stderr, "acme (R2 is not enabled)") {
		t.Errorf("missing bucket: exit %d, %s", code, stderr)
	}
	// Two accounts with the bucket: ambiguous.
	e.f.accounts["acc1"].r2Disabled = false
	e.f.accounts["acc1"].buckets = []string{"assets"}
	code, _, stderr = e.run("cloudflare", "r2", "domain", "list", "assets")
	if code != cli.ExitAmbiguous || !strings.Contains(stderr, "--profile") {
		t.Errorf("ambiguous: exit %d, %s", code, stderr)
	}
	if code, _, _ := e.run("cloudflare", "r2", "domain", "list", "assets", "--profile", "acme"); code != cli.ExitOK {
		t.Errorf("--profile acme: exit %d", code)
	}
	// --profile with a bucket the account does not have: not found.
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "list", "nosuch", "--profile", "acme"); code != cli.ExitNotFound || !strings.Contains(stderr, "bucket nosuch not found") {
		t.Errorf("--profile, missing bucket: exit %d, %s", code, stderr)
	}

	// get: one domain; a domain that is not bound is not found.
	code, stdout, _ = e.run("cloudflare", "r2", "domain", "get", "assets", "CDN.example.net.", "--profile", "beta", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"domain": "cdn.example.net"`) {
		t.Errorf("get: exit %d, %q", code, stdout)
	}
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "get", "assets", "www.example.net", "--profile", "beta"); code != cli.ExitNotFound || !strings.Contains(stderr, "not bound to bucket assets") {
		t.Errorf("get unbound: exit %d, %s", code, stderr)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("reads wrote: %v", w)
	}
}

func TestR2DomainEnsure(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.accounts["acc2"].buckets = []string{"media"}

	// A dry run reads, writes nothing, and reports what it would create.
	code, stdout, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com", "--dry-run", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("dry run: exit %d, %s", code, stderr)
	}
	rep := e.report(stdout)
	if !rep.DryRun || len(rep.Changes) != 2 || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].Detail != "enabled=true zone=a.example.com" ||
		rep.Changes[1].Resource != "r2/assets/domain/cdn.a.example.com/dns-record" || rep.Target.Profile != "acme" || rep.Target.Zone != "a.example.com" {
		t.Errorf("dry run report = %+v", rep)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("dry run wrote: %v", w)
	}

	// The real run: one POST with domain, enabled and the zone id, the
	// CNAME record reported and stored in the inventory.
	e.f.reset()
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("ensure: exit %d, %s", code, stderr)
	}
	rep = e.report(stdout)
	if got := actions(rep); len(got) != 2 || got[0] != "r2/assets/domain/cdn.a.example.com created" || got[1] != "r2/assets/domain/cdn.a.example.com/dns-record created" {
		t.Errorf("changes = %v", got)
	}
	if !strings.Contains(rep.Changes[1].Detail, "CNAME cdn.a.example.com -> public.r2.dev (proxied, auto-created by Cloudflare)") {
		t.Errorf("record detail = %q", rep.Changes[1].Detail)
	}
	if w := e.f.writes(); len(w) != 1 || w[0] != "POST /accounts/acc1/r2/buckets/assets/domains/custom" {
		t.Errorf("writes = %v", w)
	}
	body := e.f.body("POST /accounts/acc1/r2/buckets/assets/domains/custom")
	if body["domain"] != "cdn.a.example.com" || body["enabled"] != true || body["zoneId"] != "zone-a" || len(body) != 3 {
		t.Errorf("body = %v", body)
	}
	rows := e.cachedRecords("cdn.a.example.com")
	if len(rows) != 1 || !strings.Contains(string(rows[0].Data), `"r2_bucket":"assets"`) {
		t.Errorf("inventory = %v", rows)
	}

	// Again: unchanged, no write.
	for i := 0; i < 2; i++ {
		e.f.reset()
		code, stdout, _ = e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com")
		if code != cli.ExitOK || !strings.Contains(stdout, "unchanged") || len(e.f.writes()) != 0 {
			t.Errorf("repeat %d: exit %d, %q, writes %v", i, code, stdout, e.f.writes())
		}
	}

	// Disabled binding: one PUT with enabled only; --min-tls compared when given.
	e.f.accounts["acc1"].domains["assets"][0]["enabled"] = false
	e.f.accounts["acc1"].domains["assets"][0]["minTLS"] = "1.0"
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com")
	if w := e.f.writes(); code != cli.ExitOK || len(w) != 1 || !strings.HasPrefix(w[0], "PUT ") || !strings.Contains(stdout, "enabled false -> true") {
		t.Errorf("enable: exit %d, %q, writes %v", code, stdout, w)
	}
	if b := e.f.body("PUT /accounts/acc1/r2/buckets/assets/domains/custom/cdn.a.example.com"); len(b) != 1 || b["enabled"] != true {
		t.Errorf("PUT body = %v", b)
	}
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com", "--min-tls", "1.2")
	if b := e.f.body("PUT /accounts/acc1/r2/buckets/assets/domains/custom/cdn.a.example.com"); code != cli.ExitOK || len(b) != 1 || b["minTLS"] != "1.2" || !strings.Contains(stdout, "min_tls 1.0 -> 1.2") {
		t.Errorf("min tls: exit %d, %q, body %v", code, stdout, b)
	}

	// Bound with another zone than --zone: an error, nothing written.
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com", "--zone", "example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "detach it first") || len(e.f.writes()) != 0 {
		t.Errorf("other zone: exit %d, %s, writes %v", code, stderr, e.f.writes())
	}
	// The same zone by id or name: fine.
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.a.example.com", "--zone", "zone-a", "--min-tls", "1.2"); code != cli.ExitOK {
		t.Errorf("same zone by id: exit %d, %s", code, stderr)
	}

	// Zone selection: the longest match, also under a multi-label suffix.
	e.f.reset()
	if code, stdout, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "x.example.co.uk", "--dry-run"); code != cli.ExitOK || !strings.Contains(stdout, "zone=example.co.uk") {
		t.Errorf("co.uk: exit %d, %q, %s", code, stdout, stderr)
	}
	// No zone in the bucket's account (example.net is beta's): not found.
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.example.net", "--dry-run"); code != cli.ExitNotFound || !strings.Contains(stderr, "no zone for cdn.example.net") {
		t.Errorf("no zone: exit %d, %s", code, stderr)
	}
	// A zone that is not active yet is refused before anything is written.
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.pending.test"); code != cli.ExitError || !strings.Contains(stderr, "not active") {
		t.Errorf("pending zone: exit %d, %s", code, stderr)
	}
	// --zone of another account: not found.
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "attach", "assets", "cdn.example.net", "--zone", "example.net"); code != cli.ExitNotFound || !strings.Contains(stderr, "same account as the bucket") {
		t.Errorf("zone of beta: exit %d, %s", code, stderr)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("refused runs wrote: %v", w)
	}

	// --disabled and --min-tls on creation.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "img.example.com", "--disabled", "--min-tls", "1.3"); code != cli.ExitOK {
		t.Fatalf("disabled: exit %d, %s", code, stderr)
	}
	if b := e.f.body("POST /accounts/acc1/r2/buckets/assets/domains/custom"); b["enabled"] != false || b["minTLS"] != "1.3" || b["zoneId"] != "zone-ex" {
		t.Errorf("body = %v", b)
	}
	for k := range e.f.body("POST /accounts/acc1/r2/buckets/assets/domains/custom") {
		if strings.Contains(k, "_") {
			t.Errorf("snake_case key %q in a request", k)
		}
	}
}

func TestR2DomainAttachUpdateDetach(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "other"}

	// Invalid input is refused before any request.
	for _, args := range [][]string{
		{"attach", "assets", "*.example.com"},
		{"attach", "assets", "cdn example.com"},
		{"attach", "assets", "localhost"},
		{"attach", "assets", "cdn.example.com", "--zone", "example.org"},
		{"attach", "assets", "cdn.example.com", "--min-tls", "2.0"},
		{"ensure", "assets", "*.x.example.com"},
		{"update", "assets", "cdn.example.com"},
		{"get", "assets"},
	} {
		code, _, stderr := e.run(append([]string{"cloudflare", "r2", "domain"}, args...)...)
		if code != cli.ExitUsage {
			t.Errorf("%v: exit %d, %s", args, code, stderr)
		}
	}
	if len(e.f.requests) != 0 {
		t.Errorf("invalid input made requests: %v", e.f.requests)
	}

	// attach creates; the same again is an error pointing to ensure.
	code, stdout, stderr := e.run("cloudflare", "r2", "domain", "attach", "assets", "cdn.example.com")
	if code != cli.ExitOK || !strings.Contains(stdout, "created") || !strings.Contains(stdout, "enabled=true zone=example.com") {
		t.Fatalf("attach: exit %d, %q, %s", code, stdout, stderr)
	}
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "assets", "cdn.example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "r2 domain ensure") {
		t.Errorf("attach again: exit %d, %s", code, stderr)
	}
	// Bound to another bucket: the API refuses (409 / 10052).
	e.f.reset()
	delete(e.f.records, "zone-ex") // no record to warn about beforehand
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "attach", "other", "cdn.example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "already in use") || !strings.Contains(stdout, "failed") {
		t.Errorf("attach to another bucket: exit %d, %q, %s", code, stdout, stderr)
	}
	// An A record of the same name is found before the binding is sent.
	e.f.records["zone-ex"] = append(e.f.records["zone-ex"], map[string]any{"id": "a1", "name": "www.example.com", "type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": false})
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "assets", "www.example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "A record www.example.com") || len(e.f.writes()) != 0 {
		t.Errorf("A record: exit %d, %s, writes %v", code, stderr, e.f.writes())
	}
	// When the API refuses with 10051 all the same, the message lists the causes.
	e.f.records["zone-ex"] = nil
	e.f.postErr = 10051
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "assets", "api.example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "not active yet") || !strings.Contains(stderr, "is not in the zone") || !strings.Contains(stderr, "A, AAAA or CNAME record named api.example.com") {
		t.Errorf("10051: exit %d, %s", code, stderr)
	}
	e.f.postErr = 0
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "r2", "domain", "attach", "assets", "api.example.com", "--zone", "zone-ex")
	if code != cli.ExitOK {
		t.Fatalf("attach by zone id: exit %d, %s", code, stderr)
	}

	// update: --enabled=false reads, then PUTs enabled only.
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "r2", "domain", "update", "assets", "cdn.example.com", "--enabled=false")
	if code != cli.ExitOK || !strings.Contains(stdout, "enabled true -> false") || e.f.count("GET /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com") != 1 {
		t.Errorf("update: exit %d, %q, %v", code, stdout, e.f.requests)
	}
	if b := e.f.body("PUT /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com"); len(b) != 1 || b["enabled"] != false {
		t.Errorf("PUT body = %v", b)
	}
	// Unchanged: no PUT. Unbound: not found, no PUT (the API would say 200).
	e.f.reset()
	if code, stdout, _ := e.run("cloudflare", "r2", "domain", "update", "assets", "cdn.example.com", "--enabled=false"); code != cli.ExitOK || !strings.Contains(stdout, "unchanged") || len(e.f.writes()) != 0 {
		t.Errorf("update unchanged: exit %d, %q, %v", code, stdout, e.f.writes())
	}
	if code, _, _ := e.run("cloudflare", "r2", "domain", "update", "assets", "nope.example.com", "--min-tls", "1.2"); code != cli.ExitNotFound || len(e.f.writes()) != 0 {
		t.Errorf("update unbound: exit %d, %v", code, e.f.writes())
	}
	// --dry-run writes nothing.
	if code, stdout, _ := e.run("cloudflare", "r2", "domain", "update", "assets", "cdn.example.com", "--enabled", "--dry-run"); code != cli.ExitOK || !strings.Contains(stdout, "would update") || len(e.f.writes()) != 0 {
		t.Errorf("update --dry-run: exit %d, %q", code, stdout)
	}

	// detach: non-interactive without --yes is a usage error, before any request.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "detach", "assets", "cdn.example.com"); code != cli.ExitUsage || !strings.Contains(stderr, "--yes") || len(e.f.requests) != 0 {
		t.Errorf("detach without --yes: exit %d, %s, %v", code, stderr, e.f.requests)
	}
	// Interactive, declined: nothing to do.
	if code, _, stderr := e.runIn(&terminal{t}, "n\n", "cloudflare", "r2", "domain", "detach", "assets", "cdn.example.com"); code != cli.ExitOK || !strings.Contains(stderr, "(y/N)") || len(e.f.writes()) != 0 {
		t.Errorf("detach declined: exit %d, %s, %v", code, stderr, e.f.writes())
	}
	// --dry-run: would delete both, no question.
	code, stdout, _ = e.run("cloudflare", "r2", "domain", "detach", "assets", "cdn.example.com", "--dry-run")
	if code != cli.ExitOK || strings.Count(stdout, "would delete") != 2 || len(e.f.writes()) != 0 {
		t.Errorf("detach --dry-run: exit %d, %q", code, stdout)
	}
	// --yes: GET then DELETE; the CNAME leaves the inventory.
	if len(e.cachedRecords("cdn.example.com")) != 1 {
		t.Fatalf("the CNAME of cdn.example.com is not cached")
	}
	e.f.reset()
	code, stdout, stderr = e.run("cloudflare", "r2", "domain", "detach", "assets", "cdn.example.com", "--yes")
	if code != cli.ExitOK || strings.Count(stdout, "deleted") != 2 {
		t.Errorf("detach: exit %d, %q, %s", code, stdout, stderr)
	}
	if w := e.f.writes(); len(w) != 1 || w[0] != "DELETE /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com" || e.f.count("GET /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com") != 1 {
		t.Errorf("requests = %v", e.f.requests)
	}
	if rows := e.cachedRecords("cdn.example.com"); len(rows) != 0 {
		t.Errorf("inventory still holds %v", rows)
	}
	// Not bound (any more): not found, no DELETE.
	e.f.reset()
	if code, _, _ := e.run("cloudflare", "r2", "domain", "detach", "assets", "cdn.example.com", "--yes"); code != cli.ExitNotFound || len(e.f.writes()) != 0 {
		t.Errorf("detach unbound: exit %d, %v", code, e.f.writes())
	}
}

// Deleting the CNAME of an R2 custom domain unbinds the domain: the DNS
// record itself cannot be deleted through the DNS API.
func TestDNSDeleteUnbindsR2Domain(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.bind("acc1", "assets", "cdn.example.com", "zone-ex", true, "")
	recID := e.f.records["zone-ex"][0]["id"].(string)

	// Dry run: says so, deletes nothing.
	code, stdout, _ := e.run("cloudflare", "dns", "delete", "example.com", recID, "--profile", "acme", "--dry-run")
	if code != cli.ExitOK || !strings.Contains(stdout, "unbound from r2 bucket assets") || len(e.f.writes()) != 0 {
		t.Errorf("dry run: exit %d, %q, %v", code, stdout, e.f.writes())
	}
	// The R2 DELETE goes out, the DNS DELETE does not.
	e.f.reset()
	code, _, stderr := e.run("cloudflare", "dns", "delete", "example.com", recID, "--profile", "acme")
	if code != cli.ExitOK {
		t.Fatalf("delete: exit %d, %s", code, stderr)
	}
	if w := e.f.writes(); len(w) != 1 || w[0] != "DELETE /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com" {
		t.Errorf("writes = %v", w)
	}

	// The neutral command does the same.
	e.f.bind("acc1", "assets", "cdn.example.com", "zone-ex", true, "")
	e.f.reset()
	code, _, stderr = e.run("dns", "delete", "example.com", "--type", "CNAME", "--name", "cdn", "--profile", "acme", "--platform", "cloudflare")
	if code != cli.ExitOK || len(e.f.writes()) != 1 || !strings.HasPrefix(e.f.writes()[0], "DELETE /accounts/acc1/r2/") {
		t.Errorf("dns delete: exit %d, %s, %v", code, stderr, e.f.writes())
	}

	// R2 refused for lack of permission: no DNS DELETE, a failure.
	e.f.bind("acc1", "assets", "cdn.example.com", "zone-ex", true, "")
	recID = e.f.records["zone-ex"][0]["id"].(string)
	e.f.accounts["acc1"].r2Disabled = true
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "dns", "delete", "example.com", recID, "--profile", "acme")
	if code == cli.ExitOK || !strings.Contains(stderr, "R2 unbind failed") || !strings.Contains(stderr, "code 1052") || e.f.count("DELETE /zones/") != 0 || e.f.count("GET /accounts/acc2") != 0 {
		t.Errorf("without R2: exit %d, %s, %v", code, stderr, e.f.requests)
	}

	// The bucket is in another account: found there through its domain
	// list, and unbound there only.
	e.f.accounts["acc1"].r2Disabled = false
	e.f.accounts["acc1"].buckets = nil
	e.f.accounts["acc1"].domains = map[string][]map[string]any{}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.accounts["acc2"].domains["assets"] = []map[string]any{{"domain": "cdn.example.com", "enabled": true, "zoneId": "zone-ex"}}
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "dns", "delete", "example.com", recID, "--profile", "acme")
	if w := e.f.writes(); code != cli.ExitOK || len(w) != 2 || w[0] != "DELETE /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com" ||
		w[1] != "DELETE /accounts/acc2/r2/buckets/assets/domains/custom/cdn.example.com" || e.f.count("GET /accounts/acc2/r2/buckets/assets/domains/custom") != 1 {
		t.Errorf("other account: exit %d, %s, %v", code, stderr, e.f.requests)
	}
}

// When one of several matching records cannot be unbound, it is left in
// place, the others are deleted, and the command fails.
func TestDNSDeleteUnbindPartialFailure(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	// Two CNAME records of the name: the R2 one cannot be unbound (R2 is
	// disabled), the plain one is deleted all the same.
	e.f.bind("acc1", "assets", "cdn.example.com", "zone-ex", true, "")
	e.f.records["zone-ex"] = append(e.f.records["zone-ex"], map[string]any{
		"id": "plain1", "zone_id": "zone-ex", "zone_name": "example.com", "name": "cdn.example.com", "type": "CNAME",
		"content": "origin.example.net", "ttl": 300, "proxied": false,
	})
	e.f.accounts["acc1"].r2Disabled = true
	code, _, stderr := e.run("dns", "delete", "example.com", "--type", "CNAME", "--name", "cdn", "--profile", "acme", "--platform", "cloudflare", "--yes")
	if w := e.f.writes(); code != cli.ExitError || !strings.Contains(stderr, "R2 unbind failed") ||
		len(w) != 2 || w[1] != "DELETE /zones/zone-ex/dns_records/plain1" || !strings.HasPrefix(w[0], "DELETE /accounts/acc1/r2/") {
		t.Errorf("partial: exit %d, %s, %v", code, stderr, w)
	}
	if n := len(e.f.records["zone-ex"]); n != 1 {
		t.Errorf("records left = %d, want the R2 CNAME only", n)
	}
}

// A failed ensure goes to hooks.on_failure (a dry run notifies nobody).
func TestR2EnsureFailureHook(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	var mu sync.Mutex
	var events []map[string]any
	hook := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var ev map[string]any
		_ = json.NewDecoder(r.Body).Decode(&ev)
		mu.Lock()
		events = append(events, ev)
		mu.Unlock()
	}))
	t.Cleanup(hook.Close)
	cfgPath := filepath.Join(e.dir, "config.yaml")
	cfg, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cfgPath, append(cfg, []byte("hooks:\n  on_failure: "+hook.URL+"\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.pending.test", "--dry-run"); code != cli.ExitError {
		t.Fatalf("dry run: exit %d, %s", code, stderr)
	}
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "ensure", "assets", "cdn.pending.test"); code != cli.ExitError {
		t.Fatalf("ensure: exit %d, %s", code, stderr)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(events) != 1 || events[0]["event"] != "cloudflare.r2.domain.ensure.failed" || events[0]["profile"] != "acme" ||
		!strings.Contains(fmt.Sprint(events[0]["error"]), "not active") {
		t.Errorf("events = %v", events)
	}
}

// dns delete --all unbinds the CNAME of an R2 custom domain instead of
// deleting it, deletes the other records (a non-proxied CNAME to r2.dev
// is an ordinary record) and keeps the apex NS.
func TestDNSDeleteAllUnbindsR2Domains(t *testing.T) {
	setup := func(e *r2Env) {
		e.f.accounts["acc1"].buckets = []string{"assets"}
		e.f.records["zone-ex"] = nil
		e.f.bind("acc1", "assets", "cdn.example.com", "zone-ex", true, "")
		e.f.records["zone-ex"] = append(e.f.records["zone-ex"],
			map[string]any{"id": "a1", "zone_id": "zone-ex", "zone_name": "example.com", "name": "www.example.com", "type": "A", "content": "203.0.113.10", "ttl": 300, "proxied": false},
			map[string]any{"id": "c2", "zone_id": "zone-ex", "zone_name": "example.com", "name": "files.example.com", "type": "CNAME", "content": "pub-1.r2.dev", "ttl": 300, "proxied": false},
			map[string]any{"id": "ns1", "zone_id": "zone-ex", "zone_name": "example.com", "name": "example.com", "type": "NS", "content": "ns1.example.net", "ttl": 300, "proxied": false},
		)
		e.f.reset()
	}
	all := []string{"dns", "delete", "example.com", "--all", "--profile", "acme", "--platform", "cloudflare", "-o", "json"}

	// Dry run: nothing written, no other account searched.
	e := newR2Env(t)
	setup(e)
	code, stdout, stderr := e.run(append(all, "--dry-run")...)
	rep := e.report(stdout)
	if code != cli.ExitOK || len(e.f.writes()) != 0 || e.f.count("GET /accounts/acc2") != 0 || len(rep.Changes) != 4 ||
		rep.Changes[0].Action != platform.WouldDelete || rep.Changes[0].Attrs["via"] != "unbind:cloudflare" || rep.Changes[3].Action != platform.Skipped {
		t.Fatalf("dry run: exit %d, %s, %+v, %v", code, stderr, rep, e.f.requests)
	}

	// For real: one R2 DELETE, two DNS DELETEs, never the CNAME itself.
	code, stdout, stderr = e.run(append(all, "--yes")...)
	rep = e.report(stdout)
	w := e.f.writes()
	if code != cli.ExitOK || len(w) != 3 || w[0] != "DELETE /accounts/acc1/r2/buckets/assets/domains/custom/cdn.example.com" ||
		w[1] != "DELETE /zones/zone-ex/dns_records/a1" || w[2] != "DELETE /zones/zone-ex/dns_records/c2" || *rep.Summary != (platform.Summary{Deleted: 3, Skipped: 1}) {
		t.Errorf("delete --all: exit %d, %s, %v, %+v", code, stderr, w, rep.Summary)
	}

	// --keep-bound: the R2 CNAME is skipped and left alone.
	e = newR2Env(t)
	setup(e)
	code, stdout, stderr = e.run(append(all, "--yes", "--keep-bound")...)
	rep = e.report(stdout)
	if code != cli.ExitOK || e.f.count("DELETE /accounts/") != 0 || e.f.count("DELETE /zones/") != 2 || rep.Changes[0].Action != platform.Skipped ||
		!strings.Contains(rep.Changes[0].Detail, "--keep-bound") {
		t.Errorf("--keep-bound: exit %d, %s, %v", code, stderr, e.f.requests)
	}

	// No R2 permission: the CNAME fails without a DNS DELETE and without
	// searching the other account; the rest is deleted; exit code 1.
	e = newR2Env(t)
	setup(e)
	e.f.accounts["acc1"].r2Disabled = true
	code, stdout, stderr = e.run(append(all, "--yes")...)
	rep = e.report(stdout)
	if code != cli.ExitError || e.f.count("DELETE /accounts/acc1/r2/") != 1 || e.f.count("GET /accounts/acc2") != 0 ||
		e.f.count("DELETE /zones/zone-ex/dns_records/cname") != 0 || e.f.count("DELETE /zones/") != 2 ||
		rep.Changes[0].Action != platform.Failed || !strings.Contains(rep.Changes[0].Detail, "R2 unbind failed") || rep.Summary.Failed != 1 {
		t.Errorf("without R2: exit %d, %s, %v, %+v", code, stderr, e.f.requests, rep)
	}

	// The bucket lives in another account: found there and unbound there.
	e = newR2Env(t)
	setup(e)
	e.f.accounts["acc1"].buckets = nil
	e.f.accounts["acc1"].domains = map[string][]map[string]any{}
	e.f.accounts["acc2"].buckets = []string{"assets"}
	e.f.accounts["acc2"].domains["assets"] = []map[string]any{{"domain": "cdn.example.com", "enabled": true, "zoneId": "zone-ex"}}
	code, _, stderr = e.run(append(all, "--yes")...)
	if code != cli.ExitOK || e.f.count("DELETE /accounts/acc2/r2/buckets/assets/domains/custom/cdn.example.com") != 1 || e.f.count("DELETE /zones/zone-ex/dns_records/cname") != 0 {
		t.Errorf("other account: exit %d, %s, %v", code, stderr, e.f.requests)
	}
}
