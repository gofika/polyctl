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

// zfSetting is a zone setting of the fake.
type zfSetting struct {
	value    any
	editable bool
}

// zfZone is a zone of the fake API.
type zfZone struct {
	id, name, status, account, plan string
	ns                              []string
	foundation                      bool
	deleted                         bool
	settings                        map[string]*zfSetting
	rum, argo                       string
	records                         int
}

// zoneFake is the part of the Cloudflare v4 API the zone lifecycle commands
// use, with the answers observed on the real API: a deleted zone answers
// HTTP 400 code 1001 "Invalid zone identifier", an id that never existed
// HTTP 403 code 9109, a second zone of a name HTTP 400 code 1061, an unknown
// setting 400 / 1003 (GET) and 400 / 1006 (PATCH), a setting the plan cannot
// change 400 / 1015, and rum is missing from the bulk settings listing.
type zoneFake struct {
	t        *testing.T
	mu       sync.Mutex
	tokens   map[string]string // token -> the account ids it sees, comma-separated
	zones    []*zfZone
	requests []string
	bodies   map[string]string // "METHOD path" -> last body
	nextID   int

	// knobs
	foundationDefault map[string]bool // account -> new zones get Foundation DNS at once
	foundationErr     [2]int          // status, code of PATCH dns_settings
	subscriptionErr   [2]int          // status, code of PUT subscription
	ignoreAccount     bool            // GET /zones ignores the account (shows every account's zones)
	throttle          map[string]int  // "METHOD path" -> number of 429 answers to give first
	html              map[string]bool // "METHOD path" -> answer an HTML page (403)
	envelopeErr       map[string]int  // "METHOD path" -> HTTP 200 with success:false and this code

	rules rulesFake // the entrypoint rulesets of the zones (rules_e2e_test.go)
}

func newZoneFake(t *testing.T) *zoneFake {
	return &zoneFake{
		t:                 t,
		tokens:            map[string]string{"tok-acme": "acc1", "tok-beta": "acc2", "tok-both": "acc1,acc2"},
		bodies:            map[string]string{},
		foundationDefault: map[string]bool{},
		throttle:          map[string]int{},
		html:              map[string]bool{},
		envelopeErr:       map[string]int{},
	}
}

func defaultSettings(plan string) map[string]*zfSetting {
	ent := plan == "enterprise"
	return map[string]*zfSetting{
		"0rtt":                     {"off", true},
		"early_hints":              {"off", true},
		"always_use_https":         {"off", true},
		"automatic_https_rewrites": {"on", true},
		"ssl":                      {"full", true},
		"ipv6":                     {"on", true},
		"response_buffering":       {"off", ent},
		"min_tls_version":          {"1.0", true},
		"browser_cache_ttl":        {float64(14400), true},
	}
}

// addZone adds an existing zone.
func (f *zoneFake) addZone(name, account, plan, status string) *zfZone {
	f.nextID++
	z := &zfZone{id: fmt.Sprintf("%032x", f.nextID), name: name, status: status, account: account, plan: plan,
		ns: []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}, settings: defaultSettings(plan), rum: "off", argo: "off"}
	f.zones = append(f.zones, z)
	return z
}

func (f *zoneFake) zoneByID(id string) *zfZone {
	for _, z := range f.zones {
		if z.id == id {
			return z
		}
	}
	return nil
}

func (f *zoneFake) zoneNamed(name string) *zfZone {
	for _, z := range f.zones {
		if z.name == name && !z.deleted {
			return z
		}
	}
	return nil
}

func (f *zoneFake) zoneJSON(z *zfZone) map[string]any {
	meta := map[string]any{}
	if z.foundation {
		meta["foundation_dns"] = true
	}
	return map[string]any{"id": z.id, "name": z.name, "status": z.status, "type": "full", "paused": false,
		"name_servers": z.ns, "original_name_servers": nil, "meta": meta,
		"plan":    map[string]any{"name": strings.ToUpper(z.plan[:1]) + z.plan[1:] + " Website", "legacy_id": z.plan},
		"account": map[string]any{"id": z.account, "name": "Account " + z.account}}
}

func (f *zoneFake) setFoundation(z *zfZone, on bool) {
	z.foundation = on
	if on {
		z.ns = []string{"a.foundationdns.com", "b.foundationdns.net", "c.foundationdns.org"}
	} else {
		z.ns = []string{"ada.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	}
}

func (f *zoneFake) ok(w http.ResponseWriter, result any, info map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("cf-ray", "8f00test-NRT")
	body := map[string]any{"success": true, "errors": []any{}, "messages": []any{}, "result": result}
	if info != nil {
		body["result_info"] = info
	}
	_ = json.NewEncoder(w).Encode(body)
}

func (f *zoneFake) fail(w http.ResponseWriter, status, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("cf-ray", "8f00test-NRT")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": msg}}, "messages": []any{}, "result": nil})
}

func (f *zoneFake) writes() []string {
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

func (f *zoneFake) reqs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.requests...)
}

func (f *zoneFake) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.requests = nil
	f.bodies = map[string]string{}
}

func (f *zoneFake) body(key string) map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	var m map[string]any
	_ = json.Unmarshal([]byte(f.bodies[key]), &m)
	return m
}

func settingJSON(id string, s *zfSetting) map[string]any {
	return map[string]any{"id": id, "value": s.value, "editable": s.editable, "modified_on": nil}
}

func (f *zoneFake) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, _ := io.ReadAll(r.Body)
	key := r.Method + " " + r.URL.Path
	f.requests = append(f.requests, r.Method+" "+r.URL.RequestURI())
	f.bodies[key] = string(b)
	if n := f.throttle[key]; n > 0 {
		f.throttle[key] = n - 1
		f.fail(w, http.StatusTooManyRequests, 971, "Please wait and consider throttling your request speed")
		return
	}
	if f.html[key] {
		w.Header().Set("Content-Type", "text/html")
		w.Header().Set("cf-ray", "8f00html-NRT")
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, "<!DOCTYPE html><html><head><title>Attention Required! | Cloudflare</title></head><body>blocked</body></html>")
		return
	}
	if code := f.envelopeErr[key]; code != 0 {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": "Invalid value for zone setting"}}, "messages": []any{}, "result": nil})
		return
	}
	acc, known := f.tokens[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
	if !known {
		f.fail(w, http.StatusForbidden, 9109, "Invalid access token")
		return
	}
	var in map[string]any
	_ = json.Unmarshal(b, &in)
	p := r.URL.Path
	parts := strings.Split(strings.Trim(p, "/"), "/")
	switch {
	case p == "/user/tokens/verify":
		f.ok(w, map[string]any{"id": "tok-id", "status": "active"}, nil)
	case p == "/user":
		f.ok(w, map[string]any{"id": "user", "email": "ops@example.com"}, nil)
	case p == "/accounts":
		var out []any
		for _, id := range strings.Split(acc, ",") {
			out = append(out, map[string]any{"id": id, "name": "Account " + id})
		}
		f.ok(w, out, map[string]any{"page": 1, "per_page": 50, "count": len(out), "total_count": len(out), "total_pages": 1})
	case p == "/zones" && r.Method == http.MethodGet:
		var out []any
		for _, z := range f.zones {
			if z.deleted || (!f.ignoreAccount && !sees(acc, z.account)) {
				continue
			}
			if want := r.URL.Query().Get("account.id"); want != "" && want != z.account && !f.ignoreAccount {
				continue
			}
			if want := r.URL.Query().Get("name"); want != "" && want != z.name {
				continue
			}
			out = append(out, f.zoneJSON(z))
		}
		f.ok(w, out, map[string]any{"page": 1, "per_page": 50, "count": len(out), "total_count": len(out), "total_pages": 1})
	case p == "/zones" && r.Method == http.MethodPost:
		name := strings.ToLower(fmt.Sprint(in["name"]))
		if !strings.Contains(name, ".") {
			f.fail(w, http.StatusBadRequest, 1002, "Invalid domain")
			return
		}
		if f.zoneNamed(name) != nil {
			f.fail(w, http.StatusBadRequest, 1061, name+" already exists")
			return
		}
		account, _ := in["account"].(map[string]any)
		z := f.addZone(name, fmt.Sprint(account["id"]), "free", "pending")
		if f.foundationDefault[z.account] {
			f.setFoundation(z, true)
		}
		f.ok(w, f.zoneJSON(z), nil)
	case parts[0] == "zones" && len(parts) >= 3 && parts[2] == "rulesets":
		f.serveRules(w, r, parts[1], parts[3:], acc, b)
	case parts[0] == "zones" && len(parts) >= 2:
		z := f.zoneByID(parts[1])
		if z == nil {
			f.fail(w, http.StatusForbidden, 9109, "Invalid zone identifier")
			return
		}
		if z.deleted {
			f.fail(w, http.StatusBadRequest, 1001, "Invalid zone identifier")
			return
		}
		if !sees(acc, z.account) {
			f.fail(w, http.StatusForbidden, 10000, "Authentication error")
			return
		}
		f.serveZone(w, r, z, parts[2:], in)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		f.fail(w, http.StatusNotFound, 7000, "No route for that URI")
	}
}

func (f *zoneFake) serveZone(w http.ResponseWriter, r *http.Request, z *zfZone, rest []string, in map[string]any) {
	sub := strings.Join(rest, "/")
	switch {
	case sub == "" && r.Method == http.MethodGet:
		f.ok(w, f.zoneJSON(z), nil)
	case sub == "" && r.Method == http.MethodDelete:
		z.deleted = true
		f.ok(w, map[string]any{"id": z.id}, nil)
	case sub == "dns_records" && r.Method == http.MethodPost:
		// The created record is the request with an id.
		in["id"] = "rec-new"
		f.ok(w, in, nil)
	case sub == "dns_records":
		f.ok(w, []any{}, map[string]any{"page": 1, "per_page": 1, "count": 0, "total_count": z.records, "total_pages": z.records})
	case sub == "subscription" && r.Method == http.MethodPut:
		if f.subscriptionErr[0] != 0 {
			f.fail(w, f.subscriptionErr[0], f.subscriptionErr[1], "Authentication error")
			return
		}
		z.plan = "free"
		f.ok(w, map[string]any{"rate_plan": map[string]any{"id": "free"}}, nil)
	case sub == "dns_settings":
		if r.Method == http.MethodPatch {
			if f.foundationErr[0] != 0 {
				msg := "Foundation DNS is not available for this account"
				if f.foundationErr[1] == 1001 {
					msg = "Request body is invalid."
				}
				f.fail(w, f.foundationErr[0], f.foundationErr[1], msg)
				return
			}
			on, ok := in["foundation_dns"].(bool)
			if !ok {
				f.fail(w, http.StatusBadRequest, 1001, "Request body is invalid.")
				return
			}
			f.setFoundation(z, on)
		}
		f.ok(w, map[string]any{"foundation_dns": z.foundation, "multi_provider": false, "nameservers": map[string]any{"type": "cloudflare.standard"}}, nil)
	case sub == "argo/smart_routing":
		if r.Method == http.MethodPatch {
			z.argo = fmt.Sprint(in["value"])
		}
		f.ok(w, map[string]any{"id": "smart_routing", "value": z.argo, "editable": true, "modified_on": "0001-01-01T00:00:00Z"}, nil)
	case sub == "settings":
		var out []any
		for _, id := range []string{"0rtt", "always_use_https", "automatic_https_rewrites", "browser_cache_ttl", "early_hints", "ipv6", "min_tls_version", "response_buffering", "ssl"} {
			if s := z.settings[id]; s != nil {
				out = append(out, settingJSON(id, s))
			}
		}
		f.ok(w, out, nil)
	case len(rest) == 2 && rest[0] == "settings":
		id := rest[1]
		if id == "rum" {
			if r.Method == http.MethodPatch {
				z.rum = fmt.Sprint(in["value"])
			}
			f.ok(w, map[string]any{"id": "rum", "value": z.rum, "editable": true, "site_tag": nil, "lite": nil}, nil)
			return
		}
		s := z.settings[id]
		if s == nil {
			if r.Method == http.MethodPatch {
				f.fail(w, http.StatusBadRequest, 1006, "Unrecognized zone setting name")
			} else {
				f.fail(w, http.StatusBadRequest, 1003, "Undefined zone setting")
			}
			return
		}
		if r.Method == http.MethodPatch {
			if !s.editable {
				f.fail(w, http.StatusBadRequest, 1015, "Not allowed to edit zone setting "+id)
				return
			}
			if id == "ssl" && in["value"] == "bogus" {
				f.fail(w, http.StatusBadRequest, 1007, "Invalid value for zone setting ssl")
				return
			}
			s.value = in["value"]
		}
		f.ok(w, settingJSON(id, s), nil)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		f.fail(w, http.StatusNotFound, 7000, "No route for that URI")
	}
}

// zoneEnv runs the command line against the fake, with the profiles acme
// (account acc1) and beta (account acc2) logged in; acme is current.
type zoneEnv struct {
	t   *testing.T
	dir string
	f   *zoneFake
}

func newZoneEnv(t *testing.T) *zoneEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	t.Setenv(app.EnvNonInteractive, "")
	f := newZoneFake(t)
	srv := httptest.NewServer(f)
	t.Cleanup(srv.Close)
	cloudflare.UseBaseURL(t, srv.URL)
	cloudflare.SetFoundationPollInterval(t, 0)
	e := &zoneEnv{t: t, dir: dir, f: f}
	for _, p := range []string{"acme", "beta"} {
		if code, _, stderr := e.run("auth", "login", "cloudflare", "--profile", p, "--set", "token=tok-"+p); code != cli.ExitOK {
			t.Fatalf("login %s: exit %d, %s", p, code, stderr)
		}
	}
	f.reset()
	return e
}

func (e *zoneEnv) run(args ...string) (int, string, string) {
	e.t.Helper()
	return e.runIn(false, "", args...)
}

// runIn runs the command line; interactive runs answer the confirmations
// with the lines of answers.
func (e *zoneEnv) runIn(interactive bool, answers string, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(answers), &out, &errb)
	if interactive {
		rt.Picker = terminal{e.t}
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

// zoneReport is the json report of zone create / ensure.
type zoneReport struct {
	Target struct {
		Platform  string `json:"platform"`
		Profile   string `json:"profile"`
		AccountID string `json:"account_id"`
	} `json:"target"`
	DryRun bool `json:"dry_run"`
	Zone   *struct {
		ID                  string   `json:"id"`
		Name                string   `json:"name"`
		Status              string   `json:"status"`
		Plan                string   `json:"plan"`
		NameServers         []string `json:"name_servers"`
		OriginalNameServers []string `json:"original_name_servers"`
	} `json:"zone"`
	Changes []platform.Change `json:"changes"`
}

func (e *zoneEnv) report(stdout string) zoneReport {
	e.t.Helper()
	var rep zoneReport
	if err := json.Unmarshal([]byte(stdout), &rep); err != nil {
		e.t.Fatalf("not a report: %q (%v)", stdout, err)
	}
	return rep
}

func (e *zoneEnv) inventory(typ platform.ResourceType) []inventory.Resource {
	e.t.Helper()
	db, err := inventory.Open(e.dir + "/inventory.db")
	if err != nil {
		e.t.Fatal(err)
	}
	defer db.Close()
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.Cloudflare, Type: typ})
	if err != nil {
		e.t.Fatal(err)
	}
	return rows
}

// changeMap maps resource -> "action detail".
func changeMap(changes []platform.Change) map[string]string {
	m := map[string]string{}
	for _, c := range changes {
		m[c.Resource] = string(c.Action) + " " + c.Detail
	}
	return m
}

func indexOf(list []string, prefix string) int {
	for i, s := range list {
		if strings.HasPrefix(s, prefix) {
			return i
		}
	}
	return -1
}

func TestZoneEnsureCreatesAndConverges(t *testing.T) {
	e := newZoneEnv(t)
	code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "Example.ORG.", "--preset", "optimized", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	z := e.f.zoneNamed("example.org")
	if z == nil {
		t.Fatalf("no zone created: %v", e.f.reqs())
	}
	if body := e.f.body("POST /zones"); body["name"] != "example.org" || body["type"] != "full" || body["account"].(map[string]any)["id"] != "acc1" {
		t.Errorf("create body = %v", body)
	}
	reqs := e.f.reqs()
	post, fdns, get, settings := indexOf(reqs, "POST /zones"), indexOf(reqs, "PATCH /zones/"+z.id+"/dns_settings"),
		indexOf(reqs, "GET /zones/"+z.id), indexOf(reqs, "GET /zones/"+z.id+"/settings")
	if !(post >= 0 && post < fdns && fdns < get && get < settings) {
		t.Errorf("request order: %v", reqs)
	}
	wantWrites := []string{
		"POST /zones",
		"PATCH /zones/" + z.id + "/dns_settings",
		"PATCH /zones/" + z.id + "/settings/0rtt",
		"PATCH /zones/" + z.id + "/settings/early_hints",
		"PATCH /zones/" + z.id + "/settings/rum",
		"PATCH /zones/" + z.id + "/settings/always_use_https",
		"PATCH /zones/" + z.id + "/settings/ssl",
	}
	if got := e.f.writes(); strings.Join(got, "\n") != strings.Join(wantWrites, "\n") {
		t.Errorf("writes:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(wantWrites, "\n"))
	}
	rep := e.report(stdout)
	if rep.Target.Profile != "acme" || rep.Target.AccountID != "acc1" || rep.DryRun || rep.Zone == nil || rep.Zone.ID != z.id || rep.Zone.Plan != "free" || rep.Zone.Status != "pending" {
		t.Errorf("report = %+v", rep)
	}
	if len(rep.Zone.NameServers) != 3 || !strings.Contains(rep.Zone.NameServers[0], "foundationdns") || len(rep.Zone.OriginalNameServers) != 0 {
		t.Errorf("nameservers = %v / %v (the ones after Foundation DNS)", rep.Zone.NameServers, rep.Zone.OriginalNameServers)
	}
	m := changeMap(rep.Changes)
	for res, want := range map[string]string{
		"zone/example.org":                                  "created id=" + z.id + " status=pending",
		"zone/example.org/foundation-dns":                   "created enabled",
		"zone/example.org/setting/0rtt":                     "updated off -> on",
		"zone/example.org/setting/rum":                      "updated off -> on",
		"zone/example.org/setting/response_buffering":       "skipped enterprise only (plan=free)",
		"zone/example.org/setting/ipv6":                     "skipped enterprise only (plan=free)",
		"zone/example.org/setting/argo_smart_routing":       "skipped enterprise only (plan=free)",
		"zone/example.org/setting/automatic_https_rewrites": "unchanged on",
		"zone/example.org/setting/ssl":                      "updated full -> strict",
	} {
		if m[res] != want {
			t.Errorf("%s = %q, want %q", res, m[res], want)
		}
	}
	if rows := e.inventory(platform.ResZone); len(rows) != 1 || rows[0].ID != z.id {
		t.Errorf("inventory = %v", rows)
	}

	// A second run writes nothing.
	e.f.reset()
	code, stdout, stderr = e.run("cloudflare", "zone", "ensure", "example.org", "--preset", "optimized")
	if code != cli.ExitOK || len(e.f.writes()) != 0 {
		t.Fatalf("second run: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
	if strings.Contains(stdout, "updated") || strings.Contains(stdout, "created") || !strings.Contains(stdout, "unchanged") {
		t.Errorf("second run table:\n%s", stdout)
	}
	// The zone is pending: the nameservers are printed below the table.
	if !strings.Contains(stdout, "Nameservers (set these at your registrar):") || !strings.Contains(stdout, "a.foundationdns.com") {
		t.Errorf("no nameserver block:\n%s", stdout)
	}
}

func TestZoneEnsurePartialAndFlexible(t *testing.T) {
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "free", "active")
	for id, v := range map[string]string{"0rtt": "on", "early_hints": "on", "always_use_https": "on", "ssl": "strict"} {
		z.settings[id].value = v
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "example.com", "--preset", "optimized", "--ssl", "flexible", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	want := []string{"PATCH /zones/" + z.id + "/settings/rum", "PATCH /zones/" + z.id + "/settings/ssl"}
	if got := e.f.writes(); strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("writes = %v, want %v", got, want)
	}
	m := changeMap(e.report(stdout).Changes)
	if m["zone/example.com/setting/ssl"] != "updated strict -> flexible" || m["zone/example.com"] != "unchanged id="+z.id+" status=active" {
		t.Errorf("changes = %v", m)
	}
	if _, has := m["zone/example.com/foundation-dns"]; has {
		t.Errorf("foundation dns of an existing zone was touched without --foundation-dns: %v", m)
	}
	if strings.Contains(stdout, "Nameservers") {
		t.Errorf("an active zone prints no nameserver block")
	}

	// --ssl alone sets the SSL mode only.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "zone", "ensure", "example.com", "--ssl", "strict"); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if got := e.f.writes(); len(got) != 1 || got[0] != "PATCH /zones/"+z.id+"/settings/ssl" {
		t.Errorf("--ssl alone wrote %v", got)
	}
	// defaults.cloudflare.ssl is the default of --ssl with the preset.
	e.f.reset()
	if err := writeConfigDefault(e.dir, "flexible"); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "example.com", "--preset", "optimized", "-o", "json"); code != cli.ExitOK ||
		changeMap(e.report(stdout).Changes)["zone/example.com/setting/ssl"] != "updated strict -> flexible" {
		t.Errorf("config default: exit %d, %s %s", code, stdout, stderr)
	}
}

// writeConfigDefault sets defaults.cloudflare.ssl in config.yaml.
func writeConfigDefault(dir, ssl string) error {
	path := filepath.Join(dir, "config.yaml")
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, []byte("defaults:\n  cloudflare:\n    ssl: "+ssl+"\n")...), 0o600)
}

func TestZoneEnsureDryRun(t *testing.T) {
	e := newZoneEnv(t)
	code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "example.org", "--preset", "optimized", "--dry-run", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if w := e.f.writes(); len(w) != 0 {
		t.Errorf("dry run wrote %v", w)
	}
	rep := e.report(stdout)
	m := changeMap(rep.Changes)
	if !rep.DryRun || rep.Zone.ID != platform.Pending || m["zone/example.org"] != "would_create account=acc1 type=full" ||
		m["zone/example.org/foundation-dns"] != "would_create enable" || m["zone/example.org/setting/0rtt"] != "would_update (pending) -> on" ||
		m["zone/example.org/setting/ipv6"] != "skipped enterprise only (plan unknown until created)" || m["zone/example.org/setting/ssl"] != "would_update (pending) -> strict" {
		t.Errorf("dry run report = %+v", rep)
	}
	for _, c := range rep.Changes {
		if c.Resource == "zone/example.org" && c.ID != platform.Pending {
			t.Errorf("the zone to create has id %q", c.ID)
		}
	}

	// An existing zone: the report is the real one.
	z := e.f.addZone("example.com", "acc1", "free", "active")
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "ensure", "example.com", "--preset", "optimized", "--dry-run", "-o", "json")
	m = changeMap(e.report(stdout).Changes)
	if code != cli.ExitOK || len(e.f.writes()) != 0 || m["zone/example.com/setting/ssl"] != "would_update full -> strict" || m["zone/example.com/setting/automatic_https_rewrites"] != "unchanged on" {
		t.Errorf("existing dry run: exit %d, writes %v, %v", code, e.f.writes(), m)
	}
	_ = z
}

func TestZoneEnsureEnterprise(t *testing.T) {
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "enterprise", "active")
	z.settings["ssl"].editable = false
	code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "example.com", "--preset", "optimized", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	writes := strings.Join(e.f.writes(), ",")
	for _, w := range []string{"/settings/response_buffering", "/settings/ipv6", "/argo/smart_routing"} {
		if !strings.Contains(writes, w) {
			t.Errorf("no write of %s: %s", w, writes)
		}
	}
	if strings.Contains(writes, "/settings/ssl") {
		t.Errorf("a setting that is not editable was written: %s", writes)
	}
	m := changeMap(e.report(stdout).Changes)
	if m["zone/example.com/setting/ssl"] != "skipped not editable on this plan" || m["zone/example.com/setting/ipv6"] != "updated on -> off" ||
		m["zone/example.com/setting/argo_smart_routing"] != "updated off -> on" {
		t.Errorf("changes = %v", m)
	}
	if z.argo != "on" || z.settings["ipv6"].value != "off" {
		t.Errorf("fake state: argo %s ipv6 %v", z.argo, z.settings["ipv6"].value)
	}
}

func TestZoneFoundationDNS(t *testing.T) {
	e := newZoneEnv(t)
	// An account that cannot use Foundation DNS: skipped, the zone is created.
	e.f.foundationErr = [2]int{400, 1003}
	code, stdout, stderr := e.run("cloudflare", "zone", "create", "example.org", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	m := changeMap(e.report(stdout).Changes)
	if !strings.HasPrefix(m["zone/example.org/foundation-dns"], "skipped account does not support foundation dns") || !strings.HasPrefix(m["zone/example.org"], "created") {
		t.Errorf("changes = %v", m)
	}
	// Any other refusal is a failure, after the zone was created.
	e.f.foundationErr = [2]int{400, 1001}
	code, stdout, stderr = e.run("cloudflare", "zone", "create", "example.net", "-o", "json")
	if code != cli.ExitError || e.f.zoneNamed("example.net") == nil {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if m := changeMap(e.report(stdout).Changes); !strings.HasPrefix(m["zone/example.net/foundation-dns"], "failed") {
		t.Errorf("changes = %v", m)
	}
	// --foundation-dns=false does not try.
	e.f.foundationErr = [2]int{}
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "zone", "create", "example.info", "--foundation-dns=false"); code != cli.ExitOK || strings.Contains(strings.Join(e.f.writes(), ","), "dns_settings") {
		t.Errorf("exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
	// An account that switches it on for new zones by itself: no PATCH.
	e.f.foundationDefault["acc1"] = true
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "create", "example.dev", "-o", "json")
	if code != cli.ExitOK || strings.Contains(strings.Join(e.f.writes(), ","), "dns_settings") || changeMap(e.report(stdout).Changes)["zone/example.dev/foundation-dns"] != "unchanged enabled" {
		t.Errorf("exit %d, writes %v, %s", code, e.f.writes(), stdout)
	}
	// An existing zone with --foundation-dns: switched on.
	z := e.f.addZone("example.com", "acc1", "free", "active")
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "ensure", "example.com", "--foundation-dns", "-o", "json")
	if code != cli.ExitOK || !z.foundation || changeMap(e.report(stdout).Changes)["zone/example.com/foundation-dns"] != "updated enabled" {
		t.Errorf("exit %d, %s", code, stdout)
	}
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "ensure", "example.com", "--foundation-dns", "-o", "json")
	if code != cli.ExitOK || len(e.f.writes()) != 0 || changeMap(e.report(stdout).Changes)["zone/example.com/foundation-dns"] != "unchanged enabled" {
		t.Errorf("second run: exit %d, %v, %s", code, e.f.writes(), stdout)
	}
}

func TestZoneCreateExisting(t *testing.T) {
	e := newZoneEnv(t)
	e.f.addZone("example.com", "acc1", "free", "active")
	code, _, stderr := e.run("cloudflare", "zone", "create", "example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "zone ensure") || len(e.f.writes()) != 0 {
		t.Errorf("existing: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
	// In another account: Cloudflare refuses (1061).
	e.f.addZone("example.net", "acc2", "free", "active")
	code, _, stderr = e.run("cloudflare", "zone", "create", "example.net")
	if code != cli.ExitError || !strings.Contains(stderr, "already exists") || !strings.Contains(stderr, "--profile") {
		t.Errorf("other account: exit %d, %s", code, stderr)
	}
	// ensure fails the same way: the zone is not in the account.
	code, _, stderr = e.run("cloudflare", "zone", "ensure", "example.net")
	if code != cli.ExitError || !strings.Contains(stderr, "code 1061") {
		t.Errorf("ensure other account: exit %d, %s", code, stderr)
	}
}

func TestZoneEnsureUsageErrors(t *testing.T) {
	e := newZoneEnv(t)
	for _, args := range [][]string{
		{"cloudflare", "zone", "ensure", "example.com", "--ssl", "full"},
		{"cloudflare", "zone", "ensure", "example.com", "--preset", "fast"},
		{"cloudflare", "zone", "create", "http://example.com"},
		{"cloudflare", "zone", "create", "nodot"},
		{"cloudflare", "zone", "create", "192.0.2.1"},
		{"cloudflare", "zone", "create"},
		{"cloudflare", "zone", "delete"},
		{"cloudflare", "zone", "setting", "set", "example.com", "argo_smart_routing", "maybe"},
		{"cloudflare", "zone", "setting", "get", "example.com"},
	} {
		if code, _, stderr := e.run(args...); code != cli.ExitUsage {
			t.Errorf("%v: exit %d, %s", args, code, stderr)
		}
	}
	if r := e.f.reqs(); len(r) != 0 {
		t.Errorf("usage errors made requests: %v", r)
	}
	if code, _, _ := e.run("cloudflare", "zone", "ensure", "example.com", "--offline"); code != cli.ExitOffline {
		t.Errorf("--offline: exit %d", code)
	}
}

// --account keeps to its account also when the API ignores the account
// filter of the lookup. Without it a login works on every account its
// credentials see, so a name two of them hold a zone of is ambiguous.
func TestZoneEnsureAccountFilter(t *testing.T) {
	e := newZoneEnv(t)
	e.f.ignoreAccount = true
	other := e.f.addZone("example.com", "acc2", "free", "active")
	mine := e.f.addZone("example.com", "acc1", "free", "active")
	if code, _, stderr := e.run("cloudflare", "zone", "ensure", "example.com", "-o", "json"); code != cli.ExitAmbiguous || !strings.Contains(stderr, "--account <id or name>") {
		t.Fatalf("two accounts: exit %d: %s", code, stderr)
	}
	code, stdout, stderr := e.run("cloudflare", "zone", "ensure", "example.com", "--account", "acc1", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if rep := e.report(stdout); rep.Zone.ID != mine.id || rep.Zone.ID == other.id || len(e.f.writes()) != 0 {
		t.Errorf("zone = %s (mine %s), writes %v", rep.Zone.ID, mine.id, e.f.writes())
	}
}

func TestZoneSettingCommands(t *testing.T) {
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "free", "active")

	code, stdout, stderr := e.run("cloudflare", "zone", "setting", "get", "example.com", "ssl", "-o", "json")
	var row map[string]any
	if code != cli.ExitOK || json.Unmarshal([]byte(stdout), &row) != nil || row["id"] != "ssl" || row["value"] != "full" || row["editable"] != true || row["zone"] != "example.com" {
		t.Fatalf("get: exit %d, %s %s", code, stdout, stderr)
	}
	if code, stdout, _ := e.run("cloudflare", "zone", "setting", "get", "example.com", "ssl"); code != cli.ExitOK || !strings.Contains(stdout, "SETTING") || !strings.Contains(stdout, "full") {
		t.Errorf("get table: %s", stdout)
	}

	// set: written when it differs, unchanged (no PATCH) when it does not.
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "setting", "set", "example.com", "always_use_https", "true", "-o", "json")
	var rep platform.Report
	_ = json.Unmarshal([]byte(stdout), &rep)
	if code != cli.ExitOK || z.settings["always_use_https"].value != "on" || len(rep.Changes) != 1 || rep.Changes[0].Detail != "off -> on" {
		t.Errorf("set: exit %d, %s", code, stdout)
	}
	if indexOf(e.f.reqs(), "GET /zones/"+z.id) < 0 {
		t.Errorf("the zone was not verified before the write: %v", e.f.reqs())
	}
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "setting", "set", "example.com", "always_use_https", "on")
	if code != cli.ExitOK || len(e.f.writes()) != 0 || !strings.Contains(stdout, "unchanged") {
		t.Errorf("set again: exit %d, writes %v, %s", code, e.f.writes(), stdout)
	}
	// A number stays a number.
	if code, _, _ := e.run("cloudflare", "zone", "setting", "set", "example.com", "browser_cache_ttl", "7200"); code != cli.ExitOK || z.settings["browser_cache_ttl"].value != float64(7200) {
		t.Errorf("number: exit %d, %v", code, z.settings["browser_cache_ttl"].value)
	}
	// --dry-run reads, writes nothing.
	e.f.reset()
	code, stdout, _ = e.run("cloudflare", "zone", "setting", "set", "example.com", "ssl", "strict", "--dry-run")
	if code != cli.ExitOK || len(e.f.writes()) != 0 || !strings.Contains(stdout, "would update") || !strings.Contains(stdout, "full -> strict") {
		t.Errorf("dry run: exit %d, %v, %s", code, e.f.writes(), stdout)
	}

	// Argo and Foundation DNS go to their own endpoints.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "zone", "setting", "set", "example.com", "argo_smart_routing", "on"); code != cli.ExitOK || z.argo != "on" ||
		e.f.writes()[0] != "PATCH /zones/"+z.id+"/argo/smart_routing" {
		t.Errorf("argo: exit %d, %v, %s", code, e.f.writes(), stderr)
	}
	code, stdout, _ = e.run("cloudflare", "zone", "setting", "get", "example.com", "argo_smart_routing", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"id": "argo_smart_routing"`) || !strings.Contains(stdout, `"modified_on": ""`) {
		t.Errorf("argo get: %s", stdout)
	}
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "setting", "set", "example.com", "foundation_dns", "on")
	if code != cli.ExitOK || !z.foundation || e.f.body("PATCH /zones/" + z.id + "/dns_settings")["foundation_dns"] != true || !strings.Contains(stderr, "a.foundationdns.com") {
		t.Errorf("foundation: exit %d, %v, %s", code, e.f.writes(), stderr)
	}
	if code, stdout, _ := e.run("cloudflare", "zone", "setting", "get", "example.com", "foundation_dns"); code != cli.ExitOK || !strings.Contains(stdout, "true") {
		t.Errorf("foundation get: %s", stdout)
	}

	// Errors: unknown setting (4), not on the plan (7), invalid value (1),
	// an answer of success:false with HTTP 200 (1).
	if code, _, stderr := e.run("cloudflare", "zone", "setting", "get", "example.com", "nope"); code != cli.ExitNotFound || !strings.Contains(stderr, "setting list") {
		t.Errorf("unknown get: exit %d, %s", code, stderr)
	}
	if code, _, _ := e.run("cloudflare", "zone", "setting", "set", "example.com", "nope", "on"); code != cli.ExitNotFound {
		t.Errorf("unknown set: exit %d", code)
	}
	if code, _, stderr := e.run("cloudflare", "zone", "setting", "set", "example.com", "response_buffering", "on"); code != cli.ExitNotSupported || !strings.Contains(stderr, "plan free") {
		t.Errorf("not on plan: exit %d, %s", code, stderr)
	}
	if code, _, stderr := e.run("cloudflare", "zone", "setting", "set", "example.com", "ssl", "bogus"); code != cli.ExitError || !strings.Contains(stderr, "code 1007") {
		t.Errorf("bad value: exit %d, %s", code, stderr)
	}
	e.f.envelopeErr["PATCH /zones/"+z.id+"/settings/min_tls_version"] = 1007
	if code, _, stderr := e.run("cloudflare", "zone", "setting", "set", "example.com", "min_tls_version", "1.2"); code != cli.ExitError || !strings.Contains(stderr, "code 1007") {
		t.Errorf("success:false: exit %d, %s", code, stderr)
	}

	// list
	code, stdout, _ = e.run("cloudflare", "zone", "setting", "list", "example.com", "-o", "json")
	var rows []map[string]any
	if code != cli.ExitOK || json.Unmarshal([]byte(stdout), &rows) != nil || len(rows) != 9 || rows[0]["id"] != "0rtt" {
		t.Errorf("list: exit %d, %s", code, stdout)
	}
}

func TestZoneDelete(t *testing.T) {
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "free", "active")
	z.records = 12
	// Sync so that the inventory holds the zone and a record.
	if code, _, stderr := e.run("sync", "--platform", "cloudflare", "--type", "zone"); code != cli.ExitOK {
		t.Fatalf("sync: %s", stderr)
	}
	seedRecord(t, e, z.id)

	// Non-interactive without --yes: usage error before any request.
	e.f.reset()
	if code, _, _ := e.run("cloudflare", "zone", "delete", "example.com"); code != cli.ExitUsage || len(e.f.reqs()) != 0 {
		t.Errorf("no --yes: exit %d, %v", code, e.f.reqs())
	}
	// --dry-run needs no --yes and writes nothing.
	code, stdout, _ := e.run("cloudflare", "zone", "delete", "example.com", "--dry-run")
	if code != cli.ExitOK || len(e.f.writes()) != 0 || !strings.Contains(stdout, "would delete") || !strings.Contains(stdout, "plan=free records=12") {
		t.Errorf("dry run: exit %d, %s", code, stdout)
	}
	// Interactive, answered no: nothing deleted, exit 0.
	code, _, stderr := e.runIn(true, "n\n", "cloudflare", "zone", "delete", "example.com")
	if code != cli.ExitOK || z.deleted || !strings.Contains(stderr, "12 DNS records") {
		t.Errorf("declined: exit %d, %s", code, stderr)
	}
	// Interactive, yes.
	code, _, stderr = e.runIn(true, "y\n", "cloudflare", "zone", "delete", "example.com")
	if code != cli.ExitOK || !z.deleted {
		t.Fatalf("confirmed: exit %d, %s", code, stderr)
	}
	if rows := e.inventory(platform.ResZone); len(rows) != 0 {
		t.Errorf("zone left in the inventory: %v", rows)
	}
	if rows := e.inventory(platform.ResDNSRecord); len(rows) != 0 {
		t.Errorf("records left in the inventory: %v", rows)
	}
	// Again: not found.
	if code, _, stderr := e.run("cloudflare", "zone", "delete", "example.com", "--yes"); code != cli.ExitNotFound {
		t.Errorf("again: exit %d, %s", code, stderr)
	}
}

// seedRecord stores a DNS record of the zone in the inventory.
func seedRecord(t *testing.T, e *zoneEnv, zoneID string) {
	t.Helper()
	db, err := inventory.Open(e.dir + "/inventory.db")
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	rec := platform.Record{ID: "rec1", ZoneID: zoneID, Name: "www.example.com", Type: "A", Value: "192.0.2.1"}
	set := inventory.Set{Platform: platform.Cloudflare, Profile: "acme", Type: platform.ResDNSRecord, Scope: zoneID}
	if err := db.Replace(context.Background(), set, app.RecordResources(zoneID, "example.com", []platform.Record{rec}), 3600e9); err != nil {
		t.Fatal(err)
	}
}

func TestZoneDeleteEnterprise(t *testing.T) {
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "enterprise", "active")
	// Without --downgrade-enterprise: refused, nothing written.
	if code, _, stderr := e.run("cloudflare", "zone", "delete", "example.com", "--yes"); code != cli.ExitError || !strings.Contains(stderr, "--downgrade-enterprise") || len(e.f.writes()) != 0 {
		t.Errorf("no flag: exit %d, %v, %s", code, e.f.writes(), stderr)
	}
	// Dry run with it: both steps.
	code, stdout, _ := e.run("cloudflare", "zone", "delete", "example.com", "--downgrade-enterprise", "--dry-run")
	if code != cli.ExitOK || !strings.Contains(stdout, "zone/example.com/subscription") || !strings.Contains(stdout, "enterprise -> free") || len(e.f.writes()) != 0 {
		t.Errorf("dry run: exit %d, %s", code, stdout)
	}
	// No billing permission: exit 3, not deleted.
	e.f.subscriptionErr = [2]int{403, 10000}
	e.f.reset()
	code, _, stderr := e.run("cloudflare", "zone", "delete", "example.com", "--downgrade-enterprise", "--yes")
	if code != cli.ExitAuth || z.deleted || !strings.Contains(stderr, "Downgrade the zone to Free in the dashboard") || indexOf(e.f.writes(), "DELETE") >= 0 {
		t.Errorf("403: exit %d, %v, %s", code, e.f.writes(), stderr)
	}
	// Downgraded, then deleted.
	e.f.subscriptionErr = [2]int{}
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "zone", "delete", "example.com", "--downgrade-enterprise", "--yes")
	if code != cli.ExitOK || !z.deleted || strings.Join(e.f.writes(), ",") != "PUT /zones/"+z.id+"/subscription,DELETE /zones/"+z.id {
		t.Errorf("downgrade: exit %d, %v, %s", code, e.f.writes(), stderr)
	}
}

func TestZoneStaleInventory(t *testing.T) {
	e := newZoneEnv(t)
	old := e.f.addZone("example.com", "acc1", "free", "active")
	if code, _, stderr := e.run("sync", "--platform", "cloudflare", "--type", "zone"); code != cli.ExitOK {
		t.Fatalf("sync: %s", stderr)
	}
	seedRecord(t, e, old.id)
	// Deleted in the dashboard: not found, and the inventory forgets it.
	old.deleted = true
	code, _, stderr := e.run("cloudflare", "zone", "setting", "get", "example.com", "ssl")
	if code != cli.ExitNotFound {
		t.Errorf("gone: exit %d, %s", code, stderr)
	}
	if rows := e.inventory(platform.ResZone); len(rows) != 0 {
		t.Errorf("stale zone kept: %v", rows)
	}
	if rows := e.inventory(platform.ResDNSRecord); len(rows) != 0 {
		t.Errorf("stale records kept: %v", rows)
	}
	// Deleted and added again (new id): found by name.
	if code, _, stderr := e.run("sync", "--platform", "cloudflare", "--type", "zone"); code != cli.ExitOK {
		t.Fatalf("sync: %s", stderr)
	}
	readded := e.f.addZone("example.com", "acc1", "free", "pending")
	_ = readded
	e.f.zones[0].deleted = true
	// The inventory now names nothing; give it the old id back.
	db, _ := inventory.Open(e.dir + "/inventory.db")
	z := platform.Zone{ID: old.id, Name: "example.com"}
	_ = db.Upsert(context.Background(), inventory.Set{Platform: platform.Cloudflare, Profile: "acme", Type: platform.ResZone}, app.ZoneResources([]platform.Zone{z})[0], 3600e9)
	db.Close()
	code, stdout, stderr := e.run("cloudflare", "zone", "setting", "get", "example.com", "ssl", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"value": "full"`) {
		t.Errorf("re-added: exit %d, %s %s", code, stdout, stderr)
	}
	if rows := e.inventory(platform.ResZone); len(rows) != 1 || rows[0].ID != readded.id {
		t.Errorf("inventory = %v", rows)
	}
}

func TestZoneTransportOddities(t *testing.T) {
	e := newZoneEnv(t)
	// A 429 before the creation is retried; the zone is created once.
	e.f.throttle["POST /zones"] = 1
	code, _, stderr := e.run("cloudflare", "zone", "create", "example.org", "--foundation-dns=false")
	if code != cli.ExitOK {
		t.Fatalf("429: exit %d, %s", code, stderr)
	}
	n := 0
	for _, z := range e.f.zones {
		if z.name == "example.org" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d zones created", n)
	}
	// An HTML page instead of the API: a readable failure with the ray id.
	e.f.html["GET /zones"] = true
	code, _, stderr = e.run("cloudflare", "zone", "ensure", "example.com")
	if code != cli.ExitError || !strings.Contains(stderr, "not the API's JSON") || !strings.Contains(stderr, "cf-ray 8f00html-NRT") {
		t.Errorf("html: exit %d, %s", code, stderr)
	}
}
