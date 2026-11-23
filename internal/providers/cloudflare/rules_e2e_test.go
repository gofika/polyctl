package cloudflare_test

import (
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/platform"
)

const (
	phaseCache    = "http_request_cache_settings"
	phaseRedirect = "http_request_dynamic_redirect"
)

// rfRuleset is an entrypoint ruleset of the fake.
type rfRuleset struct {
	id      string
	version int
	rules   []map[string]any
}

// rulesFake is the Rulesets part of the fake API, with the answers
// observed on the real API: a phase never configured answers HTTP 404 code
// 10003, a zone that does not exist HTTP 403 code 10000, a token without
// the phase's permission HTTP 403 with a message and no code, an unknown key
// HTTP 400 without code, a bad expression HTTP 400 code 20127 with a JSON
// pointer, too many rules HTTP 400 code 50001; an empty ruleset has no
// "rules" key; rule ids stay when a rule keeps its content and position.
type rulesFake struct {
	sets      map[string]*rfRuleset // zone id + "|" + phase
	forbidden map[string]bool       // phase -> 403 "request is not authorized"
	limit     int                   // rules per phase (default 10)
	nextID    int
	puts      []map[string]any // the PUT bodies
	nulls     bool             // GET adds null fields to every rule
}

var phaseActions = map[string]string{phaseCache: "set_cache_settings", phaseRedirect: "redirect"}

// apiRuleKeys are the keys the API accepts in a rule of a PUT body.
var apiRuleKeys = map[string]bool{"id": true, "ref": true, "description": true, "action": true, "expression": true, "enabled": true,
	"action_parameters": true, "version": true, "last_updated": true, "logging": true, "categories": true}

func (f *zoneFake) failMsg(w http.ResponseWriter, status int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"message": msg}}, "messages": []any{}, "result": nil})
}

func (f *zoneFake) failAt(w http.ResponseWriter, code int, msg, pointer string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]any{"success": false, "errors": []any{map[string]any{"code": code, "message": msg, "source": map[string]any{"pointer": pointer}}}, "messages": []any{}, "result": nil})
}

// seedRules sets the rules of a phase of a zone as the API stores them.
func (f *zoneFake) seedRules(zoneID, phase string, rules ...map[string]any) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.rules.sets == nil {
		f.rules.sets = map[string]*rfRuleset{}
	}
	rs := &rfRuleset{id: "rs-" + phase, version: 1}
	for _, r := range rules {
		f.rules.nextID++
		c := map[string]any{"id": fmt.Sprintf("rule%d", f.rules.nextID), "version": "1", "last_updated": "2026-11-17T00:00:00Z"}
		for k, v := range r {
			c[k] = v
		}
		if _, ok := c["ref"]; !ok {
			c["ref"] = c["id"]
		}
		if _, ok := c["enabled"]; !ok {
			c["enabled"] = true
		}
		rs.rules = append(rs.rules, c)
	}
	f.rules.sets[zoneID+"|"+phase] = rs
}

func (f *zoneFake) storedRules(zoneID, phase string) []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rs := f.rules.sets[zoneID+"|"+phase]; rs != nil {
		return rs.rules
	}
	return nil
}

func (f *zoneFake) putBodies() []map[string]any {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]map[string]any(nil), f.rules.puts...)
}

func (f *zoneFake) rulesetJSON(rs *rfRuleset, phase string) map[string]any {
	out := map[string]any{"id": rs.id, "name": "default", "description": "", "kind": "zone", "phase": phase,
		"version": fmt.Sprint(rs.version), "last_updated": "2026-11-17T00:00:00Z"}
	if len(rs.rules) > 0 {
		var rules []any
		for _, r := range rs.rules {
			c := map[string]any{}
			for k, v := range r {
				c[k] = v
			}
			if f.rules.nulls {
				c["logging"], c["categories"] = nil, nil
				if ap, ok := c["action_parameters"].(map[string]any); ok {
					ap2 := map[string]any{"origin_error_page_passthru": nil}
					for k, v := range ap {
						ap2[k] = v
					}
					c["action_parameters"] = ap2
				}
			}
			rules = append(rules, c)
		}
		out["rules"] = rules
	}
	return out
}

// sameContent compares two stored rules without their server fields.
func sameContent(a, b map[string]any) bool {
	strip := func(m map[string]any) map[string]any {
		c := map[string]any{}
		for k, v := range m {
			switch k {
			case "id", "version", "last_updated":
				continue
			case "ref":
				if v == m["id"] {
					continue
				}
			}
			c[k] = v
		}
		return c
	}
	return reflect.DeepEqual(strip(a), strip(b))
}

func (f *zoneFake) serveRules(w http.ResponseWriter, r *http.Request, zoneID string, rest []string, acc string, body []byte) {
	z := f.zoneByID(zoneID)
	if z == nil || z.deleted || z.account != acc {
		f.fail(w, http.StatusForbidden, 10000, "Authentication error")
		return
	}
	if len(rest) != 3 || rest[0] != "phases" || rest[2] != "entrypoint" {
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		f.fail(w, http.StatusNotFound, 7000, "No route for that URI")
		return
	}
	phase := rest[1]
	if f.rules.forbidden[phase] {
		f.failMsg(w, http.StatusForbidden, "request is not authorized")
		return
	}
	action, known := phaseActions[phase]
	if !known {
		f.failMsg(w, http.StatusBadRequest, fmt.Sprintf("unknown phase %q", phase))
		return
	}
	if f.rules.sets == nil {
		f.rules.sets = map[string]*rfRuleset{}
	}
	key := zoneID + "|" + phase
	cur := f.rules.sets[key]
	switch r.Method {
	case http.MethodGet:
		if cur == nil {
			f.fail(w, http.StatusNotFound, 10003, "could not find entrypoint ruleset in the "+phase+" phase")
			return
		}
		f.ok(w, f.rulesetJSON(cur, phase), nil)
	case http.MethodPut:
		var in map[string]any
		if err := json.Unmarshal(body, &in); err != nil {
			f.failMsg(w, http.StatusBadRequest, "invalid JSON")
			return
		}
		f.rules.puts = append(f.rules.puts, in)
		for k := range in {
			if k != "rules" && k != "description" {
				f.failMsg(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: unknown field %q", k))
				return
			}
		}
		list, _ := in["rules"].([]any)
		limit := f.rules.limit
		if limit == 0 {
			limit = 10
		}
		if len(list) > limit {
			f.failAt(w, 50001, fmt.Sprintf("exceeded the maximum number of rules in the phase %s: %d out of %d", phase, len(list), limit), "/rules")
			return
		}
		var next []map[string]any
		for i, e := range list {
			m, _ := e.(map[string]any)
			for k := range m {
				if !apiRuleKeys[k] {
					f.failMsg(w, http.StatusBadRequest, fmt.Sprintf("invalid JSON: unknown field %q", k))
					return
				}
			}
			if m["action"] == nil {
				f.failMsg(w, http.StatusBadRequest, "action is required for action parameters")
				return
			}
			if m["action"] != action {
				f.failAt(w, 20016, fmt.Sprintf("not possible to use the %v action in a ruleset with phase %s", m["action"], phase), fmt.Sprintf("/rules/%d/action", i))
				return
			}
			expr, _ := m["expression"].(string)
			if expr == "" {
				f.failAt(w, 20125, "expression cannot be blank", fmt.Sprintf("/rules/%d/expression", i))
				return
			}
			if strings.Contains(expr, "bogus.field") {
				f.failAt(w, 20127, "could not parse filter expression: Filter parsing error (1:2): unknown identifier", fmt.Sprintf("/rules/%d/expression", i))
				return
			}
			c := map[string]any{}
			for k, v := range m {
				if v != nil && k != "id" && k != "version" && k != "last_updated" {
					c[k] = v
				}
			}
			if _, ok := c["enabled"]; !ok {
				c["enabled"] = true
			}
			if cur != nil && i < len(cur.rules) && sameContent(cur.rules[i], c) {
				old := cur.rules[i]
				c["id"], c["version"], c["last_updated"] = old["id"], old["version"], old["last_updated"]
				if _, ok := c["ref"]; !ok {
					c["ref"] = old["ref"]
				}
			} else {
				f.rules.nextID++
				c["id"], c["version"], c["last_updated"] = fmt.Sprintf("rule%d", f.rules.nextID), "1", "2026-11-18T00:00:00Z"
				if _, ok := c["ref"]; !ok {
					c["ref"] = c["id"]
				}
			}
			next = append(next, c)
		}
		if cur == nil {
			cur = &rfRuleset{id: "rs-" + phase}
			f.rules.sets[key] = cur
		}
		cur.version++
		cur.rules = next
		f.ok(w, f.rulesetJSON(cur, phase), nil)
	default:
		f.t.Errorf("unexpected request %s %s", r.Method, r.URL)
		f.fail(w, http.StatusMethodNotAllowed, 7001, "Method not allowed")
	}
}

// --- helpers -------------------------------------------------------------------

func newRulesEnv(t *testing.T) (*zoneEnv, *zfZone) {
	t.Helper()
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "free", "active")
	return e, z
}

func (e *zoneEnv) file(content string) string {
	e.t.Helper()
	p := filepath.Join(e.t.TempDir(), "rules.yaml")
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		e.t.Fatal(err)
	}
	return p
}

func (e *zoneEnv) puts() int {
	n := 0
	for _, w := range e.f.writes() {
		if strings.HasPrefix(w, "PUT ") {
			n++
		}
	}
	return n
}

func ruleDescs(rules []map[string]any) []string {
	var out []string
	for _, r := range rules {
		out = append(out, fmt.Sprint(r["description"]))
	}
	return out
}

func cacheRule(desc, expr string, ttl int) map[string]any {
	return map[string]any{"description": desc, "action": "set_cache_settings", "expression": expr,
		"action_parameters": map[string]any{"cache": true, "edge_ttl": map[string]any{"mode": "override_origin", "default": float64(ttl)}}}
}

const threeRules = `rules:
  - description: No Cache Rule
    action: set_cache_settings
    enabled: true
    expression: '(starts_with(http.request.uri, "/api/"))'
    action_parameters:
      cache: false
  - description: Default Cache Rule
    action: set_cache_settings
    expression: '(http.request.uri.path.extension in {"jpg" "png"})'
    action_parameters:
      cache: true
      edge_ttl:
        mode: override_origin
        default: 2678400
        status_code_ttl:
          - status_code_range: { from: 200, to: 299 }
            value: 2678400
          - status_code_range: { from: 400 }
            value: 0
      browser_ttl:
        mode: override_origin
        default: 2678400
  - description: Cache All
    action: set_cache_settings
    expression: '(http.request.uri wildcard r"/*")'
    action_parameters:
      cache: true
      edge_ttl: { mode: override_origin, default: 300 }
`

// --- tests ---------------------------------------------------------------------

func TestCacheRuleSetCreatesTheEntrypoint(t *testing.T) {
	e, z := newRulesEnv(t)
	code, stdout, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "--file", e.file(threeRules), "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	bodies := e.f.putBodies()
	if len(bodies) != 1 {
		t.Fatalf("PUTs = %d, want 1", len(bodies))
	}
	rules := bodies[0]["rules"].([]any)
	if len(rules) != 3 {
		t.Fatalf("body rules = %d", len(rules))
	}
	for _, r := range rules {
		for k := range r.(map[string]any) {
			switch k {
			case "description", "action", "expression", "enabled", "action_parameters":
			default:
				t.Errorf("unexpected key %q in %v", k, r)
			}
		}
		if r.(map[string]any)["enabled"] != true {
			t.Errorf("enabled not written explicitly: %v", r)
		}
	}
	rep := e.report(stdout)
	m := changeMap(rep.Changes)
	if m["zone/example.com/cache-rule/No Cache Rule"] != "created position 1" ||
		m["zone/example.com/cache-rule/Cache All"] != "created position 3" ||
		m["zone/example.com/cache-rules"] != "created PUT entrypoint (3 rules)" {
		t.Errorf("changes = %v", m)
	}
	if got := ruleDescs(e.f.storedRules(z.id, phaseCache)); strings.Join(got, ",") != "No Cache Rule,Default Cache Rule,Cache All" {
		t.Errorf("stored = %v", got)
	}

	// A second run finds everything as desired: no PUT.
	e.f.reset()
	code, stdout, stderr = e.run("cloudflare", "cache", "rule", "set", "example.com", "--file", e.file(threeRules), "-o", "json")
	if code != cli.ExitOK || e.puts() != 0 {
		t.Fatalf("second run: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	for _, c := range e.report(stdout).Changes {
		if c.Action != platform.Unchanged {
			t.Errorf("second run change %+v", c)
		}
	}
}

func TestCacheRuleSetUnchangedWithServerFields(t *testing.T) {
	e, z := newRulesEnv(t)
	// The stored rules carry id, version, last_updated and ref, and the
	// API adds null fields; the file leaves enabled out.
	e.f.seedRules(z.id, phaseCache,
		map[string]any{"description": "A", "action": "set_cache_settings", "expression": "(http.host eq \"a.example.com\")",
			"action_parameters": map[string]any{"cache": false}},
		cacheRule("B", "(http.host eq \"b.example.com\")", 3600))
	e.f.rules.nulls = true
	file := e.file(`- description: A
  action: set_cache_settings
  expression: (http.host eq "a.example.com")
  action_parameters: {cache: false}
- description: B
  action: set_cache_settings
  expression: (http.host eq "b.example.com")
  action_parameters:
    cache: true
    edge_ttl: {mode: override_origin, default: 3600}
`)
	for i := 0; i < 2; i++ {
		code, stdout, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file)
		if code != cli.ExitOK || e.puts() != 0 {
			t.Fatalf("run %d: exit %d, puts %d: %s", i, code, e.puts(), stderr)
		}
		if strings.Count(stdout, "unchanged") != 2 || strings.Contains(stdout, "cache-rules") {
			t.Errorf("report:\n%s", stdout)
		}
	}
}

func TestCacheRuleSetMergesInPlace(t *testing.T) {
	e, z := newRulesEnv(t)
	e.f.seedRules(z.id, phaseCache, cacheRule("A", "(http.host eq \"a\")", 60), cacheRule("B", "(http.host eq \"b\")", 3600))
	idA := e.f.storedRules(z.id, phaseCache)[0]["id"]
	file := e.file(`rules:
  - description: B
    action: set_cache_settings
    expression: (http.host eq "b")
    action_parameters: {cache: true, edge_ttl: {mode: override_origin, default: 2678400}}
  - description: C
    action: set_cache_settings
    expression: (http.host eq "c")
    action_parameters: {cache: false}
`)
	code, stdout, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file, "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if e.puts() != 1 {
		t.Fatalf("puts = %d", e.puts())
	}
	stored := e.f.storedRules(z.id, phaseCache)
	if got := ruleDescs(stored); strings.Join(got, ",") != "A,B,C" {
		t.Fatalf("stored = %v", got)
	}
	if stored[0]["id"] != idA {
		t.Errorf("A lost its id: %v -> %v", idA, stored[0]["id"])
	}
	m := changeMap(e.report(stdout).Changes)
	if m["zone/example.com/cache-rule/B"] != "updated edge_ttl.default 3600 -> 2678400" || m["zone/example.com/cache-rule/C"] != "created position 3" ||
		m["zone/example.com/cache-rules"] != "updated PUT entrypoint (3 rules)" {
		t.Errorf("changes = %v", m)
	}
	if _, listed := m["zone/example.com/cache-rule/A"]; listed {
		t.Errorf("A is reported although it stayed where it was: %v", m)
	}
}

func TestCacheRuleSetFirst(t *testing.T) {
	e, z := newRulesEnv(t)
	e.f.seedRules(z.id, phaseCache, cacheRule("A", "(http.host eq \"a\")", 60), cacheRule("Cache All", "(http.request.uri wildcard r\"/*\")", 300))
	file := e.file(`rules:
  - {description: N1, action: set_cache_settings, expression: (http.host eq "n1"), action_parameters: {cache: false}}
  - {description: N2, action: set_cache_settings, expression: (http.host eq "n2"), action_parameters: {cache: false}}
`)
	code, stdout, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--first", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	if got := ruleDescs(e.f.storedRules(z.id, phaseCache)); strings.Join(got, ",") != "N1,N2,A,Cache All" {
		t.Fatalf("stored = %v", got)
	}
	m := changeMap(e.report(stdout).Changes)
	if m["zone/example.com/cache-rule/N1"] != "created position 1" || m["zone/example.com/cache-rule/A"] != "updated position 1 -> 3" ||
		m["zone/example.com/cache-rule/Cache All"] != "updated position 2 -> 4" {
		t.Errorf("changes = %v", m)
	}
	if code, _, _ := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--first", "--replace"); code != cli.ExitUsage {
		t.Errorf("--first --replace: exit %d", code)
	}
}

func TestCacheRuleSetReplace(t *testing.T) {
	e, z := newRulesEnv(t)
	seed := func() {
		e.f.seedRules(z.id, phaseCache, cacheRule("A", "(http.host eq \"a\")", 60), cacheRule("B", "(http.host eq \"b\")", 60), cacheRule("C", "(http.host eq \"c\")", 60))
		e.f.reset()
	}
	seed()
	file := e.file(`rules:
  - description: B
    action: set_cache_settings
    expression: (http.host eq "b")
    action_parameters: {cache: true, edge_ttl: {mode: override_origin, default: 60}}
`)
	// Non-interactive without --yes: usage error, nothing written.
	code, _, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--replace")
	if code != cli.ExitUsage || e.puts() != 0 || !strings.Contains(stderr, "--yes") {
		t.Fatalf("without --yes: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	// --dry-run reports the deletions and writes nothing.
	code, stdout, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--replace", "--dry-run", "-o", "json")
	if code != cli.ExitOK || e.puts() != 0 {
		t.Fatalf("dry run: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	rep := e.report(stdout)
	m := changeMap(rep.Changes)
	if !rep.DryRun || m["zone/example.com/cache-rule/A"] != "would_delete position 1" || m["zone/example.com/cache-rule/C"] != "would_delete position 3" ||
		m["zone/example.com/cache-rule/B"] != "would_update position 2 -> 1" || m["zone/example.com/cache-rules"] != "would_update PUT entrypoint (1 rules)" {
		t.Errorf("dry-run changes = %v", m)
	}
	// Interactive, declined: nothing written, exit 0.
	code, _, stderr = e.runIn(true, "n\n", "cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--replace")
	if code != cli.ExitOK || e.puts() != 0 || !strings.Contains(stderr, "  A") {
		t.Fatalf("declined: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	// --yes: one PUT with B only.
	code, stdout, stderr = e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--replace", "-y", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("--yes: exit %d: %s", code, stderr)
	}
	if got := ruleDescs(e.f.storedRules(z.id, phaseCache)); strings.Join(got, ",") != "B" || e.puts() != 1 {
		t.Fatalf("stored = %v, puts %d", got, e.puts())
	}
	m = changeMap(e.report(stdout).Changes)
	if m["zone/example.com/cache-rule/A"] != "deleted position 1" || m["zone/example.com/cache-rule/C"] != "deleted position 3" {
		t.Errorf("changes = %v", m)
	}
	// Interactive, accepted.
	seed()
	code, _, stderr = e.runIn(true, "y\n", "cloudflare", "cache", "rule", "set", "example.com", "-f", file, "--replace")
	if code != cli.ExitOK || e.puts() != 1 {
		t.Fatalf("accepted: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
}

func TestCacheRuleSetDryRunWritesNothing(t *testing.T) {
	e, z := newRulesEnv(t)
	code, stdout, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", e.file(threeRules), "--dry-run")
	if code != cli.ExitOK || e.puts() != 0 {
		t.Fatalf("exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	if !strings.Contains(stdout, "would create  PUT entrypoint (3 rules)") || !strings.Contains(stdout, "position 2") {
		t.Errorf("report:\n%s", stdout)
	}
	if e.f.storedRules(z.id, phaseCache) != nil {
		t.Error("a dry run created the ruleset")
	}
}

func TestCacheRuleSetKeepsZeroValues(t *testing.T) {
	e, z := newRulesEnv(t)
	file := e.file(`rules:
  - description: Off
    action: set_cache_settings
    enabled: false
    expression: (http.host eq "x")
    action_parameters:
      cache: false
  - description: Zero
    action: set_cache_settings
    expression: (http.host eq "y")
    action_parameters:
      cache: true
      edge_ttl:
        mode: override_origin
        default: 0
        status_code_ttl:
          - status_code: 404
            value: 0
          - status_code_range: {to: 199}
            value: 60
`)
	if code, _, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	raw, _ := json.Marshal(e.f.putBodies()[0])
	for _, want := range []string{`"enabled":false`, `"cache":false`, `"default":0`, `"value":0`, `"status_code":404`, `"to":199`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("PUT body lacks %s: %s", want, raw)
		}
	}
	// Read back, the same file is unchanged.
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", file); code != cli.ExitOK || e.puts() != 0 {
		t.Fatalf("second run: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	_ = z
}

func TestCacheRuleListShapes(t *testing.T) {
	e, z := newRulesEnv(t)
	// Never configured: empty, not an error.
	code, stdout, stderr := e.run("cloudflare", "cache", "rule", "list", "example.com", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	var out struct {
		Zone      struct{ ID, Name string }
		Phase     string
		RulesetID string `json:"ruleset_id"`
		Rules     []map[string]any
	}
	if err := json.Unmarshal([]byte(stdout), &out); err != nil || out.Rules == nil || len(out.Rules) != 0 || out.RulesetID != "" ||
		out.Phase != phaseCache || out.Zone.Name != "example.com" || out.Zone.ID != z.id {
		t.Fatalf("empty list = %s (%v)", stdout, err)
	}
	if code, stdout, _ := e.run("cloudflare", "cache", "rule", "list", "example.com"); code != cli.ExitOK || !strings.Contains(stdout, "no cache rules") {
		t.Errorf("empty table: %q", stdout)
	}

	e.f.seedRules(z.id, phaseCache,
		map[string]any{"action": "set_cache_settings", "expression": "(http.host eq \"anon\")", "action_parameters": map[string]any{"cache": true}},
		map[string]any{"description": "Long", "action": "set_cache_settings", "ref": "my_ref", "enabled": false,
			"expression": "(http.request.uri.path.extension in {\"jpg\" \"png\" \"zip\" \"gif\"})",
			"action_parameters": map[string]any{"cache": true,
				"edge_ttl": map[string]any{"mode": "override_origin", "default": float64(2678400), "status_code_ttl": []any{
					map[string]any{"status_code_range": map[string]any{"from": float64(200), "to": float64(299)}, "value": float64(2678400)},
					map[string]any{"status_code_range": map[string]any{"from": float64(400)}, "value": float64(0)},
				}},
				"browser_ttl": map[string]any{"mode": "respect_origin"}}},
		map[string]any{"description": "Redirect-ish", "action": "log"})
	e.f.rules.nulls = true
	code, stdout, _ = e.run("cloudflare", "cache", "rule", "list", "example.com", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("exit %d", code)
	}
	out.Rules = nil
	if err := json.Unmarshal([]byte(stdout), &out); err != nil || len(out.Rules) != 3 || out.RulesetID == "" {
		t.Fatalf("list = %s", stdout)
	}
	for _, r := range out.Rules {
		for _, k := range []string{"id", "version", "last_updated", "logging", "categories"} {
			if _, ok := r[k]; ok {
				t.Errorf("rule keeps %s: %v", k, r)
			}
		}
		if ap, ok := r["action_parameters"].(map[string]any); ok {
			if _, ok := ap["origin_error_page_passthru"]; ok {
				t.Errorf("null kept: %v", ap)
			}
		}
	}
	if _, ok := out.Rules[0]["ref"]; ok || out.Rules[1]["ref"] != "my_ref" || out.Rules[1]["enabled"] != false {
		t.Errorf("ref / enabled: %v", out.Rules)
	}

	code, stdout, _ = e.run("cloudflare", "cache", "rule", "list", "example.com")
	if code != cli.ExitOK {
		t.Fatal(code)
	}
	for _, want := range []string{"(no description)", "default", "override 2678400s (31d)", "respect origin", "(http.request.uri.path.extension in {...", "Redirect-ish"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("table lacks %q:\n%s", want, stdout)
		}
	}
	code, stdout, _ = e.run("cloudflare", "cache", "rule", "list", "example.com", "--wide")
	if code != cli.ExitOK || !strings.Contains(stdout, "200-299:2678400, 400+:0") || !strings.Contains(stdout, `"zip" "gif"})`) || !strings.Contains(stdout, "my_ref") {
		t.Errorf("wide table:\n%s", stdout)
	}

	// The yaml export is a valid input of set, and changes nothing. The
	// rule without description stays as it is.
	code, yamlOut, _ := e.run("cloudflare", "cache", "rule", "list", "example.com", "-o", "yaml")
	if code != cli.ExitOK {
		t.Fatal(code)
	}
	// The export holds a rule without description, which a file may not:
	// drop it, the merge keeps it anyway.
	anon := "  - enabled: true\n    action: set_cache_settings\n    expression: (http.host eq \"anon\")\n    action_parameters:\n      cache: true\n"
	logRule := "  - description: Redirect-ish\n    enabled: true\n    action: log\n"
	if !strings.Contains(yamlOut, anon) || !strings.Contains(yamlOut, logRule) {
		t.Fatalf("yaml export:\n%s", yamlOut)
	}
	fixed := strings.Replace(strings.Replace(yamlOut, anon, "", 1), logRule, "", 1)
	e.f.reset()
	code, _, stderr = e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", e.file(fixed))
	if code != cli.ExitOK || e.puts() != 0 {
		t.Fatalf("export -> set: exit %d, puts %d: %s\n%s", code, e.puts(), stderr, fixed)
	}
}

func TestCacheRuleZoneGoneAndPermissions(t *testing.T) {
	e, z := newRulesEnv(t)
	// Known to the inventory, then deleted in the dashboard: the
	// entrypoint answers 403 / 10000 and the zone 400 / 1001.
	if code, _, stderr := e.run("cloudflare", "cache", "rule", "list", "example.com"); code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	z.deleted = true
	code, _, stderr := e.run("cloudflare", "cache", "rule", "list", "example.com")
	if code != cli.ExitNotFound || !strings.Contains(stderr, "not found") {
		t.Fatalf("gone zone: exit %d: %s", code, stderr)
	}
	if rows := e.inventory(platform.ResZone); len(rows) != 0 {
		t.Errorf("inventory keeps %v", rows)
	}

	// A token without the phase permission: exit 3, the zone exists.
	e2, z2 := newRulesEnv(t)
	e2.f.rules.forbidden = map[string]bool{phaseRedirect: true}
	code, _, stderr = e2.run("cloudflare", "redirect", "rule", "list", "example.com")
	if code != cli.ExitAuth || !strings.Contains(stderr, "Single Redirects") {
		t.Fatalf("forbidden: exit %d: %s", code, stderr)
	}
	code, _, stderr = e2.run("cloudflare", "redirect", "rule", "set", "example.com", "-f", e2.file(`rules:
  - {description: R, action: redirect, expression: (http.host eq "x"), action_parameters: {from_value: {status_code: 301, target_url: {value: "https://example.org"}}}}
`))
	if code != cli.ExitAuth || e2.puts() != 0 {
		t.Fatalf("forbidden set: exit %d: %s", code, stderr)
	}
	_ = z2
	// --offline refuses.
	if code, _, _ := e2.run("cloudflare", "cache", "rule", "list", "example.com", "--offline"); code != cli.ExitOffline {
		t.Errorf("--offline: exit %d", code)
	}
}

func TestCacheRuleSetFileValidation(t *testing.T) {
	e, _ := newRulesEnv(t)
	cases := map[string]string{
		"duplicate":   "rules:\n  - {description: A, action: set_cache_settings, expression: x}\n  - {description: A, action: set_cache_settings, expression: y}\n",
		"no expr":     "rules:\n  - {description: A, action: set_cache_settings}\n",
		"bad key":     "rules:\n  - {description: A, action: set_cache_settings, expression: x, id: abc}\n",
		"bad action":  "rules:\n  - {description: A, action: redirect, expression: x}\n",
		"no desc":     "- {action: set_cache_settings, expression: x}\n",
		"bad enabled": "- {description: A, action: set_cache_settings, expression: x, enabled: \"yes\"}\n",
		"not yaml":    "rules: [\n",
		"empty":       "",
		"phase":       "phase: http_request_dynamic_redirect\nrules: []\n",
		"top key":     "rule: []\n",
	}
	for name, content := range cases {
		code, _, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", e.file(content))
		if code != cli.ExitUsage {
			t.Errorf("%s: exit %d: %s", name, code, stderr)
		}
	}
	if code, _, _ := e.run("cloudflare", "cache", "rule", "set", "example.com"); code != cli.ExitUsage {
		t.Errorf("without --file: exit %d", code)
	}
	if code, _, _ := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", filepath.Join(e.dir, "missing.yaml")); code != cli.ExitUsage {
		t.Errorf("missing file: exit %d", code)
	}
	if reqs := e.f.reqs(); len(reqs) != 0 {
		t.Errorf("requests were sent: %v", reqs)
	}
}

func TestCacheRuleSetDuplicateExistingDescriptions(t *testing.T) {
	e, z := newRulesEnv(t)
	e.f.seedRules(z.id, phaseCache, cacheRule("A", "(http.host eq \"a1\")", 60), cacheRule("B", "(http.host eq \"b\")", 60), cacheRule("A", "(http.host eq \"a2\")", 60))
	code, _, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", e.file(`rules:
  - {description: A, action: set_cache_settings, expression: (http.host eq "new"), action_parameters: {cache: false}}
`))
	if code != cli.ExitOK {
		t.Fatalf("exit %d: %s", code, stderr)
	}
	stored := e.f.storedRules(z.id, phaseCache)
	if len(stored) != 3 || stored[0]["expression"] != `(http.host eq "new")` || stored[2]["expression"] != `(http.host eq "a2")` {
		t.Errorf("stored = %v", stored)
	}
	if !strings.Contains(stderr, "duplicate description") {
		t.Errorf("no warning: %s", stderr)
	}
}

func TestCacheRuleSetAPIErrors(t *testing.T) {
	e, z := newRulesEnv(t)
	e.f.seedRules(z.id, phaseCache, cacheRule("A", "(http.host eq \"a\")", 60))
	before := e.f.storedRules(z.id, phaseCache)
	code, _, stderr := e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", e.file(`rules:
  - {description: Broken, action: set_cache_settings, expression: (bogus.field eq 1), action_parameters: {cache: false}}
`))
	if code != cli.ExitError || !strings.Contains(stderr, "cache rule 2 (Broken)") || !strings.Contains(stderr, "code 20127") {
		t.Fatalf("bad expression: exit %d: %s", code, stderr)
	}
	if after := e.f.storedRules(z.id, phaseCache); !reflect.DeepEqual(before, after) {
		t.Errorf("rules changed: %v", after)
	}
	// Too many rules for the plan: exit 7.
	e.f.rules.limit = 1
	code, _, stderr = e.run("cloudflare", "cache", "rule", "set", "example.com", "-f", e.file(`rules:
  - {description: B, action: set_cache_settings, expression: (http.host eq "b"), action_parameters: {cache: false}}
`))
	if code != cli.ExitNotSupported || !strings.Contains(stderr, "Free zones allow 10 cache rules") {
		t.Fatalf("limit: exit %d: %s", code, stderr)
	}
}

func TestRedirectRuleSetRoundTrip(t *testing.T) {
	e, z := newRulesEnv(t)
	file := e.file(`rules:
  - description: HTTPS to HTTP
    ref: https_to_http_redirect
    action: redirect
    expression: '(http.request.full_uri wildcard r"https://*")'
    action_parameters:
      from_value:
        status_code: 301
        preserve_query_string: true
        target_url:
          expression: 'wildcard_replace(http.request.full_uri, r"https://*", r"http://${1}")'
`)
	code, _, stderr := e.run("cloudflare", "redirect", "rule", "set", "example.com", "-f", file)
	if code != cli.ExitOK || e.puts() != 1 {
		t.Fatalf("exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	if indexOf(e.f.reqs(), "PUT /zones/"+z.id+"/rulesets/phases/"+phaseRedirect+"/entrypoint") < 0 {
		t.Errorf("requests: %v", e.f.reqs())
	}
	stored := e.f.storedRules(z.id, phaseRedirect)
	if len(stored) != 1 || stored[0]["ref"] != "https_to_http_redirect" {
		t.Fatalf("stored = %v", stored)
	}
	// The cache phase is not touched.
	if e.f.storedRules(z.id, phaseCache) != nil {
		t.Error("the cache phase was written")
	}
	e.f.reset()
	if code, _, stderr := e.run("cloudflare", "redirect", "rule", "set", "example.com", "-f", file); code != cli.ExitOK || e.puts() != 0 {
		t.Fatalf("second run: exit %d, puts %d: %s", code, e.puts(), stderr)
	}
	code, stdout, _ := e.run("cloudflare", "redirect", "rule", "list", "example.com")
	if code != cli.ExitOK || !strings.Contains(stdout, "301") || !strings.Contains(stdout, "expr: wildcard_replace(") {
		t.Errorf("list:\n%s", stdout)
	}
	// A cache action in the redirect phase is a usage error.
	if code, _, _ := e.run("cloudflare", "redirect", "rule", "set", "example.com", "-f", e.file(threeRules)); code != cli.ExitUsage {
		t.Errorf("cache rules in the redirect phase: exit %d", code)
	}
}

func TestCacheRuleSetReadsStdin(t *testing.T) {
	e, z := newRulesEnv(t)
	code, _, stderr := e.runIn(false, threeRules, "cloudflare", "cache", "rule", "set", "example.com", "-f", "-")
	if code != cli.ExitOK || len(e.f.storedRules(z.id, phaseCache)) != 3 {
		t.Fatalf("exit %d: %s", code, stderr)
	}
}
