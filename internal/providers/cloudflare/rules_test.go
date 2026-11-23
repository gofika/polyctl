package cloudflare

import (
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestCleanRuleDropsServerFieldsAndNulls(t *testing.T) {
	var r apiRule
	raw := `{"id":"r1","ref":"r1","version":"3","last_updated":"x","description":"D","action":"set_cache_settings",
		"expression":"e","logging":null,"categories":null,
		"action_parameters":{"cache":false,"edge_ttl":null,"browser_ttl":{"mode":"override_origin","default":0},
		"list":[{"value":0,"status_code_range":{"from":400,"to":null}}]}}`
	if err := json.Unmarshal([]byte(raw), &r); err != nil {
		t.Fatal(err)
	}
	got := cleanRule(r)
	want := Rule{Description: "D", Enabled: true, Action: "set_cache_settings", Expression: "e", ActionParameters: map[string]any{
		"cache":       false,
		"browser_ttl": map[string]any{"mode": "override_origin", "default": int64(0)},
		"list":        []any{map[string]any{"value": int64(0), "status_code_range": map[string]any{"from": int64(400)}}},
	}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("clean = %#v\nwant %#v", got, want)
	}
	// A ref of its own is kept; enabled false is kept.
	f := false
	if c := cleanRule(apiRule{ID: "a", Ref: "mine", Enabled: &f}); c.Ref != "mine" || c.Enabled {
		t.Errorf("ref/enabled = %+v", c)
	}
}

func TestParseRulesFileShapes(t *testing.T) {
	// A bare list, JSON, and the list output shape all parse to the same.
	inputs := []string{
		"- {description: A, action: set_cache_settings, expression: x, action_parameters: {cache: true, edge_ttl: {default: 60}}}",
		`{"rules":[{"description":"A","action":"set_cache_settings","expression":"x","action_parameters":{"cache":true,"edge_ttl":{"default":60}}}]}`,
		"zone: {id: z, name: example.com}\nphase: http_request_cache_settings\nruleset_id: rs\nrules:\n  - {description: A, enabled: true, action: set_cache_settings, expression: x, action_parameters: {cache: true, edge_ttl: {default: 60}}}",
	}
	want := []Rule{{Description: "A", Enabled: true, Action: "set_cache_settings", Expression: "x",
		ActionParameters: map[string]any{"cache": true, "edge_ttl": map[string]any{"default": int64(60)}}}}
	for _, in := range inputs {
		got, err := parseRulesFile([]byte(in), cacheRules)
		if err != nil || !reflect.DeepEqual(got, want) {
			t.Errorf("%s:\n got %#v (%v)", in, got, err)
		}
	}
	if got, err := parseRulesFile([]byte("rules: []"), cacheRules); err != nil || len(got) != 0 {
		t.Errorf("empty list = %v, %v", got, err)
	}
	_, err := parseRulesFile([]byte("- {description: A, action: set_cache_settings}\n- {description: B}"), cacheRules)
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "rule 1: missing expression") {
		t.Errorf("missing = %v", err)
	}
}

func TestPlanRulesReplaceAndRefs(t *testing.T) {
	r := func(desc, expr, ref string) Rule {
		return Rule{Description: desc, Enabled: true, Action: "set_cache_settings", Expression: expr, Ref: ref}
	}
	existing := []Rule{r("A", "a", "ref_a"), r("", "anon", ""), r("A", "a2", ""), r("B", "b", "")}

	// Merge: the file rule without ref keeps the ref of the rule it
	// replaces; the second A and the rule without description are kept.
	p := planRules(cacheRules, "example.com", existing, []Rule{r("A", "new", "")}, false, false)
	if !p.Write || p.Final[0].Ref != "ref_a" || p.Final[0].Expression != "new" || len(p.Final) != 4 || len(p.Warnings) != 1 {
		t.Errorf("merge = %+v", p)
	}
	if len(p.Changes) != 1 || p.Changes[0].Detail != "expression" {
		t.Errorf("merge changes = %+v", p.Changes)
	}

	// Replace: everything the file does not name is deleted, the second
	// A included.
	p = planRules(cacheRules, "example.com", existing, []Rule{r("B", "b", ""), r("A", "a", "")}, true, false)
	var deleted []string
	for _, c := range p.Changes {
		if c.Action == platform.Deleted {
			deleted = append(deleted, c.Resource+" "+c.Detail)
		}
	}
	want := []string{"zone/example.com/cache-rule/(no description) position 2", "zone/example.com/cache-rule/A position 3"}
	if !reflect.DeepEqual(deleted, want) || len(p.Deleted) != 2 || p.Final[1].Ref != "ref_a" {
		t.Errorf("replace deleted = %v, final %+v", deleted, p.Final)
	}

	// Nothing to do.
	p = planRules(cacheRules, "example.com", existing, []Rule{r("B", "b", "")}, false, true)
	if p.Write || len(p.Changes) != 1 || p.Changes[0].Action != platform.Unchanged {
		t.Errorf("unchanged = %+v", p)
	}
}

func TestRuleDiffDetails(t *testing.T) {
	a := Rule{Enabled: true, Action: "x", ActionParameters: map[string]any{"cache": true, "edge_ttl": map[string]any{"default": int64(3600)}}}
	b := Rule{Enabled: false, Action: "x", Ref: "r", ActionParameters: map[string]any{"cache": true, "edge_ttl": map[string]any{"default": int64(2678400), "mode": "override_origin"}}}
	got := strings.Join(ruleDiff(a, b), ", ")
	if got != "enabled true -> false, ref - -> r, edge_ttl.default 3600 -> 2678400, edge_ttl.mode - -> override_origin" {
		t.Errorf("diff = %q", got)
	}
}

func TestRulesErrorHint(t *testing.T) {
	rules := []Rule{{Description: "A"}, {Description: "B"}}
	err := newError(400, "PUT", "/x", []message{{Code: 20127, Message: "could not parse", Source: &errorSource{Pointer: "/rules/1/expression"}}})
	if got := rulesErrorHint(cacheRules, rules, err); !strings.Contains(got.Error(), "cache rule 2 (B), at /rules/1/expression") {
		t.Errorf("hint = %v", got)
	}
	err = newError(400, "PUT", "/x", []message{{Code: 50001, Message: "exceeded", Source: &errorSource{Pointer: "/rules"}}})
	if got := rulesErrorHint(cacheRules, rules, err); !errors.Is(got, platform.ErrNotSupported) {
		t.Errorf("limit = %v", got)
	}
	if !noEntrypoint(newError(404, "GET", "/x", []message{{Code: 10003, Message: "could not find entrypoint ruleset"}})) {
		t.Error("404 / 10003 is not taken for a missing entrypoint")
	}
	if !noEntrypoint(newError(404, "GET", "/x", []message{{Message: "could not find entrypoint ruleset in the http_request_cache_settings phase"}})) {
		t.Error("404 with the message and no code is not taken for a missing entrypoint")
	}
	for _, e := range []*Error{
		newError(404, "GET", "/x", []message{{Message: "Not Found"}}),
		newError(404, "GET", "/x", nil),
		newError(404, "GET", "/x", []message{{Code: 7003, Message: "Could not route"}}),
		newError(403, "GET", "/x", []message{{Code: 10003, Message: "could not find entrypoint ruleset"}}),
	} {
		if noEntrypoint(e) {
			t.Errorf("%v is taken for a missing entrypoint", e)
		}
	}
}
