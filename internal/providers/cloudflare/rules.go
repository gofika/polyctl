package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// This file holds the Rulesets API layer of the cache rules (phase
// http_request_cache_settings) and the redirect rules (Single Redirects,
// phase http_request_dynamic_redirect) of a zone: reading and writing the
// entrypoint ruleset of a phase, the cleaned form of a rule that is compared
// and printed, the rules file, and the merge of a file into the rules that
// exist.

// Cloudflare error codes of the Rulesets endpoints, as observed on the API.
const (
	codeNoEntrypoint = 10003 // GET of the entrypoint of a phase never configured (HTTP 404)
	codeAuthError    = 10000 // "Authentication error": also the answer for a zone that does not exist (HTTP 403)
	codeTooManyRules = 50001 // "exceeded the maximum number of rules in the phase ..." (HTTP 400)
)

// rulesetPhase describes one entrypoint phase the rule commands manage.
type rulesetPhase struct {
	// Phase is the Cloudflare phase name.
	Phase string
	// Action is the only action the rules of the phase may have.
	Action string
	// Noun names a rule in messages ("cache rule").
	Noun string
	// Res names a rule in change reports ("cache-rule").
	Res string
	// Service is the command group (cache, redirect).
	Service string
	// Permission is the hint of a refusal of the token.
	Permission string
}

var (
	cacheRules = &rulesetPhase{
		Phase: "http_request_cache_settings", Action: "set_cache_settings",
		Noun: "cache rule", Res: "cache-rule", Service: "cache",
		Permission: "Cache Rules edit",
	}
	redirectRules = &rulesetPhase{
		Phase: "http_request_dynamic_redirect", Action: "redirect",
		Noun: "redirect rule", Res: "redirect-rule", Service: "redirect",
		Permission: "Single Redirects (Dynamic URL Redirects) edit",
	}
)

// apiRule is a rule as the API sends it. Fields the API adds (id, version,
// last_updated, categories, logging, ...) other than id and ref are not
// read: they are not part of what polyctl compares or writes.
type apiRule struct {
	ID               string         `json:"id,omitempty"`
	Ref              string         `json:"ref,omitempty"`
	Description      string         `json:"description,omitempty"`
	Action           string         `json:"action,omitempty"`
	Expression       string         `json:"expression,omitempty"`
	Enabled          *bool          `json:"enabled,omitempty"`
	ActionParameters map[string]any `json:"action_parameters,omitempty"`
}

// apiRuleset is the entrypoint ruleset of a phase. A ruleset without rules
// has no "rules" key at all.
type apiRuleset struct {
	ID          string    `json:"id"`
	Name        string    `json:"name,omitempty"`
	Description string    `json:"description,omitempty"`
	Kind        string    `json:"kind,omitempty"`
	Phase       string    `json:"phase,omitempty"`
	Version     any       `json:"version,omitempty"`
	LastUpdated string    `json:"last_updated,omitempty"`
	Rules       []apiRule `json:"rules"`
}

// Rule is the cleaned form of a rule: the only keys polyctl compares,
// prints and writes. It is also the shape of a rule in a rules file.
// Enabled is always explicit (a missing one is true, as the API stores it),
// so false is never lost; zero numbers and false booleans inside
// ActionParameters are kept as they are, only null values are dropped. Ref
// is empty when the rule has no reference of its own (the API sets it to
// the rule id then).
type Rule struct {
	Description      string         `json:"description,omitempty" yaml:"description,omitempty"`
	Ref              string         `json:"ref,omitempty" yaml:"ref,omitempty"`
	Enabled          bool           `json:"enabled" yaml:"enabled"`
	Action           string         `json:"action,omitempty" yaml:"action,omitempty"`
	Expression       string         `json:"expression,omitempty" yaml:"expression,omitempty"`
	ActionParameters map[string]any `json:"action_parameters,omitempty" yaml:"action_parameters,omitempty"`
}

// cleanRule turns a rule read from the API into its cleaned form.
func cleanRule(r apiRule) Rule {
	out := Rule{
		Description: r.Description,
		Enabled:     r.Enabled == nil || *r.Enabled,
		Action:      r.Action,
		Expression:  r.Expression,
	}
	if r.Ref != r.ID {
		out.Ref = r.Ref
	}
	out.ActionParameters = cleanParams(r.ActionParameters)
	return out
}

// cleanParams normalizes action parameters: nulls dropped (recursively),
// whole numbers as int64, an empty object as none.
func cleanParams(m map[string]any) map[string]any {
	if m == nil {
		return nil
	}
	out, _ := normValue(m).(map[string]any)
	if len(out) == 0 {
		return nil
	}
	return out
}

// normValue is the normal form of a decoded JSON or YAML value: maps with
// string keys and without null values, whole numbers as int64 and other
// numbers as float64, so that the same parameters compare equal whichever
// decoder read them.
func normValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if n := normValue(e); n != nil {
				out[k] = n
			}
		}
		return out
	case map[any]any:
		out := make(map[string]any, len(x))
		for k, e := range x {
			if n := normValue(e); n != nil {
				out[fmt.Sprint(k)] = n
			}
		}
		return out
	case []any:
		out := make([]any, 0, len(x))
		for _, e := range x {
			if n := normValue(e); n != nil {
				out = append(out, n)
			}
		}
		return out
	case float64:
		if x == math.Trunc(x) && math.Abs(x) < 1<<53 {
			return int64(x)
		}
		return x
	case float32:
		return normValue(float64(x))
	case int:
		return int64(x)
	case int32:
		return int64(x)
	case int64:
		return x
	case uint64:
		if x <= math.MaxInt64 {
			return int64(x)
		}
		return float64(x)
	case json.Number:
		if n, err := x.Int64(); err == nil {
			return n
		}
		if f, err := x.Float64(); err == nil {
			return normValue(f)
		}
		return x.String()
	}
	return v
}

// wire is the body form of a cleaned rule.
func (r Rule) wire() map[string]any {
	m := map[string]any{"enabled": r.Enabled}
	if r.Description != "" {
		m["description"] = r.Description
	}
	if r.Ref != "" {
		m["ref"] = r.Ref
	}
	if r.Action != "" {
		m["action"] = r.Action
	}
	if r.Expression != "" {
		m["expression"] = r.Expression
	}
	if r.ActionParameters != nil {
		m["action_parameters"] = r.ActionParameters
	}
	return m
}

// label names a rule in reports and messages.
func (r Rule) label() string {
	if r.Description == "" {
		return "(no description)"
	}
	return r.Description
}

// --- API ---------------------------------------------------------------------

func entrypointPath(zoneID, phase string) string {
	return "/zones/" + url.PathEscape(zoneID) + "/rulesets/phases/" + url.PathEscape(phase) + "/entrypoint"
}

// noEntrypoint reports whether err says the zone has no entrypoint ruleset
// in the phase (HTTP 404, code 10003): the phase was never configured. The
// zone exists then; a zone that does not exist answers HTTP 403.
func noEntrypoint(err error) bool {
	e := apiError(err)
	return e != nil && (e.HasCode(codeNoEntrypoint) || e.Status == http.StatusNotFound && !e.HasCode(7003))
}

// getEntrypoint reads the entrypoint ruleset of a phase. A phase that was
// never configured returns nil without an error.
func (a *api) getEntrypoint(ctx context.Context, zoneID, phase string) (*apiRuleset, error) {
	var rs apiRuleset
	if _, err := a.do(ctx, http.MethodGet, entrypointPath(zoneID, phase), nil, nil, &rs); err != nil {
		if noEntrypoint(err) {
			return nil, nil
		}
		return nil, err
	}
	return &rs, nil
}

// putEntrypoint replaces the rules of the entrypoint ruleset of a phase
// (creating the ruleset when there is none). Rules not in rules are
// deleted. Only the rules go in the body: the ruleset's own id, version and
// so on are refused there.
func (a *api) putEntrypoint(ctx context.Context, zoneID, phase string, rules []Rule) (*apiRuleset, error) {
	body := struct {
		Rules []map[string]any `json:"rules"`
	}{Rules: make([]map[string]any, 0, len(rules))}
	for _, r := range rules {
		body.Rules = append(body.Rules, r.wire())
	}
	var rs apiRuleset
	if _, err := a.do(ctx, http.MethodPut, entrypointPath(zoneID, phase), nil, body, &rs); err != nil {
		return nil, err
	}
	return &rs, nil
}

// cleanRules cleans the rules of a ruleset (nil for none).
func cleanRules(rs *apiRuleset) []Rule {
	if rs == nil {
		return nil
	}
	out := make([]Rule, 0, len(rs.Rules))
	for _, r := range rs.Rules {
		out = append(out, cleanRule(r))
	}
	return out
}

// versionText prints the version of a ruleset (a string on the API; a
// number is accepted too).
func versionText(v any) string {
	switch x := v.(type) {
	case nil:
		return ""
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	}
	return fmt.Sprint(v)
}

// rulesErrorHint adds what polyctl knows about a failed write of rules to
// err: the rule a JSON pointer such as /rules/2/expression points at, and
// that the number of rules a phase holds depends on the plan. A refused
// limit is not supported (exit code 7).
func rulesErrorHint(ph *rulesetPhase, rules []Rule, err error) error {
	e := apiError(err)
	if e == nil {
		return err
	}
	if e.HasCode(codeTooManyRules) {
		return fmt.Errorf("%w: %v (the number of %ss a phase holds depends on the plan; Free zones allow 10 cache rules)", platform.ErrNotSupported, err, ph.Noun)
	}
	for _, m := range e.Errors {
		if m.Source == nil {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(m.Source.Pointer, "/"), "/")
		if len(parts) < 2 || parts[0] != "rules" {
			continue
		}
		i, cerr := strconv.Atoi(parts[1])
		if cerr != nil || i < 0 || i >= len(rules) {
			continue
		}
		return fmt.Errorf("%s %d (%s), at %s: %w", ph.Noun, i+1, rules[i].label(), m.Source.Pointer, err)
	}
	return err
}

// --- rules file ----------------------------------------------------------------

// ruleKeys are the keys a rule of a rules file may have.
var ruleKeys = map[string]bool{"action": true, "expression": true, "description": true, "enabled": true, "action_parameters": true, "ref": true}

// fileKeys are the top-level keys of a rules file written as an object:
// the shape `rule list -o yaml|json` prints.
var fileKeys = map[string]bool{"rules": true, "zone": true, "phase": true, "ruleset_id": true}

// parseRulesFile reads a rules file (YAML or JSON): an object with a
// "rules" array, or the array itself. Every error is a usage error naming
// the rule (1-based) it is about.
func parseRulesFile(data []byte, ph *rulesetPhase) ([]Rule, error) {
	var doc any
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&doc); err != nil {
		if errors.Is(err, io.EOF) || strings.TrimSpace(string(data)) == "" {
			return nil, app.UsageErrf("the rules file is empty (it needs a rules: list)")
		}
		return nil, app.UsageErrf("the rules file is not valid YAML or JSON: %v", err)
	}
	var list any
	switch x := doc.(type) {
	case []any:
		list = x
	case map[string]any:
		var unknown []string
		for k := range x {
			if !fileKeys[k] {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, app.UsageErrf("the rules file has unknown top-level key(s) %s (expected rules)", strings.Join(unknown, ", "))
		}
		if p, ok := x["phase"]; ok && p != nil && fmt.Sprint(p) != ph.Phase {
			return nil, app.UsageErrf("the rules file holds rules of phase %v, not %s (%ss)", p, ph.Phase, ph.Noun)
		}
		l, ok := x["rules"]
		if !ok {
			return nil, app.UsageErrf("the rules file has no rules: list")
		}
		list = l
	case nil:
		return nil, app.UsageErrf("the rules file is empty (it needs a rules: list)")
	default:
		return nil, app.UsageErrf("the rules file must be a rules: list (or a list of rules)")
	}
	items, ok := list.([]any)
	if list != nil && !ok {
		return nil, app.UsageErrf("rules must be a list")
	}
	out := make([]Rule, 0, len(items))
	seen := map[string]int{}
	for i, it := range items {
		n := i + 1
		m, ok := normValue(it).(map[string]any)
		if !ok {
			return nil, app.UsageErrf("rule %d is not an object", n)
		}
		var unknown []string
		for k := range m {
			if !ruleKeys[k] {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			sort.Strings(unknown)
			return nil, app.UsageErrf("rule %d: unknown key(s) %s (allowed: action, expression, description, enabled, action_parameters, ref)", n, strings.Join(unknown, ", "))
		}
		str := func(k string) (string, error) {
			v, ok := m[k]
			if !ok {
				return "", nil
			}
			s, ok := v.(string)
			if !ok {
				return "", app.UsageErrf("rule %d: %s must be a string", n, k)
			}
			return s, nil
		}
		r := Rule{Enabled: true}
		var err error
		if r.Description, err = str("description"); err != nil {
			return nil, err
		}
		if r.Action, err = str("action"); err != nil {
			return nil, err
		}
		if r.Expression, err = str("expression"); err != nil {
			return nil, err
		}
		if r.Ref, err = str("ref"); err != nil {
			return nil, err
		}
		var missing []string
		for _, f := range []struct{ k, v string }{{"action", r.Action}, {"expression", r.Expression}, {"description", r.Description}} {
			if strings.TrimSpace(f.v) == "" {
				missing = append(missing, f.k)
			}
		}
		if len(missing) > 0 {
			return nil, app.UsageErrf("rule %d: missing %s", n, strings.Join(missing, ", "))
		}
		if r.Action != ph.Action {
			return nil, app.UsageErrf("rule %d (%s): action must be %s for %ss, got %q", n, r.Description, ph.Action, ph.Noun, r.Action)
		}
		if v, ok := m["enabled"]; ok {
			b, ok := v.(bool)
			if !ok {
				return nil, app.UsageErrf("rule %d (%s): enabled must be true or false", n, r.Description)
			}
			r.Enabled = b
		}
		if v, ok := m["action_parameters"]; ok {
			p, ok := v.(map[string]any)
			if !ok {
				return nil, app.UsageErrf("rule %d (%s): action_parameters must be an object", n, r.Description)
			}
			r.ActionParameters = cleanParams(p)
		}
		if prev, dup := seen[r.Description]; dup {
			return nil, app.UsageErrf("rule %d: description %q is used by rule %d too (descriptions identify the rules and must be unique)", n, r.Description, prev)
		}
		seen[r.Description] = n
		out = append(out, r)
	}
	return out, nil
}

// --- merge -------------------------------------------------------------------

// rulesPlan is what `rule set` would write and how it differs from what
// exists.
type rulesPlan struct {
	// Final is the whole rules list to write, in execution order.
	Final []Rule
	// Changes lists, in the order of Final, every rule of the file and every
	// kept rule that moved, then the deleted rules.
	Changes []platform.Change
	// Warnings are notes for stderr (duplicate descriptions).
	Warnings []string
	// Deleted are the rules --replace removes.
	Deleted []Rule
	// Write is set when Final differs from the existing rules (content or
	// order): only then is anything written.
	Write bool
}

// slot is a rule of the final list with the index of the existing rule it
// stands for (-1 for a new one).
type slot struct {
	rule     Rule
	from     int
	fromFile bool
}

// planRules merges the rules of a file into the existing ones. Rules are
// matched by description. In the merge mode a matched rule is replaced in
// place, a new one is appended (put first, in file order, with first), and
// the other existing rules are kept where they are; nothing is deleted.
// With replace the final list is the file, and the existing rules it does
// not name are deleted. A file rule without a ref keeps the ref of the rule
// it replaces.
func planRules(ph *rulesetPhase, zone string, existing, desired []Rule, replace, first bool) rulesPlan {
	var p rulesPlan
	byDesc := map[string][]int{}
	for i, r := range existing {
		if r.Description != "" {
			byDesc[r.Description] = append(byDesc[r.Description], i)
		}
	}
	var slots []slot
	used := map[int]bool{}
	if replace {
		for _, d := range desired {
			from := -1
			for _, i := range byDesc[d.Description] {
				if !used[i] {
					from = i
					break
				}
			}
			if from >= 0 {
				used[from] = true
				if d.Ref == "" {
					d.Ref = existing[from].Ref
				}
			}
			slots = append(slots, slot{rule: d, from: from, fromFile: true})
		}
		for i, r := range existing {
			if !used[i] {
				p.Deleted = append(p.Deleted, r)
			}
		}
	} else {
		slots = make([]slot, len(existing))
		for i, r := range existing {
			slots[i] = slot{rule: r, from: i}
		}
		var added []slot
		for _, d := range desired {
			idx := byDesc[d.Description]
			if len(idx) == 0 {
				added = append(added, slot{rule: d, from: -1, fromFile: true})
				continue
			}
			if d.Ref == "" {
				d.Ref = existing[idx[0]].Ref
			}
			slots[idx[0]] = slot{rule: d, from: idx[0], fromFile: true}
			if len(idx) > 1 {
				p.Warnings = append(p.Warnings, fmt.Sprintf("warning: duplicate description: %d existing %ss are named %q; only the first (position %d) is replaced, the others are kept",
					len(idx), ph.Noun, d.Description, idx[0]+1))
			}
		}
		if first {
			slots = append(added, slots...)
		} else {
			slots = append(slots, added...)
		}
	}
	res := func(r Rule) string { return "zone/" + zone + "/" + ph.Res + "/" + r.label() }
	for i, s := range slots {
		p.Final = append(p.Final, s.rule)
		if s.from < 0 {
			p.Changes = append(p.Changes, platform.Change{Resource: res(s.rule), Action: platform.Created, Detail: fmt.Sprintf("position %d", i+1)})
			continue
		}
		diffs := ruleDiff(existing[s.from], s.rule)
		if s.from != i {
			diffs = append(diffs, fmt.Sprintf("position %d -> %d", s.from+1, i+1))
		}
		switch {
		case len(diffs) > 0:
			p.Changes = append(p.Changes, platform.Change{Resource: res(s.rule), Action: platform.Updated, Detail: strings.Join(diffs, ", ")})
		case s.fromFile:
			p.Changes = append(p.Changes, platform.Change{Resource: res(s.rule), Action: platform.Unchanged})
		}
	}
	for i, r := range existing {
		if replace && !used[i] {
			p.Changes = append(p.Changes, platform.Change{Resource: res(r), Action: platform.Deleted, Detail: fmt.Sprintf("position %d", i+1)})
		}
	}
	p.Write = !sameRules(existing, p.Final)
	return p
}

// sameRules compares two rules lists, order included.
func sameRules(a, b []Rule) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !reflect.DeepEqual(a[i], b[i]) {
			return false
		}
	}
	return true
}

// ruleDiff lists what differs between two rules: the top-level fields and
// the leaves of the action parameters (edge_ttl.default 3600 -> 2678400).
func ruleDiff(a, b Rule) []string {
	var out []string
	if a.Enabled != b.Enabled {
		out = append(out, fmt.Sprintf("enabled %t -> %t", a.Enabled, b.Enabled))
	}
	if a.Action != b.Action {
		out = append(out, fmt.Sprintf("action %s -> %s", orDash(a.Action), orDash(b.Action)))
	}
	if a.Expression != b.Expression {
		out = append(out, "expression")
	}
	if a.Ref != b.Ref {
		out = append(out, fmt.Sprintf("ref %s -> %s", orDash(a.Ref), orDash(b.Ref)))
	}
	var pa, pb any
	if a.ActionParameters != nil {
		pa = a.ActionParameters
	}
	if b.ActionParameters != nil {
		pb = b.ActionParameters
	}
	return append(out, valueDiff("", pa, pb)...)
}

func valueDiff(path string, a, b any) []string {
	ma, aok := a.(map[string]any)
	mb, bok := b.(map[string]any)
	if aok && bok {
		keys := map[string]bool{}
		for k := range ma {
			keys[k] = true
		}
		for k := range mb {
			keys[k] = true
		}
		names := make([]string, 0, len(keys))
		for k := range keys {
			names = append(names, k)
		}
		sort.Strings(names)
		var out []string
		for _, k := range names {
			p := k
			if path != "" {
				p = path + "." + k
			}
			out = append(out, valueDiff(p, ma[k], mb[k])...)
		}
		return out
	}
	if reflect.DeepEqual(a, b) {
		return nil
	}
	if path == "" {
		path = "action_parameters"
	}
	from, to := valueText(a), valueText(b)
	if len(from) > 30 || len(to) > 30 {
		return []string{path}
	}
	return []string{path + " " + from + " -> " + to}
}

// valueText prints a parameter value in a change detail.
func valueText(v any) string {
	switch x := v.(type) {
	case nil:
		return "-"
	case string:
		return x
	case int64:
		return strconv.FormatInt(x, 10)
	case bool:
		return strconv.FormatBool(x)
	}
	b, err := json.Marshal(v)
	if err != nil {
		return fmt.Sprint(v)
	}
	return string(b)
}

func orDash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}
