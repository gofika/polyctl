package cloudflare

import (
	"context"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// This file holds `cloudflare cache rule list|set` and
// `cloudflare redirect rule list|set`.

// expressionWidth is where the table cuts an expression (json and yaml
// never cut).
const expressionWidth = 40

// resolveRulesZone finds the zone a rule command works on through the
// inventory, without reading it: the rule requests tell whether it exists.
func resolveRulesZone(ctx context.Context, rt *app.Runtime, arg string) (*zoneScope, error) {
	c, res, err := routeZone(ctx, rt, zoneRef(arg))
	if err != nil {
		return nil, err
	}
	return &zoneScope{c: c, profile: res.Profile, z: &apiZone{ID: res.ID, Name: res.Name}}, nil
}

// rulesError maps the failure of a request for the rules of the zone of s.
// The Rulesets endpoints answer HTTP 403 code 10000 for a zone that does
// not exist, the same answer as for a token without the permission, so the
// zone is read to tell them apart: a zone that is gone is not found (exit
// code 4) and leaves the inventory; otherwise the token lacks the
// permission (exit code 3).
func (s *zoneScope) rulesError(ctx context.Context, rt *app.Runtime, ph *rulesetPhase, rules []Rule, err error) error {
	e := apiError(err)
	if e == nil {
		return err
	}
	if zoneGone(err) {
		return s.gone(ctx, rt, err)
	}
	if e.Status == 403 || e.HasCode(codeAuthError) {
		if e.HasCode(codeAuthError) {
			_, gerr := s.c.api.getZone(ctx, s.z.ID)
			if ge := apiError(gerr); zoneGone(gerr) || ge != nil && ge.Status == 404 {
				dropZone(ctx, rt, s.profile, s.z.ID)
				return fmt.Errorf("%w: zone %s not found (id %s; removed from the local inventory): %v", platform.ErrNotFound, s.name(), s.z.ID, err)
			}
		}
		return fmt.Errorf("the token of cloudflare/%s may not read or write the %ss of zone %s (it needs the %s permission): %w",
			s.profile, ph.Noun, s.name(), ph.Permission, err)
	}
	return rulesErrorHint(ph, rules, err)
}

// rulesList is the json / yaml shape of `rule list`; its rules are also
// the input of `rule set --file`.
type rulesList struct {
	Zone      rulesZone `json:"zone" yaml:"zone"`
	Phase     string    `json:"phase" yaml:"phase"`
	RulesetID string    `json:"ruleset_id" yaml:"ruleset_id"`
	Rules     []Rule    `json:"rules" yaml:"rules"`
}

type rulesZone struct {
	ID   string `json:"id" yaml:"id"`
	Name string `json:"name" yaml:"name"`
}

// newRuleCmd builds the `rule` group of a phase.
func newRuleCmd(rt *app.Runtime, ph *rulesetPhase) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rule",
		Short: "List and set the " + ph.Noun + "s of a zone",
	}
	cmd.AddCommand(newRuleListCmd(rt, ph), newRuleSetCmd(rt, ph))
	return cmd
}

func newRuleListCmd(rt *app.Runtime, ph *rulesetPhase) *cobra.Command {
	var wide bool
	cmd := &cobra.Command{
		Use:   "list <zone>",
		Short: "List the " + ph.Noun + "s of a zone, in execution order",
		Long: `List the ` + ph.Noun + `s of <zone> (a name or a zone id), in execution order,
read live from the entrypoint ruleset of the phase ` + ph.Phase + `.
A zone that never had any is listed empty. The table cuts expressions at
` + strconv.Itoa(expressionWidth) + ` characters; --wide prints them whole and adds the details. The rules
of -o json / -o yaml are cleaned (only description, ref, enabled, action,
expression and action_parameters) and are the input of 'rule set --file'.`,
		Example:           fmt.Sprintf("  polyctl cloudflare %s rule list example.com\n  polyctl cloudflare %s rule list example.com -o yaml > rules.yaml", ph.Service, ph.Service),
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := resolveRulesZone(ctx, rt, app.Arg(args, 0))
			if err != nil {
				return err
			}
			rs, err := s.c.api.getEntrypoint(ctx, s.z.ID, ph.Phase)
			if err != nil {
				return s.rulesError(ctx, rt, ph, nil, err)
			}
			out := rulesList{Zone: rulesZone{ID: s.z.ID, Name: s.name()}, Phase: ph.Phase, Rules: cleanRules(rs)}
			if rs != nil {
				out.RulesetID = rs.ID
			}
			if out.Rules == nil {
				out.Rules = []Rule{}
			}
			if len(out.Rules) == 0 {
				rt.Infof("zone %s has no %ss (via cloudflare/%s)", s.name(), ph.Noun, s.profile)
			} else {
				rt.Infof("%d %s(s) of zone %s via cloudflare/%s", len(out.Rules), ph.Noun, s.name(), s.profile)
			}
			return rt.Render(out, func() output.Grid { return rulesGrid(ph, out.Rules, wide) })
		},
	}
	cmd.Flags().BoolVar(&wide, "wide", false, "print expressions whole and add the details (status code TTLs, redirect targets)")
	return cmd
}

func newRuleSetCmd(rt *app.Runtime, ph *rulesetPhase) *cobra.Command {
	var file string
	var replace, first bool
	cmd := &cobra.Command{
		Use:   "set <zone> --file <rules.yaml>",
		Short: "Merge the " + ph.Noun + "s of a file into a zone (--replace: make them the whole list)",
		Long: `Write the ` + ph.Noun + `s of --file (YAML or JSON; - reads stdin) to <zone>.
The file is a rules: list (or a bare list), each rule with the keys of the
Cloudflare API: description, action (` + ph.Action + `), expression,
enabled (default true), action_parameters, and optionally ref. description,
action and expression are required, and descriptions must be unique: they
identify the rules. The output of 'rule list -o yaml' is a valid file.

Cloudflare replaces the whole list of a phase on every write, so set reads
the rules first and merges: a rule whose description matches an existing
one replaces it in place, a new one is appended at the end (--first puts the
new ones first, in file order; the order of the rules is their execution
order), and existing rules the file does not name are kept. A file rule
without ref keeps the ref of the rule it replaces. When the result equals
what exists, nothing is written and every rule is reported unchanged;
otherwise the whole list is written with one request, which succeeds or
fails as a whole.

--replace makes the file the whole list: existing rules it does not name are
deleted. That asks for a confirmation (default no) in the interactive flow
and needs --yes in the non-interactive one. --dry-run reads and reports
what would change, and asks nothing.

The write has no lock: run one set per zone and phase at a time.`,
		Example: fmt.Sprintf(`  polyctl cloudflare %[1]s rule set example.com --file rules.yaml --dry-run
  polyctl cloudflare %[1]s rule set example.com --file rules.yaml
  polyctl cloudflare %[1]s rule set example.com --file rules.yaml --replace -y`, ph.Service),
		Args:              app.ArgsOrInteractive(rt, 1, nil),
		ValidArgsFunction: completeZones(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if file == "" {
				return app.UsageErrf("--file is required (a YAML or JSON rules file, - for stdin)")
			}
			if replace && first {
				return app.UsageErrf("--first applies to the merge mode only: with --replace the order of the file is the order of the rules")
			}
			data, err := readRulesFile(rt, file)
			if err != nil {
				return err
			}
			desired, err := parseRulesFile(data, ph)
			if err != nil {
				return err
			}
			s, err := resolveRulesZone(ctx, rt, app.Arg(args, 0))
			if err != nil {
				return err
			}
			rs, err := s.c.api.getEntrypoint(ctx, s.z.ID, ph.Phase)
			if err != nil {
				return s.rulesError(ctx, rt, ph, nil, err)
			}
			existing := cleanRules(rs)
			plan := planRules(ph, s.name(), existing, desired, replace, first)
			for _, w := range plan.Warnings {
				rt.Infof("%s", w)
			}
			if !plan.Write {
				rt.Infof("the %ss of zone %s are already as desired (nothing written)", ph.Noun, s.name())
				return rt.RenderReport(platform.Report{Target: s.target(), DryRun: rt.DryRun(), Changes: plan.Changes})
			}
			action := platform.Updated
			if rs == nil {
				action = platform.Created
			}
			changes := append(plan.Changes, platform.Change{Resource: "zone/" + s.name() + "/" + ph.Res + "s", Action: action,
				Detail: fmt.Sprintf("PUT entrypoint (%d rules)", len(plan.Final))})
			if done, err := rt.WouldWrite(s.target(), changes...); done || err != nil {
				return err
			}
			if len(plan.Deleted) > 0 {
				what := fmt.Sprintf("delete %d %s(s) of zone %s", len(plan.Deleted), ph.Noun, s.name())
				if err := rt.CanConfirm(what); err != nil {
					return err
				}
				rt.Infof("--replace deletes these %ss of zone %s:", ph.Noun, s.name())
				for _, r := range plan.Deleted {
					rt.Infof("  %s", r.label())
				}
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete %d %s(s) of zone %s and write %d?", len(plan.Deleted), ph.Noun, s.name(), len(plan.Final)), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; the %ss of zone %s were not changed", platform.ErrNothingToDo, ph.Noun, s.name())
				}
			}
			out, err := s.c.api.putEntrypoint(ctx, s.z.ID, ph.Phase, plan.Final)
			if err != nil {
				return s.rulesError(ctx, rt, ph, plan.Final, err)
			}
			n := len(plan.Final)
			if out != nil && out.Rules != nil {
				n = len(out.Rules)
			}
			note := ""
			if out != nil && versionText(out.Version) != "" {
				note = ", version " + versionText(out.Version)
			}
			rt.Infof("zone %s now has %d %s(s)%s via cloudflare/%s", s.name(), n, ph.Noun, note, s.profile)
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: changes})
		},
	}
	cmd.Flags().StringVarP(&file, "file", "f", "", "YAML or JSON rules file (- reads stdin); see the help text")
	cmd.Flags().BoolVar(&replace, "replace", false, "make the file the whole list: delete the existing rules it does not name (asks for confirmation)")
	cmd.Flags().BoolVar(&first, "first", false, "put new rules first (in file order) instead of appending them")
	return cmd
}

// readRulesFile reads --file, or stdin for "-".
func readRulesFile(rt *app.Runtime, file string) ([]byte, error) {
	if file == "-" {
		b, err := io.ReadAll(rt.Stdin)
		if err != nil {
			return nil, app.UsageErrf("read the rules from stdin: %v", err)
		}
		return b, nil
	}
	b, err := os.ReadFile(file)
	if err != nil {
		return nil, app.UsageErrf("read the rules file: %v", err)
	}
	return b, nil
}

// --- table -------------------------------------------------------------------

func rulesGrid(ph *rulesetPhase, rules []Rule, wide bool) output.Grid {
	if ph == redirectRules {
		return redirectGrid(rules, wide)
	}
	return cacheGrid(rules, wide)
}

func cacheGrid(rules []Rule, wide bool) output.Grid {
	g := output.Grid{Headers: []string{"#", "ENABLED", "DESCRIPTION", "EXPRESSION", "CACHE", "EDGE_TTL", "BROWSER_TTL"}, Empty: "no cache rules"}
	if wide {
		g.Headers = append(g.Headers, "STATUS_TTL", "REF")
	}
	for i, r := range rules {
		p := r.ActionParameters
		cache := "-"
		if b, ok := p["cache"].(bool); ok {
			cache = strconv.FormatBool(b)
		}
		row := []string{strconv.Itoa(i + 1), strconv.FormatBool(r.Enabled), r.label(), cutExpression(r.Expression, wide),
			cache, ttlText(p, "edge_ttl"), ttlText(p, "browser_ttl")}
		if wide {
			row = append(row, statusTTLText(p), orDash(r.Ref))
		}
		g.Rows = append(g.Rows, row)
	}
	return g
}

func redirectGrid(rules []Rule, wide bool) output.Grid {
	g := output.Grid{Headers: []string{"#", "ENABLED", "DESCRIPTION", "EXPRESSION", "STATUS", "TARGET", "KEEP_QUERY"}, Empty: "no redirect rules"}
	if wide {
		g.Headers = append(g.Headers, "REF")
	}
	for i, r := range rules {
		from, _ := r.ActionParameters["from_value"].(map[string]any)
		status, target, query := "-", "-", "-"
		if v, ok := from["status_code"]; ok {
			status = valueText(v)
		}
		if t, ok := from["target_url"].(map[string]any); ok {
			if v, ok := t["value"].(string); ok {
				target = v
			} else if v, ok := t["expression"].(string); ok {
				target = "expr: " + v
			}
		}
		if b, ok := from["preserve_query_string"].(bool); ok {
			query = strconv.FormatBool(b)
		}
		row := []string{strconv.Itoa(i + 1), strconv.FormatBool(r.Enabled), r.label(), cutExpression(r.Expression, wide),
			status, cutExpression(target, wide), query}
		if wide {
			row = append(row, orDash(r.Ref))
		}
		g.Rows = append(g.Rows, row)
	}
	return g
}

// cutExpression cuts a long expression for the table.
func cutExpression(s string, wide bool) string {
	if s == "" {
		return "-"
	}
	if wide || len([]rune(s)) <= expressionWidth {
		return s
	}
	return string([]rune(s)[:expressionWidth-3]) + "..."
}

// ttlText prints the edge_ttl or browser_ttl of cache parameters: the mode
// (override_origin as "override") and, when there is one, the default TTL.
// A rule that caches without an edge TTL uses the default.
func ttlText(p map[string]any, key string) string {
	t, ok := p[key].(map[string]any)
	if !ok {
		if key == "edge_ttl" {
			if b, ok := p["cache"].(bool); ok && b {
				return "default"
			}
		}
		return "-"
	}
	mode, _ := t["mode"].(string)
	words := strings.ReplaceAll(mode, "_", " ")
	if mode == "override_origin" {
		words = "override"
	}
	if d, ok := t["default"]; ok {
		if words == "" {
			return secondsText(d)
		}
		return words + " " + secondsText(d)
	}
	if words == "" {
		return "-"
	}
	return words
}

// secondsText prints a TTL: 300s, 2678400s (31d), 90000s (1.0d), 0s (no
// cache).
func secondsText(v any) string {
	n, ok := v.(int64)
	if !ok {
		return valueText(v)
	}
	s := strconv.FormatInt(n, 10) + "s"
	switch {
	case n == 0:
		return s + " (no cache)"
	case n > 86400 && n%86400 == 0:
		return s + " (" + strconv.FormatInt(n/86400, 10) + "d)"
	case n > 86400:
		return s + " (" + strconv.FormatFloat(float64(n)/86400, 'f', 1, 64) + "d)"
	}
	return s
}

// statusTTLText prints the status code TTLs of an edge TTL:
// 200-299:2678400, 400+:0, <=199:60, 404:0.
func statusTTLText(p map[string]any) string {
	t, _ := p["edge_ttl"].(map[string]any)
	list, _ := t["status_code_ttl"].([]any)
	if len(list) == 0 {
		return "-"
	}
	var parts []string
	for _, e := range list {
		m, _ := e.(map[string]any)
		value := valueText(m["value"])
		rng, _ := m["status_code_range"].(map[string]any)
		from, hasFrom := rng["from"]
		to, hasTo := rng["to"]
		var codes string
		switch {
		case m["status_code"] != nil:
			codes = valueText(m["status_code"])
		case hasFrom && hasTo:
			codes = valueText(from) + "-" + valueText(to)
		case hasFrom:
			codes = valueText(from) + "+"
		case hasTo:
			codes = "<=" + valueText(to)
		default:
			codes = "unknown"
		}
		parts = append(parts, codes+":"+value)
	}
	return strings.Join(parts, ", ")
}

// newRedirectCmd is the `redirect` group: Single Redirects.
func newRedirectCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "redirect", Short: "Redirect rules (Single Redirects)"}
	cmd.AddCommand(newRuleCmd(rt, redirectRules))
	return cmd
}
