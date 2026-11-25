package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// VPC firewall rules are global resources of a project: a rule name is
// unique in the project, whatever its network. Every write returns a
// global Operation; writes to one rule must not overlap (a Patch sent
// while the previous one still runs fails with "resourceNotReady"), so
// each write is waited for unless --no-wait asked for submission only.

// Firewall rule directions.
const (
	dirIngress = "INGRESS"
	dirEgress  = "EGRESS"
)

// defaultFirewallPriority is the priority of a rule that does not set one.
const defaultFirewallPriority = 1000

// firewallNameRE is the Compute Engine resource name rule.
var firewallNameRE = regexp.MustCompile(`^[a-z]([-a-z0-9]*[a-z0-9])?$`)

// checkFirewallName validates a rule name polyctl is asked to create.
func checkFirewallName(name string) error {
	if len(name) > 63 || !firewallNameRE.MatchString(name) {
		return app.UsageErrf("invalid firewall rule name %q: a lower-case letter first, then lower-case letters, digits and hyphens, not ending with a hyphen, at most 63 characters", name)
	}
	return nil
}

// networkPath is the network reference a rule is created with.
func (c *client) networkPath(network string) string {
	return "projects/" + c.project + "/global/networks/" + network
}

// ------------------------------------------------------------ API calls

// getFirewall reads a rule; a missing one is ErrNotFound.
func (c *client) getFirewall(ctx context.Context, name string) (*compute.Firewall, error) {
	fw, err := c.compute.Firewalls.Get(c.project, name).Context(ctx).Do()
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, fmt.Errorf("%w: firewall rule %s in project %s", platform.ErrNotFound, name, c.project)
		}
		return nil, err
	}
	return fw, nil
}

// findFirewall reads a rule, returning nil (no error) when it does not
// exist.
func (c *client) findFirewall(ctx context.Context, name string) (*compute.Firewall, error) {
	fw, err := c.getFirewall(ctx, name)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, nil
	}
	return fw, err
}

// listFirewalls lists every rule of the project, of every network.
func (c *client) listFirewalls(ctx context.Context) ([]*compute.Firewall, error) {
	var out []*compute.Firewall
	err := c.compute.Firewalls.List(c.project).Pages(ctx, func(l *compute.FirewallList) error {
		out = append(out, l.Items...)
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

func (c *client) waitGlobalOp(ctx context.Context, op *compute.Operation) error {
	return waitOp(ctx, op, func(ctx context.Context, name string) (*compute.Operation, error) {
		return c.compute.GlobalOperations.Wait(c.project, name).Context(ctx).Do()
	})
}

// finishGlobal waits for a global operation, or with wait false only
// reports an error the operation already carries.
func (c *client) finishGlobal(ctx context.Context, op *compute.Operation, wait bool) error {
	if !wait {
		return opError(op)
	}
	return c.waitGlobalOp(ctx, op)
}

// insertFirewall creates a rule.
func (c *client) insertFirewall(ctx context.Context, fw *compute.Firewall, wait bool) error {
	op, err := c.compute.Firewalls.Insert(c.project, fw).Context(ctx).Do()
	if err != nil {
		if isReason(err, "alreadyExists") {
			return fmt.Errorf("firewall rule %s already exists in project %s: use `polyctl gcp compute firewall ensure` to converge it, or `update` to change it: %w", fw.Name, c.project, err)
		}
		return computeErr(err)
	}
	return c.finishGlobal(ctx, op, wait)
}

// patchFirewall changes the fields set in fw (list fields are replaced
// as a whole; an empty list is not sent, so it cannot clear one).
func (c *client) patchFirewall(ctx context.Context, name string, fw *compute.Firewall, wait bool) error {
	op, err := c.compute.Firewalls.Patch(c.project, name, fw).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	return c.finishGlobal(ctx, op, wait)
}

// replaceFirewall sends the whole rule (PUT): fields it leaves out are
// cleared. It is only used to clear a list field, which Patch cannot do.
func (c *client) replaceFirewall(ctx context.Context, name string, fw *compute.Firewall, wait bool) error {
	op, err := c.compute.Firewalls.Update(c.project, name, fw).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	return c.finishGlobal(ctx, op, wait)
}

// deleteFirewall deletes a rule.
func (c *client) deleteFirewall(ctx context.Context, name string, wait bool) error {
	op, err := c.compute.Firewalls.Delete(c.project, name).Context(ctx).Do()
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return fmt.Errorf("%w: firewall rule %s in project %s", platform.ErrNotFound, name, c.project)
		}
		return err
	}
	return c.finishGlobal(ctx, op, wait)
}

// ------------------------------------------------------------ rule specs

// firewallProtocols are the protocols --allow takes.
var firewallProtocols = []string{"tcp", "udp", "icmp", "all"}

// parseAllow parses --allow values: "<protocol>" (every port) or
// "<protocol>:<ports>" with a port list of platform.ParsePortSpec
// ("tcp:80,443,8000-8100", "tcp:ssh"). The protocol is tcp, udp, icmp or
// all; only tcp and udp take ports. Values of one protocol are merged into
// one entry, and a protocol given without ports covers every port.
func parseAllow(specs []string) ([]*compute.FirewallAllowed, error) {
	var out []*compute.FirewallAllowed
	all := map[string]bool{}
	ranges := map[string][]platform.PortRange{}
	for _, raw := range specs {
		proto, ports, hasPorts := strings.Cut(strings.TrimSpace(raw), ":")
		proto = strings.ToLower(strings.TrimSpace(proto))
		if !slices.Contains(firewallProtocols, proto) {
			return nil, app.UsageErrf("--allow %q: unknown protocol %q (expected tcp, udp, icmp or all, optionally followed by :<ports> for tcp and udp, e.g. tcp:80,443,8000-8100)", raw, proto)
		}
		if hasPorts && proto != "tcp" && proto != "udp" {
			return nil, app.UsageErrf("--allow %q: ports may only be given for tcp and udp; write %s alone", raw, proto)
		}
		var e *compute.FirewallAllowed
		for _, x := range out {
			if x.IPProtocol == proto {
				e = x
			}
		}
		if e == nil {
			e = &compute.FirewallAllowed{IPProtocol: proto}
			out = append(out, e)
		}
		if !hasPorts {
			all[proto] = true
			continue
		}
		rs, err := platform.ParsePortSpec(ports)
		if err != nil {
			return nil, app.UsageErrf("--allow %q: %v", raw, err)
		}
		ranges[proto] = append(ranges[proto], rs...)
	}
	for _, e := range out {
		if all[e.IPProtocol] {
			continue
		}
		e.Ports = portStrings(ranges[e.IPProtocol])
	}
	return out, nil
}

// portStrings renders ranges sorted and without repeats.
func portStrings(rs []platform.PortRange) []string {
	sort.Slice(rs, func(i, j int) bool {
		if rs[i].From != rs[j].From {
			return rs[i].From < rs[j].From
		}
		return rs[i].To < rs[j].To
	})
	var out []string
	for _, r := range rs {
		if s := r.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out
}

// allowedLabel renders allowed entries ("tcp:80,443 icmp").
func allowedLabel(list []*compute.FirewallAllowed) string {
	var parts []string
	for _, a := range list {
		p := strings.ToLower(a.IPProtocol)
		if len(a.Ports) > 0 {
			p += ":" + strings.Join(a.Ports, ",")
		}
		parts = append(parts, p)
	}
	return strings.Join(parts, " ")
}

// allowedKey is a canonical form of allowed entries for comparison: the
// protocols lower-cased and sorted, the ports of each normalized, so the
// order Compute Engine returns them in does not matter.
func allowedKey(list []*compute.FirewallAllowed) string {
	ports := map[string][]string{}
	every := map[string]bool{}
	for _, a := range list {
		p := strings.ToLower(a.IPProtocol)
		if len(a.Ports) == 0 {
			every[p] = true
		}
		ports[p] = append(ports[p], a.Ports...)
	}
	var parts []string
	for p, ps := range ports {
		switch rs, err := platform.ParsePortSpec(strings.Join(ps, ",")); {
		case every[p]:
		case err == nil:
			p += ":" + strings.Join(portStrings(rs), ",")
		default:
			ps = slices.Clone(ps)
			sort.Strings(ps)
			p += ":" + strings.Join(slices.Compact(ps), ",")
		}
		parts = append(parts, p)
	}
	sort.Strings(parts)
	return strings.Join(parts, " ")
}

// deniedLabel renders denied entries like allowedLabel.
func deniedLabel(list []*compute.FirewallDenied) string {
	var conv []*compute.FirewallAllowed
	for _, d := range list {
		conv = append(conv, &compute.FirewallAllowed{IPProtocol: d.IPProtocol, Ports: d.Ports})
	}
	return allowedLabel(conv)
}

// parseCIDRs normalizes the CIDRs of a range flag: a bare address gets /32
// or /128 and host bits are masked. The result is sorted, without repeats.
func parseCIDRs(flag string, values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		v = strings.TrimSpace(v)
		var p netip.Prefix
		if pp, err := netip.ParsePrefix(v); err == nil {
			p = pp.Masked()
		} else if a, err := netip.ParseAddr(v); err == nil {
			p = netip.PrefixFrom(a, a.BitLen())
		} else {
			return nil, app.UsageErrf("--%s %q is not a CIDR or an IP address", flag, v)
		}
		if s := p.String(); !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	sort.Strings(out)
	return out, nil
}

// unionRanges returns have plus the ranges of want it lacks (sorted,
// without repeats) and those added ranges.
func unionRanges(have, want []string) (union, added []string) {
	set := map[string]bool{}
	for _, r := range have {
		if !set[r] {
			set[r] = true
			union = append(union, r)
		}
	}
	for _, r := range want {
		if !set[r] {
			set[r] = true
			union = append(union, r)
			added = append(added, r)
		}
	}
	sort.Strings(union)
	sort.Strings(added)
	return union, added
}

// sameSet reports whether two string lists hold the same values.
func sameSet(a, b []string) bool {
	x, y := slices.Clone(a), slices.Clone(b)
	sort.Strings(x)
	sort.Strings(y)
	return slices.Equal(slices.Compact(x), slices.Compact(y))
}

// dedupe returns the values without repeats, in their order.
func dedupe(values []string) []string {
	var out []string
	for _, v := range values {
		if v = strings.TrimSpace(v); !slices.Contains(out, v) {
			out = append(out, v)
		}
	}
	return out
}

// parseDirection reads --direction.
func parseDirection(s string) (string, error) {
	switch strings.ToUpper(strings.TrimSpace(s)) {
	case "", dirIngress:
		return dirIngress, nil
	case dirEgress:
		return dirEgress, nil
	}
	return "", app.UsageErrf("--direction %q: expected ingress or egress", s)
}

// checkPriority validates --priority.
func checkPriority(p int64) error {
	if p < 0 || p > 65535 {
		return app.UsageErrf("--priority %d is out of range 0-65535 (lower numbers win)", p)
	}
	return nil
}

// ------------------------------------------------------------ views

// ruleView is one allowed or denied entry of a rule.
type ruleView struct {
	Protocol string   `json:"protocol" yaml:"protocol"`
	Ports    []string `json:"ports" yaml:"ports"`
}

// firewallView is the output shape of a firewall rule.
type firewallView struct {
	Name string `json:"name" yaml:"name"`
	// Project is the project of the rule.
	Project           string     `json:"project,omitempty" yaml:"project,omitempty"`
	Network           string     `json:"network" yaml:"network"`
	Direction         string     `json:"direction" yaml:"direction"`
	Priority          int64      `json:"priority" yaml:"priority"`
	Allowed           []ruleView `json:"allowed" yaml:"allowed"`
	Denied            []ruleView `json:"denied,omitempty" yaml:"denied,omitempty"`
	SourceRanges      []string   `json:"source_ranges" yaml:"source_ranges"`
	DestinationRanges []string   `json:"destination_ranges,omitempty" yaml:"destination_ranges,omitempty"`
	SourceTags        []string   `json:"source_tags,omitempty" yaml:"source_tags,omitempty"`
	TargetTags        []string   `json:"target_tags" yaml:"target_tags"`
	Disabled          bool       `json:"disabled" yaml:"disabled"`
	Description       string     `json:"description" yaml:"description"`
	CreationTimestamp string     `json:"creation_timestamp" yaml:"creation_timestamp"`
}

func firewallFromAPI(fw *compute.Firewall) firewallView {
	v := firewallView{Name: fw.Name, Network: lastSegment(fw.Network), Direction: fw.Direction, Priority: fw.Priority,
		Allowed: []ruleView{}, SourceRanges: nonNil(fw.SourceRanges), DestinationRanges: fw.DestinationRanges, SourceTags: fw.SourceTags,
		TargetTags: nonNil(fw.TargetTags), Disabled: fw.Disabled, Description: fw.Description, CreationTimestamp: fw.CreationTimestamp}
	for _, a := range fw.Allowed {
		v.Allowed = append(v.Allowed, ruleView{Protocol: a.IPProtocol, Ports: nonNil(a.Ports)})
	}
	for _, d := range fw.Denied {
		v.Denied = append(v.Denied, ruleView{Protocol: d.IPProtocol, Ports: nonNil(d.Ports)})
	}
	return v
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// ruleLabel is the ALLOW cell of a rule: its allowed entries, or "deny"
// and its denied entries.
func ruleLabel(fw *compute.Firewall) string {
	if len(fw.Denied) > 0 {
		return "deny " + deniedLabel(fw.Denied)
	}
	return allowedLabel(fw.Allowed)
}

// rangeCount is the SOURCES cell: the number of source ranges of an
// ingress rule, of destination ranges of an egress one.
func rangeCount(fw *compute.Firewall) int {
	if fw.Direction == dirEgress {
		return len(fw.DestinationRanges)
	}
	return len(fw.SourceRanges)
}

// plural renders "1 source range" / "5 source ranges".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return strconv.Itoa(n) + " " + word + "s"
}
