package gcp

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive questions of the firewall commands.

// iapRange is the source range of Identity-Aware Proxy TCP forwarding,
// offered for SSH and RDP rules.
const iapRange = "35.235.240.0/20"

// firewallOptionLabel: "allow-ssh  default  INGRESS  prio 1000  tcp:22
// 10.0.0.0/8  tags ssh".
func firewallOptionLabel(fw *compute.Firewall) string {
	ranges := fw.SourceRanges
	if fw.Direction == dirEgress {
		ranges = fw.DestinationRanges
	}
	tags := "every instance"
	if len(fw.TargetTags) > 0 {
		tags = "tags " + strings.Join(fw.TargetTags, ",")
	}
	dis := ""
	if fw.Disabled {
		dis = "disabled"
	}
	return joinLabel(fw.Name, lastSegment(fw.Network), fw.Direction, "prio "+strconv.FormatInt(fw.Priority, 10), ruleLabel(fw),
		strings.Join(ranges, ","), tags, dis)
}

// firewallOptions lists the rules of the project as options, sorted by
// network and name; keep (nil: all) keeps the usable ones.
func firewallOptions(ctx context.Context, c *client, keep func(*compute.Firewall) bool) ([]prompt.Option, error) {
	all, err := c.listFirewalls(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(all, func(i, j int) bool {
		if a, b := lastSegment(all[i].Network), lastSegment(all[j].Network); a != b {
			return a < b
		}
		return all[i].Name < all[j].Name
	})
	var opts []prompt.Option
	for _, fw := range all {
		if keep == nil || keep(fw) {
			opts = append(opts, prompt.Option{Label: firewallOptionLabel(fw), Value: fw.Name})
		}
	}
	return opts, nil
}

// firewallArg fills in a missing <name> of firewall get, update and delete
// in the interactive flow with a rule of the project; none is nothing to
// do. With the argument given, it is returned.
func firewallArg(ctx context.Context, rt *app.Runtime, c *client, profile string, args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	if !rt.Interactive() {
		return "", app.UsageErrf("<name> is required")
	}
	opts, err := firewallOptions(ctx, c, nil)
	if err != nil {
		return "", err
	}
	return rt.Choose(app.Choice{Title: "Firewall rule", Options: opts, Arg: "<name>", What: "firewall rule in gcp/" + profile})
}

// askFirewallName asks the name of a new rule, checked as it is typed
// against the name rules and the rules of the project.
func askFirewallName(ctx context.Context, rt *app.Runtime, c *client) (string, error) {
	return rt.AskInput("<name>", "Name of the new firewall rule", "", func(s string) error {
		s = strings.TrimSpace(s)
		if err := checkFirewallName(s); err != nil {
			return err
		}
		fw, err := c.findFirewall(ctx, s)
		if err != nil {
			return err
		}
		if fw != nil {
			return fmt.Errorf("firewall rule %s already exists (network %s): use ensure or update to change it", s, lastSegment(fw.Network))
		}
		return nil
	})
}

// commonAllows are the --allow values offered by askAllow.
var commonAllows = []prompt.Option{
	{Label: "tcp:22  (SSH)", Value: "tcp:22"},
	{Label: "tcp:80  (HTTP)", Value: "tcp:80"},
	{Label: "tcp:443  (HTTPS)", Value: "tcp:443"},
	{Label: "tcp:3389  (RDP)", Value: "tcp:3389"},
	{Label: "icmp  (ping)", Value: "icmp"},
	{Label: "all  (every protocol and port)", Value: "all"},
}

// chooseWithOther is a multiple choice among opts plus "Other (typed)...",
// whose value is asked (otherTitle) and checked with validate. optional
// lets the user tick nothing (the result is then empty); otherwise ticking
// nothing is "nothing to do".
func chooseWithOther(rt *app.Runtime, title, arg string, opts []prompt.Option, otherLabel, otherTitle string, validate func(string) error, optional bool) ([]string, error) {
	opts = append(append([]prompt.Option(nil), opts...), prompt.Option{Label: otherLabel, Value: otherValue})
	var vs []string
	var err error
	if optional {
		if !rt.Interactive() {
			return nil, app.UsageErrf("%s is required", arg)
		}
		vs, err = rt.Pick().MultiSelect(title, opts)
	} else {
		vs, err = rt.ChooseMany(app.Choice{Title: title, Options: opts, Arg: arg, Required: true})
	}
	if err != nil {
		return nil, err
	}
	if i := slices.Index(vs, otherValue); i >= 0 {
		v, err := rt.AskInput(arg, otherTitle, "", func(s string) error { return validate(strings.TrimSpace(s)) })
		if err != nil {
			return nil, err
		}
		vs[i] = v
	}
	return vs, nil
}

// askAllow asks --allow values: the common ones (multiple choice, none
// preselected; those in have left out) and "Other (typed)...", one value
// checked as it is typed. With have (an existing rule) ticking nothing
// keeps the rule's protocols.
func askAllow(rt *app.Runtime, title string, have []string) ([]string, error) {
	var opts []prompt.Option
	for _, o := range commonAllows {
		if !slices.Contains(have, o.Value) {
			opts = append(opts, o)
		}
	}
	return chooseWithOther(rt, title, "--allow", opts, "Other (typed, such as udp:53 or tcp:8000-8100)...",
		"Protocol and ports (tcp|udp|icmp|all, optionally :<ports>)", func(s string) error {
			_, err := parseAllow([]string{s})
			return err
		}, have != nil)
}

// remoteLogin reports allow values that open SSH or RDP.
func remoteLogin(allow []string) bool {
	for _, a := range allow {
		a = strings.ToLower(a)
		if a == "all" || a == "tcp" || strings.Contains(a, "22") || strings.Contains(a, "3389") || strings.Contains(a, "ssh") || strings.Contains(a, "rdp") {
			return true
		}
	}
	return false
}

// askRanges asks the --source-range (ingress) or --destination-range
// (egress) values of a rule on network: the primary and secondary ranges
// of the network's subnetworks, the IAP TCP forwarding range for an SSH or
// RDP rule (ingress), 0.0.0.0/0 (never preselected) and "Other (typed)...",
// a CIDR checked as it is typed. have (the ranges of an existing rule) are
// left out, and with have ticking nothing keeps them.
func askRanges(ctx context.Context, rt *app.Runtime, c *client, title, network, direction string, allow, have []string) ([]string, error) {
	flag := "source-range"
	if direction == dirEgress {
		flag = "destination-range"
	}
	subs, err := c.listSubnets(ctx, "", network)
	if err != nil {
		return nil, err
	}
	sort.Slice(subs, func(i, j int) bool { return subs[i].Name < subs[j].Name })
	var opts []prompt.Option
	seen := map[string]bool{}
	for _, h := range have {
		seen[h] = true
	}
	add := func(cidr, label string) {
		if cidr != "" && !seen[cidr] {
			seen[cidr] = true
			opts = append(opts, prompt.Option{Label: joinLabel(cidr, label), Value: cidr})
		}
	}
	for _, s := range subs {
		region := s.Region
		if region == "" {
			region = regionFromURL(s.SelfLink)
		}
		add(s.IpCidrRange, fmt.Sprintf("subnet %s (%s)", s.Name, lastSegment(region)))
		for _, r := range s.SecondaryIpRanges {
			add(r.IpCidrRange, fmt.Sprintf("secondary range %s of subnet %s", r.RangeName, s.Name))
		}
	}
	if direction != dirEgress && remoteLogin(allow) {
		add(iapRange, "(IAP TCP forwarding)")
	}
	add("0.0.0.0/0", "(anywhere)")
	return chooseWithOther(rt, title, "--"+flag, opts, "Other (typed CIDR)...", "CIDR (such as 203.0.113.0/24)", func(s string) error {
		_, err := parseCIDRs(flag, []string{s})
		return err
	}, have != nil)
}

// allowValues are the allowed protocols of a rule as --allow values.
func allowValues(list []*compute.FirewallAllowed) []string {
	var out []string
	for _, a := range list {
		v := a.IPProtocol
		if len(a.Ports) > 0 {
			v += ":" + strings.Join(a.Ports, ",")
		}
		out = append(out, v)
	}
	return out
}

// askRule fills in, in the interactive flow, the --allow and range flags
// of a rule that the user left out. For a new rule (have nil) both are
// required. For the existing rule ensure adds to, the protocols and ranges
// to add are asked, the current ones shown, and ticking nothing keeps
// them.
func askRule(ctx context.Context, rt *app.Runtime, c *client, rf *ruleFlags, network string, have *compute.Firewall) error {
	if !rt.Interactive() {
		return nil
	}
	dir, err := parseDirection(rf.direction)
	if err != nil {
		return err
	}
	var haveAllow, haveRanges []string
	allowTitle, rangeWord := "Allowed protocols and ports", "Source ranges"
	if have != nil {
		dir = have.Direction
		rf.direction = strings.ToLower(dir)
		haveAllow, haveRanges = allowValues(have.Allowed), have.SourceRanges
		if dir == dirEgress {
			haveRanges = have.DestinationRanges
		}
		if haveAllow == nil {
			haveAllow = []string{}
		}
		if haveRanges == nil {
			haveRanges = []string{}
		}
		allowTitle = "Protocols to add to rule " + have.Name + " (now " + strings.Join(haveAllow, " ") + "; none: keep)"
	}
	if dir == dirEgress {
		rangeWord = "Destination ranges"
	}
	if len(rf.allow) == 0 {
		if rf.allow, err = askAllow(rt, allowTitle, haveAllow); err != nil {
			return err
		}
		if len(rf.allow) == 0 {
			rf.allow = haveAllow
		}
	}
	ranges := &rf.sourceRanges
	if dir == dirEgress {
		ranges = &rf.destRanges
	}
	if len(rf.sourceRanges) > 0 || len(rf.destRanges) > 0 {
		return nil
	}
	title := rangeWord + " of the rule on network " + network
	if have != nil {
		title = rangeWord + " to add to rule " + have.Name + " (now " + strings.Join(haveRanges, ", ") + "; none: keep)"
	}
	if *ranges, err = askRanges(ctx, rt, c, title, network, dir, rf.allow, haveRanges); err != nil {
		return err
	}
	if len(*ranges) == 0 {
		*ranges = haveRanges
	}
	return nil
}

// pickHealthCheckRegion asks, in the interactive flow, the --region of
// firewall ensure --preset lb-health-check: the regions where network has
// subnetworks, the only one preselected.
func pickHealthCheckRegion(ctx context.Context, rt *app.Runtime, c *client, network string) (string, error) {
	subs, err := c.listSubnets(ctx, "", network)
	if err != nil {
		return "", err
	}
	count := map[string]int{}
	for _, s := range subs {
		r := s.Region
		if r == "" {
			r = regionFromURL(s.SelfLink)
		}
		count[lastSegment(r)]++
	}
	var regions []string
	for r := range count {
		regions = append(regions, r)
	}
	sort.Strings(regions)
	var opts []prompt.Option
	for _, r := range regions {
		opts = append(opts, prompt.Option{Label: joinLabel(r, plural(count[r], "subnet")), Value: r})
	}
	def := ""
	if len(opts) == 1 {
		def = opts[0].Value
	}
	return rt.Choose(app.Choice{Title: "Region whose subnetworks the health check rule allows", Options: opts, Default: def,
		Arg: "--region", Required: true, What: "region with a subnetwork of network " + network,
		Missing: func() error {
			return app.UsageErrf("--region is required with --preset %s (the region whose subnetworks the rule allows; or set defaults.gcp.zone)", lbHealthCheckPreset)
		}})
}

// pickEnsureRule asks, in the interactive flow, which rule firewall ensure
// works on when neither <name> nor --preset is given: the health check
// rule of --preset lb-health-check, an existing rule (enabled allow rules
// without service account targets: ensure refuses the others), or a new
// rule, whose name is asked. It returns the preset or the name.
func pickEnsureRule(ctx context.Context, rt *app.Runtime) (preset, name string, err error) {
	c, _, err := openGCP(ctx, rt)
	if err != nil {
		return "", "", err
	}
	opts, err := firewallOptions(ctx, c, func(fw *compute.Firewall) bool {
		return !fw.Disabled && len(fw.Denied) == 0 && len(fw.TargetServiceAccounts) == 0
	})
	if err != nil {
		return "", "", err
	}
	const presetValue = "\x00preset"
	opts = append([]prompt.Option{{Label: "Health check rule for load balancers (--preset " + lbHealthCheckPreset + ")", Value: presetValue}}, opts...)
	v, err := rt.Choose(app.Choice{Title: "Firewall rule to ensure", Options: opts, Arg: "<name>",
		CreateLabel: "Create a new rule...", Create: func() (string, error) { return askFirewallName(ctx, rt, c) }})
	if err != nil {
		return "", "", err
	}
	if v == presetValue {
		return lbHealthCheckPreset, "", nil
	}
	return "", v, nil
}
