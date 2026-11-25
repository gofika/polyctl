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
// 10.0.0.0/8  tags ssh  project p1  disabled"; a rule without ranges shows
// "-" in their cell. The project cell is there only with project (a list
// of the rules of several projects).
func firewallOptionLabel(fw *compute.Firewall, project string) string {
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
	cells := []string{fw.Name, lastSegment(fw.Network), fw.Direction, "prio " + strconv.FormatInt(fw.Priority, 10), ruleLabel(fw),
		strings.Join(ranges, ","), tags}
	if project != "" {
		cells = append(cells, "project "+project)
	}
	return prompt.Cells(append(cells, dis)...)
}

// firewallOptions lists the rules of the project as options, sorted by
// network and name; keep (nil: all) keeps the usable ones. withProject
// adds the project to the labels.
func firewallOptions(ctx context.Context, c *client, withProject bool, keep func(*compute.Firewall) bool) ([]prompt.Option, error) {
	project := ""
	if withProject {
		project = c.project
	}
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
			opts = append(opts, prompt.Option{Label: firewallOptionLabel(fw, project), Value: fw.Name})
		}
	}
	return opts, nil
}

// firewallArg settles the rule of firewall get, update and delete and the
// client of its project. A <name> is looked for in every selected project
// (locateProject: a pick in the interactive flow and exit code 5 otherwise
// when several hold it). Without it the interactive flow offers the rules
// of those projects; none is nothing to do.
func firewallArg(ctx context.Context, rt *app.Runtime, c *client, profile string, args []string) (*client, string, error) {
	if len(args) > 0 {
		name := args[0]
		pc, err := locateProject(ctx, rt, c, profile, "firewall rule", name, func(ctx context.Context, pc *client) (bool, error) {
			_, err := pc.getFirewall(ctx, name)
			return notFoundIs(err)
		})
		return pc, name, err
	}
	if !rt.Interactive() {
		return nil, "", app.UsageErrf("<name> is required")
	}
	var opts []prompt.Option
	var clients []*client
	several := len(c.listProjects()) > 1
	err := c.forProjects(ctx, func(pc *client) error {
		po, err := firewallOptions(ctx, pc, several, nil)
		for _, o := range po {
			// The value names the project too: two projects may hold a
			// rule of one name.
			if several {
				o.Value = strconv.Itoa(len(clients)) + "/" + o.Value
			}
			opts = append(opts, o)
		}
		clients = append(clients, pc)
		return err
	})
	if err != nil {
		return nil, "", err
	}
	v, err := rt.Choose(app.Choice{Title: "Firewall rule", Options: opts, Arg: "<name>", What: "firewall rule in gcp/" + profile})
	if err != nil {
		return nil, "", err
	}
	if !several {
		return clients[0], v, nil
	}
	i, name, _ := strings.Cut(v, "/")
	n, _ := strconv.Atoi(i)
	return clients[n], name, nil
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
	{Label: "tcp:22  SSH", Value: "tcp:22"},
	{Label: "tcp:80  HTTP", Value: "tcp:80"},
	{Label: "tcp:443  HTTPS", Value: "tcp:443"},
	{Label: "tcp:3389  RDP", Value: "tcp:3389"},
	{Label: "icmp  ping", Value: "icmp"},
	{Label: "all  every protocol and port", Value: "all"},
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
	// The cells: the range, what it is, its region.
	add := func(cidr, what, region string) {
		if cidr != "" && !seen[cidr] {
			seen[cidr] = true
			opts = append(opts, prompt.Option{Label: prompt.Cells(cidr, what, region), Value: cidr})
		}
	}
	for _, s := range subs {
		region := s.Region
		if region == "" {
			region = regionFromURL(s.SelfLink)
		}
		add(s.IpCidrRange, "subnet "+s.Name, lastSegment(region))
		for _, r := range s.SecondaryIpRanges {
			add(r.IpCidrRange, fmt.Sprintf("secondary range %s of subnet %s", r.RangeName, s.Name), lastSegment(region))
		}
	}
	if direction != dirEgress && remoteLogin(allow) {
		add(iapRange, "IAP TCP forwarding", "")
	}
	add("0.0.0.0/0", "anywhere", "")
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
		opts = append(opts, prompt.Option{Label: prompt.Cells(r, plural(count[r], "subnet")), Value: r})
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
	opts, err := firewallOptions(ctx, c, false, func(fw *compute.Firewall) bool {
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

// askFirewallUpdate asks, in the interactive flow, what firewall update
// changes when no field flag was given, and its new value: the allowed
// protocols (not for a deny rule; the ticked ones replace the current
// ones), ranges to add (source ranges of an ingress rule, destination
// ranges of an egress rule, the current ones left out), the target tags,
// the description or the priority, each shown with its current value. It
// fills in rf (and adds) and returns the flag answered.
func askFirewallUpdate(ctx context.Context, rt *app.Runtime, c *client, fw *compute.Firewall, rf *ruleFlags, adds *[]string) (string, error) {
	have := allowValues(fw.Allowed)
	ranges, rangeFlag, rangeWord := fw.SourceRanges, "add-source-range", "Source ranges"
	if fw.Direction == dirEgress {
		ranges, rangeFlag, rangeWord = fw.DestinationRanges, "destination-range", "Destination ranges"
	}
	var opts []prompt.Option
	if len(fw.Denied) == 0 {
		opts = append(opts, prompt.Option{Label: prompt.Cells("Allowed protocols and ports", "now "+joinOrNone(have, " ")), Value: "allow"})
	}
	opts = append(opts,
		prompt.Option{Label: prompt.Cells("Add "+strings.ToLower(rangeWord), "now "+joinOrNone(ranges, ", ")), Value: rangeFlag},
		prompt.Option{Label: prompt.Cells("Target tags", "now "+joinOrNone(fw.TargetTags, ", ")), Value: "target-tag"},
		prompt.Option{Label: prompt.Cells("Description", "now "+orNone(fw.Description)), Value: "description"},
		prompt.Option{Label: prompt.Cells("Priority", "now "+strconv.FormatInt(fw.Priority, 10)), Value: "priority"},
	)
	key, err := rt.Pick().Select("What to change on rule "+fw.Name, opts, "")
	if err != nil {
		return "", err
	}
	network := lastSegment(fw.Network)
	switch key {
	case "allow":
		rf.allow, err = askAllow(rt, "Allowed protocols and ports of rule "+fw.Name+" (they replace "+joinOrNone(have, " ")+")", nil)
	case "add-source-range", "destination-range":
		var added []string
		added, err = askRanges(ctx, rt, c, rangeWord+" to add to rule "+fw.Name+" (now "+joinOrNone(ranges, ", ")+")", network, fw.Direction, have, ranges)
		if err == nil && len(added) == 0 {
			err = app.NothingToDof("no range was selected")
		}
		if key == "add-source-range" {
			*adds = added
		} else {
			rf.destRanges = append(append([]string(nil), ranges...), added...)
		}
	case "target-tag":
		var v string
		v, err = rt.AskInput("--target-tag", "Target tags of rule "+fw.Name+", separated by commas", strings.Join(fw.TargetTags, ","), func(s string) error {
			if len(splitTags(s)) == 0 {
				return fmt.Errorf("type at least one tag (--target-tag \"\" makes the rule apply to every instance)")
			}
			return nil
		})
		rf.targetTags = splitTags(v)
	case "description":
		rf.description, err = rt.AskInput("--description", "Description of rule "+fw.Name, fw.Description, nil)
	case "priority":
		var v string
		v, err = rt.AskInput("--priority", "Priority of rule "+fw.Name+" (0-65535, lower numbers win)", strconv.FormatInt(fw.Priority, 10), func(s string) error {
			p, err := strconv.ParseInt(strings.TrimSpace(s), 10, 64)
			if err != nil || p < 0 || p > 65535 {
				return fmt.Errorf("a whole number from 0 to 65535 is required")
			}
			return nil
		})
		if err == nil {
			rf.priority, _ = strconv.ParseInt(v, 10, 64)
		}
	}
	return key, err
}

// splitTags splits typed target tags at commas and spaces.
func splitTags(s string) []string {
	return dedupe(strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' }))
}

// joinOrNone joins values with sep, or says "none".
func joinOrNone(values []string, sep string) string {
	if len(values) == 0 {
		return "none"
	}
	return strings.Join(values, sep)
}
