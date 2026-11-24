package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// The ensure of a firewall rule only ever adds: ranges, target tags and
// allowed protocols missing from an existing rule are added to what it
// has (a union), and nothing it has is removed. A rule on another network,
// with the other direction, disabled, or a deny rule is left alone and
// reported (exit code 1): polyctl does not move, turn or enable a rule
// somebody set up that way.

// lbHealthCheckPreset is the preset of `firewall ensure --preset`.
const lbHealthCheckPreset = "lb-health-check"

// lbHealthCheckRanges are the source ranges of Google Cloud load balancer
// health checks (published by Google, not configurable).
var lbHealthCheckRanges = []string{"35.191.0.0/16", "130.211.0.0/22"}

// defaultLBNetworkTag is the network tag the health check rule targets
// when defaults.gcp.lb_network_tag is not set.
const defaultLBNetworkTag = "lb-health-check"

// lbFirewallDescription is the description of a health check rule.
func lbFirewallDescription(network string) string {
	return "Allow health check and proxy traffic for load balancer on " + network
}

// fitName shortens a resource name longer than 63 characters: it is cut
// and ends with "-" and a 6 character hash of the full name, so that two
// long names stay distinct and the same name always gives the same result.
func fitName(name string) string {
	if len(name) <= 63 {
		return name
	}
	sum := sha256.Sum256([]byte(name))
	base := strings.TrimRight(name[:63-7], "-")
	return base + "-" + hex.EncodeToString(sum[:])[:6]
}

// isForbidden reports a 403 that is a missing permission: not a disabled
// API, not a quota.
func isForbidden(err error) bool {
	var ge *googleapi.Error
	if !errors.As(err, &ge) || ge.Code != http.StatusForbidden {
		return false
	}
	reason := googleReason(err)
	return reason != "accessNotConfigured" && !isCapacity(reason) && !isCapacityMessage(ge.Message) &&
		!strings.Contains(ge.Message, "has not been used") && !strings.Contains(ge.Message, "is disabled")
}

// ------------------------------------------------------------ allowed

// protocolRanges returns the port ranges have allows for protocol, and
// whether an entry of it allows every port.
func protocolRanges(have []*compute.FirewallAllowed, proto string) (ranges []platform.PortRange, every, found bool) {
	for _, h := range have {
		if !strings.EqualFold(h.IPProtocol, proto) {
			continue
		}
		found = true
		if len(h.Ports) == 0 {
			every = true
			continue
		}
		rs, err := platform.ParsePortSpec(strings.Join(h.Ports, ","))
		if err == nil {
			ranges = append(ranges, rs...)
		}
	}
	return ranges, every, found
}

// coversAllowed reports whether have allows everything want allows. With
// anyPort, any entry of the protocol is enough.
func coversAllowed(have []*compute.FirewallAllowed, want *compute.FirewallAllowed, anyPort bool) bool {
	ranges, every, found := protocolRanges(have, want.IPProtocol)
	switch {
	case every, found && anyPort:
		return true
	case !found, len(want.Ports) == 0:
		return false
	}
	wantRanges, err := platform.ParsePortSpec(strings.Join(want.Ports, ","))
	if err != nil {
		return false
	}
	for _, w := range wantRanges {
		if !slices.ContainsFunc(ranges, func(r platform.PortRange) bool { return r.Contains(w) }) {
			return false
		}
	}
	return true
}

// mergeAllowed returns have with the entries of add merged in: ports are
// added to the entry of their protocol, and an entry without ports makes
// its protocol allow every port. have is not modified.
func mergeAllowed(have, add []*compute.FirewallAllowed) []*compute.FirewallAllowed {
	out := make([]*compute.FirewallAllowed, 0, len(have)+len(add))
	for _, h := range have {
		cp := *h
		cp.Ports = slices.Clone(h.Ports)
		out = append(out, &cp)
	}
	for _, a := range add {
		i := slices.IndexFunc(out, func(e *compute.FirewallAllowed) bool { return strings.EqualFold(e.IPProtocol, a.IPProtocol) })
		if i < 0 {
			cp := *a
			cp.Ports = slices.Clone(a.Ports)
			out = append(out, &cp)
			continue
		}
		e := out[i]
		if len(a.Ports) == 0 || len(e.Ports) == 0 {
			e.Ports = nil
			continue
		}
		rs, err1 := platform.ParsePortSpec(strings.Join(e.Ports, ","))
		more, err2 := platform.ParsePortSpec(strings.Join(a.Ports, ","))
		if err1 != nil || err2 != nil {
			for _, p := range a.Ports {
				if !slices.Contains(e.Ports, p) {
					e.Ports = append(e.Ports, p)
				}
			}
			continue
		}
		e.Ports = portStrings(append(rs, more...))
	}
	return out
}

// ------------------------------------------------------------ ensure

// firewallEnsureSpec is the rule an ensure converges to.
type firewallEnsureSpec struct {
	Name      string
	Network   string
	Direction string
	Allowed   []*compute.FirewallAllowed
	// AnyPort: an existing entry of a protocol satisfies the entry of
	// Allowed of that protocol whatever its ports (the preset without
	// explicit ports only needs the rule to allow tcp).
	AnyPort bool
	// Ranges are the source ranges of an ingress rule, the destination
	// ranges of an egress one.
	Ranges     []string
	TargetTags []string
	// Priority is set on creation; an existing rule gets it only with
	// SetPriority.
	Priority    int64
	SetPriority bool
	// Description is set on creation; an existing rule gets it only with
	// SetDescription.
	Description    string
	SetDescription bool
	Wait           bool
	Timeout        time.Duration
	// SkipForbidden turns a missing permission into a skipped step (the
	// load balancer ensure goes on without the rule) instead of an error.
	SkipForbidden bool
}

func (s *firewallEnsureSpec) rangeWord() string {
	if s.Direction == dirEgress {
		return "destination range"
	}
	return "source range"
}

// summary renders a rule as the report shows it ("tcp, 5 source ranges,
// tag lb-health-check").
func (s *firewallEnsureSpec) summary(allowed []*compute.FirewallAllowed, ranges, tags []string) string {
	parts := []string{allowedLabel(allowed), plural(len(ranges), s.rangeWord())}
	if len(tags) > 0 {
		parts = append(parts, "tag "+strings.Join(tags, ","))
	} else {
		parts = append(parts, "every instance")
	}
	return strings.Join(parts, ", ")
}

// skipped is the step of a rule polyctl may not manage.
func (s *firewallEnsureSpec) skipped(err error) platform.Step {
	return platform.Step{Resource: "firewall/" + s.Name, Action: platform.Skipped,
		Desc: "no permission to manage firewall rules (compute.firewalls.*); create the rule by hand or the health checks fail: " + err.Error()}
}

// ensureFirewallStep observes the rule (read-only, also in a dry run) and
// returns the step that creates it, adds what it lacks, or reports it
// unchanged. A rule that cannot be converged without moving, turning or
// enabling it is an error.
func (c *client) ensureFirewallStep(ctx context.Context, s firewallEnsureSpec) (platform.Step, error) {
	res := "firewall/" + s.Name
	fw, err := c.findFirewall(ctx, s.Name)
	if err != nil {
		if s.SkipForbidden && isForbidden(err) {
			return s.skipped(err), nil
		}
		return platform.Step{}, err
	}
	apply := func(desc string, write func(ctx context.Context) error) func(ctx context.Context) (platform.Change, error) {
		return func(ctx context.Context) (platform.Change, error) {
			wctx, cancel, conv := deadline(ctx, s.Timeout, res, "done")
			defer cancel()
			if err := write(wctx); err != nil {
				if s.SkipForbidden && isForbidden(err) {
					st := s.skipped(err)
					return platform.Change{Action: platform.Skipped, Detail: st.Desc}, nil
				}
				return platform.Change{}, conv(err)
			}
			if !s.Wait {
				return platform.Change{Detail: desc + " (requested)"}, nil
			}
			return platform.Change{}, nil
		}
	}
	ranges, _ := unionRanges(nil, s.Ranges)
	if fw == nil {
		spec := &ruleSpec{direction: s.Direction, allowed: s.Allowed, targetTags: s.TargetTags}
		if s.Direction == dirEgress {
			spec.dests = ranges
		} else {
			spec.sources = ranges
		}
		body := c.firewallBody(s.Name, s.Network, spec, s.Priority, s.Description)
		desc := s.summary(s.Allowed, ranges, s.TargetTags)
		return platform.Step{Resource: res, Action: platform.Created, Desc: desc, Attrs: rangeAttrs(s.Direction, ranges),
			Apply: apply(desc, func(ctx context.Context) error { return c.insertFirewall(ctx, body, s.Wait) })}, nil
	}
	switch {
	case lastSegment(fw.Network) != s.Network:
		return platform.Step{}, fmt.Errorf("firewall rule %s exists on network %s, not %s: polyctl does not move a rule to another network; delete it, or pass another rule name", s.Name, lastSegment(fw.Network), s.Network)
	case fw.Direction != s.Direction:
		return platform.Step{}, fmt.Errorf("firewall rule %s is an %s rule, not %s: polyctl does not change the direction of a rule; fix or delete it by hand", s.Name, fw.Direction, s.Direction)
	case fw.Disabled:
		return platform.Step{}, fmt.Errorf("firewall rule %s is disabled: polyctl does not enable a rule somebody disabled; enable it by hand (or delete it) and run ensure again", s.Name)
	case len(fw.Denied) > 0:
		return platform.Step{}, fmt.Errorf("firewall rule %s is a deny rule: polyctl does not turn it into an allow rule; delete it, or pass another rule name", s.Name)
	}
	have := fw.SourceRanges
	if s.Direction == dirEgress {
		have = fw.DestinationRanges
	}
	patch := &compute.Firewall{}
	var details []string
	union, added := unionRanges(have, ranges)
	if len(added) > 0 {
		if s.Direction == dirEgress {
			patch.DestinationRanges = union
		} else {
			patch.SourceRanges = union
		}
		details = append(details, fmt.Sprintf("+%s (now %s)", strings.Join(added, ", +"), plural(len(union), "range")))
	}
	// A rule without target tags or target service accounts already applies
	// to every instance of the network: adding a tag would narrow it to the
	// tagged instances, a removal in effect, so it is left as it is. A rule
	// that targets service accounts cannot take tags as well.
	everyInstance := len(fw.TargetTags) == 0 && len(fw.TargetServiceAccounts) == 0
	if len(fw.TargetServiceAccounts) > 0 && len(s.TargetTags) > 0 {
		return platform.Step{}, fmt.Errorf("firewall rule %s targets service accounts, not network tags: polyctl does not change its targets; fix it by hand, or pass another rule name", s.Name)
	}
	tags, addedTags := slices.Clone(fw.TargetTags), []string(nil)
	for _, t := range s.TargetTags {
		if !everyInstance && !slices.Contains(tags, t) {
			tags = append(tags, t)
			addedTags = append(addedTags, t)
		}
	}
	if len(addedTags) > 0 {
		patch.TargetTags = tags
		details = append(details, "+tag "+strings.Join(addedTags, ", +tag "))
	}
	var missing []*compute.FirewallAllowed
	for _, a := range s.Allowed {
		if !coversAllowed(fw.Allowed, a, s.AnyPort) {
			missing = append(missing, a)
		}
	}
	allowed := fw.Allowed
	if len(missing) > 0 {
		allowed = mergeAllowed(fw.Allowed, missing)
		patch.Allowed = allowed
		details = append(details, "+"+strings.ReplaceAll(allowedLabel(missing), " ", ", +"))
	}
	if s.SetPriority && fw.Priority != s.Priority {
		patch.Priority = s.Priority
		patch.ForceSendFields = append(patch.ForceSendFields, "Priority")
		details = append(details, fmt.Sprintf("priority %d -> %d", fw.Priority, s.Priority))
	}
	if s.SetDescription && fw.Description != s.Description {
		patch.Description = s.Description
		patch.ForceSendFields = append(patch.ForceSendFields, "Description")
		details = append(details, "description")
	}
	if len(details) == 0 {
		return platform.Step{Resource: res, Action: platform.Unchanged, Desc: s.summary(fw.Allowed, have, fw.TargetTags),
			Attrs: rangeAttrs(s.Direction, union)}, nil
	}
	desc := strings.Join(details, "; ")
	return platform.Step{Resource: res, Action: platform.Updated, Desc: desc, Attrs: rangeAttrs(s.Direction, union),
		Apply: apply(desc, func(ctx context.Context) error { return c.patchFirewall(ctx, s.Name, patch, s.Wait) })}, nil
}

// rangeAttrs carries the final ranges of a rule in the report.
func rangeAttrs(direction string, ranges []string) map[string]string {
	if direction == dirEgress {
		return map[string]string{"destination_ranges": strings.Join(ranges, ",")}
	}
	return map[string]string{"source_ranges": strings.Join(ranges, ",")}
}

// LBFirewallOptions configure EnsureLBFirewall.
type LBFirewallOptions struct {
	// Network is the VPC network of the load balancer backends; Region
	// the region whose subnetworks may send health check and proxy
	// traffic (subnetworks are regional, so the rule widens as load
	// balancers in other regions run the ensure).
	Network string
	Region  string
	// Name is the rule name (default allow-lb-health-check-{network},
	// shortened with a hash when longer than 63 characters).
	Name string
	// TargetTag is the network tag the rule targets (default
	// lb-health-check).
	TargetTag string
	// Ports are the tcp ports to allow (default: every tcp port).
	Ports []string
	// Allowed replaces the allowed protocols entirely (--allow).
	Allowed []*compute.FirewallAllowed
	// Description is set on a rule created now (default
	// "Allow health check and proxy traffic for load balancer on {network}").
	Description string
	Wait        bool
	Timeout     time.Duration
	// SkipForbidden makes a missing permission a skipped step instead of
	// an error: a load balancer ensure goes on (a shared VPC host project
	// may manage the rules).
	SkipForbidden bool
}

// buildLBFirewallSourceRanges returns the source ranges a health check
// rule needs, sorted and without repeats: the health check ranges, the
// primary and secondary ranges of the network's subnetworks in the region,
// and its proxy-only subnetworks (already among the subnetworks; kept as a
// source of their own).
func buildLBFirewallSourceRanges(subnets []*compute.Subnetwork) []string {
	all := slices.Concat(lbHealthCheckRanges, vpcRanges(subnets), proxyOnlySubnets(subnets))
	out, _ := unionRanges(nil, all)
	return out
}

// EnsureLBFirewall observes the load balancer health check rule of a
// network and returns the step that creates it, adds the source ranges,
// target tag or tcp entry it lacks (never removing anything), or reports it
// unchanged. The observation runs at once (in a dry run too); the step
// writes when the plan runs. A rule that is disabled or not ingress is an
// error (exit code 1), left for a person to fix.
func (c *client) EnsureLBFirewall(ctx context.Context, o LBFirewallOptions) (platform.Step, error) {
	if o.Name == "" {
		o.Name = fitName("allow-lb-health-check-" + o.Network)
	}
	if o.TargetTag == "" {
		o.TargetTag = defaultLBNetworkTag
	}
	if o.Description == "" {
		o.Description = lbFirewallDescription(o.Network)
	}
	spec := firewallEnsureSpec{Name: o.Name, Network: o.Network, Direction: dirIngress, Priority: defaultFirewallPriority,
		TargetTags: []string{o.TargetTag}, Description: o.Description, Wait: o.Wait, Timeout: o.Timeout, SkipForbidden: o.SkipForbidden}
	switch {
	case len(o.Allowed) > 0:
		spec.Allowed = o.Allowed
	case len(o.Ports) > 0:
		spec.Allowed = []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: o.Ports}}
	default:
		spec.Allowed = []*compute.FirewallAllowed{{IPProtocol: "tcp"}}
		spec.AnyPort = true
	}
	subnets, err := c.subnetworksOf(ctx, o.Region, o.Network)
	if err != nil {
		if o.SkipForbidden && isForbidden(err) {
			return spec.skipped(err), nil
		}
		return platform.Step{}, err
	}
	spec.Ranges = buildLBFirewallSourceRanges(subnets)
	return c.ensureFirewallStep(ctx, spec)
}

// ------------------------------------------------------------ instance tag

// setInstanceTags replaces the network tags of an instance; fingerprint
// must be the one of the tags as read.
func (c *client) setInstanceTags(ctx context.Context, zone, name string, items []string, fingerprint string, wait bool) error {
	op, err := c.compute.Instances.SetTags(c.project, zone, name, &compute.Tags{Items: items, Fingerprint: fingerprint}).Context(ctx).Do()
	if err != nil {
		return err
	}
	if !wait {
		return opError(op)
	}
	return c.waitZoneOp(ctx, zone, op)
}

// EnsureInstanceTag returns the step that adds a network tag to an
// instance (any status, TERMINATED included). Tags are replaced as a
// whole, so the existing ones are always sent along, with the fingerprint
// of the tags as read; a stale fingerprint (the tags changed in between)
// is re-read and retried once. stored is called with the instance read
// after the change.
func (c *client) EnsureInstanceTag(zone string, in *compute.Instance, tag string, wait bool, timeout time.Duration, stored func(*compute.Instance)) platform.Step {
	res := "instance/" + in.Name + "/tag"
	var have []string
	if in.Tags != nil {
		have = in.Tags.Items
	}
	if slices.Contains(have, tag) {
		return platform.Step{Resource: res, Action: platform.Unchanged, Desc: tag}
	}
	return platform.Step{Resource: res, Action: platform.Created, Desc: tag, Apply: func(ctx context.Context) (platform.Change, error) {
		wctx, cancel, conv := deadline(ctx, timeout, res, "done")
		defer cancel()
		cur := in
		for attempt := 0; ; attempt++ {
			var items []string
			fp := ""
			if cur.Tags != nil {
				items, fp = slices.Clone(cur.Tags.Items), cur.Tags.Fingerprint
			}
			if slices.Contains(items, tag) {
				return platform.Change{Action: platform.Unchanged, Detail: tag}, nil
			}
			err := c.setInstanceTags(wctx, zone, in.Name, append(items, tag), fp, wait)
			if err != nil && attempt == 0 && isFingerprintMismatch(err) {
				if cur, err = c.getInstance(wctx, zone, in.Name); err != nil {
					return platform.Change{}, conv(err)
				}
				continue
			}
			if err != nil {
				return platform.Change{}, conv(computeErr(err))
			}
			break
		}
		if stored != nil {
			if after, err := c.getInstance(ctx, zone, in.Name); err == nil {
				stored(after)
			}
		}
		if !wait {
			return platform.Change{Detail: tag + " (requested)"}, nil
		}
		return platform.Change{}, nil
	}}
}

// ------------------------------------------------------------ command

func firewallEnsureCmd(rt *app.Runtime) *cobra.Command {
	var rf ruleFlags
	var preset, region, instance, zone string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "ensure [<name>]",
		Short: "Create a firewall rule, or add to an existing one what it lacks",
		Long: `Make sure a VPC firewall rule allows what is asked: a missing rule is created;
an existing one gets the ranges, target tags and allowed protocols it lacks
added to the ones it has (a union: nothing is ever removed; use update
--source-range to replace ranges). --priority and --description change an
existing rule only when given. A rule on another network, with the other
direction, disabled, a deny rule or one targeting service accounts is exit
code 1: polyctl does not move, turn, enable or retarget it. A rule without
target tags applies to every instance and gets no tag.

Without --preset, <name>, --allow and --source-range (or, for --direction
egress, --destination-range) are required, as for create.

--preset lb-health-check makes the rule load balancer health checks and
proxies need: the name defaults to allow-lb-health-check-{network}
(naming.gcp_lb_firewall; shortened with a hash beyond 63 characters), the
source ranges are 35.191.0.0/16, 130.211.0.0/22 and every primary and
secondary range of the network's subnetworks in --region, proxy-only
subnetworks included, the target tag is lb-health-check
(defaults.gcp.lb_network_tag, or --target-tag), the rule allows every tcp
port (an existing rule that allows tcp on some ports is kept as it is;
--allow sets other protocols or ports), at priority 1000. --instance also
adds the target tag to that instance (found like instance get finds it; the
account holding it is used, and its network and region are the defaults of
--network and --region). Without --instance, --region defaults to the
region of defaults.gcp.zone. Run it again for each region the network's load
balancers use.

On a terminal, without <name> and --preset a pick offers the health check
rule of the preset, the rules of the project and "Create a new rule..." (its
name checked as it is typed); then what the rule lacks is asked: the
allowed protocols and the ranges of a new rule (common protocols, the
ranges of the network's subnetworks, the IAP range for SSH and RDP,
0.0.0.0/0 never preselected, or typed), the protocols to add to an
existing one. The preset without a region asks for one of the regions
where the network has subnetworks.

The command waits for each operation (--timeout, 10m); --no-wait only
submits them.`,
		Example: `  polyctl gcp compute firewall ensure --preset lb-health-check --network default --region us-central1 --instance web-1 --dry-run
  polyctl gcp compute firewall ensure allow-ssh-internal --network default --allow tcp:22 --source-range 10.0.0.0/8 --target-tag ssh-internal`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			fl := cmd.Flags()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
				if err := checkFirewallName(name); err != nil {
					return err
				}
			}
			if name == "" && preset == "" && rt.Interactive() {
				if preset, name, err = pickEnsureRule(ctx, rt); err != nil {
					return err
				}
			}
			switch preset {
			case "":
				return runFirewallEnsure(cmd, rt, &rf, name, wait, timeout, region, instance, zone)
			case lbHealthCheckPreset:
			default:
				return app.UsageErrf("unknown --preset %q (the only preset is %s)", preset, lbHealthCheckPreset)
			}
			for _, f := range []string{"source-range", "destination-range", "direction", "priority"} {
				if fl.Changed(f) {
					return app.UsageErrf("--%s does not apply to --preset %s: the preset computes the ranges, is an ingress rule and has priority 1000", f, lbHealthCheckPreset)
				}
			}
			if zone != "" && instance == "" {
				return app.UsageErrf("--zone locates the --instance; pass --instance too")
			}
			if len(rf.targetTags) > 1 {
				return app.UsageErrf("--preset %s targets one network tag; pass --target-tag once", lbHealthCheckPreset)
			}
			var allowed []*compute.FirewallAllowed
			if fl.Changed("allow") {
				if allowed, err = parseAllow(rf.allow); err != nil {
					return err
				}
			}
			var c *client
			var profile string
			var located *locatedInstance
			if instance != "" {
				if located, err = resolveInstance(ctx, rt, instance, zone, false); err != nil {
					return err
				}
				c, profile = located.c, located.profile
				if def, perr := gcpProfile(rt); perr == nil && def != profile {
					rt.Infof("note: instance %s is in gcp/%s, not gcp/%s; the firewall rule is ensured in gcp/%s", located.name(), profile, def, profile)
				}
			} else if c, profile, err = openGCP(ctx, rt); err != nil {
				return err
			}
			network := rf.network
			if network == "" && located != nil && len(located.inst.NetworkInterfaces) > 0 {
				network = lastSegment(located.inst.NetworkInterfaces[0].Network)
			}
			if network, err = defaultNetwork(rt, profile, network); err != nil {
				return err
			}
			if located != nil {
				var nets []string
				for _, nic := range located.inst.NetworkInterfaces {
					nets = append(nets, lastSegment(nic.Network))
				}
				if !slices.Contains(nets, network) {
					return app.UsageErrf("instance %s is not attached to network %s (its networks: %s): the tag would not let health checks reach it", located.name(), network, strings.Join(nets, ", "))
				}
			}
			if region == "" && located != nil {
				region = located.region()
			}
			if region == "" {
				z, err := rt.Setting(profile, platform.GCP, "zone", "")
				if err != nil {
					return err
				}
				if z != "" {
					region = regionOf(z)
				}
			}
			if region == "" && rt.Interactive() {
				if region, err = pickHealthCheckRegion(ctx, rt, c, network); err != nil {
					return err
				}
			}
			if region == "" {
				return app.UsageErrf("--region is required with --preset %s (the region whose subnetworks the rule allows; or set defaults.gcp.zone)", lbHealthCheckPreset)
			}
			tag := ""
			if len(rf.targetTags) == 1 {
				tag = strings.TrimSpace(rf.targetTags[0])
				if tag == "" {
					return app.UsageErrf("--target-tag must not be empty")
				}
			}
			if tag, err = rt.Setting(profile, platform.GCP, "lb_network_tag", tag); err != nil {
				return err
			}
			if _, err := c.network(ctx, network); err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			rendered, err := rt.ResourceName("gcp_lb_firewall", name, map[string]string{"network": network, "region": region})
			if err != nil {
				return app.UsageErrf("%v", err)
			}
			name = fitName(rendered)
			if err := checkFirewallName(name); err != nil {
				return err
			}
			desc := ""
			if fl.Changed("description") {
				desc = rf.description
			}
			step, err := c.EnsureLBFirewall(ctx, LBFirewallOptions{Network: network, Region: region, Name: name, TargetTag: tag,
				Allowed: allowed, Description: desc, Wait: wait, Timeout: timeout})
			if err != nil {
				return err
			}
			var plan platform.Plan
			plan.Add(step)
			if located != nil {
				l := located
				plan.Add(c.EnsureInstanceTag(l.zone, l.inst, tag, wait, timeout, func(in *compute.Instance) { storeInstance(ctx, rt, l.profile, in) }))
			}
			return rt.Ensure(ctx, "gcp.compute.firewall.ensure", platform.Target{Platform: platform.GCP, Profile: profile, Region: region}, &plan)
		},
	}
	rf.register(cmd, true)
	fl := cmd.Flags()
	fl.StringVar(&preset, "preset", "", "lb-health-check: the rule load balancer health checks need (computed ranges, tag and protocol)")
	fl.StringVar(&region, "region", "", "with --preset: the region whose subnetworks the rule allows (default: the --instance's region, else that of defaults.gcp.zone)")
	fl.StringVar(&instance, "instance", "", "with --preset: also add the target tag to this instance (name or id)")
	fl.StringVar(&zone, "zone", "", "zone of the --instance (default: from the inventory)")
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}

// runFirewallEnsure is the ensure of a rule given in full (no preset).
func runFirewallEnsure(cmd *cobra.Command, rt *app.Runtime, rf *ruleFlags, name string, wait bool, timeout time.Duration, region, instance, zone string) error {
	ctx := cmd.Context()
	fl := cmd.Flags()
	if name == "" {
		return app.UsageErrf("the rule name is required without --preset: firewall ensure <name> --allow ... --source-range ...")
	}
	if region != "" || instance != "" || zone != "" {
		return app.UsageErrf("--region, --instance and --zone apply to --preset %s", lbHealthCheckPreset)
	}
	if !rt.Interactive() {
		// Refused before anything is read.
		if _, err := rf.parseRule(); err != nil {
			return err
		}
	}
	c, profile, err := openGCP(ctx, rt)
	if err != nil {
		return err
	}
	var have *compute.Firewall
	if rt.Interactive() {
		if have, err = c.findFirewall(ctx, name); err != nil {
			return err
		}
	}
	network := rf.network
	if network == "" && have != nil {
		network = lastSegment(have.Network)
	}
	if network, err = ruleNetwork(ctx, rt, c, profile, network); err != nil {
		return err
	}
	if err := askRule(ctx, rt, c, rf, network, have); err != nil {
		return err
	}
	spec, err := rf.parseRule()
	if err != nil {
		return err
	}
	if _, err := c.network(ctx, network); err != nil {
		return fmt.Errorf("%w (gcp/%s)", err, profile)
	}
	ranges := spec.sources
	if spec.direction == dirEgress {
		ranges = spec.dests
	}
	step, err := c.ensureFirewallStep(ctx, firewallEnsureSpec{Name: name, Network: network, Direction: spec.direction, Allowed: spec.allowed,
		Ranges: ranges, TargetTags: spec.targetTags, Priority: rf.priority, SetPriority: fl.Changed("priority"),
		Description: rf.description, SetDescription: fl.Changed("description"), Wait: wait, Timeout: timeout})
	if err != nil {
		return err
	}
	var plan platform.Plan
	plan.Add(step)
	return rt.Ensure(ctx, "gcp.compute.firewall.ensure", firewallTarget(profile), &plan)
}
