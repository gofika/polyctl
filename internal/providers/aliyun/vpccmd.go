package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Defaults of the network commands.
const (
	defaultVPCCIDR      = "172.16.0.0/12"
	defaultVSwitchMask  = 22
	vpcWaitTimeout      = 60 * time.Second
	shortWaitTimeout    = 30 * time.Second
	netNameMaxLength    = 128
	minVSwitchMask      = 16
	maxVSwitchMask      = 29
	vpcWaitInterval     = 2 * time.Second
	shortWaitInterval   = 2 * time.Second
	vswitchSkippedLater = "run ensure again once the VPC is Available"
	// statusNotFound is the status a wait reports while the resource it
	// awaits is not listed yet (a resource just created may lag).
	statusNotFound = "NotFound"
)

// defaultZones are the zone suffixes of vswitch ensure ({region}-b, -c).
var defaultZones = []string{"b", "c"}

// netWaitClock is the clock of the VPC, vSwitch and EIP waits (nil is the
// real clock; tests replace it).
var netWaitClock platform.Clock

func netClock() platform.Clock {
	if netWaitClock != nil {
		return netWaitClock
	}
	return platform.RealClock
}

// newVPCCmd is `aliyun vpc`: VPCs and vSwitches.
func newVPCCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "vpc",
		Short: "Virtual Private Cloud: VPCs and vSwitches",
		Long: `VPCs and vSwitches. Both belong to one region (--region, the profile's region
by default). Alibaba Cloud keeps the names of neither unique: a name held by
several is a pick on a terminal and ambiguous (exit code 5) in the
non-interactive flow; pass the id.`,
	}
	v := &cobra.Command{Use: "vpc", Short: "VPCs"}
	v.AddCommand(vpcListCmd(rt), vpcGetCmd(rt), vpcCreateCmd(rt), vpcEnsureCmd(rt))
	s := &cobra.Command{Use: "vswitch", Short: "vSwitches (subnets of a VPC in one zone)"}
	s.AddCommand(vswListCmd(rt), vswGetCmd(rt), vswCreateCmd(rt), vswEnsureCmd(rt))
	cmd.AddCommand(v, s)
	return cmd
}

// checkNetName refuses a name that would be read as an id (prefix), that
// Alibaba Cloud refuses, or that is too long.
func checkNetName(kind, prefix, name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return app.UsageErrf("the %s name is empty", kind)
	case strings.HasPrefix(name, prefix):
		return app.UsageErrf("%s name %q: names may not start with %s (that is how ids are written)", kind, name, prefix)
	case strings.HasPrefix(name, "http://"), strings.HasPrefix(name, "https://"):
		return app.UsageErrf("%s name %q: names may not start with http:// or https://", kind, name)
	case len([]rune(name)) > netNameMaxLength:
		return app.UsageErrf("%s name %q is longer than %d characters", kind, name, netNameMaxLength)
	}
	return nil
}

// parseCIDRFlag validates an IPv4 CIDR block given with a flag: it has to
// be aligned to its mask (172.16.9.0/22 is not).
func parseCIDRFlag(flag, v string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(strings.TrimSpace(v))
	if err != nil || !p.Addr().Is4() {
		return netip.Prefix{}, app.UsageErrf("--%s %q is not an IPv4 CIDR block (such as %s)", flag, v, defaultVPCCIDR)
	}
	if p.Masked() != p {
		return netip.Prefix{}, app.UsageErrf("--%s %s is not aligned to its mask (did you mean %s?)", flag, v, p.Masked())
	}
	return p, nil
}

func checkNetmask(mask int) error {
	if mask < minVSwitchMask || mask > maxVSwitchMask {
		return app.UsageErrf("--netmask must be between %d and %d, got %d", minVSwitchMask, maxVSwitchMask, mask)
	}
	return nil
}

// zoneTarget is one zone a vSwitch is wanted in.
type zoneTarget struct {
	ID     string // the zone id (cn-hongkong-b)
	Suffix string // its suffix (b)
}

var zoneSuffixRe = regexp.MustCompile(`^[a-z0-9]+$`)

// parseZone reads a zone given as a suffix (b) or as a zone id of the
// region (cn-hongkong-b).
func parseZone(region, v, flag string) (zoneTarget, error) {
	v = strings.TrimSpace(v)
	suffix := v
	if strings.Contains(v, "-") {
		if !strings.HasPrefix(v, region+"-") {
			return zoneTarget{}, app.UsageErrf("--%s %q: the zone is not in region %s (give a suffix such as b, or a zone id %s-<suffix>)", flag, v, region, region)
		}
		suffix = strings.TrimPrefix(v, region+"-")
	}
	if !zoneSuffixRe.MatchString(suffix) {
		return zoneTarget{}, app.UsageErrf("--%s %q is not a zone (give a suffix such as b, or a zone id %s-<suffix>)", flag, v, region)
	}
	return zoneTarget{ID: region + "-" + suffix, Suffix: suffix}, nil
}

// parseZones reads --zones: one or more zones, each once.
func parseZones(region string, list []string) ([]zoneTarget, error) {
	if len(list) == 0 {
		return nil, app.UsageErrf("--zones is empty: give one or more zones (such as b,c)")
	}
	var out []zoneTarget
	for _, v := range list {
		z, err := parseZone(region, v, "zones")
		if err != nil {
			return nil, err
		}
		if slices.ContainsFunc(out, func(o zoneTarget) bool { return o.ID == z.ID }) {
			return nil, app.UsageErrf("--zones names zone %s twice", z.ID)
		}
		out = append(out, z)
	}
	return out, nil
}

// vswName is the name of the vSwitch of a zone: --prefix and the zone
// suffix (a hyphen between them unless the prefix ends with one), else
// naming.aliyun_vswitch ({region}-switch-{zone}, zone being the suffix).
func vswName(rt *app.Runtime, region, prefix string, z zoneTarget) (string, error) {
	var name string
	if prefix != "" {
		name = prefix + z.Suffix
		if !strings.HasSuffix(prefix, "-") {
			name = prefix + "-" + z.Suffix
		}
	} else {
		var err error
		if name, err = rt.ResourceName("aliyun_vswitch", "", map[string]string{"region": region, "zone": z.Suffix}); err != nil {
			return "", err
		}
	}
	return name, checkNetName("vSwitch", "vsw-", name)
}

// waitVPC waits until the VPC of that id is Available (looked up by id:
// names are not unique). A VPC that is still Pending refuses vSwitches
// (IncorrectVpcStatus), so the wait is not optional before creating them.
func waitVPC(ctx context.Context, s *ecsScope, id string, timeout time.Duration) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "vpc/" + id, Want: statusAvailable, Timeout: timeout,
		Interval: vpcWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		st, err := s.c.vpcStatus(ctx, s.region, id)
		if errors.Is(err, platform.ErrNotFound) {
			// A resource just created may not be listed yet.
			return platform.KeepWaiting, statusNotFound, nil
		}
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if st == statusAvailable {
			return platform.WaitDone, st, nil
		}
		return platform.KeepWaiting, st, nil
	})
}

// waitVSwitch waits a little for a new vSwitch to be Available. Running
// out of time is not a failure: a note says so.
func waitVSwitch(ctx context.Context, rt *app.Runtime, s *ecsScope, id string) {
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "vswitch/" + id, Want: statusAvailable, Timeout: shortWaitTimeout,
		Interval: shortWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		st, err := s.c.vSwitchStatus(ctx, s.region, id)
		if errors.Is(err, platform.ErrNotFound) {
			return platform.KeepWaiting, statusNotFound, nil
		}
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if st == statusAvailable {
			return platform.WaitDone, st, nil
		}
		return platform.KeepWaiting, st, nil
	})
	if err != nil {
		rt.Infof("warning: vSwitch %s: %v", id, err)
	}
}

// vpcCreateStep is the step that creates the VPC (and waits for it when
// wait is set); it stores the new id in *id.
func vpcCreateStep(s *ecsScope, name, cidr string, wait bool, timeout time.Duration, id *string) platform.Step {
	return platform.Step{Resource: "vpc/" + name, Action: platform.Created, Desc: cidr,
		Apply: func(ctx context.Context) (platform.Change, error) {
			start := netClock().Now()
			vid, err := s.c.createVPC(ctx, s.region, name, cidr)
			if err != nil {
				return platform.Change{}, err
			}
			*id = vid
			detail := vid + " " + cidr
			if wait {
				if err := waitVPC(ctx, s, vid, timeout); err != nil {
					return platform.Change{ID: vid}, fmt.Errorf("VPC %s (%s) was created: %w", name, vid, err)
				}
				detail += fmt.Sprintf(" (Available after %s)", netClock().Now().Sub(start).Round(time.Second))
			}
			return platform.Change{ID: vid, Detail: detail}, nil
		}}
}

// vswPlan adds the steps that make sure a vSwitch exists in each zone, in
// the VPC vpcID returns (the id of a VPC an earlier step creates). existing
// are the vSwitches of that VPC (none for a VPC still to be created). The
// missing ones get the first free /mask blocks of the VPC's CIDR block. A
// non-empty skip reports them skipped instead (the VPC is not Available).
type vswPlan struct {
	rt       *app.Runtime
	s        *ecsScope
	vpcID    func() string
	vpcCIDR  string
	pending  bool
	existing []vSwitch
	mask     int
	// fixedMask is set when mask is not a flag of the command (vswitch
	// create): a block that does not fit asks for --cidr instead.
	fixedMask bool
	wait      bool
	skip      string
	// created, when set, is told the id of each vSwitch created.
	created func(name, id string)
}

type vswWant struct {
	Name string
	Zone zoneTarget
	// CIDR is the block to create it with ("" = allocated).
	CIDR string
}

func (p vswPlan) add(plan *platform.Plan, wants []vswWant) error {
	var missing []vswWant
	for _, w := range wants {
		res := "vswitch/" + w.Name
		var named []vSwitch
		for _, v := range p.existing {
			if v.Name == w.Name {
				named = append(named, v)
			}
		}
		var have *vSwitch
		switch {
		case len(named) == 1:
			have = &named[0]
		case len(named) > 1:
			// Several of the name in the VPC (another zone may reuse a
			// name): the one in the zone asked for, when it is alone.
			var inZone []vSwitch
			for _, v := range named {
				if v.Zone == w.Zone.ID {
					inZone = append(inZone, v)
				}
			}
			if len(inZone) != 1 {
				var ids []string
				for _, v := range named {
					ids = append(ids, v.ID+" ("+v.Zone+")")
				}
				amb := &app.AmbiguousError{What: fmt.Sprintf("vSwitch %q in %s", w.Name, p.vpcID()), Candidates: ids,
					Hint: "Alibaba Cloud lets several vSwitches of a VPC share a name; rename one, or pass --prefix"}
				if len(inZone) == 0 {
					return amb
				}
				pick, err := pickAmong(p.s, amb, inZone, func(v vSwitch) string { return v.ID }, func(v vSwitch) string { return vswLabel(v, nil) })
				if err != nil {
					return err
				}
				inZone = []vSwitch{*pick}
			}
			have = &inZone[0]
		}
		if have != nil {
			detail := have.ID + " " + have.Zone + " " + have.CIDR
			if have.Zone != w.Zone.ID {
				detail += " (warning: in zone " + have.Zone + ", not " + w.Zone.ID + "; a vSwitch cannot move)"
			}
			if w.CIDR != "" && have.CIDR != w.CIDR {
				detail += " (warning: CIDR block " + have.CIDR + ", not " + w.CIDR + ")"
			}
			plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: have.ID, Desc: detail})
			continue
		}
		missing = append(missing, w)
	}
	if len(missing) == 0 {
		return nil
	}
	var used []string
	for _, v := range p.existing {
		used = append(used, v.CIDR)
	}
	var auto int
	for _, w := range missing {
		if w.CIDR == "" {
			auto++
		} else {
			used = append(used, w.CIDR)
		}
	}
	var blocks []string
	if auto > 0 {
		var err error
		if blocks, err = allocateCIDR(used, p.vpcCIDR, p.mask, auto); err != nil {
			if errors.Is(err, platform.ErrInvalidInput) {
				if p.fixedMask {
					return app.UsageErrf("%v: pass --cidr", err)
				}
				return app.UsageErrf("--netmask %d: %v", p.mask, err)
			}
			return fmt.Errorf("VPC %s (%s): %w", p.vpcID(), p.vpcCIDR, err)
		}
	}
	for _, w := range missing {
		cidr := w.CIDR
		if cidr == "" {
			cidr, blocks = blocks[0], blocks[1:]
		}
		desc := w.Zone.ID + " " + cidr
		if p.pending {
			desc += " (vpc pending)"
		}
		res := "vswitch/" + w.Name
		if p.skip != "" {
			plan.Add(platform.Step{Resource: res, Action: platform.Skipped, Desc: desc + ": " + p.skip})
			continue
		}
		plan.Add(platform.Step{Resource: res, Action: platform.Created, Desc: desc,
			Apply: func(ctx context.Context) (platform.Change, error) {
				id, err := p.s.c.createVSwitch(ctx, p.s.region, p.vpcID(), w.Zone.ID, w.Name, cidr)
				if err != nil {
					return platform.Change{}, err
				}
				if p.created != nil {
					p.created(w.Name, id)
				}
				if p.wait {
					waitVSwitch(ctx, p.rt, p.s, id)
				}
				return platform.Change{ID: id, Detail: id + " " + w.Zone.ID + " " + cidr}, nil
			}})
	}
	return nil
}

// netReadScope opens the scope of a read-only network command.
func netReadScope(ctx context.Context, rt *app.Runtime, region string) (*ecsScope, error) {
	if rt.Flags.Offline {
		// These commands always ask the API: nothing about networks is
		// kept in the local inventory.
		return nil, app.ErrOffline
	}
	return openECSScope(ctx, rt, region)
}

// ---------------------------------------------------------------- vpc

func vpcGrid(vpcs []vpcInfo) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "ID", "CIDR", "STATUS", "DEFAULT"}, Empty: "no VPCs"}
	for _, v := range vpcs {
		g.Rows = append(g.Rows, []string{orDash(v.Name), v.ID, v.CIDR, v.Status, strconv.FormatBool(v.IsDefault)})
	}
	return g
}

func vpcListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var all bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the VPCs of a region (the default VPC with --all)",
		Long: `List the VPCs of the profile's region, or of --region, read from the API. The
default VPC (which Alibaba Cloud creates on its own) is left out unless --all
is given.`,
		Example: "  polyctl aliyun vpc vpc list --region cn-hongkong -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := netReadScope(ctx, rt, region)
			if err != nil {
				return err
			}
			vpcs, err := s.c.listVPCs(ctx, s.region, all)
			if err != nil {
				return err
			}
			if vpcs == nil {
				vpcs = []vpcInfo{}
			}
			if len(vpcs) == 0 {
				rt.Infof("no VPCs in %s", s.where())
			} else {
				rt.Infof("%d VPC(s) in %s", len(vpcs), s.where())
			}
			return rt.Render(vpcs, func() output.Grid { return vpcGrid(vpcs) })
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "include the default VPC")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// vpcDetail is the output of `vpc get`.
type vpcDetail struct {
	vpcInfo   `yaml:",inline"`
	Profile   string    `json:"profile" yaml:"profile"`
	VSwitches []vSwitch `json:"vswitches" yaml:"vswitches"`
}

func vpcGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show a VPC and its vSwitches",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := netReadScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = vpcArg(ctx, rt, s, args); err != nil {
				return err
			}
			v, err := resolveVPC(ctx, s, args[0])
			if err != nil {
				return err
			}
			vsw, err := s.c.listVSwitches(ctx, s.region, v.ID, "", "")
			if err != nil {
				return err
			}
			if vsw == nil {
				vsw = []vSwitch{}
			}
			d := vpcDetail{vpcInfo: v, Profile: s.profile, VSwitches: vsw}
			return rt.Render(d, func() output.Grid {
				g := output.Grid{Rows: [][]string{
					{"NAME", orDash(v.Name), "ID", v.ID},
					{"CIDR", v.CIDR, "STATUS", v.Status},
					{"REGION", v.Region, "DEFAULT", strconv.FormatBool(v.IsDefault)},
					{"VSWITCHES"},
				}}
				if len(vsw) == 0 {
					g.Rows = append(g.Rows, []string{"  (none)"})
				}
				for _, w := range vsw {
					g.Rows = append(g.Rows, []string{"  " + orDash(w.Name), w.ID, w.Zone, w.CIDR, w.Status})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func vpcCreateCmd(rt *app.Runtime) *cobra.Command {
	var region, cidr string
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a VPC",
		Long: `Create the VPC <name> with the CIDR block --cidr (172.16.0.0/12 by default; it
cannot be changed later). A VPC of that name in the region is an error (exit
code 1): use ensure to reuse it. With --wait the command returns once the VPC
is Available (about 3 seconds), bounded by --timeout. On a terminal a
missing <name> is asked (the naming.aliyun_vpc name proposed when it is
free), checked as it is typed.`,
		Example: "  polyctl aliyun vpc vpc create web --cidr 10.0.0.0/16 --wait",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			if name == "" {
				// The interactive flow asks for the name, the one of
				// naming.aliyun_vpc proposed when it is free.
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				s, err := openECSScope(ctx, rt, region)
				if err != nil {
					return err
				}
				vpcs, err := s.c.listVPCs(ctx, s.region, true)
				if err != nil {
					return err
				}
				proposal, _ := rt.ResourceName("aliyun_vpc", "", map[string]string{"region": s.region})
				if name, err = askNetName(rt, "VPC", "vpc-", "Name of the new VPC", proposal, func(n string) string {
					for _, v := range vpcs {
						if v.Name == n {
							return v.ID
						}
					}
					return ""
				}); err != nil {
					return err
				}
			}
			if err := checkNetName("VPC", "vpc-", name); err != nil {
				return err
			}
			p, err := parseCIDRFlag("cidr", cidr)
			if err != nil {
				return err
			}
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			found, err := s.c.findVPCs(ctx, s.region, name)
			if err != nil {
				return err
			}
			if len(found) > 0 {
				return fmt.Errorf("VPC %q already exists in %s (%s): use `polyctl aliyun vpc vpc ensure %s` to reuse it", name, s.where(), found[0].ID, name)
			}
			var id string
			var plan platform.Plan
			plan.Add(vpcCreateStep(s, name, p.String(), wait, timeout, &id))
			return rt.Ensure(ctx, "aliyun.vpc.vpc.create", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&cidr, "cidr", defaultVPCCIDR, "CIDR block of the VPC (cannot be changed later)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	app.AddWaitFlags(cmd, &w, false, vpcWaitTimeout)
	return cmd
}

func vpcEnsureCmd(rt *app.Runtime) *cobra.Command {
	var region, cidr string
	var zones []string
	var mask int
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "ensure [<name>]",
		Short: "Make sure a VPC and its vSwitches exist",
		Long: `Make sure the VPC <name> (default naming.aliyun_vpc, {region}-vpc) exists with a
vSwitch in each of --zones, as vswitch ensure does. Running it again changes
nothing.

- A missing VPC is created with --cidr (172.16.0.0/12 by default) and waited
  for until it is Available (bounded by --timeout): a Pending VPC refuses
  vSwitches. An existing one is used as it is: its status and CIDR block are
  not compared, but a Pending one is waited for. Several VPCs of the name are
  a pick on a terminal and ambiguous (exit code 5) otherwise.
- vSwitches are named by naming.aliyun_vswitch ({region}-switch-{zone}, zone
  being the suffix) and looked up by name in the VPC only. The missing ones
  get the first free /--netmask blocks of the VPC's CIDR block.
- --no-wait returns once the VPC creation was requested; the vSwitches of a
  VPC that is not Available yet are then skipped (run ensure again).`,
		Example: `  polyctl aliyun vpc vpc ensure --region cn-hongkong --dry-run
  polyctl aliyun vpc vpc ensure web-vpc --cidr 10.0.0.0/16 --zones b,c,d`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			p, err := parseCIDRFlag("cidr", cidr)
			if err != nil {
				return err
			}
			if err := checkNetmask(mask); err != nil {
				return err
			}
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			if len(args) == 1 {
				if err := checkNetName("VPC", "vpc-", args[0]); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			targets, err := parseZones(s.region, zones)
			if err != nil {
				return err
			}
			name := ""
			if len(args) == 1 {
				name = args[0]
			}
			if name, err = rt.ResourceName("aliyun_vpc", name, map[string]string{"region": s.region}); err != nil {
				return err
			}
			if err := checkNetName("VPC", "vpc-", name); err != nil {
				return err
			}
			var wants []vswWant
			for _, z := range targets {
				n, err := vswName(rt, s.region, "", z)
				if err != nil {
					return err
				}
				wants = append(wants, vswWant{Name: n, Zone: z})
			}
			found, err := s.c.findVPCs(ctx, s.region, name)
			if err != nil {
				return err
			}
			if found, err = narrowVPCs(s, name, found, "Alibaba Cloud lets several VPCs share a name; rename one, or ensure another name"); err != nil {
				return err
			}
			var plan platform.Plan
			var vpcID string
			vp := vswPlan{rt: rt, s: s, vpcID: func() string { return vpcID }, mask: mask, wait: wait}
			switch len(found) {
			case 0:
				vp.vpcCIDR, vp.pending = p.String(), true
				if !wait {
					vp.skip = vswitchSkippedLater
				}
				plan.Add(vpcCreateStep(s, name, p.String(), wait, timeout, &vpcID))
			case 1:
				v := found[0]
				vpcID, vp.vpcCIDR = v.ID, v.CIDR
				if cmd.Flags().Changed("cidr") && v.CIDR != p.String() {
					rt.Infof("note: VPC %s keeps its CIDR block %s (it cannot be changed)", v.ID, v.CIDR)
				}
				step := platform.Step{Resource: "vpc/" + name, Action: platform.Unchanged, ID: v.ID, Desc: v.ID + " " + v.CIDR}
				if v.Status != statusAvailable {
					step.Desc += " (" + orDash(v.Status) + ")"
					if wait {
						step.Apply = func(ctx context.Context) (platform.Change, error) {
							if err := waitVPC(ctx, s, v.ID, timeout); err != nil {
								return platform.Change{}, err
							}
							return platform.Change{Detail: v.ID + " " + v.CIDR + " (now Available)"}, nil
						}
					} else {
						vp.skip = vswitchSkippedLater
					}
				}
				plan.Add(step)
				if vp.existing, err = s.c.listVSwitches(ctx, s.region, v.ID, "", ""); err != nil {
					return err
				}
			default:
				var ids []string
				for _, v := range found {
					ids = append(ids, v.ID)
				}
				return &app.AmbiguousError{What: fmt.Sprintf("VPC %q in %s", name, s.where()), Candidates: ids,
					Hint: "Alibaba Cloud lets several VPCs share a name; rename one, or ensure another name"}
			}
			if err := vp.add(&plan, wants); err != nil {
				return err
			}
			return rt.Ensure(ctx, "aliyun.vpc.vpc.ensure", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&cidr, "cidr", defaultVPCCIDR, "CIDR block of a new VPC (cannot be changed later)")
	cmd.Flags().StringSliceVar(&zones, "zones", defaultZones, "zones of the vSwitches: suffixes (b) or zone ids of the region (cn-hongkong-b)")
	cmd.Flags().IntVar(&mask, "netmask", defaultVSwitchMask, "mask length of the vSwitches created (16-29)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	app.AddWaitFlags(cmd, &w, true, vpcWaitTimeout)
	return cmd
}

// ------------------------------------------------------------- vswitch

func vswGrid(list []vSwitch) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "ID", "VPC", "ZONE", "CIDR", "STATUS", "AVAILABLE IPS"}, Empty: "no vSwitches"}
	for _, v := range list {
		g.Rows = append(g.Rows, []string{orDash(v.Name), v.ID, v.VPC, v.Zone, v.CIDR, v.Status, strconv.FormatInt(v.AvailableIPs, 10)})
	}
	return g
}

func vswListCmd(rt *app.Runtime) *cobra.Command {
	var region, vpcRef string
	cmd := &cobra.Command{
		Use:     "list",
		Short:   "List the vSwitches of a region, or of one VPC",
		Example: "  polyctl aliyun vpc vswitch list --vpc cn-hongkong-vpc",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := netReadScope(ctx, rt, region)
			if err != nil {
				return err
			}
			vpcID, where := "", s.where()
			if vpcRef != "" {
				v, err := resolveVPC(ctx, s, vpcRef)
				if err != nil {
					return err
				}
				vpcID, where = v.ID, where+" ("+v.ID+")"
			}
			list, err := s.c.listVSwitches(ctx, s.region, vpcID, "", "")
			if err != nil {
				return err
			}
			if list == nil {
				list = []vSwitch{}
			}
			if len(list) == 0 {
				rt.Infof("no vSwitches in %s", where)
			} else {
				rt.Infof("%d vSwitch(es) in %s", len(list), where)
			}
			return rt.Render(list, func() output.Grid { return vswGrid(list) })
		},
	}
	cmd.Flags().StringVar(&vpcRef, "vpc", "", "only the vSwitches of this VPC (id or name)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// resolveVSwitch returns the vSwitch ref names (an id, or a name looked up
// in vpcRef when given, else in the whole region).
func resolveVSwitch(ctx context.Context, s *ecsScope, ref, vpcRef string) (*vSwitch, error) {
	vpcID := ""
	if vpcRef != "" {
		v, err := resolveVPC(ctx, s, vpcRef)
		if err != nil {
			return nil, err
		}
		vpcID = v.ID
	}
	var found []vSwitch
	var err error
	if looksLikeVSwitchID(ref) {
		found, err = s.c.listVSwitches(ctx, s.region, vpcID, "", ref)
	} else {
		found, err = s.c.listVSwitches(ctx, s.region, vpcID, ref, "")
	}
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		in := s.where()
		if vpcID != "" {
			in += " (" + vpcID + ")"
		}
		return nil, fmt.Errorf("%w: vSwitch %q in %s", platform.ErrNotFound, ref, in)
	case 1:
		return &found[0], nil
	}
	var ids []string
	for _, v := range found {
		ids = append(ids, v.ID+" ("+v.VPC+", "+v.Zone+")")
	}
	hint := "Alibaba Cloud lets several vSwitches share a name; pass the vSwitch id"
	if vpcID == "" {
		hint += " or --vpc <vpc>"
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("vSwitch %q in %s", ref, s.where()), Candidates: ids, Hint: hint}
	return pickAmong(s, amb, found, func(v vSwitch) string { return v.ID }, func(v vSwitch) string { return vswLabel(v, nil) })
}

// vswDetail is the output of `vswitch get`.
type vswDetail struct {
	vSwitch `yaml:",inline"`
	Profile string `json:"profile" yaml:"profile"`
}

func vswGetCmd(rt *app.Runtime) *cobra.Command {
	var region, vpcRef string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show a vSwitch",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			s, err := netReadScope(ctx, rt, region)
			if err != nil {
				return err
			}
			if args, err = vswArg(ctx, rt, s, args, vpcRef); err != nil {
				return err
			}
			v, err := resolveVSwitch(ctx, s, args[0], vpcRef)
			if err != nil {
				return err
			}
			d := vswDetail{vSwitch: *v, Profile: s.profile}
			return rt.Render(d, func() output.Grid {
				return output.Grid{Rows: [][]string{
					{"NAME", orDash(v.Name), "ID", v.ID},
					{"VPC", v.VPC, "ZONE", v.Zone},
					{"CIDR", v.CIDR, "STATUS", v.Status},
					{"AVAILABLE IPS", strconv.FormatInt(v.AvailableIPs, 10), "REGION", v.Region},
				}}
			})
		},
	}
	cmd.Flags().StringVar(&vpcRef, "vpc", "", "VPC (id or name) to look the name up in (default: every VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func vswCreateCmd(rt *app.Runtime) *cobra.Command {
	var region, vpcRef, zone, cidr string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a vSwitch in a VPC and zone",
		Long: `Create the vSwitch <name> in --vpc (id or name) and --zone (a suffix such as b,
or a zone id of the region), both required. --cidr gives its block (inside
the VPC's, aligned to its mask); without it the first free /22 of the VPC's
block is taken. A vSwitch of that name in the same zone of the VPC is an
error (exit code 1): use ensure. The command waits up to 30 seconds for the
vSwitch to be Available; running out of time is only a warning. On a
terminal a missing --vpc is picked from the Available VPCs, a missing --zone
from the zones that offer instances (the first default zone without a
vSwitch of the VPC preselected), and a missing <name> asked (the
naming.aliyun_vswitch name of the zone proposed).`,
		Example: "  polyctl aliyun vpc vswitch create web-b --vpc cn-hongkong-vpc --zone b --cidr 172.16.8.0/22",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := app.Arg(args, 0)
			if name != "" {
				if err := checkNetName("vSwitch", "vsw-", name); err != nil {
					return err
				}
			}
			if (vpcRef == "" || zone == "") && !rt.Interactive() {
				return app.UsageErrf("--vpc and --zone are required: a vSwitch belongs to one VPC and one zone")
			}
			if cidr != "" {
				p, err := parseCIDRFlag("cidr", cidr)
				if err != nil {
					return err
				}
				cidr = p.String()
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			var z zoneTarget
			if zone != "" {
				if z, err = parseZone(s.region, zone, "zone"); err != nil {
					return err
				}
			}
			var v vpcInfo
			if vpcRef == "" {
				prefer, _ := rt.ResourceName("aliyun_vpc", "", map[string]string{"region": s.region})
				v, err = pickVPC(ctx, rt, s, "--vpc", prefer, nil)
			} else {
				v, err = resolveVPC(ctx, s, vpcRef)
			}
			if err != nil {
				return err
			}
			existing, err := s.c.listVSwitches(ctx, s.region, v.ID, "", "")
			if err != nil {
				return err
			}
			if zone == "" {
				if z, err = pickZone(ctx, rt, s, existing); err != nil {
					return err
				}
			}
			if name == "" {
				proposal, _ := vswName(rt, s.region, "", z)
				if name, err = askNetName(rt, "vSwitch", "vsw-", "Name of the new vSwitch ("+z.ID+")", proposal, func(n string) string {
					for _, e := range existing {
						if e.Name == n && e.Zone == z.ID {
							return e.ID
						}
					}
					return ""
				}); err != nil {
					return err
				}
			}
			for _, e := range existing {
				if e.Name == name && e.Zone == z.ID {
					return fmt.Errorf("vSwitch %q already exists in %s, zone %s (%s): use `polyctl aliyun vpc vswitch ensure` to reuse it", name, v.ID, z.ID, e.ID)
				}
			}
			var plan platform.Plan
			// Only the vSwitches of other names count as existing: the one
			// asked for is created even when another zone has its name.
			var others []vSwitch
			for _, e := range existing {
				if e.Name != name {
					others = append(others, e)
				} else {
					others = append(others, vSwitch{CIDR: e.CIDR})
				}
			}
			vp := vswPlan{rt: rt, s: s, vpcID: func() string { return v.ID }, vpcCIDR: v.CIDR, existing: others, mask: defaultVSwitchMask, fixedMask: true, wait: true}
			if err := vp.add(&plan, []vswWant{{Name: name, Zone: z, CIDR: cidr}}); err != nil {
				return err
			}
			return rt.Ensure(ctx, "aliyun.vpc.vswitch.create", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&vpcRef, "vpc", "", "VPC of the vSwitch, id or name (required)")
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the vSwitch: a suffix (b) or a zone id of the region (required)")
	cmd.Flags().StringVar(&cidr, "cidr", "", "CIDR block of the vSwitch (default: the first free /22 of the VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

func vswEnsureCmd(rt *app.Runtime) *cobra.Command {
	var region, vpcRef, prefix string
	var zones []string
	var mask int
	cmd := &cobra.Command{
		Use:   "ensure",
		Short: "Make sure a VPC has a vSwitch in each zone",
		Long: `Make sure the VPC --vpc (id or name; default naming.aliyun_vpc, {region}-vpc,
which must exist) has a vSwitch in each of --zones (b,c by default: the zones
{region}-b and {region}-c). Running it again changes nothing.

- vSwitches are named <prefix>-<zone suffix> with --prefix, else by
  naming.aliyun_vswitch ({region}-switch-{zone}, zone being the suffix), and
  looked up by name in that VPC only: a vSwitch of the name in another VPC
  never counts.
- An existing vSwitch is unchanged, whatever its zone or block (a warning
  says when its zone differs: vSwitches cannot be changed).
- A missing one gets the first free /--netmask block of the VPC's CIDR
  block (scanned from its start, so --dry-run shows the real blocks) and is
  waited for up to 30 seconds.
- A zone the region does not have is exit code 7: pass --zones.`,
		Example: "  polyctl aliyun vpc vswitch ensure --vpc cn-hongkong-vpc --zones b,c,d",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if err := checkNetmask(mask); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			targets, err := parseZones(s.region, zones)
			if err != nil {
				return err
			}
			var wants []vswWant
			for _, z := range targets {
				n, err := vswName(rt, s.region, prefix, z)
				if err != nil {
					return err
				}
				wants = append(wants, vswWant{Name: n, Zone: z})
			}
			ref := vpcRef
			if ref == "" {
				if ref, err = rt.ResourceName("aliyun_vpc", "", map[string]string{"region": s.region}); err != nil {
					return err
				}
			}
			v, err := resolveVPC(ctx, s, ref)
			if vpcRef == "" && errors.Is(err, platform.ErrNotFound) {
				missing := app.UsageErrf("the default VPC %q (naming.aliyun_vpc) does not exist in %s; pass --vpc <id|name>, or create it with `polyctl aliyun vpc vpc ensure`", ref, s.region)
				if !rt.Interactive() {
					return missing
				}
				// The interactive flow offers the VPCs of the region.
				v, err = pickVPC(ctx, rt, s, "--vpc", "", missing)
			}
			if err != nil {
				return err
			}
			existing, err := s.c.listVSwitches(ctx, s.region, v.ID, "", "")
			if err != nil {
				return err
			}
			var plan platform.Plan
			vp := vswPlan{rt: rt, s: s, vpcID: func() string { return v.ID }, vpcCIDR: v.CIDR, existing: existing, mask: mask, wait: true}
			if err := vp.add(&plan, wants); err != nil {
				return err
			}
			return rt.Ensure(ctx, "aliyun.vpc.vswitch.ensure", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&vpcRef, "vpc", "", "VPC, id or name (default: naming.aliyun_vpc)")
	cmd.Flags().StringSliceVar(&zones, "zones", defaultZones, "zones: suffixes (b) or zone ids of the region (cn-hongkong-b)")
	cmd.Flags().StringVar(&prefix, "prefix", "", "name prefix of the vSwitches (<prefix>-<zone suffix>; default naming.aliyun_vswitch)")
	cmd.Flags().IntVar(&mask, "netmask", defaultVSwitchMask, "mask length of the vSwitches created (16-29)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}
