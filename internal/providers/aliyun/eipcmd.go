package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// newEIPCmd is `aliyun eip`: elastic IP addresses.
func newEIPCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "eip", Short: "Elastic IP addresses"}
	addr := &cobra.Command{
		Use:   "address",
		Short: "Elastic IP addresses of a region",
		Long: `Elastic IP addresses (EIPs). An EIP belongs to one region (--region, the
profile's region by default) and is named by its allocation id (eip-...) or
its address.

New EIPs are allocated with AllocateEipAddress: --bandwidth Mbps (200 by
default, or defaults.aliyun.eip.bandwidth), --isp (BGP_PRO by default, or
defaults.aliyun.eip.isp), pay by traffic, pay as you go, paid automatically,
in the resource group --resource-group (a name or an rg- id; default
defaults.aliyun.resource_group, else the group named "default"). An EIP is
billed as long as it exists, bound or not: there is no release command, and
list --unused shows the idle ones.`,
	}
	addr.AddCommand(eipListCmd(rt), eipAllocateCmd(rt), eipAssociateCmd(rt), eipEnsureCmd(rt))
	cmd.AddCommand(addr)
	return cmd
}

// storeEIP records an EIP in the inventory.
func storeEIP(ctx context.Context, rt *app.Runtime, profile string, e eipAddress) {
	if e.AllocationID == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResEIP}, e.resource(), cfg.TTLFor(platform.ResEIP))
}

// refreshEIP reads an EIP again and stores it; nil when it cannot be read.
func refreshEIP(ctx context.Context, rt *app.Runtime, s *ecsScope, id string) *eipAddress {
	e, err := s.c.getEIP(ctx, s.region, id)
	if err != nil || e == nil {
		rt.Verbosef("re-read EIP %s: %v", id, err)
		return nil
	}
	storeEIP(ctx, rt, s.profile, *e)
	return e
}

// eipSettings resolves the allocation settings: the flags, else
// defaults.aliyun.eip.bandwidth / isp, else the built-in defaults.
func eipSettings(rt *app.Runtime, profile, bandwidth, isp string) (eipSpec, error) {
	bw, err := rt.Setting(profile, platform.Aliyun, "eip.bandwidth", bandwidth)
	if err != nil {
		return eipSpec{}, err
	}
	if bw == "" {
		bw = eipDefaultBandwidth
	}
	if n, err := strconv.Atoi(bw); err != nil || n <= 0 {
		return eipSpec{}, app.UsageErrf("--bandwidth must be a positive number of Mbps, got %q", bw)
	}
	i, err := rt.Setting(profile, platform.Aliyun, "eip.isp", isp)
	if err != nil {
		return eipSpec{}, err
	}
	if i = strings.TrimSpace(i); i == "" {
		i = eipDefaultISP
	}
	return eipSpec{Bandwidth: bw, ISP: i}, nil
}

// resolveResourceGroup returns the id of --resource-group (an rg- id is
// taken as it is; a name is looked up), else of
// defaults.aliyun.resource_group, else of the group named "default".
func resolveResourceGroup(ctx context.Context, rt *app.Runtime, s *ecsScope, flag string) (string, error) {
	ref, err := rt.Setting(s.profile, platform.Aliyun, "resource_group", flag)
	if err != nil {
		return "", err
	}
	if ref = strings.TrimSpace(ref); ref == "" {
		ref = defaultResourceGroup
	}
	if strings.HasPrefix(ref, "rg-") {
		return ref, nil
	}
	return s.c.resourceGroupID(ctx, ref)
}

// waitEIP waits until the EIP of that id satisfies done, for at most
// shortWaitTimeout; want names the awaited state in errors.
func waitEIP(ctx context.Context, s *ecsScope, id, want string, done func(eipAddress) bool) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "eip/" + id, Want: want, Timeout: shortWaitTimeout,
		Interval: shortWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		e, err := s.c.getEIP(ctx, s.region, id)
		if err != nil && !errors.Is(err, platform.ErrNotFound) {
			return platform.KeepWaiting, "", err
		}
		if e == nil {
			// An EIP just allocated may not be listed yet; the timeout
			// bounds how long it may stay missing.
			return platform.KeepWaiting, statusNotFound, nil
		}
		if done(*e) {
			return platform.WaitDone, e.Status, nil
		}
		return platform.KeepWaiting, e.Status, nil
	})
}

// allocateAndRead allocates an EIP, then reads it back (the answer of the
// allocation lacks most fields) once it is Available.
func allocateAndRead(ctx context.Context, rt *app.Runtime, s *ecsScope, spec eipSpec) (eipAddress, error) {
	id, ip, err := s.c.allocateEIP(ctx, s.region, spec)
	if err != nil {
		return eipAddress{}, err
	}
	if err := waitEIP(ctx, s, id, eipAvailable, func(e eipAddress) bool { return e.Status == eipAvailable }); err != nil {
		return eipAddress{AllocationID: id, IP: ip}, fmt.Errorf("EIP %s (%s) was allocated: %w", id, ip, err)
	}
	if e := refreshEIP(ctx, rt, s, id); e != nil {
		return *e, nil
	}
	return eipAddress{AllocationID: id, IP: ip, Region: s.region}, nil
}

// associateAndWait binds an EIP to an instance and waits until the EIP is
// InUse by that instance.
func associateAndWait(ctx context.Context, rt *app.Runtime, s *ecsScope, eipID, instanceID string) error {
	if err := s.c.associateEIP(ctx, s.region, eipID, instanceID); err != nil {
		return err
	}
	err := waitEIP(ctx, s, eipID, eipInUse+" by "+instanceID, func(e eipAddress) bool {
		return e.Status == eipInUse && e.InstanceID == instanceID
	})
	refreshEIP(ctx, rt, s, eipID)
	refreshInstance(rt, ctx, s.c, s.profile, s.region, instanceID)
	return err
}

// instanceScope finds an instance (name or id) through the inventory of
// every selected account and opens its account in its region. A --region
// that differs from the instance's is a usage error: an EIP can only be
// bound to an instance of its own region.
func instanceScope(ctx context.Context, rt *app.Runtime, ref, region string) (*ecsScope, *Instance, error) {
	res, err := rt.ResolveResource(ctx, platform.Aliyun, platform.ResInstance, ref)
	if err != nil {
		return nil, nil, err
	}
	var cached Instance
	_ = res.Decode(&cached)
	instRegion := cached.Region
	if instRegion == "" {
		instRegion = res.ParentID
	}
	if region != "" && instRegion != "" && region != instRegion {
		return nil, nil, app.UsageErrf("--region %s differs from the region of instance %s (%s): an EIP can only be bound to an instance of its own region", region, ref, instRegion)
	}
	c, err := openNamed(rt, ctx, res.Profile)
	if err != nil {
		return nil, nil, err
	}
	s := &ecsScope{c: c, profile: res.Profile, region: c.regionOr(instRegion), rt: rt}
	inst, err := c.describeInstance(ctx, s.region, res.ID)
	if err != nil {
		return nil, nil, err
	}
	return s, inst, nil
}

// checkEIPRef refuses a reference that is neither an allocation id nor an
// address.
func checkEIPRef(ref string) error {
	if strings.HasPrefix(ref, "eip-") && len(ref) > 4 {
		return nil
	}
	if _, err := netip.ParseAddr(ref); err == nil {
		return nil
	}
	return app.UsageErrf("%q is neither an EIP allocation id (eip-...) nor an IP address", ref)
}

func eipGrid(eips []eipAddress) output.Grid {
	g := output.Grid{Headers: []string{"ALLOCATION_ID", "IP", "STATUS", "BOUND_TO", "NAME / DESC", "BANDWIDTH", "ISP"}, Empty: "no EIPs"}
	for _, e := range eips {
		label := e.Name
		if label == "" {
			label = e.Description
		}
		g.Rows = append(g.Rows, []string{e.AllocationID, e.IP, e.Status, e.boundTo(), orDash(label), e.Bandwidth, e.ISP})
	}
	return g
}

// ---------------------------------------------------------------- list

func eipListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var unused, bound bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the EIPs of a region (cached locally)",
		Long: `List the EIPs of the profile's region, or of --region; the list is cached in the
local inventory per region. --unused keeps the EIPs bound to nothing (they
are billed all the same), --bound the others.`,
		Example: "  polyctl aliyun eip address list --unused -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if unused && bound {
				return app.UsageErrf("--unused and --bound are mutually exclusive")
			}
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			region, err := resolveRegion(rt, prof, region)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResEIP, Scope: region}
			rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.eipResources(ctx, region)
			})
			if err != nil {
				return err
			}
			eips := []eipAddress{}
			for _, r := range rows {
				var e eipAddress
				if err := r.Decode(&e); err != nil {
					return fmt.Errorf("decode cached EIP %s: %w", r.ID, err)
				}
				if (unused && e.bound()) || (bound && !e.bound()) {
					continue
				}
				eips = append(eips, e)
			}
			where := "aliyun/" + prof + "/" + region
			if len(eips) == 0 {
				rt.Infof("no EIPs in %s%s", where, cacheNote(cached))
			} else {
				rt.Infof("%d EIP(s) in %s%s", len(eips), where, cacheNote(cached))
			}
			return rt.Render(eips, func() output.Grid { return eipGrid(eips) })
		},
	}
	cmd.Flags().BoolVar(&unused, "unused", false, "only the EIPs bound to nothing")
	cmd.Flags().BoolVar(&bound, "bound", false, "only the EIPs bound to an instance, a network interface or a load balancer")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// ------------------------------------------------------------ allocate

func addEIPSpecFlags(cmd *cobra.Command, bandwidth, isp, group *string) {
	cmd.Flags().StringVar(bandwidth, "bandwidth", "", "peak bandwidth in Mbps of a new EIP (default defaults.aliyun.eip.bandwidth, else 200)")
	cmd.Flags().StringVar(isp, "isp", "", "line type of a new EIP: BGP_PRO, BGP, ... (default defaults.aliyun.eip.isp, else BGP_PRO)")
	cmd.Flags().StringVar(group, "resource-group", "", "resource group of a new EIP, a name or an rg- id (default defaults.aliyun.resource_group, else \"default\")")
}

// allocateStep is the step that allocates an EIP; it stores it in *out.
func allocateStep(rt *app.Runtime, s *ecsScope, resource string, spec eipSpec, out *eipAddress) platform.Step {
	return platform.Step{Resource: resource, Action: platform.Created, Desc: "allocate " + spec.summary(),
		Apply: func(ctx context.Context) (platform.Change, error) {
			e, err := allocateAndRead(ctx, rt, s, spec)
			*out = e
			if err != nil {
				return platform.Change{ID: e.AllocationID}, err
			}
			return platform.Change{ID: e.AllocationID, Detail: "allocated " + e.IP + " " + spec.summary()}, nil
		}}
}

func eipAllocateCmd(rt *app.Runtime) *cobra.Command {
	var region, bandwidth, isp, group string
	cmd := &cobra.Command{
		Use:   "allocate",
		Short: "Allocate a new EIP (billed until it is released)",
		Long: `Allocate a new EIP with --bandwidth, --isp and --resource-group (see aliyun eip
address --help for the defaults). It is billed until it is released, bound or
not; ensure reuses an idle EIP instead.`,
		Example: "  polyctl aliyun eip address allocate --bandwidth 100 --isp BGP",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, region)
			if err != nil {
				return err
			}
			spec, err := eipSettings(rt, s.profile, bandwidth, isp)
			if err != nil {
				return err
			}
			if spec.ResourceGroup, err = resolveResourceGroup(ctx, rt, s, group); err != nil {
				return err
			}
			var e eipAddress
			var plan platform.Plan
			plan.Add(allocateStep(rt, s, "eip/1", spec, &e))
			return rt.Ensure(ctx, "aliyun.eip.address.allocate", s.target(), &plan)
		},
	}
	addEIPSpecFlags(cmd, &bandwidth, &isp, &group)
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// ----------------------------------------------------------- associate

// associateStep binds e to inst, or reports it bound already.
func associateStep(rt *app.Runtime, s *ecsScope, inst *Instance, eipID func() string, label string) platform.Step {
	return platform.Step{Resource: "instance/" + instanceLabel(inst), Action: platform.Updated, ID: inst.ID,
		Desc: fmt.Sprintf("associate %s with %s", label, inst.ID),
		Apply: func(ctx context.Context) (platform.Change, error) {
			id := eipID()
			if err := associateAndWait(ctx, rt, s, id, inst.ID); err != nil {
				return platform.Change{}, err
			}
			return platform.Change{Detail: fmt.Sprintf("associated %s with %s", id, inst.ID)}, nil
		}}
}

func eipAssociateCmd(rt *app.Runtime) *cobra.Command {
	var region, instance string
	cmd := &cobra.Command{
		Use:   "associate <allocation-id|ip>",
		Short: "Bind an EIP to an ECS instance",
		Long: `Bind the EIP (allocation id or address) to the ECS instance --instance (name or
id, found through the inventory in every selected account; required). The
EIP is looked up in the instance's region. The EIP has to be Available (an
EIP bound elsewhere is exit code 1) and the instance has to be a VPC instance
without an EIP; an EIP already bound to the instance is unchanged. The
command waits up to 30 seconds for the EIP to be InUse.`,
		Example: "  polyctl aliyun eip address associate 203.0.113.10 --instance site-a",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref := args[0]
			if instance == "" {
				return app.UsageErrf("--instance is required: name the ECS instance to bind the EIP to")
			}
			if err := checkEIPRef(ref); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, inst, err := instanceScope(ctx, rt, instance, region)
			if err != nil {
				return err
			}
			e, err := s.c.getEIP(ctx, s.region, ref)
			if err != nil {
				return err
			}
			if e == nil {
				return fmt.Errorf("%w: EIP %s in %s (the region of instance %s)", platform.ErrNotFound, ref, s.where(), instance)
			}
			storeEIP(ctx, rt, s.profile, *e)
			var plan platform.Plan
			res := "instance/" + instanceLabel(inst)
			switch {
			case e.InstanceID == inst.ID:
				plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: inst.ID, Desc: "already bound " + e.IP + " (" + e.AllocationID + ")"})
			case e.bound():
				return fmt.Errorf("EIP %s (%s) is bound to %s already", e.AllocationID, e.IP, e.boundTo())
			case e.Status != eipAvailable:
				return fmt.Errorf("EIP %s (%s) is %s, not Available", e.AllocationID, e.IP, e.Status)
			case inst.EIP != "":
				return fmt.Errorf("instance %s holds the EIP %s already: an instance holds one EIP", inst.ID, inst.EIP)
			case inst.VpcID == "":
				return fmt.Errorf("instance %s is in no VPC; an EIP can only be bound to a VPC instance", inst.ID)
			default:
				plan.Add(associateStep(rt, s, inst, func() string { return e.AllocationID }, e.IP+" ("+e.AllocationID+")"))
			}
			return rt.Ensure(ctx, "aliyun.eip.address.associate", s.target(), &plan)
		},
	}
	cmd.Flags().StringVar(&instance, "instance", "", "ECS instance to bind the EIP to, name or id (required)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the instance's region)")
	return cmd
}

// -------------------------------------------------------------- ensure

// eipRef is an EIP in the result of ensure.
type eipRef struct {
	AllocationID string `json:"allocation_id" yaml:"allocation_id"`
	IP           string `json:"ip" yaml:"ip"`
}

// eipEnsureReport is the output of eip ensure: the change report and the
// EIPs it stands for.
type eipEnsureReport struct {
	platform.Report `yaml:",inline"`
	Result          struct {
		EIPs []eipRef `json:"eips" yaml:"eips"`
	} `json:"result" yaml:"result"`
}

func eipEnsureCmd(rt *app.Runtime) *cobra.Command {
	var region, instance, bandwidth, isp, group string
	var count int
	var exclude []string
	cmd := &cobra.Command{
		Use:   "ensure",
		Short: "Make sure there are EIPs to use: reuse idle ones, allocate the rest",
		Long: `Make sure --count EIPs (1 by default) are there to use, and with --instance that
the instance holds one. Running it again changes nothing.

- An idle EIP of the account in the region is reused first (unchanged,
  "reuse idle"): bound to nothing, Available, not managed by a cloud product
  (a load balancer keeps its EIPs managed for up to a minute after letting
  them go) and of the ISP asked for (--isp). Any idle EIP of the account
  qualifies, whoever allocated it. --exclude leaves allocation ids out;
  the EIPs picked by one run are never picked twice.
- The rest are allocated (created; see aliyun eip address --help for
  --bandwidth, --isp and --resource-group) and read back once Available.
- --instance (name or id, found through the inventory in every selected
  account; the EIPs are those of its region) binds the EIP to the instance
  (updated) and waits until it is InUse. An instance that holds an EIP
  already is unchanged, and nothing is reused or allocated. --instance takes
  --count 1 only.
- -o json adds "result": {"eips": [{"allocation_id", "ip"}]}.`,
		Example: `  polyctl aliyun eip address ensure --count 2
  polyctl aliyun eip address ensure --instance site-a --dry-run`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if count < 1 {
				return app.UsageErrf("--count must be at least 1, got %d", count)
			}
			if instance != "" && count != 1 {
				return app.UsageErrf("--instance takes --count 1: an instance holds one EIP")
			}
			for _, x := range exclude {
				if !strings.HasPrefix(x, "eip-") {
					return app.UsageErrf("--exclude %q is not an EIP allocation id (eip-...)", x)
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			var s *ecsScope
			var inst *Instance
			var err error
			if instance != "" {
				if s, inst, err = instanceScope(ctx, rt, instance, region); err != nil {
					return err
				}
			} else if s, err = openECSScope(ctx, rt, region); err != nil {
				return err
			}
			spec, err := eipSettings(rt, s.profile, bandwidth, isp)
			if err != nil {
				return err
			}
			var plan platform.Plan
			var picked []*eipAddress
			if inst != nil && inst.EIP != "" {
				plan.Add(platform.Step{Resource: "eip/1", Action: platform.Unchanged, ID: inst.EIPAllocationID, Desc: "already bound " + inst.EIP + " to " + inst.ID})
				picked = append(picked, &eipAddress{AllocationID: inst.EIPAllocationID, IP: inst.EIP})
				return renderEIPEnsure(ctx, rt, s, &plan, picked)
			}
			eips, err := s.c.listEIPs(ctx, s.region, eipFilter{})
			if err != nil {
				return err
			}
			for _, e := range eips {
				storeEIP(ctx, rt, s.profile, e)
			}
			skip := map[string]bool{}
			for _, x := range exclude {
				skip[x] = true
			}
			var toAllocate int
			type slot struct {
				reuse *eipAddress
				fresh *eipAddress
			}
			slots := make([]slot, count)
			for i := range slots {
				if e := pickIdleEIP(eips, spec.ISP, skip); e != nil {
					skip[e.AllocationID] = true
					slots[i].reuse = e
				} else {
					slots[i].fresh = &eipAddress{}
					toAllocate++
				}
			}
			if toAllocate > 0 {
				if spec.ResourceGroup, err = resolveResourceGroup(ctx, rt, s, group); err != nil {
					return err
				}
			}
			for i, sl := range slots {
				res := "eip/" + strconv.Itoa(i+1)
				if sl.reuse != nil {
					plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: sl.reuse.AllocationID, Desc: "reuse idle " + sl.reuse.IP})
					picked = append(picked, sl.reuse)
				} else {
					plan.Add(allocateStep(rt, s, res, spec, sl.fresh))
					picked = append(picked, sl.fresh)
				}
			}
			if inst != nil {
				e := picked[0]
				label := e.IP
				if label == "" {
					label = platform.Pending
				}
				if inst.VpcID == "" {
					return fmt.Errorf("instance %s is in no VPC; an EIP can only be bound to a VPC instance", inst.ID)
				}
				plan.Add(associateStep(rt, s, inst, func() string { return e.AllocationID }, label))
			}
			return renderEIPEnsure(ctx, rt, s, &plan, picked)
		},
	}
	cmd.Flags().IntVar(&count, "count", 1, "how many EIPs to make sure of (a dual-zone load balancer needs 2)")
	cmd.Flags().StringVar(&instance, "instance", "", "bind the EIP to this ECS instance (name or id)")
	cmd.Flags().StringSliceVar(&exclude, "exclude", nil, "allocation ids never to reuse (repeatable)")
	addEIPSpecFlags(cmd, &bandwidth, &isp, &group)
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region, or the instance's)")
	return cmd
}

// renderEIPEnsure runs the plan of eip ensure and prints its report with
// the EIPs it stands for, like app.Runtime.Ensure does for a plain report.
func renderEIPEnsure(ctx context.Context, rt *app.Runtime, s *ecsScope, plan *platform.Plan, picked []*eipAddress) error {
	rep, err := rt.RunPlan(ctx, s.target(), plan)
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	out := eipEnsureReport{Report: rep}
	out.Result.EIPs = []eipRef{}
	for _, e := range picked {
		r := eipRef{AllocationID: e.AllocationID, IP: e.IP}
		if r.AllocationID == "" {
			r.AllocationID = platform.Pending
		}
		out.Result.EIPs = append(out.Result.EIPs, r)
	}
	if rerr := rt.Render(out, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
		err = rerr
	}
	if err != nil && !rep.DryRun && !errors.Is(err, app.ErrUsage) {
		rt.NotifyFailure(ctx, app.Failure{Event: "aliyun.eip.address.ensure.failed", Platform: string(platform.Aliyun), Profile: s.profile,
			Error: err.Error(), Changes: rep.Changes})
	}
	return err
}
