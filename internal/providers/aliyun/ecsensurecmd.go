package aliyun

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// defaultInstanceRules are the ingress rules ensure gives the security
// group when neither --rule nor defaults.aliyun.ecs_security_group_rules
// is set.
var defaultInstanceRules = []string{"icmp:all:0.0.0.0/0", "tcp:80:0.0.0.0/0", "tcp:443:0.0.0.0/0"}

// instanceResult is the "result" of instance ensure.
type instanceResult struct {
	InstanceID string `json:"instance_id" yaml:"instance_id"`
	PublicIP   string `json:"public_ip" yaml:"public_ip"`
}

// instanceEnsureReport is the output of instance ensure: the change report
// and the instance it stands for.
type instanceEnsureReport struct {
	platform.Report `yaml:",inline"`
	Result          instanceResult `json:"result" yaml:"result"`
}

func ecsEnsureCmd(rt *app.Runtime) *cobra.Command {
	var f instanceFlags
	var specs []string
	cmd := &cobra.Command{
		Use:   "ensure <name>",
		Short: "Make sure an ECS instance exists, with everything it needs, Running and with an EIP",
		Long: `Make sure the ECS instance <name> exists in the region (--region, else the
profile's), Running, with an EIP. Running it again changes nothing.

- An instance of the name (compared case-sensitively; several are exit code
  5) is used as it is: nothing it depends on is checked or repaired, and a
  --type or --disk that differs is reported skipped ("use resize"), never
  changed (a --type size is compared with the vCPUs and memory of the
  instance). A Stopped instance is reported skipped (start it); one that is
  Pending or Starting is waited for.
- Otherwise everything missing is created, in this order: the key pair (an
  existing one first: --key-pair, or the key pair holding --ssh-key /
  --ssh-key-file; no name is ever chosen for you), the VPC
  (naming.aliyun_vpc, {region}-vpc, 172.16.0.0/12, waited for until
  Available), its vSwitches in zones b and c (naming.aliyun_vswitch, the
  first free /22 blocks), the security group (--security-group, else
  naming.aliyun_ecs_security_group, sg-common) in that VPC with the --rule
  ingress rules (else defaults.aliyun.ecs_security_group_rules, else
  icmp:all, tcp:80 and tcp:443 from 0.0.0.0/0; missing rules are added,
  none removed), then the instance in the vSwitch of zone b (--vswitch
  places it in an existing vSwitch instead: the VPC and vSwitches are then
  not ensured). Nothing created is rolled back when a later step fails:
  running ensure again goes on from there.
- The instance is --type (defaults.aliyun.ecs_instance_type, else
  ecs.u1-c1m1.large; a type id, or a size <cores>H<memory>G such as 2H4G,
  see Instance sizes below), --image or the newest image of --os for the
  type's architecture (as for create, --os windows included), a --disk GiB
  --disk-category system disk, pay as you go, without a public address of
  its own. A Linux instance logs in with its key pair only (polyctl never
  sets a password). A new --os windows instance gets a generated
  Administrator password, stored encrypted and shown as create shows it
  (printed at the end when interactive; otherwise a note names
  ` + "`polyctl aliyun ecs instance password <name|id>`" + `); an existing
  instance keeps its password. It is waited for until Running (every 2 seconds, --timeout 10m);
  --no-wait returns at once and skips the EIP.
- --eip (default; --eip=false skips it) binds an idle EIP of the region,
  else a new one (see aliyun eip address), unless the instance holds one.
- Another account or region of the inventory holding an instance of the
  name is a note, not an error.
- -o json adds "result": {"instance_id", "public_ip"}.
` + instanceSizeHelp,
		Example: `  polyctl aliyun ecs instance ensure site-a --type ecs.u1-c1m1.large --disk 40 \
    --ssh-key-file ~/.ssh/id_ed25519.pub --key-pair ops --region cn-hongkong
  polyctl aliyun ecs instance ensure site-a --ssh-key-file ~/.ssh/id_ed25519.pub --dry-run`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			if err := checkInstanceName(name); err != nil {
				return err
			}
			host, renamed, err := normalizeHostName(name)
			if err != nil {
				return err
			}
			if err := f.check(cmd); err != nil {
				return err
			}
			if host, renamed, err = f.hostName(name, host, renamed); err != nil {
				return err
			}
			wait, timeout, err := f.wait.Resolve(cmd)
			if err != nil {
				return err
			}
			if _, err := platform.ParseIngressRules(specs); err != nil {
				return err
			}
			if _, err := f.keys.PublicKey(); err != nil {
				return err
			}
			if f.keys.KeyPair != "" {
				if err := checkKeyPairName(f.keys.KeyPair); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, f.region)
			if err != nil {
				return err
			}
			if f.typ, err = rt.Setting(s.profile, platform.Aliyun, "ecs_instance_type", f.typ); err != nil {
				return err
			}
			if f.typ == "" {
				f.typ = defaultInstanceType
			}
			if err := f.parseSize(); err != nil {
				return err
			}
			noteNamesakes(ctx, rt, s, name)

			found, err := s.c.findInstances(ctx, s.region, name)
			if err != nil {
				return err
			}
			e := &instanceEnsure{rt: rt, s: s, name: name, f: &f, wait: wait, timeout: timeout}
			switch len(found) {
			case 0:
				if renamed {
					rt.Infof("note: the host name of %s is %s (%s)", name, host, f.hostNameRule())
				}
				if err := e.planNew(ctx, cmd, host, specs); err != nil {
					return err
				}
			case 1:
				if err := e.planExisting(ctx, cmd, &found[0]); err != nil {
					return err
				}
			default:
				return ambiguousInstances(name, s, found)
			}
			return e.run(ctx)
		},
	}
	f.add(cmd, true, true, "instance type id, or a size <cores>H<memory>G such as 2H4G resolved to the cheapest x86 type in stock (default defaults.aliyun.ecs_instance_type, else "+defaultInstanceType+")", "security group, name (default naming.aliyun_ecs_security_group, sg-common) or id")
	cmd.Flags().StringArrayVar(&specs, "rule", nil, "ingress rule of the security group <protocol>:<port|from-to|alias|all>:<source> (repeatable; default defaults.aliyun.ecs_security_group_rules, else icmp, 80 and 443 from anywhere)")
	return cmd
}

// noteNamesakes notes instances of the name that the inventory knows in
// other accounts or regions: ensure creates its own all the same.
func noteNamesakes(ctx context.Context, rt *app.Runtime, s *ecsScope, name string) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Aliyun, Type: platform.ResInstance, Name: name})
	if err != nil {
		return
	}
	for _, r := range rows {
		if r.Name != name {
			continue
		}
		var in Instance
		_ = r.Decode(&in)
		region := in.Region
		if region == "" {
			region = r.ParentID
		}
		if r.Profile == s.profile && region == s.region {
			continue
		}
		rt.Infof("note: an instance named %s also exists in aliyun/%s/%s (%s); this ensure works in %s", name, r.Profile, region, r.ID, s.where())
	}
}

// instanceEnsure is the plan of one instance ensure.
type instanceEnsure struct {
	rt      *app.Runtime
	s       *ecsScope
	name    string
	f       *instanceFlags
	wait    bool
	timeout time.Duration
	plan    platform.Plan

	instID string
	eip    eipRef
	// knownIP is the EIP of an instance that holds one already.
	knownIP string
	// win is the login of a new Windows instance (nil otherwise: an
	// existing instance keeps its password).
	win *windowsLogin
}

func (e *instanceEnsure) id() string { return e.instID }

// planExisting reports an existing instance and plans what it may still
// need: the wait for Running and the EIP.
func (e *instanceEnsure) planExisting(ctx context.Context, cmd *cobra.Command, in *Instance) error {
	e.instID = in.ID
	storeInstance(ctx, e.rt, e.s.profile, *in)
	res := "instance/" + e.name
	step := platform.Step{Resource: res, Action: platform.Unchanged, ID: in.ID, Desc: fmt.Sprintf("%s %s %s", in.ID, in.Type, in.Status)}
	var differs []string
	switch {
	case !cmd.Flags().Changed("type"):
	case e.f.size != nil:
		// A size is compared with the size of the instance, whatever its
		// type: nothing is resolved for an existing instance.
		if !e.f.size.Matches(in.CPU, in.MemoryMB) {
			differs = append(differs, fmt.Sprintf("size differs: current %s (%s), want %s; use resize", in.Type, instanceSize(in), e.f.size))
		}
	case in.Type != e.f.typ:
		differs = append(differs, fmt.Sprintf("type differs: current %s, want %s; use resize", in.Type, e.f.typ))
	}
	if cmd.Flags().Changed("disk") {
		size, err := e.s.c.systemDiskSize(ctx, e.s.region, in.ID)
		if err != nil {
			return err
		}
		if size != 0 && size != e.f.disk {
			differs = append(differs, fmt.Sprintf("system disk differs: current %dGiB, want %dGiB; not changed", size, e.f.disk))
		}
	}
	if len(differs) > 0 {
		step.Action = platform.Skipped
		step.Desc = in.ID + ": " + strings.Join(differs, "; ")
	}
	e.plan.Add(step)

	statusRes := res + " status"
	running := false
	switch in.Status {
	case instRunning:
		running = true
		e.plan.Add(platform.Step{Resource: statusRes, Action: platform.Unchanged, ID: in.ID, Desc: instRunning})
	case instPending, instStarting:
		if e.wait {
			running = true
			e.plan.Add(waitStep(e.rt, e.s, e.name, e.id, e.timeout))
		} else {
			e.plan.Add(platform.Step{Resource: statusRes, Action: platform.Skipped, ID: in.ID, Desc: in.Status + ": not waited for (--no-wait)"})
		}
	default:
		hint := ""
		if in.Status == instStopped {
			hint = fmt.Sprintf("; start it with `polyctl aliyun ecs instance start %s`", in.ID)
		}
		e.plan.Add(platform.Step{Resource: statusRes, Action: platform.Skipped, ID: in.ID, Desc: in.Status + hint})
	}
	if !e.f.eip {
		return nil
	}
	eipRes := "eip/" + e.name
	switch {
	case in.EIP != "":
		e.knownIP = in.EIP
		e.eip = eipRef{AllocationID: in.EIPAllocationID, IP: in.EIP}
		e.plan.Add(platform.Step{Resource: eipRes, Action: platform.Unchanged, ID: in.EIPAllocationID, Desc: "EIP " + in.EIP + " already bound"})
	case !running:
		e.plan.Add(platform.Step{Resource: eipRes, Action: platform.Skipped, Desc: "instance not Running yet"})
	default:
		ep, err := planEIP(ctx, e.rt, e.s)
		if err != nil {
			return err
		}
		step := eipStep(e.rt, e.s, e.name, e.id, ep, &e.eip)
		if in.PublicIP != "" {
			step.Desc += " (the instance also has its own public address " + in.PublicIP + ")"
		}
		e.plan.Add(step)
	}
	return nil
}

// planNew plans the whole chain: key pair, VPC, vSwitches, security
// group, rules, the instance, the wait and the EIP.
func (e *instanceEnsure) planNew(ctx context.Context, cmd *cobra.Command, host string, specs []string) error {
	rt, s := e.rt, e.s
	var kp platform.KeyPairPlan
	if e.f.windows() {
		e.win = newWindowsLogin(rt, s, e.name)
	} else {
		in, err := e.f.keyInput(rt)
		if err != nil {
			return err
		}
		var kpStep platform.Step
		if kp, kpStep, err = resolveKeyPairStep(ctx, rt, s, in); err != nil {
			return err
		}
		e.plan.Add(kpStep)
	}

	image, err := e.f.resolveImage(ctx, rt, s)
	if err != nil {
		return err
	}

	// The network: the VPC and its vSwitches, or --vswitch.
	var vpcID, vswID string
	vpcPending := false
	vswFresh := false
	if e.f.vswitch != "" {
		v, err := resolveVSwitch(ctx, s, e.f.vswitch, "")
		if err != nil {
			return err
		}
		if e.f.size != nil {
			if err := e.f.resolveSize(ctx, rt, cmd, s, image, []string{v.Zone}); err != nil {
				return err
			}
		}
		vpcID, vswID = v.VPC, v.ID
		e.plan.Add(platform.Step{Resource: "vswitch/" + orID(v.Name, v.ID), Action: platform.Unchanged, ID: v.ID, Desc: v.ID + " " + v.Zone + " " + v.CIDR})
	} else {
		vpcName, err := rt.ResourceName("aliyun_vpc", "", map[string]string{"region": s.region})
		if err != nil {
			return err
		}
		if err := checkNetName("VPC", "vpc-", vpcName); err != nil {
			return err
		}
		var wants []vswWant
		for _, suffix := range defaultZones {
			z := zoneTarget{ID: s.region + "-" + suffix, Suffix: suffix}
			n, err := vswName(rt, s.region, "", z)
			if err != nil {
				return err
			}
			wants = append(wants, vswWant{Name: n, Zone: z})
		}
		// The instance goes in the vSwitch of zone b, or with a --type size
		// in that of the zone the size resolved to.
		place := wants[0]
		if e.f.size != nil {
			var zones []string
			for _, w := range wants {
				zones = append(zones, w.Zone.ID)
			}
			if err := e.f.resolveSize(ctx, rt, cmd, s, image, zones); err != nil {
				return err
			}
			for _, w := range wants {
				if w.Zone.ID == e.f.choice.Zone {
					place = w
				}
			}
		}
		vpcs, err := s.c.findVPCs(ctx, s.region, vpcName)
		if err != nil {
			return err
		}
		vp := vswPlan{rt: rt, s: s, vpcID: func() string { return vpcID }, mask: defaultVSwitchMask, wait: true,
			created: func(name, id string) {
				if name == place.Name {
					vswID, vswFresh = id, true
				}
			}}
		switch len(vpcs) {
		case 0:
			vpcPending = true
			vp.vpcCIDR, vp.pending = defaultVPCCIDR, true
			e.plan.Add(vpcCreateStep(s, vpcName, defaultVPCCIDR, true, vpcWaitTimeout, &vpcID))
		case 1:
			v := vpcs[0]
			vpcID, vp.vpcCIDR = v.ID, v.CIDR
			step := platform.Step{Resource: "vpc/" + vpcName, Action: platform.Unchanged, ID: v.ID, Desc: v.ID + " " + v.CIDR}
			if v.Status != statusAvailable {
				step.Desc += " (" + orDash(v.Status) + ")"
				step.Apply = func(ctx context.Context) (platform.Change, error) {
					if err := waitVPC(ctx, s, v.ID, vpcWaitTimeout); err != nil {
						return platform.Change{}, err
					}
					return platform.Change{Detail: v.ID + " " + v.CIDR + " (now Available)"}, nil
				}
			}
			e.plan.Add(step)
			if vp.existing, err = s.c.listVSwitches(ctx, s.region, v.ID, "", ""); err != nil {
				return err
			}
			if have := pickVSwitch(vp.existing, place); have != nil {
				vswID = have.ID
			}
		default:
			var ids []string
			for _, v := range vpcs {
				ids = append(ids, v.ID)
			}
			return &app.AmbiguousError{What: fmt.Sprintf("VPC %q in %s", vpcName, s.where()), Candidates: ids,
				Hint: "Alibaba Cloud lets several VPCs share a name; rename one, set naming.aliyun_vpc, or pass --vswitch"}
		}
		if err := vp.add(&e.plan, wants); err != nil {
			return err
		}
	}

	// The security group and its rules.
	sgRef, err := rt.ResourceName("aliyun_ecs_security_group", e.f.securityGroup, map[string]string{"region": s.region})
	if err != nil {
		return err
	}
	ruleSpecs, err := rt.SettingList(s.profile, platform.Aliyun, "ecs_security_group_rules", specs)
	if err != nil {
		return err
	}
	if len(ruleSpecs) == 0 {
		ruleSpecs = defaultInstanceRules
	}
	rules, err := platform.ParseIngressRules(ruleSpecs)
	if err != nil {
		if len(specs) == 0 {
			return app.UsageErrf("defaults.aliyun.ecs_security_group_rules: %v", err)
		}
		return err
	}
	if err := checkInstanceSGName(sgRef); err != nil {
		return err
	}
	lookIn := vpcID
	if vpcPending {
		lookIn = ""
	}
	sg, err := findInstanceSG(ctx, s, sgRef, lookIn)
	if err != nil {
		return err
	}
	if sg != nil && (vpcPending || sg.VPC != vpcID) {
		return fmt.Errorf("security group %s is in VPC %s, not in the instance's VPC %s: pass a security group name to create one there", sg.ID, sg.VPC, orPending(vpcID, vpcPending))
	}
	sgLabel := sgRef
	if sg != nil && sg.Name != "" {
		sgLabel = sg.Name
	}
	sgRes := "security-group/" + sgLabel
	var groupID string
	var groupCreated bool
	missing, present := rules, []platform.IngressRule(nil)
	if sg != nil {
		groupID = sg.ID
		storeSG(ctx, rt, s, *sg)
		e.plan.Add(platform.Step{Resource: sgRes, Action: platform.Unchanged, ID: sg.ID, Desc: sg.ID + " " + sg.VPC})
		have, err := s.c.securityGroupRules(ctx, s.region, sg.ID)
		if err != nil {
			return err
		}
		missing, present = splitRules(have, rules)
	} else {
		desc := "vpc " + orPending(vpcID, vpcPending)
		e.plan.Add(platform.Step{Resource: sgRes, Action: platform.Created, Desc: desc, Apply: func(ctx context.Context) (platform.Change, error) {
			id, err := s.c.createSecurityGroup(ctx, s.region, sgRef, vpcID, "")
			if err != nil {
				return platform.Change{}, err
			}
			groupID, groupCreated = id, true
			refreshSG(ctx, rt, s, id)
			return platform.Change{ID: id, Detail: id + " " + vpcID}, nil
		}})
	}
	addRuleSteps(&e.plan, rt, s, sgRes+"/rule", func() string { return groupID }, func() bool { return groupCreated }, missing, present, sgPriorityDefault, "")

	// The instance.
	e.plan.Add(runStep(rt, s, e.name, host, e.f, image, func() string { return groupID }, func() string { return vswID },
		func() string { return kp.Name }, func() bool { return groupCreated || vswFresh }, e.win, &e.instID))
	if e.wait {
		e.plan.Add(waitStep(rt, s, e.name, e.id, e.timeout))
	}
	if e.f.eip {
		if !e.wait {
			e.plan.Add(platform.Step{Resource: "eip/" + e.name, Action: platform.Skipped, Desc: "instance not Running yet (--no-wait)"})
			return nil
		}
		ep, err := planEIP(ctx, rt, s)
		if err != nil {
			return err
		}
		e.plan.Add(eipStep(rt, s, e.name, e.id, ep, &e.eip))
	}
	return nil
}

// pickVSwitch returns the existing vSwitch a want stands for, as vswPlan
// picks it: the only one of the name, else the only one of the name in the
// zone.
func pickVSwitch(existing []vSwitch, w vswWant) *vSwitch {
	var named []vSwitch
	for _, v := range existing {
		if v.Name == w.Name {
			named = append(named, v)
		}
	}
	if len(named) == 1 {
		return &named[0]
	}
	var inZone []vSwitch
	for _, v := range named {
		if v.Zone == w.Zone.ID {
			inZone = append(inZone, v)
		}
	}
	if len(inZone) == 1 {
		return &inZone[0]
	}
	return nil
}

func orPending(id string, pending bool) string {
	if pending || id == "" {
		return platform.Pending
	}
	return id
}

// run runs the plan and prints the report with the result.
func (e *instanceEnsure) run(ctx context.Context) error {
	rt := e.rt
	if e.win != nil {
		// Before the first write: a password that cannot be stored would
		// be lost once the instance exists.
		if err := rt.PrepareSecrets(); err != nil {
			return fmt.Errorf("the Windows password could not be stored, nothing was created: %w", err)
		}
	}
	rep, err := rt.RunPlan(ctx, e.s.target(), &e.plan)
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	out := instanceEnsureReport{Report: rep}
	out.Result.InstanceID = e.instID
	if out.Result.InstanceID == "" {
		out.Result.InstanceID = platform.Pending
	}
	out.Result.PublicIP = e.knownIP
	if e.eip.IP != "" {
		out.Result.PublicIP = e.eip.IP
	}
	if err == nil && !rep.DryRun && out.Result.PublicIP != "" {
		rt.Infof("instance %s (%s): public ip %s", e.name, out.Result.InstanceID, out.Result.PublicIP)
	}
	if rerr := rt.Render(out, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
		err = rerr
	}
	if werr := e.win.finish(ctx); werr != nil {
		err = errors.Join(err, werr)
	}
	if err != nil && !rep.DryRun && !errors.Is(err, app.ErrUsage) {
		rt.NotifyFailure(ctx, app.Failure{Event: "aliyun.ecs.instance.ensure.failed", Platform: string(platform.Aliyun), Profile: e.s.profile,
			Error: err.Error(), Changes: rep.Changes})
	}
	return err
}
