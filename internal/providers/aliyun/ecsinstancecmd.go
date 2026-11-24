package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// ------------------------------------------------------------ routing

// resolveECSInstance finds the instance ref names (an id, i-..., or a
// name) and opens the account that holds it in its region. With region,
// the selected profile is asked directly in that region. Otherwise the
// inventory tells which account and region hold it (one sync of the stale
// accounts when none does; several matches are ambiguous, exit code 5),
// and the instance is then read live by id. Names are compared
// case-sensitively: Alibaba Cloud does not keep them unique, and its name
// filter ignores case.
func resolveECSInstance(ctx context.Context, rt *app.Runtime, ref, region string) (*ecsScope, *Instance, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, nil, app.UsageErrf("the instance name or id is empty")
	}
	if rt.Flags.Offline {
		return nil, nil, app.ErrOffline
	}
	if region != "" {
		s, err := openECSScope(ctx, rt, region)
		if err != nil {
			return nil, nil, err
		}
		in, err := findInstanceIn(ctx, s, ref)
		if err != nil {
			return nil, nil, err
		}
		storeInstance(ctx, rt, s.profile, *in)
		return s, in, nil
	}
	res, err := rt.ResolveResource(ctx, platform.Aliyun, platform.ResInstance, ref)
	if err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return nil, nil, fmt.Errorf("%w (an instance outside the profile's region is found with --region <region>)", err)
		}
		return nil, nil, err
	}
	var cached Instance
	_ = res.Decode(&cached)
	instRegion := cached.Region
	if instRegion == "" {
		instRegion = res.ParentID
	}
	c, err := openNamed(rt, ctx, res.Profile)
	if err != nil {
		return nil, nil, err
	}
	s := &ecsScope{c: c, profile: res.Profile, region: c.regionOr(instRegion)}
	in, err := c.describeInstance(ctx, s.region, res.ID)
	if errors.Is(err, platform.ErrNotFound) {
		dropInstance(ctx, rt, res.Profile, res.ID)
		return nil, nil, fmt.Errorf("%w: instance %s (%s) no longer exists in %s (removed from the local inventory)", platform.ErrNotFound, ref, res.ID, s.where())
	}
	if err != nil {
		return nil, nil, err
	}
	storeInstance(ctx, rt, s.profile, *in)
	return s, in, nil
}

// findInstanceIn returns the instance ref names in the scope's region.
func findInstanceIn(ctx context.Context, s *ecsScope, ref string) (*Instance, error) {
	if looksLikeInstanceID(ref) {
		return s.c.describeInstance(ctx, s.region, ref)
	}
	found, err := s.c.findInstances(ctx, s.region, ref)
	if err != nil {
		return nil, err
	}
	switch len(found) {
	case 0:
		return nil, fmt.Errorf("%w: instance %q in %s", platform.ErrNotFound, ref, s.where())
	case 1:
		return &found[0], nil
	}
	return nil, ambiguousInstances(ref, s, found)
}

func ambiguousInstances(ref string, s *ecsScope, found []Instance) error {
	var ids []string
	for _, in := range found {
		ids = append(ids, in.ID+" ("+in.Status+")")
	}
	return &app.AmbiguousError{What: fmt.Sprintf("instance %q in %s", ref, s.where()), Candidates: ids,
		Hint: "Alibaba Cloud lets several instances share a name; pass the instance id"}
}

// ---------------------------------------------------------------- get

// instanceDetail is the output of `instance get`.
type instanceDetail struct {
	Name             string   `json:"name" yaml:"name"`
	ID               string   `json:"id" yaml:"id"`
	Profile          string   `json:"profile" yaml:"profile"`
	Region           string   `json:"region" yaml:"region"`
	Zone             string   `json:"zone" yaml:"zone"`
	Type             string   `json:"type" yaml:"type"`
	Status           string   `json:"status" yaml:"status"`
	PublicIP         string   `json:"public_ip" yaml:"public_ip"`
	PrivateIP        string   `json:"private_ip" yaml:"private_ip"`
	EIP              *eipRef  `json:"eip" yaml:"eip"`
	VpcID            string   `json:"vpc_id" yaml:"vpc_id"`
	VSwitchID        string   `json:"vswitch_id" yaml:"vswitch_id"`
	SecurityGroupIDs []string `json:"security_group_ids" yaml:"security_group_ids"`
	KeyPair          string   `json:"key_pair" yaml:"key_pair"`
	CreatedAt        string   `json:"created_at" yaml:"created_at"`
	Cached           bool     `json:"cached" yaml:"cached"`
}

func detailOf(profile string, in Instance, cached bool) instanceDetail {
	d := instanceDetail{Name: in.Name, ID: in.ID, Profile: profile, Region: in.Region, Zone: in.Zone, Type: in.Type, Status: in.Status,
		PublicIP: in.PublicIP, PrivateIP: in.PrivateIP, VpcID: in.VpcID, VSwitchID: in.VSwitchID, KeyPair: in.KeyPair,
		SecurityGroupIDs: in.SecurityGroupIDs, CreatedAt: createdAt(in.CreationTime), Cached: cached}
	if d.SecurityGroupIDs == nil {
		d.SecurityGroupIDs = []string{}
	}
	if in.EIP != "" {
		d.EIP = &eipRef{AllocationID: in.EIPAllocationID, IP: in.EIP}
	}
	return d
}

// createdAt writes a creation time as RFC 3339; Alibaba Cloud keeps minutes
// only (2026-11-17T16:10Z). A value it cannot read is kept as it is.
func createdAt(s string) string {
	if t, ok := parseKeyPairTime(s); ok {
		return t.UTC().Format(time.RFC3339)
	}
	return s
}

func detailGrid(d instanceDetail) output.Grid {
	eip := "no"
	if d.EIP != nil {
		eip = "yes"
	}
	return output.Grid{Headers: []string{"NAME", "ID", "REGION", "TYPE", "STATUS", "PUBLIC_IP", "PRIVATE_IP", "EIP"},
		Rows: [][]string{{d.Name, d.ID, d.Region, d.Type, d.Status, d.PublicIP, d.PrivateIP, eip}}}
}

func ecsGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show an ECS instance with its addresses",
		Long: `Show an ECS instance: its type, status, public and private address and EIP.
<name|id> is an instance id (i-...) or a name. Without --region the local
inventory tells which account and region hold it (synced once when it does
not know the instance; several instances of the name are ambiguous, exit
code 5, pass the id), and the instance is then read live. With --region the
selected profile is asked in that region. The public address is the
instance's own one, else its EIP's; the private address is the primary
address of its network interface. With --offline the local inventory is
shown as it is (exit code 6 when it does not hold the instance).`,
		Example: "  polyctl aliyun ecs instance get site-a -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if rt.Flags.Offline {
				res, err := rt.ResolveResource(ctx, platform.Aliyun, platform.ResInstance, args[0])
				if errors.Is(err, platform.ErrNotFound) {
					return fmt.Errorf("%w: instance %q is not in the local inventory", app.ErrOffline, args[0])
				}
				if err != nil {
					return err
				}
				var in Instance
				if err := res.Decode(&in); err != nil {
					return fmt.Errorf("decode cached instance %s: %w", res.ID, err)
				}
				d := detailOf(res.Profile, in, true)
				rt.Infof("instance %s via aliyun/%s (local inventory; --refresh reads it again)", in.ID, res.Profile)
				return rt.Render(d, func() output.Grid { return detailGrid(d) })
			}
			s, in, err := resolveECSInstance(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			d := detailOf(s.profile, *in, false)
			if d.Region == "" {
				d.Region = s.region
			}
			rt.Infof("instance %s in %s", in.ID, s.where())
			return rt.Render(d, func() output.Grid { return detailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	return cmd
}

// ------------------------------------------------------------- create

// instanceFlags are the flags create and ensure share.
type instanceFlags struct {
	typ, image, osName, diskCategory, vswitch, securityGroup string
	disk                                                     int
	keys                                                     app.KeyFlags
	eip                                                      bool
	wait                                                     app.WaitFlags
	region                                                   string
	// size is --type written as <cores>H<memory>G (nil for a type id);
	// choice is the type it resolved to.
	size   *platform.TypeShorthand
	choice *typeChoice
	// diskSet reports that --disk was given; imageWindows that --image is
	// a Windows image (known once inspectImage has read it).
	diskSet      bool
	imageWindows bool
}

func (f *instanceFlags) add(cmd *cobra.Command, eipDefault, waitDefault bool, typeHelp, sgHelp string) {
	cmd.Flags().StringVar(&f.typ, "type", "", typeHelp)
	cmd.Flags().StringVar(&f.image, "image", "", "image id (default: the newest image of --os)")
	cmd.Flags().StringVar(&f.osName, "os", osAlibabaCloudLinux, "operating system of the newest public image used when --image is not given: "+supportedOSes)
	cmd.Flags().IntVar(&f.disk, "disk", defaultSystemDiskGiB, "system disk size in GiB (at least the image's size; for a Windows instance the default is 40, the least it takes, or a Windows --image's size if larger)")
	cmd.Flags().StringVar(&f.diskCategory, "disk-category", defaultSystemDiskCat, "system disk category (cloud_essd_entry, cloud_essd, cloud_auto, ...)")
	cmd.Flags().StringVar(&f.vswitch, "vswitch", "", "vSwitch of the instance, id or name (it decides the zone)")
	cmd.Flags().StringVar(&f.securityGroup, "security-group", "", sgHelp)
	app.AddKeyFlags(cmd, &f.keys)
	eipHelp := "bind an EIP once the instance is Running (an idle EIP is reused, else one is allocated)"
	if eipDefault {
		eipHelp += "; --eip=false skips it"
	}
	cmd.Flags().BoolVar(&f.eip, "eip", eipDefault, eipHelp)
	app.AddWaitFlags(cmd, &f.wait, waitDefault, defaultInstanceTimeout)
	cmd.Flags().StringVar(&f.region, "region", "", "region id (default: the profile's region)")
}

// check validates the flags that need no account.
func (f *instanceFlags) check(cmd *cobra.Command) error {
	if f.disk <= 0 {
		return app.UsageErrf("--disk must be a positive number of GiB, got %d", f.disk)
	}
	if strings.TrimSpace(f.diskCategory) == "" {
		return app.UsageErrf("--disk-category is empty")
	}
	f.diskSet = cmd.Flags().Changed("disk")
	if f.image != "" && cmd.Flags().Changed("os") {
		return app.UsageErrf("--image and --os are mutually exclusive")
	}
	if f.image == "" {
		if _, ok := osImageFamilyPatterns[f.osName]; !ok {
			return app.UsageErrf("unsupported os %q: --os takes %s (pass --image <id> for any other system)", f.osName, supportedOSes)
		}
	}
	if f.windows() {
		if f.keys.Given() {
			return app.UsageErrf("--os windows takes no --key-pair, --ssh-key or --ssh-key-file: ECS key pairs are for Linux instances only; a Windows instance logs in as %s with a password polyctl generates and stores encrypted (`polyctl %s password <name|id>` shows it)", windowsUser, ecsInstanceTree)
		}
		if !f.diskSet {
			f.disk = windowsMinDiskGiB
		} else if f.disk < windowsMinDiskGiB {
			return app.UsageErrf("--os windows needs --disk %d or more (the Windows Server images are %d GiB), got %d", windowsMinDiskGiB, windowsMinDiskGiB, f.disk)
		}
	}
	if _, _, err := platform.ParseTypeShorthand(f.typ); err != nil {
		return err
	}
	return nil
}

// windows reports a Windows instance: the newest Windows Server image
// (--os windows), or an --image that inspectImage found to be a Windows
// image. It takes no key pair but a generated Administrator password, a
// system disk of windowsMinDiskGiB or more and a Windows host name.
func (f *instanceFlags) windows() bool {
	return f.imageWindows || (f.image == "" && f.osName == osWindows)
}

// inspectImage reads --image (a read-only call, made in a dry run too) to
// tell a Windows image from a Linux one: only then is it known whether the
// instance takes a key pair or a generated password. A Windows image
// refuses the key pair flags (a usage error, before anything is written)
// and gets a system disk of at least windowsMinDiskGiB and the image's
// size unless --disk is given. An image that does not exist is
// platform.ErrNotFound. Without --image it does nothing.
func (f *instanceFlags) inspectImage(ctx context.Context, rt *app.Runtime, s *ecsScope) error {
	if f.image == "" {
		return nil
	}
	im, err := s.c.describeImage(ctx, s.region, f.image)
	if err != nil {
		return err
	}
	if !windowsImage(im) {
		return nil
	}
	f.imageWindows = true
	if f.keys.Given() {
		return app.UsageErrf("--image %s is a Windows image, which takes no --key-pair, --ssh-key or --ssh-key-file: ECS key pairs are for Linux instances only; a Windows instance logs in as %s with a password polyctl generates and stores encrypted (`polyctl %s password <name|id>` shows it)", f.image, windowsUser, ecsInstanceTree)
	}
	least := max(windowsMinDiskGiB, im.Size)
	switch {
	case !f.diskSet:
		f.disk = max(f.disk, least)
	case f.disk < im.Size:
		return app.UsageErrf("Windows image %s needs --disk %d or more (its size), got %d", f.image, im.Size, f.disk)
	}
	label := imageFrom(s.region, im).OSName
	if label == "" {
		label = im.ImageName
	}
	rt.Infof("note: image %s is a Windows image (%s): the instance logs in as %s with a generated password, no key pair", f.image, label, windowsUser)
	return nil
}

// hostName fits the host name of an instance to its OS: a Windows host
// name holds no dots, at most 15 characters, and not only digits.
func (f *instanceFlags) hostName(name, host string, renamed bool) (string, bool, error) {
	if !f.windows() {
		return host, renamed, nil
	}
	h := strings.ReplaceAll(host, ".", "-")
	if len(h) > windowsHostNameMax {
		h = h[:windowsHostNameMax]
	}
	h = strings.Trim(h, "-")
	if len(h) < hostNameMin || strings.Trim(h, "0123456789") == "" {
		return "", false, app.UsageErrf("instance name %q gives no usable Windows host name (%d to %d letters, digits and hyphens, not only digits)", name, hostNameMin, windowsHostNameMax)
	}
	return h, h != name, nil
}

// hostNameRule says what the host names of the instance's OS hold.
func (f *instanceFlags) hostNameRule() string {
	if f.windows() {
		return "Windows host names hold letters, digits and hyphens only, at most 15 characters"
	}
	return "host names hold letters, digits, hyphens and dots only"
}

// parseSize reads --type as a <cores>H<memory>G size: f.size stays nil
// for an exact type id. A malformed size is a usage error.
func (f *instanceFlags) parseSize() error {
	sz, ok, err := platform.ParseTypeShorthand(f.typ)
	if err != nil {
		return err
	}
	f.size = nil
	if ok {
		f.size = &sz
	}
	return nil
}

// resolveSize resolves f.size to the cheapest x86 type in stock in one of
// zones (a read-only step, made in a dry run too) and puts that type and
// the system disk category it takes in f.
func (f *instanceFlags) resolveSize(ctx context.Context, rt *app.Runtime, cmd *cobra.Command, s *ecsScope, image string, zones []string) error {
	ch, err := s.c.resolveTypeSize(ctx, s.region, typeRequest{Size: *f.size, Zones: zones, Image: image, DiskGiB: f.disk,
		DiskCategory: f.diskCategory, DiskFixed: cmd.Flags().Changed("disk-category")})
	if err != nil {
		return err
	}
	rt.Infof("%s", ch.note())
	if ch.DiskCategory != f.diskCategory {
		rt.Infof("note: %s offers no %s system disk in %s: the system disk is %s", ch.Type, f.diskCategory, ch.Zone, ch.DiskCategory)
	}
	f.typ, f.diskCategory, f.choice = ch.Type, ch.DiskCategory, ch
	return nil
}

// typeLabel is the type in the change report, with the size it was
// resolved from.
func (f *instanceFlags) typeLabel() string {
	if f.choice == nil {
		return f.typ
	}
	return f.typ + " " + f.choice.label()
}

// resolveImage returns --image, else the newest public image of --os for
// the architecture of the instance type (read-only calls, made in a dry
// run too). A size resolves to an x86 type; a type id is looked up.
func (f *instanceFlags) resolveImage(ctx context.Context, rt *app.Runtime, s *ecsScope) (string, error) {
	if f.image != "" {
		return f.image, nil
	}
	arch := archX86
	if f.size == nil {
		a, known, err := s.c.typeArch(ctx, s.region, f.typ)
		if err != nil {
			return "", err
		}
		if !known {
			rt.Infof("note: %s does not list instance type %s: its image is picked for %s", s.where(), f.typ, archX86)
		}
		arch = a
	}
	if err := checkImageOS(f.osName, arch); err != nil {
		return "", err
	}
	im, err := s.c.latestImage(ctx, s.region, f.osName, arch)
	if err != nil {
		return "", err
	}
	rt.Infof("image: %s (%s, %s, created %s)", im.ImageID, im.OSName, arch, im.CreationTime)
	return im.ImageID, nil
}

// keyInput is the key pair input of create and ensure.
func (f *instanceFlags) keyInput(rt *app.Runtime) (platform.KeyInput, error) {
	if f.keys.KeyPair != "" {
		if err := checkKeyPairName(f.keys.KeyPair); err != nil {
			return platform.KeyInput{}, err
		}
	}
	in, err := rt.KeyInput(&f.keys, platform.KeyInput{Match: platform.MatchByFingerprintMD5,
		AllowedTypes: platform.AliyunKeyTypes, MinNameLength: keyPairNameMin})
	if err != nil {
		return in, err
	}
	if in.Key != nil {
		if err := in.Key.CheckType(platform.AliyunKeyTypes); err != nil {
			return in, err
		}
	}
	return in, nil
}

// instanceSizeHelp explains --type <cores>H<memory>G in the help of create
// and ensure.
const instanceSizeHelp = `
Instance sizes: --type <cores>H<memory>G (2H4G, 4H8G, 1H0.5G; any case)
is resolved on every run, in a dry run too, and never remembered (stock
and prices change). The candidates are the x86 types of exactly that many
vCPUs and GiB in stock for pay-as-you-go instances, in the zones the
instance may go to (the zone of --vswitch, else the zones of the default
vSwitches, b and c); each is priced by the hour with the image and the
system disk the instance gets, the cheapest wins (ties: the type name,
then the zone), and its zone places the instance. The system disk is
--disk-category when the type offers it there, else (unless
--disk-category was given) the first offered of cloud_essd_entry,
cloud_essd, cloud_auto, cloud_efficiency, cloud_ssd. The choice is printed
on stderr ("2H4G -> ecs.e-c1m2.large (cn-hongkong-b, 0.0123 CNY/hour)")
and shown in the change report. The memory must match exactly (a 3.5 GiB
type is not 4 GiB): no match is exit code 4, and a size of 0 vCPUs or
0 GiB is exit code 2. Anything else is a type id, used as it is.`

// createDesc describes the instance a step creates.
func createDesc(typ string, disk int, category, image string) string {
	return fmt.Sprintf("%s, system disk %dGiB %s, image %s", typ, disk, category, image)
}

// runStep is the step that creates the instance; the ids of the security
// group, the vSwitch and the key pair are read when it runs (an earlier
// step may create them). It stores the new id in *id.
// fresh reports that the group or the vSwitch was created by this run: a
// RunInstances that does not find them yet is then retried a few times.
//
// win is the login of a Windows instance (nil for Linux): the password is
// generated when the step runs, never in a dry run, and the credentials
// are stored as soon as RunInstances answers the instance id.
func runStep(rt *app.Runtime, s *ecsScope, name, host string, f *instanceFlags, image string, sg, vsw, kp func() string, fresh func() bool, win *windowsLogin, id *string) platform.Step {
	desc := createDesc(f.typeLabel(), f.disk, f.diskCategory, image)
	if host != name {
		desc += ", host name " + host
	}
	if win != nil {
		desc += ", login " + windowsUser + " with a generated password"
	}
	return platform.Step{Resource: "instance/" + name, Action: platform.Created, Desc: desc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			spec := runSpec{Name: name, HostName: host, Type: f.typ, Image: image, SecurityGroup: sg(), VSwitch: vsw(), KeyPair: kp(),
				DiskGiB: f.disk, DiskCategory: f.diskCategory}
			if win != nil {
				p, err := win.generate()
				if err != nil {
					return platform.Change{}, fmt.Errorf("generate the Windows password: %w", err)
				}
				spec.Password = p
			}
			spec.ClientToken = spec.token(s.profile, s.region)
			call := func(ctx context.Context) (string, error) {
				var iid string
				run := func(ctx context.Context) error {
					var err error
					iid, err = s.c.runInstance(ctx, s.region, spec)
					return err
				}
				var err error
				if fresh != nil && fresh() {
					err = platform.Retry(ctx, platform.RetryPolicy{Codes: []string{errSGIDNotFound, errVSwitchNotExist}, Initial: 2 * time.Second,
						Max: 4 * time.Second, MaxAttempts: 5, Clock: netClock()}, run)
				} else {
					err = run(ctx)
				}
				return iid, err
			}
			iid, err := call(ctx)
			if err != nil {
				return platform.Change{}, err
			}
			in, lerr := lookupNewInstance(ctx, s, iid)
			if errors.Is(lerr, platform.ErrNotFound) {
				// The token is derived from the content of the request: an
				// instance of the same name and settings created and deleted
				// before is answered again. Ask once more under a new token.
				rt.Infof("note: RunInstances answered %s, an instance of an earlier identical request that no longer exists; asking again with a new client token", iid)
				spec.ClientToken = platform.ClientToken(spec.ClientToken, netClock().Now().UnixNano())
				if iid, err = call(ctx); err != nil {
					return platform.Change{}, err
				}
				in, lerr = lookupNewInstance(ctx, s, iid)
			}
			*id = iid
			if win != nil {
				win.created(ctx, iid)
			}
			if lerr == nil && in != nil {
				storeInstance(ctx, rt, s.profile, *in)
			} else {
				storeInstance(ctx, rt, s.profile, Instance{ID: iid, Name: name, Type: f.typ, Region: s.region, Status: instPending})
			}
			detail := iid + " " + f.typeLabel()
			if host != name {
				detail += " (host name " + host + ")"
			}
			return platform.Change{ID: iid, Detail: detail}, nil
		}}
}

// waitStep is the "instance/<name> status" step: it waits until the
// instance is Running.
func waitStep(rt *app.Runtime, s *ecsScope, name string, id func() string, timeout time.Duration) platform.Step {
	return platform.Step{Resource: "instance/" + name + " status", Action: platform.Updated, Desc: "wait " + instRunning,
		Apply: func(ctx context.Context) (platform.Change, error) {
			took, err := waitInstanceRunning(ctx, s, id(), name, timeout)
			if err != nil {
				return platform.Change{ID: id()}, fmt.Errorf("instance %s (%s) was created and is kept; run ensure again to go on: %w", name, id(), err)
			}
			if in, err := s.c.describeInstance(ctx, s.region, id()); err == nil {
				storeInstance(ctx, rt, s.profile, *in)
			}
			return platform.Change{ID: id(), Detail: fmt.Sprintf("%s (waited %s)", instRunning, took.Round(time.Second))}, nil
		}}
}

// eipPlan decides how an instance without an EIP gets one: an idle EIP of
// the region (read now, in a dry run too), else a new one.
type eipPlan struct {
	idle *eipAddress
	spec eipSpec
}

func planEIP(ctx context.Context, rt *app.Runtime, s *ecsScope) (eipPlan, error) {
	spec, err := eipSettings(rt, s.profile, "", "")
	if err != nil {
		return eipPlan{}, err
	}
	eips, err := s.c.listEIPs(ctx, s.region, eipFilter{})
	if err != nil {
		return eipPlan{}, err
	}
	for _, e := range eips {
		storeEIP(ctx, rt, s.profile, e)
	}
	if e := pickIdleEIP(eips, spec.ISP, nil); e != nil {
		return eipPlan{idle: e, spec: spec}, nil
	}
	if spec.ResourceGroup, err = resolveResourceGroup(ctx, rt, s, ""); err != nil {
		return eipPlan{}, err
	}
	return eipPlan{spec: spec}, nil
}

// associateRetry retries a binding refused because the EIP or the instance
// is not ready yet: 3 seconds apart, 10 attempts. Which codes ECS answers
// then is not verified, so every status refusal counts.
func associateRetry(ctx context.Context, fn func(ctx context.Context) error) error {
	return platform.Retry(ctx, platform.RetryPolicy{Initial: 3 * time.Second, Max: 3 * time.Second, Multiplier: 1, MaxAttempts: 10,
		Timeout: time.Minute, Clock: netClock(), Match: func(err error) bool {
			code := platform.ErrorCode(err)
			return strings.HasPrefix(code, "Incorrect") || strings.Contains(code, "Status") || strings.Contains(code, "TaskConflict")
		}}, fn)
}

// eipStep binds an EIP to the instance: the idle one of p, else a new one.
// The address reported is the EIP's own (the instance's EipAddress may lag).
func eipStep(rt *app.Runtime, s *ecsScope, name string, id func() string, p eipPlan, result *eipRef) platform.Step {
	step := platform.Step{Resource: "eip/" + name}
	if p.idle != nil {
		step.Action = platform.Updated
		step.ID = p.idle.AllocationID
		step.Desc = "reuse idle " + p.idle.IP + " " + p.idle.AllocationID
	} else {
		step.Action = platform.Created
		step.Desc = "allocate " + p.spec.summary()
	}
	step.Apply = func(ctx context.Context) (platform.Change, error) {
		e := eipAddress{}
		if p.idle != nil {
			e = *p.idle
		} else {
			fresh, err := allocateAndRead(ctx, rt, s, p.spec)
			if err != nil {
				return platform.Change{ID: fresh.AllocationID}, err
			}
			e = fresh
		}
		err := associateRetry(ctx, func(ctx context.Context) error { return s.c.associateEIP(ctx, s.region, e.AllocationID, id()) })
		if err != nil {
			return platform.Change{ID: e.AllocationID}, fmt.Errorf("bind EIP %s (%s) to %s: %w", e.AllocationID, e.IP, id(), err)
		}
		// Reported only once bound: a failed run reports no address.
		*result = eipRef{AllocationID: e.AllocationID, IP: e.IP}
		if err := waitEIP(ctx, s, e.AllocationID, eipInUse+" by "+id(), func(x eipAddress) bool {
			return x.Status == eipInUse && x.InstanceID == id()
		}); err != nil {
			rt.Infof("warning: EIP %s: %v", e.AllocationID, err)
		}
		refreshEIP(ctx, rt, s, e.AllocationID)
		refreshInstance(rt, ctx, s.c, s.profile, s.region, id())
		verb := "associated"
		if p.idle == nil {
			verb = "allocated and associated"
		}
		return platform.Change{ID: e.AllocationID, Detail: fmt.Sprintf("%s %s %s", e.IP, e.AllocationID, verb),
			Attrs: map[string]string{"ip": e.IP, "allocation_id": e.AllocationID}}, nil
	}
	return step
}

func ecsCreateCmd(rt *app.Runtime) *cobra.Command {
	var f instanceFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an ECS instance from existing network resources",
		Long: `Create the ECS instance <name>, pay as you go, without a public address of its
own (outbound bandwidth 0): the public address is an EIP (--eip). Nothing
else is created except the key pair: use ensure to create the VPC, the
vSwitches and the security group as well.

- --type is required (or defaults.aliyun.ecs_instance_type): a type id,
  or a size <cores>H<memory>G such as 2H4G (see Instance sizes below).
- --vswitch (id or name) places the instance and decides its zone; default
  the vSwitch named by naming.aliyun_vswitch for zone b ({region}-switch-b)
  in the VPC named by naming.aliyun_vpc, which must exist.
- --security-group (name or id; required) is looked up in the vSwitch's
  VPC.
- The key pair: an existing one first (--key-pair, or the key pair that
  holds --ssh-key / --ssh-key-file, compared by fingerprint), else the key
  is imported under --key-pair (asked for on a terminal; no name is ever
  chosen for you). A key pair is required: Linux instances log in with a
  key only and polyctl never sets a password; without any key flag a
  terminal asks for a key file, and the non-interactive flow is exit
  code 2 before anything is read (with --image, once the image is read:
  only then is it known to be Linux or Windows; still before anything is
  written).
- The image is --image (any image id: the way to use another system), else
  the newest public image of --os (alibaba-cloud-linux, or windows; see
  image latest) for the architecture of the type (a size resolves to an
  x86 type). The system disk is --disk GiB of --disk-category.
- --image is read first (DescribeImages, available images only: a missing
  or deprecated image is exit code 4):
  an image whose OSType is windows (such as an English Windows Server
  image, which --os windows never picks) is created as --os windows is,
  below, with --disk defaulting to 40 or the image's size if larger
  (smaller than the image: exit code 2); any other image is Linux.
- A Windows instance (--os windows, or a Windows --image) takes no key
  pair flags (exit code 2) and imports no key pair (ECS key
  pairs are for Linux only): polyctl generates the Administrator password
  (20 characters from crypto/rand; no flag takes one) and sets it in
  RunInstances, then stores the user name and password encrypted in its
  database. An interactive create prints them, clearly labelled, at the
  end (on stdout, on stderr with -o json / -o yaml); a non-interactive one
  never prints the password: a note on stderr names the command that
  shows it, ` + "`polyctl aliyun ecs instance password <name|id>`" + `. A dry
  run generates and stores nothing. The host name holds no dots and at
  most 15 characters. With --os windows, --disk defaults to 40 (smaller
  is exit code 2) and an arm64 type is exit code 2.
- The host name is the name with every character other than letters,
  digits, hyphens and dots replaced by a hyphen, cut to 64 characters.
- An instance of the name in the region is exit code 1: use ensure.
- create waits until it is Running (by default, as on every platform:
  polled every 2 seconds, --timeout; --no-wait returns at once); --eip waits too, then binds an idle EIP of the region, else a new one.
` + instanceSizeHelp,
		Example: `  polyctl aliyun ecs instance create site-a --type ecs.u1-c1m1.large --security-group sg-common \
    --key-pair ops --ssh-key-file ~/.ssh/id_ed25519.pub`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			if err := checkInstanceName(name); err != nil {
				return err
			}
			baseHost, baseRenamed, err := normalizeHostName(name)
			if err != nil {
				return err
			}
			if err := f.check(cmd); err != nil {
				return err
			}
			host, renamed, err := f.hostName(name, baseHost, baseRenamed)
			if err != nil {
				return err
			}
			if f.securityGroup == "" {
				return app.UsageErrf("--security-group is required: pass the name or id of a security group of the vSwitch's VPC (or use ensure)")
			}
			wait, timeout, err := f.wait.Resolve(cmd)
			if err != nil {
				return err
			}
			var in platform.KeyInput
			if !f.windows() {
				if in, err = f.keyInput(rt); err != nil {
					return err
				}
				// Before anything is read: an instance without a key pair
				// is one nobody can log in to. An --image is known to be
				// Windows or Linux only once it is read (below).
				if f.image == "" {
					if err := requireKey(rt, &f); err != nil {
						return err
					}
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := openECSScope(ctx, rt, f.region)
			if err != nil {
				return err
			}
			if f.image != "" {
				if err := f.inspectImage(ctx, rt, s); err != nil {
					return err
				}
				if !f.windows() {
					if err := requireKey(rt, &f); err != nil {
						return err
					}
				} else if host, renamed, err = f.hostName(name, baseHost, baseRenamed); err != nil {
					return err
				}
			}
			if f.typ, err = rt.RequireSetting(s.profile, platform.Aliyun, "ecs_instance_type", "type", f.typ); err != nil {
				return err
			}
			if err := f.parseSize(); err != nil {
				return err
			}
			// A size picks its zone among the vSwitches it may use: --vswitch,
			// else the default vSwitches that exist.
			vsws, err := createVSwitches(ctx, rt, s, f.vswitch, f.size != nil)
			if err != nil {
				return err
			}
			vsw := vsws[0]
			sg, err := findInstanceSG(ctx, s, f.securityGroup, vsw.VPC)
			if err != nil {
				return err
			}
			if sg == nil {
				return fmt.Errorf("%w: security group %q in %s (%s)", platform.ErrNotFound, f.securityGroup, s.where(), vsw.VPC)
			}
			if sg.VPC != vsw.VPC {
				return fmt.Errorf("security group %s is in VPC %s and vSwitch %s in VPC %s: they must be in the same VPC", sg.ID, sg.VPC, vsw.ID, vsw.VPC)
			}
			if found, err := s.c.findInstances(ctx, s.region, name); err != nil {
				return err
			} else if len(found) > 0 {
				return fmt.Errorf("instance %q already exists in %s (%s): use `polyctl aliyun ecs instance ensure %s` to reuse it", name, s.where(), found[0].ID, name)
			}
			image, err := f.resolveImage(ctx, rt, s)
			if err != nil {
				return err
			}
			if f.size != nil {
				var zones []string
				for _, v := range vsws {
					zones = append(zones, v.Zone)
				}
				if err := f.resolveSize(ctx, rt, cmd, s, image, zones); err != nil {
					return err
				}
				for _, v := range vsws {
					if v.Zone == f.choice.Zone {
						vsw = v
						break
					}
				}
			}
			var kp platform.KeyPairPlan
			var kpStep platform.Step
			if !f.windows() {
				if kp, kpStep, err = resolveKeyPairStep(ctx, rt, s, in); err != nil {
					return err
				}
			}
			if renamed {
				rt.Infof("note: the host name of %s is %s (%s)", name, host, f.hostNameRule())
			}
			var ep eipPlan
			if f.eip {
				if ep, err = planEIP(ctx, rt, s); err != nil {
					return err
				}
				if !wait {
					rt.Infof("note: --eip waits until the instance is Running before binding the EIP")
				}
			}
			var plan platform.Plan
			var instID string
			id := func() string { return instID }
			if kpStep.Resource != "" {
				plan.Add(kpStep)
			}
			var win *windowsLogin
			if f.windows() {
				// Before the first write: a password that cannot be stored
				// would be lost once the instance exists.
				if err := rt.PrepareSecrets(); err != nil {
					return fmt.Errorf("the Windows password could not be stored, nothing was created: %w", err)
				}
				win = newWindowsLogin(rt, s, name)
			}
			plan.Add(runStep(rt, s, name, host, &f, image, func() string { return sg.ID }, func() string { return vsw.ID }, func() string { return kp.Name }, nil, win, &instID))
			if wait || f.eip {
				plan.Add(waitStep(rt, s, name, id, timeout))
			}
			if f.eip {
				var res eipRef
				plan.Add(eipStep(rt, s, name, id, ep, &res))
			}
			err = rt.Ensure(ctx, "aliyun.ecs.instance.create", s.target(), &plan)
			if werr := win.finish(ctx); werr != nil {
				err = errors.Join(err, werr)
			}
			return err
		},
	}
	f.add(cmd, false, true, "instance type id, or a size <cores>H<memory>G such as 2H4G resolved to the cheapest x86 type in stock (required, unless defaults.aliyun.ecs_instance_type is set)", "security group of the instance, name or id (required)")
	return cmd
}

// requireKey refuses a non-interactive Linux create without any key flag:
// an instance without a key pair is one nobody can log in to.
func requireKey(rt *app.Runtime, f *instanceFlags) error {
	if f.keys.Given() || rt.Interactive() {
		return nil
	}
	return app.UsageErrf("a key pair is required (Linux instances log in with a key only, never a password): pass --key-pair <name> (an existing key pair), or --ssh-key-file <path> / --ssh-key <public key> with --key-pair <name> to import one")
}

// findInstanceSG finds the security group of an instance: the group of
// that id when ref is written like one (sg-...) and such a group exists,
// else the group of that exact name in vpc ("" when the VPC is still to be
// created: nothing to look in). The default name sg-common starts like an
// id, so a reference that is no group id is always looked up as a name too.
func findInstanceSG(ctx context.Context, s *ecsScope, ref, vpc string) (*securityGroup, error) {
	if looksLikeGroupID(ref) {
		found, err := s.c.listSecurityGroups(ctx, s.region, "", "", fmt.Sprintf("[%q]", ref))
		if err != nil {
			code := platform.ErrorCode(err)
			if !errors.Is(err, platform.ErrNotFound) && !strings.Contains(code, "Malformed") && code != "InvalidParameter" {
				return nil, err
			}
		}
		for i := range found {
			if found[i].ID == ref {
				return &found[i], nil
			}
		}
	}
	if vpc == "" {
		return nil, nil
	}
	found, err := s.c.listSecurityGroups(ctx, s.region, vpc, ref, "")
	if err != nil {
		return nil, err
	}
	var named []securityGroup
	for _, g := range found {
		if g.Name == ref && g.VPC == vpc {
			named = append(named, g)
		}
	}
	switch len(named) {
	case 0:
		return nil, nil
	case 1:
		return &named[0], nil
	}
	var ids []string
	for _, g := range named {
		ids = append(ids, g.ID)
	}
	return nil, &app.AmbiguousError{What: fmt.Sprintf("security group %q in %s (%s)", ref, s.where(), vpc), Candidates: ids,
		Hint: "Alibaba Cloud lets several groups share a name; pass the security group id"}
}

// checkInstanceSGName refuses a security group name Alibaba Cloud refuses.
func checkInstanceSGName(name string) error {
	switch {
	case strings.TrimSpace(name) == "":
		return app.UsageErrf("the security group name is empty")
	case strings.HasPrefix(name, "http://"), strings.HasPrefix(name, "https://"):
		return app.UsageErrf("security group name %q may not start with http:// or https://", name)
	case len([]rune(name)) > sgNameMaxLength:
		return app.UsageErrf("security group name %q is longer than %d characters", name, sgNameMaxLength)
	}
	return nil
}

// createVSwitches resolves the --vswitch of create: the vSwitch given (id
// or name), else the default vSwitch of zone b in the default VPC. With
// all (a --type size, which picks the zone), every default vSwitch that
// exists (zones b and c) is returned instead, in that order.
func createVSwitches(ctx context.Context, rt *app.Runtime, s *ecsScope, ref string, all bool) ([]*vSwitch, error) {
	if ref != "" {
		v, err := resolveVSwitch(ctx, s, ref, "")
		if err != nil {
			return nil, err
		}
		return []*vSwitch{v}, nil
	}
	vpcName, err := rt.ResourceName("aliyun_vpc", "", map[string]string{"region": s.region})
	if err != nil {
		return nil, err
	}
	zones := defaultZones[:1]
	if all {
		zones = defaultZones
	}
	var out []*vSwitch
	var names []string
	for _, suffix := range zones {
		name, err := vswName(rt, s.region, "", zoneTarget{ID: s.region + "-" + suffix, Suffix: suffix})
		if err != nil {
			return nil, err
		}
		names = append(names, fmt.Sprintf("%q", name))
		v, err := resolveVSwitch(ctx, s, name, vpcName)
		if errors.Is(err, platform.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	if len(out) == 0 {
		return nil, app.UsageErrf("no vSwitch for the instance: the default vSwitch %s of VPC %q does not exist in %s; pass --vswitch <id|name>, or use ensure", strings.Join(names, " or "), vpcName, s.region)
	}
	return out, nil
}

// ------------------------------------------------------------- delete

// showInstance prints an instance on stderr before a confirmation.
func showInstance(rt *app.Runtime, s *ecsScope, in *Instance) {
	rt.Infof("instance %s in %s", instanceLabel(in), s.where())
	rt.Infof("  id          %s", in.ID)
	rt.Infof("  type        %s", in.Type)
	rt.Infof("  status      %s", in.Status)
	rt.Infof("  private ip  %s", orNone(in.PrivateIP))
	rt.Infof("  public ip   %s", orNone(in.PublicIP))
	if in.EIP != "" {
		rt.Infof("  eip         %s (%s)", in.EIP, in.EIPAllocationID)
	}
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// settle waits for an instance that is Pending, Starting or Stopping to be
// Running or Stopped, and returns its status.
func settle(ctx context.Context, rt *app.Runtime, s *ecsScope, in *Instance, timeout time.Duration) (string, error) {
	switch in.Status {
	case instRunning, instStopped:
		return in.Status, nil
	}
	rt.Infof("instance %s is %s: waiting until it is Running or Stopped", instanceLabel(in), in.Status)
	return waitInstanceSettled(ctx, s, in.ID, instanceLabel(in), timeout)
}

// stopAndWait stops a running instance and waits until it is Stopped.
func stopAndWait(ctx context.Context, rt *app.Runtime, s *ecsScope, in *Instance, timeout time.Duration) error {
	if err := retryInitializing(ctx, func(ctx context.Context) error { return s.c.StopInstance(ctx, s.region, in.ID, false) }); err != nil {
		return err
	}
	if err := waitInstanceStatus(ctx, s, in.ID, instanceLabel(in), instStopped, timeout); err != nil {
		return fmt.Errorf("stop of %s was requested: %w", instanceLabel(in), err)
	}
	refreshInstance(rt, ctx, s.c, s.profile, s.region, in.ID)
	return nil
}

func ecsDeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var force bool
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:     "delete <name|id>",
		Aliases: []string{"terminate"},
		Short:   "Delete an ECS instance (asks first)",
		Long: `Delete an ECS instance, found like get finds it. The instance and its
addresses are shown, then a confirmation is asked (default no; --yes skips
it, and the non-interactive flow needs --yes: exit code 2 without it).

A Running instance is stopped first and deleted once Stopped; --force
deletes it at once (DeleteInstance with Force). A Stopped instance is
deleted. An instance that is Pending, Starting or Stopping is waited for
until it is Running or Stopped (--timeout bounds every wait). A new
instance cannot be deleted for about 45 seconds after its creation
(IncorrectInstanceStatus.Initializing): the delete is retried for up to 2
minutes. An instance with deletion protection is not deleted (exit code 1):
switch the protection off in the console first. --wait then waits until
the instance is no longer listed.

An EIP bound to the instance is not released: it becomes idle, stays billed
and is reused by the next ensure. The Windows credentials polyctl stored
for the instance (see password) are removed once it is deleted.`,
		Example: "  polyctl aliyun ecs instance delete site-a --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			if !rt.DryRun() {
				if err := rt.CanConfirm("delete instance " + args[0]); err != nil {
					return err
				}
			}
			s, in, err := resolveECSInstance(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			label := instanceLabel(in)
			res := "instance/" + label
			showInstance(rt, s, in)
			if in.DeletionProtection {
				return fmt.Errorf("instance %s (%s) has deletion protection: switch it off in the Alibaba Cloud console first (polyctl never does)", label, in.ID)
			}
			var changes []platform.Change
			stopFirst := in.Status != instStopped && !force
			if stopFirst {
				changes = append(changes, platform.Change{Resource: res, Action: platform.Updated, ID: in.ID, Detail: "stop"})
			}
			del := platform.Change{Resource: res, Action: platform.Deleted, ID: in.ID, Detail: "delete"}
			if force && in.Status != instStopped {
				del.Detail = "delete (forced)"
			}
			changes = append(changes, del)
			if done, err := rt.WouldWrite(s.target(), changes...); done || err != nil {
				return err
			}
			rt.Infof("This cannot be undone! The instance and its system disk will be permanently deleted.")
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete instance %s (%s)?", label, in.ID), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; instance %s was not deleted", platform.ErrNothingToDo, label)
			}
			st, err := settle(ctx, rt, s, in, timeout)
			if err != nil {
				return err
			}
			changes = changes[:0]
			if st == instRunning && !force {
				if err := stopAndWait(ctx, rt, s, in, timeout); err != nil {
					return err
				}
				changes = append(changes, platform.Change{Resource: res, Action: platform.Updated, ID: in.ID, Detail: "stop; stopped"})
			}
			forced := st == instRunning && force
			err = retryInitializing(ctx, func(ctx context.Context) error { return s.c.deleteInstance(ctx, s.region, in.ID, forced) })
			if platform.HasErrorCode(err, errDeletionProtection) {
				return fmt.Errorf("instance %s (%s) has deletion protection: switch it off in the Alibaba Cloud console first: %w", label, in.ID, err)
			}
			if err != nil {
				return err
			}
			dropInstance(ctx, rt, s.profile, in.ID)
			forgetLogin(ctx, rt, s, in.ID)
			del.Detail = "deleted"
			if forced {
				del.Detail = "deleted (forced)"
			}
			changes = append(changes, del)
			rt.Infof("instance %s (%s) deleted", label, in.ID)
			if wait {
				if err := waitInstanceStatus(ctx, s, in.ID, label, statusNotFound, timeout); err != nil {
					return fmt.Errorf("delete of %s was requested: %w", label, err)
				}
				del.Detail += "; gone"
				changes[len(changes)-1] = del
			}
			if in.EIP != "" {
				rt.Infof("note: EIP %s (%s) was unbound and is still billed; ensure reuses idle EIPs, release it in the console if it is no longer needed", in.EIP, in.EIPAllocationID)
				refreshEIP(ctx, rt, s, in.EIPAllocationID)
			}
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: changes})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "delete a Running instance at once instead of stopping it first")
	app.AddWaitFlags(cmd, &w, false, defaultInstanceTimeout)
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	return cmd
}

// ------------------------------------------------------------- reboot

func ecsRebootCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var force bool
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "reboot <name|id>",
		Short: "Reboot a Running ECS instance",
		Long: `Reboot a Running ECS instance, found like get finds it. --force stops it hard
(ForceStop, like pulling the power) instead of shutting it down, so it asks
for a confirmation first (default no; --yes skips it, and the
non-interactive flow needs --yes: exit code 2 without it); a plain reboot
asks nothing. An instance that is not Running is
exit code 1 (start a stopped one with start). --wait waits until it is
Running again: a Running read counts only after the instance was seen
leaving Running (or 30 seconds after the reboot), so a read taken before
the reboot began does not end the wait; a Stopped read on the way is
accepted for 30 seconds.`,
		Example: "  polyctl aliyun ecs instance reboot site-a --wait",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			// A forced reboot cuts the power: the non-interactive flow
			// without --yes is refused before any lookup.
			if force && !rt.DryRun() {
				if err := rt.CanConfirm("force-reboot instance " + args[0]); err != nil {
					return err
				}
			}
			s, in, err := resolveECSInstance(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			label := instanceLabel(in)
			if in.Status != instRunning {
				return fmt.Errorf("instance %s (%s) is %s: only a Running instance can be rebooted (start a stopped one with `polyctl aliyun ecs instance start %s`)", label, in.ID, in.Status, in.ID)
			}
			change := platform.Change{Resource: "instance/" + label, Action: platform.Updated, ID: in.ID, Detail: "reboot"}
			if force {
				change.Detail = "reboot (force stop)"
			}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			if force {
				rt.Infof("This is a forced reboot: the operating system is not shut down gracefully (like pulling the power); unsaved data is lost.")
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Force-reboot instance %s (no graceful OS shutdown)?", label), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not rebooted", platform.ErrNothingToDo, label)
				}
			}
			if err := s.c.rebootInstance(ctx, s.region, in.ID, force); err != nil {
				return err
			}
			if wait {
				took, err := waitRebooted(ctx, s, in.ID, label, timeout)
				if err != nil {
					return fmt.Errorf("reboot of %s was requested: %w", label, err)
				}
				change.Detail += fmt.Sprintf("; Running (waited %s)", took.Round(time.Second))
			} else {
				rt.Infof("reboot of %s requested; it is Running again within about 15 seconds", label)
			}
			refreshInstance(rt, ctx, s.c, s.profile, s.region, in.ID)
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "force the stop (ForceStop: like pulling the power)")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	app.AddWaitFlags(cmd, &w, false, defaultInstanceTimeout)
	return cmd
}

// ------------------------------------------------------------- resize

// resizeChoice resolves a --type size for an instance: the cheapest x86
// type of that size it can change to in its zone, priced with its image
// and system disk.
func resizeChoice(ctx context.Context, s *ecsScope, in *Instance, size platform.TypeShorthand) (*typeChoice, error) {
	diskGiB, category, err := s.c.systemDisk(ctx, s.region, in.ID)
	if err != nil {
		return nil, err
	}
	r := typeRequest{Size: size, Image: in.ImageID, DiskGiB: diskGiB, DiskCategory: category, DiskFixed: true, Resize: in.ID, Current: in.Type}
	if in.Zone != "" {
		r.Zones = []string{in.Zone}
	}
	return s.c.resolveTypeSize(ctx, s.region, r)
}

func ecsResizeCmd(rt *app.Runtime) *cobra.Command {
	var region, typ string
	var w app.WaitFlags
	var start bool
	var port int
	cmd := &cobra.Command{
		Use:   "resize <name|id>",
		Short: "Change the type of an ECS instance: stop, modify, start",
		Long: `Change the instance type of an ECS instance, found like get finds it. ECS
changes the type of a Stopped instance only, so a Running instance is
stopped (after a confirmation, default no; --yes skips it, the
non-interactive flow needs --yes: exit code 2), its type is changed
(ModifyInstanceSpec), and it is started again. The instance ends in the
power state it had: a Stopped instance stays Stopped (and needs no
confirmation) unless --start is given, and --start=false leaves a Running
one Stopped. An instance that is Pending, Starting or Stopping is waited
for first. The stop is always waited for; --wait also waits until the
instance is Running again (--timeout bounds every wait). --wait-port then
waits until that TCP port (22 for SSH) accepts connections on the public
IP, the EIP or the private IP; it implies --wait.
The same type is unchanged. A type the zone has no stock of, or that the
instance cannot change to, is exit code 1 with the Alibaba Cloud message;
the instance is then Stopped with its old type: start it, or run the
command again with another type.

--type also takes a size <cores>H<memory>G (2H4G, 4H8G, 1H0.5G), resolved
before anything changes (in a dry run too, never remembered): an instance
of that size already is unchanged; otherwise the candidates are the x86
types of exactly that size in stock that the instance can change to in
its zone (DescribeResourcesModification), each priced by the hour with
its image and system disk, and the cheapest wins (ties: the type name).
The choice is printed on stderr ("2H4G -> ecs.e-c1m2.large
(cn-hongkong-b, 0.0123 CNY/hour)") and shown in the change report; no
match is exit code 4, a size of 0 vCPUs or 0 GiB exit code 2.`,
		Example: "  polyctl aliyun ecs instance resize site-a --type ecs.u1-c1m2.large --yes --wait",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if typ == "" {
				return app.UsageErrf("--type is required")
			}
			size, isSize, err := platform.ParseTypeShorthand(typ)
			if err != nil {
				return err
			}
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			if port < 0 || port > 65535 {
				return app.UsageErrf("--wait-port must be a TCP port (1-65535), got %d", port)
			}
			if port > 0 {
				wait = true
			}
			s, in, err := resolveECSInstance(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			label := instanceLabel(in)
			res := "instance/" + label
			typeDesc := typ
			if isSize {
				if size.Matches(in.CPU, in.MemoryMB) {
					rt.Infof("instance %s already is %s (%s)", label, size, in.Type)
					return rt.RenderReport(platform.Report{Target: s.target(), DryRun: rt.DryRun(), Changes: []platform.Change{
						{Resource: res, Action: platform.Unchanged, ID: in.ID, Detail: "type " + in.Type + " (" + size.String() + ")"}}})
				}
				ch, err := resizeChoice(ctx, s, in, size)
				if err != nil {
					return err
				}
				rt.Infof("%s", ch.note())
				typ = ch.Type
				typeDesc = typ + " " + ch.label()
			}
			if in.Type == typ {
				rt.Infof("instance %s already is %s", label, typ)
				return rt.RenderReport(platform.Report{Target: s.target(), DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: res, Action: platform.Unchanged, ID: in.ID, Detail: "type " + typ}}})
			}
			running := in.Status != instStopped
			startSet := cmd.Flags().Changed("start")
			wantStart := running
			if startSet {
				wantStart = start
			}
			var plan platform.Plan
			cur := in.Type
			if running {
				plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: in.ID, Desc: "stop", Apply: func(ctx context.Context) (platform.Change, error) {
					st, err := settle(ctx, rt, s, in, timeout)
					if err != nil {
						return platform.Change{}, err
					}
					if st == instStopped {
						running = false
						if !startSet {
							wantStart = false
						}
						return platform.Change{Detail: "already Stopped"}, nil
					}
					if err := stopAndWait(ctx, rt, s, in, timeout); err != nil {
						return platform.Change{}, err
					}
					return platform.Change{Detail: "stop; stopped"}, nil
				}})
			}
			plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: in.ID, Desc: fmt.Sprintf("modify type %s -> %s", cur, typeDesc), Apply: func(ctx context.Context) (platform.Change, error) {
				if err := s.c.modifyInstanceSpec(ctx, s.region, in.ID, typ); err != nil {
					return platform.Change{}, fmt.Errorf("%w; the instance is Stopped with its type %s: start it with `polyctl aliyun ecs instance start %s`, or run resize again", err, cur, in.ID)
				}
				refreshInstance(rt, ctx, s.c, s.profile, s.region, in.ID)
				return platform.Change{}, nil
			}})
			if wantStart {
				plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: in.ID, Desc: "start", Apply: func(ctx context.Context) (platform.Change, error) {
					if !wantStart {
						return platform.Change{Action: platform.Skipped, Detail: "was Stopped: stays Stopped"}, nil
					}
					if err := s.c.StartInstance(ctx, s.region, in.ID); err != nil {
						return platform.Change{}, fmt.Errorf("instance %s is Stopped with type %s: %w", label, typ, err)
					}
					detail := "start"
					if wait {
						took, err := waitInstanceRunning(ctx, s, in.ID, label, timeout)
						if err != nil {
							return platform.Change{}, fmt.Errorf("start of %s was requested: %w", label, err)
						}
						detail = fmt.Sprintf("start; Running (waited %s)", took.Round(time.Second))
					}
					refreshInstance(rt, ctx, s.c, s.profile, s.region, in.ID)
					return platform.Change{Detail: detail}, nil
				}})
			} else {
				rt.Infof("note: instance %s stays Stopped (pass --start to start it)", label)
			}
			if running && !rt.DryRun() {
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Stop instance %s to change its type from %s to %s? It is unavailable until it runs again.", label, cur, typ), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not changed", platform.ErrNothingToDo, label)
				}
			}
			if err := rt.Ensure(ctx, "aliyun.ecs.instance.resize", s.target(), &plan); err != nil || rt.DryRun() || port == 0 {
				return err
			}
			after, err := s.c.describeInstance(ctx, s.region, in.ID)
			if err != nil {
				return err
			}
			if after.Status != instRunning {
				rt.Infof("note: --wait-port %d skipped: instance %s is %s", port, label, after.Status)
				return nil
			}
			host := after.PublicIP
			if host == "" {
				host = after.EIP
			}
			if host == "" {
				host = after.PrivateIP
			}
			if host == "" {
				return fmt.Errorf("instance %s has no address to check port %d on", label, port)
			}
			addr := net.JoinHostPort(host, strconv.Itoa(port))
			if err := waitTCPPort(ctx, addr, label, timeout); err != nil {
				return err
			}
			rt.Infof("port %d of %s accepts connections", port, addr)
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "new instance type id, or a size <cores>H<memory>G such as 2H4G resolved to the cheapest x86 type (required)")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	cmd.Flags().BoolVar(&start, "start", false, "start the instance after the change (default: only when it was running; --start=false leaves it stopped)")
	cmd.Flags().IntVar(&port, "wait-port", 0, "after the start, wait until this TCP port accepts connections (22 for SSH; implies --wait)")
	app.AddWaitFlags(cmd, &w, false, defaultInstanceTimeout)
	return cmd
}
