package aws

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// ------------------------------------------------------------ routing

// locatedInstance is an instance found for a command, with the client of
// the account that holds it.
type locatedInstance struct {
	c       *client
	profile string
	region  string
	inst    ec2types.Instance
}

func (l *locatedInstance) id() string { return awssdk.ToString(l.inst.InstanceId) }

// name is the instance's Name tag, or its id: the name of report rows.
func (l *locatedInstance) name() string {
	if n := instanceName(l.inst); n != "" {
		return n
	}
	return l.id()
}

func (l *locatedInstance) resource() string { return "instance/" + l.name() }

func (l *locatedInstance) target() platform.Target {
	return platform.Target{Platform: platform.AWS, Profile: l.profile, Region: l.region}
}

// resolveInstance finds the instance ref names (a Name tag or an instance
// id) without the user naming the account. With region, the selected
// profile's account is asked directly in that region. Otherwise the
// inventory tells which accounts hold an instance of that name or id (one
// sync of the stale accounts when none does), and each of them is asked
// live: an inventory row may be stale, and terminated instances stay
// visible for a while. When none of them holds a live one, the remaining
// accounts are asked too. One live instance is the answer; several are
// ambiguous (exit code 5). allowTerminated returns a terminated instance
// when no live one exists (delete reports it unchanged, get
// --include-terminated shows it).
func resolveInstance(ctx context.Context, rt *app.Runtime, ref, region string, allowTerminated bool) (*locatedInstance, error) {
	if strings.TrimSpace(ref) == "" {
		return nil, app.UsageErrf("the instance name or id is empty")
	}
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	var found []*locatedInstance
	var failure error
	ask := func(profile, region string) {
		c, err := openProfile(ctx, rt, profile)
		if err == nil {
			region = c.regionOr(region)
			var all []ec2types.Instance
			if all, err = c.findInstances(ctx, region, ref); err == nil {
				for _, in := range all {
					found = append(found, &locatedInstance{c: c, profile: profile, region: region, inst: in})
				}
				return
			}
		}
		rt.Infof("warning: looking up instance %q in aws/%s: %v", ref, profile, err)
		if failure == nil {
			failure = fmt.Errorf("aws/%s: %w", profile, err)
		}
	}
	if region != "" {
		profile, err := rt.ProfileFor(platform.AWS)
		if err != nil {
			return nil, err
		}
		ask(profile, region)
		return pickInstance(ref, found, failure, allowTerminated)
	}
	accounts, err := awsAccounts(rt)
	if err != nil {
		return nil, err
	}
	hits, err := inventoryHits(ctx, rt, accounts, ref)
	if err != nil {
		return nil, err
	}
	askedPair, askedProfile := map[string]bool{}, map[string]bool{}
	for _, h := range hits {
		if key := h.profile + "|" + h.region; !askedPair[key] {
			askedPair[key], askedProfile[h.profile] = true, true
			ask(h.profile, h.region)
		}
	}
	if len(liveOnly(found)) == 0 {
		for _, a := range accounts {
			if !askedProfile[a.Profile] {
				askedProfile[a.Profile] = true
				ask(a.Profile, "")
			}
		}
	}
	return pickInstance(ref, found, failure, allowTerminated)
}

// openProfile opens the AWS client of a profile.
func openProfile(ctx context.Context, rt *app.Runtime, profile string) (*client, error) {
	c, _, err := rt.Open(ctx, profile, platform.AWS)
	if err != nil {
		return nil, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, fmt.Errorf("unexpected AWS client type %T", c)
	}
	return ac, nil
}

// awsAccounts returns the AWS accounts selected by --profile.
func awsAccounts(rt *app.Runtime) ([]config.AccountRef, error) {
	all, err := rt.Accounts()
	if err != nil {
		return nil, err
	}
	var out []config.AccountRef
	for _, a := range all {
		if a.Platform == platform.AWS {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		// The error of ProfileFor names what is missing.
		if _, err := rt.ProfileFor(platform.AWS); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: no AWS account selected", platform.ErrUnauthorized)
	}
	return out, nil
}

type inventoryHit struct{ profile, region string }

// inventoryHits returns the accounts (and regions) whose cached instances
// include ref by id or name, in any state. When none does, the stale
// instance sets are synced once and the lookup is repeated.
func inventoryHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, ref string) ([]inventoryHit, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	lookup := func() ([]inventoryHit, error) {
		var out []inventoryHit
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResInstance})
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				if r.ID != ref && r.Name != ref {
					continue
				}
				var i instanceInfo
				_ = r.Decode(&i)
				out = append(out, inventoryHit{profile: a.Profile, region: i.Region})
			}
		}
		return out, nil
	}
	hits, err := lookup()
	if err != nil || len(hits) > 0 {
		return hits, err
	}
	var stale []config.AccountRef
	for _, a := range accounts {
		st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: platform.ResInstance})
		if err != nil {
			return nil, err
		}
		if rt.Flags.Refresh || !st.Fresh(time.Now()) {
			stale = append(stale, a)
		}
	}
	if len(stale) == 0 {
		return nil, nil
	}
	rt.Infof("looking up instance %q: syncing the instances of %d account(s)...", ref, len(stale))
	for _, a := range stale {
		reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{platform.ResInstance})
		if err == nil {
			for _, r := range reps {
				if r.Err != nil {
					err = r.Err
					break
				}
			}
		}
		if err != nil {
			// The live lookup that follows asks the account again.
			rt.Verbosef("sync %s: %v", a.Label(), err)
		}
	}
	return lookup()
}

func liveOnly(found []*locatedInstance) []*locatedInstance {
	var out []*locatedInstance
	for _, l := range found {
		if instanceState(l.inst) != stateTerminated {
			out = append(out, l)
		}
	}
	return out
}

// pickInstance chooses among the instances found.
func pickInstance(ref string, found []*locatedInstance, failure error, allowTerminated bool) (*locatedInstance, error) {
	live := liveOnly(found)
	switch {
	case len(live) == 1:
		return live[0], nil
	case len(live) > 1:
		var names []string
		accounts := map[string]bool{}
		for _, l := range live {
			names = append(names, fmt.Sprintf("aws/%s/%s (%s, %s)", l.profile, l.region, l.id(), instanceState(l.inst)))
			accounts[l.profile] = true
		}
		hint := "pass --profile <name> to choose"
		if len(accounts) == 1 {
			hint = "the account holds several instances with this name; pass the instance id"
		}
		return nil, &app.AmbiguousError{What: fmt.Sprintf("instance %q", ref), Candidates: names, Hint: hint}
	}
	if allowTerminated && len(found) > 0 {
		return found[0], nil
	}
	if failure != nil {
		// An account that could not be asked may hold it: that is not
		// "not found".
		return nil, fmt.Errorf("cannot tell where instance %q is: %w", ref, failure)
	}
	what := "instance"
	if len(found) > 0 {
		what = "live instance (only terminated ones exist)"
	}
	return nil, fmt.Errorf("%w: %s %q in the selected AWS accounts (pass --region for an instance outside the profile's region)", platform.ErrNotFound, what, ref)
}

// storeInstance writes an instance to the inventory, when it belongs to
// the region the inventory holds (the profile's region).
func storeInstance(ctx context.Context, rt *app.Runtime, profile string, c *client, region string, in ec2types.Instance) {
	if c.regionOr(region) != c.region || awssdk.ToString(in.InstanceId) == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResInstance},
		instanceFrom(c.region, in).resource(), cfg.TTLFor(platform.ResInstance))
}

// dropInstance removes an instance from the inventory.
func dropInstance(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResInstance}, platform.ResInstance, id)
	}
}

// reread reads the instance again and stores it; on failure the instance
// as known is kept.
func (l *locatedInstance) reread(ctx context.Context, rt *app.Runtime) {
	if in, err := l.c.describeInstance(ctx, l.region, l.id()); err == nil {
		l.inst = in
	} else {
		rt.Verbosef("re-read instance %s: %v", l.id(), err)
	}
	storeInstance(ctx, rt, l.profile, l.c, l.region, l.inst)
}

// ---------------------------------------------------------------- get

// instanceDetail is the output of `instance get`.
type instanceDetail struct {
	InstanceID       string           `json:"instance_id" yaml:"instance_id"`
	InstanceName     string           `json:"instance_name" yaml:"instance_name"`
	Profile          string           `json:"profile" yaml:"profile"`
	Region           string           `json:"region" yaml:"region"`
	AvailabilityZone string           `json:"availability_zone" yaml:"availability_zone"`
	InstanceType     string           `json:"instance_type" yaml:"instance_type"`
	State            string           `json:"state" yaml:"state"`
	Platform         string           `json:"platform" yaml:"platform"`
	Architecture     string           `json:"architecture" yaml:"architecture"`
	PrivateIP        string           `json:"private_ip" yaml:"private_ip"`
	PublicIP         string           `json:"public_ip" yaml:"public_ip"`
	VpcID            string           `json:"vpc_id" yaml:"vpc_id"`
	SubnetID         string           `json:"subnet_id" yaml:"subnet_id"`
	SecurityGroups   []string         `json:"security_groups" yaml:"security_groups"`
	KeyName          string           `json:"key_name" yaml:"key_name"`
	LaunchTime       string           `json:"launch_time" yaml:"launch_time"`
	RootDevice       string           `json:"root_device" yaml:"root_device"`
	Volumes          []instanceVolume `json:"volumes" yaml:"volumes"`
}

func detailFrom(profile, region string, in ec2types.Instance, vols []instanceVolume) instanceDetail {
	d := instanceDetail{
		InstanceID: awssdk.ToString(in.InstanceId), InstanceName: instanceName(in), Profile: profile, Region: region,
		InstanceType: string(in.InstanceType), State: instanceState(in), Platform: "linux", Architecture: string(in.Architecture),
		PrivateIP: awssdk.ToString(in.PrivateIpAddress), PublicIP: awssdk.ToString(in.PublicIpAddress),
		VpcID: awssdk.ToString(in.VpcId), SubnetID: awssdk.ToString(in.SubnetId), KeyName: awssdk.ToString(in.KeyName),
		RootDevice: awssdk.ToString(in.RootDeviceName), SecurityGroups: []string{}, Volumes: vols,
	}
	if in.Platform == ec2types.PlatformValuesWindows {
		d.Platform = "windows"
	}
	if in.Placement != nil {
		d.AvailabilityZone = awssdk.ToString(in.Placement.AvailabilityZone)
	}
	if in.LaunchTime != nil {
		d.LaunchTime = in.LaunchTime.UTC().Format(time.RFC3339)
	}
	for _, g := range in.SecurityGroups {
		d.SecurityGroups = append(d.SecurityGroups, awssdk.ToString(g.GroupId))
	}
	if d.Volumes == nil {
		d.Volumes = []instanceVolume{}
	}
	return d
}

// detailFields are the fields `get --field` prints.
var detailFields = []string{"instance_id", "instance_name", "profile", "region", "availability_zone", "instance_type", "state",
	"platform", "architecture", "private_ip", "public_ip", "vpc_id", "subnet_id", "security_groups", "key_name", "launch_time", "root_device"}

func (d instanceDetail) field(name string) string {
	switch name {
	case "instance_id":
		return d.InstanceID
	case "instance_name":
		return d.InstanceName
	case "profile":
		return d.Profile
	case "region":
		return d.Region
	case "availability_zone":
		return d.AvailabilityZone
	case "instance_type":
		return d.InstanceType
	case "state":
		return d.State
	case "platform":
		return d.Platform
	case "architecture":
		return d.Architecture
	case "private_ip":
		return d.PrivateIP
	case "public_ip":
		return d.PublicIP
	case "vpc_id":
		return d.VpcID
	case "subnet_id":
		return d.SubnetID
	case "security_groups":
		return strings.Join(d.SecurityGroups, ",")
	case "key_name":
		return d.KeyName
	case "launch_time":
		return d.LaunchTime
	case "root_device":
		return d.RootDevice
	}
	return ""
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

func volumeNote(v instanceVolume, root string) string {
	var notes []string
	if v.Device == root {
		notes = append(notes, "root")
	}
	if v.DeleteOnTermination {
		notes = append(notes, "delete-on-termination")
	} else {
		notes = append(notes, "keep on termination")
	}
	return "(" + strings.Join(notes, ", ") + ")"
}

func detailGrid(d instanceDetail) output.Grid {
	az := d.Region
	if d.AvailabilityZone != "" {
		az += " (" + d.AvailabilityZone + ")"
	}
	g := output.Grid{Rows: [][]string{
		{"NAME", d.InstanceName, "INSTANCE", d.InstanceID},
		{"PROFILE", d.Profile, "REGION", az},
		{"TYPE", d.InstanceType, "STATE", d.State},
		{"PRIVATE IP", orNone(d.PrivateIP), "PUBLIC IP", orNone(d.PublicIP)},
		{"VPC/SUBNET", d.VpcID + " / " + d.SubnetID},
		{"SGS", strings.Join(d.SecurityGroups, ", ")},
		{"KEY PAIR", orNone(d.KeyName), "PLATFORM", d.Platform},
		{"LAUNCHED", d.LaunchTime},
		{"VOLUMES"},
	}}
	for _, v := range d.Volumes {
		g.Rows = append(g.Rows, []string{"  " + v.VolumeID, v.Device, v.VolumeType, fmt.Sprintf("%dGB  %s  %s", v.Size, v.State, volumeNote(v, d.RootDevice))})
	}
	return g
}

// noPublicIPHint explains an instance without a public IP.
func noPublicIPHint(state string) string {
	if state != stateRunning {
		return fmt.Sprintf("the instance has no public IP: it is %s; once started it gets a new public IP (unless it has an Elastic IP)", state)
	}
	return "the instance has no public IP: it has no Elastic IP and was launched without a public address (create assigns one unless --public-ip=false)"
}

func ec2GetCmd(rt *app.Runtime) *cobra.Command {
	var region, field string
	var includeTerminated bool
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show one EC2 instance, its addresses and volumes",
		Long: `Show one EC2 instance, found by its Name tag or its id in every selected AWS
account (--profile narrows the search, --region looks in another region of
the profile's account). Instances in any state but terminated are shown;
--include-terminated also finds a terminated one. --field prints the raw
value of one field (public_ip, private_ip, instance_id, ...) for scripts;
an empty value is exit code 1.`,
		Example: `  polyctl aws ec2 instance get site-xz7
  polyctl aws ec2 instance get site-xz7 --field public_ip`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if field != "" && !slices.Contains(detailFields, field) {
				return app.UsageErrf("unknown --field %q (one of %s)", field, strings.Join(detailFields, ", "))
			}
			l, err := resolveInstance(cmd.Context(), rt, args[0], region, includeTerminated)
			if err != nil {
				return err
			}
			storeInstance(cmd.Context(), rt, l.profile, l.c, l.region, l.inst)
			vols, err := l.c.instanceVolumes(cmd.Context(), l.region, l.inst)
			if err != nil {
				rt.Infof("warning: cannot list the volumes of %s: %v", l.id(), err)
				vols = nil
			}
			d := detailFrom(l.profile, l.region, l.inst, vols)
			if field != "" {
				v := d.field(field)
				if v == "" {
					if field == "public_ip" {
						return errors.New(noPublicIPHint(d.State))
					}
					return fmt.Errorf("instance %s has no %s", l.name(), field)
				}
				_, err := fmt.Fprintln(rt.Stdout, v)
				return err
			}
			if d.State != stateRunning {
				rt.Infof("note: instance %s is %s", l.name(), d.State)
			}
			return rt.Render(d, func() output.Grid { return detailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	cmd.Flags().StringVar(&field, "field", "", "print only the raw value of this field ("+strings.Join(detailFields, ", ")+")")
	cmd.Flags().BoolVar(&includeTerminated, "include-terminated", false, "also find a terminated instance")
	return cmd
}

// ------------------------------------------------------------- create

// parseTags parses --tag key=value flags.
func parseTags(args []string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, app.UsageErrf("--tag %q: expected key=value", a)
		}
		if k == "Name" {
			return nil, app.UsageErrf("--tag Name=...: the Name tag is the instance name (the argument)")
		}
		out[k] = v
	}
	return out, nil
}

// diskTypes are the EBS volume types --disk-type accepts.
var diskTypes = []string{"gp3", "gp2", "io1", "io2", "st1", "sc1", "standard"}

// diskFlags are the data disk flags of create.
type diskFlags struct {
	size, iops, throughput int32
	device, typ            string
}

// spec validates the data disk flags; nil means no data disk.
func (f diskFlags) spec(cmd *cobra.Command) (*platform.InstanceDisk, error) {
	changed := func(n string) bool { return cmd.Flags().Changed(n) }
	if f.size == 0 {
		for _, n := range []string{"disk-device", "disk-type", "disk-iops", "disk-throughput"} {
			if changed(n) {
				return nil, app.UsageErrf("--%s needs --disk <GB>", n)
			}
		}
		return nil, nil
	}
	if f.size < 0 {
		return nil, app.UsageErrf("--disk must be a positive size in GB, got %d", f.size)
	}
	if !slices.Contains(diskTypes, f.typ) {
		return nil, app.UsageErrf("--disk-type %q: expected one of %s", f.typ, strings.Join(diskTypes, ", "))
	}
	if !strings.HasPrefix(f.device, "/dev/") {
		return nil, app.UsageErrf("--disk-device %q: expected a device name such as /dev/sdb", f.device)
	}
	d := &platform.InstanceDisk{SizeGB: f.size, Device: f.device, Type: f.typ}
	switch f.typ {
	case "gp3":
		d.IOPS, d.Throughput = f.iops, f.throughput
	case "io1", "io2":
		if !changed("disk-iops") {
			return nil, app.UsageErrf("--disk-type %s needs --disk-iops", f.typ)
		}
		if changed("disk-throughput") {
			return nil, app.UsageErrf("--disk-throughput applies to gp3 only")
		}
		d.IOPS = f.iops
	default:
		if changed("disk-iops") || changed("disk-throughput") {
			return nil, app.UsageErrf("--disk-iops and --disk-throughput do not apply to --disk-type %s", f.typ)
		}
	}
	if d.IOPS < 0 || d.Throughput < 0 {
		return nil, app.UsageErrf("--disk-iops and --disk-throughput must be positive")
	}
	return d, nil
}

func diskDesc(d *platform.InstanceDisk) string {
	keep := "keep"
	if d.DeleteOnTermination {
		keep = "delete"
	}
	return fmt.Sprintf("%dGB(%s, %s, %s)", d.SizeGB, d.Device, d.Type, keep)
}

func createDesc(spec platform.CreateSpec) string {
	parts := []string{"type=" + spec.Type, "ami=" + spec.Image, "subnet=" + spec.Subnet}
	if len(spec.SecurityGroups) > 0 {
		parts = append(parts, "sgs="+strings.Join(spec.SecurityGroups, ","))
	} else {
		parts = append(parts, "sgs=(vpc default)")
	}
	if spec.Disk != nil {
		parts = append(parts, "disk="+diskDesc(spec.Disk))
	}
	if spec.KeyPair != "" {
		parts = append(parts, "key-pair="+spec.KeyPair)
	}
	if !spec.PublicIP {
		parts = append(parts, "public-ip=no")
	}
	return strings.Join(parts, " ")
}

func ec2CreateCmd(rt *app.Runtime) *cobra.Command {
	var typ, ami, osName, arch, subnet, region string
	var sgs, tagArgs []string
	var keys app.KeyFlags
	var disk diskFlags
	var publicIP bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create an EC2 instance (Amazon Linux 2023 by default)",
		Long: `Create an EC2 instance named <name> (its Name tag) in the profile's region, or
--region. An instance of that name that is not terminated is an error (exit
code 1): AWS does not keep names unique, and two instances of one name
cannot be told apart later.

The image is --ami, or the latest Amazon Linux 2023 image of the instance
type's architecture (--arch, by default arm64 for Graviton types and x86_64
otherwise): the SSM parameter al2023-ami-kernel-default-<arch> first, the
newest Amazon "al2023-ami-2023.*-kernel-6.1-<arch>" image when the
parameter cannot be read (the two may use different kernels).

--type, --subnet, --sg and --key-pair default to defaults.aws.instance_type,
subnet_id, security_group_ids and key_name in config.yaml; a missing type
or subnet is a usage error. The network goes into one network interface
with a public IP unless --public-ip=false. --ssh-key / --ssh-key-file bind
the key pair that holds that public key, importing it under --key-pair when
none does. Without any key pair the instance gets no SSH key.

--disk adds a data disk (/dev/sdb, gp3, 3000 IOPS, 125 MiB/s by default)
that is kept when the instance is deleted; encryption follows the
account's EBS default. The Name tag and the tags of defaults.aws.tags and
--tag go on the instance and on its volumes. --wait waits until the
instance is running and prints its addresses.`,
		Example: `  polyctl aws ec2 instance create site-new --type c6a.xlarge --disk 400 --wait --dry-run
  polyctl aws ec2 instance create site-new --type t4g.small --ssh-key-file ~/.ssh/id_ed25519.pub --key-pair ops`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := strings.TrimSpace(args[0])
			if name == "" || len(name) > 256 {
				return app.UsageErrf("the instance name must be 1 to 256 characters")
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if ami != "" && cmd.Flags().Changed("os") {
				return app.UsageErrf("--ami and --os are mutually exclusive")
			}
			if osName != "al2023" {
				return app.UsageErrf("--os %q: only al2023 is supported; pass --ami <ami-id> for another system", osName)
			}
			if arch != "" && arch != "x86_64" && arch != "arm64" {
				return app.UsageErrf("--arch %q: expected x86_64 or arm64", arch)
			}
			diskSpec, err := disk.spec(cmd)
			if err != nil {
				return err
			}
			extraTags, err := parseTags(tagArgs)
			if err != nil {
				return err
			}
			if _, err := keys.PublicKey(); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			if typ, err = rt.RequireSetting(profile, platform.AWS, "instance_type", "type", typ); err != nil {
				return err
			}
			if subnet, err = rt.RequireSetting(profile, platform.AWS, "subnet_id", "subnet", subnet); err != nil {
				return err
			}
			if sgs, err = rt.SettingList(profile, platform.AWS, "security_group_ids", sgs); err != nil {
				return err
			}
			defaultKey, err := rt.Setting(profile, platform.AWS, "key_name", "")
			if err != nil {
				return err
			}
			tags, err := keyPairTags(rt, profile)
			if err != nil {
				return err
			}
			if tags == nil {
				tags = map[string]string{}
			}
			for k, v := range extraTags {
				tags[k] = v
			}
			tags["Name"] = name
			base := keyInputBase()
			base.DefaultName = defaultKey
			keyIn, err := rt.KeyInput(&keys, base)
			if err != nil {
				return err
			}

			c, prof, err := openClient(ctx, rt)
			if err != nil {
				return err
			}
			region = c.regionOr(region)
			target := platform.Target{Platform: platform.AWS, Profile: prof.Name, Region: region}

			existing, err := c.findInstances(ctx, region, name)
			if err != nil {
				return err
			}
			if live := liveInstances(existing); len(live) > 0 {
				return fmt.Errorf("instance %q already exists in %s (%s, %s): use `polyctl aws ec2 instance get %s`, or choose another name",
					name, region, awssdk.ToString(live[0].InstanceId), instanceState(live[0]), name)
			}
			archs, err := c.instanceTypeArchs(ctx, region, typ)
			if err != nil {
				return err
			}
			if arch == "" {
				arch = archFor(archs)
			} else if !slices.Contains(archs, arch) {
				return app.UsageErrf("instance type %s does not run %s (it runs %s)", typ, arch, strings.Join(archs, ", "))
			}
			var img imageInfo
			if ami != "" {
				if img, err = c.describeImage(ctx, region, ami); err != nil {
					return err
				}
				if img.Arch != "" && !slices.Contains(archs, img.Arch) {
					return fmt.Errorf("image %s is %s, which instance type %s does not run (it runs %s)", ami, img.Arch, typ, strings.Join(archs, ", "))
				}
				if img.Arch != "" {
					// The image decides; --arch only picks a default image.
					arch = img.Arch
				}
			} else if img, err = c.latestAL2023AMI(ctx, region, arch, func(s string) { rt.Infof("%s", s) }); err != nil {
				return err
			}
			if diskSpec != nil && img.RootDevice != "" && diskSpec.Device == img.RootDevice {
				return app.UsageErrf("--disk-device %s is the root device of image %s; choose another one", diskSpec.Device, img.ID)
			}

			var plan platform.Plan
			spec := platform.CreateSpec{Name: name, Region: region, Type: typ, Image: img.ID, Arch: arch, Subnet: subnet,
				SecurityGroups: sgs, PublicIP: publicIP, Disk: diskSpec, Tags: tags, ClientToken: newClientToken()}
			if keys.Given() || defaultKey != "" {
				kp, err := platform.ResolveKeyPair(ctx, &keyPairLister{c: c, region: region}, keyIn)
				if err != nil {
					return err
				}
				for _, n := range kp.Notes {
					rt.Infof("%s", n)
				}
				spec.KeyPair = kp.Name
				var kpTags map[string]string
				if kp.Create && !rt.DryRun() {
					if kpTags, err = keyPairTags(rt, prof.Name); err != nil {
						return err
					}
				}
				plan.Add(kp.Step(func(ctx context.Context, name string, key *platform.PublicKey) (string, error) {
					info, err := c.importKeyPair(ctx, region, name, key, kpTags)
					if err != nil {
						return "", err
					}
					storeKeyPair(ctx, rt, c, prof.Name, info)
					return info.KeyPairID, nil
				}))
			} else {
				rt.Infof("note: no key pair (pass --key-pair, --ssh-key or --ssh-key-file, or set defaults.aws.key_name): the instance gets no SSH key")
			}
			if len(sgs) == 0 {
				rt.Infof("note: no security group given (--sg or defaults.aws.security_group_ids): the VPC's default security group is used")
			}
			desc := createDesc(spec)
			plan.Add(platform.Step{Resource: "instance/" + name, Action: platform.Created, Desc: desc, Apply: func(ctx context.Context) (platform.Change, error) {
				id, err := c.CreateInstance(ctx, spec)
				if err != nil {
					return platform.Change{}, err
				}
				storeInstance(ctx, rt, prof.Name, c, region, ec2types.Instance{InstanceId: awssdk.String(id), InstanceType: ec2types.InstanceType(typ),
					State: &ec2types.InstanceState{Name: ec2types.InstanceStateNamePending}, Tags: sortedTags(tags)})
				ch := platform.Change{ID: id, Detail: desc}
				if !wait {
					rt.Infof("instance %s (%s) is starting; `polyctl aws ec2 instance get %s` shows its addresses once it runs", name, id, id)
					return ch, nil
				}
				in, err := c.waitInstanceState(ctx, region, id, name, stateRunning, timeout)
				if err != nil {
					return platform.Change{ID: id}, fmt.Errorf("instance %s (%s) was created but did not become running: %w", name, id, err)
				}
				storeInstance(ctx, rt, prof.Name, c, region, in)
				pub, priv := awssdk.ToString(in.PublicIpAddress), awssdk.ToString(in.PrivateIpAddress)
				ch.Detail = fmt.Sprintf("%s; running, public ip %s, private ip %s", desc, orNone(pub), orNone(priv))
				ch.Attrs = map[string]string{"state": stateRunning, "public_ip": pub, "private_ip": priv}
				rt.Infof("instance %s (%s) is running: public ip %s, private ip %s", name, id, orNone(pub), orNone(priv))
				return ch, nil
			}})
			return rt.Ensure(ctx, "aws.ec2.instance.create", target, &plan)
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "instance type (default: defaults.aws.instance_type)")
	cmd.Flags().StringVar(&ami, "ami", "", "image id (default: the latest image of --os)")
	cmd.Flags().StringVar(&osName, "os", "al2023", "system whose latest image is used when --ami is not given (al2023 only)")
	cmd.Flags().StringVar(&arch, "arch", "", "image architecture, x86_64 or arm64 (default: from the instance type)")
	cmd.Flags().StringVar(&subnet, "subnet", "", "subnet id (default: defaults.aws.subnet_id)")
	cmd.Flags().StringArrayVar(&sgs, "sg", nil, "security group id (repeatable; default: defaults.aws.security_group_ids)")
	app.AddKeyFlags(cmd, &keys)
	cmd.Flags().Int32Var(&disk.size, "disk", 0, "add a data disk of this size in GB (kept when the instance is deleted)")
	cmd.Flags().StringVar(&disk.device, "disk-device", "/dev/sdb", "device name of the data disk")
	cmd.Flags().StringVar(&disk.typ, "disk-type", "gp3", "volume type of the data disk ("+strings.Join(diskTypes, ", ")+")")
	cmd.Flags().Int32Var(&disk.iops, "disk-iops", 3000, "IOPS of the data disk (gp3, io1, io2; required for io1 and io2)")
	cmd.Flags().Int32Var(&disk.throughput, "disk-throughput", 125, "throughput of the data disk in MiB/s (gp3 only)")
	cmd.Flags().BoolVar(&publicIP, "public-ip", true, "assign a public IP (--public-ip=false for none)")
	cmd.Flags().StringArrayVar(&tagArgs, "tag", nil, "extra tag key=value (repeatable; Name is always the instance name)")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: the profile's region)")
	app.AddWaitFlags(cmd, &wf, false, defaultInstanceTimeout)
	return cmd
}

// ------------------------------------------------------------- delete

func ec2DeleteCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:     "delete <name|id>",
		Aliases: []string{"terminate"},
		Short:   "Terminate an EC2 instance (asks first)",
		Long: `Terminate an EC2 instance, found like get finds it. The instance, its
addresses and its volumes are shown first, then a confirmation is asked
(default no; --yes skips it, and the non-interactive flow needs --yes). The
root volume is deleted with the instance; data volumes created by create
are kept and keep costing money until deleted, as do Elastic IPs and
snapshots. An instance with termination protection is not terminated
(exit code 1): switch the protection off in AWS first. A terminated
instance is reported unchanged. --wait waits until it is terminated.`,
		Example: "  polyctl aws ec2 instance delete site-old --yes --wait",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], region, true)
			if err != nil {
				return err
			}
			target := l.target()
			if instanceState(l.inst) == stateTerminated {
				dropInstance(ctx, rt, l.profile, l.id())
				rt.Infof("instance %s is already terminated", instanceLabel(l.inst))
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "already terminated"}}})
			}
			vols, verr := l.c.instanceVolumes(ctx, l.region, l.inst)
			if verr != nil {
				rt.Infof("warning: cannot list the volumes of %s: %v", l.id(), verr)
			}
			root := awssdk.ToString(l.inst.RootDeviceName)
			rt.Infof("instance %s in aws/%s/%s", l.name(), l.profile, l.region)
			rt.Infof("  id          %s", l.id())
			rt.Infof("  type        %s", string(l.inst.InstanceType))
			rt.Infof("  state       %s", instanceState(l.inst))
			rt.Infof("  private ip  %s", orNone(awssdk.ToString(l.inst.PrivateIpAddress)))
			rt.Infof("  public ip   %s", orNone(awssdk.ToString(l.inst.PublicIpAddress)))
			var kept []string
			for _, v := range vols {
				rt.Infof("  volume      %s %s %s %dGB %s", v.VolumeID, v.Device, v.VolumeType, v.Size, volumeNote(v, root))
				if v.DeleteOnTermination {
					rt.Infof("              volume %s will be permanently deleted", v.VolumeID)
				} else {
					kept = append(kept, v.VolumeID)
					rt.Infof("              volume %s will be kept and has to be deleted separately", v.VolumeID)
				}
			}
			rt.Infof("This cannot be undone! The instance and its root volume will be permanently deleted!")
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: "terminate"}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Terminate instance %s?", instanceLabel(l.inst)), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; instance %s was not terminated", platform.ErrNothingToDo, instanceLabel(l.inst))
			}
			if err := l.c.DeleteInstance(ctx, l.region, l.id()); err != nil {
				return err
			}
			if wait {
				if _, err := l.c.waitInstanceState(ctx, l.region, l.id(), l.name(), stateTerminated, timeout); err != nil {
					return fmt.Errorf("termination of %s was requested: %w", instanceLabel(l.inst), err)
				}
				change.Detail = "terminate; terminated"
				rt.Infof("instance %s is terminated", instanceLabel(l.inst))
			} else {
				rt.Infof("termination of %s requested; the instance is deleted within a few minutes", instanceLabel(l.inst))
			}
			dropInstance(ctx, rt, l.profile, l.id())
			if len(kept) > 0 {
				rt.Infof("left behind: data volume(s) %s, now available and still billed; delete them separately when no longer needed", strings.Join(kept, ", "))
			}
			rt.Infof("note: Elastic IPs and snapshots of the instance are not deleted")
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	app.AddWaitFlags(cmd, &wf, false, defaultInstanceTimeout)
	return cmd
}

// ------------------------------------------------------------- reboot

func ec2RebootCmd(rt *app.Runtime) *cobra.Command {
	var region string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "reboot <name|id>",
		Short: "Reboot a running EC2 instance, or start a stopped one",
		Long: `Reboot a running EC2 instance, or start it when it is stopped (rebooting a
stopped instance means starting it). Any other state is exit code 1.

A reboot keeps the instance running with its addresses, so there is no
state to wait for: --wait applies to the start of a stopped instance only,
which waits until it runs and prints its new public IP (it changes unless
the instance has an Elastic IP).`,
		Example: "  polyctl aws ec2 instance reboot site-xz7",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], region, false)
			if err != nil {
				return err
			}
			target := l.target()
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id()}
			switch st := instanceState(l.inst); st {
			case stateRunning:
				change.Detail = "reboot"
				if done, err := rt.WouldWrite(target, change); done || err != nil {
					return err
				}
				if err := l.c.RebootInstance(ctx, l.region, l.id()); err != nil {
					return err
				}
				rt.Infof("reboot of %s requested; allow 1-2 minutes", instanceLabel(l.inst))
				if wait {
					rt.Infof("note: --wait does not apply to a reboot: the instance stays running throughout")
				}
			case stateStopped:
				change.Detail = "start (instance is stopped)"
				if done, err := rt.WouldWrite(target, change); done || err != nil {
					return err
				}
				if err := l.c.startInstanceChecked(ctx, l.region, l.id()); err != nil {
					return err
				}
				if wait {
					in, err := l.c.waitInstanceState(ctx, l.region, l.id(), l.name(), stateRunning, timeout)
					if err != nil {
						return fmt.Errorf("start of %s was requested: %w", instanceLabel(l.inst), err)
					}
					l.inst = in
					pub := awssdk.ToString(in.PublicIpAddress)
					change.Detail += "; running, public ip " + orNone(pub)
					rt.Infof("instance %s is running: public ip %s, private ip %s", instanceLabel(in), orNone(pub), orNone(awssdk.ToString(in.PrivateIpAddress)))
				} else {
					rt.Infof("start of %s requested; its public IP changes unless it has an Elastic IP", instanceLabel(l.inst))
				}
			default:
				return fmt.Errorf("instance %s is %s: it can be neither rebooted nor started now", instanceLabel(l.inst), st)
			}
			l.reread(ctx, rt)
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	app.AddWaitFlags(cmd, &wf, false, defaultInstanceTimeout)
	return cmd
}

// ------------------------------------------------------------- resize

func ec2ResizeCmd(rt *app.Runtime) *cobra.Command {
	var region, typ string
	var start bool
	var timeout time.Duration
	var waitPort int
	cmd := &cobra.Command{
		Use:   "resize <name|id>",
		Short: "Change the type of an EC2 instance: stop, modify, start",
		Long: `Change the instance type of an EC2 instance: stop it when it runs (after a
confirmation, default no; --yes skips it and the non-interactive flow needs
it), change the type, and start it again. Each step waits (5 second polls,
--timeout each). The instance ends in the power state it had: a stopped
instance stays stopped unless --start is given, --start=false leaves a
running one stopped.

The new type is checked before anything is written: an unknown type is a
usage error, a type of another architecture (x86_64 and arm64 cannot be
swapped) or one not offered in the instance's availability zone is exit
code 1. A failed type change leaves the instance stopped with its old type;
running the command again continues from there.

Without an Elastic IP the public IP changes with the restart: the old and
the new one are printed. --wait-port waits until that TCP port (22 for SSH,
3389 for RDP) accepts connections after the start.

A gradual path that works well: c6a.large (2 vCPU, 4 GiB), c6a.xlarge,
c6a.2xlarge, c6a.4xlarge; burstable t3 types can stall under steady load.`,
		Example: "  polyctl aws ec2 instance resize site-xz7 --type c6a.2xlarge --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if typ == "" {
				return app.UsageErrf("--type is required")
			}
			if timeout <= 0 {
				return app.UsageErrf("--timeout must be a positive duration, got %s", timeout)
			}
			if waitPort < 0 || waitPort > 65535 {
				return app.UsageErrf("--wait-port must be a TCP port (1-65535), got %d", waitPort)
			}
			l, err := resolveInstance(ctx, rt, args[0], region, false)
			if err != nil {
				return err
			}
			target := l.target()
			began := time.Now()
			orig, cur := instanceState(l.inst), string(l.inst.InstanceType)
			origPublic := awssdk.ToString(l.inst.PublicIpAddress)
			if orig == stateShuttingDown || orig == stateTerminated {
				return fmt.Errorf("instance %s is %s and cannot be resized", instanceLabel(l.inst), orig)
			}
			wantStart := orig == stateRunning || orig == statePending
			if cmd.Flags().Changed("start") {
				wantStart = start
			}
			same := cur == typ
			if !same {
				archs, err := l.c.instanceTypeArchs(ctx, l.region, typ)
				if err != nil {
					return err
				}
				if a := string(l.inst.Architecture); a != "" && !slices.Contains(archs, a) {
					return fmt.Errorf("instance %s is %s and type %s runs %s: x86_64 and arm64 cannot be swapped by a type change", instanceLabel(l.inst), a, typ, strings.Join(archs, ", "))
				}
				az := ""
				if l.inst.Placement != nil {
					az = awssdk.ToString(l.inst.Placement.AvailabilityZone)
				}
				if az != "" {
					offered, zones, err := l.c.typeOffered(ctx, l.region, typ, az)
					if err != nil {
						return err
					}
					if !offered {
						where := "no zone of " + l.region
						if len(zones) > 0 {
							where = strings.Join(zones, ", ")
						}
						return fmt.Errorf("instance type %s is not offered in %s, the zone of %s (offered in: %s)", typ, az, instanceLabel(l.inst), where)
					}
				}
			}
			running := orig == stateRunning || orig == statePending
			needStop := !same && orig != stateStopped
			needStart := wantStart && (needStop || !running)
			if same && !needStart {
				rt.Infof("instance %s already is %s", instanceLabel(l.inst), typ)
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "type " + typ}}})
			}
			label := l.name()
			var plan platform.Plan
			if needStop {
				plan.Add(platform.Step{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Desc: "stop", Apply: func(ctx context.Context) (platform.Change, error) {
					st := orig
					if st == statePending {
						// StopInstances refuses an instance that never ran.
						if _, err := l.c.waitInstanceState(ctx, l.region, l.id(), label, stateRunning, timeout); err != nil {
							return platform.Change{}, err
						}
						st = stateRunning
					}
					if st == stateRunning {
						if err := l.c.stopInstanceChecked(ctx, l.region, l.id()); err != nil {
							return platform.Change{}, err
						}
					}
					in, err := l.c.waitInstanceState(ctx, l.region, l.id(), label, stateStopped, timeout)
					if err != nil {
						return platform.Change{}, err
					}
					l.inst = in
					storeInstance(ctx, rt, l.profile, l.c, l.region, in)
					return platform.Change{Detail: "stop; stopped"}, nil
				}})
			}
			if !same {
				plan.Add(platform.Step{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Desc: fmt.Sprintf("modify-type %s -> %s", cur, typ), Apply: func(ctx context.Context) (platform.Change, error) {
					if err := l.c.ResizeInstance(ctx, l.region, l.id(), platform.ResizeSpec{Type: typ}); err != nil {
						return platform.Change{}, fmt.Errorf("%w; the instance is stopped and its type is still %s: run the same command again to continue (with --start to start it afterwards)", err, cur)
					}
					return platform.Change{}, nil
				}})
			}
			if needStart {
				plan.Add(platform.Step{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Desc: "start", Apply: func(ctx context.Context) (platform.Change, error) {
					if err := l.c.startInstanceChecked(ctx, l.region, l.id()); err != nil {
						return platform.Change{}, fmt.Errorf("instance %s is stopped with type %s: %w", label, typ, err)
					}
					in, err := l.c.waitInstanceState(ctx, l.region, l.id(), label, stateRunning, timeout)
					if err != nil {
						return platform.Change{}, err
					}
					l.inst = in
					storeInstance(ctx, rt, l.profile, l.c, l.region, in)
					pub := awssdk.ToString(in.PublicIpAddress)
					detail := "start; running, public ip " + orNone(pub)
					if origPublic != "" && pub != origPublic {
						detail = fmt.Sprintf("start; running, public ip %s -> %s", origPublic, orNone(pub))
						rt.Infof("public ip of %s changed: %s -> %s; update the DNS records, SSH configuration and allow lists that use it", label, origPublic, orNone(pub))
					}
					return platform.Change{Detail: detail, Attrs: map[string]string{"public_ip": pub, "private_ip": awssdk.ToString(in.PrivateIpAddress)}}, nil
				}})
			} else if !same && !wantStart {
				rt.Infof("note: instance %s stays stopped (pass --start to start it)", label)
			}
			if needStop && !rt.DryRun() {
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Stop instance %s to change its type from %s to %s? It is unavailable until it runs again.", instanceLabel(l.inst), cur, typ), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not changed", platform.ErrNothingToDo, instanceLabel(l.inst))
				}
			}
			if err := rt.Ensure(ctx, "aws.ec2.instance.resize", target, &plan); err != nil || rt.DryRun() {
				return err
			}
			l.reread(ctx, rt)
			if !same {
				rt.Infof("instance %s resized %s -> %s (%s) in %s", label, cur, typ, instanceState(l.inst), time.Since(began).Round(time.Second))
			}
			if waitPort > 0 && instanceState(l.inst) != stateRunning {
				rt.Infof("note: --wait-port %d skipped: instance %s is %s", waitPort, label, instanceState(l.inst))
			}
			if waitPort > 0 && instanceState(l.inst) == stateRunning {
				host := awssdk.ToString(l.inst.PublicIpAddress)
				if host == "" {
					host = awssdk.ToString(l.inst.PrivateIpAddress)
				}
				if host == "" {
					return fmt.Errorf("instance %s has no address to check port %d on", label, waitPort)
				}
				addr := net.JoinHostPort(host, strconv.Itoa(waitPort))
				if err := waitTCPPort(ctx, addr, label, timeout); err != nil {
					return err
				}
				rt.Infof("port %d of %s accepts connections", waitPort, addr)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "new instance type (required)")
	cmd.Flags().BoolVar(&start, "start", false, "start the instance after the change (default: the power state it had; --start=false leaves it stopped)")
	cmd.Flags().DurationVar(&timeout, "timeout", defaultInstanceTimeout, "upper bound of each wait (a Go duration such as 90s or 10m)")
	cmd.Flags().IntVar(&waitPort, "wait-port", 0, "after the start, wait until this TCP port accepts connections (22 for SSH, 3389 for RDP)")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	return cmd
}
