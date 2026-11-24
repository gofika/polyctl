package gcp

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive picks of the gcp commands: what a resource is (name, id)
// and the facts that tell candidates apart (zone, status, type, CIDR,
// account). Every list holds only usable candidates (x86 only, available
// only, not deprecated); see README "Interactive and non-interactive use".

// otherValue is the value of the "Other ..." option of a pick.
const otherValue = "\x00other"

// joinLabel joins the non-empty parts of a label with two spaces.
func joinLabel(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "  ")
}

// instanceOptionLabel: "web-1  1234  RUNNING  e2-medium  us-central1-a
// 10.128.0.5  203.0.113.10  gcp/lab".
func instanceOptionLabel(in Instance, profile string) string {
	return joinLabel(in.Name, in.ID, in.Status, in.MachineType, in.Zone, in.InternalIP, in.ExternalIP, "gcp/"+profile)
}

// statusIn keeps the instances in one of the statuses.
func statusIn(statuses ...string) func(Instance) bool {
	return func(in Instance) bool { return slices.Contains(statuses, in.Status) }
}

// stoppedInstance keeps the instances start can start.
func stoppedInstance(in Instance) bool { return stopped(in.Status) || in.Status == "SUSPENDED" }

// pickInstanceRef asks for an instance of the selected GCP accounts in the
// interactive flow, from the inventory (synced first when stale, never
// with --offline): those in zone when it is given, those keep accepts
// (nil: all). The value is the instance id, which resolveInstance finds
// again. what names the candidates of an empty list ("stopped GCP
// instance"); arg is the input for messages ("<name|id>"). required turns
// an empty list into a usage error naming arg instead of "nothing to do".
func pickInstanceRef(ctx context.Context, rt *app.Runtime, arg, zone, what string, required bool, keep func(Instance) bool) (string, error) {
	return rt.PickResource(ctx, app.ResourcePick{Platform: platform.GCP, Kind: platform.ResInstance,
		Title: "Instance", Arg: arg, What: what, Required: required,
		Filter: func(r inventory.Resource) bool {
			var in Instance
			if r.Decode(&in) != nil {
				return false
			}
			if zone != "" && in.Zone != zone {
				return false
			}
			return keep == nil || keep(in)
		},
		Label: func(r inventory.Resource) string {
			var in Instance
			_ = r.Decode(&in)
			return instanceOptionLabel(in, r.Profile)
		}})
}

// instanceArg fills in a missing <name|id> of an instance command in the
// interactive flow with pickInstanceRef; with the argument given, args is
// returned as it is.
func instanceArg(ctx context.Context, rt *app.Runtime, args []string, zone, what string, keep func(Instance) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	id, err := pickInstanceRef(ctx, rt, "<name|id>", zone, what, false, keep)
	if err != nil {
		return nil, err
	}
	return []string{id}, nil
}

// disambiguate turns an ambiguous lookup into a pick in the interactive
// flow: amb gets one option per candidate (value: its index, label: label
// of it) and the candidate chosen is returned. The non-interactive flow
// gets amb back (exit code 5).
func disambiguate[T any](rt *app.Runtime, amb *app.AmbiguousError, found []T, label func(T) string) (T, error) {
	var zero T
	for i, f := range found {
		amb.Options = append(amb.Options, prompt.Option{Label: label(f), Value: strconv.Itoa(i)})
	}
	v, err := rt.Disambiguate(amb)
	if err != nil {
		return zero, err
	}
	i, err := strconv.Atoi(v)
	if err != nil || i < 0 || i >= len(found) {
		return zero, fmt.Errorf("unexpected choice %q", v)
	}
	return found[i], nil
}

// defaultPickMachineType is the type preselected by the machine type pick
// of create.
const defaultPickMachineType = "e2-medium"

// machineTypeLabel: "e2-medium  2 vCPU  4 GB  shared core".
func machineTypeLabel(mt *compute.MachineType) string {
	gb := strconv.FormatFloat(float64(mt.MemoryMb)/1024, 'f', -1, 64)
	shared := ""
	if mt.IsSharedCpu {
		shared = "shared core"
	}
	return joinLabel(mt.Name, fmt.Sprintf("%d vCPU", mt.GuestCpus), gb+" GB", shared)
}

// e2Rank orders the E2 presets first, in the order of e2Presets.
func e2Rank(name string) int {
	for i, p := range e2Presets {
		if p.Name == name {
			return i
		}
	}
	return len(e2Presets)
}

// pickMachineType asks for the --machine-type of create and resize in the
// interactive flow: the machine types of zone that the pick offers
// (usableMachineType: x86_64, current families, not deprecated), the E2
// presets first, current (the type of the instance a resize changes) left
// out, def preselected; then "Size <cores>H<memory>G...", a size checked
// as it is typed and resolved as --machine-type resolves it. x86 false (an
// Arm instance) asks for an exact type only: no Arm type is ever proposed.
// The non-interactive flow returns the usage error "--machine-type is
// required".
func pickMachineType(ctx context.Context, rt *app.Runtime, c *client, zone, current, def string, x86 bool) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("--machine-type is required")
	}
	if !x86 {
		return rt.AskInput("--machine-type", "Exact machine type of the instance's architecture (such as c4a-standard-2)", "", func(s string) error {
			if strings.TrimSpace(s) == "" || strings.ContainsAny(s, " /") {
				return fmt.Errorf("a machine type such as c4a-standard-2 is required")
			}
			return nil
		})
	}
	types, err := c.listMachineTypes(ctx, zone)
	if err != nil {
		return "", err
	}
	sort.SliceStable(types, func(i, j int) bool {
		a, b := types[i], types[j]
		if ra, rb := e2Rank(a.Name), e2Rank(b.Name); ra != rb {
			return ra < rb
		}
		fa, _, _ := strings.Cut(a.Name, "-")
		fb, _, _ := strings.Cut(b.Name, "-")
		if fa != fb {
			return slices.Index(pickMachineFamilies, fa) < slices.Index(pickMachineFamilies, fb)
		}
		if a.GuestCpus != b.GuestCpus {
			return a.GuestCpus < b.GuestCpus
		}
		if a.MemoryMb != b.MemoryMb {
			return a.MemoryMb < b.MemoryMb
		}
		return a.Name < b.Name
	})
	var opts []prompt.Option
	for _, mt := range types {
		if mt.Name == current {
			continue
		}
		opts = append(opts, prompt.Option{Label: machineTypeLabel(mt), Value: mt.Name})
	}
	title := "Machine type (" + zone + ")"
	if current != "" {
		title = "Machine type (" + zone + "; currently " + current + ")"
	}
	v := otherValue
	if len(opts) > 0 {
		if !slices.ContainsFunc(opts, func(o prompt.Option) bool { return o.Value == def }) {
			def = ""
		}
		opts = append(opts, prompt.Option{Label: "Size <cores>H<memory>G (an E2 type of that shape)...", Value: otherValue})
		if v, err = rt.Pick().Select(title, opts, def); err != nil {
			return "", err
		}
	}
	if v != otherValue {
		return v, nil
	}
	return rt.AskInput("--machine-type", "Size <cores>H<memory>G (such as 4H8G)", "", func(s string) error {
		_, isSize, err := platform.ParseTypeShorthand(strings.TrimSpace(s))
		if err != nil {
			return err
		}
		if !isSize {
			return fmt.Errorf("%q is not a size such as 4H8G", s)
		}
		return nil
	})
}

// pickZone asks for the --zone of create in the interactive flow: the
// zones of the project that are UP and not deprecated, labelled with their
// region, the zone most of the profile's known instances use preselected
// (else none). The non-interactive flow returns the usage error of a
// missing zone.
func pickZone(ctx context.Context, rt *app.Runtime, c *client, profile string) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("zone is required: pass --zone, or set defaults.gcp.zone")
	}
	zones, err := c.listZonesUp(ctx)
	if err != nil {
		return "", err
	}
	used := map[string]int{}
	if db, err := rt.DB(); err == nil {
		rows, _ := db.List(ctx, inventory.Query{Platform: platform.GCP, Profile: profile, Type: platform.ResInstance})
		for _, r := range rows {
			used[r.ParentID]++
		}
	}
	var opts []prompt.Option
	def, best := "", 0
	for _, z := range zones {
		opts = append(opts, prompt.Option{Label: joinLabel(z.Name, "("+lastSegment(z.Region)+")"), Value: z.Name})
		if used[z.Name] > best {
			def, best = z.Name, used[z.Name]
		}
	}
	return rt.Choose(app.Choice{Title: "Zone", Options: opts, Default: def, Arg: "--zone", Required: true, What: "zone that is UP"})
}

// networkLabel: "default  auto  42 subnets".
func networkLabel(n *compute.Network) string {
	return joinLabel(n.Name, networkMode(n), fmt.Sprintf("%d subnets", len(n.Subnetworks)))
}

// builtinNetwork returns the network a command uses when neither the flag
// nor defaults.gcp.network names one: "default" when the project has it;
// otherwise, in the interactive flow, a network picked from the project's
// VPC networks, and "default" in the non-interactive flow (which then
// fails where the network is read).
func builtinNetwork(ctx context.Context, rt *app.Runtime, c *client) (string, error) {
	if !rt.Interactive() {
		return "default", nil
	}
	nets, err := c.listNetworks(ctx)
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, n := range nets {
		if n.Name == "default" {
			return "default", nil
		}
		opts = append(opts, prompt.Option{Label: networkLabel(n), Value: n.Name})
	}
	def := ""
	if len(opts) == 1 {
		def = opts[0].Value
	}
	return rt.Choose(app.Choice{Title: "VPC network (the project has no network named default)", Options: opts, Default: def,
		Arg: "--network", Required: true, What: "VPC network"})
}

// pickSubnet asks, in the interactive flow, which of several subnetworks
// of a network in a region create uses: the ordinary ones (no proxy-only
// or other special purpose), labelled with their range.
func pickSubnet(rt *app.Runtime, network, region string, subs []*compute.Subnetwork) (string, error) {
	var opts []prompt.Option
	for _, s := range subs {
		if s.Purpose != "" && !strings.EqualFold(s.Purpose, "PRIVATE") {
			continue
		}
		opts = append(opts, prompt.Option{Label: joinLabel(s.Name, s.IpCidrRange, region), Value: s.Name})
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].Value < opts[j].Value })
	if len(opts) == 1 {
		return opts[0].Value, nil
	}
	return rt.Choose(app.Choice{Title: "Subnetwork of " + network + " in " + region, Options: opts, Arg: "--subnet", Required: true, What: "subnetwork"})
}

// errNoLocalKey says there is no ~/.ssh/*.pub to offer and nothing was
// typed: the caller keeps its own usage error.
var errNoLocalKey = errors.New("no local public key")

// pickSSHKey asks, in the interactive flow, for a public key to put into
// the ssh-keys metadata of a new Linux instance when the project offers
// no SSH login: the usable ~/.ssh/*.pub files (type, fingerprint,
// comment; those already in the project metadata marked), or "Another
// file..." for a path checked as it is typed. A key whose user cannot be
// told (no user: prefix, no e-mail comment, no --ssh-user) asks for the
// user. No local key file returns errNoLocalKey.
func pickSSHKey(rt *app.Runtime, sshUser string, md *compute.Metadata) ([]sshKey, error) {
	present := metadataKeys(md)
	var opts []prompt.Option
	def := ""
	for _, path := range platform.PublicKeyFiles() {
		pk, err := platform.LoadPublicKeyFile(path)
		if err != nil || pk.CheckType(platform.AnyKeyTypes) != nil {
			continue
		}
		label := joinLabel(app.HomeRelative(path), pk.Summary())
		for _, m := range present {
			if string(m.Key.Marshal()) == string(pk.Key.Marshal()) {
				label += "  [in project metadata]"
				break
			}
		}
		if def == "" || filepath.Base(path) == "id_ed25519.pub" {
			def = path
		}
		opts = append(opts, prompt.Option{Label: label, Value: path})
	}
	if len(opts) == 0 {
		return nil, errNoLocalKey
	}
	opts = append(opts, prompt.Option{Label: "Another file...", Value: otherValue})
	pick := rt.Pick()
	path, err := pick.Select("SSH public key for the instance (the project metadata offers no SSH login)", opts, def)
	if err != nil {
		return nil, err
	}
	if path == otherValue {
		if path, err = pick.Input("Path of the public key file (.pub)", "", func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("a path is required")
			}
			_, err := platform.LoadPublicKeyFile(s)
			return err
		}); err != nil {
			return nil, err
		}
	}
	keys, err := loadSSHKeyFile(path, sshUser)
	if err == nil || sshUser != "" || !strings.Contains(err.Error(), "cannot tell the user") {
		return keys, err
	}
	user, err := pick.Input("User of the key on the instance (--ssh-user)", "", func(s string) error {
		return checkSSHUser(strings.TrimSpace(s), "--ssh-user")
	})
	if err != nil {
		return nil, err
	}
	return loadSSHKeyFile(path, strings.TrimSpace(user))
}
