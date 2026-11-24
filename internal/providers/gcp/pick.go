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
