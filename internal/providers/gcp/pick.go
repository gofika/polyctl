package gcp

import (
	"context"
	"errors"
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
// only, not deprecated); see docs/interactive.md.

// otherValue is the value of the "Other ..." option of a pick.
const otherValue = "\x00other"

// The labels are rows of cells (prompt.Cells): a fact keeps its position
// in every row of a list, and "-" stands for one a row does not have.

// instanceOptionLabel: "web-1  1234  RUNNING  e2-medium  us-central1-a
// 10.128.0.5  203.0.113.10  project p1  gcp/lab"; an instance without an
// external address shows "-" in its cell.
func instanceOptionLabel(in Instance, profile string) string {
	project := ""
	if in.Project != "" {
		project = "project " + in.Project
	}
	return prompt.Cells(in.Name, in.ID, in.Status, in.MachineType, in.Zone, in.InternalIP, in.ExternalIP, project, "gcp/"+profile)
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
			if !keepProject(rt, r.Profile, in.Project) {
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
	return prompt.Cells(mt.Name, fmt.Sprintf("%d vCPU", mt.GuestCpus), gb+" GB", shared)
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
			// Only the instances of the project the new one goes to count.
			if project, zone := locationOf(r.ParentID); project == c.project {
				used[zone]++
			}
		}
	}
	var opts []prompt.Option
	def, best := "", 0
	for _, z := range zones {
		opts = append(opts, prompt.Option{Label: prompt.Cells(z.Name, lastSegment(z.Region)), Value: z.Name})
		if used[z.Name] > best {
			def, best = z.Name, used[z.Name]
		}
	}
	return rt.Choose(app.Choice{Title: "Zone", Options: opts, Default: def, Arg: "--zone", Required: true, What: "zone that is UP"})
}

// networkLabel: "default  auto  42 subnets".
func networkLabel(n *compute.Network) string {
	return prompt.Cells(n.Name, networkMode(n), fmt.Sprintf("%d subnets", len(n.Subnetworks)))
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
		// Without the permission to list networks, "default" is used as in
		// the non-interactive flow: reading it reports what is wrong.
		rt.Verbosef("list networks: %v", err)
		return "default", nil
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

// ordinarySubnet reports a subnetwork instances can use: no purpose, or
// PRIVATE (not proxy-only or another special purpose).
func ordinarySubnet(s *compute.Subnetwork) bool {
	return s.Purpose == "" || strings.EqualFold(s.Purpose, "PRIVATE")
}

// pickSubnet asks, in the interactive flow, which of several subnetworks
// of a network in a region create uses: the ordinary ones (no proxy-only
// or other special purpose), labelled with their range.
func pickSubnet(rt *app.Runtime, network, region string, subs []*compute.Subnetwork) (string, error) {
	var opts []prompt.Option
	for _, s := range subs {
		if !ordinarySubnet(s) {
			continue
		}
		opts = append(opts, prompt.Option{Label: prompt.Cells(s.Name, s.IpCidrRange, region), Value: s.Name})
	}
	sort.Slice(opts, func(i, j int) bool { return opts[i].Value < opts[j].Value })
	if len(opts) == 1 {
		return opts[0].Value, nil
	}
	return rt.Choose(app.Choice{Title: "Subnetwork of " + network + " in " + region, Options: opts, Arg: "--subnet", Required: true, What: "subnetwork"})
}

// typedSSHKeySource is the source of a public key typed in the
// interactive flow.
const typedSSHKeySource = platform.TypedKeySource

// pickSSHKey asks, in the interactive flow, for a public key to put into
// the ssh-keys metadata of a new Linux instance when the project offers
// no SSH login: the usable ~/.ssh/*.pub files (type, fingerprint,
// comment; those already in the project metadata marked), "Another
// file..." for a path checked as it is typed, or "Enter a public key..."
// for the key itself (one line, an optional "user:" prefix), checked as
// it is typed. A key whose user cannot be told (no user: prefix, no e-mail
// comment, no --ssh-user) asks for the user. A key the project metadata
// already holds for that user is pointed out: the instance can rely on the
// project key (no keys returned) unless the project blocks its keys, or
// the key is added to the instance anyway.
func pickSSHKey(rt *app.Runtime, sshUser string, md *compute.Metadata) ([]sshKey, error) {
	present := metadataKeys(md)
	var candidates []platform.KeyFileCandidate
	for _, path := range platform.PublicKeyFiles() {
		pk, err := platform.LoadPublicKeyFile(path)
		if err != nil || pk.CheckType(platform.AnyKeyTypes) != nil {
			continue
		}
		c := platform.KeyFileCandidate{Path: path, Key: pk}
		for _, m := range present {
			if pk.Equal(m.Key) {
				c.Note = "in project metadata"
				break
			}
		}
		candidates = append(candidates, c)
	}
	pick := rt.Pick()
	choice, err := app.PickKeyFile(pick, "SSH public key for the instance (the project metadata offers no SSH login)", candidates)
	if err != nil {
		return nil, err
	}
	var keys []sshKey
	switch {
	case app.IsTypedKey(choice):
		keys, err = askTypedSSHKey(pick, sshUser)
	case app.IsOtherKeyFile(choice):
		var path string
		if path, err = pick.Input("Path of the public key file (.pub)", "", func(s string) error {
			if strings.TrimSpace(s) == "" {
				return errors.New("a path is required")
			}
			_, err := platform.LoadPublicKeyFile(s)
			return err
		}); err != nil {
			return nil, err
		}
		keys, err = loadPickedKeyFile(pick, path, sshUser)
	default:
		keys, err = loadPickedKeyFile(pick, choice, sshUser)
	}
	if err != nil {
		return nil, err
	}
	return projectKeyOrInstance(rt, md, present, keys)
}

// loadPickedKeyFile reads a picked public key file; when the user of its
// key cannot be told, the user is asked.
func loadPickedKeyFile(pick prompt.Picker, path, sshUser string) ([]sshKey, error) {
	keys, err := loadSSHKeyFile(path, sshUser)
	if err == nil || sshUser != "" || !strings.Contains(err.Error(), "cannot tell the user") {
		return keys, err
	}
	user, err := askKeyUser(pick)
	if err != nil {
		return nil, err
	}
	return loadSSHKeyFile(path, user)
}

// askTypedSSHKey asks for a public key itself (one line, an optional
// "user:" prefix), checked as it is typed, and then for its user when it
// cannot be told.
func askTypedSSHKey(pick prompt.Picker, sshUser string) ([]sshKey, error) {
	parse := func(text string) (string, *platform.PublicKey, error) {
		prefix, rest := splitUser(strings.TrimSpace(text))
		pk, err := platform.ParseTypedPublicKey(rest)
		if err == nil {
			err = pk.CheckType(platform.AnyKeyTypes)
		}
		if err == nil && prefix != "" {
			err = checkSSHUser(prefix, "user: prefix")
		}
		return prefix, pk, err
	}
	text, err := pick.Input("Public key (one line: \"ssh-ed25519 AAAA... comment\", optionally user:...)", "", func(s string) error {
		_, _, err := parse(s)
		return inlineErr(err)
	})
	if err != nil {
		return nil, err
	}
	prefix, pk, err := parse(text)
	if err != nil {
		return nil, err
	}
	user, err := keyUser(prefix, sshUser, pk, typedSSHKeySource)
	if err != nil {
		if prefix != "" || sshUser != "" || !strings.Contains(err.Error(), "cannot tell the user") {
			return nil, err
		}
		if user, err = askKeyUser(pick); err != nil {
			return nil, err
		}
	}
	return []sshKey{{User: user, Key: pk, Source: typedSSHKeySource}}, nil
}

func askKeyUser(pick prompt.Picker) (string, error) {
	user, err := pick.Input("User of the key on the instance (--ssh-user)", "", func(s string) error {
		return checkSSHUser(strings.TrimSpace(s), "--ssh-user")
	})
	return strings.TrimSpace(user), err
}

// projectKeyOrInstance points out keys the project metadata already holds
// for the same user. When the project does not block its keys, the user
// may rely on them (no keys for the instance) or add them to the instance
// anyway; when it does, they are added to the instance, with a note.
func projectKeyOrInstance(rt *app.Runtime, md *compute.Metadata, present []metadataKey, keys []sshKey) ([]sshKey, error) {
	var inProject []sshKey
	for _, k := range keys {
		for _, m := range present {
			if k.same(m.User, m.Key) {
				inProject = append(inProject, k)
				break
			}
		}
	}
	if len(inProject) == 0 || len(inProject) != len(keys) {
		return keys, nil
	}
	if projectKeysBlocked(md) {
		rt.Infof("note: the key of user %s is in the project metadata, but the project blocks its SSH keys (block-project-ssh-keys=TRUE): it is added to the instance", inProject[0].User)
		return keys, nil
	}
	const useProject, addAnyway = "project", "instance"
	v, err := rt.Pick().Select(fmt.Sprintf("This public key is already in the project metadata for user %q", inProject[0].User), []prompt.Option{
		{Label: "Use the project key (no ssh-keys metadata on the instance)", Value: useProject},
		{Label: "Add it to the instance anyway", Value: addAnyway},
	}, useProject)
	if err != nil {
		return nil, err
	}
	if v == useProject {
		return nil, nil
	}
	return keys, nil
}

// inlineErr drops the "invalid input: " prefix of an error shown under a
// question.
func inlineErr(err error) error {
	if err == nil {
		return nil
	}
	return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
}

// zoneArg fills in a missing <zone> of a gcp dns command in the
// interactive flow with a managed zone of the profile (from the
// inventory, synced when stale), labelled "<zone>  <dns name>
// <visibility>  <N> nameservers  project <id>"; the value is the zone id
// ("<project>/<managed zone>"), which resolveZone finds again. required (upsert) turns an empty list
// into a usage error naming <zone> (polyctl cannot create managed zones)
// instead of "nothing to do". With the argument given, args is returned.
func zoneArg(ctx context.Context, rt *app.Runtime, args []string, profile string, required bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	if !rt.Interactive() {
		return nil, app.UsageErrf("<zone> is required")
	}
	zones, _, err := cachedZones(ctx, rt, profile)
	if err != nil && !errors.Is(err, inventory.ErrNeverSynced) {
		return nil, err
	}
	sort.Slice(zones, func(i, j int) bool { return zones[i].ID < zones[j].ID })
	var opts []prompt.Option
	for _, z := range zones {
		opts = append(opts, prompt.Option{Label: zoneLabel(z), Value: z.ID})
	}
	def := ""
	if len(opts) == 1 {
		def = opts[0].Value
	}
	v, err := rt.Choose(app.Choice{Title: "Managed zone", Options: opts, Default: def, Arg: "<zone>", Required: required,
		What: "managed zone in gcp/" + profile})
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// recordSet is the records of one name and type of a zone.
type recordSet struct {
	Name, Type string
	Records    []platform.Record
}

// recordSetsOf groups records into sets, sorted by name and type.
func recordSetsOf(recs []platform.Record) []recordSet {
	sortRecords(recs)
	var out []recordSet
	for _, r := range recs {
		if n := len(out); n > 0 && out[n-1].Name == r.Name && out[n-1].Type == r.Type {
			out[n-1].Records = append(out[n-1].Records, r)
			continue
		}
		out = append(out, recordSet{Name: r.Name, Type: r.Type, Records: []platform.Record{r}})
	}
	return out
}

// recordValue is a record value as shown: "10 mail.example.com" for MX.
func recordValue(r platform.Record) string {
	if r.Priority != nil {
		return fmt.Sprintf("%d %s", *r.Priority, r.Value)
	}
	return r.Value
}

// recordSetLabel: "www.example.com  A  192.0.2.1  ttl 300  +1 more"; a set
// without a TTL and with several values shows "-" in the TTL cell.
func recordSetLabel(s recordSet) string {
	v, more := recordValue(s.Records[0]), ""
	if n := len(s.Records); n > 1 {
		more = fmt.Sprintf("+%d more", n-1)
	}
	ttl := ""
	if s.Records[0].TTL > 0 {
		ttl = fmt.Sprintf("ttl %d", s.Records[0].TTL)
	}
	return prompt.Cells(s.Name, s.Type, v, ttl, more)
}

// pickRecordToDelete asks, in the interactive flow, which record set of
// zone z to delete (the apex SOA and NS sets, which Cloud DNS refuses to
// delete, left out), then, for a set of several values, the whole set or
// one value. It returns the set and the value chosen (nil: the whole
// set). An empty zone is nothing to do.
func pickRecordToDelete(rt *app.Runtime, z *zoneRef, recs []platform.Record) (recordSet, *platform.Record, error) {
	sets := recordSetsOf(recs)
	var opts []prompt.Option
	for i, s := range sets {
		if (s.Type == "SOA" || s.Type == "NS") && platform.NormalizeDomain(s.Name) == platform.NormalizeDomain(z.Name) {
			continue
		}
		opts = append(opts, prompt.Option{Label: recordSetLabel(s), Value: strconv.Itoa(i)})
	}
	v, err := rt.Choose(app.Choice{Title: "Record set to delete", Options: opts, Arg: "<name> and <type>", What: "deletable record set in zone " + z.ID})
	if err != nil {
		return recordSet{}, nil, err
	}
	i, _ := strconv.Atoi(v)
	s := sets[i]
	if len(s.Records) == 1 {
		return s, nil, nil
	}
	vopts := []prompt.Option{{Label: fmt.Sprintf("The whole set (%d values)", len(s.Records)), Value: "all"}}
	for j, r := range s.Records {
		vopts = append(vopts, prompt.Option{Label: "Only " + recordValue(r), Value: strconv.Itoa(j)})
	}
	w, err := rt.Pick().Select("Delete which values of "+s.Name+" "+s.Type+"?", vopts, "all")
	if err != nil || w == "all" {
		return s, nil, err
	}
	j, _ := strconv.Atoi(w)
	return s, &s.Records[j], nil
}
