package gcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/secrets"
)

// ------------------------------------------------------------ routing

// locatedInstance is an instance found for a command, with the client of
// the account that holds it. inst is read live.
type locatedInstance struct {
	c       *client
	profile string
	zone    string
	inst    *compute.Instance
}

func (l *locatedInstance) name() string     { return l.inst.Name }
func (l *locatedInstance) region() string   { return regionOf(l.zone) }
func (l *locatedInstance) resource() string { return "instance/" + l.inst.Name }

func (l *locatedInstance) target() platform.Target {
	return platform.Target{Platform: platform.GCP, Profile: l.profile, Project: l.c.project, Zone: l.zone}
}

func (l *locatedInstance) label() string {
	return fmt.Sprintf("%s (gcp/%s, project %s, zone %s)", l.inst.Name, l.profile, l.c.project, l.zone)
}

// gcpAccounts returns the GCP accounts selected by --profile.
func gcpAccounts(rt *app.Runtime) ([]config.AccountRef, error) {
	all, err := rt.Accounts()
	if err != nil {
		return nil, err
	}
	var out []config.AccountRef
	for _, a := range all {
		if a.Platform == platform.GCP {
			out = append(out, a)
		}
	}
	if len(out) == 0 {
		if _, err := rt.ProfileFor(platform.GCP); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: no GCP account selected", platform.ErrUnauthorized)
	}
	return out, nil
}

// openProfile opens the GCP client of a profile for a command: bound to
// the default project of the account, or, with --project, pinned to that
// one.
func openProfile(ctx context.Context, rt *app.Runtime, profile string) (*client, error) {
	c, err := openAccount(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	if pin := pinnedProject(rt); pin != "" {
		return c.pin(pin), nil
	}
	return c, nil
}

// openAccount opens the GCP client of a profile as the inventory sync
// uses it: bound to the default project, whatever --project says.
func openAccount(ctx context.Context, rt *app.Runtime, profile string) (*client, error) {
	c, _, err := rt.Open(ctx, profile, platform.GCP)
	if err != nil {
		return nil, err
	}
	gc, ok := c.(*client)
	if !ok {
		return nil, fmt.Errorf("unexpected client type %T for gcp", c)
	}
	return gc, nil
}

// instanceHit is an inventory row that matches the instance asked for.
// inst.Project is always set: rows stored without it are of the default
// project of the account.
type instanceHit struct {
	profile string
	inst    Instance
}

// inventoryInstanceHits returns the cached instances (any status) that
// ref names: by id, else by name, or with byIP by internal or external IP.
// When none does (and always with --refresh), the instance sets of the
// accounts are synced once and the lookup repeated. A sync that fails is returned
// as syncErr: the instance may be in that account.
func inventoryInstanceHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, ref string, byIP bool) (hits []instanceHit, syncErr error, err error) {
	db, err := rt.DB()
	if err != nil {
		return nil, nil, err
	}
	lookup := func() ([]instanceHit, error) {
		var byID, other []instanceHit
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.GCP, Profile: a.Profile, Type: platform.ResInstance})
			if err != nil {
				return nil, err
			}
			def, _, _ := accountProjects(rt, a.Profile)
			for _, r := range rows {
				var in Instance
				if err := r.Decode(&in); err != nil {
					continue
				}
				if in.Project == "" {
					in.Project = def
				}
				// --project pins the instance: one of the same name in
				// another project is another machine.
				if !keepProject(rt, a.Profile, in.Project) {
					continue
				}
				h := instanceHit{profile: a.Profile, inst: in}
				switch {
				case byIP:
					if in.InternalIP == ref || in.ExternalIP == ref {
						other = append(other, h)
					}
				case in.ID == ref:
					byID = append(byID, h)
				case in.Name == ref:
					other = append(other, h)
				}
			}
		}
		if len(byID) > 0 {
			return byID, nil
		}
		return other, nil
	}
	if !rt.Flags.Refresh {
		if hits, err = lookup(); err != nil || len(hits) > 0 || rt.Flags.Offline {
			return hits, nil, err
		}
	}
	// A miss syncs every selected account once: an instance created
	// since the last sync is not in a set that is still fresh. An account
	// whose pinned project is outside its selection has nothing to sync:
	// that project is asked live (liveInstanceHits).
	var stale []config.AccountRef
	for _, a := range accounts {
		if !pinUnselected(rt, a.Profile) {
			stale = append(stale, a)
		}
	}
	if len(stale) == 0 {
		return nil, nil, nil
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
			rt.Infof("warning: sync %s: %v", a.Label(), err)
			if syncErr == nil {
				syncErr = fmt.Errorf("sync %s: %w", a.Label(), err)
			}
		}
	}
	hits, err = lookup()
	return hits, syncErr, err
}

// resolveInstance finds the instance ref names without the user naming the
// account: the inventory of every selected GCP account is searched by id
// and by name (with allowIP, an IP address is looked up among the
// instances' internal and external IPs), in every status. --zone keeps
// only the matches in that zone (a name is unique only within a zone, so
// a match elsewhere is another machine), and finds an instance of that
// zone the inventory does not know yet; with no match in the zone it is
// not found (exit code 4), naming the zones that hold the name. --project
// keeps only the matches in that project, in the same way, and a project
// outside the selection of its account is asked live. Several matches (a
// name held in several zones, projects or accounts) are settled by
// chooseHit: the interactive flow asks which one, the non-interactive flow
// fails with exit code 5. The instance is then read live: the inventory may
// be stale.
func resolveInstance(ctx context.Context, rt *app.Runtime, ref, zone string, allowIP bool) (*locatedInstance, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, app.UsageErrf("the instance name, id or IP is empty")
	}
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	accounts, err := gcpAccounts(rt)
	if err != nil {
		return nil, err
	}
	byIP := allowIP && net.ParseIP(ref) != nil
	hits, syncErr, err := inventoryInstanceHits(ctx, rt, accounts, ref, byIP)
	if err != nil {
		return nil, err
	}
	if len(hits) == 0 {
		// A pinned project outside the selection is not in the inventory.
		live, err := liveInstanceHits(ctx, rt, accounts, ref, byIP)
		if err != nil {
			return nil, err
		}
		hits = live
	}
	// An explicit --zone pins the instance: names are unique only within
	// a zone, so a match in another zone is another machine.
	var elsewhere []string
	if zone != "" {
		var inZone []instanceHit
		for _, h := range hits {
			if h.inst.Zone == zone {
				inZone = append(inZone, h)
			} else if !slices.Contains(elsewhere, h.inst.Zone) {
				elsewhere = append(elsewhere, h.inst.Zone)
			}
		}
		hits = inZone
	}
	if len(hits) == 0 && zone != "" && !byIP {
		// Not cached yet: ask each project of each account in that zone.
		scopes, err := scopesOf(rt, accounts)
		if err != nil {
			return nil, err
		}
		var found []*locatedInstance
		for _, sc := range scopes {
			c, err := openScope(ctx, rt, sc)
			if err != nil {
				return nil, err
			}
			in, err := c.findInstance(ctx, zone, ref)
			if err != nil {
				if len(scopes) > 1 && isAPIDisabled(err) {
					continue
				}
				return nil, err
			}
			if in != nil {
				found = append(found, &locatedInstance{c: c, profile: sc.profile, zone: zone, inst: in})
			}
		}
		if len(found) == 1 {
			storeInstance(ctx, rt, found[0].c, found[0].profile, found[0].inst)
			return found[0], nil
		}
		for _, f := range found {
			hits = append(hits, instanceHit{profile: f.profile, inst: f.c.instanceOf(f.inst)})
		}
	}
	what := "instance"
	if byIP {
		what = "instance with IP"
	}
	switch {
	case len(hits) == 0:
		if len(elsewhere) > 0 {
			sort.Strings(elsewhere)
			if len(elsewhere) == 1 {
				return nil, fmt.Errorf("%w: %s %q in zone %s (one is in zone %s; pass that --zone to use it)", platform.ErrNotFound, what, ref, zone, elsewhere[0])
			}
			return nil, fmt.Errorf("%w: %s %q in zone %s (it is in zones %s; pass one of them as --zone)", platform.ErrNotFound, what, ref, zone, strings.Join(elsewhere, ", "))
		}
		if syncErr != nil {
			return nil, fmt.Errorf("cannot tell where %s %q is: %w", what, ref, syncErr)
		}
		if pin := pinnedProject(rt); pin != "" {
			return nil, fmt.Errorf("%w: %s %q in project %s of the selected GCP accounts", platform.ErrNotFound, what, ref, pin)
		}
		return nil, fmt.Errorf("%w: %s %q in the selected GCP accounts", platform.ErrNotFound, what, ref)
	case len(hits) > 1:
		h, err := chooseHit(rt, what, ref, hits)
		if err != nil {
			return nil, err
		}
		hits = []instanceHit{h}
	}
	h := hits[0]
	c, err := openScope(ctx, rt, scope{h.profile, h.inst.Project})
	if err != nil {
		return nil, err
	}
	in, err := c.getInstance(ctx, h.inst.Zone, h.inst.Name)
	if errors.Is(err, platform.ErrNotFound) {
		dropInstance(ctx, rt, h.profile, h.inst.ID)
		return nil, fmt.Errorf("%w: instance %s in zone %s of project %s (gcp/%s) no longer exists (the local inventory was stale)", platform.ErrNotFound, h.inst.Name, h.inst.Zone, c.project, h.profile)
	}
	if err != nil {
		return nil, err
	}
	storeInstance(ctx, rt, c, h.profile, in)
	return &locatedInstance{c: c, profile: h.profile, zone: h.inst.Zone, inst: in}, nil
}

// liveInstanceHits asks the pinned project of the accounts in whose
// selection it is not (so that the inventory does not hold it) for the
// instance: every zone of it is listed once. Without such an account there
// is nothing to ask.
func liveInstanceHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, ref string, byIP bool) ([]instanceHit, error) {
	var hits []instanceHit
	for _, a := range accounts {
		if !pinUnselected(rt, a.Profile) {
			continue
		}
		c, err := openProfile(ctx, rt, a.Profile)
		if err != nil {
			return nil, err
		}
		res, err := c.syncInstances(ctx)
		if err != nil && platform.AsRegionSyncError(err) == nil {
			return nil, err
		}
		var byID, other []instanceHit
		for _, r := range res {
			in := r.Data.(Instance)
			h := instanceHit{profile: a.Profile, inst: in}
			switch {
			case byIP:
				if in.InternalIP == ref || in.ExternalIP == ref {
					other = append(other, h)
				}
			case in.ID == ref:
				byID = append(byID, h)
			case in.Name == ref:
				other = append(other, h)
			}
		}
		if len(byID) > 0 {
			other = byID
		}
		hits = append(hits, other...)
	}
	return hits, nil
}

// chooseHit settles several matches (a name held in several zones,
// projects or accounts, an IP that several projects share): the
// interactive flow asks which one, with a pick that shows the project and
// the zone of each; the non-interactive flow fails with exit code 5,
// listing the candidates and the flags that choose one (--profile,
// --project, --zone, whichever differ among them) or the instance id.
func chooseHit(rt *app.Runtime, what, ref string, hits []instanceHit) (instanceHit, error) {
	sort.Slice(hits, func(i, j int) bool {
		if hits[i].profile != hits[j].profile {
			return hits[i].profile < hits[j].profile
		}
		a, b := hits[i].inst, hits[j].inst
		return a.Project+"/"+a.Zone+"/"+a.Name < b.Project+"/"+b.Zone+"/"+b.Name
	})
	cands := make([]cand, 0, len(hits))
	for _, h := range hits {
		cands = append(cands, cand{profile: h.profile, project: h.inst.Project, where: h.inst.Zone, id: h.inst.ID, detail: h.inst.Status})
	}
	amb := ambiguous(what, ref, cands, "--zone <zone>", "the instance id")
	return disambiguate(rt, amb, hits, func(h instanceHit) string { return instanceOptionLabel(h.inst, h.profile) })
}

// storeInstance writes an instance to the inventory.
//
// Nothing of a project outside the selection is stored (--project may name
// one): the next sync of the account would not cover its rows.
func storeInstance(ctx context.Context, rt *app.Runtime, c *client, profile string, in *compute.Instance) {
	if in == nil || in.Id == 0 || !c.selected() {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	ttl := time.Duration(0)
	if cfg != nil {
		ttl = cfg.TTLFor(platform.ResInstance)
	}
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResInstance}, instanceResource(c.instanceOf(in)), ttl)
}

// dropInstance removes an instance from the inventory.
func dropInstance(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil && id != "" {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResInstance}, platform.ResInstance, id)
	}
}

// reread reads the instance again and stores it; on failure the instance
// as known is kept.
func (l *locatedInstance) reread(ctx context.Context, rt *app.Runtime) {
	if in, err := l.c.getInstance(ctx, l.zone, l.inst.Name); err == nil {
		l.inst = in
	} else {
		rt.Verbosef("re-read instance %s: %v", l.inst.Name, err)
	}
	storeInstance(ctx, rt, l.c, l.profile, l.inst)
}

// ips returns the internal and external IP of an instance's first NIC.
func ips(in *compute.Instance) (internal, external string) {
	f := instanceFromAPI(in)
	return f.InternalIP, f.ExternalIP
}

func orNone(s string) string {
	if s == "" {
		return "none"
	}
	return s
}

// ---------------------------------------------------------------- get

// instanceDisk is a disk in the output of `instance get`.
type instanceDisk struct {
	Name       string `json:"name" yaml:"name"`
	Boot       bool   `json:"boot" yaml:"boot"`
	SizeGB     int64  `json:"size_gb" yaml:"size_gb"`
	Type       string `json:"type" yaml:"type"`
	AutoDelete bool   `json:"auto_delete" yaml:"auto_delete"`
}

// instanceDetail is the output of `instance get`.
type instanceDetail struct {
	Name               string         `json:"name" yaml:"name"`
	ID                 string         `json:"id" yaml:"id"`
	Zone               string         `json:"zone" yaml:"zone"`
	Status             string         `json:"status" yaml:"status"`
	MachineType        string         `json:"machine_type" yaml:"machine_type"`
	InternalIP         string         `json:"internal_ip" yaml:"internal_ip"`
	ExternalIP         string         `json:"external_ip" yaml:"external_ip"`
	Network            string         `json:"network" yaml:"network"`
	Subnetwork         string         `json:"subnetwork" yaml:"subnetwork"`
	Tags               []string       `json:"tags" yaml:"tags"`
	CanIPForward       bool           `json:"can_ip_forward" yaml:"can_ip_forward"`
	DeletionProtection bool           `json:"deletion_protection" yaml:"deletion_protection"`
	Disks              []instanceDisk `json:"disks" yaml:"disks"`
	CreationTimestamp  string         `json:"creation_timestamp" yaml:"creation_timestamp"`
	Profile            string         `json:"profile" yaml:"profile"`
	Project            string         `json:"project" yaml:"project"`
}

// getFields are the values `get --field` prints.
var getFields = []string{"external-ip", "internal-ip", "status", "zone", "machine-type"}

func (d instanceDetail) field(name string) string {
	switch name {
	case "external-ip":
		return d.ExternalIP
	case "internal-ip":
		return d.InternalIP
	case "status":
		return d.Status
	case "zone":
		return d.Zone
	case "machine-type":
		return d.MachineType
	}
	return ""
}

// instanceDisks lists the attached disks; their types are read from the
// disks themselves (an attached disk only says PERSISTENT).
func (l *locatedInstance) instanceDisks(ctx context.Context, warn func(string)) []instanceDisk {
	out := []instanceDisk{}
	warned := false
	for _, ad := range l.inst.Disks {
		d := instanceDisk{Name: lastSegment(ad.Source), Boot: ad.Boot, SizeGB: ad.DiskSizeGb, AutoDelete: ad.AutoDelete}
		zone := l.zone
		if parts := strings.Split(ad.Source, "/"); len(parts) >= 4 && parts[len(parts)-4] == "zones" {
			zone = parts[len(parts)-3]
		}
		if d.Name != "" {
			if disk, err := l.c.disk(ctx, zone, d.Name); err == nil {
				d.Type = lastSegment(disk.Type)
				if disk.SizeGb > 0 {
					d.SizeGB = disk.SizeGb
				}
			} else if !warned {
				warned = true
				warn(fmt.Sprintf("warning: cannot read the disks of %s: %v", l.inst.Name, err))
			}
		}
		out = append(out, d)
	}
	return out
}

func detailFrom(l *locatedInstance, disks []instanceDisk) instanceDetail {
	f := instanceFromAPI(l.inst)
	d := instanceDetail{Name: f.Name, ID: f.ID, Zone: f.Zone, Status: f.Status, MachineType: f.MachineType, InternalIP: f.InternalIP,
		ExternalIP: f.ExternalIP, Tags: []string{}, CanIPForward: l.inst.CanIpForward, DeletionProtection: l.inst.DeletionProtection,
		Disks: disks, CreationTimestamp: f.CreationTimestamp, Profile: l.profile, Project: l.c.project}
	if l.inst.Tags != nil && len(l.inst.Tags.Items) > 0 {
		d.Tags = l.inst.Tags.Items
	}
	if len(l.inst.NetworkInterfaces) > 0 {
		d.Network = lastSegment(l.inst.NetworkInterfaces[0].Network)
		d.Subnetwork = lastSegment(l.inst.NetworkInterfaces[0].Subnetwork)
	}
	if d.Disks == nil {
		d.Disks = []instanceDisk{}
	}
	return d
}

func detailGrid(d instanceDetail) output.Grid {
	g := output.KV(
		"name", d.Name, "id", d.ID, "profile", d.Profile, "project", d.Project, "zone", d.Zone, "status", d.Status,
		"machine type", d.MachineType, "internal ip", orNone(d.InternalIP), "external ip", orNone(d.ExternalIP),
		"network", d.Network, "subnetwork", d.Subnetwork, "tags", strings.Join(d.Tags, ", "),
		"ip forward", strconv.FormatBool(d.CanIPForward), "deletion protection", strconv.FormatBool(d.DeletionProtection),
		"created", d.CreationTimestamp)
	for _, disk := range d.Disks {
		var notes []string
		if disk.Boot {
			notes = append(notes, "boot")
		}
		size := fmt.Sprintf("%dGB", disk.SizeGB)
		if disk.Type != "" {
			size += " " + disk.Type
		}
		notes = append(notes, size)
		if disk.AutoDelete {
			notes = append(notes, "auto-delete")
		} else {
			notes = append(notes, "kept on delete")
		}
		g.Rows = append(g.Rows, []string{"disk " + disk.Name, strings.Join(notes, ", ")})
	}
	return g
}

// noExternalIPReason explains an instance without an external IP.
func noExternalIPReason(name, status string) string {
	switch {
	case stopped(status):
		return fmt.Sprintf("instance %s has no external IP: it is %s, and its ephemeral external IP was released (a static address stays bound while it is stopped)", name, status)
	case status == statusRunning:
		return fmt.Sprintf("instance %s has no external IP: it has no external access configured", name)
	}
	return fmt.Sprintf("instance %s has no external IP: it is %s", name, status)
}

func computeGetCmd(rt *app.Runtime) *cobra.Command {
	var zone, field string
	cmd := &cobra.Command{
		Use:   "get <name|id>",
		Short: "Show one Compute Engine instance, its addresses and disks",
		Long: `Show one Compute Engine instance, found by its name or id in the inventory of
every selected GCP account (in any status; --profile narrows the search,
--zone picks among instances of one name in several zones). The instance is
read live. --field prints one raw value for scripts: external-ip,
internal-ip, status, zone or machine-type. An instance without an external
IP is exit code 1 with --field external-ip, with the reason on stderr and
nothing on stdout.`,
		Example: `  polyctl gcp compute instance get web-1
  polyctl gcp compute instance get web-1 --field external-ip`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if field != "" && !slices.Contains(getFields, field) {
				return app.UsageErrf("unknown --field %q (one of %s)", field, strings.Join(getFields, ", "))
			}
			args, err := instanceArg(ctx, rt, args, zone, "GCP instance", nil)
			if err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, false)
			if err != nil {
				return err
			}
			if field != "" {
				d := detailFrom(l, nil)
				v := d.field(field)
				if v == "" {
					if field == "external-ip" {
						return errors.New(noExternalIPReason(d.Name, d.Status))
					}
					return fmt.Errorf("instance %s has no %s", d.Name, field)
				}
				_, err := fmt.Fprintln(rt.Stdout, output.Clean(v))
				return err
			}
			d := detailFrom(l, l.instanceDisks(ctx, func(s string) { rt.Infof("%s", s) }))
			if d.ExternalIP == "" {
				rt.Infof("warning: %s", noExternalIPReason(d.Name, d.Status))
			} else if d.Status != statusRunning {
				rt.Infof("note: instance %s is %s", d.Name, d.Status)
			}
			return rt.Render(d, func() output.Grid { return detailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used (default: from the inventory)")
	cmd.Flags().StringVar(&field, "field", "", "print only the raw value of this field ("+strings.Join(getFields, ", ")+")")
	return cmd
}

// ------------------------------------------------------------- create

var (
	// instanceNameRe is the Compute Engine name rule (63 characters at most).
	instanceNameRe = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
	// networkTagRe is the rule of network tags.
	networkTagRe = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)
)

// diskTypes are the persistent disk types --disk-type and --data-disk-type take.
var diskTypes = []string{"pd-standard", "pd-balanced", "pd-ssd", "pd-extreme"}

// serviceAccountScopes are the scopes of the instance's service account.
var serviceAccountScopes = []string{
	"https://www.googleapis.com/auth/devstorage.read_only",
	"https://www.googleapis.com/auth/logging.write",
	"https://www.googleapis.com/auth/monitoring.write",
	"https://www.googleapis.com/auth/service.management.readonly",
	"https://www.googleapis.com/auth/servicecontrol",
	"https://www.googleapis.com/auth/trace.append",
}

// checkInstanceName validates a new instance name.
func checkInstanceName(name string) error {
	if instanceNameRe.MatchString(name) {
		return nil
	}
	hint := "lower-case letters, digits and hyphens, at most 63 characters, not ending with a hyphen"
	if name != "" && name[0] >= '0' && name[0] <= '9' {
		hint = "add a prefix such as \"vm-\""
	}
	return app.UsageErrf("invalid instance name %q: a GCE instance name must start with a lower-case letter (%s)", name, hint)
}

// createDerivedNames renders the static address names of create and
// checks them, and the disk names, against the Compute Engine name rule:
// a valid instance name can still be too long for them.
func createDerivedNames(rt *app.Runtime, o *createOptions, name, zone, region string) (ext, internal string, err error) {
	vars := map[string]string{"name": name, "zone": zone, "region": region}
	if ext, err = rt.ResourceName("gcp_instance_external_ip", "", vars); err != nil {
		return "", "", err
	}
	if internal, err = rt.ResourceName("gcp_instance_internal_ip", "", vars); err != nil {
		return "", "", err
	}
	type derived struct{ what, name, fix string }
	var check []derived
	if o.staticIP {
		check = append(check,
			derived{"external address", ext, "change naming.gcp_instance_external_ip, or pass --static-ip=false"},
			derived{"internal address", internal, "change naming.gcp_instance_internal_ip, or pass --static-ip=false"})
	}
	check = append(check, derived{"boot disk", name + "-boot", ""})
	if o.disk > 0 {
		check = append(check, derived{"data disk", name + "-data", ""})
	}
	for _, d := range check {
		if instanceNameRe.MatchString(d.name) {
			continue
		}
		hint := "use a shorter instance name"
		if d.fix != "" {
			hint += ", " + d.fix
		}
		return "", "", app.UsageErrf("the %s name %q derived from instance name %q is not a valid Compute Engine name (lower-case letters, digits and hyphens, at most 63 characters): %s", d.what, d.name, name, hint)
	}
	return ext, internal, nil
}

// mergeTags returns the --tag values followed by the configured ones,
// without repeats, each validated.
func mergeTags(flags, defaults []string) ([]string, error) {
	var out []string
	for _, t := range append(append([]string(nil), flags...), defaults...) {
		t = strings.TrimSpace(t)
		if t == "" || slices.Contains(out, t) {
			continue
		}
		if !networkTagRe.MatchString(t) {
			return nil, app.UsageErrf("invalid network tag %q: lower-case letters, digits and hyphens, starting with a letter, at most 63 characters", t)
		}
		out = append(out, t)
	}
	return out, nil
}

// createOptions are the flags of create.
type createOptions struct {
	machineType, zone, diskType, dataDiskType, osName, osVersion, image string
	network, subnet, serviceAccount, sshUser                            string
	disk, bootDiskSize                                                  int64
	sshKeys, sshKeyFiles, tags                                          []string
	spot, ipForward, staticIP, sshInstanceOnly                          bool
	wf                                                                  app.WaitFlags
	// windowsUser and passwordTimeout are the Windows login of a Windows
	// instance.
	windowsUser     string
	passwordTimeout time.Duration
	// size is the size --machine-type was resolved from (nil: a type).
	size *machineChoice
}

// typeLabel is the machine type in the change report, with the size it
// was resolved from.
func (o *createOptions) typeLabel() string {
	if o.size == nil {
		return o.machineType
	}
	return o.machineType + " " + o.size.label()
}

// createDesc is the detail of the instance row of create.
func createDesc(o *createOptions, bootGB int64, tags []string, users []string) string {
	parts := []string{o.typeLabel(), fmt.Sprintf("boot %dGB %s", bootGB, o.diskType)}
	if o.disk > 0 {
		d := fmt.Sprintf("data %dGB", o.disk)
		if o.dataDiskType != o.diskType {
			d += " " + o.dataDiskType
		}
		parts = append(parts, d)
	}
	if len(tags) > 0 {
		parts = append(parts, "tags "+strings.Join(tags, ","))
	}
	if len(users) > 0 {
		parts = append(parts, "ssh keys "+strings.Join(users, ","))
	}
	if o.spot {
		parts = append(parts, "spot")
	}
	parts = append(parts, "ip-forward "+strconv.FormatBool(o.ipForward))
	return strings.Join(parts, ", ")
}

func computeCreateCmd(rt *app.Runtime) *cobra.Command {
	o := &createOptions{}
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Create a Compute Engine instance",
		Long: `Create a Compute Engine instance named <name> in --zone, in the default
project of the selected profile's account (--profile, or the default GCP
profile) or in the project of --project. An instance of that
name in the zone is exit code 1: create is not ensure. The name must start
with a lower-case letter (exit code 2 otherwise).

--machine-type and --zone default to defaults.gcp.machine_type and zone in
config.yaml; neither is a usage error. The machine type must exist in the
zone (exit code 2). It may also be a size <cores>H<memory>G (2H2G, 2H4G,
4H4G, 1H0.5G), resolved in the zone on every run (in a dry run too, never
remembered): the predefined E2 type of exactly that shape (2H1G e2-micro,
2H2G e2-small, 2H4G e2-medium, 2H8G e2-standard-2, 4H4G e2-highcpu-4,
2H16G e2-highmem-2, ...; the shared-core types first) when the zone has
it, else the E2 custom type e2-custom-<cores>-<MiB> (an even number of 2
to 32 vCPUs, 0.5 to 8 GiB per vCPU, at most 128 GiB, in multiples of 0.25
GiB). The choice is printed on stderr ("2H4G -> e2-medium (us-central1-a,
E2 predefined)") and shown in the change report. No fit is exit code 4
with the nearest E2 size; a size of 0 vCPUs or 0 GiB is exit code 2.

The image is --image (projects/<p>/global/images/<name> or
.../family/<family>; an image whose architecture differs from the
machine type's is exit code 2), or the latest public image of --os
(debian by default: it boots from the smallest disk, 10 GB; ubuntu picks
the newest LTS) and --os-version for the architecture of the machine type:
the one the API reports, else arm64 for the Arm families (t2a, c4a, n4a,
a4x) and x86_64 for the others; a size is always x86_64. The highest
release is found in the image list on every run, never written into
polyctl; deprecated, obsolete, deleted and not READY images are never
picked. Nothing found (windows has no arm64 image) is exit code 4. The
boot disk ({name}-boot, --disk-type, pd-balanced by default) has the
image's minimum size unless --boot-disk-size; --disk adds
an empty data disk ({name}-data). Both disks are deleted with the instance.

The network is --network (default defaults.gcp.network, else "default");
the subnetwork is --subnet (default defaults.gcp.subnet), else the only
ordinary subnetwork of that network in the zone's region (proxy-only ones
left out; several are a usage error). With --static-ip (default) the external and internal addresses
{name}-external-ip and {name}-internal-ip (naming.gcp_instance_external_ip
and naming.gcp_instance_internal_ip) are reserved, or reused when they
exist, and bound to the instance; --static-ip=false uses ephemeral ones.

--ssh-key (the public key itself, "user:ssh-ed25519 AAAA..." or a key whose
comment ends with an e-mail address, whose whole local part is the user),
--ssh-key-file (every key of the file; --ssh-user names the user) and
defaults.gcp.ssh_keys go into the instance's ssh-keys metadata, except the
keys the project metadata already holds (--ssh-key-instance-only writes
them anyway). Unlike on AWS and Alibaba Cloud, where an instance binds one
key pair and the two flags take one key and exclude each other, both flags
repeat and combine here: Compute Engine metadata holds any number of keys.
Linux instances log in with an SSH key only: polyctl never sets or
enables a password. Without any key of its own, a Linux instance (any
image but --os windows, an image of the windows-cloud project or one
with the WINDOWS guest OS feature) is created only when the project
metadata holds SSH keys (not blocked) or enables OS Login; otherwise
create is exit code 2 before anything is written (on a terminal, a public
key from ~/.ssh/*.pub, another file or a key typed in is offered for the
instance's own ssh-keys metadata instead; a key the project metadata holds
for that user is pointed out).

On a terminal, what is missing is asked: the zone (UP, not deprecated),
the machine type of the zone (x86_64, current families, not deprecated,
the E2 presets first, e2-medium preselected; or a size), the network when
the project has none named default, the subnetwork when the network has
several in the region, and the name, checked as it is typed against the
name rules and the instances of the zone. A configured default is used
without asking.

A Windows instance (--os windows, an image of the windows-cloud project
or one with the WINDOWS guest OS feature) logs in with a user name and a
password. Compute Engine Windows images have no password of their own, so
once the instance runs create asks its guest agent to create the user
--windows-user (polyctl-admin by default; an administrator) and set a new
password, the way gcloud compute reset-windows-password does: an RSA-2048
key generated for this request (kept in memory only), its public half
written into the windows-keys metadata of the instance, and the password
the agent encrypts with it read from serial port 4 (every 10 seconds, up
to --password-timeout, 10m) and decrypted. User and password are stored
encrypted in polyctl's database: an interactive create prints them at the
end, a non-interactive one prints a note naming "polyctl gcp compute
instance password <id>". When the agent does not answer in time, or with
--no-wait, the create still succeeds with a note: "password <id> --reset"
sets a password later. --windows-user and --password-timeout are exit
code 2 with a Linux image. A dry run generates, writes and stores nothing.

--tag and defaults.gcp.tags are network tags. The instance
gets the service account --service-account (default: the default compute
service account), Shielded VM with vTPM and integrity monitoring, and
ip forwarding only with --ip-forward.

By default create waits until the instance runs (--timeout, 10m) and
prints its addresses; --no-wait returns once the creation was accepted.
Nothing is rolled back on failure: reserved addresses are kept and reused
by the next attempt.`,
		Example: `  polyctl gcp compute instance create web-1 --machine-type e2-standard-4 --zone us-central1-a \
    --disk 100 --os ubuntu --ssh-key-file ~/.ssh/id_ed25519.pub --tag http-server --dry-run
  polyctl gcp compute instance create tmp-1 --machine-type e2-medium --zone us-central1-a --os debian --os-version 12 --static-ip=false
  polyctl gcp compute instance create win-1 --machine-type e2-standard-4 --zone us-central1-a --os windows`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			return runCreate(cmd, rt, o, strings.TrimSpace(app.Arg(args, 0)))
		},
	}
	f := cmd.Flags()
	f.StringVar(&o.machineType, "machine-type", "", "machine type such as e2-standard-4, or a size <cores>H<memory>G such as 2H4G (default: defaults.gcp.machine_type)")
	f.StringVar(&o.zone, "zone", "", "zone of the instance (default: defaults.gcp.zone)")
	f.Int64Var(&o.disk, "disk", 0, "size in GB of an empty data disk to add (0: none)")
	f.Int64Var(&o.bootDiskSize, "boot-disk-size", 0, "boot disk size in GB (default: the image's minimum)")
	f.StringVar(&o.diskType, "disk-type", "pd-balanced", "boot disk type ("+strings.Join(diskTypes, ", ")+")")
	f.StringVar(&o.dataDiskType, "data-disk-type", "", "data disk type (default: --disk-type)")
	f.StringVar(&o.osName, "os", "debian", "system whose latest public image for the machine type's architecture is used ("+strings.Join(supportedOS, ", ")+")")
	f.StringVar(&o.osVersion, "os-version", "", "release of --os, such as 12 or 22.04 (default: the latest)")
	f.StringVar(&o.image, "image", "", "image path projects/<p>/global/images/<name> or .../family/<family> (overrides --os)")
	f.StringArrayVar(&o.sshKeys, "ssh-key", nil, "SSH public key itself, optionally as user:<key> (repeatable)")
	f.StringArrayVar(&o.sshKeyFiles, "ssh-key-file", nil, "file of SSH public keys, every key line is used (repeatable; ~ is expanded)")
	f.StringVar(&o.sshUser, "ssh-user", "", "user of the keys that carry no user: prefix")
	f.BoolVar(&o.sshInstanceOnly, "ssh-key-instance-only", false, "write the keys into the instance metadata even when the project metadata holds them")
	f.StringArrayVar(&o.tags, "tag", nil, "network tag (repeatable; added to defaults.gcp.tags)")
	f.StringVar(&o.network, "network", "", "VPC network (default: defaults.gcp.network, else default)")
	f.StringVar(&o.subnet, "subnet", "", "subnetwork in the zone's region (default: defaults.gcp.subnet, else the network's only one)")
	f.BoolVar(&o.spot, "spot", false, "create a Spot (preemptible) instance")
	f.BoolVar(&o.ipForward, "ip-forward", false, "allow the instance to forward IP packets (--ip-forward=false: no)")
	f.BoolVar(&o.staticIP, "static-ip", true, "reserve static external and internal addresses (--static-ip=false: ephemeral)")
	f.StringVar(&o.serviceAccount, "service-account", "default", "service account e-mail, or default for the default compute service account")
	f.StringVar(&o.windowsUser, "windows-user", defaultWindowsUser, "Windows only: the user the guest agent creates (an administrator) and sets the password of")
	f.DurationVar(&o.passwordTimeout, "password-timeout", defaultPasswordTimeout, "Windows only: upper bound of the wait for the guest agent to set the password once the instance runs")
	_ = cmd.MarkFlagFilename("ssh-key-file", "pub")
	app.AddWaitFlags(cmd, &o.wf, true, app.DefaultWaitTimeout)
	return cmd
}

// windows reports a Windows image: --os windows, or an --image of the
// windows-cloud project.
func (o *createOptions) windows() bool {
	if o.image == "" {
		return o.osName == "windows"
	}
	project, _, _, err := parseImagePath(o.image)
	return err == nil && project == osImageProjects["windows"]
}

// checkProjectLogin makes sure a Linux instance created without an SSH key
// of its own can be logged in to: the project metadata holds SSH keys
// (and does not block them), or enables OS Login. Anything else, a project
// metadata the account may not read included, is a usage error: pass a
// key. Other read failures keep their own class.
func checkProjectLogin(rt *app.Runtime, read func() (*compute.Metadata, error)) error {
	const pass = "pass --ssh-key <public key> or --ssh-key-file <path>, or set defaults.gcp.ssh_keys (Linux instances log in with an SSH key only, never a password)"
	md, err := read()
	if err != nil {
		if errors.Is(err, platform.ErrForbidden) {
			return app.UsageErrf("no SSH key given, and the project metadata cannot be read to find one (%v): %s", err, pass)
		}
		// Anything else (an expired login, a network failure) keeps its
		// own exit code.
		return fmt.Errorf("no SSH key given, and the project metadata cannot be read to find one: %w", err)
	}
	switch {
	case osLoginEnabled(md):
		rt.Infof("note: no SSH key given: the project enables OS Login (enable-oslogin=TRUE), so SSH access needs roles/compute.osLogin in IAM")
		return nil
	case !projectKeysBlocked(md) && len(metadataKeys(md)) > 0:
		rt.Infof("note: no SSH key given: the instance accepts the SSH keys of the project metadata")
		return nil
	case projectKeysBlocked(md):
		return app.UsageErrf("no SSH key given, and the project metadata blocks its SSH keys (block-project-ssh-keys=TRUE): %s", pass)
	}
	return app.UsageErrf("no SSH key given, and the project metadata holds none and does not enable OS Login: %s", pass)
}

func runCreate(cmd *cobra.Command, rt *app.Runtime, o *createOptions, name string) error {
	ctx := cmd.Context()
	if name != "" || !rt.Interactive() {
		if err := checkInstanceName(name); err != nil {
			return err
		}
	}
	wait, timeout, err := o.wf.Resolve(cmd)
	if err != nil {
		return err
	}
	if o.image == "" {
		if _, ok := osImageProjects[o.osName]; !ok {
			return app.UsageErrf("--os %q is not supported (supported: %s)", o.osName, strings.Join(supportedOS, ", "))
		}
	} else {
		if _, _, _, err := parseImagePath(o.image); err != nil {
			return err
		}
		if cmd.Flags().Changed("os") || cmd.Flags().Changed("os-version") {
			rt.Infof("note: --image is given, so --os and --os-version are ignored")
		}
	}
	if o.dataDiskType == "" {
		o.dataDiskType = o.diskType
	}
	for _, f := range [][2]string{{"disk-type", o.diskType}, {"data-disk-type", o.dataDiskType}} {
		if !slices.Contains(diskTypes, f[1]) {
			return app.UsageErrf("--%s %q: expected one of %s", f[0], f[1], strings.Join(diskTypes, ", "))
		}
	}
	if o.disk < 0 || o.bootDiskSize < 0 {
		return app.UsageErrf("--disk and --boot-disk-size must be sizes in GB")
	}
	if o.disk == 0 && cmd.Flags().Changed("data-disk-type") {
		return app.UsageErrf("--data-disk-type needs --disk <GB>")
	}
	if o.sshUser != "" {
		if err := checkSSHUser(o.sshUser, "--ssh-user"); err != nil {
			return err
		}
	}
	if strings.TrimSpace(o.serviceAccount) == "" {
		return app.UsageErrf("--service-account is empty (pass an e-mail, or default)")
	}
	if o.image == "" && !o.windows() {
		// An --image is known to be Windows or not once it is read.
		if err := windowsCreateFlags(cmd, "--os "+o.osName+" is not Windows"); err != nil {
			return err
		}
	}
	if err := checkWindowsUser(o.windowsUser, "--windows-user"); err != nil {
		return err
	}
	if o.passwordTimeout <= 0 {
		return app.UsageErrf("--password-timeout must be a positive duration, got %s", o.passwordTimeout)
	}
	if _, _, err := platform.ParseTypeShorthand(o.machineType); err != nil {
		return err
	}
	if rt.Flags.Offline {
		return app.ErrOffline
	}
	profile, err := rt.ProfileFor(platform.GCP)
	if err != nil {
		return err
	}
	// The interactive flow picks a machine type and a zone that neither
	// the flags nor defaults.gcp name, once the client is open.
	if o.machineType, err = rt.Setting(profile, platform.GCP, "machine_type", o.machineType); err != nil {
		return err
	}
	if o.zone, err = rt.Setting(profile, platform.GCP, "zone", o.zone); err != nil {
		return err
	}
	if !rt.Interactive() {
		if o.machineType, err = rt.RequireSetting(profile, platform.GCP, "machine_type", "machine-type", o.machineType); err != nil {
			return err
		}
		if o.zone, err = rt.RequireSetting(profile, platform.GCP, "zone", "zone", o.zone); err != nil {
			return err
		}
	}
	// A malformed size is refused before the client opens.
	if o.machineType != "" {
		if _, _, err := platform.ParseTypeShorthand(o.machineType); err != nil {
			return err
		}
	}
	if o.network, err = rt.Setting(profile, platform.GCP, "network", o.network); err != nil {
		return err
	}
	if o.subnet, err = rt.Setting(profile, platform.GCP, "subnet", o.subnet); err != nil {
		return err
	}
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	defTags, err := cfg.DefaultStrings(profile, platform.GCP, "tags")
	if err != nil {
		return app.UsageErrf("config.yaml: %v", err)
	}
	tags, err := mergeTags(o.tags, defTags)
	if err != nil {
		return err
	}
	defKeys, err := cfg.DefaultStrings(profile, platform.GCP, "ssh_keys")
	if err != nil {
		return app.UsageErrf("config.yaml: %v", err)
	}
	keys, err := collectSSHKeys(o.sshKeys, o.sshKeyFiles, defKeys, o.sshUser)
	if err != nil {
		return err
	}

	c, err := openProfile(ctx, rt, profile)
	if err != nil {
		return err
	}
	if o.zone == "" {
		if o.zone, err = pickZone(ctx, rt, c, profile); err != nil {
			return err
		}
	}
	if o.machineType == "" {
		if o.machineType, err = pickMachineType(ctx, rt, c, o.zone, "", defaultPickMachineType, true); err != nil {
			return err
		}
	}
	size, isSize, err := platform.ParseTypeShorthand(o.machineType)
	if err != nil {
		return err
	}
	if o.network == "" {
		if o.network, err = builtinNetwork(ctx, rt, c); err != nil {
			return err
		}
	}
	zone, region := o.zone, regionOf(o.zone)
	target := platform.Target{Platform: platform.GCP, Profile: profile, Project: c.project, Zone: zone}
	warn := func(s string) { rt.Infof("%s", s) }

	// Observe (read-only, in a dry run too).
	if name == "" {
		// A new name cannot be listed: it is asked, and checked as it is
		// typed against the rules and the instances of the zone.
		if name, err = rt.AskInput("<name>", "Name of the new instance (in "+zone+")", "", func(s string) error {
			s = strings.TrimSpace(s)
			if err := checkInstanceName(s); err != nil {
				return err
			}
			if _, _, err := createDerivedNames(rt, o, s, zone, region); err != nil {
				return err
			}
			in, err := c.findInstance(ctx, zone, s)
			if err != nil {
				return err
			}
			if in != nil {
				return fmt.Errorf("instance %s already exists in zone %s (%s)", s, zone, in.Status)
			}
			return nil
		}); err != nil {
			return err
		}
	}
	// The names derived from the instance name are checked before any
	// call: a name too long for them would fail with a raw API error.
	extName, intName, err := createDerivedNames(rt, o, name, zone, region)
	if err != nil {
		return err
	}
	existing, err := c.findInstance(ctx, zone, name)
	if err != nil {
		return err
	}
	if existing != nil {
		return fmt.Errorf("instance %s already exists in zone %s of project %s (%s): use `polyctl gcp compute instance get %s`, or choose another name", name, zone, c.project, existing.Status, name)
	}
	o.size = nil
	// A size resolves to an E2 type, which is x86_64; a machine type has
	// the architecture the API reports (machineArch).
	arch := archX86
	if isSize {
		ch, err := c.resolveMachineSize(ctx, zone, size)
		if err != nil {
			return err
		}
		rt.Infof("%s", ch.note())
		o.machineType, o.size = ch.Type, &ch
	} else {
		mt, err := c.machineType(ctx, zone, o.machineType)
		if err != nil {
			return err
		}
		arch = machineArch(mt)
	}
	var img imageChoice
	if o.image != "" {
		img, err = c.explicitImage(ctx, o.image, warn)
		if err == nil && img.Arch != "" && img.Arch != arch {
			return app.UsageErrf("--image %s is an %s image, but machine type %s is %s: pass an %s image, or a machine type of that architecture",
				o.image, archText(img.Arch), o.machineType, archText(arch), archText(arch))
		}
	} else {
		img, err = c.resolveImage(ctx, o.osName, o.osVersion, arch, o.machineType, zone)
	}
	if err != nil {
		return err
	}
	// Linux instances log in with an SSH key only (polyctl never sets a
	// password): without a key of its own, the project must hold one, or
	// enable OS Login, before anything is created. The image is known by
	// now, so that an image of one's own built from Windows Server counts
	// as Windows.
	var projectMD *compute.Metadata
	var projectMDErr error
	projectMDRead := false
	readProjectMD := func() (*compute.Metadata, error) {
		if !projectMDRead {
			projectMD, projectMDErr = c.projectMetadata(ctx)
			projectMDRead = true
		}
		return projectMD, projectMDErr
	}
	windows := o.windows() || img.Windows
	if !windows {
		if err := windowsCreateFlags(cmd, "image "+img.Name+" is not a Windows image"); err != nil {
			return err
		}
	}
	if len(keys) == 0 && !windows {
		if err := checkProjectLogin(rt, readProjectMD); err != nil {
			if !rt.Interactive() || !errors.Is(err, app.ErrUsage) {
				return err
			}
			// The interactive flow offers a local public key for the
			// instance's own ssh-keys metadata instead.
			md, _ := readProjectMD()
			picked, perr := pickSSHKey(rt, o.sshUser, md)
			if perr != nil {
				return perr
			}
			keys = picked
		}
	}
	bootGB := img.MinDiskGB
	if o.bootDiskSize > 0 {
		if o.bootDiskSize < img.MinDiskGB {
			return app.UsageErrf("--boot-disk-size %d is smaller than the %d GB image %s needs", o.bootDiskSize, img.MinDiskGB, img.Name)
		}
		bootGB = o.bootDiskSize
	}
	subnet, err := resolveSubnet(ctx, rt, c, region, o.network, o.subnet)
	if err != nil {
		return err
	}
	if o.staticIP && subnet == "" {
		return fmt.Errorf("network %s has no subnetwork in region %s to reserve the internal address %s in: pass --subnet, or --static-ip=false", o.network, region, intName)
	}

	var plan platform.Plan
	imgDetail := img.Name
	if img.Known {
		imgDetail += fmt.Sprintf(" (min disk %dGB)", img.MinDiskGB)
	} else {
		imgDetail += fmt.Sprintf(" (min disk assumed %dGB)", img.MinDiskGB)
	}
	plan.Add(platform.Step{Resource: "image/" + img.Label, Action: platform.Unchanged, ID: img.Path, Desc: imgDetail})

	var toWrite []sshKey
	if len(keys) > 0 {
		var projectKeys []metadataKey
		if md, err := readProjectMD(); err != nil {
			if errors.Is(err, context.Canceled) {
				return err
			}
			rt.Infof("warning: cannot read the project metadata (%v): every key goes into the instance metadata", err)
		} else {
			if osLoginEnabled(md) {
				rt.Infof("warning: the project enables OS Login (enable-oslogin=TRUE): ssh-keys metadata is ignored, and SSH access needs roles/compute.osLogin in IAM")
			}
			if projectKeysBlocked(md) {
				rt.Infof("note: the project metadata sets block-project-ssh-keys=TRUE: every key goes into the instance metadata")
			} else {
				projectKeys = metadataKeys(md)
			}
		}
		for _, k := range keys {
			if !o.sshInstanceOnly && k.presentIn(projectKeys) {
				plan.Add(platform.Step{Resource: "ssh-key/" + k.User, Action: platform.Unchanged, Desc: "present in project metadata (" + k.Key.Summary() + ")"})
				continue
			}
			toWrite = append(toWrite, k)
		}
	}

	var extIP, intIP string
	if o.staticIP {
		ext, err := c.getAddress(ctx, region, extName)
		if err != nil {
			return err
		}
		step, err := c.externalAddressStep(region, extName, ext, &extIP)
		if err != nil {
			return err
		}
		plan.Add(step)
		internal, err := c.getAddress(ctx, region, intName)
		if err != nil {
			return err
		}
		if step, err = c.internalAddressStep(region, intName, subnet, internal, &intIP); err != nil {
			return err
		}
		plan.Add(step)
	}

	var users []string
	for _, k := range toWrite {
		if !slices.Contains(users, k.User) {
			users = append(users, k.User)
		}
	}
	desc := createDesc(o, bootGB, tags, users)
	var win *windowsLogin
	if windows {
		win = &windowsLogin{rt: rt, c: c, profile: profile, zone: zone, name: name, user: o.windowsUser, timeout: o.passwordTimeout, wait: wait}
		desc += ", Windows login " + o.windowsUser
	}
	var createdID string
	build := func() *compute.Instance {
		return instanceBody(c, o, name, zone, region, subnet, img.Path, bootGB, tags, toWrite, extIP, intIP)
	}
	plan.Add(platform.Step{Resource: "instance/" + name, Action: platform.Created, Desc: desc, Apply: func(ctx context.Context) (platform.Change, error) {
		wctx, cancel, conv := deadline(ctx, timeout, "instance/"+name, "created")
		defer cancel()
		if err := c.insertInstance(wctx, zone, build(), wait); err != nil {
			return platform.Change{}, conv(err)
		}
		if win != nil {
			win.created = true
		}
		if !wait {
			rt.Infof("instance %s is being created; `polyctl gcp compute instance get %s` shows its addresses once it runs", name, name)
			return platform.Change{Detail: desc + " (provisioning)"}, nil
		}
		return platform.Change{Detail: desc}, nil
	}})
	if wait {
		plan.Add(platform.Step{Resource: "instance/" + name + "/status", Action: platform.Created, Desc: statusRunning, Apply: func(ctx context.Context) (platform.Change, error) {
			in, err := c.waitStatus(ctx, zone, name, statusRunning, timeout)
			if in != nil {
				storeInstance(ctx, rt, c, profile, in)
			}
			if err != nil {
				return platform.Change{}, fmt.Errorf("instance %s was created but did not become RUNNING: %w", name, err)
			}
			createdID = strconv.FormatUint(in.Id, 10)
			in2, ext := ips(in)
			rt.Infof("instance %s is RUNNING: external ip %s, internal ip %s", name, orNone(ext), orNone(in2))
			return platform.Change{ID: strconv.FormatUint(in.Id, 10), Detail: fmt.Sprintf("RUNNING, external ip %s, internal ip %s", orNone(ext), orNone(in2)),
				Attrs: map[string]string{"external_ip": ext, "internal_ip": in2}}, nil
		}})
	}
	if win != nil && wait {
		plan.Add(win.step(func() string { return createdID }))
	}
	if win != nil && wait && !rt.DryRun() {
		// Before the first write: a login that cannot be stored would be
		// lost once the instance exists.
		if err := rt.PrepareSecrets(); err != nil {
			return fmt.Errorf("the Windows login could not be stored, nothing was created: %w", err)
		}
	}
	err = rt.Ensure(ctx, "gcp.compute.instance.create", target, &plan)
	if werr := win.finish(ctx); werr != nil {
		err = errors.Join(err, werr)
	}
	if err == nil && !wait && !rt.DryRun() {
		if in, gerr := c.getInstance(ctx, zone, name); gerr == nil {
			storeInstance(ctx, rt, c, profile, in)
		}
	}
	if err != nil && !rt.DryRun() && o.staticIP && (extIP != "" || intIP != "") {
		rt.Infof("note: nothing is rolled back: the addresses %s and %s in %s are kept and reused when create is run again; once the instance exists, `polyctl gcp compute instance delete %s --release-ips` releases them", extName, intName, region, name)
	}
	return err
}

// resolveSubnet decides the subnetwork of the NIC: the one given (which
// must exist and belong to network), else the only ordinary (not
// proxy-only) subnetwork of network in the region. Several are a pick in the interactive flow and a usage
// error otherwise. None is "" for an auto-mode
// (or legacy) network, where Compute Engine picks the region's one, and a
// failure for a custom-mode network.
func resolveSubnet(ctx context.Context, rt *app.Runtime, c *client, region, network, subnet string) (string, error) {
	if subnet != "" {
		s, err := c.subnetwork(ctx, region, subnet)
		if err != nil {
			return "", err
		}
		if n := lastSegment(s.Network); n != "" && n != network {
			return "", app.UsageErrf("subnetwork %s belongs to network %s, not %s: pass --network %s", subnet, n, network, n)
		}
		return subnet, nil
	}
	all, err := c.subnetworksOf(ctx, region, network)
	if err != nil {
		return "", err
	}
	// Only an ordinary subnetwork holds instances: a proxy-only one (such
	// as the one a regional load balancer needs) is left out.
	var subs []*compute.Subnetwork
	for _, s := range all {
		if ordinarySubnet(s) {
			subs = append(subs, s)
		}
	}
	switch len(subs) {
	case 1:
		return subs[0].Name, nil
	case 0:
	default:
		if rt.Interactive() {
			return pickSubnet(rt, network, region, subs)
		}
		var names []string
		for _, s := range subs {
			names = append(names, s.Name)
		}
		sort.Strings(names)
		return "", app.UsageErrf("network %s has %d subnetworks in region %s (%s): pass --subnet", network, len(subs), region, strings.Join(names, ", "))
	}
	n, err := c.network(ctx, network)
	if err != nil {
		return "", err
	}
	if n.AutoCreateSubnetworks || n.IPv4Range != "" {
		return "", nil
	}
	return "", fmt.Errorf("network %s is a custom-mode network without a subnetwork in region %s: create one, or pass --subnet / --network", network, region)
}

// instanceBody builds the instance create inserts.
func instanceBody(c *client, o *createOptions, name, zone, region, subnet, image string, bootGB int64, tags []string, keys []sshKey, extIP, intIP string) *compute.Instance {
	diskType := func(t string) string { return "zones/" + zone + "/diskTypes/" + t }
	disks := []*compute.AttachedDisk{{
		Boot: true, AutoDelete: true, Type: "PERSISTENT", Index: 0,
		InitializeParams: &compute.AttachedDiskInitializeParams{SourceImage: image, DiskSizeGb: bootGB, DiskType: diskType(o.diskType), DiskName: name + "-boot"},
	}}
	if o.disk > 0 {
		disks = append(disks, &compute.AttachedDisk{Boot: false, AutoDelete: true, Type: "PERSISTENT", Index: 1,
			InitializeParams: &compute.AttachedDiskInitializeParams{DiskSizeGb: o.disk, DiskType: diskType(o.dataDiskType), DiskName: name + "-data"}})
	}
	nic := &compute.NetworkInterface{Network: "global/networks/" + o.network, NetworkIP: intIP, StackType: "IPV4_ONLY",
		AccessConfigs: []*compute.AccessConfig{{Type: "ONE_TO_ONE_NAT", Name: "External NAT", NetworkTier: "PREMIUM", NatIP: extIP}}}
	if subnet != "" {
		nic.Subnetwork = "regions/" + region + "/subnetworks/" + subnet
	}
	in := &compute.Instance{
		Name:              name,
		MachineType:       machineTypeURL(zone, o.machineType),
		Disks:             disks,
		NetworkInterfaces: []*compute.NetworkInterface{nic},
		ShieldedInstanceConfig: &compute.ShieldedInstanceConfig{EnableSecureBoot: false, EnableVtpm: true, EnableIntegrityMonitoring: true,
			ForceSendFields: []string{"EnableSecureBoot"}},
		// Without a service account the instance gets none at all:
		// "default" is the default compute service account.
		ServiceAccounts:    []*compute.ServiceAccount{{Email: strings.TrimSpace(o.serviceAccount), Scopes: serviceAccountScopes}},
		CanIpForward:       o.ipForward,
		DeletionProtection: false,
		ForceSendFields:    []string{"CanIpForward", "DeletionProtection"},
	}
	restart := !o.spot
	if o.spot {
		in.Scheduling = &compute.Scheduling{ProvisioningModel: "SPOT", OnHostMaintenance: "TERMINATE", AutomaticRestart: &restart, Preemptible: true}
	} else {
		// OnHostMaintenance is left out: Compute Engine picks MIGRATE, or
		// TERMINATE for machine types with GPUs, which cannot migrate.
		in.Scheduling = &compute.Scheduling{ProvisioningModel: "STANDARD", AutomaticRestart: &restart, Preemptible: false,
			ForceSendFields: []string{"Preemptible"}}
	}
	if len(tags) > 0 {
		in.Tags = &compute.Tags{Items: tags}
	}
	if len(keys) > 0 {
		in.Metadata = &compute.Metadata{Items: []*compute.MetadataItems{sshKeysMetadata(keys)}}
	}
	return in
}

// ------------------------------------------------------------- delete

// instanceAddressNames are the names of the static addresses of create.
func instanceAddressNames(rt *app.Runtime, name, zone string) (ext, internal string, err error) {
	vars := map[string]string{"name": name, "zone": zone, "region": regionOf(zone)}
	if ext, err = rt.ResourceName("gcp_instance_external_ip", "", vars); err != nil {
		return "", "", err
	}
	internal, err = rt.ResourceName("gcp_instance_internal_ip", "", vars)
	return ext, internal, err
}

func computeDeleteCmd(rt *app.Runtime) *cobra.Command {
	var zone string
	var releaseIPs bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:     "delete <name|id>",
		Aliases: []string{"terminate"},
		Short:   "Delete a Compute Engine instance (asks first)",
		Long: `Delete a Compute Engine instance, found like get finds it. The instance, its
disks and the static addresses it keeps are shown first, then a confirmation
is asked (default no; --yes skips it, and the non-interactive flow needs
--yes). Disks created with the instance (auto-delete) go with it; disks
attached later and static addresses are kept, and keep costing money. An
instance with deletion protection is exit code 1: polyctl never switches
the protection off.

--release-ips also deletes the addresses {name}-external-ip and
{name}-internal-ip once the instance is gone, when they are RESERVED (an
address another resource uses is skipped); it implies --wait. --wait waits
until the instance is deleted (--timeout, 10m). Once the deletion is
requested, the Windows login polyctl stored for the instance is removed.`,
		Example: "  polyctl gcp compute instance delete tmp-1 --release-ips --yes",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if args, err = instanceArg(ctx, rt, args, zone, "GCP instance", nil); err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, false)
			if err != nil {
				return err
			}
			if l.inst.DeletionProtection {
				return fmt.Errorf("instance %s has deletion protection: switch it off first (gcloud compute instances update %s --zone %s --no-deletion-protection); polyctl does not switch it off", l.label(), l.name(), l.zone)
			}
			region := l.region()
			extName, intName, err := instanceAddressNames(rt, l.name(), l.zone)
			if err != nil {
				return err
			}
			addrs, err := l.c.listAddresses(ctx, region)
			if err != nil {
				return err
			}
			byName := map[string]*compute.Address{}
			var kept []string
			for _, a := range addrs {
				byName[a.Name] = a
				named := a.Name == extName || a.Name == intName
				if usedOnlyBy(a, l.inst.SelfLink) || (named && a.Status == addrReserved) {
					if !(releaseIPs && named) {
						kept = append(kept, fmt.Sprintf("%s (%s)", a.Name, a.Address))
					}
				}
			}
			internal, external := ips(l.inst)
			rt.Infof("instance %s", l.label())
			rt.Infof("  status        %s", l.inst.Status)
			rt.Infof("  machine type  %s", lastSegment(l.inst.MachineType))
			rt.Infof("  internal ip   %s", orNone(internal))
			rt.Infof("  external ip   %s", orNone(external))
			for _, d := range l.inst.Disks {
				fate := "is deleted with the instance"
				if !d.AutoDelete {
					fate = "is kept (not auto-delete) and has to be deleted separately"
				}
				rt.Infof("  disk          %s %dGB %s", lastSegment(d.Source), d.DiskSizeGb, fate)
			}
			if len(kept) > 0 {
				rt.Infof("  kept          static address(es) %s, billed while reserved", strings.Join(kept, ", "))
			}
			var plan platform.Plan
			release := releaseIPs
			plan.Add(platform.Step{Resource: l.resource(), Action: platform.Deleted, ID: strconv.FormatUint(l.inst.Id, 10), Desc: "zone " + l.zone,
				Apply: func(ctx context.Context) (platform.Change, error) {
					wctx, cancel, conv := deadline(ctx, timeout, l.resource(), "deleted")
					defer cancel()
					if err := l.c.deleteInstance(wctx, l.zone, l.name(), wait || release); err != nil {
						return platform.Change{}, conv(err)
					}
					dropInstance(ctx, rt, l.profile, strconv.FormatUint(l.inst.Id, 10))
					rt.ForgetCredentials(ctx, secrets.Ref{Platform: platform.GCP, Profile: l.profile, Location: l.zone, InstanceID: strconv.FormatUint(l.inst.Id, 10)})
					if wait || release {
						return platform.Change{Detail: "zone " + l.zone + "; deleted"}, nil
					}
					rt.Infof("deletion of %s requested; it completes within a few minutes", l.name())
					return platform.Change{}, nil
				}})
			if release {
				for _, n := range []string{extName, intName} {
					s := l.c.releaseStep(region, n, byName[n], l.inst.SelfLink)
					s.ContinueOnError = true
					plan.Add(s)
				}
			}
			if !rt.DryRun() {
				rt.Infof("This cannot be undone! The instance and its auto-delete disks will be permanently deleted!")
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete instance %s?", l.label()), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not deleted", platform.ErrNothingToDo, l.name())
				}
			}
			rep, err := rt.RunPlan(ctx, l.target(), &plan)
			if rerr := rt.RenderReport(rep); rerr != nil && err == nil {
				err = rerr
			}
			return err
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used (default: from the inventory)")
	cmd.Flags().BoolVar(&releaseIPs, "release-ips", false, "also delete the RESERVED addresses {name}-external-ip and {name}-internal-ip (implies --wait)")
	app.AddWaitFlags(cmd, &wf, false, app.DefaultWaitTimeout)
	return cmd
}

// ------------------------------------------------------------- reboot

// defaultResetTimeout bounds the wait of reboot --wait.
const defaultResetTimeout = 3 * time.Minute

func computeRebootCmd(rt *app.Runtime) *cobra.Command {
	var zone string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "reboot <name|id|ip>",
		Short: "Hard-reset a running Compute Engine instance (asks first)",
		Long: `Hard-reset a running Compute Engine instance, like
"gcloud compute instances reset": the virtual machine is restarted at once,
without a graceful shutdown of the operating system, so data not yet
written to disk is lost. The instance keeps its addresses and stays
RUNNING; it is never stopped and started.

The instance is found like get finds it, or by its internal or external IP;
an IP that instances of several projects share is ambiguous (exit code 5;
a terminal lets you choose). Its status is read live: an instance that is
not RUNNING is exit code 1. A confirmation is asked (default no; --yes
skips it, and the non-interactive flow needs --yes). --wait waits for the
reset to complete (--timeout, 3m).`,
		Example: `  polyctl gcp compute instance reboot web-1
  polyctl gcp compute instance reboot 203.0.113.10 --yes`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if args, err = instanceArg(ctx, rt, args, zone, "running GCP instance", statusIn(statusRunning)); err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, true)
			if err != nil {
				return err
			}
			if l.inst.Status != statusRunning {
				return fmt.Errorf("instance %s is %s: a reset applies to a RUNNING instance only (start it with `polyctl gcp compute instance start %s`)", l.label(), l.inst.Status, l.name())
			}
			internal, external := ips(l.inst)
			rt.Infof("instance %s", l.name())
			rt.Infof("  project       %s (gcp/%s)", l.c.project, l.profile)
			rt.Infof("  zone          %s", l.zone)
			rt.Infof("  status        %s", l.inst.Status)
			rt.Infof("  internal ip   %s", orNone(internal))
			rt.Infof("  external ip   %s", orNone(external))
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: strconv.FormatUint(l.inst.Id, 10), Detail: "reset (hard reboot)"}
			if done, err := rt.WouldWrite(l.target(), change); done || err != nil {
				return err
			}
			rt.Infof("This is a hard reset: the operating system is not shut down gracefully and is restarted at once; unsaved data is lost.")
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Hard-reset instance %s (no graceful OS shutdown)?", l.label()), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; instance %s was not reset", platform.ErrNothingToDo, l.name())
			}
			wctx, cancel, conv := deadline(ctx, timeout, l.resource(), "reset")
			defer cancel()
			if err := l.c.resetInstance(wctx, l.zone, l.name(), wait); err != nil {
				return conv(err)
			}
			if wait {
				change.Detail += "; done"
				rt.Infof("instance %s was reset", l.name())
			} else {
				rt.Infof("reset of %s requested", l.name())
			}
			return rt.RenderReport(platform.Report{Target: l.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used (default: from the inventory)")
	app.AddWaitFlags(cmd, &wf, false, defaultResetTimeout)
	return cmd
}

// ------------------------------------------------------------- update

func computeUpdateCmd(rt *app.Runtime) *cobra.Command {
	var zone string
	var ipForward bool
	cmd := &cobra.Command{
		Use:   "update <name|id>",
		Short: "Change settings of a Compute Engine instance in place",
		Long: `Change settings of a Compute Engine instance in place, without stopping or
recreating it. --ip-forward[=false] switches IP forwarding (CanIpForward) on
or off, running or stopped: the instance is sent back whole with that field
changed, allowing at most a refresh (never a restart). A value that is
already set is unchanged. Without any setting to change it is a usage
error; on a terminal, IP forwarding on or off is asked instead (the current
value marked).`,
		Example: "  polyctl gcp compute instance update web-1 --ip-forward",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			askForward := !cmd.Flags().Changed("ip-forward")
			if askForward && !rt.Interactive() {
				return app.UsageErrf("nothing to update: pass --ip-forward or --ip-forward=false")
			}
			args, err := instanceArg(ctx, rt, args, zone, "GCP instance", nil)
			if err != nil {
				return err
			}
			l, err := resolveInstance(ctx, rt, args[0], zone, false)
			if err != nil {
				return err
			}
			if askForward {
				cur := l.inst.CanIpForward
				v, err := rt.PickOnOff("IP forwarding of "+l.name(), &cur)
				if err != nil {
					return err
				}
				ipForward = v == "on"
			}
			res := l.resource() + "/ip-forward"
			cur := l.inst.CanIpForward
			if cur == ipForward {
				return rt.RenderReport(platform.Report{Target: l.target(), DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: res, Action: platform.Unchanged, Detail: strconv.FormatBool(cur)}}})
			}
			change := platform.Change{Resource: res, Action: platform.Updated, Detail: fmt.Sprintf("%v -> %v", cur, ipForward)}
			if done, err := rt.WouldWrite(l.target(), change); done || err != nil {
				return err
			}
			in, err := l.c.setIPForward(ctx, l.zone, l.inst, ipForward)
			if in != nil {
				l.inst = in
				storeInstance(ctx, rt, l.c, l.profile, in)
			}
			if err != nil {
				return err
			}
			rt.Infof("ip forwarding of %s is %v (status %s)", l.name(), ipForward, l.inst.Status)
			return rt.RenderReport(platform.Report{Target: l.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone of the instance; only an instance in this zone is used (default: from the inventory)")
	cmd.Flags().BoolVar(&ipForward, "ip-forward", false, "allow the instance to forward IP packets (--ip-forward=false switches it off)")
	return cmd
}
