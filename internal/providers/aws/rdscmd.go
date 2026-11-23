package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// Built-in defaults of `rds instance create`; defaults.aws.rds.* and the
// flags override them.
const (
	rdsDefaultClass       = "db.m5.large"
	rdsDefaultMajor       = "8.0"
	rdsDefaultStorageType = "gp3"
	rdsDefaultMaxSize     = 1000
	rdsDefaultRetention   = 7
	rdsDefaultBackupWin   = "03:00-04:00"
	rdsDefaultMaintWin    = "sun:04:00-sun:05:00"
	rdsDefaultMasterUser  = "admin"
	rdsEngineMySQL        = "mysql"
)

// Default timeouts of the RDS waits.
const (
	rdsCreateTimeout = 30 * time.Minute
	rdsPowerTimeout  = 30 * time.Minute
	rdsResizeTimeout = 60 * time.Minute
	rdsDeleteTimeout = 60 * time.Minute
	rdsEnsureTimeout = 30 * time.Minute
)

// rdsStorageTypes are the storage types create accepts, with the smallest
// size AWS took for each (measured for db.t3.micro and MySQL 8.0).
var rdsStorageTypes = map[string]int32{"gp2": 5, "gp3": 20, "io1": 100, "io2": 100, "standard": 5}

func rdsCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rds",
		Short: "Amazon RDS: database instances",
		Long:  "Amazon Relational Database Service. Only MySQL instances are created for now;\nlisting and the lifecycle commands work for any engine except Aurora.",
	}
	inst := &cobra.Command{
		Use:   "instance",
		Short: "RDS database instances: list, get, create, start, stop, resize, delete, ensure",
		Long: `RDS database instances. An instance is named by its identifier, or by its
endpoint DNS name (identifiers cannot hold a dot): the inventory tells which
account and region hold it, as for domains. The inventory (db_instance)
holds the instances of every enabled region.`,
	}
	inst.AddCommand(rdsListCmd(rt), rdsGetCmd(rt), rdsCreateCmd(rt), rdsPowerCmd(rt, true), rdsPowerCmd(rt, false),
		rdsResizeCmd(rt), rdsDeleteCmd(rt), rdsEnsureCmd(rt))
	cmd.AddCommand(inst)
	return cmd
}

// ------------------------------------------------------------ routing

// locatedDB is an RDS instance found for a command, with the client of the
// account that holds it.
type locatedDB struct {
	c       *client
	profile string
	region  string
	db      rdstypes.DBInstance
}

func (l *locatedDB) id() string       { return awssdk.ToString(l.db.DBInstanceIdentifier) }
func (l *locatedDB) status() string   { return awssdk.ToString(l.db.DBInstanceStatus) }
func (l *locatedDB) class() string    { return awssdk.ToString(l.db.DBInstanceClass) }
func (l *locatedDB) resource() string { return "db-instance/" + l.id() }
func (l *locatedDB) target() platform.Target {
	return platform.Target{Platform: platform.AWS, Profile: l.profile, Region: l.region}
}

// reread reads the instance again; on failure it is kept as known.
func (l *locatedDB) reread(ctx context.Context) error {
	db, err := l.c.describeDB(ctx, l.region, l.id())
	if err != nil {
		return err
	}
	l.db = db
	return nil
}

// store writes the instance as known to the inventory.
func (l *locatedDB) store(ctx context.Context, rt *app.Runtime) {
	storeDB(ctx, rt, l.profile, l.region, l.db)
}

// aurora returns the error of an Aurora cluster member, which is started,
// stopped and resized through its cluster.
func (l *locatedDB) aurora() error {
	if cl := awssdk.ToString(l.db.DBClusterIdentifier); cl != "" {
		return fmt.Errorf("%w: RDS instance %s is a member of the Aurora cluster %s: Aurora is managed through its cluster, which polyctl does not support yet", platform.ErrNotSupported, l.id(), cl)
	}
	return nil
}

// validDBIdentifier checks an RDS instance identifier as AWS does: a
// letter first, then ASCII letters, digits and hyphens, no trailing or
// double hyphen, at most 63 characters.
func validDBIdentifier(id string) error {
	if id == "" || len(id) > 63 {
		return fmt.Errorf("must be 1 to 63 characters")
	}
	if c := id[0]; !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z') {
		return fmt.Errorf("must begin with a letter")
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return fmt.Errorf("may hold only ASCII letters, digits and hyphens")
		}
	}
	if strings.HasSuffix(id, "-") || strings.Contains(id, "--") {
		return fmt.Errorf("must not end with a hyphen or hold two hyphens in a row")
	}
	return nil
}

// normalizeEndpoint compares endpoint names: no case, no trailing dot.
func normalizeEndpoint(s string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(s), "."))
}

// dbHit is an instance of the inventory and the profile that holds it.
type dbHit struct {
	profile string
	d       dbInstance
}

// dbInventoryHits returns the cached instances of the accounts that match,
// one per profile, region and identifier. When none does, the db_instance
// sets of the accounts are synced once and the lookup repeated; an account that could not be synced is returned as the
// error when still nothing matches (it may hold the instance). With
// --offline nothing is synced, and an inventory that never held the
// instances is ErrNeverSynced.
func dbInventoryHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, what string, match func(dbInstance) bool) ([]dbHit, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	lookup := func() ([]dbHit, error) {
		var out []dbHit
		seen := map[string]bool{}
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResDBInstance})
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				var d dbInstance
				if r.Decode(&d) != nil || d.ID == "" {
					continue
				}
				key := a.Profile + "|" + dbKey(d.Region, d.ID)
				if seen[key] || !match(d) {
					continue
				}
				seen[key] = true
				out = append(out, dbHit{profile: a.Profile, d: d})
			}
		}
		return out, nil
	}
	hits, err := lookup()
	if err != nil || len(hits) > 0 {
		return hits, err
	}
	if rt.Flags.Offline {
		for _, a := range accounts {
			st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: platform.ResDBInstance})
			if err != nil {
				return nil, err
			}
			if st != nil {
				return nil, nil
			}
		}
		return nil, fmt.Errorf("%w: the RDS instances of the selected AWS accounts are not in the local inventory", inventory.ErrNeverSynced)
	}
	// A miss syncs every candidate account once, fresh or not: an instance
	// created since the last sync is found without --refresh.
	stale := accounts
	rt.Infof("looking up %s: syncing the RDS instances of %d account(s)...", what, len(stale))
	var syncErr error
	for _, a := range stale {
		if err := syncDBs(ctx, rt, a); err != nil {
			rt.Infof("warning: sync %s: %v", a.Label(), err)
			if syncErr == nil {
				syncErr = fmt.Errorf("sync %s: %w", a.Label(), err)
			}
		}
	}
	if hits, err = lookup(); err != nil {
		return nil, err
	}
	if len(hits) == 0 && syncErr != nil {
		return nil, fmt.Errorf("cannot tell where %s is: %w", what, syncErr)
	}
	return hits, nil
}

// syncDBs syncs the db_instance set of one account.
func syncDBs(ctx context.Context, rt *app.Runtime, a config.AccountRef) error {
	reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{platform.ResDBInstance})
	if err != nil {
		return err
	}
	for _, r := range reps {
		if r.Err != nil {
			return r.Err
		}
	}
	return nil
}

// dbMatcher returns the inventory match of ref: an endpoint DNS name when
// it holds a dot, else an identifier (compared without case: RDS stores
// identifiers in lower case). region, when set, restricts the match.
func dbMatcher(ref, region string) (func(dbInstance) bool, bool) {
	endpoint := strings.Contains(ref, ".")
	want := strings.ToLower(ref)
	if endpoint {
		want = normalizeEndpoint(ref)
	}
	return func(d dbInstance) bool {
		if region != "" && d.Region != region {
			return false
		}
		if endpoint {
			return d.Endpoint != "" && normalizeEndpoint(d.Endpoint) == want
		}
		return strings.ToLower(d.ID) == want
	}, endpoint
}

// pickDBHit chooses among inventory hits: one is the answer, several are
// ambiguous (exit code 5), none is not found (exit code 4).
func pickDBHit(rt *app.Runtime, ref string, hits []dbHit) (dbHit, error) {
	switch len(hits) {
	case 0:
		hint := "retry with --refresh, or check --region and --profile"
		if rt.Flags.Offline {
			hint = "it is not in the local inventory; retry without --offline"
		}
		return dbHit{}, fmt.Errorf("%w: RDS instance %q in the selected AWS accounts (%s)", platform.ErrNotFound, ref, hint)
	case 1:
		return hits[0], nil
	}
	var names []string
	for _, h := range hits {
		names = append(names, fmt.Sprintf("aws/%s/%s (%s)", h.profile, h.d.Region, h.d.ID))
	}
	return dbHit{}, &app.AmbiguousError{What: fmt.Sprintf("RDS instance %q", ref), Candidates: names, Hint: "pass --profile <name> and/or --region <r> to choose"}
}

// resolveDB finds the instance ref names (an identifier or an endpoint DNS
// name) and reads it live. An identifier with --region is asked of the
// selected profile's account in that region directly. Otherwise the
// inventory tells the account and region (one sync of the accounts
// when it does not know the instance). An inventory row whose instance is
// gone is removed, the account synced again and the lookup repeated once.
func resolveDB(ctx context.Context, rt *app.Runtime, ref, region string) (*locatedDB, error) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return nil, app.UsageErrf("the RDS instance identifier is empty")
	}
	if region != "" && !validRegionName(region) {
		return nil, app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
	}
	if rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	match, endpoint := dbMatcher(ref, region)
	if region != "" && !endpoint {
		profile, err := rt.ProfileFor(platform.AWS)
		if err != nil {
			return nil, err
		}
		c, err := openProfile(ctx, rt, profile)
		if err != nil {
			return nil, err
		}
		db, err := c.describeDB(ctx, region, strings.ToLower(ref))
		if err != nil {
			if errors.Is(err, platform.ErrNotFound) {
				dropDB(ctx, rt, profile, region, strings.ToLower(ref))
				return nil, fmt.Errorf("%w: RDS instance %q in aws/%s/%s", platform.ErrNotFound, ref, profile, region)
			}
			return nil, err
		}
		return &locatedDB{c: c, profile: profile, region: region, db: db}, nil
	}
	accounts, err := awsAccounts(rt)
	if err != nil {
		return nil, err
	}
	what := fmt.Sprintf("RDS instance %q", ref)
	for attempt := 0; ; attempt++ {
		hits, err := dbInventoryHits(ctx, rt, accounts, what, match)
		if err != nil {
			return nil, err
		}
		h, err := pickDBHit(rt, ref, hits)
		if err != nil {
			return nil, err
		}
		c, err := openProfile(ctx, rt, h.profile)
		if err != nil {
			return nil, err
		}
		db, err := c.describeDB(ctx, h.d.Region, h.d.ID)
		if err == nil {
			return &locatedDB{c: c, profile: h.profile, region: h.d.Region, db: db}, nil
		}
		if !errors.Is(err, platform.ErrNotFound) {
			return nil, err
		}
		dropDB(ctx, rt, h.profile, h.d.Region, h.d.ID)
		if attempt > 0 {
			return nil, fmt.Errorf("%w: RDS instance %q (gone from aws/%s/%s)", platform.ErrNotFound, ref, h.profile, h.d.Region)
		}
		rt.Infof("RDS instance %s is gone from aws/%s/%s; syncing the account again...", h.d.ID, h.profile, h.d.Region)
		if err := syncDBs(ctx, rt, config.AccountRef{Profile: h.profile, Platform: platform.AWS}); err != nil {
			rt.Infof("warning: sync aws/%s: %v", h.profile, err)
		}
	}
}

// storeDB writes an instance to the inventory.
func storeDB(ctx context.Context, rt *app.Runtime, profile, region string, db rdstypes.DBInstance) {
	if awssdk.ToString(db.DBInstanceIdentifier) == "" {
		return
	}
	idb, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = idb.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResDBInstance}, dbFrom(region, db).resource(), cfg.TTLFor(platform.ResDBInstance))
}

// dropDB removes an instance from the inventory (the row of an older
// polyctl, keyed by the identifier alone, too).
func dropDB(ctx context.Context, rt *app.Runtime, profile, region, id string) {
	idb, err := rt.DB()
	if err != nil {
		return
	}
	set := inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResDBInstance}
	_ = idb.Delete(ctx, set, platform.ResDBInstance, dbKey(region, id))
	_ = idb.Delete(ctx, set, platform.ResDBInstance, id)
}

// --------------------------------------------------------------- views

// dbView is a row of `rds instance list`.
type dbView struct {
	ID                 string   `json:"id" yaml:"id"`
	Profile            string   `json:"profile" yaml:"profile"`
	Region             string   `json:"region" yaml:"region"`
	Class              string   `json:"class" yaml:"class"`
	Status             string   `json:"status" yaml:"status"`
	Engine             string   `json:"engine" yaml:"engine"`
	EngineVersion      string   `json:"engine_version" yaml:"engine_version"`
	AllocatedStorageGB int32    `json:"allocated_storage_gb" yaml:"allocated_storage_gb"`
	StorageType        string   `json:"storage_type" yaml:"storage_type"`
	AZ                 string   `json:"az" yaml:"az"`
	MultiAZ            bool     `json:"multi_az" yaml:"multi_az"`
	Endpoint           string   `json:"endpoint" yaml:"endpoint"`
	Port               int32    `json:"port" yaml:"port"`
	DeletionProtection bool     `json:"deletion_protection" yaml:"deletion_protection"`
	SubnetGroup        string   `json:"subnet_group" yaml:"subnet_group"`
	SecurityGroups     []string `json:"security_groups" yaml:"security_groups"`
	// CreatedAt is RFC 3339, "" while AWS has not set it.
	CreatedAt string `json:"created_at" yaml:"created_at"`
}

// dbDetail is the output of `rds instance get`.
type dbDetail struct {
	dbView             `yaml:",inline"`
	ParameterGroup     string            `json:"parameter_group" yaml:"parameter_group"`
	BackupRetention    int32             `json:"backup_retention" yaml:"backup_retention"`
	PubliclyAccessible bool              `json:"publicly_accessible" yaml:"publicly_accessible"`
	Tags               map[string]string `json:"tags" yaml:"tags"`
}

func dbViewOf(profile string, d dbInstance) dbView {
	v := dbView{ID: d.ID, Profile: profile, Region: d.Region, Class: d.Class, Status: d.Status, Engine: d.Engine,
		EngineVersion: d.EngineVersion, AllocatedStorageGB: d.Storage, StorageType: d.StorageType, AZ: d.Zone, MultiAZ: d.MultiAZ,
		Endpoint: d.Endpoint, Port: d.Port, DeletionProtection: d.DeletionProtection, SubnetGroup: d.SubnetGroup,
		SecurityGroups: append([]string{}, d.SecurityGroups...)}
	if !d.CreatedAt.IsZero() {
		v.CreatedAt = d.CreatedAt.UTC().Format(time.RFC3339)
	}
	return v
}

func dbDetailOf(profile string, d dbInstance) dbDetail {
	tags := map[string]string{}
	for k, v := range d.Tags {
		tags[k] = v
	}
	return dbDetail{dbView: dbViewOf(profile, d), ParameterGroup: d.ParameterGroup, BackupRetention: d.BackupRetention,
		PubliclyAccessible: d.Public, Tags: tags}
}

func endpointCell(v dbView) string {
	if v.Endpoint == "" {
		return "-"
	}
	if v.Port > 0 {
		return v.Endpoint + ":" + strconv.Itoa(int(v.Port))
	}
	return v.Endpoint
}

func dbListGrid(rows []dbView) output.Grid {
	g := output.Grid{Headers: []string{"ID", "PROFILE", "REGION", "CLASS", "STATUS", "ENGINE", "VERSION", "STORAGE", "ENDPOINT"}, Empty: "no RDS instances"}
	for _, v := range rows {
		g.Rows = append(g.Rows, []string{v.ID, v.Profile, v.Region, v.Class, v.Status, v.Engine, dashIfEmpty(v.EngineVersion),
			fmt.Sprintf("%dGB", v.AllocatedStorageGB), endpointCell(v)})
	}
	return g
}

func dbDetailGrid(d dbDetail) output.Grid {
	tags := make([]string, 0, len(d.Tags))
	for k, v := range d.Tags {
		tags = append(tags, k+"="+v)
	}
	slices.Sort(tags)
	return output.KV(
		"id", d.ID, "profile", d.Profile, "region", d.Region, "class", d.Class, "status", d.Status,
		"engine", d.Engine+" "+d.EngineVersion, "storage", fmt.Sprintf("%dGB %s", d.AllocatedStorageGB, d.StorageType),
		"az", dashIfEmpty(d.AZ), "multi_az", strconv.FormatBool(d.MultiAZ), "endpoint", endpointCell(d.dbView),
		"deletion_protection", strconv.FormatBool(d.DeletionProtection), "subnet_group", dashIfEmpty(d.SubnetGroup),
		"security_groups", dashIfEmpty(strings.Join(d.SecurityGroups, ",")), "parameter_group", dashIfEmpty(d.ParameterGroup),
		"backup_retention", strconv.Itoa(int(d.BackupRetention)), "publicly_accessible", strconv.FormatBool(d.PubliclyAccessible),
		"created_at", dashIfEmpty(d.CreatedAt), "tags", dashIfEmpty(strings.Join(tags, ",")))
}

// ---------------------------------------------------------------- list

func rdsListCmd(rt *app.Runtime) *cobra.Command {
	var state, class, name, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List RDS instances (the inventory caches every region)",
		Long: `List the RDS instances of the profile's region from the local inventory,
which holds those of every enabled region; --region <r> shows another region
and --region all every region. --refresh reads AWS again, --offline reads
only the inventory. --state keeps instances in that status (available,
stopped, creating, ...), --class those of that class, --name those whose
identifier matches the glob pattern (db-*).`,
		Example: "  polyctl aws rds instance list --state available\n  polyctl aws rds instance list --name 'db-test-*' --region all -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if name != "" {
				if _, err := path.Match(name, ""); err != nil {
					return app.UsageErrf("--name %q: malformed pattern", name)
				}
			}
			if region != "" && region != "all" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1, or all", region)
			}
			profile, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResDBInstance}
			listRegion := ""
			rows, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openProfile(ctx, rt, profile)
				if err != nil {
					return nil, err
				}
				listRegion = c.region
				return c.Sync(ctx, platform.ResDBInstance)
			})
			if err != nil {
				if rt.Flags.Offline && errors.Is(err, inventory.ErrNeverSynced) {
					return fmt.Errorf("%w: %v", app.ErrOffline, err)
				}
				return err
			}
			switch {
			case region == "all":
				listRegion = ""
			case region != "":
				listRegion = region
			case listRegion == "":
				listRegion = profileRegion(rt, profile)
			}
			where := "aws/" + profile
			if listRegion != "" {
				where += "/" + listRegion
			}
			out := []dbView{}
			seen := map[string]bool{}
			for _, r := range rows {
				var d dbInstance
				if err := r.Decode(&d); err != nil {
					return fmt.Errorf("decode cached RDS instance %s: %w", r.ID, err)
				}
				key := dbKey(d.Region, d.ID)
				if d.ID == "" || seen[key] {
					continue
				}
				seen[key] = true
				if listRegion != "" && d.Region != listRegion {
					continue
				}
				if state != "" && d.Status != state {
					continue
				}
				if class != "" && d.Class != class {
					continue
				}
				if name != "" {
					if ok, _ := path.Match(name, d.ID); !ok {
						continue
					}
				}
				out = append(out, dbViewOf(profile, d))
			}
			slices.SortFunc(out, func(a, b dbView) int { return strings.Compare(a.ID+"|"+a.Region, b.ID+"|"+b.Region) })
			if cached {
				rt.Infof("RDS instances via %s (local inventory)", where)
			}
			if len(out) == 0 {
				rt.Infof("no RDS instances via %s", where)
			}
			return rt.Render(out, func() output.Grid { return dbListGrid(out) })
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "only instances in this status (the RDS status as it is: available, stopped, ...)")
	cmd.Flags().StringVar(&class, "class", "", "only instances of this class (db.t3.micro, ...)")
	cmd.Flags().StringVar(&name, "name", "", "only instances whose identifier matches this glob pattern")
	cmd.Flags().StringVar(&region, "region", "", "region to show (default: the profile's), or all")
	return cmd
}

// ----------------------------------------------------------------- get

func rdsGetCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "get <id|endpoint-dns>",
		Short: "Show an RDS instance",
		Long: `Show an RDS instance, named by its identifier or its endpoint DNS name. The
account and region come from the inventory (synced once when it does not know
the instance; several matches are exit code 5: pass --profile and/or
--region). The instance is read live; with --offline the inventory's copy is
shown.`,
		Example: "  polyctl aws rds instance get db-prod-01 -o json\n  polyctl aws rds instance get db-prod-01.abc123.eu-west-1.rds.amazonaws.com",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if rt.Flags.Offline {
				accounts, err := awsAccounts(rt)
				if err != nil {
					return err
				}
				match, _ := dbMatcher(strings.TrimSpace(args[0]), region)
				hits, err := dbInventoryHits(ctx, rt, accounts, fmt.Sprintf("RDS instance %q", args[0]), match)
				if err != nil {
					if errors.Is(err, inventory.ErrNeverSynced) {
						return fmt.Errorf("%w: %v", app.ErrOffline, err)
					}
					return err
				}
				h, err := pickDBHit(rt, args[0], hits)
				if err != nil {
					return err
				}
				rt.Infof("RDS instance %s via aws/%s/%s (local inventory)", h.d.ID, h.profile, h.d.Region)
				d := dbDetailOf(h.profile, h.d)
				return rt.Render(d, func() output.Grid { return dbDetailGrid(d) })
			}
			l, err := resolveDB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			d := dbDetailOf(l.profile, dbFrom(l.region, l.db))
			return rt.Render(d, func() output.Grid { return dbDetailGrid(d) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	return cmd
}

// --------------------------------------------------------------- create

// createResult is the output of `rds instance create`.
type createResult struct {
	ID            string `json:"id" yaml:"id"`
	Endpoint      string `json:"endpoint,omitempty" yaml:"endpoint,omitempty"`
	Port          int32  `json:"port,omitempty" yaml:"port,omitempty"`
	EngineVersion string `json:"engine_version" yaml:"engine_version"`
	Status        string `json:"status" yaml:"status"`
}

func (r createResult) grid() output.Grid {
	g := output.Grid{}
	if r.Endpoint != "" {
		g.Rows = append(g.Rows, []string{"RDS_ENDPOINT=" + r.Endpoint})
		if r.Port > 0 {
			g.Rows = append(g.Rows, []string{"RDS_PORT=" + strconv.Itoa(int(r.Port))})
		}
		return g
	}
	g.Rows = append(g.Rows, []string{"RDS_ID=" + r.ID}, []string{"RDS_STATUS=" + r.Status})
	return g
}

// rdsSettings are the defaults.aws.rds.* values create uses.
type rdsSettings struct {
	class, major, storageType, subnetGroup, parameterGroup string
	securityGroups                                         []string
	tags                                                   map[string]string
}

func rdsDefaults(rt *app.Runtime, profile string) (rdsSettings, error) {
	s := rdsSettings{class: rdsDefaultClass, major: rdsDefaultMajor, storageType: rdsDefaultStorageType, tags: map[string]string{}}
	cfg, err := rt.Config()
	if err != nil {
		return s, err
	}
	str := func(key string, into *string) error {
		v, err := cfg.DefaultString(profile, platform.AWS, key)
		if err != nil {
			return app.UsageErrf("config.yaml: %v", err)
		}
		if v = strings.TrimSpace(v); v != "" {
			*into = v
		}
		return nil
	}
	for key, into := range map[string]*string{"rds.default_class": &s.class, "rds.default_major": &s.major,
		"rds.default_storage_type": &s.storageType, "rds.subnet_group": &s.subnetGroup, "rds.parameter_group": &s.parameterGroup} {
		if err := str(key, into); err != nil {
			return s, err
		}
	}
	if s.securityGroups, err = cfg.DefaultStrings(profile, platform.AWS, "rds.security_group_ids"); err != nil {
		return s, app.UsageErrf("config.yaml: %v", err)
	}
	for _, key := range []string{"tags", "rds.default_tags"} {
		m, err := cfg.DefaultMap(profile, platform.AWS, key)
		if err != nil {
			return s, app.UsageErrf("config.yaml: %v", err)
		}
		for k, v := range m {
			s.tags[k] = v
		}
	}
	return s, nil
}

// readPassword reads the master password from stdin (--password-stdin:
// one line of a pipe, or a question without echo on a terminal) or from an
// environment variable (--password-env). It is never an argument, so it
// stays out of the shell history and the process list.
func readPassword(ctx context.Context, rt *app.Runtime, fromStdin bool, env string) (string, error) {
	switch {
	case fromStdin && env != "":
		return "", app.UsageErrf("--password-stdin and --password-env contradict each other")
	case !fromStdin && env == "":
		return "", app.UsageErrf("create needs the master password: pass --password-stdin (the password on stdin) or --password-env <VAR>")
	}
	var pw string
	if env != "" {
		pw = os.Getenv(env)
		if pw == "" {
			return "", app.UsageErrf("--password-env %s: the variable is not set or empty", env)
		}
	} else {
		p := rt.Prompt().WithContext(ctx)
		var err error
		if rt.Interactive() {
			pw, err = p.RequiredSecret("Master password")
		} else {
			pw, err = p.ReadValue()
			switch {
			case errors.Is(err, prompt.ErrStdinTerminal):
				return "", app.UsageErrf("--password-stdin needs the password piped on stdin (stdin is a terminal)")
			case errors.Is(err, prompt.ErrNoValue):
				return "", app.UsageErrf("--password-stdin found no password on stdin")
			}
		}
		if err != nil {
			return "", err
		}
	}
	pw = strings.TrimRight(pw, "\r\n")
	if len(pw) < 8 {
		return "", app.UsageErrf("the master password must be at least 8 characters")
	}
	return pw, nil
}

// parseRDSTags reads --tag k=v; a key repeats a default to override it.
func parseRDSTags(args []string) (map[string]string, error) {
	out := map[string]string{}
	for _, a := range args {
		k, v, ok := strings.Cut(a, "=")
		k = strings.TrimSpace(k)
		if !ok || k == "" {
			return nil, app.UsageErrf("--tag %q: expected key=value", a)
		}
		out[k] = v
	}
	return out, nil
}

func rdsCreateCmd(rt *app.Runtime) *cobra.Command {
	var (
		size, maxSize, retention                                       int32
		az, engine, version, major, class, user, storageType           string
		subnetGroup, parameterGroup, backupWindow, maintWindow, region string
		passwordEnv                                                    string
		passwordStdin, public                                          bool
		securityGroups, tags                                           []string
		wf                                                             app.WaitFlags
	)
	cmd := &cobra.Command{
		Use:   "create <id>",
		Short: "Create a MySQL RDS instance and wait for its endpoint",
		Long: `Create a MySQL RDS instance in the account of --profile and the region of
--region (or the profile's). --size (GB) and --az are required: put the
instance in the availability zone of the instances that use it, as traffic
across zones costs money. The master password comes from --password-stdin or
--password-env <VAR>, never from an argument.

The version is --engine-version, or with latest (the default) the newest
available version of --major (default 8.0, defaults.aws.rds.default_major),
compared number by number; a plain version wins over an -rds.<date> build of
the same version. --class defaults to defaults.aws.rds.default_class (built-in
db.m5.large), --storage-type to gp3, --max-size (storage autoscaling limit) to
1000 GB (0 turns autoscaling off), --subnet-group, --security-group and
--parameter-group to defaults.aws.rds.*; without them AWS uses the default VPC
and its default subnet group. Tags: Name=<id>, defaults.aws.tags,
defaults.aws.rds.default_tags, then --tag. An instance of that identifier is
exit code 1. create waits until the instance is available (30 second polls,
--timeout 30m; --wait=false returns at once) and prints its endpoint:
RDS_ENDPOINT=... and RDS_PORT=... lines, or {"id", "endpoint", "port",
"engine_version", "status"} with -o json. A wait that runs out of time keeps
the instance.`,
		Example: "  RDS_PW=... polyctl aws rds instance create db-test-01 --size 50 --az eu-west-1a --password-env RDS_PW --major 8.0 --class db.t3.medium\n" +
			"  printf '%s\\n' \"$PW\" | polyctl aws rds instance create db-test-01 --size 20 --az eu-west-1a --password-stdin --dry-run",
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			id := strings.TrimSpace(args[0])
			if err := validDBIdentifier(id); err != nil {
				return app.UsageErrf("RDS instance identifier %q: %v", id, err)
			}
			id = strings.ToLower(id)
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if !strings.EqualFold(engine, rdsEngineMySQL) {
				return fmt.Errorf("%w: --engine %s: only mysql can be created for now", platform.ErrNotSupported, engine)
			}
			if size <= 0 {
				return app.UsageErrf("create needs --size <GB> (the allocated storage)")
			}
			if strings.TrimSpace(az) == "" {
				return app.UsageErrf("create needs --az <zone>: the availability zone of the instances that use the database")
			}
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			if maxSize < 0 || maxSize > 0 && maxSize <= size {
				return app.UsageErrf("--max-size %d must be greater than --size %d (or 0 to turn storage autoscaling off)", maxSize, size)
			}
			if retention < 0 {
				return app.UsageErrf("--backup-retention must not be negative")
			}
			profile, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			settings, err := rdsDefaults(rt, profile)
			if err != nil {
				return err
			}
			if cmd.Flags().Changed("major") {
				settings.major = major
			}
			if !majorPattern.MatchString(settings.major) {
				return app.UsageErrf("--major %q: expected a major version of the form X.Y, such as 8.0 or 8.4", settings.major)
			}
			version = strings.TrimSpace(version)
			latest := version == "" || strings.EqualFold(version, "latest")
			if !latest && cmd.Flags().Changed("major") && version != settings.major && !strings.HasPrefix(version, settings.major+".") {
				return app.UsageErrf("--engine-version %s is not a version of --major %s", version, settings.major)
			}
			if cmd.Flags().Changed("class") {
				settings.class = class
			}
			if cmd.Flags().Changed("storage-type") {
				settings.storageType = storageType
			}
			settings.storageType = strings.ToLower(strings.TrimSpace(settings.storageType))
			minSize, known := rdsStorageTypes[settings.storageType]
			if !known {
				return app.UsageErrf("--storage-type %q: expected one of gp2, gp3, io1, io2, standard", settings.storageType)
			}
			if size < minSize {
				return app.UsageErrf("--size %d: %s storage needs at least %d GB", size, settings.storageType, minSize)
			}
			if cmd.Flags().Changed("subnet-group") {
				settings.subnetGroup = subnetGroup
			}
			if cmd.Flags().Changed("security-group") {
				settings.securityGroups = securityGroups
			}
			if cmd.Flags().Changed("parameter-group") {
				settings.parameterGroup = parameterGroup
			}
			userTags, err := parseRDSTags(tags)
			if err != nil {
				return err
			}
			allTags := map[string]string{"Name": id}
			for k, v := range settings.tags {
				allTags[k] = v
			}
			for k, v := range userTags {
				allTags[k] = v
			}
			password, err := readPassword(ctx, rt, passwordStdin, passwordEnv)
			if err != nil {
				return err
			}
			c, err := openProfile(ctx, rt, profile)
			if err != nil {
				return err
			}
			region = c.regionOr(region)
			if latest {
				if version, err = c.resolveLatestVersion(ctx, region, rdsEngineMySQL, settings.major); err != nil {
					return err
				}
				rt.Infof("using MySQL version %s", version)
			}
			if _, err := c.describeDB(ctx, region, id); err == nil {
				return fmt.Errorf("RDS instance %s already exists in aws/%s/%s (create never changes an existing instance)", id, profile, region)
			} else if !errors.Is(err, platform.ErrNotFound) {
				return err
			}
			spec := dbCreateSpec{ID: id, Class: settings.class, Engine: rdsEngineMySQL, EngineVersion: version, MasterUser: user,
				Password: password, Size: size, MaxSize: maxSize, StorageType: settings.storageType, AZ: az,
				SubnetGroup: settings.subnetGroup, ParameterGroup: settings.parameterGroup, SecurityGroups: settings.securityGroups,
				BackupRetention: retention, BackupWindow: backupWindow, MaintenanceWindow: maintWindow, Public: public, Tags: allTags}
			if spec.SubnetGroup == "" && len(spec.SecurityGroups) == 0 && spec.ParameterGroup == "" {
				rt.Infof("note: no subnet group, security group or parameter group given: AWS uses the default VPC with its default subnet group and security group")
			}
			target := platform.Target{Platform: platform.AWS, Profile: profile, Region: region}
			resource := "db-instance/" + id
			detail := fmt.Sprintf("mysql %s %s %dGB %s az=%s", version, spec.Class, size, spec.StorageType, az)
			changes := []platform.Change{{Resource: resource, Action: platform.Created, ID: id, Detail: detail,
				Attrs: map[string]string{"engine_version": version, "endpoint": platform.Pending}}}
			if wait {
				changes = append(changes, platform.Change{Resource: resource + "/wait", Action: platform.Skipped, Detail: "(dry-run)"})
			}
			if rt.DryRun() {
				rt.Infof("dry run: endpoint=%s", platform.Pending)
			}
			if done, err := rt.WouldWrite(target, changes...); done || err != nil {
				return err
			}
			db, err := c.createDB(ctx, region, spec, rt.Verbosef)
			if err != nil {
				return err
			}
			storeDB(ctx, rt, profile, region, db)
			res := createResult{ID: id, EngineVersion: version, Status: awssdk.ToString(db.DBInstanceStatus)}
			if res.Status == "" {
				res.Status = dbCreating
			}
			if !wait {
				rt.Infof("RDS instance %s is being created in aws/%s/%s; it takes several minutes (check it with `polyctl aws rds instance get %s`)", id, profile, region, id)
				return rt.Render(res, res.grid)
			}
			rt.Infof("RDS instance %s is being created in aws/%s/%s; waiting until it is available (this takes several minutes)...", id, profile, region)
			db, err = c.waitDB(ctx, dbWait{region: region, id: id, want: dbAvailable, interval: dbCreatePoll, timeout: timeout, done: statusIs(dbAvailable)})
			if awssdk.ToString(db.DBInstanceIdentifier) != "" {
				storeDB(ctx, rt, profile, region, db)
			}
			if err != nil {
				return fmt.Errorf("RDS instance %s was created but is not available yet: %w; it is kept (check it with `polyctl aws rds instance get %s`)", id, err, id)
			}
			res.Status = awssdk.ToString(db.DBInstanceStatus)
			if v := awssdk.ToString(db.EngineVersion); v != "" {
				res.EngineVersion = v
			}
			if db.Endpoint != nil {
				res.Endpoint, res.Port = awssdk.ToString(db.Endpoint.Address), awssdk.ToInt32(db.Endpoint.Port)
			}
			rt.Infof("RDS instance %s is available", id)
			return rt.Render(res, res.grid)
		},
	}
	f := cmd.Flags()
	f.Int32Var(&size, "size", 0, "allocated storage in GB (required)")
	f.StringVar(&az, "az", "", "availability zone (required; the zone of the instances that use the database)")
	f.BoolVar(&passwordStdin, "password-stdin", false, "read the master password from stdin")
	f.StringVar(&passwordEnv, "password-env", "", "read the master password from this environment variable")
	f.StringVar(&engine, "engine", rdsEngineMySQL, "database engine (only mysql for now)")
	f.StringVar(&version, "engine-version", "latest", "engine version (8.0.36, ...), or latest: the newest of --major")
	f.StringVar(&major, "major", rdsDefaultMajor, "major version that latest picks from (X.Y; default defaults.aws.rds.default_major, else 8.0)")
	f.StringVar(&class, "class", "", "instance class (default defaults.aws.rds.default_class, else "+rdsDefaultClass+")")
	f.StringVar(&user, "master-user", rdsDefaultMasterUser, "master user name")
	f.Int32Var(&maxSize, "max-size", rdsDefaultMaxSize, "storage autoscaling limit in GB (0: no autoscaling)")
	f.StringVar(&storageType, "storage-type", "", "storage type: gp2, gp3, io1, io2 or standard (default defaults.aws.rds.default_storage_type, else gp3)")
	f.StringVar(&subnetGroup, "subnet-group", "", "DB subnet group (default defaults.aws.rds.subnet_group)")
	f.StringSliceVar(&securityGroups, "security-group", nil, "VPC security group id (repeatable; default defaults.aws.rds.security_group_ids)")
	f.StringVar(&parameterGroup, "parameter-group", "", "DB parameter group (default defaults.aws.rds.parameter_group)")
	f.Int32Var(&retention, "backup-retention", rdsDefaultRetention, "days automated backups are kept")
	f.StringVar(&backupWindow, "backup-window", rdsDefaultBackupWin, "daily backup window, hh:mm-hh:mm UTC")
	f.StringVar(&maintWindow, "maintenance-window", rdsDefaultMaintWin, "weekly maintenance window, ddd:hh:mm-ddd:hh:mm UTC")
	f.StringArrayVar(&tags, "tag", nil, "tag key=value (repeatable; overrides a default tag of the same key)")
	f.BoolVar(&public, "public", false, "make the instance publicly accessible")
	f.StringVar(&region, "region", "", "region (default: the profile's)")
	app.AddWaitFlags(cmd, &wf, true, rdsCreateTimeout)
	return cmd
}

// ------------------------------------------------------------ start, stop

func rdsPowerCmd(rt *app.Runtime, start bool) *cobra.Command {
	var region string
	var wf app.WaitFlags
	verb, want, going, from := "stop", dbStopped, dbStopping, dbAvailable
	if start {
		verb, want, going, from = "start", dbAvailable, dbStarting, dbStopped
	}
	long := `Start a stopped RDS instance. An available instance is reported unchanged
and nothing is sent; a starting one too (--wait waits until it is available).
Any other status is exit code 1. --wait waits until the instance is available
(15 second polls, --timeout 30m).`
	if !start {
		long = `Stop an available RDS instance (no snapshot is taken). A stopped instance is
reported unchanged and nothing is sent; a stopping one too (--wait waits until
it is stopped). Any other status is exit code 1. --wait waits until the
instance is stopped (15 second polls, --timeout 30m). AWS starts a stopped
instance again after 7 days: run ` + "`rds instance ensure <id> --state stopped`" + `
daily (cron) to keep it stopped.`
	}
	cmd := &cobra.Command{
		Use:     verb + " <id|endpoint-dns>",
		Short:   strings.ToUpper(verb[:1]) + verb[1:] + " an RDS instance",
		Long:    long,
		Example: "  polyctl aws rds instance " + verb + " db-test-01 --wait",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			l, err := resolveDB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			if err := l.aurora(); err != nil {
				return err
			}
			target := l.target()
			st := l.status()
			waitFor := func(prefix string) error {
				db, err := l.c.waitDB(ctx, dbWait{region: l.region, id: l.id(), want: want, interval: dbPowerPoll, timeout: timeout, done: statusIs(want), goneFails: true})
				if awssdk.ToString(db.DBInstanceIdentifier) != "" {
					l.db = db
					l.store(ctx, rt)
				}
				if err != nil {
					return fmt.Errorf("%s: %w", prefix, err)
				}
				return nil
			}
			switch st {
			case want:
				detail := "already stopped"
				if start {
					detail = "already running"
				}
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: detail}}})
			case going:
				ch := platform.Change{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "already " + going}
				if wait && !rt.DryRun() {
					if err := waitFor(fmt.Sprintf("RDS instance %s is %s", l.id(), going)); err != nil {
						return err
					}
					ch.Detail += "; now " + want
				}
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{ch}})
			case from:
			default:
				return fmt.Errorf("RDS instance %s is %s: it cannot be %s now (wanted %s)", l.id(), st, map[bool]string{true: "started", false: "stopped"}[start], from)
			}
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: from + " -> " + going}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			var got string
			if start {
				got, err = l.c.startDB(ctx, l.region, l.id())
			} else {
				got, err = l.c.stopDB(ctx, l.region, l.id())
			}
			if err != nil {
				return err
			}
			l.db.DBInstanceStatus = awssdk.String(got)
			l.store(ctx, rt)
			rt.Infof("%s requested for RDS instance %s (status %s)", verb, l.id(), got)
			change.Detail = got + " (was " + from + ")"
			if wait {
				if err := waitFor(fmt.Sprintf("%s of RDS instance %s was requested", verb, l.id())); err != nil {
					return err
				}
				change.Detail = want + " (was " + from + ")"
			}
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	app.AddWaitFlags(cmd, &wf, false, rdsPowerTimeout)
	return cmd
}

// --------------------------------------------------------------- resize

func rdsResizeCmd(rt *app.Runtime) *cobra.Command {
	var class, region string
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "resize <id|endpoint-dns> --class <db.xxx>",
		Short: "Change the class of an RDS instance and wait for it",
		Long: `Change the class of an RDS instance at once (ApplyImmediately). This restarts
the instance: a few minutes of downtime, a failover for Multi-AZ. The same
class is reported unchanged. An instance that is not available is waited for
first; a stopped one is exit code 1 (start it first). resize waits until the
new class is in place and the instance is available again (15 second polls,
--timeout 60m; --no-wait returns at once). AWS checks that the class fits the
engine and storage.`,
		Example: "  polyctl aws rds instance resize db-test-01 --class db.m5.xlarge",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			class = strings.TrimSpace(class)
			if class == "" {
				return app.UsageErrf("resize needs --class <db.xxx>")
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			l, err := resolveDB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			if err := l.aurora(); err != nil {
				return err
			}
			target := l.target()
			pending := func() string {
				if l.db.PendingModifiedValues == nil {
					return ""
				}
				return awssdk.ToString(l.db.PendingModifiedValues.DBInstanceClass)
			}
			unchanged := func() error {
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "class is " + class + " already"}}})
			}
			if l.class() == class && pending() == "" {
				return unchanged()
			}
			if l.status() == dbStopped {
				return fmt.Errorf("RDS instance %s is stopped: start it first (`polyctl aws rds instance start %s --wait`), then resize", l.id(), l.id())
			}
			old := l.class()
			if l.status() != dbAvailable {
				if rt.DryRun() {
					_, err := rt.WouldWrite(target, platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(),
						Detail: fmt.Sprintf("%s -> %s (apply immediately, after waiting for available; now %s)", old, class, l.status())})
					return err
				}
				if err := waitAvailable(ctx, rt, l, dbResizePoll, timeout); err != nil {
					return err
				}
				old = l.class()
				if old == class && pending() == "" {
					return unchanged()
				}
			}
			change := platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: fmt.Sprintf("%s -> %s (apply immediately)", old, class)}
			if done, err := rt.WouldWrite(target, change); done || err != nil {
				return err
			}
			rt.Infof("changing the class of RDS instance %s from %s to %s: the instance restarts (a few minutes of downtime; a failover for Multi-AZ)", l.id(), old, class)
			start := rdsClock.Now()
			for attempt := 0; ; attempt++ {
				_, err = l.c.modifyClass(ctx, l.region, l.id(), class)
				if err == nil {
					break
				}
				if !isInvalidDBState(err) || attempt > 0 {
					return err
				}
				// The status changed since it was read: wait for available
				// again, then try once more.
				if rerr := l.reread(ctx); rerr != nil {
					return rerr
				}
				if l.status() == dbAvailable {
					return err
				}
				if err := waitAvailable(ctx, rt, l, dbResizePoll, timeout); err != nil {
					return err
				}
			}
			if !wait {
				_ = l.reread(ctx)
				l.store(ctx, rt)
				change.Detail = fmt.Sprintf("%s -> %s (modifying)", old, class)
				rt.Infof("class change of RDS instance %s requested", l.id())
				return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
			}
			db, err := l.c.waitDB(ctx, dbWait{region: l.region, id: l.id(), want: "available with class " + class, interval: dbResizePoll, timeout: timeout,
				done: classApplied(class), goneFails: true})
			if awssdk.ToString(db.DBInstanceIdentifier) != "" {
				l.db = db
				l.store(ctx, rt)
			}
			if err != nil {
				return fmt.Errorf("class change of RDS instance %s was requested: %w", l.id(), err)
			}
			secs := int(rdsClock.Now().Sub(start).Seconds())
			rt.Infof("RDS instance %s class change %s -> %s done in %d seconds", l.id(), old, class, secs)
			change.Detail = fmt.Sprintf("%s -> %s", old, class)
			return rt.RenderReport(platform.Report{Target: target, Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&class, "class", "", "the new instance class (required)")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	app.AddWaitFlags(cmd, &wf, true, rdsResizeTimeout)
	return cmd
}

// waitAvailable waits until the instance is available and reads it; a
// stopped instance never becomes available by itself (error), and one that
// disappears is not found.
func waitAvailable(ctx context.Context, rt *app.Runtime, l *locatedDB, interval, timeout time.Duration) error {
	rt.Infof("RDS instance %s is %s; waiting until it is available...", l.id(), l.status())
	db, err := l.c.waitDB(ctx, dbWait{region: l.region, id: l.id(), want: dbAvailable, interval: interval, timeout: timeout,
		done: statusIs(dbAvailable), goneFails: true,
		fatal: func(s string) bool { return dbFatal(s) || s == dbStopped }})
	if awssdk.ToString(db.DBInstanceIdentifier) != "" {
		l.db = db
		l.store(ctx, rt)
	}
	return err
}

// --------------------------------------------------------------- delete

func rdsDeleteCmd(rt *app.Runtime) *cobra.Command {
	var snapshot, region string
	var skip, keepProtection bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "delete <id|endpoint-dns>",
		Short: "Delete an RDS instance, with a final snapshot (asks first)",
		Long: `Delete an RDS instance. A final snapshot is taken unless --skip-final-snapshot:
<id>-final-snapshot, or --final-snapshot <name>. A snapshot of that name that
exists already is exit code 1 before anything changes. Automated backups are
deleted with the instance (the AWS default). The instance, its status, its
deletion protection and the snapshot are shown, then a confirmation is asked
(default no; --yes skips it, and the non-interactive flow needs --yes). With
deletion protection on, it is switched off first, unless --keep-protection
(then exit code 1). An instance being deleted is reported unchanged. --wait
waits until the instance is gone (30 second polls, --timeout 60m).`,
		Example: "  polyctl aws rds instance delete db-test-01 --yes\n  polyctl aws rds instance delete db-test-01 --skip-final-snapshot --yes --wait",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if skip && cmd.Flags().Changed("final-snapshot") {
				return app.UsageErrf("--skip-final-snapshot and --final-snapshot contradict each other")
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			l, err := resolveDB(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			l.store(ctx, rt)
			target := l.target()
			waitGone := func() error {
				_, err := l.c.waitDB(ctx, dbWait{region: l.region, id: l.id(), want: "deleted", interval: dbDeletePoll, timeout: timeout,
					goneIsDone: true, fatal: func(s string) bool { return s != dbDeleting && dbFatal(s) }})
				return err
			}
			if l.status() == dbDeleting {
				ch := platform.Change{Resource: l.resource(), Action: platform.Unchanged, ID: l.id(), Detail: "already being deleted"}
				if wait && !rt.DryRun() {
					if err := waitGone(); err != nil {
						return fmt.Errorf("RDS instance %s is being deleted: %w", l.id(), err)
					}
					dropDB(ctx, rt, l.profile, l.region, l.id())
					ch.Detail += "; deleted"
				}
				return rt.RenderReport(platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{ch}})
			}
			if snapshot == "" {
				snapshot = l.id() + "-final-snapshot"
			}
			if !skip {
				exists, err := l.c.snapshotExists(ctx, l.region, snapshot)
				if err != nil {
					return err
				}
				if exists {
					return fmt.Errorf("a DB snapshot named %s exists already in aws/%s/%s: pass another --final-snapshot, or delete the old snapshot first (nothing was changed)", snapshot, l.profile, l.region)
				}
			}
			protected := awssdk.ToBool(l.db.DeletionProtection)
			if protected && keepProtection {
				return fmt.Errorf("RDS instance %s has deletion protection on (--keep-protection leaves it on): nothing was deleted", l.id())
			}
			rt.Infof("RDS instance %s in aws/%s/%s", l.id(), l.profile, l.region)
			rt.Infof("  status               %s", l.status())
			rt.Infof("  class                %s", l.class())
			rt.Infof("  deletion protection  %v", protected)
			if skip {
				rt.Infof("  WARNING: no final snapshot will be taken: the data is gone for good")
			} else {
				rt.Infof("  final snapshot       %s", snapshot)
			}
			rt.Infof("  automated backups are deleted with the instance")
			if protected {
				rt.Infof("Deletion protection will be switched off first.")
			}
			var changes []platform.Change
			if protected {
				changes = append(changes, platform.Change{Resource: l.resource(), Action: platform.Updated, ID: l.id(), Detail: "disable deletion protection"})
			}
			delDetail := "skip final snapshot"
			if !skip {
				delDetail = "final snapshot " + snapshot
			}
			changes = append(changes, platform.Change{Resource: l.resource(), Action: platform.Deleted, ID: l.id(), Detail: delDetail})
			if !skip {
				changes = append(changes, platform.Change{Resource: l.resource() + "/final-snapshot", Action: platform.Created, ID: snapshot, Detail: snapshot})
			}
			if done, err := rt.WouldWrite(target, changes...); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete RDS instance %s?", l.id()), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; RDS instance %s was not deleted", platform.ErrNothingToDo, l.id())
			}
			if protected {
				if err := l.c.disableProtection(ctx, l.region, l.id()); err != nil {
					return fmt.Errorf("switching off the deletion protection of RDS instance %s failed (nothing was deleted): %w", l.id(), err)
				}
				// The change is immediate; read it back to be sure.
				_, err := l.c.waitDB(ctx, dbWait{region: l.region, id: l.id(), want: "without deletion protection", interval: 5 * time.Second, timeout: time.Minute,
					done: func(db rdstypes.DBInstance) bool { return !awssdk.ToBool(db.DeletionProtection) }, goneFails: true})
				if err != nil {
					return fmt.Errorf("deletion protection of RDS instance %s was switched off but does not read so yet (nothing was deleted): %w", l.id(), err)
				}
			}
			got, err := l.c.deleteDB(ctx, l.region, l.id(), skip, snapshot)
			if err != nil {
				if protected {
					return fmt.Errorf("%w; deletion protection was switched off: switch it on again if the instance stays", err)
				}
				return err
			}
			rt.Infof("delete requested for RDS instance %s (status %s)", l.id(), got)
			for i := range changes {
				if changes[i].Action == platform.Deleted {
					changes[i].Detail = got + "; " + delDetail
				}
			}
			if wait {
				if err := waitGone(); err != nil {
					return fmt.Errorf("delete of RDS instance %s was requested: %w", l.id(), err)
				}
				for i := range changes {
					if changes[i].Action == platform.Deleted {
						changes[i].Detail = "deleted; " + delDetail
					}
				}
				rt.Infof("RDS instance %s is deleted", l.id())
			}
			dropDB(ctx, rt, l.profile, l.region, l.id())
			return rt.RenderReport(platform.Report{Target: target, Changes: changes})
		},
	}
	cmd.Flags().StringVar(&snapshot, "final-snapshot", "", "name of the final snapshot (default <id>-final-snapshot)")
	cmd.Flags().BoolVar(&skip, "skip-final-snapshot", false, "take no final snapshot: the data is gone for good")
	cmd.Flags().BoolVar(&keepProtection, "keep-protection", false, "leave deletion protection on: a protected instance is then not deleted (exit code 1)")
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	app.AddWaitFlags(cmd, &wf, false, rdsDeleteTimeout)
	return cmd
}
