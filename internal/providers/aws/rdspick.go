package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/rds"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// dbOptionLabel: "db-prod-01  mysql 8.0.36  db.m5.large  available
// ap-east-1a  aws/lab/ap-east-1  db-prod-01.abc.rds.amazonaws.com".
func dbOptionLabel(profile string, d dbInstance) string {
	eng := strings.TrimSpace(d.Engine + " " + d.EngineVersion)
	return joinLabel(d.ID, eng, d.Class, d.Status, d.Zone, "aws/"+profile+"/"+d.Region, d.Endpoint)
}

// dbOptions lists the RDS instances of the selected AWS accounts as the
// inventory knows them (synced first when stale), those in region when
// given and those keep accepts, valued by identifier.
func pickDB(ctx context.Context, rt *app.Runtime, region, what string, keep func(dbInstance) bool) (string, error) {
	return rt.PickResource(ctx, app.ResourcePick{Platform: platform.AWS, Kind: platform.ResDBInstance,
		Title: "RDS instance", Arg: "<id|endpoint-dns>", What: what,
		Filter: func(r inventory.Resource) bool {
			var d dbInstance
			if r.Decode(&d) != nil || d.ID == "" || (region != "" && d.Region != region) {
				return false
			}
			return keep == nil || keep(d)
		},
		Label: func(r inventory.Resource) string {
			var d dbInstance
			_ = r.Decode(&d)
			return dbOptionLabel(r.Profile, d)
		},
		Value: func(r inventory.Resource) string {
			var d dbInstance
			_ = r.Decode(&d)
			return d.ID
		}})
}

// dbArg fills in a missing <id|endpoint-dns> in the interactive flow with
// pickDB; with the argument given, args is returned as it is.
func dbArg(ctx context.Context, rt *app.Runtime, args []string, region, what string, keep func(dbInstance) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	v, err := pickDB(ctx, rt, region, what, keep)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// dbStatusIn keeps the instances in one of the statuses.
func dbStatusIn(statuses ...string) func(dbInstance) bool {
	return func(d dbInstance) bool { return slices.Contains(statuses, d.Status) }
}

// x86Class reports whether an RDS class runs on x86 processors: Graviton
// (arm64) classes are db.t4g, db.m6g, db.m6gd, db.r7g, db.x2g, ...
func x86Class(class string) bool {
	fam, _, _ := strings.Cut(strings.TrimPrefix(class, "db."), ".")
	// The generation digits come first, the processor letters after
	// them: a "g" there is Graviton (m6g, m6gd, r7g, t4g, x2g).
	i := strings.IndexFunc(fam, func(r rune) bool { return r >= '0' && r <= '9' })
	return i < 0 || !strings.Contains(fam[i:], "g")
}

// previousGenFamilies are the RDS class families of earlier generations,
// which AWS lists as previous generation and is retiring: never offered.
var previousGenFamilies = []string{"t1", "t2", "m1", "m2", "m3", "m4", "r3", "r4"}

// currentGenClass reports whether an RDS class is of a current
// generation (not db.t2, db.m4, db.r4, ...).
func currentGenClass(class string) bool {
	fam, _, _ := strings.Cut(strings.TrimPrefix(class, "db."), ".")
	return !slices.Contains(previousGenFamilies, fam)
}

// orderableClasses lists the classes engine (version, when given) offers
// with storageType in az (in any zone when az is ""), x86 and current
// generation only, sorted.
func (c *client) orderableClasses(ctx context.Context, region, engine, version, storageType, az string) ([]string, error) {
	in := &rds.DescribeOrderableDBInstanceOptionsInput{Engine: awssdk.String(engine)}
	if version != "" {
		in.EngineVersion = awssdk.String(version)
	}
	pg := rds.NewDescribeOrderableDBInstanceOptionsPaginator(c.rdsFor(region), in)
	var out []string
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, rdsErr("DescribeOrderableDBInstanceOptions", region, err)
		}
		for _, o := range page.OrderableDBInstanceOptions {
			class := awssdk.ToString(o.DBInstanceClass)
			if class == "" || !x86Class(class) || !currentGenClass(class) || (storageType != "" && awssdk.ToString(o.StorageType) != storageType) || slices.Contains(out, class) {
				continue
			}
			ok := az == ""
			for _, z := range o.AvailabilityZones {
				ok = ok || awssdk.ToString(z.Name) == az
			}
			if ok {
				out = append(out, class)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// classZones lists the zones where engine offers class with storageType.
func (c *client) classZones(ctx context.Context, region, engine, class, storageType string) ([]string, error) {
	pg := rds.NewDescribeOrderableDBInstanceOptionsPaginator(c.rdsFor(region), &rds.DescribeOrderableDBInstanceOptionsInput{
		Engine: awssdk.String(engine), DBInstanceClass: awssdk.String(class)})
	var out []string
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, rdsErr("DescribeOrderableDBInstanceOptions", region, err)
		}
		for _, o := range page.OrderableDBInstanceOptions {
			if awssdk.ToString(o.StorageType) != storageType {
				continue
			}
			for _, z := range o.AvailabilityZones {
				out = appendNew(out, awssdk.ToString(z.Name))
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// pickDBClass asks for the new class of resize in the interactive flow:
// the x86 classes of a current generation the instance's engine and
// version offer with its storage type in its zone (Graviton and previous
// generation classes never listed), its current class left
// out. None is a usage error naming --class.
func pickDBClass(ctx context.Context, rt *app.Runtime, l *locatedDB) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("resize needs --class <db.xxx>")
	}
	classes, err := l.c.orderableClasses(ctx, l.region, awssdk.ToString(l.db.Engine), awssdk.ToString(l.db.EngineVersion),
		awssdk.ToString(l.db.StorageType), awssdk.ToString(l.db.AvailabilityZone))
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, c := range classes {
		if c != l.class() {
			opts = append(opts, prompt.Option{Label: c, Value: c})
		}
	}
	return rt.Choose(app.Choice{Title: fmt.Sprintf("New class of %s (now %s)", l.id(), l.class()), Options: opts, Arg: "--class", Required: true,
		What: "other current x86 class offered for " + l.id()})
}

// askDBCreate asks what rds instance create misses in the interactive
// flow: the identifier (checked as typed, not taken), the storage size
// (checked against the storage type and --max-size) and the availability
// zone (the zones of the subnet group, or of the region, where the class
// is offered with the storage type).
func askDBCreate(ctx context.Context, rt *app.Runtime, c *client, region string, id *string, size *int32, az *string, s rdsSettings, maxSize int32) error {
	if *id == "" {
		v, err := rt.AskInput("<id>", "Identifier of the new RDS instance", "", func(v string) error {
			v = strings.ToLower(strings.TrimSpace(v))
			if err := validDBIdentifier(v); err != nil {
				return err
			}
			if _, err := c.describeDB(ctx, region, v); err == nil {
				return fmt.Errorf("RDS instance %s already exists in %s", v, region)
			} else if !errors.Is(err, platform.ErrNotFound) {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
		*id = strings.ToLower(v)
	}
	if *size <= 0 {
		minSize := rdsStorageTypes[s.storageType]
		v, err := rt.AskInput("--size", fmt.Sprintf("Allocated storage in GB (%s: at least %d)", s.storageType, minSize), strconv.Itoa(int(max(minSize, 20))), func(v string) error {
			n, err := strconv.Atoi(strings.TrimSpace(v))
			switch {
			case err != nil || n <= 0:
				return fmt.Errorf("a whole number of GB is required")
			case int32(n) < minSize:
				return fmt.Errorf("%s storage needs at least %d GB", s.storageType, minSize)
			case maxSize > 0 && int32(n) >= maxSize:
				return fmt.Errorf("the size must be below --max-size %d", maxSize)
			}
			return nil
		})
		if err != nil {
			return err
		}
		n, _ := strconv.Atoi(v)
		*size = int32(n)
	}
	if *az == "" {
		var zones []string
		var err error
		if s.subnetGroup != "" {
			zones, err = c.subnetGroupZones(ctx, region, s.subnetGroup)
		} else {
			zones, err = c.availableZones(ctx, region)
		}
		if err != nil {
			return err
		}
		offered, err := c.classZones(ctx, region, rdsEngineMySQL, s.class, s.storageType)
		if err != nil {
			return err
		}
		var opts []prompt.Option
		for _, z := range zones {
			if slices.Contains(offered, z) {
				opts = append(opts, prompt.Option{Label: z, Value: z})
			}
		}
		if *az, err = rt.Choose(app.Choice{Title: "Availability zone (that of the instances that use the database)", Options: opts, Arg: "--az", Required: true,
			What: fmt.Sprintf("zone of %s offering %s with %s storage", region, s.class, s.storageType)}); err != nil {
			return err
		}
	}
	return nil
}
