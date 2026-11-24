package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// newR2Cmd is `polyctl cloudflare r2`: R2 buckets and the custom domains
// bound to them.
func newR2Cmd(rt *app.Runtime) *cobra.Command {
	var jur string
	cmd := &cobra.Command{
		Use:   "r2",
		Short: "R2 buckets and their custom domains",
		Long: `R2 buckets and the custom domains bound to them.

R2 is addressed per account. Without --profile, ` + "`r2 bucket list`" + ` lists the
buckets of every Cloudflare profile, and the ` + "`r2 domain`" + ` commands find the
profile whose account holds <bucket> (a name held by several accounts is
ambiguous: pass --profile). Accounts that have not enabled R2 are skipped.

A custom domain must be in a zone of the bucket's account; by default the
zone is the longest zone name <domain> ends in. Binding a domain makes
Cloudflare create a proxied CNAME record <domain> -> public.r2.dev in that
zone, and unbinding it removes that record; the record cannot be changed or
deleted through the DNS API.`,
	}
	cmd.PersistentFlags().StringVar(&jur, "jurisdiction", "", "R2 jurisdiction of the buckets (eu, fedramp; default: the default jurisdiction)")
	bucket := &cobra.Command{Use: "bucket", Short: "R2 buckets"}
	bucket.AddCommand(newR2BucketListCmd(rt, &jur))
	domain := &cobra.Command{Use: "domain", Short: "Custom domains of an R2 bucket"}
	domain.AddCommand(newR2DomainListCmd(rt, &jur), newR2DomainGetCmd(rt, &jur), newR2DomainAttachCmd(rt, &jur),
		newR2DomainUpdateCmd(rt, &jur), newR2DomainDetachCmd(rt, &jur), newR2DomainEnsureCmd(rt, &jur))
	cmd.AddCommand(bucket, domain)
	return cmd
}

// --- accounts ----------------------------------------------------------------

// r2Acct is an opened Cloudflare account, ready for R2 requests.
type r2Acct struct {
	profile string
	client  *Client
	// api is the client's API scoped to the --jurisdiction.
	api     *api
	account string
}

func openR2(ctx context.Context, rt *app.Runtime, name, jurisdiction string) (*r2Acct, error) {
	c, p, err := rt.Open(ctx, name, platform.Cloudflare)
	if err != nil {
		return nil, err
	}
	cc, ok := c.(*Client)
	if !ok {
		return nil, fmt.Errorf("unexpected client type %T", c)
	}
	acc, err := cc.r2Account(ctx)
	if err != nil {
		return nil, err
	}
	return &r2Acct{profile: p.Name, client: cc, api: cc.api.withJurisdiction(jurisdiction), account: acc}, nil
}

// r2Profiles returns the Cloudflare profiles an R2 command looks at: the one
// of --profile, or all of them. explicit says which.
func r2Profiles(rt *app.Runtime) (names []string, explicit bool, err error) {
	if rt.Flags.Profile != "" {
		name, err := rt.ProfileFor(platform.Cloudflare)
		if err != nil {
			return nil, true, err
		}
		return []string{name}, true, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return nil, false, err
	}
	names = cfg.ProfilesFor(platform.Cloudflare)
	if len(names) == 0 {
		return nil, false, fmt.Errorf("%w: no cloudflare account configured (run `polyctl auth login cloudflare`)", platform.ErrUnauthorized)
	}
	return names, false, nil
}

// skipReason tells why a profile is left out of a search, or "" when the
// error is not one that is skipped.
func skipReason(err error) string {
	switch {
	case errors.Is(err, platform.ErrNotSupported):
		return "R2 is not enabled"
	case errors.Is(err, platform.ErrUnauthorized), errors.Is(err, platform.ErrForbidden):
		return "no R2 permission or rejected credentials"
	}
	return ""
}

// findBucket returns the account that holds bucket: the account of
// --profile, or the only account among all profiles that lists it. In the
// default jurisdiction the inventory (r2_bucket) is asked first: when it
// names exactly one account for the bucket, that account is used without
// listing the buckets of every profile. Otherwise (no inventory, no or
// several matches, --refresh) every profile is asked live.
func findBucket(ctx context.Context, rt *app.Runtime, bucket, jurisdiction string) (*r2Acct, error) {
	names, explicit, err := r2Profiles(rt)
	if err != nil {
		return nil, err
	}
	if explicit {
		a, err := openR2(ctx, rt, names[0], jurisdiction)
		if err != nil {
			return nil, err
		}
		rt.Infof("bucket %s via cloudflare/%s", bucket, a.profile)
		return a, nil
	}
	if jurisdiction == "" && !rt.Flags.Refresh {
		if name := inventoryBucketProfile(ctx, rt, names, bucket); name != "" {
			a, err := openR2(ctx, rt, name, jurisdiction)
			if err != nil {
				return nil, err
			}
			rt.Infof("bucket %s via cloudflare/%s (local inventory)", bucket, a.profile)
			return a, nil
		}
	}
	var hits []*r2Acct
	var skipped []string
	var hard error
	seen := map[string]bool{}
	for _, name := range names {
		a, err := openR2(ctx, rt, name, jurisdiction)
		if err == nil && seen[a.account] {
			continue
		}
		var buckets []r2Bucket
		if err == nil {
			seen[a.account] = true
			buckets, err = a.api.listBuckets(ctx, a.account, bucket)
		}
		if err != nil {
			if why := skipReason(err); why != "" {
				rt.Verbosef("cloudflare/%s: skipped: %v", name, err)
				skipped = append(skipped, name+" ("+why+")")
			} else if hard == nil {
				hard = fmt.Errorf("cloudflare/%s: %w", name, err)
			}
			continue
		}
		if slices.ContainsFunc(buckets, func(b r2Bucket) bool { return b.Name == bucket }) {
			hits = append(hits, a)
		}
	}
	switch len(hits) {
	case 1:
		rt.Infof("bucket %s via cloudflare/%s", bucket, hits[0].profile)
		return hits[0], nil
	case 0:
	default:
		var cands []string
		for _, h := range hits {
			cands = append(cands, h.profile)
		}
		return nil, &app.AmbiguousError{What: fmt.Sprintf("R2 bucket %q (several accounts hold a bucket of that name)", bucket), Candidates: cands}
	}
	if hard != nil {
		// The bucket may be in the account that could not be read.
		return nil, hard
	}
	msg := fmt.Sprintf("bucket %s not found in any cloudflare profile", bucket)
	if len(skipped) > 0 {
		msg += "; these profiles were skipped: " + strings.Join(skipped, ", ")
	}
	return nil, fmt.Errorf("%w: %s", platform.ErrNotFound, msg)
}

// inventoryBucketProfile returns the profile whose synced buckets hold
// bucket, when the bucket sets of all the given profiles are fresh and
// name exactly one account that has it; "" otherwise.
func inventoryBucketProfile(ctx context.Context, rt *app.Runtime, names []string, bucket string) string {
	db, err := rt.DB()
	if err != nil {
		return ""
	}
	for _, name := range names {
		st, err := db.GetState(ctx, inventory.Set{Platform: platform.Cloudflare, Profile: name, Type: platform.ResR2Bucket})
		if err != nil || st == nil || !st.Fresh(time.Now()) {
			return ""
		}
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Type: platform.ResR2Bucket, Name: bucket})
	if err != nil {
		return ""
	}
	profile, account := "", ""
	for _, r := range rows {
		if !slices.Contains(names, r.Profile) {
			continue
		}
		var row r2BucketRow
		if r.Decode(&row) != nil {
			return ""
		}
		switch {
		case account == "":
			profile, account = r.Profile, row.AccountID
		case row.AccountID != account:
			return "" // several accounts: let the live search report it
		}
	}
	return profile
}

// r2Err explains an error of an R2 request of account a.
func r2Err(err error, a *r2Acct, bucket string) error {
	switch {
	case err == nil:
		return nil
	case hasCode(err, codeR2NoSuchBucket):
		return fmt.Errorf("bucket %s not found in the account of cloudflare/%s: %w", bucket, a.profile, err)
	case errors.Is(err, platform.ErrNotSupported):
		return fmt.Errorf("R2 is not enabled on the account of cloudflare/%s: %w", a.profile, err)
	case errors.Is(err, platform.ErrUnauthorized) && a.client.api.oauth != nil:
		return fmt.Errorf("a browser login does not cover R2: log cloudflare/%s in with an API token that has R2 permission: %w", a.profile, err)
	case errors.Is(err, platform.ErrUnauthorized):
		return fmt.Errorf("the credentials of cloudflare/%s cannot use R2 on account %s (an API token needs R2 read/write permission, and a binding also DNS edit on the zone): %w", a.profile, a.account, err)
	}
	return err
}

// --- output shapes ---------------------------------------------------------

type r2BucketRow struct {
	Profile      string `json:"profile" yaml:"profile"`
	AccountID    string `json:"account_id" yaml:"account_id"`
	Name         string `json:"name" yaml:"name"`
	CreationDate string `json:"creation_date" yaml:"creation_date"`
	Location     string `json:"location,omitempty" yaml:"location,omitempty"`
	StorageClass string `json:"storage_class,omitempty" yaml:"storage_class,omitempty"`
	Jurisdiction string `json:"jurisdiction,omitempty" yaml:"jurisdiction,omitempty"`
}

type r2StatusView struct {
	Ownership string `json:"ownership" yaml:"ownership"`
	SSL       string `json:"ssl" yaml:"ssl"`
}

// r2DomainView is a custom domain as polyctl prints it. MinTLS is null when
// it was never set (Cloudflare then applies its own default).
type r2DomainView struct {
	Domain   string       `json:"domain" yaml:"domain"`
	Enabled  bool         `json:"enabled" yaml:"enabled"`
	ZoneID   string       `json:"zone_id" yaml:"zone_id"`
	ZoneName string       `json:"zone_name" yaml:"zone_name"`
	MinTLS   *string      `json:"min_tls" yaml:"min_tls"`
	Ciphers  []string     `json:"ciphers,omitempty" yaml:"ciphers,omitempty"`
	Status   r2StatusView `json:"status" yaml:"status"`
}

type r2DomainListResult struct {
	Bucket  string         `json:"bucket" yaml:"bucket"`
	Profile string         `json:"profile" yaml:"profile"`
	Domains []r2DomainView `json:"domains" yaml:"domains"`
}

// zoneNamesOf maps the zone ids of a profile to their names, from the
// inventory: the name of a zone a custom domain answer leaves out.
func zoneNamesOf(ctx context.Context, rt *app.Runtime, profile string) map[string]string {
	out := map[string]string{}
	db, err := rt.DB()
	if err != nil {
		return out
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone})
	if err != nil {
		return out
	}
	for _, r := range rows {
		out[r.ID] = r.Name
	}
	return out
}

func viewOf(d r2CustomDomain, zoneNames map[string]string) r2DomainView {
	v := r2DomainView{Domain: platform.NormalizeDomain(d.Domain), Enabled: d.Enabled, ZoneID: d.ZoneID, ZoneName: d.ZoneName, Ciphers: d.Ciphers}
	if v.ZoneName == "" && d.ZoneID != "" {
		v.ZoneName = zoneNames[d.ZoneID]
	}
	if d.MinTLS != "" {
		m := d.MinTLS
		v.MinTLS = &m
	}
	if d.Status != nil {
		v.Status = r2StatusView{Ownership: d.Status.Ownership, SSL: d.Status.SSL}
	}
	return v
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

func (v r2DomainView) zoneLabel() string {
	if v.ZoneName != "" {
		return v.ZoneName
	}
	return dash(v.ZoneID)
}

func (v r2DomainView) minTLSLabel() string {
	if v.MinTLS == nil {
		return "-"
	}
	return *v.MinTLS
}

func domainGrid(views []r2DomainView) output.Grid {
	g := output.Grid{Headers: []string{"DOMAIN", "ENABLED", "ZONE", "MIN_TLS", "OWNERSHIP", "SSL"}, Empty: "no custom domains"}
	for _, v := range views {
		g.Rows = append(g.Rows, []string{v.Domain, fmt.Sprint(v.Enabled), v.zoneLabel(), v.minTLSLabel(), dash(v.Status.Ownership), dash(v.Status.SSL)})
	}
	return g
}

// --- bucket list -------------------------------------------------------------

func newR2BucketListCmd(rt *app.Runtime, jur *string) *cobra.Command {
	var wide bool
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the R2 buckets of every Cloudflare profile (or of --profile)",
		Long: `List the R2 buckets of every Cloudflare profile, or of the account of --profile.

The buckets of the default jurisdiction come from the local inventory
(resource type r2_bucket, kept fresh for an hour; --refresh reads them
again, --offline only reads the inventory); with --jurisdiction they are
read live. The listing names each bucket and its creation date; --wide also
reads each bucket for its location, storage class and jurisdiction (one
more request per bucket, so not with --offline). Without --profile, an
account that has not enabled R2 is skipped silently and one that fails is
reported as a warning; the command fails only when no account could be
read.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if rt.Flags.Offline && (*jur != "" || wide) {
				return app.ErrOffline
			}
			names, explicit, err := r2Profiles(rt)
			if err != nil {
				return err
			}
			rows := []r2BucketRow{}
			seen := map[string]bool{}
			var failures []error
			read, cachedSets := 0, 0
			for _, name := range names {
				var list []r2BucketRow
				var a *r2Acct
				var err error
				if *jur == "" {
					var cached bool
					list, cached, err = cachedBuckets(ctx, rt, name)
					if cached {
						cachedSets++
					}
				} else {
					list, a, err = liveBuckets(ctx, rt, name, *jur)
				}
				if err != nil {
					if explicit {
						return err
					}
					if errors.Is(err, platform.ErrNotSupported) {
						rt.Verbosef("cloudflare/%s: skipped: %v", name, err)
						continue
					}
					rt.Infof("warning: cloudflare/%s: %v", name, err)
					failures = append(failures, err)
					continue
				}
				if len(list) > 0 && seen[list[0].AccountID] {
					rt.Verbosef("cloudflare/%s: account %s is listed already", name, list[0].AccountID)
					continue
				}
				if len(list) > 0 {
					seen[list[0].AccountID] = true
				}
				read++
				for _, row := range list {
					if wide {
						if a == nil {
							if a, err = openR2(ctx, rt, name, *jur); err != nil {
								return err
							}
						}
						full, err := a.api.getBucket(ctx, a.account, row.Name)
						if err != nil {
							return r2Err(err, a, row.Name)
						}
						row.Location, row.StorageClass, row.Jurisdiction = full.Location, full.StorageClass, full.Jurisdiction
					}
					rows = append(rows, row)
				}
			}
			if read == 0 && len(failures) > 0 {
				return failures[0]
			}
			sort.SliceStable(rows, func(i, j int) bool {
				if rows[i].Profile != rows[j].Profile {
					return rows[i].Profile < rows[j].Profile
				}
				return rows[i].Name < rows[j].Name
			})
			note := ""
			if cachedSets > 0 {
				note = " (local inventory)"
			}
			rt.Infof("%d bucket(s) in %d account(s)%s", len(rows), read, note)
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"PROFILE", "BUCKET", "CREATED"}, Empty: "no buckets"}
				if wide {
					g.Headers = append(g.Headers, "LOCATION", "STORAGE_CLASS", "JURISDICTION")
				}
				for _, r := range rows {
					line := []string{r.Profile, r.Name, r.CreationDate}
					if wide {
						line = append(line, dash(r.Location), dash(r.StorageClass), dash(r.Jurisdiction))
					}
					g.Rows = append(g.Rows, line)
				}
				return g
			})
		},
	}
	cmd.Flags().BoolVar(&wide, "wide", false, "also show location, storage class and jurisdiction (one request per bucket)")
	return cmd
}

// cachedBuckets serves the buckets of a profile's account (default
// jurisdiction) through the inventory.
func cachedBuckets(ctx context.Context, rt *app.Runtime, profile string) ([]r2BucketRow, bool, error) {
	set := inventory.Set{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResR2Bucket}
	res, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		a, err := openR2(ctx, rt, profile, "")
		if err != nil {
			return nil, err
		}
		out, err := a.client.bucketResources(ctx)
		return out, r2Err(err, a, "")
	})
	if err != nil {
		return nil, cached, err
	}
	out := make([]r2BucketRow, 0, len(res))
	for _, r := range res {
		var row r2BucketRow
		if err := r.Decode(&row); err != nil {
			return nil, cached, fmt.Errorf("decode cached bucket %s: %w", r.ID, err)
		}
		row.Profile = profile
		out = append(out, row)
	}
	return out, cached, nil
}

// liveBuckets reads the buckets of a profile's account in a jurisdiction.
func liveBuckets(ctx context.Context, rt *app.Runtime, profile, jurisdiction string) ([]r2BucketRow, *r2Acct, error) {
	a, err := openR2(ctx, rt, profile, jurisdiction)
	if err != nil {
		return nil, nil, err
	}
	buckets, err := a.api.listBuckets(ctx, a.account, "")
	if err != nil {
		return nil, a, r2Err(err, a, "")
	}
	out := make([]r2BucketRow, 0, len(buckets))
	for _, b := range buckets {
		out = append(out, r2BucketRow{Profile: a.profile, AccountID: a.account, Name: b.Name, CreationDate: b.CreationDate})
	}
	return out, a, nil
}

// --- domain list / get -------------------------------------------------------

func newR2DomainListCmd(rt *app.Runtime, jur *string) *cobra.Command {
	return &cobra.Command{
		Use:   "list <bucket>",
		Short: "List the custom domains of a bucket",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := bucketArgs(ctx, rt, args)
			if err != nil {
				return err
			}
			bucket := args[0]
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			a, err := findBucket(ctx, rt, bucket, *jur)
			if err != nil {
				return err
			}
			ds, err := a.api.listCustomDomains(ctx, a.account, bucket)
			if err != nil {
				return r2Err(err, a, bucket)
			}
			names := zoneNamesOf(ctx, rt, a.profile)
			views := make([]r2DomainView, 0, len(ds))
			for _, d := range ds {
				views = append(views, viewOf(d, names))
			}
			sort.SliceStable(views, func(i, j int) bool { return views[i].Domain < views[j].Domain })
			return rt.Render(r2DomainListResult{Bucket: bucket, Profile: a.profile, Domains: views}, func() output.Grid { return domainGrid(views) })
		},
	}
}

// domainArg validates the <domain> argument (a usage error otherwise).
func domainArg(s string) (string, error) {
	d, err := NormalizeR2Domain(s)
	if err != nil {
		return "", app.UsageErrf("%v", err)
	}
	return d, nil
}

// minTLSFlag validates --min-tls.
func minTLSFlag(v string) error {
	if v != "" && !ValidMinTLS(v) {
		return app.UsageErrf("--min-tls must be one of %s, got %q", strings.Join(minTLSValues, ", "), v)
	}
	return nil
}

// currentDomain reads one custom domain; a domain that is not bound to the
// bucket is not found (exit code 4).
func currentDomain(ctx context.Context, a *r2Acct, bucket, domain string) (*r2CustomDomain, error) {
	d, err := a.api.getCustomDomain(ctx, a.account, bucket, domain)
	if err != nil {
		if hasCode(err, codeR2DomainNotFound) || (errors.Is(err, platform.ErrNotFound) && !hasCode(err, codeR2NoSuchBucket)) {
			return nil, fmt.Errorf("%w: custom domain %s is not bound to bucket %s (cloudflare/%s)", platform.ErrNotFound, domain, bucket, a.profile)
		}
		return nil, r2Err(err, a, bucket)
	}
	return d, nil
}

func newR2DomainGetCmd(rt *app.Runtime, jur *string) *cobra.Command {
	return &cobra.Command{
		Use:   "get <bucket> <domain>",
		Short: "Show one custom domain of a bucket",
		Args:  app.ArgsOrInteractive(rt, 2, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := bucketArgs(ctx, rt, args)
			if err != nil {
				return err
			}
			bucket := args[0]
			domain := ""
			if len(args) > 1 {
				if domain, err = domainArg(args[1]); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			a, err := findBucket(ctx, rt, bucket, *jur)
			if err != nil {
				return err
			}
			if domain == "" {
				if domain, err = pickBucketDomain(ctx, rt, a, bucket); err != nil {
					return err
				}
			}
			d, err := currentDomain(ctx, a, bucket, domain)
			if err != nil {
				return err
			}
			v := viewOf(*d, zoneNamesOf(ctx, rt, a.profile))
			return rt.Render(v, func() output.Grid {
				return output.KV("domain", v.Domain, "bucket", bucket, "profile", a.profile, "enabled", fmt.Sprint(v.Enabled),
					"zone", v.zoneLabel(), "zone_id", dash(v.ZoneID), "min_tls", v.minTLSLabel(),
					"ownership", dash(v.Status.Ownership), "ssl", dash(v.Status.SSL))
			})
		},
	}
}

// --- writes ----------------------------------------------------------------

func domainResource(bucket, domain string) string { return "r2/" + bucket + "/domain/" + domain }

func recordResource(bucket, domain string) string {
	return domainResource(bucket, domain) + "/dns-record"
}

// act returns action in its dry-run form when the run is a dry run.
func act(rt *app.Runtime, a platform.Action) platform.Action {
	if rt.DryRun() {
		return a.DryRun()
	}
	return a
}

// r2Run collects the change report of an R2 write command.
type r2Run struct {
	rt      *app.Runtime
	target  platform.Target
	changes []platform.Change
}

func (r *r2Run) add(c platform.Change) {
	r.changes = append(r.changes, c)
	if r.rt.DryRun() && c.Action.Writes() {
		r.rt.Infof("dry run: %s %s (%s)", c.Action.Label(), c.Resource, c.Detail)
	}
}

// fail records the failed step and returns err.
func (r *r2Run) fail(resource string, err error) error {
	r.changes = append(r.changes, platform.Change{Resource: resource, Action: platform.Failed, Detail: err.Error()})
	return err
}

// finish prints the report and returns err. A failure of an ensure (event
// set; not a dry run, not a usage error) goes to hooks.on_failure too.
func (r *r2Run) finish(ctx context.Context, event string, err error) error {
	rep := platform.Report{Target: r.target, DryRun: r.rt.DryRun(), Changes: r.changes}
	if rerr := r.rt.RenderReport(rep); rerr != nil && err == nil {
		err = rerr
	}
	if err != nil && event != "" && !rep.DryRun && !errors.Is(err, app.ErrUsage) {
		r.rt.NotifyFailure(ctx, app.Failure{Event: event + ".failed", Platform: string(platform.Cloudflare), Profile: r.target.Profile,
			Domain: r.target.Domain, Error: err.Error(), Changes: rep.Changes})
	}
	return err
}

// selectZone returns the zone a custom domain is bound with: --zone (a name
// or an id), or the longest zone name domain ends in, among the zones of
// the bucket's account. The zone must be active.
func selectZone(ctx context.Context, rt *app.Runtime, a *r2Acct, domain, flag string) (*platform.Zone, error) {
	byName := func(name string) (*apiZone, error) {
		q := url.Values{}
		q.Set("account.id", a.account)
		q.Set("name", name)
		zs, err := paginate[apiZone](ctx, a.client.api, "/zones", q, zonesPerPage)
		if err != nil {
			return nil, err
		}
		for i := range zs {
			if platform.NormalizeDomain(zs[i].Name) == name && (zs[i].Account.ID == "" || zs[i].Account.ID == a.account) {
				return &zs[i], nil
			}
		}
		return nil, nil
	}
	active := func(z platform.Zone) (*platform.Zone, error) {
		if z.Status != "" && z.Status != "active" {
			return nil, fmt.Errorf("zone %s is %s, not active yet: custom domains can only be bound in an active zone", z.Name, z.Status)
		}
		return &z, nil
	}
	notInAccount := func(z string) error {
		return fmt.Errorf("%w: zone %s not found in the account of the bucket (cloudflare/%s); the zone must belong to the same account as the bucket", platform.ErrNotFound, z, a.profile)
	}
	if flag != "" {
		var z *apiZone
		var err error
		if strings.Contains(flag, ".") {
			if z, err = byName(platform.NormalizeDomain(flag)); err != nil {
				return nil, err
			}
		} else {
			z, err = a.client.api.getZone(ctx, flag)
			if errors.Is(err, platform.ErrNotFound) {
				z, err = nil, nil
			}
			if err != nil {
				return nil, err
			}
			if z != nil && z.Account.ID != "" && z.Account.ID != a.account {
				z = nil
			}
		}
		if z == nil {
			return nil, notInAccount(flag)
		}
		if !underZone(domain, platform.NormalizeDomain(z.Name)) {
			return nil, app.UsageErrf("%s is not in zone %s", domain, z.Name)
		}
		return active(toZone(*z))
	}
	known := map[string]platform.Zone{}
	if db, err := rt.DB(); err == nil {
		if rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: a.profile, Type: platform.ResZone}); err == nil {
			for _, r := range rows {
				var z platform.Zone
				if r.Decode(&z) == nil {
					if acc, _ := z.Extra["account_id"].(string); acc == a.account {
						known[platform.NormalizeDomain(z.Name)] = z
					}
				}
			}
		}
	}
	for _, cand := range zoneCandidates(domain) {
		if z, ok := known[cand]; ok && z.Status == "active" {
			return &z, nil
		}
		z, err := byName(cand)
		if err != nil {
			return nil, err
		}
		if z != nil {
			return active(toZone(*z))
		}
	}
	return nil, fmt.Errorf("%w: no zone for %s found in the account of cloudflare/%s; add the zone to that account first, or pass --zone", platform.ErrNotFound, domain, a.profile)
}

// checkConflicts looks for the records of domain that make Cloudflare refuse
// the binding: an A, AAAA or CNAME record of that name (a TXT record does
// not conflict). The answer of the API would only say "invalid zone"
// (code 10051). A zone whose records cannot be read is not checked.
func checkConflicts(ctx context.Context, rt *app.Runtime, a *r2Acct, z *platform.Zone, bucket, domain string) error {
	recs, err := a.client.api.listRecordsNamed(ctx, z.ID, domain)
	if err != nil {
		rt.Verbosef("records of %s in zone %s not checked: %v", domain, z.Name, err)
		return nil
	}
	for _, ar := range recs {
		r := toRecord(ar)
		if r.Name != domain {
			continue
		}
		switch r.Type {
		case "A", "AAAA", "CNAME":
		default:
			continue
		}
		if b := R2Bucket(r); b != "" {
			if b == bucket {
				return fmt.Errorf("custom domain %s is already bound to bucket %s; `polyctl cloudflare r2 domain ensure %s %s` accepts a domain that is bound already", domain, bucket, bucket, domain)
			}
			return fmt.Errorf("custom domain %s is already bound to R2 bucket %s; detach it there first", domain, b)
		}
		return fmt.Errorf("zone %s already has the %s record %s -> %s: Cloudflare does not bind a custom domain over an A, AAAA or CNAME record of the same name; delete that record first (see `polyctl cloudflare dns list %s --name %s`)",
			z.Name, r.Type, domain, r.Value, z.Name, domain)
	}
	return nil
}

// explainAttach adds what an error of the creation of a custom domain means.
func explainAttach(err error, bucket, domain string) error {
	switch {
	case hasCode(err, codeR2DomainInUse):
		return fmt.Errorf("custom domain %s is already in use (bound to this bucket or another one; `polyctl cloudflare r2 domain ensure %s %s` succeeds when it is bound to this bucket): %w", domain, bucket, domain, err)
	case hasCode(err, codeR2InvalidZone), hasCode(err, codeR2ZoneNotFound):
		return fmt.Errorf("%w; Cloudflare gives this answer when the zone is not active yet, when %s is not in the zone, or when the zone has an A, AAAA or CNAME record named %s", err, domain, domain)
	}
	return err
}

// bind creates the custom domain and reports it, with the CNAME record
// Cloudflare creates for it once that record could be read.
func bind(ctx context.Context, rt *app.Runtime, run *r2Run, a *r2Acct, bucket, domain string, z *platform.Zone, enabled bool, minTLS string) error {
	detail := fmt.Sprintf("enabled=%t zone=%s", enabled, z.Name)
	if minTLS != "" {
		detail += " min_tls=" + minTLS
	}
	res := domainResource(bucket, domain)
	if rt.DryRun() {
		run.add(platform.Change{Resource: res, Action: platform.WouldCreate, Detail: detail})
		run.add(platform.Change{Resource: recordResource(bucket, domain), Action: platform.WouldCreate, Detail: "CNAME " + domain + " -> " + r2PublicHost + " (auto-created by Cloudflare)"})
		return nil
	}
	body := r2AttachBody{Domain: domain, Enabled: enabled, ZoneID: z.ID, MinTLS: minTLS}
	if _, err := a.api.attachCustomDomain(ctx, a.account, bucket, body); err != nil {
		return run.fail(res, explainAttach(r2Err(err, a, bucket), bucket, domain))
	}
	run.add(platform.Change{Resource: res, Action: platform.Created, Detail: detail})
	rt.Infof("bound %s to bucket %s via cloudflare/%s", domain, bucket, a.profile)
	// The answer of the creation has no status; reading it back is for -v.
	if d, err := a.api.getCustomDomain(ctx, a.account, bucket, domain); err == nil && d.Status != nil {
		rt.Verbosef("custom domain %s: ownership %s, ssl %s", domain, dash(d.Status.Ownership), dash(d.Status.SSL))
	}
	recs, err := a.client.api.listRecordsNamed(ctx, z.ID, domain)
	if err != nil {
		rt.Verbosef("CNAME record of %s not confirmed: %v", domain, err)
		return nil
	}
	for _, ar := range recs {
		r := toRecord(ar)
		if r.Type != "CNAME" || r.Name != domain {
			continue
		}
		px := ""
		if r.Proxied != nil && *r.Proxied {
			px = "proxied, "
		}
		run.add(platform.Change{Resource: recordResource(bucket, domain), Action: platform.Created, ID: r.ID,
			Detail: fmt.Sprintf("CNAME %s -> %s (%sauto-created by Cloudflare)", domain, r.Value, px)})
		storeRecord(ctx, rt, a.profile, z, r)
		break
	}
	return nil
}

// forgetDomainRecord removes the CNAME record of a custom domain from the
// inventory once the domain is unbound (Cloudflare deletes the record).
func forgetDomainRecord(ctx context.Context, rt *app.Runtime, profile, domain string) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResDNSRecord, Name: domain})
	if err != nil {
		return
	}
	for _, row := range rows {
		var rec platform.Record
		if row.Decode(&rec) == nil && strings.EqualFold(rec.Type, "CNAME") {
			if err := db.Delete(ctx, recordSet(profile, ""), platform.ResDNSRecord, row.ID); err != nil {
				rt.Verbosef("inventory: %v", err)
			}
		}
	}
}

// domainUpdate is the partial update that brings cur to the wanted state,
// with the description of the change; an empty description means nothing
// differs. enabled is nil and minTLS "" for "keep".
func domainUpdate(cur r2CustomDomain, enabled *bool, minTLS string) (r2UpdateBody, string) {
	var body r2UpdateBody
	var parts []string
	if enabled != nil && *enabled != cur.Enabled {
		e := *enabled
		body.Enabled = &e
		parts = append(parts, fmt.Sprintf("enabled %t -> %t", cur.Enabled, e))
	}
	if minTLS != "" && minTLS != cur.MinTLS {
		body.MinTLS = minTLS
		parts = append(parts, fmt.Sprintf("min_tls %s -> %s", dash(cur.MinTLS), minTLS))
	}
	return body, strings.Join(parts, "; ")
}

// applyUpdate reports and (unless in a dry run) writes the update of cur.
func applyUpdate(ctx context.Context, rt *app.Runtime, run *r2Run, a *r2Acct, bucket, domain string, cur r2CustomDomain, enabled *bool, minTLS string) error {
	res := domainResource(bucket, domain)
	body, desc := domainUpdate(cur, enabled, minTLS)
	if desc == "" {
		run.add(platform.Change{Resource: res, Action: platform.Unchanged, Detail: fmt.Sprintf("enabled=%t min_tls=%s", cur.Enabled, dash(cur.MinTLS))})
		return nil
	}
	if !rt.DryRun() {
		if _, err := a.api.updateCustomDomain(ctx, a.account, bucket, domain, body); err != nil {
			return run.fail(res, r2Err(err, a, bucket))
		}
		rt.Infof("updated custom domain %s of bucket %s via cloudflare/%s", domain, bucket, a.profile)
	}
	run.add(platform.Change{Resource: res, Action: act(rt, platform.Updated), Detail: desc})
	return nil
}

func newR2DomainAttachCmd(rt *app.Runtime, jur *string) *cobra.Command {
	var zone, minTLS string
	var disabled bool
	cmd := &cobra.Command{
		Use:   "attach <bucket> <domain>",
		Short: "Bind a custom domain to a bucket (fails when it is bound already)",
		Long: `Bind the custom domain <domain> to <bucket>. Cloudflare then creates the proxied
CNAME record <domain> -> public.r2.dev in the zone.

The zone is --zone (a name or an id) or else the longest zone name <domain>
ends in, among the zones of the bucket's account; it must be active. A domain
that is bound already (to this bucket or another) is an error: use
` + "`r2 domain ensure`" + ` for a binding that may exist. So is an A, AAAA or CNAME record
of the same name in the zone.`,
		Args: app.ArgsOrInteractive(rt, 2, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := bucketArgs(ctx, rt, args)
			if err != nil {
				return err
			}
			bucket := args[0]
			domain := ""
			if len(args) > 1 {
				if domain, err = domainArg(args[1]); err != nil {
					return err
				}
			}
			if domain == "" {
				// A new binding: the hostname cannot be listed, it is
				// asked and checked as it is typed.
				v, err := rt.AskInput("<domain>", "Custom domain to bind to "+bucket, "", func(s string) error {
					_, err := domainArg(s)
					return err
				})
				if err != nil {
					return err
				}
				if domain, err = domainArg(v); err != nil {
					return err
				}
			}
			if err := minTLSFlag(minTLS); err != nil {
				return err
			}
			if err := localZoneCheck(domain, zone); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			a, err := findBucket(ctx, rt, bucket, *jur)
			if err != nil {
				return err
			}
			run := &r2Run{rt: rt, target: platform.Target{Platform: platform.Cloudflare, Profile: a.profile, Domain: domain}}
			z, err := selectZone(ctx, rt, a, domain, zone)
			if err != nil {
				return err
			}
			run.target.Zone = z.Name
			if err := checkConflicts(ctx, rt, a, z, bucket, domain); err != nil {
				return err
			}
			return run.finish(ctx, "", bind(ctx, rt, run, a, bucket, domain, z, !disabled, minTLS))
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone name or id (default: the longest zone name the domain ends in, in the bucket's account)")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "create the binding disabled (default: enabled)")
	cmd.Flags().StringVar(&minTLS, "min-tls", "", "minimum TLS version: 1.0, 1.1, 1.2 or 1.3 (default: not set, Cloudflare decides)")
	return cmd
}

// localZoneCheck refuses a --zone given by name that does not hold domain,
// before anything is requested.
func localZoneCheck(domain, zone string) error {
	if zone == "" || !strings.Contains(zone, ".") {
		return nil
	}
	if z := platform.NormalizeDomain(zone); !underZone(domain, z) {
		return app.UsageErrf("%s is not in zone %s", domain, z)
	}
	return nil
}

func newR2DomainUpdateCmd(rt *app.Runtime, jur *string) *cobra.Command {
	var minTLS string
	var enabled bool
	cmd := &cobra.Command{
		Use:   "update <bucket> <domain>",
		Short: "Enable or disable a custom domain, or set its minimum TLS version",
		Long: `Change a custom domain of a bucket: --enabled / --enabled=false switches it on
or off (the = is required), --min-tls sets its minimum TLS version. At least
one of them is required; what is not given keeps its value. A domain that is
not bound to the bucket is not found (exit code 4).`,
		Args: app.ArgsOrInteractive(rt, 2, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := bucketArgs(ctx, rt, args)
			if err != nil {
				return err
			}
			bucket := args[0]
			domain := ""
			if len(args) > 1 {
				if domain, err = domainArg(args[1]); err != nil {
					return err
				}
			}
			if err := minTLSFlag(minTLS); err != nil {
				return err
			}
			var want *bool
			if cmd.Flags().Changed("enabled") {
				e := enabled
				want = &e
			}
			if want == nil && minTLS == "" && !rt.Interactive() {
				return app.UsageErrf("nothing to update: pass --enabled[=false] and/or --min-tls")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			a, err := findBucket(ctx, rt, bucket, *jur)
			if err != nil {
				return err
			}
			if domain == "" {
				if domain, err = pickBucketDomain(ctx, rt, a, bucket); err != nil {
					return err
				}
			}
			// The API answers 200 to an update of a domain that is not
			// bound, so the domain is read first.
			cur, err := currentDomain(ctx, a, bucket, domain)
			if err != nil {
				return err
			}
			if want == nil && minTLS == "" {
				// The interactive flow asks what to change.
				if want, minTLS, err = askDomainUpdate(rt, *cur); err != nil {
					return err
				}
			}
			run := &r2Run{rt: rt, target: platform.Target{Platform: platform.Cloudflare, Profile: a.profile, Zone: cur.ZoneName, Domain: domain}}
			return run.finish(ctx, "", applyUpdate(ctx, rt, run, a, bucket, domain, *cur, want, minTLS))
		},
	}
	cmd.Flags().BoolVar(&enabled, "enabled", false, "serve the domain: --enabled or --enabled=false (default: keep)")
	cmd.Flags().StringVar(&minTLS, "min-tls", "", "minimum TLS version: 1.0, 1.1, 1.2 or 1.3 (default: keep)")
	return cmd
}

func newR2DomainDetachCmd(rt *app.Runtime, jur *string) *cobra.Command {
	return &cobra.Command{
		Use:   "detach <bucket> <domain>",
		Short: "Unbind a custom domain from a bucket (Cloudflare deletes its CNAME record)",
		Long: `Unbind the custom domain <domain> from <bucket>; Cloudflare deletes the CNAME
record it created for it. The interactive flow asks for confirmation (default
no; --yes skips it). The non-interactive flow asks nothing: --yes is required,
and without it the command is a usage error (exit code 2). A domain that is
not bound to the bucket is not found (exit code 4).`,
		Args: app.ArgsOrInteractive(rt, 2, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := bucketArgs(ctx, rt, args)
			if err != nil {
				return err
			}
			bucket := args[0]
			domain := ""
			if len(args) > 1 {
				if domain, err = domainArg(args[1]); err != nil {
					return err
				}
			}
			action := fmt.Sprintf("unbind %s from R2 bucket %s", domain, bucket)
			if !rt.DryRun() {
				if err := rt.CanConfirm(action); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			a, err := findBucket(ctx, rt, bucket, *jur)
			if err != nil {
				return err
			}
			if domain == "" {
				if domain, err = pickBucketDomain(ctx, rt, a, bucket); err != nil {
					return err
				}
				action = fmt.Sprintf("unbind %s from R2 bucket %s", domain, bucket)
			}
			// The API answers 200 to the removal of a domain that is not
			// bound, so the domain is read first.
			cur, err := currentDomain(ctx, a, bucket, domain)
			if err != nil {
				return err
			}
			run := &r2Run{rt: rt, target: platform.Target{Platform: platform.Cloudflare, Profile: a.profile, Zone: cur.ZoneName, Domain: domain}}
			res := domainResource(bucket, domain)
			if !rt.DryRun() {
				ok, err := rt.Confirm(ctx, action+" (Cloudflare deletes its CNAME record)", false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: custom domain %s was not detached", platform.ErrNothingToDo, domain)
				}
				if err := a.api.removeCustomDomain(ctx, a.account, bucket, domain); err != nil {
					return run.finish(ctx, "", run.fail(res, r2Err(err, a, bucket)))
				}
				forgetDomainRecord(ctx, rt, a.profile, domain)
				rt.Infof("unbound %s from bucket %s via cloudflare/%s", domain, bucket, a.profile)
			}
			run.add(platform.Change{Resource: res, Action: act(rt, platform.Deleted), Detail: "zone " + dash(viewOf(*cur, zoneNamesOf(ctx, rt, a.profile)).ZoneName)})
			run.add(platform.Change{Resource: recordResource(bucket, domain), Action: act(rt, platform.Deleted), Detail: "CNAME " + domain + " -> " + r2PublicHost + " (removed by Cloudflare)"})
			return run.finish(ctx, "", nil)
		},
	}
}

func newR2DomainEnsureCmd(rt *app.Runtime, jur *string) *cobra.Command {
	var zone, minTLS string
	var disabled bool
	cmd := &cobra.Command{
		Use:   "ensure <bucket> <domain>",
		Short: "Make sure a custom domain is bound to a bucket, as given",
		Long: `Make sure <domain> is bound to <bucket>, enabled (or disabled with --disabled)
and, with --min-tls, with that minimum TLS version. A binding that is as
given is reported unchanged and nothing is written; one that differs is
updated; a missing one is created like ` + "`r2 domain attach`" + ` does, with the zone
of --zone or the longest zone name <domain> ends in, in the bucket's account.

A domain bound with another zone than --zone is an error: it is not
unbound automatically. A domain bound to another bucket makes the creation
fail. Running the command again changes nothing.`,
		Args: app.ArgsOrInteractive(rt, 2, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			args, err := bucketArgs(ctx, rt, args)
			if err != nil {
				return err
			}
			bucket := args[0]
			domain := ""
			if len(args) > 1 {
				if domain, err = domainArg(args[1]); err != nil {
					return err
				}
			}
			if domain == "" {
				// A new binding: the hostname cannot be listed, it is
				// asked and checked as it is typed.
				v, err := rt.AskInput("<domain>", "Custom domain to bind to "+bucket, "", func(s string) error {
					_, err := domainArg(s)
					return err
				})
				if err != nil {
					return err
				}
				if domain, err = domainArg(v); err != nil {
					return err
				}
			}
			if err := minTLSFlag(minTLS); err != nil {
				return err
			}
			if err := localZoneCheck(domain, zone); err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			a, err := findBucket(ctx, rt, bucket, *jur)
			if err != nil {
				return err
			}
			run := &r2Run{rt: rt, target: platform.Target{Platform: platform.Cloudflare, Profile: a.profile, Domain: domain}}
			const event = "cloudflare.r2.domain.ensure"
			ds, err := a.api.listCustomDomains(ctx, a.account, bucket)
			if err != nil {
				return run.finish(ctx, event, run.fail(domainResource(bucket, domain), r2Err(err, a, bucket)))
			}
			var cur *r2CustomDomain
			for i := range ds {
				if platform.NormalizeDomain(ds[i].Domain) == domain {
					cur = &ds[i]
					break
				}
			}
			want := !disabled
			if cur != nil {
				run.target.Zone = cur.ZoneName
				if zone != "" && zone != cur.ZoneID && platform.NormalizeDomain(zone) != platform.NormalizeDomain(cur.ZoneName) {
					z, err := selectZone(ctx, rt, a, domain, zone)
					if err != nil {
						return run.finish(ctx, event, err)
					}
					if z.ID != cur.ZoneID {
						bound := cur.ZoneName
						if bound == "" {
							bound = cur.ZoneID
						}
						return run.finish(ctx, event, run.fail(domainResource(bucket, domain),
							fmt.Errorf("custom domain %s is bound with zone %s, not %s; the zone of a binding cannot be changed: detach it first", domain, bound, z.Name)))
					}
				}
				return run.finish(ctx, event, applyUpdate(ctx, rt, run, a, bucket, domain, *cur, &want, minTLS))
			}
			z, err := selectZone(ctx, rt, a, domain, zone)
			if err != nil {
				return run.finish(ctx, event, err)
			}
			run.target.Zone = z.Name
			if err := checkConflicts(ctx, rt, a, z, bucket, domain); err != nil {
				return run.finish(ctx, event, run.fail(domainResource(bucket, domain), err))
			}
			return run.finish(ctx, event, bind(ctx, rt, run, a, bucket, domain, z, want, minTLS))
		},
	}
	cmd.Flags().StringVar(&zone, "zone", "", "zone name or id (default: the longest zone name the domain ends in, in the bucket's account)")
	cmd.Flags().BoolVar(&disabled, "disabled", false, "keep the domain bound but disabled (default: enabled)")
	cmd.Flags().StringVar(&minTLS, "min-tls", "", "minimum TLS version: 1.0, 1.1, 1.2 or 1.3 (default: not compared, not set)")
	return cmd
}
