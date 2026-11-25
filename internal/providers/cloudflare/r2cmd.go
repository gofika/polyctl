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
	"github.com/gofika/polyctl/internal/prompt"
)

// newR2Cmd is `polyctl cloudflare r2`: R2 buckets and the custom domains
// bound to them.
func newR2Cmd(rt *app.Runtime) *cobra.Command {
	var jur string
	cmd := &cobra.Command{
		Use:   "r2",
		Short: "R2 buckets and their custom domains",
		Long: `R2 buckets and the custom domains bound to them.

R2 is addressed per account. ` + "`r2 bucket list`" + ` lists the buckets of every
enabled account of every Cloudflare profile, and the ` + "`r2 domain`" + ` commands
find the account that holds <bucket> among them. --profile narrows both to
the accounts of one profile and --account to one account, by id or name; an
account that is disabled for the login is read live and not cached. The name of
a bucket is unique in its account only: a name held by several accounts is a
list to pick from in the interactive flow and ambiguous (exit code 5)
otherwise: pass --account, or --profile when the accounts are of different
profiles. Accounts that have not enabled R2 are skipped.

A custom domain must be in a zone of the bucket's account; by default the
zone is the longest zone name <domain> ends in. Binding a domain makes
Cloudflare create a proxied CNAME record <domain> -> public.r2.dev in that
zone, and unbinding it removes that record; the record cannot be changed or
deleted through the DNS API.`,
	}
	addAccountFlag(rt, cmd)
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
	// multi says the account is one of several the command reads in the
	// profile, or is not the default account of its login: what is said
	// about it names the account next to the profile.
	multi bool
}

// via names the account in a status line: the profile, with the account
// when the profile has several.
func (a *r2Acct) via() string {
	if a.multi {
		return "account " + a.account + " of cloudflare/" + a.profile
	}
	return "cloudflare/" + a.profile
}

// where names the account in an explanation.
func (a *r2Acct) where() string {
	if a.multi {
		return a.via()
	}
	return "the account of cloudflare/" + a.profile
}

// cand is the account as a candidate of an ambiguous bucket name.
func (a *r2Acct) cand() string { return "cloudflare/" + a.profile + " account " + a.account }

// candCells is the candidate as an option of the pick that settles the
// lookup: "cloudflare/work  account acc1".
func (a *r2Acct) candCells() string {
	return prompt.Cells("cloudflare/"+a.profile, "account "+a.account)
}

// newR2Acct is the account of a scope's profile, opened as c. several
// says the command reads more accounts of the profile than this one.
func newR2Acct(c *Client, sc acctScope, account, jurisdiction string, several bool) *r2Acct {
	return &r2Acct{profile: sc.profile, client: c.inAccount(account), api: c.api.withJurisdiction(jurisdiction), account: account,
		multi: several || sc.named(account)}
}

// openR2Accounts opens the accounts an R2 command works on in the profile
// of a scope: the account of --account, else every enabled account of the
// login (see Client.enabledAccounts).
func openR2Accounts(ctx context.Context, rt *app.Runtime, sc acctScope, jurisdiction string) ([]*r2Acct, error) {
	c, err := openProfile(ctx, rt, sc.profile)
	if err != nil {
		return nil, err
	}
	ids := []string{sc.pin}
	if sc.pin == "" {
		if ids, err = c.enabledAccounts(ctx); err != nil {
			return nil, err
		}
		if len(ids) == 0 {
			return nil, fmt.Errorf("%w: every account the credentials of cloudflare/%s see is disabled", platform.ErrNotFound, sc.profile)
		}
	}
	out := make([]*r2Acct, 0, len(ids))
	for _, id := range ids {
		out = append(out, newR2Acct(c, sc, id, jurisdiction, len(ids) > 1))
	}
	return out, nil
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

// r2Scopes are the scopes of an R2 command: the enabled accounts of every
// Cloudflare login (or of the one of --profile), or, with --account, that
// account in the logins that know it and do not disable it; an account no
// login knows is taken through the profile every Cloudflare command would
// use, and read live when it is disabled there.
// explicit says --profile was given.
func r2Scopes(ctx context.Context, rt *app.Runtime) (scopes []acctScope, explicit bool, err error) {
	names, explicit, err := r2Profiles(rt)
	if err != nil {
		return nil, explicit, err
	}
	if pinnedAccount(rt) != "" {
		scopes, err = routeScopes(ctx, rt)
		return scopes, explicit, err
	}
	for _, name := range names {
		sc, err := profileScope(ctx, rt, name)
		if err != nil {
			return nil, explicit, err
		}
		scopes = append(scopes, sc)
	}
	return scopes, explicit, nil
}

// skipReason tells why an account is left out of a search, or "" when the
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

// findBucket returns the account that holds bucket, among the accounts the
// command covers: every enabled account of every Cloudflare login, of the
// login of --profile, or the one account of --account. The same account
// in two logins counts once.
//
// The account of --account is used as it is, without a listing. Otherwise,
// in the default jurisdiction, the inventory (r2_bucket) is asked first:
// when it names exactly one account for the bucket, that account is used.
// Failing that (no inventory, no or several matches, --refresh) the
// accounts are asked live: the only account of the login of --profile is
// used as it is, and of several each one is asked for the bucket. A name several accounts hold a bucket of is a pick in the
// interactive flow and ambiguous (exit code 5) otherwise.
func findBucket(ctx context.Context, rt *app.Runtime, bucket, jurisdiction string) (*r2Acct, error) {
	scopes, explicit, err := r2Scopes(ctx, rt)
	if err != nil {
		return nil, err
	}
	if len(scopes) == 0 {
		return nil, fmt.Errorf("%w: no cloudflare account configured (run `polyctl auth login cloudflare`)", platform.ErrUnauthorized)
	}
	if pinnedAccount(rt) != "" {
		// One account: the logins of the scopes all name it.
		var first error
		for _, sc := range scopes {
			accts, err := openR2Accounts(ctx, rt, sc, jurisdiction)
			if err == nil {
				rt.Infof("bucket %s via %s", bucket, accts[0].via())
				return accts[0], nil
			}
			if first == nil {
				first = err
			}
		}
		return nil, first
	}
	if jurisdiction == "" && !rt.Flags.Refresh {
		if sc, account, ok := inventoryBucket(ctx, rt, scopes, bucket); ok {
			c, err := openProfile(ctx, rt, sc.profile)
			if err != nil {
				return nil, err
			}
			a := newR2Acct(c, sc, account, jurisdiction, false)
			rt.Infof("bucket %s via %s (local inventory)", bucket, a.via())
			return a, nil
		}
	}
	var hits []*r2Acct
	var searched, skipped []string
	var hard error
	skip := func(who string, err error) {
		if why := skipReason(err); why != "" {
			rt.Verbosef("cloudflare/%s: skipped: %v", who, err)
			skipped = append(skipped, who+" ("+why+")")
		} else if hard == nil {
			hard = fmt.Errorf("cloudflare/%s: %w", who, err)
		}
	}
	seen := map[string]bool{}
	for _, sc := range scopes {
		accts, err := openR2Accounts(ctx, rt, sc, jurisdiction)
		if err != nil {
			if explicit {
				return nil, err
			}
			skip(sc.profile, err)
			continue
		}
		if explicit && len(scopes) == 1 && len(accts) == 1 {
			// The one account of the login of --profile: no listing.
			rt.Infof("bucket %s via %s", bucket, accts[0].via())
			return accts[0], nil
		}
		for _, a := range accts {
			if seen[a.account] {
				continue
			}
			seen[a.account] = true
			searched = append(searched, a.account)
			buckets, err := a.api.listBuckets(ctx, a.account, bucket)
			if err != nil {
				who := a.profile
				if a.multi {
					who += " account " + a.account
				}
				skip(who, err)
				continue
			}
			if slices.ContainsFunc(buckets, func(b r2Bucket) bool { return b.Name == bucket }) {
				hits = append(hits, a)
			}
		}
	}
	switch len(hits) {
	case 1:
		rt.Infof("bucket %s via %s", bucket, hits[0].via())
		return hits[0], nil
	case 0:
	default:
		a, err := disambiguate(rt, ambiguousBucket(bucket, hits), hits, (*r2Acct).candCells)
		if err != nil {
			return nil, err
		}
		rt.Infof("bucket %s via %s", bucket, a.via())
		return a, nil
	}
	if hard != nil {
		// The bucket may be in the account that could not be read.
		return nil, hard
	}
	msg := fmt.Sprintf("bucket %s not found in any cloudflare profile", bucket)
	what := "profiles"
	if explicit {
		msg = fmt.Sprintf("bucket %s not found in the enabled accounts of cloudflare/%s (%s)", bucket, scopes[0].profile, strings.Join(searched, ", "))
		what = "accounts"
	}
	if len(skipped) > 0 {
		msg += "; these " + what + " were skipped: " + strings.Join(skipped, ", ")
	}
	return nil, fmt.Errorf("%w: %s", platform.ErrNotFound, msg)
}

// ambiguousBucket is the error of a bucket name several accounts hold a
// bucket of: every account with its profile, and the flags whose value
// differs among them.
func ambiguousBucket(bucket string, hits []*r2Acct) *app.AmbiguousError {
	cands := make([]string, 0, len(hits))
	profiles := false
	for _, h := range hits {
		cands = append(cands, h.cand())
		profiles = profiles || h.profile != hits[0].profile
	}
	hint := "pass --account <id or name> to choose"
	if profiles {
		hint = "pass --profile <name> or --account <id or name> to choose"
	}
	return &app.AmbiguousError{What: fmt.Sprintf("R2 bucket %q (several accounts hold a bucket of that name)", bucket), Candidates: cands, Hint: hint}
}

// bucketRowAccount is the account of a cached bucket row.
func bucketRowAccount(r inventory.Resource, row r2BucketRow) string {
	if row.AccountID != "" {
		return row.AccountID
	}
	return r.ParentID
}

// inventoryBucket returns the scope and the account whose synced buckets
// hold bucket, when the bucket sets of all the profiles of the scopes are
// fresh and name exactly one account of the scopes that has it.
func inventoryBucket(ctx context.Context, rt *app.Runtime, scopes []acctScope, bucket string) (acctScope, string, bool) {
	none := acctScope{}
	db, err := rt.DB()
	if err != nil {
		return none, "", false
	}
	byProfile := map[string]acctScope{}
	for _, sc := range scopes {
		st, err := db.GetState(ctx, inventory.Set{Platform: platform.Cloudflare, Profile: sc.profile, Type: platform.ResR2Bucket})
		if err != nil || st == nil || !st.Fresh(time.Now()) {
			return none, "", false
		}
		byProfile[sc.profile] = sc
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Type: platform.ResR2Bucket, Name: bucket})
	if err != nil {
		return none, "", false
	}
	found, account := none, ""
	for _, r := range rows {
		sc, ok := byProfile[r.Profile]
		if !ok {
			continue
		}
		var row r2BucketRow
		if r.Decode(&row) != nil {
			return none, "", false
		}
		acc := bucketRowAccount(r, row)
		switch {
		case acc == "" || !sc.keeps(acc):
			// A row of an account that is disabled for the login.
		case account == "":
			found, account = sc, acc
		case acc != account:
			return none, "", false // several accounts: let the live search report it
		}
	}
	return found, account, account != ""
}

// r2Err explains an error of an R2 request of account a.
func r2Err(err error, a *r2Acct, bucket string) error {
	switch {
	case err == nil:
		return nil
	case hasCode(err, codeR2NoSuchBucket):
		return fmt.Errorf("bucket %s not found in %s: %w", bucket, a.where(), err)
	case errors.Is(err, platform.ErrNotSupported):
		return fmt.Errorf("R2 is not enabled on %s: %w", a.where(), err)
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
	Bucket  string `json:"bucket" yaml:"bucket"`
	Profile string `json:"profile" yaml:"profile"`
	// AccountID is the account that holds the bucket.
	AccountID string         `json:"account_id" yaml:"account_id"`
	Domains   []r2DomainView `json:"domains" yaml:"domains"`
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
		Long: `List the R2 buckets of every enabled account of every Cloudflare profile, of
the profile of --profile, or of the account of --account.

The buckets of the default jurisdiction come from the local inventory
(resource type r2_bucket, kept fresh for an hour; --refresh reads them
again, --offline only reads the inventory); with --jurisdiction, and for an
account of --account that is disabled for the login, they are read live.
The listing names each bucket and its creation date, and its account when a
profile lists the buckets of several; --wide also reads each bucket for its
location, storage class and jurisdiction (one more request per bucket, so
not with --offline). An account listed by one profile is not listed again
by another. Without --profile, an account that has not enabled R2 is
skipped silently and a profile that fails is reported as a warning; the
command fails only when no account could be read.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if rt.Flags.Offline && (*jur != "" || wide) {
				return app.ErrOffline
			}
			scopes, explicit, err := r2Scopes(ctx, rt)
			if err != nil {
				return err
			}
			rows := []r2BucketRow{}
			owner := map[string]string{} // account -> the profile that lists it
			clients := map[string]*Client{}
			var failures []error
			read, cachedSets := 0, 0
			for _, sc := range scopes {
				list, cached, err := scopeBuckets(ctx, rt, sc, *jur)
				if cached {
					cachedSets++
				}
				if err != nil {
					if explicit {
						return err
					}
					if errors.Is(err, platform.ErrNotSupported) {
						rt.Verbosef("cloudflare/%s: skipped: %v", sc.profile, err)
						continue
					}
					rt.Infof("warning: cloudflare/%s: %v", sc.profile, err)
					failures = append(failures, err)
					continue
				}
				// The accounts the profile answered for: the account of
				// --account, else its default account and those of its
				// buckets.
				var covered []string
				switch {
				case sc.pin != "":
					covered = []string{sc.pin}
				case sc.def != "":
					covered = []string{sc.def}
				}
				if sc.pin == "" {
					for _, row := range list {
						if !slices.Contains(covered, row.AccountID) {
							covered = append(covered, row.AccountID)
						}
					}
				}
				if len(covered) == 0 {
					read++
				}
				for _, acc := range covered {
					if p, ok := owner[acc]; ok && p != sc.profile {
						rt.Verbosef("cloudflare/%s: account %s is listed already", sc.profile, acc)
						continue
					}
					if _, ok := owner[acc]; !ok {
						owner[acc] = sc.profile
						read++
					}
				}
				for _, row := range list {
					if owner[row.AccountID] != sc.profile {
						continue
					}
					if wide {
						c := clients[sc.profile]
						if c == nil {
							if c, err = openProfile(ctx, rt, sc.profile); err != nil {
								return err
							}
							clients[sc.profile] = c
						}
						a := newR2Acct(c, sc, row.AccountID, *jur, false)
						full, err := a.api.getBucket(ctx, row.AccountID, row.Name)
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
				if rows[i].Name != rows[j].Name {
					return rows[i].Name < rows[j].Name
				}
				return rows[i].AccountID < rows[j].AccountID
			})
			// A profile that lists the buckets of several accounts has
			// each bucket say which account it is of.
			several := false
			first := map[string]string{}
			for _, r := range rows {
				if acc, ok := first[r.Profile]; ok && acc != r.AccountID {
					several = true
				} else if !ok {
					first[r.Profile] = r.AccountID
				}
			}
			note := ""
			if cachedSets > 0 {
				note = " (local inventory)"
			}
			rt.Infof("%d bucket(s) in %d account(s)%s", len(rows), read, note)
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"PROFILE"}, Empty: "no buckets"}
				if several {
					g.Headers = append(g.Headers, "ACCOUNT")
				}
				g.Headers = append(g.Headers, "BUCKET", "CREATED")
				if wide {
					g.Headers = append(g.Headers, "LOCATION", "STORAGE_CLASS", "JURISDICTION")
				}
				for _, r := range rows {
					line := []string{r.Profile}
					if several {
						line = append(line, r.AccountID)
					}
					line = append(line, r.Name, r.CreationDate)
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

// scopeBuckets lists the buckets of a scope: through the inventory in the
// default jurisdiction, live in another one and for an account that is
// disabled for the login. cached says the inventory answered.
func scopeBuckets(ctx context.Context, rt *app.Runtime, sc acctScope, jurisdiction string) ([]r2BucketRow, bool, error) {
	if jurisdiction == "" && !sc.live {
		list, cached, err := cachedBuckets(ctx, rt, sc)
		if err != nil || len(list) > 0 || sc.pin == "" || sc.pin == sc.def || rt.Flags.Offline {
			return list, cached, err
		}
		// The inventory holds no bucket of the account of --account. It
		// may hold none because the sync does not reach the account
		// (credentials that cannot list their accounts sync the default
		// one alone): the account is asked.
	}
	list, err := liveBuckets(ctx, rt, sc, jurisdiction)
	return list, false, err
}

// cachedBuckets serves the buckets of the accounts of a scope (default
// jurisdiction) through the inventory, which holds those of every enabled
// account of the profile.
func cachedBuckets(ctx context.Context, rt *app.Runtime, sc acctScope) ([]r2BucketRow, bool, error) {
	set := inventory.Set{Platform: platform.Cloudflare, Profile: sc.profile, Type: platform.ResR2Bucket}
	res, cached, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
		c, err := openProfile(ctx, rt, sc.profile)
		if err != nil {
			return nil, err
		}
		out, err := c.bucketResources(ctx)
		if err != nil {
			// The account of a login without one is known by now.
			err = r2Err(err, newR2Acct(c, acctScope{profile: sc.profile, def: sc.def}, nonEmpty(c.api.accountID, c.r2AccountID), "", false), "")
		}
		return out, err
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
		row.Profile = sc.profile
		row.AccountID = bucketRowAccount(r, row)
		if !sc.keeps(row.AccountID) {
			continue
		}
		out = append(out, row)
	}
	return out, cached, nil
}

// liveBuckets reads the buckets of the accounts of a scope in a
// jurisdiction. Of several accounts, one that cannot be used for R2 is
// left out; when none can, that is the answer.
func liveBuckets(ctx context.Context, rt *app.Runtime, sc acctScope, jurisdiction string) ([]r2BucketRow, error) {
	accts, err := openR2Accounts(ctx, rt, sc, jurisdiction)
	if err != nil {
		return nil, err
	}
	out := []r2BucketRow{}
	var unusable []error
	for _, a := range accts {
		buckets, err := a.api.listBuckets(ctx, a.account, "")
		if err != nil {
			err = r2Err(err, a, "")
			if len(accts) == 1 || skipReason(err) == "" {
				return nil, err
			}
			rt.Verbosef("cloudflare/%s account %s: skipped: %v", a.profile, a.account, err)
			unusable = append(unusable, err)
			continue
		}
		for _, b := range buckets {
			out = append(out, r2BucketRow{Profile: a.profile, AccountID: a.account, Name: b.Name, CreationDate: b.CreationDate})
		}
	}
	if len(unusable) == len(accts) && len(unusable) > 0 {
		return nil, errors.Join(unusable...)
	}
	return out, nil
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
			return rt.Render(r2DomainListResult{Bucket: bucket, Profile: a.profile, AccountID: a.account, Domains: views}, func() output.Grid { return domainGrid(views) })
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
			return nil, fmt.Errorf("%w: custom domain %s is not bound to bucket %s (%s)", platform.ErrNotFound, domain, bucket, a.via())
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
		return fmt.Errorf("%w: zone %s not found in the account of the bucket (%s); the zone must belong to the same account as the bucket", platform.ErrNotFound, z, a.via())
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
	return nil, fmt.Errorf("%w: no zone for %s found in %s; add the zone to that account first, or pass --zone", platform.ErrNotFound, domain, a.where())
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
	rt.Infof("bound %s to bucket %s via %s", domain, bucket, a.via())
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
		rt.Infof("updated custom domain %s of bucket %s via %s", domain, bucket, a.via())
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
				rt.Infof("unbound %s from bucket %s via %s", domain, bucket, a.via())
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
