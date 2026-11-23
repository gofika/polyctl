package aws

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// acmCmd is `aws acm`: AWS Certificate Manager certificates.
func acmCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "acm",
		Short: "AWS Certificate Manager: public certificates",
		Long: `AWS Certificate Manager (ACM) certificates: list them, show one by domain or
ARN, request a public certificate validated through DNS (and print the
validation records to write with ` + "`polyctl dns ensure`" + `), and import a
certificate of the local store.

ACM is a regional service: a certificate belongs to one region of one account.
Certificates used by CloudFront must be in us-east-1; those of a load balancer
in the load balancer's region.`,
	}
	c := &cobra.Command{Use: "certificate", Short: "ACM certificates"}
	c.AddCommand(acmListCmd(rt), acmGetCmd(rt))
	cmd.AddCommand(c)
	return cmd
}

// ------------------------------------------------------------ settings

// acmSettings are the defaults.aws.acm keys, with the built-in defaults.
type acmSettings struct {
	keyAlgorithm string
	keyTypes     []string
	wildcard     bool
}

func acmDefaults(rt *app.Runtime, profile string) (acmSettings, error) {
	s := acmSettings{keyAlgorithm: acmDefaultKeyAlgorithm, keyTypes: acmDefaultKeyTypes, wildcard: true}
	cfg, err := rt.Config()
	if err != nil {
		return s, err
	}
	if v, err := cfg.DefaultString(profile, platform.AWS, "acm.default_key_algorithm"); err != nil {
		return s, app.UsageErrf("config.yaml: %v", err)
	} else if v != "" {
		k, ok := canonicalKeyAlgorithm(v)
		if !ok {
			return s, app.UsageErrf("config.yaml: defaults.aws.acm.default_key_algorithm %q: expected one of %s", v, strings.Join(acmKeyAlgorithms, ", "))
		}
		s.keyAlgorithm = k
	}
	if v, err := cfg.DefaultStrings(profile, platform.AWS, "acm.default_key_types"); err != nil {
		return s, app.UsageErrf("config.yaml: %v", err)
	} else if len(v) > 0 {
		kt, err := parseKeyTypes("config.yaml: defaults.aws.acm.default_key_types", v)
		if err != nil {
			return s, err
		}
		s.keyTypes = kt
	}
	if v, err := cfg.DefaultString(profile, platform.AWS, "acm.wildcard"); err != nil {
		return s, app.UsageErrf("config.yaml: %v", err)
	} else if v != "" {
		b, err := strconv.ParseBool(v)
		if err != nil {
			return s, app.UsageErrf("config.yaml: defaults.aws.acm.wildcard %q: expected true or false", v)
		}
		s.wildcard = b
	}
	return s, nil
}

// parseKeyTypes checks key algorithms and returns them in ACM's spelling,
// without repeats.
func parseKeyTypes(what string, values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		k, ok := canonicalKeyAlgorithm(v)
		if !ok {
			return nil, app.UsageErrf("%s %q: expected one of %s", what, v, strings.Join(acmKeyAlgorithms, ", "))
		}
		if !slices.Contains(out, k) {
			out = append(out, k)
		}
	}
	return out, nil
}

// parseStatuses checks certificate states (any case).
func parseStatuses(values []string) ([]string, error) {
	var out []string
	for _, v := range values {
		s := strings.ToUpper(strings.TrimSpace(v))
		if !slices.Contains(acmStatuses, s) {
			return nil, app.UsageErrf("--status %q: expected one of %s", v, strings.Join(acmStatuses, ", "))
		}
		if !slices.Contains(out, s) {
			out = append(out, s)
		}
	}
	return out, nil
}

// checkCertName checks a name of a certificate request the way ACM does
// (letters, digits and hyphens in labels of at most 63 characters, no
// hyphen first or last, at least two labels, an optional leading "*.").
func checkCertName(what, name string) error {
	bad := func(why string) error { return app.UsageErrf("%s %q: %s", what, name, why) }
	switch {
	case name == "":
		return app.UsageErrf("%s is empty", what)
	case strings.Contains(name, "://") || strings.ContainsAny(name, "/ \t"):
		return bad("expected a domain name, without a scheme, a path or spaces")
	case len(name) > 253:
		return bad("longer than 253 characters")
	}
	rest := strings.TrimPrefix(name, "*.")
	labels := strings.Split(rest, ".")
	if len(labels) < 2 {
		return bad("expected at least two labels (example.com)")
	}
	for i, l := range labels {
		if l == "" || len(l) > 63 {
			return bad("every label must have 1 to 63 characters")
		}
		if strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return bad("a label may not begin or end with a hyphen")
		}
		for _, r := range l {
			if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
				if r == '*' {
					return bad("only a single leading *. is allowed")
				}
				return bad(fmt.Sprintf("%q is not allowed (letters, digits and hyphens only)", r))
			}
		}
		if i == len(labels)-1 && len(l) < 2 {
			return bad("the last label must have at least 2 characters")
		}
	}
	return nil
}

// certDomainArg normalizes the <domain> argument of get and request: no
// trailing dot, lowercase, and a leading "*." removed (wildcard reports
// whether there was one).
func certDomainArg(s string) (domain string, wildcard bool, err error) {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
	d, wildcard = strings.CutPrefix(d, "*.")
	if strings.HasPrefix(d, "*") {
		return "", false, app.UsageErrf("domain %q: only a single leading *. is allowed", s)
	}
	if err := checkCertName("domain", d); err != nil {
		return "", false, err
	}
	return d, wildcard, nil
}

// parseACMTags parses --tag key=value flags.
func parseACMTags(args []string) (map[string]string, error) {
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

// ------------------------------------------------------------ views

func timeStr(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.UTC().Format(time.RFC3339)
}

func dashIfEmpty(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// acmRow is a certificate of a list.
type acmRow struct {
	ARN          string     `json:"arn" yaml:"arn"`
	Domain       string     `json:"domain" yaml:"domain"`
	Status       string     `json:"status" yaml:"status"`
	Type         string     `json:"type" yaml:"type"`
	KeyAlgorithm string     `json:"key_algorithm" yaml:"key_algorithm"`
	InUse        bool       `json:"in_use" yaml:"in_use"`
	NotAfter     *time.Time `json:"not_after" yaml:"not_after"`
	CreatedAt    *time.Time `json:"created_at" yaml:"created_at"`
	Profile      string     `json:"profile" yaml:"profile"`
	Region       string     `json:"region" yaml:"region"`
}

func acmRowOf(profile string, c platform.Certificate) acmRow {
	return acmRow{ARN: c.ID, Domain: c.Domain, Status: c.Status, Type: c.Type, KeyAlgorithm: normalizeKeyAlgorithm(c.KeyAlgorithm), InUse: c.InUse,
		NotAfter: c.NotAfter, CreatedAt: c.CreatedAt, Profile: profile, Region: c.Region}
}

func acmListGrid(rows []acmRow) output.Grid {
	g := output.Grid{Headers: []string{"DOMAIN", "STATUS", "TYPE", "KEY", "EXPIRES", "REGION", "ARN"}, Empty: "no certificates"}
	for _, r := range rows {
		g.Rows = append(g.Rows, []string{r.Domain, r.Status, r.Type, r.KeyAlgorithm, timeStr(r.NotAfter), r.Region, r.ARN})
	}
	return g
}

// acmValidationView is a DNS validation record in the output.
type acmValidationView struct {
	Domain           string `json:"domain" yaml:"domain"`
	ValidationStatus string `json:"validation_status" yaml:"validation_status"`
	Name             string `json:"name" yaml:"name"`
	Type             string `json:"type" yaml:"type"`
	Value            string `json:"value" yaml:"value"`
}

// validationViews returns the published validation records, one per
// distinct record (the wildcard and the bare name share theirs), as AWS
// reports them (trailing dot and case kept).
func validationViews(recs []platform.ValidationRecord) []acmValidationView {
	out := []acmValidationView{}
	seen := map[string]bool{}
	for _, v := range recs {
		if !v.Ready() {
			continue
		}
		key := strings.ToLower(v.Name) + "|" + strings.ToUpper(v.Type) + "|" + strings.ToLower(v.Value)
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, acmValidationView{Domain: v.Domain, ValidationStatus: v.Status, Name: v.Name, Type: v.Type, Value: v.Value})
	}
	return out
}

func validationGrid(views []acmValidationView) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "STATUS", "DOMAIN"}, Empty: "no validation records published yet"}
	for _, v := range views {
		g.Rows = append(g.Rows, []string{v.Name, v.Type, v.Value, v.ValidationStatus, v.Domain})
	}
	return g
}

// acmDetail is the output of certificate get.
type acmDetail struct {
	ARN                string               `json:"arn" yaml:"arn"`
	Domain             string               `json:"domain" yaml:"domain"`
	SANs               []string             `json:"sans" yaml:"sans"`
	Status             string               `json:"status" yaml:"status"`
	Type               string               `json:"type" yaml:"type"`
	KeyAlgorithm       string               `json:"key_algorithm" yaml:"key_algorithm"`
	Issuer             string               `json:"issuer,omitempty" yaml:"issuer,omitempty"`
	CreatedAt          *time.Time           `json:"created_at" yaml:"created_at"`
	IssuedAt           *time.Time           `json:"issued_at" yaml:"issued_at"`
	NotBefore          *time.Time           `json:"not_before" yaml:"not_before"`
	NotAfter           *time.Time           `json:"not_after" yaml:"not_after"`
	RenewalEligibility string               `json:"renewal_eligibility,omitempty" yaml:"renewal_eligibility,omitempty"`
	InUseBy            []string             `json:"in_use_by" yaml:"in_use_by"`
	FailureReason      string               `json:"failure_reason,omitempty" yaml:"failure_reason,omitempty"`
	ValidationRecords  *[]acmValidationView `json:"validation_records,omitempty" yaml:"validation_records,omitempty"`
	Profile            string               `json:"profile" yaml:"profile"`
	Region             string               `json:"region" yaml:"region"`
	Cached             bool                 `json:"cached" yaml:"cached"`
}

func acmDetailOf(profile string, c *platform.Certificate, cached, withRecords bool) acmDetail {
	d := acmDetail{ARN: c.ID, Domain: c.Domain, SANs: c.Names, Status: c.Status, Type: c.Type, KeyAlgorithm: normalizeKeyAlgorithm(c.KeyAlgorithm),
		Issuer: c.Issuer, CreatedAt: c.CreatedAt, IssuedAt: c.IssuedAt, NotBefore: c.NotBefore, NotAfter: c.NotAfter,
		RenewalEligibility: c.RenewalEligibility, InUseBy: c.InUseBy, FailureReason: c.FailureReason, Profile: profile, Region: c.Region, Cached: cached}
	if d.SANs == nil {
		d.SANs = []string{}
	}
	if d.InUseBy == nil {
		d.InUseBy = []string{}
	}
	if withRecords {
		v := validationViews(c.Validation)
		d.ValidationRecords = &v
	}
	return d
}

func acmDetailGrid(d acmDetail) output.Grid {
	return output.KV(
		"DOMAIN", d.Domain,
		"ARN", d.ARN,
		"SANS", dashIfEmpty(strings.Join(d.SANs, ", ")),
		"STATUS", d.Status,
		"TYPE", d.Type,
		"KEY", d.KeyAlgorithm,
		"ISSUER", dashIfEmpty(d.Issuer),
		"CREATED", timeStr(d.CreatedAt),
		"ISSUED", timeStr(d.IssuedAt),
		"NOT BEFORE", timeStr(d.NotBefore),
		"NOT AFTER", timeStr(d.NotAfter),
		"RENEWAL", dashIfEmpty(d.RenewalEligibility),
		"IN USE BY", dashIfEmpty(strings.Join(d.InUseBy, ", ")),
		"FAILURE", dashIfEmpty(d.FailureReason),
		"REGION", d.Region,
		"PROFILE", d.Profile,
	)
}

// renderValidationBlock prints the validation records after a table.
func renderValidationBlock(rt *app.Runtime, views []acmValidationView) error {
	if rt.Format() != output.Table {
		return nil
	}
	fmt.Fprintln(rt.Stdout, "\n# validation records")
	return output.RenderGrid(rt.Stdout, validationGrid(views))
}

// noteDNSEnsure prints the `dns ensure` commands that write the validation
// records, and why they must stay.
func noteDNSEnsure(rt *app.Runtime, domain string, c *platform.Certificate) {
	specs := platform.ACMValidationRecords(domain, c.Validation)
	if len(specs) == 0 {
		return
	}
	var args []string
	for _, s := range specs {
		args = append(args, "--record "+s.Inline())
	}
	rt.Infof("write the validation records with: polyctl dns ensure %s %s", domain, strings.Join(args, " "))
	rt.Infof("note: keep the validation records in DNS while the certificate is in use: ACM renews it through them")
}

// ------------------------------------------------------------ inventory

func storeCert(ctx context.Context, rt *app.Runtime, profile string, c platform.Certificate) {
	if c.ID == "" || c.ID == platform.Pending {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResCertificate}, acmRecord(c).resource(), cfg.TTLFor(platform.ResCertificate))
}

func dropCert(ctx context.Context, rt *app.Runtime, profile, arn string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResCertificate}, platform.ResCertificate, arn)
	}
}

// certHit is a certificate of the inventory and the profile that holds it.
type certHit struct {
	profile string
	cert    platform.Certificate
}

// certInventoryHits returns the cached certificates of the accounts that
// match. When none does, the stale certificate sets (all of them with
// --refresh, none with --offline) are synced once and the lookup repeated;
// an account that could not be synced is returned as the error when still
// nothing matches (it may hold the certificate).
func certInventoryHits(ctx context.Context, rt *app.Runtime, accounts []config.AccountRef, what string, match func(acmCertificate) bool) ([]certHit, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	lookup := func() ([]certHit, error) {
		var out []certHit
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResCertificate})
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				var c acmCertificate
				if r.Decode(&c) != nil {
					continue
				}
				if c.ARN == "" {
					c.ARN = r.ID
				}
				if match(c) {
					out = append(out, certHit{profile: a.Profile, cert: c.certificate()})
				}
			}
		}
		return out, nil
	}
	hits, err := lookup()
	if err != nil || len(hits) > 0 || rt.Flags.Offline {
		return hits, err
	}
	var stale []config.AccountRef
	for _, a := range accounts {
		st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: platform.ResCertificate})
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
	rt.Infof("looking up %s: syncing the certificates of %d account(s)...", what, len(stale))
	var syncErr error
	for _, a := range stale {
		reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{platform.ResCertificate})
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
	if hits, err = lookup(); err != nil {
		return nil, err
	}
	if len(hits) == 0 && syncErr != nil {
		return nil, fmt.Errorf("cannot tell where %s is: %w", what, syncErr)
	}
	return hits, nil
}

// acmProfileForAccount returns the AWS profile of the account id of an ARN:
// --profile when given, the only AWS account, the profile whose metadata
// or cached certificates name the account id, else the profile whose
// credentials belong to it (asked live). No profile of that account is
// ErrNotFound.
func acmProfileForAccount(ctx context.Context, rt *app.Runtime, account string) (string, error) {
	if rt.Flags.Profile != "" {
		return rt.ProfileFor(platform.AWS)
	}
	accounts, err := awsAccounts(rt)
	if err != nil {
		return "", err
	}
	if len(accounts) == 1 {
		return accounts[0].Profile, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	var hits []string
	for _, a := range accounts {
		if acc, err := cfg.Account(a.Profile, platform.AWS); err == nil && acc.Metadata[metaAccountID] == account {
			hits = append(hits, a.Profile)
		}
	}
	if len(hits) == 0 {
		if db, err := rt.DB(); err == nil {
			for _, a := range accounts {
				rows, _ := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: a.Profile, Type: platform.ResCertificate})
				for _, r := range rows {
					if p, ok := parseACMARN(r.ID); ok && p.Account == account {
						hits = append(hits, a.Profile)
						break
					}
				}
			}
		}
	}
	if len(hits) == 0 && !rt.Flags.Offline {
		for _, a := range accounts {
			c, err := openProfile(ctx, rt, a.Profile)
			if err != nil {
				rt.Infof("warning: aws/%s: %v", a.Profile, err)
				continue
			}
			id, err := c.Verify(ctx)
			if err != nil {
				rt.Infof("warning: aws/%s: %v", a.Profile, err)
				continue
			}
			if id.Account == account {
				hits = append(hits, a.Profile)
			}
		}
	}
	switch len(hits) {
	case 0:
		return "", fmt.Errorf("%w: no selected AWS profile belongs to account %s (pass --profile)", platform.ErrNotFound, account)
	case 1:
		return hits[0], nil
	}
	return "", &app.AmbiguousError{What: "profile of AWS account " + account, Candidates: hits}
}

// ---------------------------------------------------------------- list

func acmListCmd(rt *app.Runtime) *cobra.Command {
	var keyTypes, statuses []string
	var domain, region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ACM certificates (the inventory caches every region)",
		Long: `List the ACM certificates of the profile's region. The local inventory holds
those of every enabled region and of every key type; --region asks AWS about
another region directly, and --region all lists every region of the
inventory.

--key-type keeps certificates of these key algorithms (default
EC_prime256v1 and RSA_2048, or defaults.aws.acm.default_key_types): ACM itself
lists only RSA certificates unless the key types are named, so an ECDSA
certificate never "disappears". --status keeps these states (ISSUED,
PENDING_VALIDATION, EXPIRED, ...) and --domain the certificates whose primary
name is the domain or its wildcard. Several certificates of one domain are all
listed.`,
		Example: "  polyctl aws acm certificate list\n  polyctl aws acm certificate list --key-type EC_prime256v1 --key-type RSA_2048 --status ISSUED -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			profile, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			settings, err := acmDefaults(rt, profile)
			if err != nil {
				return err
			}
			kt := settings.keyTypes
			if len(keyTypes) > 0 {
				if kt, err = parseKeyTypes("--key-type", keyTypes); err != nil {
					return err
				}
			}
			st, err := parseStatuses(statuses)
			if err != nil {
				return err
			}
			if domain != "" {
				if domain, _, err = certDomainArg(domain); err != nil {
					return err
				}
			}
			all := region == "all"
			if region != "" && !all && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1, or all", region)
			}
			// The inventory holds the key types of the SDK only; others
			// are asked live.
			live := region != "" && !all
			for _, k := range kt {
				if !slices.Contains(acmSyncKeyTypes, k) {
					live = true
				}
			}
			var certs []platform.Certificate
			where := "aws/" + profile
			cached := false
			if live {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				c, err := openProfile(ctx, rt, profile)
				if err != nil {
					return err
				}
				regions := []string{c.regionOr(region)}
				if all {
					if regions, err = c.enabledRegions(ctx); err != nil {
						return err
					}
				} else {
					where += "/" + regions[0]
				}
				for _, r := range regions {
					got, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: r, KeyTypes: kt, Statuses: st})
					if err != nil {
						return err
					}
					for _, cert := range got {
						storeCert(ctx, rt, profile, cert)
					}
					certs = append(certs, got...)
				}
			} else {
				set := inventory.Set{Platform: platform.AWS, Profile: profile, Type: platform.ResCertificate}
				listRegion := ""
				rows, fromCache, err := rt.EnsureSet(ctx, set, func(ctx context.Context) ([]platform.Resource, error) {
					c, err := openProfile(ctx, rt, profile)
					if err != nil {
						return nil, err
					}
					listRegion = c.region
					return c.Sync(ctx, platform.ResCertificate)
				})
				if err != nil {
					return err
				}
				cached = fromCache
				if listRegion == "" {
					listRegion = profileRegion(rt, profile)
				}
				if !all && listRegion != "" {
					where += "/" + listRegion
				}
				for _, r := range rows {
					var a acmCertificate
					if err := r.Decode(&a); err != nil {
						return fmt.Errorf("decode cached certificate %s: %w", r.ID, err)
					}
					if !all && listRegion != "" && a.Region != "" && a.Region != listRegion {
						continue
					}
					c := a.certificate()
					if !slices.Contains(kt, normalizeKeyAlgorithm(c.KeyAlgorithm)) {
						continue
					}
					if len(st) > 0 && !slices.Contains(st, c.Status) {
						continue
					}
					certs = append(certs, c)
				}
			}
			rows := []acmRow{}
			for _, c := range certs {
				if domain != "" && !certMatchesDomain(c, domain) {
					continue
				}
				rows = append(rows, acmRowOf(profile, c))
			}
			slices.SortFunc(rows, func(a, b acmRow) int {
				return strings.Compare(a.Domain+"|"+a.Region+"|"+a.ARN, b.Domain+"|"+b.Region+"|"+b.ARN)
			})
			if cached {
				rt.Infof("certificates via %s (local inventory)", where)
			}
			if len(rows) == 0 {
				rt.Infof("no certificates via %s", where)
			}
			return rt.Render(rows, func() output.Grid { return acmListGrid(rows) })
		},
	}
	cmd.Flags().StringSliceVar(&keyTypes, "key-type", nil, "only certificates of these key algorithms (repeatable or comma-separated; default EC_prime256v1,RSA_2048)")
	cmd.Flags().StringSliceVar(&statuses, "status", nil, "only certificates in these states (repeatable or comma-separated: "+strings.Join(acmStatuses, ", ")+")")
	cmd.Flags().StringVar(&domain, "domain", "", "only certificates whose primary name is this domain or its wildcard")
	cmd.Flags().StringVar(&region, "region", "", "list another region (asks AWS), or all for every region of the inventory")
	return cmd
}

// ----------------------------------------------------------------- get

func acmGetCmd(rt *app.Runtime) *cobra.Command {
	var keyTypes []string
	var region string
	var withRecords bool
	cmd := &cobra.Command{
		Use:   "get <domain|arn>",
		Short: "Show an ACM certificate by domain or ARN, with its DNS validation records",
		Long: `Show one ACM certificate: names, state, key algorithm, validity, renewal
eligibility, the resources that use it and, with --validation-records or while
it is PENDING_VALIDATION, the DNS records that validate it.

An argument starting with arn: is a certificate ARN, read in its own region
(another --region is exit code 2) in the account it names. Anything else is a
domain: the inventory (every region of every selected account, synced once
when it does not know the domain) gives the certificates whose primary name is
the domain or its wildcard; they must all be in one account and region
(otherwise exit code 5: pass --profile and/or --region), and of several the
best is shown: ISSUED before PENDING_VALIDATION, then the later expiry, then
the newer one, with expired, failed and revoked ones last. Other names of a
certificate are not matched; ` + "`list --domain`" + ` shows them all. --region asks
that region of the profile's account directly.

A PENDING_VALIDATION certificate becomes VALIDATION_TIMED_OUT when it is not
validated within 72 hours; write its records with ` + "`polyctl dns ensure`" + ` and keep
them while the certificate is in use (ACM renews it through them).`,
		Example: "  polyctl aws acm certificate get example.com\n  polyctl aws acm certificate get arn:aws:acm:<region>:<account-id>:certificate/<uuid> --validation-records -o json",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref := strings.TrimSpace(args[0])
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			var profile string
			var found *platform.Certificate
			cached := rt.Flags.Offline
			if strings.HasPrefix(ref, "arn:") {
				a, ok := parseACMARN(ref)
				if !ok {
					return app.UsageErrf("%q is not an ACM certificate ARN (arn:aws:acm:<region>:<account-id>:certificate/<id>)", ref)
				}
				if region != "" && region != a.Region {
					return app.UsageErrf("--region %s differs from the region of %s (%s)", region, ref, a.Region)
				}
				if rt.Flags.Offline {
					accounts, err := awsAccounts(rt)
					if err != nil {
						return err
					}
					hits, err := certInventoryHits(ctx, rt, accounts, "certificate "+ref, func(c acmCertificate) bool { return c.ARN == ref })
					if err != nil {
						return err
					}
					if len(hits) == 0 {
						return fmt.Errorf("%w: certificate %s is not in the local inventory (retry without --offline)", platform.ErrNotFound, ref)
					}
					profile, found = hits[0].profile, &hits[0].cert
				} else {
					var err error
					if profile, err = acmProfileForAccount(ctx, rt, a.Account); err != nil {
						return err
					}
					c, err := openProfile(ctx, rt, profile)
					if err != nil {
						return err
					}
					if found, err = c.DescribeCertificate(ctx, a.Region, ref); err != nil {
						if errors.Is(err, platform.ErrNotFound) {
							dropCert(ctx, rt, profile, ref)
						}
						return err
					}
					storeCert(ctx, rt, profile, *found)
				}
			} else {
				domain, _, err := certDomainArg(ref)
				if err != nil {
					return err
				}
				var settings acmSettings
				var hits []certHit
				if region != "" {
					if rt.Flags.Offline {
						return app.ErrOffline
					}
					if profile, err = rt.ProfileFor(platform.AWS); err != nil {
						return err
					}
					if settings, err = acmDefaults(rt, profile); err != nil {
						return err
					}
					kt := settings.keyTypes
					if len(keyTypes) > 0 {
						if kt, err = parseKeyTypes("--key-type", keyTypes); err != nil {
							return err
						}
					}
					c, err := openProfile(ctx, rt, profile)
					if err != nil {
						return err
					}
					certs, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: kt})
					if err != nil {
						return err
					}
					for _, cert := range certs {
						storeCert(ctx, rt, profile, cert)
						if certMatchesDomain(cert, domain) {
							hits = append(hits, certHit{profile: profile, cert: cert})
						}
					}
				} else {
					accounts, err := awsAccounts(rt)
					if err != nil {
						return err
					}
					p := accounts[0].Profile
					if len(accounts) > 1 {
						p, _ = rt.ProfileFor(platform.AWS)
					}
					if settings, err = acmDefaults(rt, p); err != nil {
						return err
					}
					kt := settings.keyTypes
					if len(keyTypes) > 0 {
						if kt, err = parseKeyTypes("--key-type", keyTypes); err != nil {
							return err
						}
					}
					hits, err = certInventoryHits(ctx, rt, accounts, "the certificate of "+domain, func(c acmCertificate) bool {
						return certMatchesDomain(c.certificate(), domain) && slices.Contains(kt, normalizeKeyAlgorithm(c.KeyAlgorithm))
					})
					if err != nil {
						return err
					}
				}
				if len(hits) == 0 {
					return fmt.Errorf("%w: no certificate of domain %s in the selected AWS accounts (ACM certificates belong to one region: check --region; other key types need --key-type)", platform.ErrNotFound, domain)
				}
				groups := map[string]bool{}
				var names []string
				for _, h := range hits {
					key := h.profile + "/" + h.cert.Region
					if !groups[key] {
						groups[key] = true
					}
					names = append(names, fmt.Sprintf("aws/%s/%s (%s)", h.profile, h.cert.Region, h.cert.ID))
				}
				if len(groups) > 1 {
					slices.Sort(names)
					return &app.AmbiguousError{What: "certificate of " + domain, Candidates: names, Hint: "pass --profile <name> and/or --region <region> to choose"}
				}
				best := pickCertificate(certsOf(hits))
				profile = hits[0].profile
				found = &best
				if !rt.Flags.Offline {
					c, err := openProfile(ctx, rt, profile)
					if err != nil {
						return err
					}
					if found, err = c.DescribeCertificate(ctx, best.Region, best.ID); err != nil {
						if errors.Is(err, platform.ErrNotFound) {
							dropCert(ctx, rt, profile, best.ID)
						}
						return err
					}
					storeCert(ctx, rt, profile, *found)
				}
			}
			pending := found.Status == acmPendingValidation
			show := (withRecords || pending) && !cached
			if (withRecords || pending) && cached {
				rt.Infof("note: the local inventory holds no validation records; run without --offline to read them")
			}
			if found.Type == acmImported && withRecords {
				rt.Infof("note: %s is an imported certificate: it has no DNS validation records", found.ID)
			}
			if pending && !cached {
				rt.Infof("note: certificate %s waits for DNS validation; unvalidated within 72 hours it becomes VALIDATION_TIMED_OUT and has to be requested again", found.ID)
				noteDNSEnsure(rt, strings.TrimPrefix(strings.ToLower(found.Domain), "*."), found)
			}
			d := acmDetailOf(profile, found, cached, show)
			if err := rt.Render(d, func() output.Grid { return acmDetailGrid(d) }); err != nil {
				return err
			}
			if show {
				return renderValidationBlock(rt, *d.ValidationRecords)
			}
			return nil
		},
	}
	cmd.Flags().StringSliceVar(&keyTypes, "key-type", nil, "look up a domain among certificates of these key algorithms (default EC_prime256v1,RSA_2048)")
	cmd.Flags().StringVar(&region, "region", "", "look the domain up in this region of the profile's account (asks AWS)")
	cmd.Flags().BoolVar(&withRecords, "validation-records", false, "also show the DNS validation records (always shown while PENDING_VALIDATION)")
	return cmd
}

func certsOf(hits []certHit) []platform.Certificate {
	out := make([]platform.Certificate, 0, len(hits))
	for _, h := range hits {
		out = append(out, h.cert)
	}
	return out
}
