package aws

import (
	"errors"
	"fmt"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// ------------------------------------------------------------- request

// acmRequestReport is the output of certificate request.
type acmRequestReport struct {
	platform.Report   `yaml:",inline"`
	ARN               string              `json:"arn" yaml:"arn"`
	ValidationRecords []acmValidationView `json:"validation_records" yaml:"validation_records"`
}

func acmRequestCmd(rt *app.Runtime) *cobra.Command {
	var sans, tagArgs []string
	var keyAlgorithm, region string
	var wildcard bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "request <domain>",
		Short: "Request a public ACM certificate validated through DNS, and print its validation records",
		Long: `Request a public certificate of <domain> validated through DNS, wait until ACM
publishes the DNS validation records, and print them; write them with
` + "`polyctl dns ensure`" + ` (in whatever account hosts the zone). The certificate is
issued once ACM sees the records, which this command does not wait for: watch
it with ` + "`get`" + `.

By default (--wildcard, or defaults.aws.acm.wildcard) the certificate is
*.<domain> with <domain> as a second name: one certificate for the whole site.
--wildcard=false requests <domain> alone. --san adds names (an account may have
at most 10 names per certificate unless its quota was raised). The key
algorithm is --key-algorithm (default EC_prime256v1, or
defaults.aws.acm.default_key_algorithm; it is always sent, since ACM would
pick RSA_2048 otherwise).

A certificate of the same primary name, names and key algorithm that is
PENDING_VALIDATION or ISSUED is reused: it is reported unchanged with its
records, and nothing is requested. A certificate of the domain with other names
does not count (a note names it). The request carries an idempotency token
derived from what it asks for, so a retried request returns the same
certificate.

The account is --profile (or the current profile) and the region --region (or
the profile's). --wait (default) waits for the records (2 second polls, at most
--timeout); --no-wait reads the certificate once. A certificate that fails
(ACM refuses some names, such as those of example.com) ends the wait at once
(exit code 1). The certificate is kept when the wait fails: read the records
later with ` + "`get <arn> --validation-records`" + `.

Keep the validation records in DNS while the certificate is in use: ACM renews
it through them. On Cloudflare they must not be proxied.`,
		Example: "  polyctl aws acm certificate request example.com --dry-run\n  polyctl aws acm certificate request example.com --region us-east-1 -o json \\\n    | jq -r '.validation_records[] | \"\\(.name):CNAME:\\(.value):300\"'",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				// The interactive flow: a domain of the index (DNS zones and
				// registered domains of every platform), or another one,
				// typed and checked.
				d, err := rt.PickDomain(ctx, app.DomainPick{Title: "Domain of the certificate", Arg: "<domain>", Required: true,
					Another: func() (string, error) {
						return rt.AskInput("<domain>", "Domain of the certificate", "", func(s string) error {
							_, _, err := certDomainArg(s)
							return inline(err)
						})
					}})
				if err != nil {
					return err
				}
				args = []string{d}
			}
			domain, starred, err := certDomainArg(args[0])
			if err != nil {
				return err
			}
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			tags, err := parseACMTags(tagArgs)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			profile, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			settings, err := acmDefaults(rt, profile)
			if err != nil {
				return err
			}
			alg := settings.keyAlgorithm
			if cmd.Flags().Changed("key-algorithm") {
				var ok bool
				if alg, ok = canonicalKeyAlgorithm(keyAlgorithm); !ok {
					return app.UsageErrf("--key-algorithm %q: expected one of %s", keyAlgorithm, strings.Join(acmKeyAlgorithms, ", "))
				}
			}
			wild := settings.wildcard
			if cmd.Flags().Changed("wildcard") {
				wild = wildcard
			}
			if starred && cmd.Flags().Changed("wildcard") && !wildcard {
				return app.UsageErrf("%s asks for a wildcard certificate, which contradicts --wildcard=false", args[0])
			}
			wild = wild || starred
			primary, names := domain, []string{}
			if wild {
				primary, names = "*."+domain, []string{domain}
			}
			implicit := append([]string{primary}, names...)
			for _, s := range sans {
				s = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(s)), ".")
				if err := checkCertName("--san", s); err != nil {
					return err
				}
				if slices.Contains(implicit, s) {
					return app.UsageErrf("--san %s is already a name of the certificate (%s)", s, strings.Join(implicit, ", "))
				}
				if !slices.Contains(names, s) {
					names = append(names, s)
				}
			}
			c, err := openProfile(ctx, rt, profile)
			if err != nil {
				return err
			}
			region = c.regionOr(region)
			target := platform.Target{Platform: platform.AWS, Profile: profile, Region: region, Domain: domain}
			resource := "certificate/" + domain
			desc := strings.Join(append([]string{primary}, names...), ", ") + "; " + alg + "; DNS"

			// Reuse an equivalent certificate.
			existing, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: []string{alg}, Statuses: []string{acmPendingValidation, acmIssued}})
			if err != nil {
				return err
			}
			want := nameSet(append([]string{primary}, names...)...)
			var same []platform.Certificate
			var others []string
			for _, e := range existing {
				if e.Type != acmAmazonIssued || !strings.EqualFold(e.Domain, primary) {
					continue
				}
				have := e.Names
				if e.NamesTruncated || len(have) == 0 {
					d, err := c.DescribeCertificate(ctx, region, e.ID)
					if err != nil {
						return err
					}
					have = d.Names
				}
				if slices.Equal(nameSet(append(have, e.Domain)...), want) && normalizeKeyAlgorithm(e.KeyAlgorithm) == alg {
					same = append(same, e)
				} else {
					others = append(others, fmt.Sprintf("%s (%s)", e.ID, strings.Join(nameSet(append(have, e.Domain)...), ", ")))
				}
			}
			rep := acmRequestReport{Report: platform.Report{Target: target, DryRun: rt.DryRun()}, ValidationRecords: []acmValidationView{}}
			finish := func(err error) error {
				if rerr := rt.Render(rep, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
					err = rerr
				}
				return err
			}
			addRecords := func(cert *platform.Certificate, action platform.Action) {
				rep.ValidationRecords = validationViews(cert.Validation)
				for _, v := range rep.ValidationRecords {
					rep.Changes = append(rep.Changes, platform.Change{Resource: resource + "/validation", Action: action, Detail: v.Name + " " + v.Type + " " + v.Value})
				}
			}
			if len(same) > 0 {
				best := pickCertificate(same)
				rep.ARN = best.ID
				rep.Changes = append(rep.Changes, platform.Change{Resource: resource, Action: platform.Unchanged, ID: best.ID,
					Detail: best.ID + " (" + best.Status + "; " + desc + ")"})
				cert, err := c.waitValidationRecords(ctx, region, best.ID, wait && best.Status == acmPendingValidation, timeout)
				if cert != nil {
					storeCert(ctx, rt, profile, *cert)
					addRecords(cert, platform.Unchanged)
					if err == nil && best.Status == acmPendingValidation {
						noteDNSEnsure(rt, domain, cert)
					}
				}
				if err != nil {
					err = fmt.Errorf("certificate %s exists: %w; read its records later with `polyctl aws acm certificate get %s --validation-records`", best.ID, err, best.ID)
				}
				return finish(err)
			}
			if len(others) > 0 {
				rt.Infof("note: %s already has certificate(s) with other names or key algorithm: %s; requesting a new one", primary, strings.Join(others, "; "))
			}
			if rt.DryRun() {
				rep.ARN = platform.Pending
				rep.Changes = append(rep.Changes,
					platform.Change{Resource: resource, Action: platform.WouldCreate, ID: platform.Pending, Detail: desc},
					platform.Change{Resource: resource + "/validation", Action: platform.Skipped, Detail: "validation record available after request (dry-run)"})
				rt.Infof("dry run: would create %s (%s)", resource, desc)
				return finish(nil)
			}
			allTags, err := keyPairTags(rt, profile)
			if err != nil {
				return err
			}
			if allTags == nil {
				allTags = map[string]string{}
			}
			for k, v := range tags {
				allTags[k] = v
			}
			arn, err := c.RequestCertificate(ctx, platform.CertificateRequest{Region: region, Domain: primary, SANs: names, KeyAlgorithm: alg,
				Token: acmToken(profile, region, primary, alg, names), Tags: allTags})
			if err != nil {
				return err
			}
			rep.ARN = arn
			rep.Changes = append(rep.Changes, platform.Change{Resource: resource, Action: platform.Created, ID: arn, Detail: arn + " (" + desc + ")"})
			storeCert(ctx, rt, profile, platform.Certificate{ID: arn, Region: region, Domain: primary, Names: append([]string{primary}, names...),
				Status: acmPendingValidation, Type: acmAmazonIssued, KeyAlgorithm: alg})
			rt.Infof("requested certificate %s (%s) via aws/%s/%s", arn, desc, profile, region)
			cert, werr := c.waitValidationRecords(ctx, region, arn, wait, timeout)
			if cert != nil {
				storeCert(ctx, rt, profile, *cert)
				addRecords(cert, platform.Created)
			}
			if werr != nil {
				var te *platform.WaitTimeoutError
				if errors.As(werr, &te) {
					werr = fmt.Errorf("certificate %s was requested, but its validation records were not published within %s: %w; read them later with `polyctl aws acm certificate get %s --validation-records`", arn, timeout, werr, arn)
				} else {
					werr = fmt.Errorf("certificate %s was requested (it is kept): %w", arn, werr)
				}
				rep.Changes = append(rep.Changes, platform.Change{Resource: resource + "/validation", Action: platform.Failed, Detail: werr.Error()})
				return finish(werr)
			}
			if cert != nil {
				if !wait && !validationComplete(cert) {
					rt.Infof("note: the validation records are not published yet; read them with `polyctl aws acm certificate get %s --validation-records`", arn)
				}
				noteDNSEnsure(rt, domain, cert)
			}
			return finish(nil)
		},
	}
	cmd.Flags().BoolVar(&wildcard, "wildcard", true, "request *.<domain> with <domain> as a second name (--wildcard=false: <domain> alone)")
	cmd.Flags().StringArrayVar(&sans, "san", nil, "an additional name of the certificate (repeatable)")
	cmd.Flags().StringVar(&keyAlgorithm, "key-algorithm", acmDefaultKeyAlgorithm, "key algorithm ("+strings.Join(acmKeyAlgorithms, ", ")+")")
	cmd.Flags().StringArrayVar(&tagArgs, "tag", nil, "tag key=value of the certificate (repeatable; added to defaults.aws.tags)")
	cmd.Flags().StringVar(&region, "region", "", "region of the certificate (default: the profile's region; CloudFront needs us-east-1)")
	app.AddWaitFlags(cmd, &wf, true, acmValidationTimeout)
	return cmd
}
