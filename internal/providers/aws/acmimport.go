package aws

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// -------------------------------------------------------------- import

// acmImportReport is the output of certificate import.
type acmImportReport struct {
	platform.Report `yaml:",inline"`
	ARN             string `json:"arn" yaml:"arn"`
}

func acmImportCmd(rt *app.Runtime) *cobra.Command {
	var certFile, chainFile, keyFile, arn, region string
	var tagArgs []string
	var asNew, staging bool
	cmd := &cobra.Command{
		Use:   "import <domain>",
		Short: "Import a certificate into ACM, replacing the content of the imported certificate of the domain",
		Long: `Import a certificate into ACM: by default the certificate of the root domain of
<domain> in the local store (` + "`polyctl cert ensure`" + `), or the PEM files of
--cert-file (the leaf, or the leaf followed by its chain), --chain-file and
--key-file (an unencrypted private key, which must belong to the leaf).

An imported certificate of the domain (primary name <domain> or its wildcard,
type IMPORTED, not expired) in the region is re-imported in place: its ARN
stays, so the load balancers and CloudFront distributions that use it need no
change, and its tags stay. One that already holds the same serial number is
unchanged. Several of them are ambiguous (exit code 5): pass --arn, or --new.
Without one a new certificate is imported, tagged polyctl:domain=<domain>, the
tags of defaults.aws.tags and --tag.

ACM cannot change the key algorithm of a certificate: re-importing a
certificate with another key type is refused before anything is sent (exit
code 1); --new imports it as a new certificate (a new ARN, to be set where the
old one is used). An expired certificate cannot be imported (exit code 1).
Amazon-issued certificates are renewed by ACM and never replaced.`,
		Example: "  polyctl aws acm certificate import example.com --region us-east-1\n  polyctl aws acm certificate import example.com --cert-file fullchain.pem --key-file privkey.pem --arn arn:aws:acm:<region>:<account-id>:certificate/<uuid>",
		Args:    app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if (certFile == "") != (keyFile == "") {
				return app.UsageErrf("--cert-file and --key-file go together")
			}
			if chainFile != "" && certFile == "" {
				return app.UsageErrf("--chain-file needs --cert-file and --key-file")
			}
			if staging && certFile != "" {
				return app.UsageErrf("--staging reads the local store; it cannot be combined with --cert-file")
			}
			if asNew && arn != "" {
				return app.UsageErrf("--new and --arn contradict each other")
			}
			if region != "" && !validRegionName(region) {
				return app.UsageErrf("--region %q: expected a region name such as us-east-1", region)
			}
			var arnRef acmARN
			if arn != "" {
				var ok bool
				if arnRef, ok = parseACMARN(arn); !ok {
					return app.UsageErrf("--arn %q is not an ACM certificate ARN", arn)
				}
				if region != "" && region != arnRef.Region {
					return app.UsageErrf("--region %s differs from the region of --arn (%s)", region, arnRef.Region)
				}
				region = arnRef.Region
			}
			tags, err := parseACMTags(tagArgs)
			if err != nil {
				return err
			}
			if len(args) == 0 {
				// The interactive flow: the domain, from the unexpired
				// certificates of the local store, or typed for the files
				// of --cert-file.
				d, err := askImportDomain(rt, certFile != "", staging)
				if err != nil {
					return err
				}
				args = []string{d}
			}
			var b *cert.Bundle
			var domain string
			if certFile != "" {
				d, _, err := certDomainArg(args[0])
				if err != nil {
					return err
				}
				domain = d
				leaf, err := os.ReadFile(certFile)
				if err != nil {
					return app.UsageErrf("--cert-file: %v", err)
				}
				if chainFile != "" {
					chain, err := os.ReadFile(chainFile)
					if err != nil {
						return app.UsageErrf("--chain-file: %v", err)
					}
					leaf = append(append(leaf, '\n'), chain...)
				}
				key, err := os.ReadFile(keyFile)
				if err != nil {
					return app.UsageErrf("--key-file: %v", err)
				}
				if b, err = cert.NewBundle(domain, leaf, key); err != nil {
					return fmt.Errorf("%w: --cert-file / --key-file: %v", platform.ErrInvalidInput, err)
				}
				if !b.Covers(domain) {
					return app.UsageErrf("the certificate of --cert-file does not cover %s (it names %s)", domain, strings.Join(b.Leaf.DNSNames, ", "))
				}
			} else {
				root, err := cert.RootDomain(args[0])
				if err != nil {
					return err
				}
				domain = root
				st, err := cert.OpenRuntimeStore(rt, staging)
				if err != nil {
					return err
				}
				if b, err = st.Load(root, false); err != nil {
					return err
				}
				if b == nil {
					return fmt.Errorf("%w: no certificate of %s in the store %s; run `polyctl cert ensure %s`, or pass --cert-file and --key-file", platform.ErrNotFound, root, st.Base, root)
				}
			}
			if !time.Now().Before(b.NotAfter) {
				return fmt.Errorf("the certificate of %s expired on %s: ACM imports a certificate only during its validity period", domain, b.NotAfter.Format(time.RFC3339))
			}
			alg, err := acmKeyAlgorithmOf(b.Leaf.PublicKey)
			if err != nil {
				return err
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			var profile string
			if arn != "" {
				if profile, err = acmProfileForAccount(ctx, rt, arnRef.Account); err != nil {
					return err
				}
			} else if profile, err = rt.ProfileFor(platform.AWS); err != nil {
				return err
			}
			c, err := openProfile(ctx, rt, profile)
			if err != nil {
				return err
			}
			region = c.regionOr(region)
			target := platform.Target{Platform: platform.AWS, Profile: profile, Region: region, Domain: domain}
			resource := "certificate/" + domain
			serial := b.Serial
			desc := fmt.Sprintf("serial %s, %s, expires %s", serial, alg, b.NotAfter.Format(time.RFC3339))

			// The certificate to re-import into, if any.
			var into *platform.Certificate
			switch {
			case arn != "":
				if into, err = c.DescribeCertificate(ctx, region, arn); err != nil {
					return err
				}
			case !asNew:
				certs, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: acmSyncKeyTypes})
				if err != nil {
					return err
				}
				var cands []platform.Certificate
				for _, e := range certs {
					if e.Type == acmImported && e.Status != acmExpired && certMatchesDomain(e, domain) {
						cands = append(cands, e)
					}
				}
				switch len(cands) {
				case 0:
				case 1:
					if into, err = c.DescribeCertificate(ctx, region, cands[0].ID); err != nil {
						return err
					}
				default:
					var names []string
					for _, e := range cands {
						names = append(names, fmt.Sprintf("%s (%s, expires %s)", e.ID, e.Domain, timeStr(e.NotAfter)))
					}
					amb := &app.AmbiguousError{What: "imported certificate of " + domain + " in " + region, Candidates: names,
						Hint: "pass --arn <arn> to choose, or --new to import another certificate"}
					if !rt.Interactive() {
						return amb
					}
					// The interactive flow asks which one, or to import a
					// new certificate (--new).
					var opts []prompt.Option
					for _, e := range cands {
						use := ""
						if e.InUse {
							use = "in use"
						}
						opts = append(opts, prompt.Option{Label: joinLabel(e.ID, e.Domain, "expires "+timeStr(e.NotAfter), use), Value: e.ID})
					}
					opts = append(opts, prompt.Option{Label: "Import as a new certificate (a new ARN)", Value: ""})
					pick, err := rt.Pick().Select("Re-import into which certificate?", opts, "")
					if err != nil {
						return err
					}
					if pick != "" {
						if into, err = c.DescribeCertificate(ctx, region, pick); err != nil {
							return err
						}
					}
				}
			}
			rep := acmImportReport{Report: platform.Report{Target: target, DryRun: rt.DryRun()}}
			finish := func(err error) error {
				if rerr := rt.Render(rep, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
					err = rerr
				}
				return err
			}
			var ch platform.Change
			if into != nil {
				if into.Type != acmImported {
					return fmt.Errorf("certificate %s is %s: ACM renews it itself and its content cannot be replaced; import with --new instead", into.ID, into.Type)
				}
				have := normalizeKeyAlgorithm(into.KeyAlgorithm)
				if normalizeSerial(into.Serial) == normalizeSerial(serial) {
					rep.ARN = into.ID
					rep.Changes = append(rep.Changes, platform.Change{Resource: resource, Action: platform.Unchanged, ID: into.ID, Detail: into.ID + " (" + desc + ")"})
					storeCert(ctx, rt, profile, *into)
					return finish(nil)
				}
				if have != "" && have != alg {
					return fmt.Errorf("certificate %s holds a %s key and the new certificate a %s key: ACM cannot change the key algorithm of a certificate; import it with --new (the ARN changes: update where the old one is used)", into.ID, have, alg)
				}
				ch = platform.Change{Resource: resource, Action: platform.Updated, ID: into.ID, Detail: into.ID + " re-imported (" + desc + "; the ARN stays)"}
			} else {
				ch = platform.Change{Resource: resource, Action: platform.Created, ID: platform.Pending, Detail: desc}
			}
			if rt.DryRun() {
				ch.Action = ch.Action.DryRun()
				rep.ARN = ch.ID
				rep.Changes = append(rep.Changes, ch)
				rt.Infof("dry run: %s %s (%s)", ch.Action.Label(), resource, desc)
				return finish(nil)
			}
			imp := platform.CertificateImport{Region: region, Cert: b.CertPEM, Chain: b.ChainPEM, Key: b.PrivKeyPEM}
			if into != nil {
				imp.ARN = into.ID
			} else {
				all, err := keyPairTags(rt, profile)
				if err != nil {
					return err
				}
				imp.Tags = map[string]string{}
				for k, v := range all {
					imp.Tags[k] = v
				}
				imp.Tags["polyctl:domain"] = domain
				for k, v := range tags {
					imp.Tags[k] = v
				}
			}
			if into != nil && len(tags) > 0 {
				rt.Infof("note: --tag is ignored on a re-import (ACM keeps the tags the certificate has)")
			}
			got, err := c.ImportCertificate(ctx, imp)
			if err != nil {
				return err
			}
			ch.ID = got
			if into == nil {
				ch.Detail = got + " (" + desc + ")"
			}
			rep.ARN = got
			rep.Changes = append(rep.Changes, ch)
			after, werr := c.waitImported(ctx, region, got, serial)
			if after != nil {
				storeCert(ctx, rt, profile, *after)
			}
			if werr != nil {
				return finish(fmt.Errorf("certificate %s was imported, but reading it back failed: %w", got, werr))
			}
			rt.Infof("%s certificate %s (%s) via aws/%s/%s", ch.Action, got, desc, profile, region)
			return finish(nil)
		},
	}
	cmd.Flags().StringVar(&certFile, "cert-file", "", "PEM file of the leaf certificate (and its chain) instead of the local store")
	cmd.Flags().StringVar(&chainFile, "chain-file", "", "PEM file of the intermediate certificates (with --cert-file)")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "PEM file of the unencrypted private key (with --cert-file)")
	cmd.Flags().StringVar(&arn, "arn", "", "re-import into this imported certificate (its region is used)")
	cmd.Flags().BoolVar(&asNew, "new", false, "import as a new certificate even when the domain has an imported one")
	cmd.Flags().StringArrayVar(&tagArgs, "tag", nil, "tag key=value of a new certificate (repeatable; added to defaults.aws.tags and polyctl:domain)")
	cmd.Flags().BoolVar(&staging, "staging", false, "read the store of the Let's Encrypt staging CA")
	cmd.Flags().StringVar(&region, "region", "", "region of the certificate (default: the profile's region; CloudFront needs us-east-1)")
	return cmd
}

// askImportDomain asks for the <domain> of import in the interactive flow:
// with files (--cert-file) a domain, typed and checked; otherwise one of
// the unexpired certificates of the local store (an expired one cannot be
// imported; none is nothing to do).
func askImportDomain(rt *app.Runtime, files, staging bool) (string, error) {
	if files {
		return rt.AskInput("<domain>", "Domain of the certificate", "", func(s string) error {
			_, _, err := certDomainArg(s)
			return inline(err)
		})
	}
	st, err := cert.OpenRuntimeStore(rt, staging)
	if err != nil {
		return "", err
	}
	roots, err := st.List()
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, root := range roots {
		b, err := st.Load(root, false)
		if err != nil || b == nil || !time.Now().Before(b.NotAfter) {
			continue
		}
		days := int(time.Until(b.NotAfter).Hours() / 24)
		opts = append(opts, prompt.Option{Label: fmt.Sprintf("%s  %s  expires %s (%d days)", root, b.KeyType, b.NotAfter.UTC().Format("2006-01-02"), days), Value: root})
	}
	return rt.Choose(app.Choice{Title: "Certificate of the local store to import", Options: opts, Arg: "<domain>",
		Empty: app.NothingToDof("the store %s holds no unexpired certificate (run `polyctl cert ensure <domain>`, or pass --cert-file and --key-file)", st.Base)})
}
