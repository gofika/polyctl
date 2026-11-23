package cli

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
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// DefaultCertTimeout is the default --timeout of `cert ensure`.
const DefaultCertTimeout = 15 * time.Minute

func newCertCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cert",
		Short: "Issue Let's Encrypt certificates through DNS-01 and keep them in a local store",
	}
	cmd.AddCommand(newCertEnsureCmd(rt), newCertGetCmd(rt))
	return cmd
}

// newCertEnsureCmd is `cert ensure`.
func newCertEnsureCmd(rt *app.Runtime) *cobra.Command {
	var (
		days     int
		force    bool
		staging  bool
		email    string
		agreeTOS bool
		keyType  string
		timeout  time.Duration
	)
	cmd := &cobra.Command{
		Use:   "ensure <domain>",
		Short: "Make sure the local store holds a certificate of a domain and its wildcard that is not about to expire",
		Long: `Make sure the local certificate store holds a Let's Encrypt certificate of the
root domain of <domain> and its wildcard (example.com and *.example.com; a name
below it, such as www.example.com or *.example.com, gives the same certificate)
with more than --days whole days left: it is issued when missing, renewed when
it has --days days left or fewer, does not hold both names, or has another key
type than --key-type, and left alone otherwise. --force renews it anyway (mind
the CA's rate limits).

The CA validates with DNS-01: the TXT records go to the DNS account the root
domain routes to, like every dns command (--profile / --platform choose when
several accounts hold it; none is exit code 4, several exit code 5). The first
run registers an ACME account, which needs an e-mail address (--email or
cert.email) and the agreement to the CA's terms of service (--agree-tos or
cert.agree_tos); the interactive flow asks for both, the non-interactive flow
fails with exit code 2 without them.

--staging uses the Let's Encrypt staging CA and a separate part of the store,
which cert deploy never reads. --dry-run checks the store, the routing and the
nameservers and reports what would be done, writing nothing. A failed issuance
is not retried. Typical cron use: polyctl cert ensure example.com.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			s := cfg.CertSettings()
			o := cert.EnsureOptions{
				Domain:   args[0],
				Days:     s.RenewDays,
				Force:    force,
				KeyType:  s.KeyType,
				Email:    s.Email,
				AgreeTOS: agreeTOS || s.AgreeTOS,
				ReuseKey: s.ReuseKey,
				DryRun:   rt.DryRun(),
				Offline:  rt.Flags.Offline,
			}
			if cmd.Flags().Changed("days") {
				o.Days = days
			}
			if cmd.Flags().Changed("key-type") {
				o.KeyType = keyType
			}
			if cmd.Flags().Changed("email") {
				o.Email = email
			}
			if timeout <= 0 {
				return usageErr("--timeout must be a positive duration, got %s", timeout)
			}
			env, err := cert.NewEnv(rt, staging)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), timeout)
			defer cancel()
			res, err := cert.Ensure(ctx, env, o)
			if err != nil && errors.Is(err, context.DeadlineExceeded) && ctx.Err() != nil {
				err = fmt.Errorf("cert ensure did not finish within --timeout %s: %w", timeout, err)
			}
			if res != nil && (err == nil || len(res.Changes) > 0) {
				if rerr := rt.Render(res, func() output.Grid { return app.ChangeGrid(res.Changes) }); rerr != nil && err == nil {
					err = rerr
				}
			}
			if err != nil && !o.DryRun && !errors.Is(err, app.ErrUsage) && !errors.Is(err, platform.ErrInvalidInput) &&
				!errors.Is(err, prompt.ErrNotInteractive) && !errors.Is(err, platform.ErrNothingToDo) {
				domain := args[0]
				if root, rerr := cert.RootDomain(domain); rerr == nil {
					domain = root
				}
				rt.NotifyFailure(cmd.Context(), app.Failure{Event: "cert.ensure.failed", Domain: domain, Error: err.Error()})
			}
			return err
		},
	}
	f := cmd.Flags()
	f.IntVar(&days, "days", 0, "renew when the certificate has this many whole days left or fewer (default: cert.renew_days, 30)")
	f.BoolVar(&force, "force", false, "issue a new certificate whatever the current one's validity")
	f.BoolVar(&staging, "staging", false, "use the Let's Encrypt staging CA and its separate store (for tests; never deployed)")
	f.StringVar(&email, "email", "", "e-mail address of the ACME account, used when it is registered (default: cert.email)")
	f.BoolVar(&agreeTOS, "agree-tos", false, "agree to the CA's terms of service when registering the ACME account (or cert.agree_tos: true)")
	f.StringVar(&keyType, "key-type", "", "private key type: "+strings.Join(cert.KeyTypes, ", ")+" (default: cert.key_type, ec256)")
	f.DurationVar(&timeout, "timeout", DefaultCertTimeout, "upper bound of the whole run, waiting for the lock included (a Go duration such as 10m)")
	_ = cmd.RegisterFlagCompletionFunc("key-type", cobra.FixedCompletions(cert.KeyTypes, cobra.ShellCompDirectiveNoFileComp))
	addRouteFlags(rt, cmd)
	return cmd
}

// certView is the json / yaml shape of `cert get`.
type certView struct {
	Domain      string   `json:"domain" yaml:"domain"`
	Names       []string `json:"names" yaml:"names"`
	Subject     string   `json:"subject" yaml:"subject"`
	Issuer      string   `json:"issuer" yaml:"issuer"`
	Serial      string   `json:"serial" yaml:"serial"`
	NotBefore   string   `json:"not_before" yaml:"not_before"`
	NotAfter    string   `json:"not_after" yaml:"not_after"`
	DaysLeft    int      `json:"days_left" yaml:"days_left"`
	KeyType     string   `json:"key_type" yaml:"key_type"`
	Fingerprint string   `json:"fingerprint_sha256" yaml:"fingerprint_sha256"`
	Path        string   `json:"path" yaml:"path"`
}

// certPrintParts are the values of `cert get --print`.
var certPrintParts = []string{"fullchain", "cert", "chain", "privkey"}

// newCertGetCmd is `cert get`.
func newCertGetCmd(rt *app.Runtime) *cobra.Command {
	var print string
	var staging bool
	cmd := &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the certificate the local store holds for a domain, or print its PEM files",
		Long: `Show the certificate of the root domain of <domain> in the local store (a name
below it gives the same certificate): names, subject, issuer, serial number,
validity, key type, SHA-256 fingerprint and directory. The private key is never
shown. --print fullchain|cert|chain|privkey writes that PEM file as it is to
stdout instead, for redirecting into a file (privkey says so on stderr; protect
the file yourself). A domain without a certificate is exit code 4. --staging
reads the store of the staging CA.`,
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			if print != "" && !slices.Contains(certPrintParts, print) {
				return usageErr("--print: %q is not one of %s", print, strings.Join(certPrintParts, ", "))
			}
			root, err := cert.RootDomain(args[0])
			if err != nil {
				return err
			}
			st, err := cert.OpenRuntimeStore(rt, staging)
			if err != nil {
				return err
			}
			b, err := st.Load(root, false)
			if err != nil {
				return err
			}
			if b == nil {
				return fmt.Errorf("%w: no certificate of %s in the store %s; run `polyctl cert ensure %s`", platform.ErrNotFound, root, st.Base, root)
			}
			if print != "" {
				data := map[string][]byte{"fullchain": b.FullchainPEM, "cert": b.CertPEM, "chain": b.ChainPEM, "privkey": b.PrivKeyPEM}[print]
				if _, err := rt.Stdout.Write(data); err != nil {
					return err
				}
				if print == "privkey" {
					rt.Infof("note: the private key of %s was written to stdout; keep the file it went to private (chmod 600)", root)
				}
				return nil
			}
			v := certView{
				Domain: b.Domain, Names: b.Names, Subject: b.Subject, Issuer: b.Issuer, Serial: b.Serial,
				NotBefore: b.NotBefore.Format(time.RFC3339), NotAfter: b.NotAfter.Format(time.RFC3339),
				DaysLeft: b.DaysLeft(time.Now()), KeyType: cert.KeyLabel(b.KeyType), Fingerprint: b.Fingerprint, Path: b.Path,
			}
			return rt.Render(v, func() output.Grid {
				return output.KV(
					"DOMAIN", v.Domain,
					"NAMES", strings.Join(v.Names, ", "),
					"SUBJECT", v.Subject,
					"ISSUER", v.Issuer,
					"SERIAL", v.Serial,
					"NOT BEFORE", v.NotBefore,
					"NOT AFTER", v.NotAfter,
					"DAYS LEFT", strconv.Itoa(v.DaysLeft),
					"KEY", v.KeyType,
					"SHA256", v.Fingerprint,
					"PATH", v.Path,
				)
			})
		},
	}
	cmd.Flags().StringVar(&print, "print", "", "write one PEM file to stdout instead: "+strings.Join(certPrintParts, ", "))
	cmd.Flags().BoolVar(&staging, "staging", false, "read the store of the Let's Encrypt staging CA")
	_ = cmd.RegisterFlagCompletionFunc("print", cobra.FixedCompletions(certPrintParts, cobra.ShellCompDirectiveNoFileComp))
	return cmd
}
