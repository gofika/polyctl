package cli

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// newCertDeployCmd is `cert deploy`.
// deployAll is the value of the "--all" option of the cert deploy picker.
const deployAll = "\x00all"

func newCertDeployCmd(rt *app.Runtime) *cobra.Command {
	var (
		days      int
		all       bool
		force     bool
		prune     bool
		regions   []string
		deployers []string
		wait      app.WaitFlags
		issueTO   time.Duration
		email     string
		agreeTOS  bool
	)
	cmd := &cobra.Command{
		Use:   "deploy (<domain> | --all)",
		Short: "Put the certificates of the local store on the cloud load balancers and certificate stores that serve them",
		Long: `Find, live, every place of the cloud accounts that serves a certificate and put
the certificate of the local store on the ones that need it:

  aliyun-alb  Alibaba Cloud ALB HTTPS listeners (default certificate): the
              certificate is uploaded to CAS once (upload_<root>_<expiry>) and
              each listener is pointed at it and waited for until Running.
  gcp-lb      GCP target HTTPS proxies of forwarding rules, global and
              regional: a new certificate (cert-<root>-<expiry>) replaces the
              old one in one SetSslCertificates per proxy, the old one is
              deleted afterwards. Google-managed certificates are left alone.
  aws-acm     AWS ACM imported certificates, re-imported under their ARN, so
              load balancers and CloudFront need no change. Amazon-issued
              certificates are renewed by ACM and left alone.

With --all, a target is updated when its certificate has --days whole days
left or fewer (default cert.renew_days, 30); with <domain>, every target whose
certificate belongs to the root domain of <domain> and is not the store's
current certificate, whatever its expiry. --force updates every matching
target. The store's certificate of a root domain is ensured first, once per
run, as cert ensure would with --days plus 5 (so that a certificate just
deployed is not due again the next day); a domain no DNS account hosts skips
its targets (their certificate is managed elsewhere), unless the store holds
a certificate of it: an unexpired one is deployed with a warning, an expired
one fails the domain. The first certificate needs an ACME account: --email
and --agree-tos (or cert.email and cert.agree_tos: true) register it; the
interactive flow asks for whichever is missing, and the non-interactive flow
fails each root domain that needs one (exit code 1). The questions are asked
once per run: declining the terms or leaving the e-mail prompt skips the
targets of every root domain that needs the account.

Every account of the platforms with a deployer is scanned, narrowed by
--profile, --platform and --deployer; cert.skip_accounts leaves out a profile
("name") or one deployer of it ("name:aliyun-alb"). --region (repeatable)
replaces cert.aws.regions and cert.aliyun.regions, which default to the
profile's region; GCP scans every region unless --region names some ("global"
names the global proxies).

Each target is handled on its own: a failure is reported, sent to
hooks.on_failure (cert.deploy.failed) and the run goes on; the exit code is
then 1 (3 when every failure is a credential or permission one). Nothing is
rolled back: an uploaded certificate is found again by its name on the next
run. --prune-expired also deletes the expired certificates nothing uses any
more (CAS, GCP, ACM imported); it asks first (default no) and needs --yes in
the non-interactive flow. --dry-run runs every read and reports what would be
done, issuing, uploading, binding and deleting nothing. Typical cron use:
polyctl cert deploy --all --prune-expired --yes.`,
		Example: "  polyctl cert deploy example.com\n  polyctl cert deploy --all --prune-expired --yes -o json\n  polyctl cert deploy --all --platform aliyun --profile acme --deployer aliyun-alb --dry-run",
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				return usageErr("cert deploy takes one domain, got %d arguments", len(args))
			}
			return nil
		},
		ValidArgsFunction: completeDomains(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			if len(args) == 0 && !all && rt.Interactive() {
				// The interactive flow offers every due certificate
				// (--all) first, then each certificate of the store.
				st, err := cert.OpenRuntimeStore(rt, false)
				if err != nil {
					return err
				}
				opts, err := certStoreOptions(st)
				if err != nil {
					return err
				}
				if len(opts) == 0 {
					return nothingToDo("the store %s holds no certificate to deploy (run `polyctl cert ensure <domain>`)", st.Base)
				}
				opts = append([]prompt.Option{{Label: "Every certificate that is due (--all)", Value: deployAll}}, opts...)
				v, err := rt.Choose(app.Choice{Title: "Deploy which certificate?", Options: opts, Default: deployAll, Arg: "<domain>"})
				if err != nil {
					return err
				}
				if v == deployAll {
					all = true
				} else {
					args = []string{v}
				}
			}
			switch {
			case len(args) == 0 && !all:
				return usageErr("name a domain or pass --all")
			case len(args) == 1 && all:
				return usageErr("a domain and --all contradict each other")
			}
			doWait, timeout, err := wait.Resolve(cmd)
			if err != nil {
				return err
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			s := cfg.CertSettings()
			if issueTO <= 0 {
				return usageErr("--issue-timeout must be a positive duration, got %s", issueTO)
			}
			o := cert.DeployOptions{All: all, Days: s.RenewDays, Force: force, Prune: prune, DryRun: rt.DryRun(), NoWait: !doWait, Timeout: timeout,
				IssueTimeout: issueTO, NameTemplate: s.NameTemplate}
			if cmd.Flags().Changed("days") {
				if days < 0 {
					return usageErr("--days must not be negative, got %d", days)
				}
				o.Days = days
			}
			for _, r := range regions {
				if r = strings.TrimSpace(r); r != "" && !slices.Contains(o.Regions, r) {
					o.Regions = append(o.Regions, r)
				}
			}
			if o.Deployers, err = selectDeployers(rt, deployers); err != nil {
				return err
			}
			if err := checkSkipAccounts(s.SkipAccounts); err != nil {
				return err
			}
			if !all {
				if o.Domain, err = cert.RootDomain(args[0]); err != nil {
					return err
				}
			}
			if prune && !o.DryRun {
				if err := rt.CanConfirm("delete the expired certificates nothing uses (--prune-expired)"); err != nil {
					return err
				}
			}
			if rt.Flags.Offline {
				return fmt.Errorf("%w: certificate deployment needs the network", app.ErrOffline)
			}
			accounts, err := rt.Accounts()
			if err != nil {
				return err
			}
			acct := cert.EnsureOptions{Email: s.Email, AgreeTOS: agreeTOS || s.AgreeTOS}
			if cmd.Flags().Changed("email") {
				acct.Email = email
			}
			env, err := certDeployEnv(rt, cfg, accounts, acct)
			if err != nil {
				return err
			}
			rep, err := cert.Deploy(ctx, env, o)
			if rep != nil {
				if rerr := rt.Render(rep, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
					err = rerr
				}
			}
			return err
		},
	}
	f := cmd.Flags()
	f.BoolVar(&all, "all", false, "every target of the selected accounts whose certificate has --days days left or fewer")
	f.IntVar(&days, "days", 0, "with --all, update a target whose certificate has this many whole days left or fewer (default: cert.renew_days, 30)")
	f.BoolVar(&force, "force", false, "update every matching target, whatever its certificate")
	f.StringArrayVar(&regions, "region", nil, "region to scan (repeatable; replaces cert.aws.regions / cert.aliyun.regions; \"global\" for GCP global proxies)")
	f.StringArrayVar(&deployers, "deployer", nil, "deployer to run: "+strings.Join(platform.DeployerIDs(), ", ")+" (repeatable; default: all)")
	f.BoolVar(&prune, "prune-expired", false, "also delete the expired certificates nothing uses any more (asks first; --yes in scripts)")
	f.StringVar(&email, "email", "", "e-mail address of the ACME account, used when it is registered (default: cert.email)")
	f.BoolVar(&agreeTOS, "agree-tos", false, "agree to the CA's terms of service when registering the ACME account (or cert.agree_tos: true)")
	f.DurationVar(&issueTO, "issue-timeout", DefaultCertTimeout, "upper bound of ensuring the certificate of each root domain, waiting for its lock included")
	app.AddWaitFlags(cmd, &wait, true, app.DefaultWaitTimeout)
	_ = cmd.RegisterFlagCompletionFunc("deployer", cobra.FixedCompletions(platform.DeployerIDs(), cobra.ShellCompDirectiveNoFileComp))
	addRouteFlags(rt, cmd)
	return cmd
}

// selectDeployers returns the deployers of --deployer (every one when
// none is named), narrowed by --platform. An unknown id is a usage error; a
// platform without a deployer, or a deployer whose platform is not in this
// build, is not supported.
func selectDeployers(rt *app.Runtime, ids []string) ([]platform.CertDeployer, error) {
	var out []platform.CertDeployer
	if len(ids) == 0 {
		out = platform.Deployers()
	}
	for _, id := range ids {
		id = strings.TrimSpace(id)
		d, ok := platform.GetDeployer(id)
		if !ok {
			return nil, usageErr("--deployer: unknown deployer %q (expected one of: %s)", id, strings.Join(platform.DeployerIDs(), ", "))
		}
		if !slices.ContainsFunc(out, func(x platform.CertDeployer) bool { return x.ID() == id }) {
			out = append(out, d)
		}
	}
	only, err := rt.RoutePlatform()
	if err != nil {
		return nil, err
	}
	if only != "" {
		var kept []platform.CertDeployer
		for _, d := range out {
			if d.Platform() == only {
				kept = append(kept, d)
			}
		}
		if len(kept) == 0 {
			if len(ids) > 0 {
				return nil, usageErr("--platform %s and --deployer %s select no deployer", only, strings.Join(ids, ", "))
			}
			return nil, fmt.Errorf("%w: platform %s has no certificate deployer (deployers: %s)", platform.ErrNotSupported, only, strings.Join(platform.DeployerIDs(), ", "))
		}
		out = kept
	}
	for _, d := range out {
		if _, err := platform.Get(d.Platform()); err != nil {
			return nil, fmt.Errorf("%w: deployer %s: %v", platform.ErrNotSupported, d.ID(), err)
		}
	}
	return out, nil
}

// checkSkipAccounts validates cert.skip_accounts: "profile" or
// "profile:deployer" with a known deployer.
func checkSkipAccounts(entries []string) error {
	for _, e := range entries {
		e = strings.TrimSpace(e)
		prof, dep, found := strings.Cut(e, ":")
		if prof == "" || found && dep == "" {
			return usageErr("cert.skip_accounts: %q is not \"profile\" or \"profile:deployer\"", e)
		}
		if found {
			if _, ok := platform.GetDeployer(dep); !ok {
				return usageErr("cert.skip_accounts: %q names the unknown deployer %q (expected one of: %s)", e, dep, strings.Join(platform.DeployerIDs(), ", "))
			}
		}
	}
	return nil
}

// certDeployEnv builds the environment of cert deploy from the runtime.
// acct holds the ACME account e-mail and terms agreement (--email,
// --agree-tos or the cert settings).
func certDeployEnv(rt *app.Runtime, cfg *config.Config, accounts []config.AccountRef, acct cert.EnsureOptions) (*cert.DeployEnv, error) {
	// The DNS account of a domain is routed among every account, whatever
	// --profile / --platform select for the deployment.
	routing, err := rt.Unselected()
	if err != nil {
		return nil, err
	}
	certEnv, err := cert.NewEnv(routing, false)
	if err != nil {
		return nil, err
	}
	askOnce(certEnv)
	s := cfg.CertSettings()
	base := cert.EnsureOptions{KeyType: s.KeyType, Email: acct.Email, AgreeTOS: acct.AgreeTOS, ReuseKey: s.ReuseKey, DryRun: rt.DryRun()}
	env := &cert.DeployEnv{
		Accounts:     accounts,
		SkipAccounts: s.SkipAccounts,
		Open: func(ctx context.Context, ref config.AccountRef) (platform.Client, error) {
			c, _, err := rt.Open(ctx, ref.Profile, ref.Platform)
			return c, err
		},
		Regions: func(ref config.AccountRef) []string {
			switch ref.Platform {
			case platform.AWS:
				return s.AWS.Regions
			case platform.Aliyun:
				return s.Aliyun.Regions
			}
			return nil
		},
		Ensure: func(ctx context.Context, root string, days int) (*cert.Result, error) {
			o := base
			o.Domain, o.Days = root, days
			res, err := cert.Ensure(ctx, certEnv, o)
			return res, deployDNSHint(err, root)
		},
		Stored: func(root string) *cert.Bundle {
			b, err := certEnv.Store.Load(root, false)
			if err != nil {
				return nil
			}
			return b
		},
		History: func(e cert.HistoryEntry) {
			if err := certEnv.Store.AppendHistory(e); err != nil {
				rt.Infof("warning: history.log: %v", err)
			}
		},
		Notify: rt.NotifyFailure,
		Written: func(ctx context.Context, ref config.AccountRef, c platform.Client) {
			p, err := rt.LoadProfile(ref.Profile, ref.Platform)
			if err == nil {
				_, err = rt.SyncClient(ctx, p, c, []platform.ResourceType{platform.ResCertificate})
			}
			if err != nil {
				rt.Verbosef("inventory: certificates of %s: %v", ref.Label(), err)
			}
		},
		Infof: rt.Infof,
	}
	if !rt.Flags.Yes {
		env.ConfirmPrune = func(ctx context.Context, resources []string) (bool, error) {
			rt.Infof("expired certificates nothing uses:")
			for _, r := range resources {
				rt.Infof("  %s", r)
			}
			return rt.Confirm(ctx, fmt.Sprintf("Delete these %d expired certificate(s)?", len(resources)), false)
		}
	}
	return env, nil
}

// askOnce makes the ACME registration questions of env asked once per run:
// cert deploy ensures one certificate per root domain, and each root that
// needs the account would otherwise ask again. The e-mail address given is
// reused, and a "no" to the terms (or leaving the e-mail prompt) answers
// the later roots the same way, so their targets are skipped too.
func askOnce(env *cert.Env) {
	if ask := env.AskEmail; ask != nil {
		var email string
		var stop error
		env.AskEmail = func(ctx context.Context) (string, error) {
			if email != "" || stop != nil {
				return email, stop
			}
			v, err := ask(ctx)
			switch {
			case err == nil:
				email = v
			case errors.Is(err, platform.ErrNothingToDo):
				stop = err
			}
			return v, err
		}
	}
	if confirm := env.ConfirmTOS; confirm != nil {
		declined := false
		env.ConfirmTOS = func(ctx context.Context, directory string) (bool, error) {
			if declined {
				return false, nil
			}
			ok, err := confirm(ctx, directory)
			declined = err == nil && !ok
			return ok, err
		}
	}
}

// deployDNSHint points an ambiguous DNS account of root at
// cert.dns_accounts: the --profile / --platform of cert deploy select the
// accounts it deploys to, not the DNS account.
func deployDNSHint(err error, root string) error {
	var amb *app.AmbiguousError
	if errors.As(err, &amb) {
		amb.Hint = fmt.Sprintf("set cert.dns_accounts: {%s: <platform>/<profile>} in the configuration to choose (--profile and --platform of cert deploy select the accounts it deploys to)", root)
	}
	return err
}
