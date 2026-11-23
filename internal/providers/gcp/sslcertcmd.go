package gcp

import (
	"context"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newSSLCertificateCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "ssl-certificate", Short: "Self-managed SSL certificates of load balancers (regional and global)"}
	cmd.AddCommand(sslCertListCmd(rt), sslCertCreateCmd(rt), sslCertUpdateCmd(rt), sslCertDeleteCmd(rt))
	return cmd
}

// scopeFlags are --region / --global.
type scopeFlags struct {
	region string
	global bool
}

func (f *scopeFlags) register(cmd *cobra.Command, what string) {
	cmd.Flags().StringVar(&f.region, "region", "", "region of a regional "+what)
	cmd.Flags().BoolVar(&f.global, "global", false, "a global "+what)
}

// resolve returns the region ("" for global). required makes one of the
// two flags mandatory; otherwise neither means every scope (all true).
func (f *scopeFlags) resolve(required bool) (region string, all bool, err error) {
	f.region = strings.TrimSpace(f.region)
	switch {
	case f.global && f.region != "":
		return "", false, app.UsageErrf("--global and --region contradict each other")
	case f.global:
		return "", false, nil
	case f.region != "":
		return f.region, false, nil
	case required:
		return "", false, app.UsageErrf("pass --region <region> for a regional certificate or --global for a global one")
	}
	return "", true, nil
}

// readCertFiles reads --cert-file and --key-file; "@-" reads stdin (both
// "@-" read one text holding the chain and the key).
func readCertFiles(rt *app.Runtime, certFile, keyFile string) ([]byte, []byte, error) {
	var stdin []byte
	read := func(flag, path string) ([]byte, error) {
		if path == "@-" {
			if stdin == nil {
				b, err := io.ReadAll(rt.Stdin)
				if err != nil {
					return nil, app.UsageErrf("--%s @-: %v", flag, err)
				}
				stdin = b
			}
			return stdin, nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, app.UsageErrf("--%s: %v", flag, err)
		}
		return b, nil
	}
	c, err := read("cert-file", certFile)
	if err != nil {
		return nil, nil, err
	}
	k, err := read("key-file", keyFile)
	if err != nil {
		return nil, nil, err
	}
	return c, k, nil
}

// loadCertMaterial reads and checks the PEM files locally (exit code 2 on
// any problem, before any request).
func loadCertMaterial(rt *app.Runtime, certFile, keyFile string) (*platform.CertMaterial, error) {
	if certFile == "" || keyFile == "" {
		return nil, app.UsageErrf("--cert-file and --key-file are required (PEM files; @- reads stdin)")
	}
	c, k, err := readCertFiles(rt, certFile, keyFile)
	if err != nil {
		return nil, err
	}
	return platform.ParseCertMaterial(c, k, instanceClock.Now())
}

func sslTarget(profile, region string) platform.Target {
	return platform.Target{Platform: platform.GCP, Profile: profile, Region: region}
}

// storeSSLCert upserts a certificate into the inventory.
func storeSSLCert(ctx context.Context, rt *app.Runtime, profile string, sc *compute.SslCertificate) {
	db, err := rt.DB()
	if err != nil || sc == nil {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResCertificate}
	if err := db.Upsert(ctx, set, sslCertificateFrom(sc).resource(), cfg.TTLFor(platform.ResCertificate)); err != nil {
		rt.Verbosef("inventory: %v", err)
	}
}

// dropSSLCert removes a certificate from the inventory.
func dropSSLCert(ctx context.Context, rt *app.Runtime, profile, region, name string) {
	if db, err := rt.DB(); err == nil {
		set := inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResCertificate}
		if err := db.Delete(ctx, set, platform.ResCertificate, certInventoryID(region, name)); err != nil {
			rt.Verbosef("inventory: %v", err)
		}
	}
}

// ---------------------------------------------------------------- list

// sslCertView is a row of ssl-certificate list.
type sslCertView struct {
	Name              string   `json:"name" yaml:"name"`
	Scope             string   `json:"scope" yaml:"scope"`
	Region            string   `json:"region" yaml:"region"`
	Type              string   `json:"type" yaml:"type"`
	Domains           []string `json:"domains" yaml:"domains"`
	ExpireTime        string   `json:"expire_time" yaml:"expire_time"`
	DaysRemaining     *int     `json:"days_remaining" yaml:"days_remaining"`
	Description       string   `json:"description" yaml:"description"`
	CreationTimestamp string   `json:"creation_timestamp" yaml:"creation_timestamp"`
	UsedBy            []string `json:"used_by" yaml:"used_by"`
}

func sslCertListCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	var expiring int
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List the SSL certificates of the project with their expiry and the proxies that use them",
		Long: `List the SSL certificates of the project, read live: every region and the
global scope by default, one region with --region, the global scope with
--global. Each certificate shows its type (SELF_MANAGED or MANAGED), its
domains, its expiry in UTC, the whole days left and the target HTTPS proxies
that use it (USED-BY). A self-managed certificate no proxy uses is marked
with * after its name: an orphan, typically the old certificate of a
replacement whose deletion failed, to delete by hand.

--expiring-in <days> keeps the certificates with at most that many days
left. No certificate is exit code 0 with an empty list and a note.`,
		Example: "  polyctl gcp compute ssl-certificate list --expiring-in 30 -o json",
		Args:    cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			region, all, err := sf.resolve(false)
			if err != nil {
				return err
			}
			filter := cmd.Flags().Changed("expiring-in")
			if filter && expiring < 0 {
				return app.UsageErrf("--expiring-in must not be negative, got %d", expiring)
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			var certs []*compute.SslCertificate
			if all {
				var unreachable []string
				if certs, unreachable, err = c.listAllCerts(ctx); err != nil {
					return err
				}
				if len(unreachable) > 0 {
					rt.Infof("warning: unreachable scopes: %s", strings.Join(unreachable, ", "))
				}
			} else if certs, err = (certScope{c: c, region: region}).listCerts(ctx); err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			users, err := c.proxyUsers(ctx)
			if err != nil {
				return err
			}
			now := instanceClock.Now()
			rows := []sslCertView{}
			orphans := 0
			for _, sc := range certs {
				inv := sslCertificateFrom(sc)
				v := sslCertView{Name: inv.Name, Scope: inv.Scope, Region: inv.Region, Type: inv.Type, Domains: inv.Domains,
					ExpireTime: inv.ExpireTime, Description: inv.Description, CreationTimestamp: inv.CreationTimestamp,
					UsedBy: users[resourceKey(sc.SelfLink)]}
				if v.Domains == nil {
					v.Domains = []string{}
				}
				if v.UsedBy == nil {
					v.UsedBy = []string{}
				}
				if f := factsOf(sc); !f.Expire.IsZero() {
					d := daysLeft(f.Expire, now)
					v.DaysRemaining = &d
				}
				if filter && (v.DaysRemaining == nil || *v.DaysRemaining > expiring) {
					continue
				}
				if v.Type == certSelfManaged && len(v.UsedBy) == 0 {
					orphans++
				}
				rows = append(rows, v)
			}
			where := "project " + c.project
			if !all {
				where = (certScope{region: region}).label() + " certificates of " + where
			}
			switch {
			case len(rows) == 0 && filter:
				rt.Infof("note: no certificate expires within %d days in %s (gcp/%s)", expiring, where, profile)
			case len(rows) == 0:
				rt.Infof("note: no SSL certificates in %s (gcp/%s)", where, profile)
			default:
				rt.Infof("%d certificate(s) in %s via gcp/%s", len(rows), where, profile)
				if orphans > 0 {
					rt.Infof("* %d self-managed certificate(s) no target HTTPS proxy uses", orphans)
				}
			}
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"NAME", "SCOPE", "REGION", "TYPE", "DOMAINS", "EXPIRES", "DAYS", "USED-BY"}, Empty: "no SSL certificates"}
				for _, v := range rows {
					name := v.Name
					if v.Type == certSelfManaged && len(v.UsedBy) == 0 {
						name += " *"
					}
					days, expires := "-", "-"
					if v.DaysRemaining != nil {
						days = strconv.Itoa(*v.DaysRemaining)
					}
					if v.ExpireTime != "" {
						expires = v.ExpireTime
					}
					g.Rows = append(g.Rows, []string{name, v.Scope, dash(v.Region), v.Type, strings.Join(v.Domains, ","), expires, days, dash(strings.Join(v.UsedBy, ","))})
				}
				return g
			})
		},
	}
	sf.register(cmd, "certificate (default: every scope)")
	cmd.Flags().IntVar(&expiring, "expiring-in", 0, "only the certificates with at most this many whole days left")
	return cmd
}

func dash(s string) string {
	if s == "" {
		return "-"
	}
	return s
}

// ---------------------------------------------------------------- create

func sslCertCreateCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	var certFile, keyFile, description string
	cmd := &cobra.Command{
		Use:   "create <name>",
		Short: "Upload a self-managed SSL certificate (an existing certificate of that name is an error)",
		Long: `Upload a self-managed SSL certificate: --cert-file is the PEM chain, leaf first
(fullchain.pem), --key-file the unencrypted PEM private key; @- reads stdin
(both @- read one text holding both). --region <r> makes a regional
certificate (for regional load balancers of that region), --global a global
one; one of them is required.

The files are checked before anything is sent, since Compute Engine accepts
a key that does not belong to the certificate and an expired certificate:
unreadable PEM, an encrypted key, a key that does not match the leaf and an
expired leaf are exit code 2. The name must follow the Compute Engine rule (a
lower-case letter first, at most 63 characters; exit code 2). A certificate
of that name in the scope is exit code 1: certificates cannot be changed, use
update to replace one. --description defaults to "SSL certificate for
<domain>".`,
		Example: "  polyctl gcp compute ssl-certificate create web-example-com-cert-20261117 --cert-file fullchain.pem --key-file privkey.pem --region <region>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			if err := checkCertName(name); err != nil {
				return err
			}
			region, _, err := sf.resolve(true)
			if err != nil {
				return err
			}
			mat, err := loadCertMaterial(rt, certFile, keyFile)
			if err != nil {
				return err
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			s := certScope{c: c, region: region}
			existing, err := s.findCert(ctx, name)
			if err != nil {
				return fmt.Errorf("%w (gcp/%s)", err, profile)
			}
			if existing != nil {
				return fmt.Errorf("certificate %s already exists (%s, project %s, gcp/%s): certificates cannot be changed; use `polyctl gcp compute ssl-certificate update %s` to replace it", name, s.label(), c.project, profile, name)
			}
			domain := platform.CertDomain(mat.Names(), mat.Leaf.Subject.CommonName)
			if description == "" {
				description = "SSL certificate for " + domain
			}
			change := platform.Change{Resource: "ssl-certificate/" + name, Action: platform.Created, ID: s.certURL(name),
				Detail: fmt.Sprintf("%s, %s, expires %s", s.label(), strings.Join(mat.Names(), ","), mat.Leaf.NotAfter.UTC().Format("2006-01-02"))}
			if done, err := rt.WouldWrite(sslTarget(profile, region), change); done || err != nil {
				return err
			}
			if err := s.insertCert(ctx, name, description, mat); err != nil {
				return err
			}
			if sc, err := s.getCert(ctx, name); err == nil {
				storeSSLCert(ctx, rt, profile, sc)
			}
			rt.Infof("created certificate %s (%s) in project %s via gcp/%s", name, s.label(), c.project, profile)
			return rt.RenderReport(platform.Report{Target: sslTarget(profile, region), Changes: []platform.Change{change}})
		},
	}
	sf.register(cmd, "certificate")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "PEM chain, leaf first (fullchain.pem); @- reads stdin")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "unencrypted PEM private key; @- reads stdin")
	cmd.Flags().StringVar(&description, "description", "", "description (default: SSL certificate for <domain>)")
	return cmd
}

// ---------------------------------------------------------------- update

func sslCertUpdateCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	var certFile, keyFile string
	var keepOld bool
	cmd := &cobra.Command{
		Use:   "update <name>",
		Short: "Replace a certificate: create a new one, switch every proxy that uses it, delete the old one",
		Long: `Replace the content of a self-managed certificate. Certificates cannot be
changed in place and cannot be deleted while a proxy uses them, so update
creates a new certificate named {slug}-cert-{YYYYMMDD} after the domain of
the new leaf (naming.gcp_ssl_certificate; -2, -3... when that name already
holds another certificate), switches every target HTTPS proxy of the scope
that uses <name> to it (their other certificates are kept), then deletes
<name> unless --keep-old. A certificate that still holds the same leaf
(compared by the SHA-256 of its DER) is unchanged; a certificate of the
candidate name that holds it already (a run whose switch failed) is reused.
An old certificate still used elsewhere is skipped, not a failure.

The files are checked as for create (exit code 2). A missing certificate is
exit code 4; a Google-managed one cannot be replaced (exit code 1).`,
		Example: "  polyctl gcp compute ssl-certificate update web-example-com-cert-20260901 --cert-file new-fullchain.pem --key-file new-privkey.pem --region <region>",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			region, _, err := sf.resolve(true)
			if err != nil {
				return err
			}
			mat, err := loadCertMaterial(rt, certFile, keyFile)
			if err != nil {
				return err
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			s := certScope{c: c, region: region}
			target := sslTarget(profile, region)
			old, err := s.getCert(ctx, name)
			if err != nil {
				return fmt.Errorf("certificate %s (%s, gcp/%s): %w", name, s.label(), profile, err)
			}
			if old.Type == certManaged {
				return fmt.Errorf("certificate %s is Google-managed: Google renews it, and polyctl does not replace it", name)
			}
			oldFacts := factsOf(old)
			if oldFacts.Fingerprint == mat.Fingerprint {
				rep := platform.Report{Target: target, DryRun: rt.DryRun(), Changes: []platform.Change{{Resource: "ssl-certificate/" + name,
					Action: platform.Unchanged, ID: s.certURL(name), Detail: "already holds this certificate"}}}
				return rt.RenderReport(rep)
			}
			users, err := s.usersOf(ctx, name)
			if err != nil {
				return err
			}
			domain := platform.CertDomain(mat.Names(), mat.Leaf.Subject.CommonName)
			if domain == "" {
				domain = oldFacts.Domain
			}
			base, err := certBaseName(cfg, domain, instanceClock.Now())
			if err != nil {
				return err
			}
			rp, err := ReplaceProxyCertificate(ctx, replaceSpec{scope: s, proxies: users, domain: domain, mat: mat, baseName: base,
				description: "SSL certificate for " + domain, keepOld: keepOld, standalone: true, extraOld: []string{name},
				isOld: func(n string, _ certFacts) bool { return n == name }})
			if err != nil {
				return err
			}
			plan := &platform.Plan{Steps: rp.steps}
			rep, err := rt.RunPlan(ctx, target, plan)
			if !rep.DryRun {
				recordCertChanges(ctx, rt, profile, s, rep.Changes)
			}
			if rerr := rt.RenderReport(rep); rerr != nil && err == nil {
				err = rerr
			}
			return err
		},
	}
	sf.register(cmd, "certificate")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "PEM chain, leaf first (fullchain.pem); @- reads stdin")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "unencrypted PEM private key; @- reads stdin")
	cmd.Flags().BoolVar(&keepOld, "keep-old", false, "keep the old certificate after the switch")
	return cmd
}

// recordCertChanges mirrors the certificate rows of a change report into
// the inventory: created ones are read and upserted, deleted ones removed.
func recordCertChanges(ctx context.Context, rt *app.Runtime, profile string, s certScope, changes []platform.Change) {
	for _, ch := range changes {
		name, ok := strings.CutPrefix(ch.Resource, "ssl-certificate/")
		if !ok {
			continue
		}
		switch ch.Action {
		case platform.Created:
			if sc, err := s.getCert(ctx, name); err == nil {
				storeSSLCert(ctx, rt, profile, sc)
			}
		case platform.Deleted:
			dropSSLCert(ctx, rt, profile, s.region, name)
		}
	}
}

// ---------------------------------------------------------------- delete

func sslCertDeleteCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	cmd := &cobra.Command{
		Use:   "delete <name>",
		Short: "Delete an SSL certificate no proxy uses (asks first)",
		Long: `Delete an SSL certificate of --region <r> or --global. A certificate a target
HTTPS proxy still uses cannot be deleted: that is exit code 1, naming the
proxies (switch them to another certificate first, for example with update).
The certificate is shown first, then a confirmation is asked (default no;
--yes skips it, and the non-interactive flow needs --yes). A missing
certificate is exit code 4.`,
		Example: "  polyctl gcp compute ssl-certificate delete web-example-com-cert-20260901 --region <region> --yes",
		Args:    cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			name := args[0]
			region, _, err := sf.resolve(true)
			if err != nil {
				return err
			}
			c, profile, err := openGCP(ctx, rt)
			if err != nil {
				return err
			}
			s := certScope{c: c, region: region}
			sc, err := s.getCert(ctx, name)
			if err != nil {
				return fmt.Errorf("certificate %s (%s, gcp/%s): %w", name, s.label(), profile, err)
			}
			users, err := s.usersOf(ctx, name)
			if err != nil {
				return err
			}
			if len(users) > 0 {
				sort.Strings(users)
				return fmt.Errorf("certificate %s is used by target HTTPS proxy %s: switch the proxy to another certificate first", name, strings.Join(users, ", "))
			}
			f := factsOf(sc)
			expires := "-"
			if !f.Expire.IsZero() {
				expires = f.Expire.Format(time.RFC3339)
			}
			rt.Infof("certificate %s (gcp/%s, project %s)", name, profile, c.project)
			rt.Infof("  scope     %s", s.label())
			rt.Infof("  type      %s", sslCertificateFrom(sc).Type)
			rt.Infof("  domains   %s", strings.Join(f.Domains, ", "))
			rt.Infof("  expires   %s", expires)
			change := platform.Change{Resource: "ssl-certificate/" + name, Action: platform.Deleted, ID: s.certURL(name), Detail: s.label()}
			if done, err := rt.WouldWrite(sslTarget(profile, region), change); done || err != nil {
				return err
			}
			ok, err := rt.Confirm(ctx, fmt.Sprintf("Delete certificate %s (%s, project %s)?", name, s.label(), c.project), false)
			if err != nil {
				return err
			}
			if !ok {
				return fmt.Errorf("%w: cancelled; certificate %s was not deleted", platform.ErrNothingToDo, name)
			}
			if err := s.deleteCert(ctx, name); err != nil {
				if isReason(err, reasonInUse) {
					return fmt.Errorf("certificate %s is used by %s: switch it to another certificate first", name, inUseBy(err))
				}
				return err
			}
			dropSSLCert(ctx, rt, profile, region, name)
			rt.Infof("deleted certificate %s in project %s via gcp/%s", name, c.project, profile)
			return rt.RenderReport(platform.Report{Target: sslTarget(profile, region), Changes: []platform.Change{change}})
		},
	}
	sf.register(cmd, "certificate")
	return cmd
}
