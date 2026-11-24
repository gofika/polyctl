package gcp

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive questions of the ssl-certificate commands (and of the
// load balancer commands that take a certificate).

// globalScope is the value of the "Global" option of a scope pick.
const globalScope = "\x00global"

// askCertFiles fills in, in the interactive flow, the --cert-file and
// --key-file that a command misses: the unexpired certificates of
// polyctl's local store (domain, names, expiry; the one covering prefer
// preselected), or "Other files...", two paths checked as they are typed
// (the key against the certificate, an expired leaf refused). Without
// store entries the paths are asked at once.
func askCertFiles(rt *app.Runtime, certFile, keyFile *string, prefer string) error {
	if !rt.Interactive() || (*certFile != "" && *keyFile != "") {
		return nil
	}
	if *certFile == "" && *keyFile == "" {
		if st, err := cert.OpenRuntimeStore(rt, false); err == nil {
			roots, _ := st.List()
			now := instanceClock.Now()
			var opts []prompt.Option
			def := ""
			for _, root := range roots {
				b, err := st.Load(root, false)
				if err != nil || b == nil || !now.Before(b.NotAfter) {
					continue
				}
				opts = append(opts, prompt.Option{Label: joinLabel(root, strings.Join(b.Names, ","),
					fmt.Sprintf("expires %s (%d days)", b.NotAfter.UTC().Format("2006-01-02"), b.DaysLeft(now))), Value: root})
				if prefer != "" && def == "" && b.Covers(prefer) {
					def = root
				}
			}
			if len(opts) > 0 {
				opts = append(opts, prompt.Option{Label: "Other files...", Value: otherValue})
				v, err := rt.Pick().Select("Certificate (from polyctl's certificate store)", opts, def)
				if err != nil {
					return err
				}
				if v != otherValue {
					*certFile = filepath.Join(st.LivePath(v), "fullchain.pem")
					*keyFile = filepath.Join(st.LivePath(v), "privkey.pem")
					return nil
				}
			}
		}
	}
	readPath := func(v string) ([]byte, error) {
		switch v = strings.TrimSpace(v); v {
		case "":
			return nil, errors.New("a file path is required")
		case "@-", "-":
			return nil, errors.New("standard input is the terminal: give a file path")
		}
		return os.ReadFile(platform.ExpandHome(v))
	}
	if *certFile == "" {
		v, err := rt.AskInput("--cert-file", "Certificate chain file (PEM, leaf first: fullchain.pem)", "", func(v string) error {
			b, err := readPath(v)
			if err != nil {
				return err
			}
			if !strings.Contains(string(b), "-----BEGIN CERTIFICATE-----") {
				return errors.New("no PEM certificate in the file")
			}
			return nil
		})
		if err != nil {
			return err
		}
		*certFile = platform.ExpandHome(v)
	}
	var chain []byte
	if *certFile != "@-" {
		chain, _ = os.ReadFile(*certFile)
	}
	if *keyFile == "" {
		v, err := rt.AskInput("--key-file", "Private key file (unencrypted PEM: privkey.pem)", "", func(v string) error {
			b, err := readPath(v)
			if err != nil || chain == nil {
				return err
			}
			_, err = platform.ParseCertMaterial(chain, b, instanceClock.Now())
			if err != nil {
				return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
			}
			return nil
		})
		if err != nil {
			return err
		}
		*keyFile = platform.ExpandHome(v)
	}
	return nil
}

// pickCertScope asks, in the interactive flow, whether a new certificate
// is global or regional, and the region: "Global" and the regions that are
// UP and not deprecated, the region of defaults.gcp.zone preselected when
// it is configured.
func pickCertScope(ctx context.Context, rt *app.Runtime, c *client, profile string) (string, error) {
	regions, err := c.listRegionsUp(ctx)
	if err != nil {
		return "", err
	}
	opts := []prompt.Option{{Label: "Global  (global external load balancers)", Value: globalScope}}
	for _, r := range regions {
		opts = append(opts, prompt.Option{Label: joinLabel(r.Name, "(regional load balancers of "+r.Name+")"), Value: r.Name})
	}
	def := ""
	if z, _ := rt.Setting(profile, platform.GCP, "zone", ""); z != "" {
		def = regionOf(z)
	}
	v, err := rt.Choose(app.Choice{Title: "Scope of the certificate", Options: opts, Default: def, Arg: "--region or --global",
		Missing: func() error {
			return app.UsageErrf("pass --region <region> for a regional certificate or --global for a global one")
		}})
	if v == globalScope {
		return "", err
	}
	return v, err
}

// certOptionLabel: "web-cert  us-central1  SELF_MANAGED  example.com
// expires 2027-01-01 (40 days)  used by web-https-proxy".
func certOptionLabel(sc *compute.SslCertificate, users []string) string {
	v := sslCertificateFrom(sc)
	scope := v.Region
	if scope == "" {
		scope = "global"
	}
	exp := ""
	if f := factsOf(sc); !f.Expire.IsZero() {
		exp = fmt.Sprintf("expires %s (%d days)", f.Expire.Format("2006-01-02"), daysLeft(f.Expire, instanceClock.Now()))
	}
	used := ""
	if len(users) > 0 {
		used = "used by " + strings.Join(users, ",")
	}
	return joinLabel(v.Name, scope, v.Type, strings.Join(v.Domains, ","), exp, used)
}

// certTarget is a certificate picked or found among every scope.
type certTarget struct {
	name, region string
}

// pickCert finds the certificate a command acts on when <name> or the
// scope is missing, in the interactive flow: every certificate of the
// project (global and every region) that keep accepts, or every one named
// name (the command checks it then); one match of a name is used, several
// are a pick (none is nothing to do, or a not-found error for a name
// given). note names what keep left out, printed when it left something
// out.
func pickCert(ctx context.Context, rt *app.Runtime, c *client, profile, name string, keep func(sc *compute.SslCertificate, users []string) bool, note string) (certTarget, error) {
	all, unreachable, err := c.listAllCerts(ctx)
	if err != nil {
		return certTarget{}, err
	}
	if len(unreachable) > 0 {
		rt.Infof("warning: unreachable scopes: %s", strings.Join(unreachable, ", "))
	}
	users, err := c.proxyUsers(ctx)
	if err != nil {
		return certTarget{}, err
	}
	var found []*compute.SslCertificate
	left := 0
	for _, sc := range all {
		if name != "" && sc.Name != name {
			continue
		}
		if name == "" && keep != nil && !keep(sc, users[resourceKey(sc.SelfLink)]) {
			left++
			continue
		}
		found = append(found, sc)
	}
	if left > 0 && note != "" {
		rt.Infof("note: %d certificate(s) left out: %s", left, note)
	}
	if name != "" && len(found) == 0 {
		return certTarget{}, fmt.Errorf("%w: certificate %s in any scope of project %s (gcp/%s)", platform.ErrNotFound, name, c.project, profile)
	}
	if name != "" && len(found) == 1 {
		return certTarget{name: found[0].Name, region: lastSegment(found[0].Region)}, nil
	}
	var opts []prompt.Option
	for i, sc := range found {
		opts = append(opts, prompt.Option{Label: certOptionLabel(sc, users[resourceKey(sc.SelfLink)]), Value: fmt.Sprint(i)})
	}
	v, err := rt.Choose(app.Choice{Title: "SSL certificate", Options: opts, Arg: "<name>", What: "usable certificate in gcp/" + profile})
	if err != nil {
		return certTarget{}, err
	}
	var i int
	fmt.Sscan(v, &i)
	return certTarget{name: found[i].Name, region: lastSegment(found[i].Region)}, nil
}

// askCertName asks the name of a new certificate in the interactive flow,
// the templated name (naming.gcp_ssl_certificate) of domain proposed,
// checked as it is typed against the name rule and the certificates of
// scope s.
func askCertName(ctx context.Context, rt *app.Runtime, s certScope, domain string) (string, error) {
	def := ""
	if cfg, err := rt.Config(); err == nil && domain != "" {
		def, _ = certBaseName(cfg, domain, instanceClock.Now())
	}
	return rt.AskInput("<name>", "Name of the new certificate ("+s.label()+")", def, func(v string) error {
		v = strings.TrimSpace(v)
		if err := checkCertName(v); err != nil {
			return err
		}
		sc, err := s.findCert(ctx, v)
		if err != nil {
			return err
		}
		if sc != nil {
			return fmt.Errorf("certificate %s already exists (%s): use update to replace it", v, s.label())
		}
		return nil
	})
}
