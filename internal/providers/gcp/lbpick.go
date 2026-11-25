package gcp

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive picks of the load balancer commands.

// lbTargetLabel: "lb-web-1  us-central1  HTTP,HTTPS  203.0.113.5:80,
// 203.0.113.5:443  project p1  gcp/lab".
func lbTargetLabel(t *lbTarget) string {
	var protos, fronts []string
	for _, e := range t.entries {
		if p := e.protocol(); !slices.Contains(protos, p) {
			protos = append(protos, p)
		}
		fronts = append(fronts, e.rule.IPAddress+":"+portLabel(e.rule.PortRange))
	}
	sort.Strings(protos)
	sort.Strings(fronts)
	scope := t.region
	if scope == "" {
		scope = "global"
	}
	return prompt.Cells(t.name, scope, strings.Join(protos, ","), strings.Join(fronts, ", "), "project "+t.c.project, "gcp/"+t.profile)
}

// lbTargets lists the load balancers of every selected GCP account, read
// live (one per name and scope), those in the scope of --region /
// --global when given (all false), those keep accepts (nil: all).
func lbTargets(ctx context.Context, rt *app.Runtime, region string, all bool, keep func(*lbTarget) bool) ([]*lbTarget, error) {
	if rt.Flags.Offline {
		return nil, fmt.Errorf("%w: load balancers are read live", app.ErrOffline)
	}
	scopes, err := gcpScopes(rt)
	if err != nil {
		return nil, err
	}
	var out []*lbTarget
	for _, sc := range scopes {
		a := struct{ Profile string }{sc.profile}
		c, err := openScope(ctx, rt, sc)
		if err != nil {
			return nil, err
		}
		x, err := c.loadLBIndex(ctx)
		if err != nil {
			if !c.pinned && isAPIDisabled(err) {
				c.noteOff(c.project, err)
				continue
			}
			return nil, fmt.Errorf("%w (%s)", err, sc)
		}
		if len(x.unreachable) > 0 {
			rt.Infof("warning: %s: unreachable scopes: %s", sc, strings.Join(x.unreachable, ", "))
		}
		byKey := map[string]*lbTarget{}
		var order []string
		for _, e := range x.entries() {
			if !all && e.region != region {
				continue
			}
			k := e.region + "/" + e.name
			t := byKey[k]
			if t == nil {
				t = &lbTarget{name: e.name, profile: a.Profile, c: c, x: x, region: e.region}
				byKey[k] = t
				order = append(order, k)
			}
			t.entries = append(t.entries, e)
		}
		for _, k := range order {
			if t := byKey[k]; keep == nil || keep(t) {
				out = append(out, t)
			}
		}
	}
	flushScopes(scopes)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].profile != out[j].profile {
			return out[i].profile < out[j].profile
		}
		if out[i].c.project != out[j].c.project {
			return out[i].c.project < out[j].c.project
		}
		if out[i].name != out[j].name {
			return out[i].name < out[j].name
		}
		return out[i].region < out[j].region
	})
	return out, nil
}

// pickLBTarget asks, in the interactive flow, for a load balancer of the
// selected accounts (see lbTargets); what names the candidates of an
// empty list ("load balancer"), which is nothing to do.
func pickLBTarget(ctx context.Context, rt *app.Runtime, region string, all bool, what string, keep func(*lbTarget) bool) (*lbTarget, error) {
	if !rt.Interactive() {
		return nil, app.UsageErrf("<name> is required")
	}
	list, err := lbTargets(ctx, rt, region, all, keep)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for i, t := range list {
		opts = append(opts, prompt.Option{Label: lbTargetLabel(t), Value: strconv.Itoa(i)})
	}
	v, err := rt.Choose(app.Choice{Title: "Load balancer", Options: opts, Arg: "<name>", What: what})
	if err != nil {
		return nil, err
	}
	i, _ := strconv.Atoi(v)
	return list[i], nil
}

// httpLB keeps the load balancers cert set can work on: an HTTP(S) URL
// map behind them, and for a global one an HTTPS proxy already (a global
// load balancer is not upgraded from HTTP).
func httpLB(t *lbTarget) bool {
	hasMap, https := false, false
	for _, e := range t.entries {
		hasMap = hasMap || e.urlMap != nil
		https = https || e.proxyKind == kindHTTPSProxy
	}
	return hasMap && (t.region != "" || https)
}

// lbRefOf is the lbRef of a picked load balancer: its account, scope and
// URL map.
func lbRefOf(t *lbTarget, timeout time.Duration) *lbRef {
	ref := &lbRef{profile: t.profile, scope: certScope{c: t.c, region: t.region, timeout: timeout}}
	for _, e := range t.entries {
		if e.urlMap != nil {
			ref.urlMap = e.urlMap.Name
			break
		}
	}
	return ref
}

// pickCertDomain asks the --domain of load-balancer cert set in the
// interactive flow: the domains of the certificates on the load
// balancer's HTTPS proxies and of the unexpired certificates of polyctl's
// store, or "Another domain...", typed.
func pickCertDomain(ctx context.Context, rt *app.Runtime, lb *lbRef) (string, error) {
	var opts []prompt.Option
	seen := map[string]bool{}
	add := func(d, where, expires string) {
		d = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), ".")
		if d != "" && !seen[d] {
			seen[d] = true
			opts = append(opts, prompt.Option{Label: prompt.Cells(d, where, expires), Value: d})
		}
	}
	if proxies, err := lb.scope.listProxies(ctx); err == nil {
		for _, p := range proxies {
			if lastSegment(p.UrlMap) != lb.urlMap {
				continue
			}
			for _, u := range p.SslCertificates {
				if sc, err := lb.scope.getCert(ctx, lastSegment(u)); err == nil {
					for _, d := range factsOf(sc).Domains {
						add(d, "on proxy "+p.Name, "")
					}
				}
			}
		}
	}
	if st, err := cert.OpenRuntimeStore(rt, false); err == nil {
		roots, _ := st.List()
		now := instanceClock.Now()
		for _, root := range roots {
			if b, err := st.Load(root, false); err == nil && b != nil && now.Before(b.NotAfter) {
				add(root, "certificate store", "expires "+b.NotAfter.UTC().Format("2006-01-02"))
			}
		}
	}
	return rt.Choose(app.Choice{Title: "Domain of the certificate", Options: opts, Arg: "--domain",
		Missing:     func() error { return app.UsageErrf("--domain is required (example.com or *.example.com)") },
		CreateLabel: "Another domain...",
		Create: func() (string, error) {
			return rt.AskInput("--domain", "Domain (example.com or *.example.com)", "", func(s string) error {
				d := platform.NormalizeDomain(strings.TrimPrefix(strings.TrimSpace(s), "*."))
				if !strings.Contains(d, ".") || strings.ContainsAny(d, " /:@") {
					return fmt.Errorf("%q is not a domain name", s)
				}
				return nil
			})
		}})
}

// lbTargetArg finds the load balancer of get and delete: <name> through
// resolveLBTarget, or, without it in the interactive flow, a pick of the
// load balancers of the selected accounts (none is nothing to do).
func lbTargetArg(ctx context.Context, rt *app.Runtime, args []string, region string, all bool) (*lbTarget, error) {
	if len(args) > 0 {
		return resolveLBTarget(ctx, rt, args[0], region, all)
	}
	return pickLBTarget(ctx, rt, region, all, "load balancer in the selected GCP accounts", nil)
}

// pickLBCert asks, in the interactive flow, the --ssl-certificate of
// load-balancer ensure --protocol https: the unexpired certificates of the
// load balancer's region (domains, expiry), or "Create a new
// certificate...": its certificate (polyctl's store or files) and name
// (naming.gcp_ssl_certificate proposed), created as the first step of the
// plan. No certificate and nothing created is a usage error naming
// --ssl-certificate.
func pickLBCert(ctx context.Context, rt *app.Runtime, e *lbEnsure) error {
	s := e.scope
	certs, err := s.listCerts(ctx)
	if err != nil {
		return err
	}
	now := instanceClock.Now()
	var opts []prompt.Option
	for _, sc := range certs {
		f := factsOf(sc)
		if !f.Expire.IsZero() && !now.Before(f.Expire) {
			continue
		}
		opts = append(opts, prompt.Option{Label: certOptionLabel(sc, nil), Value: sc.Name})
	}
	v, err := rt.Choose(app.Choice{Title: "SSL certificate of the HTTPS proxy (" + s.label() + ")", Options: opts, Arg: "--ssl-certificate",
		CreateLabel: "Create a new certificate...",
		Create: func() (string, error) {
			var certFile, keyFile string
			if err := askCertFiles(rt, &certFile, &keyFile, ""); err != nil {
				return "", err
			}
			mat, err := loadCertMaterial(rt, certFile, keyFile)
			if err != nil {
				return "", err
			}
			domain := platform.CertDomain(mat.Names(), mat.Leaf.Subject.CommonName)
			name, err := askCertName(ctx, rt, s, domain)
			if err != nil {
				return "", err
			}
			e.newCert, e.newCertDesc = mat, "SSL certificate for "+domain
			return name, nil
		}})
	if err != nil {
		return err
	}
	e.sslCert = v
	return nil
}
