package gcp

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// A load balancer has no certificate of its own: certificates hang on its
// target HTTPS proxies. `load-balancer cert set` therefore finds the URL
// map of the load balancer, the HTTPS proxies that use it, and replaces
// the certificate of the domain on them; a regional load balancer with an
// HTTP proxy only is upgraded with an HTTPS proxy and a :443 forwarding
// rule on the IP of its :80 rule.

// ensureCert gets the certificate of domain from the local store,
// issuing or renewing it when it has days days left or fewer (never in a
// dry run). Tests replace it.
var ensureCert = func(ctx context.Context, rt *app.Runtime, domain string, days int) (*cert.Result, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	s := cfg.CertSettings()
	env, err := cert.NewEnv(rt, false)
	if err != nil {
		return nil, err
	}
	return cert.Ensure(ctx, env, cert.EnsureOptions{Domain: domain, Days: days, KeyType: s.KeyType, Email: s.Email, AgreeTOS: s.AgreeTOS,
		ReuseKey: s.ReuseKey, DryRun: rt.DryRun(), Offline: rt.Flags.Offline})
}

// lbRef is a resolved load balancer: the account, the scope and the URL
// map.
type lbRef struct {
	profile string
	scope   certScope
	urlMap  string
}

// urlMapOfTarget returns the URL map of the target proxy of a forwarding
// rule (an HTTPS or an HTTP proxy).
func (s certScope) urlMapOfTarget(ctx context.Context, target string) (string, error) {
	if p, err := s.getProxy(ctx, target); err == nil {
		return lastSegment(p.UrlMap), nil
	} else if !errors.Is(err, platform.ErrNotFound) {
		return "", err
	}
	p, err := s.getHTTPProxy(ctx, target)
	if errors.Is(err, platform.ErrNotFound) {
		return "", fmt.Errorf("the forwarding rule targets %s, which is not a target HTTP or HTTPS proxy (%s): only Application Load Balancers take certificates this way", target, s.label())
	}
	if err != nil {
		return "", err
	}
	return lastSegment(p.UrlMap), nil
}

func (s certScope) getHTTPProxy(ctx context.Context, name string) (*compute.TargetHttpProxy, error) {
	var p *compute.TargetHttpProxy
	var err error
	if s.global() {
		p, err = s.c.compute.TargetHttpProxies.Get(s.c.project, name).Context(ctx).Do()
	} else {
		p, err = s.c.compute.RegionTargetHttpProxies.Get(s.c.project, s.region, name).Context(ctx).Do()
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return p, nil
}

func (s certScope) listHTTPProxies(ctx context.Context) ([]*compute.TargetHttpProxy, error) {
	var out []*compute.TargetHttpProxy
	var err error
	if s.global() {
		err = s.c.compute.TargetHttpProxies.List(s.c.project).Pages(ctx, func(l *compute.TargetHttpProxyList) error {
			out = append(out, l.Items...)
			return nil
		})
	} else {
		err = s.c.compute.RegionTargetHttpProxies.List(s.c.project, s.region).Pages(ctx, func(l *compute.TargetHttpProxyList) error {
			out = append(out, l.Items...)
			return nil
		})
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

func (s certScope) listRules(ctx context.Context) ([]*compute.ForwardingRule, error) {
	var out []*compute.ForwardingRule
	var err error
	if s.global() {
		err = s.c.compute.GlobalForwardingRules.List(s.c.project).Pages(ctx, func(l *compute.ForwardingRuleList) error {
			out = append(out, l.Items...)
			return nil
		})
	} else {
		err = s.c.compute.ForwardingRules.List(s.c.project, s.region).Pages(ctx, func(l *compute.ForwardingRuleList) error {
			out = append(out, l.Items...)
			return nil
		})
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// urlMapScopes lists the scopes ("" for global) holding a URL map of name.
func (c *client) urlMapScopes(ctx context.Context, name string) ([]string, error) {
	var out []string
	unreachable, err := aggregatedPages(ctx, c.compute.UrlMaps.AggregatedList(c.project), func(l *compute.UrlMapsAggregatedList) (string, []string) {
		u := l.Unreachables
		for scope, scoped := range l.Items {
			if scoped.Warning != nil {
				u = append(u, warnedUnreachable(scope, scoped.Warning.Code)...)
			}
			for _, m := range scoped.UrlMaps {
				if m.Name == name {
					out = append(out, lastSegment(m.Region))
				}
			}
		}
		return l.NextPageToken, u
	})
	if err != nil {
		return nil, computeErr(err)
	}
	if err := unreachableListErr("URL maps", unreachable); err != nil {
		return nil, err
	}
	sort.Strings(out)
	return out, nil
}

// resolveLB finds the load balancer ref: a forwarding rule of the
// inventory (synced once when it is unknown), else a URL map of that name
// in the selected GCP accounts (the load balancer name of an Application
// Load Balancer). region "" with all false is the global scope; all true
// accepts any scope.
func resolveLB(ctx context.Context, rt *app.Runtime, ref, region string, all bool, timeout time.Duration) (*lbRef, error) {
	fits := func(r string) bool { return all || r == region }
	if rt.Flags.Profile != "" {
		// A --profile without a GCP account is exit code 7, an unknown
		// one exit code 4, before anything is searched.
		if _, err := gcpProfile(rt); err != nil {
			return nil, err
		}
	}
	rules, err := cachedRuleHits(ctx, rt, ref)
	if err != nil {
		return nil, err
	}
	var inScope []ruleHit
	for _, h := range rules {
		if fits(h.rule.Region) {
			inScope = append(inScope, h)
		}
	}
	if len(inScope) > 1 {
		cands := make([]cand, 0, len(inScope))
		for _, h := range inScope {
			cands = append(cands, cand{profile: h.profile, project: h.rule.Project, where: (certScope{region: h.rule.Region}).label(), id: h.rule.ID})
		}
		h, err := disambiguate(rt, ambiguous("load balancer", ref, cands, regionFlags, ""), inScope, func(h ruleHit) string {
			return prompt.Cells(h.rule.Name, (certScope{region: h.rule.Region}).label(), h.rule.IPAddress, "project "+h.rule.Project, "gcp/"+h.profile)
		})
		if err != nil {
			return nil, err
		}
		inScope = []ruleHit{h}
	}
	if len(inScope) == 1 {
		h := inScope[0]
		c, err := openScope(ctx, rt, scope{profile: h.profile, project: h.rule.Project})
		if err != nil {
			return nil, err
		}
		s := certScope{c: c, region: h.rule.Region, timeout: timeout}
		m, err := s.urlMapOfTarget(ctx, h.rule.Target)
		if err != nil {
			return nil, fmt.Errorf("forwarding rule %s (%s, project %s, gcp/%s): %w", h.rule.Name, s.label(), c.project, h.profile, err)
		}
		return &lbRef{profile: h.profile, scope: s, urlMap: m}, nil
	}
	accounts, err := gcpAccounts(rt)
	if err != nil {
		return nil, err
	}
	scopes, err := scopesOf(ctx, rt, accounts)
	if err != nil {
		return nil, err
	}
	type hit struct {
		profile string
		c       *client
		region  string
	}
	var hits []hit
	var firstErr error
	var searched []string
	for _, sc := range scopes {
		a := struct{ Profile string }{sc.profile}
		searched = append(searched, sc.String())
		c, err := openScope(ctx, rt, sc)
		if err == nil {
			var scopes []string
			if scopes, err = c.urlMapScopes(ctx, ref); err == nil {
				for _, r := range scopes {
					if fits(r) {
						hits = append(hits, hit{profile: a.Profile, c: c, region: r})
					}
				}
				continue
			}
		}
		if c != nil && !c.pinned && isAPIDisabled(err) {
			c.noteOff(c.project, err)
			continue
		}
		rt.Infof("warning: %s: %v", sc, err)
		if firstErr == nil {
			firstErr = fmt.Errorf("%s: %w", sc, err)
		}
	}
	flushScopes(scopes)
	switch len(hits) {
	case 0:
		if firstErr != nil {
			return nil, fmt.Errorf("cannot tell where load balancer %q is: %w", ref, firstErr)
		}
		where := "any scope"
		if !all {
			where = (certScope{region: region}).label() + " scope"
		}
		return nil, fmt.Errorf("%w: load balancer %q: no forwarding rule or URL map of that name in %s of %s", platform.ErrNotFound, ref, where, strings.Join(searched, ", "))
	case 1:
		h := hits[0]
		return &lbRef{profile: h.profile, scope: certScope{c: h.c, region: h.region, timeout: timeout}, urlMap: ref}, nil
	}
	cands := make([]cand, 0, len(hits))
	for _, h := range hits {
		cands = append(cands, cand{profile: h.profile, project: h.c.project, where: (certScope{region: h.region}).label()})
	}
	h, err := disambiguate(rt, ambiguous("load balancer", ref, cands, regionFlags, ""), hits, func(h hit) string {
		return prompt.Cells(ref, (certScope{region: h.region}).label(), "project "+h.c.project, "gcp/"+h.profile)
	})
	if err != nil {
		return nil, err
	}
	return &lbRef{profile: h.profile, scope: certScope{c: h.c, region: h.region, timeout: timeout}, urlMap: ref}, nil
}

// ruleHit is a cached forwarding rule that a load balancer reference
// names. rule.Project is always set.
type ruleHit struct {
	profile string
	rule    ForwardingRule
}

// cachedRuleHits returns the forwarding rules of the inventory named ref
// (by name or id) in the selected accounts, in the project of --project
// when it is given. The forwarding rules are synced once when none is
// known (lbScopes).
func cachedRuleHits(ctx context.Context, rt *app.Runtime, ref string) ([]ruleHit, error) {
	scopes, err := lbScopes(ctx, rt, ref)
	if err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	var hits []ruleHit
	seen := map[string]bool{}
	for _, sc := range scopes {
		if seen[sc.profile] {
			continue
		}
		seen[sc.profile] = true
		rows, err := db.List(ctx, inventory.Query{Platform: platform.GCP, Profile: sc.profile, Type: platform.ResLoadBalancer})
		if err != nil {
			return nil, err
		}
		def := defaultProject(rt, sc.profile)
		for _, r := range rows {
			var fr ForwardingRule
			if (r.Name != ref && r.ID != ref) || r.Decode(&fr) != nil {
				continue
			}
			if fr.Project == "" {
				fr.Project = def
			}
			if keepProject(rt, sc.profile, fr.Project) {
				hits = append(hits, ruleHit{profile: sc.profile, rule: fr})
			}
		}
	}
	return hits, nil
}

// prefixedName derives the name of a sibling resource: prefix<insert>rest
// when name starts with prefix (proxy-web-1 -> proxy-https-web-1), else
// name-<insert> (web-proxy -> web-proxy-https).
func prefixedName(name, prefix, insert string) string {
	if prefix != "" && strings.HasPrefix(name, prefix) {
		return fitName(prefix + insert + "-" + strings.TrimPrefix(name, prefix))
	}
	return fitName(name + "-" + insert)
}

// lbCertOptions are the inputs of cert set.
type lbCertOptions struct {
	domain  string
	lbName  string
	keepOld bool
	newIP   bool
	wait    bool
}

func lbCertSetCmd(rt *app.Runtime) *cobra.Command {
	var sf scopeFlags
	var o lbCertOptions
	var certFile, keyFile string
	var days int
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "set <lb>",
		Short: "Put the certificate of a domain on the HTTPS proxies of a load balancer, renewing it first when needed",
		Long: `Put the certificate of --domain on the target HTTPS proxies of a load balancer.
<lb> is a forwarding rule name or the load balancer name (its URL map); the
inventory and the URL maps of the selected GCP accounts tell which project and
scope hold it (several are a pick on a terminal and exit code 5 otherwise:
pass --profile, --project, --region or --global; none is exit code 4).

The certificate is --cert-file and --key-file (checked as for ssl-certificate
create, and it must cover --domain; exit code 2 otherwise), or by default the
certificate of the local store (polyctl cert ensure), issued or renewed first
when it has --days days left or fewer (default cert.renew_days, 30). A domain
whose DNS account polyctl does not hold cannot be issued: exit code 1, pass
the files instead.

Every HTTPS proxy that uses the URL map is switched as in ssl-certificate
update: a new certificate {slug}-cert-{YYYYMMDD} (naming.gcp_ssl_certificate,
-2, -3... when needed) is created in the scope of the load balancer, the
certificates of the domain on the proxy are replaced by it (other domains
stay), and the replaced ones are deleted unless --keep-old (one still used
elsewhere is skipped). A proxy that already holds the same leaf is unchanged.

A regional load balancer with only an HTTP proxy is upgraded: an HTTPS proxy
(the HTTP proxy name with gcp_proxy_prefix followed by https-, proxy-web-1 ->
proxy-https-web-1) on the same URL map, and a :443 forwarding rule (fr-web-1
-> fr-https-web-1) on the IP of the :80 rule, whose ephemeral IP is reserved
as the static address <lb>-ip first, so that both ports keep one IP (for
an internal load balancer an internal SHARED_LOADBALANCER_VIP address in the
:80 rule's subnetwork; an internal address of another purpose already
holding the IP is exit code 1 before anything is written); --new-ip gives the :443 rule a new ephemeral IP instead (DNS then has to
change). The :80 rule's labels are copied. A global load balancer without an
HTTPS proxy is exit code 1. A regional load balancer whose HTTPS proxy has no
:443 rule gets one the same way.

The certificate and proxy operations are always waited for; --no-wait
returns once a new :443 forwarding rule was requested (--timeout bounds each
wait, 10m). --dry-run checks the store without issuing anything and reads
everything, reporting what would be done.

On a terminal, without <lb> the HTTP(S) load balancers of the selected
accounts are offered (a global one only with an HTTPS proxy), and without
--domain the domains of the certificates on its HTTPS proxies and of the
local store, or another domain, typed.`,
		Example: `  polyctl gcp compute load-balancer cert set lb-web-1 --domain example.com --dry-run
  polyctl gcp compute load-balancer cert set lb-web-1 --domain www.example.com --cert-file fullchain.pem --key-file privkey.pem`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			o.lbName = app.Arg(args, 0)
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			o.wait = wait
			o.domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o.domain)), ".")
			if o.domain == "" && !rt.Interactive() {
				return app.UsageErrf("--domain is required (example.com or *.example.com)")
			}
			if (certFile == "") != (keyFile == "") {
				return app.UsageErrf("--cert-file and --key-file go together")
			}
			if days < 0 {
				return app.UsageErrf("--days must not be negative, got %d", days)
			}
			region, all, err := sf.resolve(false)
			if err != nil {
				return err
			}
			var mat *platform.CertMaterial
			if certFile != "" {
				if mat, err = loadCertMaterial(rt, certFile, keyFile); err != nil {
					return err
				}
				if o.domain == "" {
					// The interactive flow: the domain of the files.
					o.domain = platform.CertDomain(mat.Names(), mat.Leaf.Subject.CommonName)
				}
				if !mat.Covers(o.domain) {
					return app.UsageErrf("the certificate of --cert-file does not cover %s (it names %s)", o.domain, strings.Join(mat.Names(), ", "))
				}
			}
			if rt.Flags.Offline {
				return fmt.Errorf("%w: load-balancer cert set reads and writes the load balancer live", app.ErrOffline)
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			if !cmd.Flags().Changed("days") {
				days = cfg.CertSettings().RenewDays
			}
			var lb *lbRef
			if o.lbName == "" {
				t, err := pickLBTarget(ctx, rt, region, all, "HTTP(S) load balancer in the selected GCP accounts", httpLB)
				if err != nil {
					return err
				}
				o.lbName, lb = t.name, lbRefOf(t, timeout)
			} else if lb, err = resolveLB(ctx, rt, o.lbName, region, all, timeout); err != nil {
				return err
			}
			if o.domain == "" {
				if o.domain, err = pickCertDomain(ctx, rt, lb); err != nil {
					return err
				}
				o.domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(o.domain)), ".")
			}
			var pre []platform.Change
			if mat == nil {
				if mat, pre, err = storeMaterial(ctx, rt, o.domain, days); err != nil {
					return err
				}
			}
			s := lb.scope
			target := platform.Target{Platform: platform.GCP, Profile: lb.profile, Project: s.c.project, Region: s.region, Domain: o.domain}
			steps, err := planCertSet(ctx, rt, lb, o, mat)
			if err != nil {
				return err
			}
			rep, err := rt.RunPlan(ctx, target, &platform.Plan{Steps: steps})
			rep.Changes = append(pre, rep.Changes...)
			if !rep.DryRun {
				recordCertChanges(ctx, rt, lb.profile, s, rep.Changes)
			}
			if rerr := rt.RenderReport(rep); rerr != nil && err == nil {
				err = rerr
			}
			return err
		},
	}
	cmd.Flags().StringVar(&o.domain, "domain", "", "domain of the certificate (example.com, *.example.com); required")
	cmd.Flags().StringVar(&certFile, "cert-file", "", "PEM chain, leaf first, instead of the local store; @- reads stdin")
	cmd.Flags().StringVar(&keyFile, "key-file", "", "unencrypted PEM private key (with --cert-file); @- reads stdin")
	cmd.Flags().IntVar(&days, "days", 30, "renew the certificate of the local store when it has this many whole days left or fewer (default: cert.renew_days)")
	cmd.Flags().BoolVar(&o.newIP, "new-ip", false, "give a new :443 forwarding rule a new ephemeral IP instead of the IP of the :80 rule")
	cmd.Flags().BoolVar(&o.keepOld, "keep-old", false, "keep the replaced certificates")
	sf.register(cmd, "load balancer (to choose among load balancers of one name)")
	app.AddWaitFlags(cmd, &wf, true, app.DefaultWaitTimeout)
	return cmd
}

// storeMaterial gets the certificate of domain from the local store
// through ensureCert. In a dry run that would issue it, the material is
// nil and the change says so.
func storeMaterial(ctx context.Context, rt *app.Runtime, domain string, days int) (*platform.CertMaterial, []platform.Change, error) {
	res, err := ensureCert(ctx, rt, domain, days)
	if err != nil {
		switch {
		case errors.Is(err, app.ErrUsage), errors.Is(err, platform.ErrInvalidInput), errors.Is(err, platform.ErrNothingToDo),
			errors.Is(err, platform.ErrUnauthorized), errors.Is(err, platform.ErrForbidden), errors.Is(err, app.ErrOffline):
			return nil, nil, err
		}
		// No DNS account for the domain, rate limits, ...: the store
		// cannot provide it, which is not a missing load balancer.
		return nil, nil, fmt.Errorf("the certificate of %s cannot be issued: %v; if no configured DNS account holds the domain, pass --cert-file and --key-file", domain, err)
	}
	var pre []platform.Change
	for _, ch := range res.Changes {
		if strings.HasPrefix(ch.Resource, "cert/") && (ch.Action == platform.WouldCreate || ch.Action == platform.WouldUpdate) {
			ch.Detail += " (not issued in dry-run)"
		}
		pre = append(pre, ch)
	}
	b := res.Bundle
	if b == nil {
		return nil, pre, nil
	}
	if !b.Covers(domain) {
		return nil, nil, fmt.Errorf("%w: the certificate of the store covers %s, not %s: pass --cert-file and --key-file", platform.ErrInvalidInput, strings.Join(b.Names, ", "), domain)
	}
	mat, err := platform.ParseCertMaterial(b.FullchainPEM, b.PrivKeyPEM, instanceClock.Now())
	if err != nil {
		return nil, nil, fmt.Errorf("the certificate of %s in the store cannot be used: %v", domain, err)
	}
	return mat, pre, nil
}

// planCertSet observes the load balancer and returns the steps of cert
// set.
func planCertSet(ctx context.Context, rt *app.Runtime, lb *lbRef, o lbCertOptions, mat *platform.CertMaterial) ([]platform.Step, error) {
	s := lb.scope
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	base, err := certBaseName(cfg, o.domain, instanceClock.Now())
	if err != nil {
		return nil, err
	}
	proxies, err := s.listProxies(ctx)
	if err != nil {
		return nil, err
	}
	var names []string
	for _, p := range proxies {
		if lastSegment(p.UrlMap) == lb.urlMap {
			names = append(names, p.Name)
		}
	}
	sort.Strings(names)
	description := "SSL certificate for " + o.domain
	if len(names) > 0 {
		newDomain := ""
		if mat != nil {
			newDomain = platform.CertDomain(mat.Names(), mat.Leaf.Subject.CommonName)
		}
		want := normDomain(o.domain)
		// A certificate of the domain is replaced only when the new one
		// covers every name it holds (a narrower --cert-file would take
		// the other names off the proxy); otherwise it stays beside the
		// new one (SNI).
		var kept []string
		keptWhy := map[string]string{}
		isOld := func(n string, f certFacts) bool {
			if f.Domain == "" || (f.Domain != want && f.Domain != newDomain) {
				return false
			}
			if mat != nil {
				if missing := uncoveredNames(mat.Names(), f.Domains); len(missing) > 0 {
					if _, ok := keptWhy[n]; !ok {
						kept = append(kept, n)
						keptWhy[n] = strings.Join(missing, ", ")
					}
					return false
				}
			}
			return true
		}
		rp, err := ReplaceProxyCertificate(ctx, replaceSpec{scope: s, proxies: names, domain: o.domain, mat: mat, baseName: base,
			description: description, keepOld: o.keepOld, isOld: isOld})
		if err != nil {
			return nil, err
		}
		steps := rp.steps
		for _, n := range kept {
			steps = append(steps, platform.Step{Resource: "ssl-certificate/" + n, Action: platform.Skipped,
				Desc:  "kept on the proxy beside the new certificate: the new certificate does not cover " + keptWhy[n],
				Attrs: map[string]string{"scope": s.kind(), "old": n}})
		}
		if !s.global() {
			// The :443 rule is checked for the first proxy only: two
			// HTTPS proxies on one URL map would derive the same rule.
			more, err := ensureHTTPSRule(ctx, rt, s, lb, names[0], o, false)
			if err != nil {
				return nil, err
			}
			steps = append(steps, more...)
		} else if err := noteGlobalRule(ctx, rt, s, names); err != nil {
			return nil, err
		}
		return append(steps, rp.cleanup...), nil
	}
	if s.global() {
		return nil, fmt.Errorf("global load balancer %s (URL map %s, gcp/%s) has no target HTTPS proxy: polyctl upgrades regional load balancers only; create the HTTPS proxy and its :443 forwarding rule first", o.lbName, lb.urlMap, lb.profile)
	}
	// Upgrade: HTTP proxy -> HTTPS proxy + :443 rule.
	httpProxy, err := httpProxyOf(ctx, s, lb.urlMap)
	if err != nil {
		return nil, err
	}
	if httpProxy == nil {
		return nil, fmt.Errorf("%w: load balancer %s (URL map %s, %s, gcp/%s) has neither a target HTTPS nor an HTTP proxy", platform.ErrNotFound, o.lbName, lb.urlMap, s.label(), lb.profile)
	}
	httpsName := prefixedName(httpProxy.Name, cfg.NamingTemplate("gcp_proxy_prefix"), "https")
	if existing, err := s.getProxy(ctx, httpsName); err == nil {
		return nil, fmt.Errorf("target HTTPS proxy %s exists but uses URL map %s, not %s: delete or rename it first", httpsName, lastSegment(existing.UrlMap), lb.urlMap)
	} else if !errors.Is(err, platform.ErrNotFound) {
		return nil, err
	}
	certName, reuse, err := s.newCertName(ctx, base, mat)
	if err != nil {
		return nil, err
	}
	attrs := map[string]string{"scope": s.kind(), "region": s.region}
	var steps []platform.Step
	certRes := "ssl-certificate/" + certName
	if reuse {
		steps = append(steps, platform.Step{Resource: certRes, Action: platform.Unchanged, Desc: "existing, holds the same certificate (" + s.label() + ")", Attrs: attrs})
	} else {
		expires := ""
		if mat != nil {
			expires = ", expires " + mat.Leaf.NotAfter.UTC().Format("2006-01-02")
		}
		steps = append(steps, platform.Step{Resource: certRes, Action: platform.Created, ID: s.certURL(certName), Desc: s.label() + expires, Attrs: attrs,
			Apply: func(ctx context.Context) (platform.Change, error) {
				if mat == nil {
					return platform.Change{}, errors.New("no certificate material")
				}
				return platform.Change{}, s.insertCert(ctx, certName, description, mat)
			}})
	}
	urlMapRef := httpProxy.UrlMap
	steps = append(steps, platform.Step{Resource: "target-https-proxy/" + httpsName, Action: platform.Created, ID: s.proxyURL(httpsName),
		Desc: "URL map " + lb.urlMap + ", certs: " + certName, Attrs: map[string]string{"scope": s.kind(), "region": s.region, "proxy": httpsName, "new": certName},
		Apply: func(ctx context.Context) (platform.Change, error) {
			op, err := s.c.compute.RegionTargetHttpsProxies.Insert(s.c.project, s.region, &compute.TargetHttpsProxy{Name: httpsName, UrlMap: urlMapRef,
				SslCertificates: []string{s.certURL(certName)}}).Context(ctx).Do()
			if err != nil {
				return platform.Change{}, computeErr(err)
			}
			return platform.Change{}, s.wait(ctx, op)
		}})
	more, err := ensureHTTPSRule(ctx, rt, s, lb, httpsName, o, true)
	if err != nil {
		return nil, err
	}
	return append(steps, more...), nil
}

// httpProxyOf returns the first (by name) target HTTP proxy of the URL
// map, nil when there is none.
func httpProxyOf(ctx context.Context, s certScope, urlMap string) (*compute.TargetHttpProxy, error) {
	list, err := s.listHTTPProxies(ctx)
	if err != nil {
		return nil, err
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
	for _, p := range list {
		if lastSegment(p.UrlMap) == urlMap {
			return p, nil
		}
	}
	return nil, nil
}

// targetsKind reports whether a forwarding rule targets the proxy name of
// kind (targetHttpProxies, targetHttpsProxies).
func targetsKind(fr *compute.ForwardingRule, kind, name string) bool {
	return lastSegment(fr.Target) == name && strings.Contains(fr.Target, "/"+kind+"/")
}

// noteGlobalRule warns when no global forwarding rule serves :443 for the
// HTTPS proxies: polyctl does not create global rules.
func noteGlobalRule(ctx context.Context, rt *app.Runtime, s certScope, proxies []string) error {
	rules, err := s.listRules(ctx)
	if err != nil {
		return err
	}
	for _, p := range proxies {
		found := false
		for _, fr := range rules {
			if targetsKind(fr, "targetHttpsProxies", p) && portRangeCovers(fr.PortRange, 443) {
				found = true
			}
		}
		if !found {
			rt.Infof("warning: no global forwarding rule serves :443 for target HTTPS proxy %s; polyctl does not create global forwarding rules", p)
		}
	}
	return nil
}

// ensureHTTPSRule returns the steps that give the HTTPS proxy a :443
// forwarding rule on the IP of the :80 rule of the URL map's HTTP proxy.
// An existing rule is unchanged. Without a :80 rule to copy, an upgrade
// fails and an existing proxy is skipped.
func ensureHTTPSRule(ctx context.Context, rt *app.Runtime, s certScope, lb *lbRef, httpsName string, o lbCertOptions, upgrade bool) ([]platform.Step, error) {
	rules, err := s.listRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, fr := range rules {
		if targetsKind(fr, "targetHttpsProxies", httpsName) && portRangeCovers(fr.PortRange, 443) {
			return []platform.Step{{Resource: "forwarding-rule/" + fr.Name, Action: platform.Unchanged, Desc: ":443, ip " + fr.IPAddress}}, nil
		}
	}
	httpProxy, err := httpProxyOf(ctx, s, lb.urlMap)
	if err != nil {
		return nil, err
	}
	var rule80 *compute.ForwardingRule
	if httpProxy != nil {
		for _, fr := range rules {
			if targetsKind(fr, "targetHttpProxies", httpProxy.Name) && portRangeCovers(fr.PortRange, 80) {
				rule80 = fr
				break
			}
		}
	}
	if rule80 == nil {
		if upgrade && httpProxy != nil {
			return nil, fmt.Errorf("no :80 forwarding rule targets HTTP proxy %s (%s): the :443 rule takes its IP and network from it", httpProxy.Name, s.label())
		}
		return []platform.Step{{Resource: "target-https-proxy/" + httpsName + "/forwarding-rule", Action: platform.Skipped,
			Desc: "no :443 forwarding rule, and no :80 rule to copy one from"}}, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	name := prefixedName(rule80.Name, cfg.NamingTemplate("gcp_forwarding_rule_prefix"), "https")
	for _, fr := range rules {
		if fr.Name == name {
			return nil, fmt.Errorf("forwarding rule %s exists but targets %s on ports %s, not target HTTPS proxy %s on :443", name, lastSegment(fr.Target), fr.PortRange, httpsName)
		}
	}
	var steps []platform.Step
	ip := rule80.IPAddress
	// An internal load balancer's :80 IP is an internal address of its
	// subnetwork; two rules share it only through an address whose
	// purpose is SHARED_LOADBALANCER_VIP.
	internal := internalScheme(rule80.LoadBalancingScheme)
	if !o.newIP {
		addrs, err := s.c.listAddresses(ctx, s.region)
		if err != nil {
			return nil, err
		}
		addrType := addrExternal
		if internal {
			addrType = addrInternal
		}
		if a := addressByIP(addrs, ip, addrType); a != nil {
			if internal && a.Purpose != purposeSharedVIP {
				return nil, fmt.Errorf("internal address %s holds %s, the IP of forwarding rule %s, with purpose %s: a :443 rule can share it only when its purpose is %s; pass --new-ip to give the :443 rule an IP of its own",
					a.Name, ip, rule80.Name, orNone(a.Purpose), purposeSharedVIP)
			}
			steps = append(steps, platform.Step{Resource: "address/" + a.Name, Action: platform.Unchanged, Desc: "reserved " + ip})
		} else {
			addrName := fitName(o.lbName + "-ip")
			if checkCertName(addrName) != nil {
				addrName = fitName("lb-" + certSlug(o.lbName) + "-ip")
			}
			if a, err := s.c.getAddress(ctx, s.region, addrName); err != nil {
				return nil, err
			} else if a != nil {
				return nil, fmt.Errorf("address %s already holds %s, not %s, the IP of forwarding rule %s", addrName, a.Address, ip, rule80.Name)
			}
			body := &compute.Address{Name: addrName, Address: ip, AddressType: addrExternal, NetworkTier: tierOr(rule80.NetworkTier)}
			desc := "promote ephemeral " + ip
			if internal {
				body = &compute.Address{Name: addrName, Address: ip, AddressType: addrInternal, Subnetwork: rule80.Subnetwork, Purpose: purposeSharedVIP}
				desc += " (internal, " + purposeSharedVIP + ")"
			}
			steps = append(steps, platform.Step{Resource: "address/" + addrName, Action: platform.Created, Desc: desc,
				Apply: func(ctx context.Context) (platform.Change, error) {
					wctx, cancel, conv := deadline(ctx, s.timeout, "address/"+addrName, "RESERVED")
					defer cancel()
					_, err := s.c.insertAddress(wctx, s.region, body)
					return platform.Change{Detail: "promoted from ephemeral " + ip}, conv(err)
				}})
		}
	}
	scheme := rule80.LoadBalancingScheme
	if scheme == "" {
		scheme = "EXTERNAL_MANAGED"
	}
	desc := ":443, ip " + ip + " (same as :80)"
	if o.newIP {
		desc = ":443, ip " + platform.Pending + " (new)"
	}
	body := &compute.ForwardingRule{Name: name, IPProtocol: "TCP", PortRange: "443", Target: s.proxyURL(httpsName), NetworkTier: rule80.NetworkTier,
		LoadBalancingScheme: scheme, Network: rule80.Network, Subnetwork: rule80.Subnetwork}
	if !o.newIP {
		body.IPAddress = ip
	}
	labels := rule80.Labels
	steps = append(steps, platform.Step{Resource: "forwarding-rule/" + name, Action: platform.Created, Desc: desc,
		Attrs: map[string]string{"scope": s.kind(), "region": s.region, "proxy": httpsName},
		Apply: func(ctx context.Context) (platform.Change, error) {
			op, err := s.c.compute.ForwardingRules.Insert(s.c.project, s.region, body).Context(ctx).Do()
			if err != nil {
				return platform.Change{}, computeErr(err)
			}
			if !o.wait {
				if len(labels) > 0 {
					rt.Infof("warning: --no-wait: the labels of %s were not copied to forwarding rule %s", rule80.Name, name)
				}
				return platform.Change{Detail: desc + " (requested)"}, opError(op)
			}
			if err := s.wait(ctx, op); err != nil {
				return platform.Change{}, err
			}
			got, err := s.c.compute.ForwardingRules.Get(s.c.project, s.region, name).Context(ctx).Do()
			if err != nil {
				return platform.Change{}, computeErr(err)
			}
			// Labels sent with Insert are ignored: they are written
			// afterwards, with the fingerprint just read.
			if len(labels) > 0 {
				lop, err := s.c.compute.ForwardingRules.SetLabels(s.c.project, s.region, name,
					&compute.RegionSetLabelsRequest{Labels: labels, LabelFingerprint: got.LabelFingerprint}).Context(ctx).Do()
				if err == nil {
					err = s.wait(ctx, lop)
				} else {
					err = computeErr(err)
				}
				if err != nil {
					rt.Infof("warning: forwarding rule %s was created, but copying the labels of %s failed: %v", name, rule80.Name, err)
				}
			}
			d := ":443, ip " + got.IPAddress
			if !o.newIP {
				d += " (same as :80)"
			}
			rt.Infof("https://%s/ (the certificate names %s, not the IP)", got.IPAddress, o.domain)
			return platform.Change{Detail: d}, nil
		}})
	return steps, nil
}
