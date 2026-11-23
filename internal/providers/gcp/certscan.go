package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// The scan behind scheduled renewals (the GCP side of cert deploy): find
// the target HTTPS proxies that :443 forwarding rules serve, judge each
// certificate on them, and replace the self-managed ones that are about
// to expire with ReplaceProxyCertificate.

// httpsTarget is a target HTTPS proxy a :443 forwarding rule serves.
type httpsTarget struct {
	scope certScope
	rule  string
	proxy string
}

// discoverHTTPSTargets lists the target HTTPS proxies of the forwarding
// rules whose port range includes 443: the global rules, then the
// regional ones of the aggregated list (its "global" scope is skipped, as
// those rules were listed already). A proxy served by several rules is
// listed once.
func (c *client) discoverHTTPSTargets(ctx context.Context, timeout time.Duration) ([]httpsTarget, error) {
	var out []httpsTarget
	seen := map[string]bool{}
	add := func(region string, fr *compute.ForwardingRule) {
		if !portRangeCovers(fr.PortRange, 443) || !strings.Contains(fr.Target, "/targetHttpsProxies/") {
			return
		}
		key := region + "/" + lastSegment(fr.Target)
		if seen[key] {
			return
		}
		seen[key] = true
		out = append(out, httpsTarget{scope: certScope{c: c, region: region, timeout: timeout}, rule: fr.Name, proxy: lastSegment(fr.Target)})
	}
	global, err := (certScope{c: c}).listRules(ctx)
	if err != nil {
		return nil, err
	}
	for _, fr := range global {
		add("", fr)
	}
	err = c.compute.ForwardingRules.AggregatedList(c.project).Pages(ctx, func(l *compute.ForwardingRuleAggregatedList) error {
		for key, scoped := range l.Items {
			if key == "global" {
				continue
			}
			for _, fr := range scoped.ForwardingRules {
				add(lastSegment(fr.Region), fr)
			}
		}
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// consoleCertURL is the console page of a certificate, for warnings.
func consoleCertURL(name, project, region string) string {
	u := "https://console.cloud.google.com/security/ccm/lbCertificates/details/" + url.PathEscape(name) + "?project=" + url.QueryEscape(project)
	if region != "" {
		u += "&region=" + url.QueryEscape(region)
	}
	return u
}

// certJudgement is what the scan does with one certificate of a proxy.
type certJudgement struct {
	domain string
	renew  bool
	// warning is printed whatever the decision.
	warning string
	reason  string
}

// judgeCert decides on a certificate: a Google-managed one is never
// replaced (an expired one is a warning: its domain validation failed);
// a self-managed one with more than days days left is skipped, one whose
// domain cannot be told is a warning, the others are renewed.
func judgeCert(sc *compute.SslCertificate, now time.Time, days int, project, region string) certJudgement {
	f := factsOf(sc)
	link := consoleCertURL(sc.Name, project, region)
	if sc.Type == certManaged {
		j := certJudgement{domain: f.Domain, reason: "Google-managed"}
		if !f.Expire.IsZero() && !now.Before(f.Expire) {
			j.warning = fmt.Sprintf("managed certificate %s expired %d days ago; check its status (domain authorization, DNS pointing at the load balancer): %s", sc.Name, -daysLeft(f.Expire, now), link)
		}
		return j
	}
	if f.Domain == "" || f.Expire.IsZero() {
		return certJudgement{reason: "unknown domain or expiry", warning: fmt.Sprintf("cannot tell the domain or the expiry of certificate %s; check it: %s", sc.Name, link)}
	}
	left := daysLeft(f.Expire, now)
	if left > days {
		return certJudgement{domain: f.Domain, reason: fmt.Sprintf("%d days left > %d", left, days)}
	}
	return certJudgement{domain: f.Domain, renew: true, reason: fmt.Sprintf("%d days left <= %d", left, days)}
}

// renewOptions drive renewProxyCertificates.
type renewOptions struct {
	// Days: a certificate with at most this many days left is renewed;
	// EnsureDays is what the store must then provide (more, so that a new
	// certificate is not renewed again at once).
	Days, EnsureDays int
	// Ensure returns the certificate of a domain from the store. An error
	// that is ErrNotFound or app.ErrDomainUnknown means no DNS account
	// holds the domain: the certificate is skipped, not a failure.
	Ensure func(ctx context.Context, domain string, ensureDays int) (*platform.CertMaterial, error)
	// Notify receives every failure (hooks.on_failure); the scan goes on.
	Notify  func(ctx context.Context, domain string, err error)
	Infof   func(format string, args ...any)
	DryRun  bool
	KeepOld bool
	Timeout time.Duration
}

// renewProxyCertificates scans the project and replaces the certificates
// due for renewal. Every certificate is handled on its own: a failure is
// notified and reported as a Failed change, and the scan goes on; the
// error is then a PartialError.
func (c *client) renewProxyCertificates(ctx context.Context, cfg *config.Config, o renewOptions) ([]platform.Change, error) {
	infof := o.Infof
	if infof == nil {
		infof = func(string, ...any) {}
	}
	targets, err := c.discoverHTTPSTargets(ctx, o.Timeout)
	if err != nil {
		return nil, err
	}
	now := instanceClock.Now()
	var changes []platform.Change
	failed, total := 0, 0
	var first error
	fail := func(resource, domain string, err error) {
		failed++
		if first == nil {
			first = err
		}
		changes = append(changes, platform.Change{Resource: resource, Action: platform.Failed, Detail: err.Error()})
		if o.Notify != nil {
			o.Notify(ctx, domain, err)
		}
	}
	for _, t := range targets {
		s := t.scope
		p, err := s.getProxy(ctx, t.proxy)
		if err != nil {
			total++
			fail("target-https-proxy/"+t.proxy, "", err)
			continue
		}
		for _, u := range p.SslCertificates {
			sc, err := s.findCert(ctx, lastSegment(u))
			if err != nil {
				total++
				fail("ssl-certificate/"+lastSegment(u), "", err)
				continue
			}
			if sc == nil {
				continue
			}
			j := judgeCert(sc, now, o.Days, c.project, s.region)
			if j.warning != "" {
				infof("warning: %s", j.warning)
			}
			if !j.renew {
				continue
			}
			total++
			mat, err := o.Ensure(ctx, j.domain, o.EnsureDays)
			if errors.Is(err, platform.ErrNotFound) || errors.Is(err, app.ErrDomainUnknown) {
				infof("skipping certificate %s of %s: no configured DNS account holds the domain", sc.Name, j.domain)
				continue
			}
			if err != nil {
				fail("ssl-certificate/"+sc.Name, j.domain, err)
				continue
			}
			base, err := certBaseName(cfg, j.domain, now)
			if err != nil {
				fail("ssl-certificate/"+sc.Name, j.domain, err)
				continue
			}
			domain := j.domain
			rp, err := ReplaceProxyCertificate(ctx, replaceSpec{scope: s, proxies: []string{t.proxy}, domain: domain, mat: mat, baseName: base,
				description: "SSL certificate for " + domain, keepOld: o.KeepOld,
				isOld: func(_ string, f certFacts) bool { return f.Domain == domain }})
			if err != nil {
				fail("ssl-certificate/"+sc.Name, domain, err)
				continue
			}
			got, err := (&platform.Plan{Steps: append(rp.steps, rp.cleanup...)}).Run(ctx, o.DryRun)
			changes = append(changes, got...)
			if err != nil {
				failed++
				if first == nil {
					first = err
				}
				if o.Notify != nil {
					o.Notify(ctx, domain, err)
				}
			}
		}
	}
	if failed > 0 {
		return changes, &platform.PartialError{Failed: failed, Total: total, First: first}
	}
	return changes, nil
}
