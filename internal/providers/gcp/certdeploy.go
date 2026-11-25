package gcp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"maps"
	"net/url"
	"slices"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// The gcp-lb deployer of cert deploy: the target HTTPS proxies that
// forwarding rules serve, global and regional. Compute Engine certificates
// cannot be changed and cannot be deleted while a proxy uses them, so a
// due certificate is replaced by creating a new one (named after its root
// domain and expiry, which finds it again on the next run), switching the
// proxy to it, then deleting the old one. A proxy takes its certificates
// as a whole list: every certificate of one proxy that is due is replaced
// in a single SetSslCertificates, the others kept as they are.

const gcpDeployerID = "gcp-lb"

func init() { platform.RegisterDeployer(lbDeployer{}) }

// lbDeployer implements platform.BatchDeployer for target HTTPS proxies.
type lbDeployer struct{}

func (lbDeployer) ID() string            { return gcpDeployerID }
func (lbDeployer) Platform() platform.ID { return platform.GCP }

// deployClient is the GCP client of a deploy account.
func deployClient(acct *platform.DeployAccount) (*client, error) {
	c, ok := acct.Client.(*client)
	if !ok {
		return nil, fmt.Errorf("%w: the client of %s is not a GCP client", platform.ErrNotSupported, acct.Profile)
	}
	return c, nil
}

// httpsTarget is a target HTTPS proxy a forwarding rule serves.
type httpsTarget struct {
	scope certScope
	rule  string
	proxy string
}

// discoverHTTPSTargets lists the target HTTPS proxies forwarding rules
// point to, whatever their port: the global rules, then the regional ones
// of the aggregated list (its "global" scope is skipped, as those rules
// were listed already). A proxy served by several rules is listed once.
func (c *client) discoverHTTPSTargets(ctx context.Context, timeout time.Duration) ([]httpsTarget, error) {
	var out []httpsTarget
	seen := map[string]bool{}
	add := func(region string, fr *compute.ForwardingRule) {
		if !strings.Contains(fr.Target, "/targetHttpsProxies/") {
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
	unreachable, err := aggregatedPages(ctx, c.compute.ForwardingRules.AggregatedList(c.project), func(l *compute.ForwardingRuleAggregatedList) (string, []string) {
		u := l.Unreachables
		for key, scoped := range l.Items {
			if scoped.Warning != nil {
				u = append(u, warnedUnreachable(key, scoped.Warning.Code)...)
			}
			if key == "global" {
				continue
			}
			for _, fr := range scoped.ForwardingRules {
				add(lastSegment(fr.Region), fr)
			}
		}
		return l.NextPageToken, u
	})
	if err != nil {
		return nil, computeErr(err)
	}
	if err := unreachableListErr("forwarding rules", unreachable); err != nil {
		return nil, err
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

// scopeName is "global" or the region of a scope, as reports name it.
func (s certScope) scopeName() string {
	if s.global() {
		return "global"
	}
	return s.region
}

// inRegions reports whether a scope is one of --region (empty: all);
// "global" names the global scope.
func inRegions(regions []string, s certScope) bool {
	return len(regions) == 0 || slices.Contains(regions, s.scopeName())
}

// scopeOf is the scope of a target ("global" or a region).
func scopeOf(c *client, region string, timeout time.Duration) certScope {
	if region == "global" {
		region = ""
	}
	return certScope{c: c, region: region, timeout: timeout}
}

// Discover lists, for every proxy a forwarding rule serves, its
// self-managed certificates. A proxy that uses a certificate map is
// skipped; so is a Google-managed certificate (Google renews it; an
// expired one is a warning, its domain validation failed) and one whose
// domain or expiry cannot be told.
func (d lbDeployer) Discover(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.DeployTarget, []platform.Change, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, nil, err
	}
	found, err := c.discoverHTTPSTargets(ctx, o.Timeout)
	if err != nil {
		return nil, nil, err
	}
	now := o.Clock()
	var targets []platform.DeployTarget
	var skipped []platform.Change
	for _, ht := range found {
		s := ht.scope
		if !inRegions(acct.Regions, s) {
			continue
		}
		p, err := s.getProxy(ctx, ht.proxy)
		if errors.Is(err, platform.ErrNotFound) {
			continue
		}
		if err != nil {
			return nil, nil, err
		}
		name := s.scopeName() + "/" + p.Name
		res := platform.DeployResource(gcpDeployerID, acct.Profile, name)
		attrs := map[string]string{"deployer": gcpDeployerID, "platform": string(platform.GCP), "profile": acct.Profile, "region": s.scopeName()}
		if p.CertificateMap != "" {
			skipped = append(skipped, platform.Change{Resource: res, Action: platform.Skipped, Attrs: attrs,
				Detail: "uses the certificate map " + lastSegment(p.CertificateMap) + "; not managed by polyctl"})
			continue
		}
		start := len(targets)
		for _, u := range p.SslCertificates {
			sc, err := s.findCert(ctx, lastSegment(u))
			if err != nil {
				return nil, nil, err
			}
			if sc == nil {
				continue
			}
			f := factsOf(sc)
			link := consoleCertURL(sc.Name, c.project, s.region)
			if sc.Type == certManaged {
				attrs := maps.Clone(attrs)
				if root, err := platform.RegisteredDomain(f.Domain); err == nil {
					attrs["domain"] = root
				}
				if !f.Expire.IsZero() && !now.Before(f.Expire) {
					o.Warnf("managed certificate %s expired %d days ago; check its status (domain authorization, DNS pointing at the load balancer): %s",
						sc.Name, -daysLeft(f.Expire, now), link)
				}
				skipped = append(skipped, platform.Change{Resource: res, Action: platform.Skipped, ID: sc.Name, Attrs: attrs,
					Detail: "certificate " + sc.Name + " is Google-managed and renewed by Google"})
				continue
			}
			if f.Domain == "" || f.Expire.IsZero() {
				skipped = append(skipped, platform.Change{Resource: res, Action: platform.Skipped, ID: sc.Name, Attrs: attrs,
					Detail: "cannot tell the domain or the expiry of certificate " + sc.Name + ": " + link})
				continue
			}
			serial, family := "", ""
			if leaf, _, err := platform.LeafOf(sc.Certificate); err == nil {
				serial = leaf.SerialNumber.Text(16)
				family = keyFamily(leaf.PublicKey)
			}
			targets = append(targets, platform.DeployTarget{Deployer: gcpDeployerID, Platform: platform.GCP, Profile: acct.Profile, Region: s.scopeName(),
				Kind: "gcp-https-proxy", ID: sc.Name, Name: name, Group: name, CurrentCertID: sc.Name, CurrentDomains: f.Domains,
				CurrentNotAfter: f.Expire, CurrentSerial: serial, Attrs: map[string]string{"proxy": p.Name, "fingerprint": f.Fingerprint, "key_family": family}})
		}
		// proxy_key_families are the key families of the other
		// certificates of the proxy that cover every name of a target:
		// the target is one of a pair of an RSA and an ECDSA certificate
		// of the same names. A certificate of other names (another
		// subdomain) does not make it a pair.
		for i := start; i < len(targets); i++ {
			var families []string
			for j := start; j < len(targets); j++ {
				fam := targets[j].Attrs["key_family"]
				if j == i || fam == "" || slices.Contains(families, fam) || len(targets[i].CurrentDomains) == 0 ||
					len(uncoveredNames(targets[j].CurrentDomains, targets[i].CurrentDomains)) > 0 {
					continue
				}
				families = append(families, fam)
			}
			targets[i].Attrs["proxy_key_families"] = strings.Join(families, ",")
		}
	}
	return targets, skipped, nil
}

// Plan replaces the certificate of one proxy (PlanBatch with one item);
// cert deploy calls PlanBatch for the targets of this deployer.
func (d lbDeployer) Plan(ctx context.Context, acct *platform.DeployAccount, t platform.DeployTarget, cert *platform.DeployCert, o platform.DeployOptions) ([]platform.Step, error) {
	return d.PlanBatch(ctx, acct, t.Group, []platform.DeployItem{{Target: t, Cert: cert}}, o)
}

// deployCertName is the name of the new certificate of a root domain:
// cert-<root with its dots as hyphens>-<expiry, YYYYMMDD>, at most 54
// characters (a slug too long is cut and given a hash) so that the
// "-<serial>" of a name clash still fits in 63.
func deployCertName(root string, notAfter time.Time) string {
	var b strings.Builder
	for _, r := range strings.ToLower(root) {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	slug := strings.Trim(b.String(), "-")
	date := platform.Pending
	if !notAfter.IsZero() {
		date = notAfter.UTC().Format("20060102")
	}
	const limit = 63 - 9
	name := "cert-" + slug + "-" + date
	if len(name) > limit {
		sum := sha256.Sum256([]byte(slug))
		keep := limit - len("cert-") - len("-"+date) - 7
		slug = strings.TrimRight(slug[:keep], "-") + "-" + hex.EncodeToString(sum[:])[:6]
		name = "cert-" + slug + "-" + date
	}
	return name
}

// pickCertName finds the name of the new certificate in s: the base name
// when it is free or holds the same leaf, else base-<first 8 digits of the
// serial number> on the same terms. reuse reports a certificate that
// exists already (a run that created it and then failed to switch).
func (s certScope) pickCertName(ctx context.Context, base string, cert *platform.DeployCert) (name string, reuse bool, err error) {
	alt := base + "-" + strings.TrimLeft(strings.ToLower(cert.Serial), "0")
	if len(alt) > len(base)+9 {
		alt = alt[:len(base)+9]
	}
	for _, n := range []string{base, alt} {
		sc, err := s.findCert(ctx, n)
		if err != nil {
			return "", false, err
		}
		if sc == nil {
			return n, false, nil
		}
		if factsOf(sc).Fingerprint == cert.Fingerprint {
			return n, true, nil
		}
	}
	return "", false, fmt.Errorf("the certificate names %s and %s are taken by other certificates (%s)", base, alt, s.label())
}

// PlanBatch replaces the due certificates of one proxy: it creates (or
// reuses) the new certificate of each root domain in the proxy's scope,
// switches the proxy in one SetSslCertificates (each old certificate
// replaced in place, every other one kept), then deletes the old ones. An
// old certificate another resource still uses is kept; a deletion that
// fails otherwise is a warning.
func (d lbDeployer) PlanBatch(ctx context.Context, acct *platform.DeployAccount, group string, items []platform.DeployItem, o platform.DeployOptions) ([]platform.Step, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, err
	}
	first := items[0].Target
	s := scopeOf(c, first.Region, o.Timeout)
	proxy := first.Attrs["proxy"]
	p, err := s.getProxy(ctx, proxy)
	if err != nil {
		return nil, fmt.Errorf("target HTTPS proxy %s (%s): %w", proxy, s.label(), err)
	}
	var steps []platform.Step
	// A proxy can hold an RSA and an ECDSA certificate of one domain
	// (clients get the one they support); the store holds one key type,
	// so only the certificate of that key type is replaced and the other
	// one is kept.
	newFamily := func(it platform.DeployItem) string {
		if it.Cert.Leaf == nil {
			return ""
		}
		return keyFamily(it.Cert.Leaf.PublicKey)
	}
	var kept []platform.DeployItem
	var replaced []platform.DeployItem
	for _, it := range items {
		// The proxy holds a certificate of the store's key type that
		// covers every name of this one (due now or not): this one, of
		// another key type, is kept.
		have, nf := it.Target.Attrs["key_family"], newFamily(it)
		if have != "" && nf != "" && have != nf && slices.Contains(strings.Split(it.Target.Attrs["proxy_key_families"], ","), nf) {
			kept = append(kept, it)
			continue
		}
		replaced = append(replaced, it)
	}
	for _, it := range kept {
		steps = append(steps, platform.Step{Resource: platform.DeployResource(gcpDeployerID, acct.Profile, s.scopeName()+"/ssl-certificate/"+it.Target.ID),
			Action: platform.Skipped, ID: it.Target.ID,
			Desc: fmt.Sprintf("%s certificate %s of %s kept on %s beside the %s one: the store has no %s certificate of %s",
				it.Target.Attrs["key_family"], it.Target.ID, it.Cert.Root, proxy, newFamily(it), it.Target.Attrs["key_family"], it.Cert.Root)})
	}
	items = replaced
	if len(items) == 0 {
		return steps, nil
	}
	newOf := map[string]string{}   // root -> new certificate name
	replace := map[string]string{} // old name -> new name
	var olds []string
	var keyChanges []string
	for _, it := range items {
		root := it.Cert.Root
		if have, nf := it.Target.Attrs["key_family"], newFamily(it); have != "" && nf != "" && have != nf {
			keyChanges = append(keyChanges, fmt.Sprintf("%s: %s -> %s", it.Target.ID, have, nf))
		}
		name, ok := newOf[root]
		if !ok {
			res := platform.DeployResource(gcpDeployerID, acct.Profile, s.scopeName()+"/ssl-certificate/")
			attrs := map[string]string{"deployer": gcpDeployerID, "platform": string(platform.GCP), "profile": acct.Profile, "region": s.scopeName(), "domain": root}
			if it.Cert.Pending {
				name = deployCertName(root, time.Time{})
				attrs["cert_name"] = name
				steps = append(steps, platform.Step{Resource: res + name, Action: platform.Created, ID: platform.Pending, Desc: s.label(), Attrs: attrs,
					Apply: func(context.Context) (platform.Change, error) {
						return platform.Change{}, errors.New("the certificate was not issued")
					}})
			} else {
				var reuse bool
				if name, reuse, err = s.pickCertName(ctx, deployCertName(root, it.Cert.NotAfter), it.Cert); err != nil {
					return nil, err
				}
				attrs["cert_name"] = name
				if reuse {
					steps = append(steps, platform.Step{Resource: res + name, Action: platform.Unchanged, ID: s.certURL(name),
						Desc: "existing, holds the same certificate (" + s.label() + ")", Attrs: attrs})
				} else {
					mat, n := it.Cert.Material(), name
					steps = append(steps, platform.Step{Resource: res + name, Action: platform.Created, ID: s.certURL(name),
						Desc: s.label() + ", expires " + it.Cert.NotAfter.UTC().Format("2006-01-02"), Attrs: attrs,
						Apply: func(ctx context.Context) (platform.Change, error) {
							if err := s.insertCert(ctx, n, "SSL certificate for "+root, mat); err != nil {
								return platform.Change{}, err
							}
							return platform.Change{ID: s.certURL(n)}, nil
						}})
				}
			}
			newOf[root] = name
		}
		if it.Target.ID != name {
			replace[it.Target.ID] = name
			olds = append(olds, it.Target.ID)
		}
	}
	res := first.Resource()
	if len(replace) == 0 {
		steps = append(steps, platform.Step{Resource: res, Action: platform.Unchanged, Desc: "already holds the certificate"})
		return steps, nil
	}
	var urls []string
	var added []string
	for _, u := range p.SslCertificates {
		n := lastSegment(u)
		nw, ok := replace[n]
		if !ok {
			urls = append(urls, u)
			continue
		}
		if !slices.Contains(added, nw) {
			added = append(added, nw)
			urls = append(urls, s.certURL(nw))
		}
	}
	for _, nw := range newOf {
		// A replaced certificate the proxy no longer lists (changed
		// meanwhile) still gets its successor.
		if !slices.Contains(added, nw) && slices.ContainsFunc(olds, func(o string) bool { return replace[o] == nw }) {
			added = append(added, nw)
			urls = append(urls, s.certURL(nw))
		}
	}
	if len(urls) > maxProxyCerts {
		return nil, fmt.Errorf("target HTTPS proxy %s would hold %d certificates; a proxy takes at most %d", proxy, len(urls), maxProxyCerts)
	}
	desc := strings.Join(olds, ",") + " -> " + strings.Join(added, ",")
	if len(keyChanges) > 0 {
		desc += " (key type changes, " + strings.Join(keyChanges, "; ") + ")"
	}
	steps = append(steps, platform.Step{Resource: res, Action: platform.Updated, ID: proxy, Desc: desc,
		Attrs: map[string]string{"proxy": proxy, "old": strings.Join(olds, ","), "cert_name": strings.Join(added, ",")},
		Apply: func(ctx context.Context) (platform.Change, error) {
			return platform.Change{}, s.switchProxyCerts(ctx, proxy, replace, added, true)
		}})
	for _, old := range olds {
		name := old
		steps = append(steps, platform.Step{Resource: platform.DeployResource(gcpDeployerID, acct.Profile, s.scopeName()+"/ssl-certificate/"+name),
			Action: platform.Deleted, ID: s.certURL(name), Desc: "old, replaced on " + proxy,
			Apply: func(ctx context.Context) (platform.Change, error) {
				err := deleteRetry(ctx, s, name)
				switch {
				case err == nil:
					return platform.Change{Detail: "old, no longer referenced"}, nil
				case certInUse(err):
					return platform.Change{Action: platform.Skipped, Detail: "old, still used by " + inUseBy(err) + "; kept"}, nil
				}
				o.Warnf("the old certificate %s was not deleted: %v", name, err)
				return platform.Change{Action: platform.Skipped, Detail: "old, not deleted: " + err.Error()}, nil
			}})
	}
	return steps, nil
}

// Prune deletes the expired self-managed certificates of the project (of
// --region when given) that no target HTTPS proxy uses.
func (d lbDeployer) Prune(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.Step, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, err
	}
	certs, unreachable, err := c.listAllCerts(ctx)
	if err != nil {
		return nil, err
	}
	if len(unreachable) > 0 {
		o.Warnf("%s: the certificates of %s could not be listed", acct.Profile, strings.Join(unreachable, ", "))
	}
	users, err := c.proxyUsers(ctx)
	if err != nil {
		return nil, err
	}
	now := o.Clock()
	var steps []platform.Step
	for _, sc := range certs {
		if sc.Type == certManaged {
			continue
		}
		s := certScope{c: c, region: lastSegment(sc.Region), timeout: o.Timeout}
		if !inRegions(acct.Regions, s) {
			continue
		}
		f := factsOf(sc)
		if f.Expire.IsZero() || now.Before(f.Expire) {
			continue
		}
		res := platform.DeployResource(gcpDeployerID, acct.Profile, s.scopeName()+"/ssl-certificate/"+sc.Name)
		desc := fmt.Sprintf("cert=%s expired (%s)", sc.Name, f.Expire.Format("2006-01-02"))
		if by := users[resourceKey(s.certURL(sc.Name))]; len(by) > 0 {
			steps = append(steps, platform.Step{Resource: res, Action: platform.Skipped, ID: sc.Name, Desc: desc + "; still used by " + strings.Join(by, ", ")})
			continue
		}
		name := sc.Name
		steps = append(steps, platform.Step{Resource: res, Action: platform.Deleted, ID: sc.Name, Desc: desc,
			Apply: func(ctx context.Context) (platform.Change, error) { return platform.Change{}, s.deleteCert(ctx, name) }})
	}
	return steps, nil
}

// keyFamily names the key family of a public key: RSA, ECDSA, or "" for
// anything else.
func keyFamily(pub crypto.PublicKey) string {
	switch pub.(type) {
	case *rsa.PublicKey:
		return "RSA"
	case *ecdsa.PublicKey:
		return "ECDSA"
	}
	return ""
}
