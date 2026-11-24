package gcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// Self-managed SSL certificates of Compute Engine. A certificate resource
// is immutable and cannot be deleted while a target HTTPS proxy uses it,
// so replacing one is always: create a new certificate, switch the proxies
// to it, then delete the old one. A regional certificate serves regional
// proxies of its region only, a global one global proxies only.

const (
	certSelfManaged = "SELF_MANAGED"
	certManaged     = "MANAGED"

	// maxProxyCerts is the number of certificates a target HTTPS proxy
	// takes at most.
	maxProxyCerts = 15

	reasonInUse = "resourceInUseByAnotherResource"
)

// certNameRe is the Compute Engine resource name rule.
var certNameRe = regexp.MustCompile(`^[a-z]([-a-z0-9]{0,61}[a-z0-9])?$`)

// checkCertName validates a certificate name polyctl is asked to create.
func checkCertName(name string) error {
	if !certNameRe.MatchString(name) {
		return fmt.Errorf("%w: invalid certificate name %q: a lower-case letter first, then lower-case letters, digits and hyphens, not ending with a hyphen, at most 63 characters (a domain such as 163.com needs a prefix: cert-163-com)", platform.ErrInvalidInput, name)
	}
	return nil
}

// certScope is the regional (region set) or global scope of certificates
// and target HTTPS proxies. It keeps the two API families apart.
type certScope struct {
	c      *client
	region string
	// timeout bounds each operation wait (0: the default limit).
	timeout time.Duration
}

func (s certScope) global() bool { return s.region == "" }

// kind is "global" or "regional".
func (s certScope) kind() string {
	if s.global() {
		return "global"
	}
	return "regional"
}

// label is "global" or "regional, <region>".
func (s certScope) label() string {
	if s.global() {
		return "global"
	}
	return "regional, " + s.region
}

func (s certScope) prefix() string {
	if s.global() {
		return "projects/" + s.c.project + "/global/"
	}
	return "projects/" + s.c.project + "/regions/" + s.region + "/"
}

// certURL is the reference of a certificate a proxy takes.
func (s certScope) certURL(name string) string { return s.prefix() + "sslCertificates/" + name }

// proxyURL is the reference of a target HTTPS proxy a forwarding rule takes.
func (s certScope) proxyURL(name string) string { return s.prefix() + "targetHttpsProxies/" + name }

// resourceKey reduces a resource URL to "projects/..." so that a full URL
// and a relative reference compare equal.
func resourceKey(u string) string {
	if i := strings.Index(u, "projects/"); i >= 0 {
		return u[i:]
	}
	return u
}

func (s certScope) wait(ctx context.Context, op *compute.Operation) error {
	wctx, cancel, conv := deadline(ctx, s.timeout, "operation/"+op.Name, "DONE")
	defer cancel()
	if s.global() {
		return conv(s.c.waitGlobalOp(wctx, op))
	}
	return conv(s.c.waitRegionOp(wctx, s.region, op))
}

// getCert reads a certificate; a missing one is ErrNotFound.
func (s certScope) getCert(ctx context.Context, name string) (*compute.SslCertificate, error) {
	var sc *compute.SslCertificate
	var err error
	if s.global() {
		sc, err = s.c.compute.SslCertificates.Get(s.c.project, name).Context(ctx).Do()
	} else {
		sc, err = s.c.compute.RegionSslCertificates.Get(s.c.project, s.region, name).Context(ctx).Do()
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return sc, nil
}

// findCert reads a certificate, nil when it does not exist.
func (s certScope) findCert(ctx context.Context, name string) (*compute.SslCertificate, error) {
	sc, err := s.getCert(ctx, name)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, nil
	}
	return sc, err
}

func (s certScope) listCerts(ctx context.Context) ([]*compute.SslCertificate, error) {
	var out []*compute.SslCertificate
	var err error
	if s.global() {
		err = s.c.compute.SslCertificates.List(s.c.project).Pages(ctx, func(l *compute.SslCertificateList) error {
			out = append(out, l.Items...)
			return nil
		})
	} else {
		err = s.c.compute.RegionSslCertificates.List(s.c.project, s.region).Pages(ctx, func(l *compute.SslCertificateList) error {
			out = append(out, l.Items...)
			return nil
		})
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// insertCert uploads a certificate and waits for the operation. Type is
// never set: a certificate with a certificate and a private key is
// self-managed, and Type SELF_MANAGED would require the SelfManaged
// structure instead.
func (s certScope) insertCert(ctx context.Context, name, description string, m *platform.CertMaterial) error {
	sc := &compute.SslCertificate{Name: name, Description: description, Certificate: string(m.Fullchain), PrivateKey: string(m.PrivKey)}
	var op *compute.Operation
	var err error
	if s.global() {
		op, err = s.c.compute.SslCertificates.Insert(s.c.project, sc).Context(ctx).Do()
	} else {
		op, err = s.c.compute.RegionSslCertificates.Insert(s.c.project, s.region, sc).Context(ctx).Do()
	}
	if err != nil {
		return computeErr(err)
	}
	return s.wait(ctx, op)
}

// deleteCert deletes a certificate and waits for the operation. A
// certificate a proxy uses fails at submission with reasonInUse.
func (s certScope) deleteCert(ctx context.Context, name string) error {
	var op *compute.Operation
	var err error
	if s.global() {
		op, err = s.c.compute.SslCertificates.Delete(s.c.project, name).Context(ctx).Do()
	} else {
		op, err = s.c.compute.RegionSslCertificates.Delete(s.c.project, s.region, name).Context(ctx).Do()
	}
	if err != nil {
		return computeErr(err)
	}
	return s.wait(ctx, op)
}

// getProxy reads a target HTTPS proxy; a missing one is ErrNotFound.
func (s certScope) getProxy(ctx context.Context, name string) (*compute.TargetHttpsProxy, error) {
	var p *compute.TargetHttpsProxy
	var err error
	if s.global() {
		p, err = s.c.compute.TargetHttpsProxies.Get(s.c.project, name).Context(ctx).Do()
	} else {
		p, err = s.c.compute.RegionTargetHttpsProxies.Get(s.c.project, s.region, name).Context(ctx).Do()
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return p, nil
}

func (s certScope) listProxies(ctx context.Context) ([]*compute.TargetHttpsProxy, error) {
	var out []*compute.TargetHttpsProxy
	var err error
	if s.global() {
		err = s.c.compute.TargetHttpsProxies.List(s.c.project).Pages(ctx, func(l *compute.TargetHttpsProxyList) error {
			out = append(out, l.Items...)
			return nil
		})
	} else {
		err = s.c.compute.RegionTargetHttpsProxies.List(s.c.project, s.region).Pages(ctx, func(l *compute.TargetHttpsProxyList) error {
			out = append(out, l.Items...)
			return nil
		})
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// setProxyCerts replaces the certificate list of a proxy as a whole and
// waits for the operation.
func (s certScope) setProxyCerts(ctx context.Context, proxy string, urls []string) error {
	var op *compute.Operation
	var err error
	if s.global() {
		op, err = s.c.compute.TargetHttpsProxies.SetSslCertificates(s.c.project, proxy,
			&compute.TargetHttpsProxiesSetSslCertificatesRequest{SslCertificates: urls}).Context(ctx).Do()
	} else {
		op, err = s.c.compute.RegionTargetHttpsProxies.SetSslCertificates(s.c.project, s.region, proxy,
			&compute.RegionTargetHttpsProxiesSetSslCertificatesRequest{SslCertificates: urls}).Context(ctx).Do()
	}
	if err != nil {
		return computeErr(err)
	}
	return s.wait(ctx, op)
}

// usersOf lists the proxies of the scope whose certificates hold name.
func (s certScope) usersOf(ctx context.Context, name string) ([]string, error) {
	proxies, err := s.listProxies(ctx)
	if err != nil {
		return nil, err
	}
	key := resourceKey(s.certURL(name))
	var out []string
	for _, p := range proxies {
		for _, u := range p.SslCertificates {
			if resourceKey(u) == key {
				out = append(out, p.Name)
				break
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- facts

// certFacts are the facts of a certificate resource polyctl decides on.
type certFacts struct {
	Domains     []string
	Domain      string
	Expire      time.Time // zero when unknown
	Fingerprint string    // "" when the PEM cannot be read
}

// factsOf reads the domains and expiry of a certificate from the API
// fields, falling back to its PEM.
func factsOf(sc *compute.SslCertificate) certFacts {
	f := certFacts{Domains: sc.SubjectAlternativeNames}
	leaf, fp, err := platform.LeafOf(sc.Certificate)
	if err == nil {
		f.Fingerprint = fp
	}
	if len(f.Domains) == 0 && leaf != nil {
		f.Domains = leaf.DNSNames
	}
	cn := ""
	if leaf != nil {
		cn = leaf.Subject.CommonName
	}
	f.Domain = platform.CertDomain(f.Domains, cn)
	if sc.ExpireTime != "" {
		if t, err := time.Parse(time.RFC3339, sc.ExpireTime); err == nil {
			f.Expire = t.UTC()
		}
	}
	if f.Expire.IsZero() && leaf != nil {
		f.Expire = leaf.NotAfter.UTC()
	}
	return f
}

// uncoveredNames returns the names of old that a certificate of names
// does not cover (a wildcard is covered by the same wildcard only).
func uncoveredNames(names, old []string) []string {
	var out []string
	for _, n := range old {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n != "" && !platform.CertCovers(names, n) && !slices.Contains(out, n) {
			out = append(out, n)
		}
	}
	return out
}

// daysLeft is the number of whole days until t, rounded down.
func daysLeft(t, now time.Time) int { return int(math.Floor(t.Sub(now).Hours() / 24)) }

// normDomain lowercases a domain and drops "*." and a trailing dot, the
// form CertDomain returns.
func normDomain(d string) string {
	return strings.TrimPrefix(strings.TrimSuffix(strings.ToLower(strings.TrimSpace(d)), "."), "*.")
}

// ---------------------------------------------------------------- naming

// certSlug turns a domain into the start of a certificate name: lower
// case, dots to hyphens, "*." to "wildcard-", and a "cert-" prefix when
// it would not start with a letter.
func certSlug(domain string) string {
	d := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(domain)), ".")
	wild := strings.HasPrefix(d, "*.")
	d = strings.TrimPrefix(d, "*.")
	var b strings.Builder
	for _, r := range d {
		if r >= 'a' && r <= 'z' || r >= '0' && r <= '9' {
			b.WriteRune(r)
		} else if !strings.HasSuffix(b.String(), "-") {
			b.WriteByte('-')
		}
	}
	s := strings.Trim(b.String(), "-")
	if wild {
		s = "wildcard-" + s
	}
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		s = "cert-" + s
	}
	return strings.TrimRight(s, "-")
}

// certSuffixRoom is kept free at the end of a name for "-2" ... "-99".
const certSuffixRoom = 3

// certBaseName is the name of a new certificate of domain on day now:
// naming.gcp_ssl_certificate ({slug}-cert-{date} by default), the slug
// shortened with a 6-character hash when the name would not leave room
// for a "-N" suffix within 63 characters.
func certBaseName(cfg *config.Config, domain string, now time.Time) (string, error) {
	date := now.UTC().Format("20060102")
	slug := certSlug(domain)
	render := func(slug string) (string, error) {
		n, err := cfg.Name("gcp_ssl_certificate", map[string]string{"slug": slug, "date": date})
		if err != nil {
			return "", fmt.Errorf("%w: naming.gcp_ssl_certificate: %v (it may use {slug} and {date})", platform.ErrInvalidInput, err)
		}
		return n, nil
	}
	name, err := render(slug)
	if err != nil {
		return "", err
	}
	if limit := 63 - certSuffixRoom; len(name) > limit {
		empty, _ := render("")
		room := limit - len(empty)
		if room < 8 || !strings.Contains(cfg.NamingTemplate("gcp_ssl_certificate"), "{slug}") {
			return "", fmt.Errorf("%w: naming.gcp_ssl_certificate gives %q, longer than %d characters", platform.ErrInvalidInput, name, limit)
		}
		sum := sha256.Sum256([]byte(slug))
		short := strings.TrimRight(slug[:room-7], "-") + "-" + hex.EncodeToString(sum[:])[:6]
		if name, err = render(short); err != nil {
			return "", err
		}
	}
	if err := checkCertName(name); err != nil {
		return "", fmt.Errorf("%w (from naming.gcp_ssl_certificate)", err)
	}
	return name, nil
}

// certNameN is the n-th candidate name: the base, then base-2, base-3...
func certNameN(base string, n int) string {
	if n <= 1 {
		return base
	}
	return fmt.Sprintf("%s-%d", base, n)
}

// newCertName picks the name of a new certificate holding m: the first
// candidate that is free, or that already holds the same leaf (a run that
// created it and then failed to switch the proxies). reuse reports the
// latter. m nil (a dry run that would issue the certificate) takes the
// first free name.
func (s certScope) newCertName(ctx context.Context, base string, m *platform.CertMaterial) (name string, reuse bool, err error) {
	for n := 1; n < 100; n++ {
		name := certNameN(base, n)
		sc, err := s.findCert(ctx, name)
		if err != nil {
			return "", false, err
		}
		if sc == nil {
			return name, false, nil
		}
		if m != nil && factsOf(sc).Fingerprint == m.Fingerprint {
			return name, true, nil
		}
	}
	return "", false, fmt.Errorf("no free certificate name from %s to %s", base, certNameN(base, 99))
}

// ---------------------------------------------------------------- replace

// replaceSpec is the input of ReplaceProxyCertificate.
type replaceSpec struct {
	scope certScope
	// proxies are the target HTTPS proxies to switch.
	proxies []string
	// isOld tells the certificates the new one replaces on the proxies.
	isOld func(name string, f certFacts) bool
	// domain names the new certificate and its description.
	domain string
	// mat is the new certificate; nil in a dry run that would issue it.
	mat         *platform.CertMaterial
	baseName    string
	description string
	keepOld     bool
	// standalone creates the new certificate even when no proxy needs it
	// (ssl-certificate update of a certificate no proxy uses).
	standalone bool
	// extraOld are certificates to delete after the switch although no
	// proxy of the list holds them (the certificate update replaces).
	extraOld []string
}

// replacePlan is what ReplaceProxyCertificate found and will do.
type replacePlan struct {
	// steps create the certificate and switch the proxies; cleanup
	// deletes (or keeps) the old certificates, to run last.
	steps   []platform.Step
	cleanup []platform.Step
	// newName is the certificate the proxies end with ("" when nothing
	// needs it).
	newName string
	// current reports that every proxy already holds the new certificate.
	current bool
}

// ReplaceProxyCertificate observes the proxies of spec (read-only) and
// returns the steps that put the new certificate on them: create it (or
// reuse a certificate of the candidate name that holds the same leaf),
// switch each proxy that does not hold it yet, replacing only the old
// certificates and keeping the others (SNI), and delete the old ones that
// no proxy uses any more (one still in use is skipped, not a failure).
// Leaves are compared by the SHA-256 of their DER, never as PEM text. A
// proxy that already holds the new leaf is unchanged.
func ReplaceProxyCertificate(ctx context.Context, spec replaceSpec) (*replacePlan, error) {
	s := spec.scope
	type proxyState struct {
		name    string
		urls    []string
		olds    []string // names
		current bool
	}
	facts := map[string]*certFacts{} // by resource key
	var states []proxyState
	for _, pn := range spec.proxies {
		p, err := s.getProxy(ctx, pn)
		if err != nil {
			return nil, fmt.Errorf("target HTTPS proxy %s (%s): %w", pn, s.label(), err)
		}
		st := proxyState{name: p.Name, urls: p.SslCertificates}
		for _, u := range p.SslCertificates {
			key := resourceKey(u)
			f, ok := facts[key]
			if !ok {
				sc, err := s.findCert(ctx, lastSegment(u))
				if err != nil {
					return nil, err
				}
				if sc != nil {
					ff := factsOf(sc)
					f = &ff
				}
				facts[key] = f
			}
			if f == nil {
				continue
			}
			switch {
			case spec.mat != nil && f.Fingerprint == spec.mat.Fingerprint:
				st.current = true
			case spec.isOld(lastSegment(u), *f):
				st.olds = append(st.olds, lastSegment(u))
			}
		}
		states = append(states, st)
	}
	rp := &replacePlan{current: len(states) > 0}
	for _, st := range states {
		rp.current = rp.current && st.current
	}
	need := spec.standalone && len(states) == 0
	for _, st := range states {
		need = need || !st.current
	}
	attrs := func(extra ...string) map[string]string {
		a := map[string]string{"scope": s.kind()}
		if !s.global() {
			a["region"] = s.region
		}
		for i := 0; i+1 < len(extra); i += 2 {
			if extra[i+1] != "" {
				a[extra[i]] = extra[i+1]
			}
		}
		return a
	}
	expires := ""
	if spec.mat != nil {
		expires = ", expires " + spec.mat.Leaf.NotAfter.UTC().Format("2006-01-02")
	}
	if need {
		name, reuse, err := s.newCertName(ctx, spec.baseName, spec.mat)
		if err != nil {
			return nil, err
		}
		rp.newName = name
		res := "ssl-certificate/" + name
		if reuse {
			rp.steps = append(rp.steps, platform.Step{Resource: res, Action: platform.Unchanged,
				Desc: "existing, holds the same certificate (" + s.label() + ")", Attrs: attrs("new", name)})
		} else {
			mat := spec.mat
			rp.steps = append(rp.steps, platform.Step{Resource: res, Action: platform.Created, ID: s.certURL(name),
				Desc: s.label() + expires, Attrs: attrs("new", name),
				Apply: func(ctx context.Context) (platform.Change, error) {
					if mat == nil {
						return platform.Change{}, errors.New("no certificate material")
					}
					if err := s.insertCert(ctx, name, spec.description, mat); err != nil {
						return platform.Change{}, err
					}
					return platform.Change{ID: s.certURL(name)}, nil
				}})
		}
	}
	oldSet := map[string]bool{}
	var oldOrder []string
	addOld := func(n string) {
		if n != rp.newName && !oldSet[n] {
			oldSet[n] = true
			oldOrder = append(oldOrder, n)
		}
	}
	for _, st := range states {
		res := "target-https-proxy/" + st.name
		if st.current {
			rp.steps = append(rp.steps, platform.Step{Resource: res, Action: platform.Unchanged,
				Desc: "already holds the certificate", Attrs: attrs("proxy", st.name)})
			continue
		}
		var urls []string
		for _, u := range st.urls {
			if !slices.Contains(st.olds, lastSegment(u)) {
				urls = append(urls, u)
			}
		}
		urls = append(urls, s.certURL(rp.newName))
		if len(urls) > maxProxyCerts {
			return nil, fmt.Errorf("target HTTPS proxy %s would hold %d certificates; a proxy takes at most %d: remove certificates it no longer needs first", st.name, len(urls), maxProxyCerts)
		}
		oldLabel := strings.Join(st.olds, ",")
		desc := "certs: " + oldLabel + " -> " + rp.newName
		if oldLabel == "" {
			desc = "certs: + " + rp.newName
		}
		for _, o := range st.olds {
			addOld(o)
		}
		proxy := st.name
		rp.steps = append(rp.steps, platform.Step{Resource: res, Action: platform.Updated, Desc: desc,
			Attrs: attrs("proxy", proxy, "old", oldLabel, "new", rp.newName),
			Apply: func(ctx context.Context) (platform.Change, error) {
				return platform.Change{}, s.setProxyCerts(ctx, proxy, urls)
			}})
	}
	// A proxy left unchanged (it holds the new leaf already) keeps its
	// certificates, so an extra old one it still holds is not deleted.
	held := map[string]bool{}
	for _, st := range states {
		if st.current {
			for _, u := range st.urls {
				held[lastSegment(u)] = true
			}
		}
	}
	for _, o := range spec.extraOld {
		if !held[o] {
			addOld(o)
		}
	}
	for _, o := range oldOrder {
		res := "ssl-certificate/" + o
		if spec.keepOld {
			rp.cleanup = append(rp.cleanup, platform.Step{Resource: res, Action: platform.Skipped, Desc: "old, kept (--keep-old)", Attrs: attrs("old", o)})
			continue
		}
		name := o
		rp.cleanup = append(rp.cleanup, platform.Step{Resource: res, Action: platform.Deleted, Desc: "old, after switch", Attrs: attrs("old", name),
			Apply: func(ctx context.Context) (platform.Change, error) {
				err := deleteRetry(ctx, s, name)
				if err == nil {
					return platform.Change{Detail: "old, no longer referenced"}, nil
				}
				if isReason(err, reasonInUse) {
					return platform.Change{Action: platform.Skipped, Detail: "old, still used by " + inUseBy(err)}, nil
				}
				return platform.Change{}, err
			}})
	}
	return rp, nil
}

// certDeleteRetry is the retry of a delete that finds the certificate
// still in use: defensive only, as the reference is released when the
// switch operation is done.
var certDeleteRetry = platform.RetryPolicy{Initial: 3 * time.Second, Multiplier: 1, MaxAttempts: 3,
	Match: certInUse}

func deleteRetry(ctx context.Context, s certScope, name string) error {
	p := certDeleteRetry
	p.Clock = instanceClock
	return platform.Retry(ctx, p, func(ctx context.Context) error { return s.deleteCert(ctx, name) })
}

var inUseRe = regexp.MustCompile(`already being used by '([^']+)'`)

// certInUse reports the error of deleting a certificate another resource
// still uses: the reason resourceInUseByAnotherResource, or, for a
// regional certificate whose error may lack that reason, the message.
func certInUse(err error) bool {
	return err != nil && (isReason(err, reasonInUse) || inUseRe.MatchString(err.Error()))
}

// inUseBy names the resource an "in use" error says uses the certificate.
func inUseBy(err error) string {
	if m := inUseRe.FindStringSubmatch(err.Error()); m != nil {
		return lastSegment(m[1])
	}
	return "another resource"
}

// portRangeCovers reports whether the port range of a forwarding rule
// ("443", "443-443", "80-443") includes port. The range is parsed, never
// compared as a string.
func portRangeCovers(pr string, port int) bool {
	lo, hi, found := strings.Cut(strings.TrimSpace(pr), "-")
	if !found {
		hi = lo
	}
	a, err1 := strconv.Atoi(strings.TrimSpace(lo))
	b, err2 := strconv.Atoi(strings.TrimSpace(hi))
	return err1 == nil && err2 == nil && a <= port && port <= b
}

// ---------------------------------------------------------------- inventory

// SSLCertificate is the inventory form of a certificate resource. Region
// is empty for a global certificate.
type SSLCertificate struct {
	Name              string   `json:"name" yaml:"name"`
	Scope             string   `json:"scope" yaml:"scope"`
	Region            string   `json:"region,omitempty" yaml:"region,omitempty"`
	Type              string   `json:"type" yaml:"type"`
	Domains           []string `json:"domains,omitempty" yaml:"domains,omitempty"`
	ExpireTime        string   `json:"expire_time,omitempty" yaml:"expire_time,omitempty"`
	Description       string   `json:"description,omitempty" yaml:"description,omitempty"`
	CreationTimestamp string   `json:"creation_timestamp,omitempty" yaml:"creation_timestamp,omitempty"`
}

func sslCertificateFrom(sc *compute.SslCertificate) SSLCertificate {
	f := factsOf(sc)
	v := SSLCertificate{Name: sc.Name, Scope: "global", Region: lastSegment(sc.Region), Type: sc.Type, Domains: f.Domains,
		Description: sc.Description, CreationTimestamp: sc.CreationTimestamp}
	if v.Region != "" {
		v.Scope = "regional"
	}
	if v.Type == "" {
		v.Type = certSelfManaged
	}
	if !f.Expire.IsZero() {
		v.ExpireTime = f.Expire.Format(time.RFC3339)
	}
	return v
}

// certInventoryID is the inventory id of a certificate: "<region>/<name>",
// or "global/<name>".
func certInventoryID(region, name string) string { return fallbackID("", "", region, name) }

func (v SSLCertificate) resource() platform.Resource {
	return platform.Resource{Type: platform.ResCertificate, ID: certInventoryID(v.Region, v.Name), Name: v.Name, ParentID: v.Region, Data: v}
}

// listAllCerts lists the certificates of every scope.
func (c *client) listAllCerts(ctx context.Context) ([]*compute.SslCertificate, []string, error) {
	var out []*compute.SslCertificate
	var unreachable []string
	err := c.compute.SslCertificates.AggregatedList(c.project).Pages(ctx, func(l *compute.SslCertificateAggregatedList) error {
		for _, scoped := range l.Items {
			out = append(out, scoped.SslCertificates...)
		}
		unreachable = append(unreachable, l.Unreachables...)
		return nil
	})
	if err != nil {
		return nil, nil, computeErr(err)
	}
	sort.Slice(out, func(i, j int) bool {
		if ri, rj := lastSegment(out[i].Region), lastSegment(out[j].Region); ri != rj {
			return ri < rj
		}
		return out[i].Name < out[j].Name
	})
	return out, unreachable, nil
}

// syncCertificates lists every certificate of the project for the
// inventory.
func (c *client) syncCertificates(ctx context.Context) ([]platform.Resource, error) {
	certs, unreachable, err := c.listAllCerts(ctx)
	if err != nil {
		return nil, err
	}
	out := make([]platform.Resource, 0, len(certs))
	for _, sc := range certs {
		out = append(out, sslCertificateFrom(sc).resource())
	}
	return out, unreachableErr(unreachable)
}

// proxyUsers maps the resource key of every certificate to the target
// HTTPS proxies (of every scope) that use it.
func (c *client) proxyUsers(ctx context.Context) (map[string][]string, error) {
	out := map[string][]string{}
	err := c.compute.TargetHttpsProxies.AggregatedList(c.project).Pages(ctx, func(l *compute.TargetHttpsProxyAggregatedList) error {
		for _, scoped := range l.Items {
			for _, p := range scoped.TargetHttpsProxies {
				for _, u := range p.SslCertificates {
					out[resourceKey(u)] = append(out[resourceKey(u)], p.Name)
				}
			}
		}
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}
