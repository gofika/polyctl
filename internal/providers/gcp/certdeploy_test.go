package gcp

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func TestDiscoverHTTPSTargets(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addRule("global", "fr-g", "targetHttpsProxies/proxy-https-g", "34.8.8.8", "443-443", nil)
	h.gce.addRule("us-central1", "fr-range", "targetHttpsProxies/proxy-https-a", "34.1.1.1", "80-443", nil)
	h.gce.addRule("us-central1", "fr-8443", "targetHttpsProxies/proxy-https-b", "34.1.1.2", "8443", nil)
	h.gce.addRule("us-central1", "fr-80", "targetHttpProxies/proxy-c", "34.1.1.3", "80-80", nil)
	h.gce.addRule("us-central1", "fr-again", "targetHttpsProxies/proxy-https-a", "34.1.1.4", "443-443", nil)
	c, err := openProfile(t.Context(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	targets, err := c.discoverHTTPSTargets(t.Context(), 0)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, x := range targets {
		got = append(got, x.scope.label()+"/"+x.proxy)
	}
	slices.Sort(got)
	// The target decides, not the port: 8443 is served too; the global
	// scope of the aggregated list is not taken as a region.
	if want := []string{"global/proxy-https-g", "regional, us-central1/proxy-https-a", "regional, us-central1/proxy-https-b"}; !slices.Equal(got, want) {
		t.Errorf("targets = %v", got)
	}
}

func TestDeployCertName(t *testing.T) {
	day := time.Date(2027, 2, 14, 12, 0, 0, 0, time.UTC)
	for root, want := range map[string]string{
		"example.com":           "cert-example-com-20270214",
		"123.com":               "cert-123-com-20270214",
		"xn--bcher-kva.example": "cert-xn-bcher-kva-example-20270214",
	} {
		if got := deployCertName(root, day); got != want || checkCertName(got) != nil {
			t.Errorf("%s: %q", root, got)
		}
	}
	long := strings.Repeat("a", 60) + ".com"
	if got := deployCertName(long, day); len(got) > 54 || checkCertName(got) != nil || !strings.HasSuffix(got, "-20270214") {
		t.Errorf("long name %q (%d)", got, len(got))
	}
}

// gcpDeploy runs cert deploy with the gcp-lb deployer against the fake.
type gcpDeploy struct {
	t       *testing.T
	h       *gcpHarness
	c       *client
	bundles map[string]*cert.Bundle
	notes   []string
}

func newGCPDeploy(t *testing.T) *gcpDeploy {
	h := newGCPHarness(t, app.Flags{}, nil)
	c, err := openProfile(t.Context(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	return &gcpDeploy{t: t, h: h, c: c, bundles: map[string]*cert.Bundle{}}
}

func (d *gcpDeploy) bundle(root string, days int) *cert.Bundle {
	d.t.Helper()
	p := newPair(d.t, []string{root, "*." + root}, days)
	b, err := cert.NewBundle(root, p.chain, p.key)
	if err != nil {
		d.t.Fatal(err)
	}
	d.bundles[root] = b
	return b
}

func (d *gcpDeploy) run(o cert.DeployOptions, regions ...string) (*cert.DeployReport, error) {
	d.t.Helper()
	dep, _ := platform.GetDeployer(gcpDeployerID)
	o.Deployers = []platform.CertDeployer{dep}
	if o.Days == 0 {
		o.Days = 30
	}
	if o.Domain == "" {
		o.All = true
	}
	d.notes = nil
	d.h.gce.mu.Lock()
	d.h.gce.calls = nil
	d.h.gce.mu.Unlock()
	env := &cert.DeployEnv{
		Accounts: []config.AccountRef{{Profile: "lab", Platform: platform.GCP}},
		Open:     func(context.Context, config.AccountRef) (platform.Client, error) { return d.c, nil },
		Regions:  func(config.AccountRef) []string { return regions },
		Ensure: func(_ context.Context, root string, days int) (*cert.Result, error) {
			b := d.bundles[root]
			if b == nil {
				return nil, fmt.Errorf("%w: %s", app.ErrDomainUnknown, root)
			}
			return &cert.Result{Bundle: b}, nil
		},
		Now:   func() time.Time { return harnessNow },
		Infof: func(f string, a ...any) { d.notes = append(d.notes, fmt.Sprintf(f, a...)) },
	}
	return cert.Deploy(context.Background(), env, o)
}

func reportRows(rep *cert.DeployReport) []string {
	var out []string
	for _, c := range rep.Changes {
		out = append(out, c.Resource+" "+string(c.Action)+" "+c.Detail)
	}
	return out
}

func TestGCPDeployerReplacesDueCertificatesInOneSwitch(t *testing.T) {
	d := newGCPDeploy(t)
	g := d.h.gce
	com := newPair(t, []string{"example.com", "*.example.com"}, 20)
	org := newPair(t, []string{"www.example.org"}, 10)
	fresh := newPair(t, []string{"fresh.com"}, 60)
	g.addCert("us-central1", "example-com-old", com.chain)
	g.addCert("us-central1", "example-org-old", org.chain)
	g.addCert("us-central1", "fresh-com", fresh.chain)
	g.addHTTPSProxy("us-central1", "proxy-web", "lb-web", "example-com-old", "fresh-com", "example-org-old")
	g.addRule("us-central1", "fr-web", "targetHttpsProxies/proxy-web", "34.1.2.3", "8443", nil)
	g.addManagedCert("global", "managed-expired", []string{"www.example.com"}, "2025-12-01T00:00:00.000-08:00")
	g.addHTTPSProxy("global", "proxy-g", "lb-g", "managed-expired")
	g.addRule("global", "fr-g", "targetHttpsProxies/proxy-g", "34.8.8.8", "443", nil)
	g.addHTTPSProxy("global", "proxy-map", "lb-map")
	g.mu.Lock()
	g.lb().httpsProxies["proj/global/proxy-map"].CertificateMap = "//certificatemanager.googleapis.com/projects/proj/locations/global/certificateMaps/m"
	g.mu.Unlock()
	g.addRule("global", "fr-map", "targetHttpsProxies/proxy-map", "34.8.8.9", "443", nil)
	d.bundle("example.com", 90)
	d.bundle("example.org", 90)

	rep, err := d.run(cert.DeployOptions{})
	if err != nil {
		t.Fatalf("deploy: %v\n%s", err, strings.Join(reportRows(rep), "\n"))
	}
	if certs := g.proxyCerts("us-central1", "proxy-web"); !slices.Equal(certs, []string{"cert-example-com-20260401", "fresh-com", "cert-example-org-20260401"}) {
		t.Errorf("proxy certificates = %v", certs)
	}
	var sets int
	for _, w := range g.lbWrites() {
		if strings.Contains(w, "setSslCertificates") {
			sets++
		}
	}
	if sets != 1 {
		t.Errorf("%d SetSslCertificates, want one for both certificates: %v", sets, g.lbWrites())
	}
	if g.cert("us-central1", "example-com-old") != nil || g.cert("us-central1", "example-org-old") != nil || g.cert("us-central1", "fresh-com") == nil {
		t.Error("the old certificates must be deleted, the others kept")
	}
	rows := reportRows(rep)
	for _, w := range []string{
		"gcp-lb/lab/us-central1/ssl-certificate/cert-example-com-20260401 created regional, us-central1, expires 2026-04-01",
		"gcp-lb/lab/us-central1/proxy-web updated example-com-old,example-org-old -> cert-example-com-20260401,cert-example-org-20260401",
		"gcp-lb/lab/us-central1/ssl-certificate/example-com-old deleted old, no longer referenced",
		"gcp-lb/lab/us-central1/proxy-web unchanged days_left=60",
		"gcp-lb/lab/global/proxy-g skipped certificate managed-expired is Google-managed and renewed by Google",
		"gcp-lb/lab/global/proxy-map skipped uses the certificate map m; not managed by polyctl",
	} {
		if !slices.Contains(rows, w) {
			t.Errorf("missing row %q in\n%s", w, strings.Join(rows, "\n"))
		}
	}
	if !slices.ContainsFunc(d.notes, func(n string) bool { return strings.Contains(n, "managed certificate managed-expired expired") }) {
		t.Errorf("notes = %v", d.notes)
	}
	// Nothing to do the second time.
	if _, err := d.run(cert.DeployOptions{}); err != nil || len(g.lbWrites()) != 0 {
		t.Errorf("second run: %v %v", err, g.lbWrites())
	}
	// --region limits the scan; "global" names the global proxies.
	rep, _ = d.run(cert.DeployOptions{}, "global")
	if slices.ContainsFunc(reportRows(rep), func(r string) bool { return strings.Contains(r, "us-central1") }) {
		t.Errorf("--region global: %v", reportRows(rep))
	}
}

func TestGCPDeployerKeepsTheCertificateOfAnotherKeyType(t *testing.T) {
	d := newGCPDeploy(t)
	g := d.h.gce
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaOld := pairWith(t, rsaKey, rsaKey, []string{"example.com", "*.example.com"}, 20)
	ecOld := newPair(t, []string{"example.com", "*.example.com"}, 20)
	rsaOnly := pairWith(t, rsaKey, rsaKey, []string{"example.org"}, 10)
	g.addCert("us-central1", "example-com-rsa", rsaOld.chain)
	g.addCert("us-central1", "example-com-ec", ecOld.chain)
	g.addCert("us-central1", "example-org-rsa", rsaOnly.chain)
	g.addHTTPSProxy("us-central1", "proxy-web", "lb-web", "example-com-rsa", "example-com-ec", "example-org-rsa")
	g.addRule("us-central1", "fr-web", "targetHttpsProxies/proxy-web", "34.1.2.3", "443", nil)
	d.bundle("example.com", 90)
	d.bundle("example.org", 90)
	rep, err := d.run(cert.DeployOptions{})
	if err != nil {
		t.Fatalf("deploy: %v\n%s", err, strings.Join(reportRows(rep), "\n"))
	}
	if certs := g.proxyCerts("us-central1", "proxy-web"); !slices.Equal(certs, []string{"example-com-rsa", "cert-example-com-20260401", "cert-example-org-20260401"}) {
		t.Errorf("proxy certificates = %v", certs)
	}
	if g.cert("us-central1", "example-com-rsa") == nil || g.cert("us-central1", "example-com-ec") != nil {
		t.Error("the RSA certificate must be kept, the ECDSA one replaced")
	}
	rows := reportRows(rep)
	for _, w := range []string{
		"gcp-lb/lab/us-central1/ssl-certificate/example-com-rsa skipped RSA certificate example-com-rsa of example.com kept on proxy-web beside the ECDSA one: the store has no RSA certificate of example.com",
		"gcp-lb/lab/us-central1/proxy-web updated example-com-ec,example-org-rsa -> cert-example-com-20260401,cert-example-org-20260401 (key type changes, example-org-rsa: RSA -> ECDSA)",
	} {
		if !slices.Contains(rows, w) {
			t.Errorf("missing row %q in\n%s", w, strings.Join(rows, "\n"))
		}
	}
	// The next run keeps the RSA certificate although the proxy's ECDSA
	// certificate is no longer due.
	rep, err = d.run(cert.DeployOptions{})
	if err != nil || len(g.lbWrites()) != 0 {
		t.Fatalf("second run: %v %v\n%s", err, g.lbWrites(), strings.Join(reportRows(rep), "\n"))
	}
}

func TestGCPDeployerNamesAndFailures(t *testing.T) {
	d := newGCPDeploy(t)
	g := d.h.gce
	old := newPair(t, []string{"example.com"}, 5)
	g.addCert("global", "example-com-old", old.chain)
	g.addHTTPSProxy("global", "proxy-a", "lb-a", "example-com-old")
	g.addHTTPSProxy("global", "proxy-b", "lb-b", "example-com-old")
	g.addRule("global", "fr-a", "targetHttpsProxies/proxy-a", "34.8.8.8", "443", nil)
	b := d.bundle("example.com", 90)
	// The name is taken by another certificate: the serial number is
	// appended, and the proxy references the name actually created.
	other := newPair(t, []string{"example.com"}, 90)
	g.addCert("global", "cert-example-com-20260401", other.chain)
	rep, err := d.run(cert.DeployOptions{Domain: "example.com"})
	if err != nil {
		t.Fatalf("deploy: %v %v", err, reportRows(rep))
	}
	alt := "cert-example-com-20260401-" + strings.TrimLeft(b.Serial, "0")
	if certs := g.proxyCerts("global", "proxy-a"); !slices.Equal(certs, []string{alt}) {
		t.Errorf("proxy-a = %v", certs)
	}
	// proxy-b still uses the old one: it is kept, and that is no failure.
	if g.cert("global", "example-com-old") == nil ||
		!slices.Contains(reportRows(rep), "gcp-lb/lab/global/ssl-certificate/example-com-old skipped old, still used by proxy-b; kept") {
		t.Errorf("rows = %v", reportRows(rep))
	}
	// A failed insert stops the replacement of that proxy only.
	d2 := newGCPDeploy(t)
	g2 := d2.h.gce
	g2.addCert("global", "example-com-old", old.chain)
	g2.addHTTPSProxy("global", "proxy-a", "lb-a", "example-com-old")
	g2.addRule("global", "fr-a", "targetHttpsProxies/proxy-a", "34.8.8.8", "443", nil)
	d2.bundle("example.com", 90)
	g2.opFail["insertSslCertificate"] = compute.OperationErrorErrors{Code: "INTERNAL_ERROR", Message: "x"}
	rep, err = d2.run(cert.DeployOptions{})
	if exitClass(err) != "general" || !slices.Equal(g2.proxyCerts("global", "proxy-a"), []string{"example-com-old"}) {
		t.Errorf("failed insert: %v %v", err, reportRows(rep))
	}
	// A dry run writes nothing.
	delete(g2.opFail, "insertSslCertificate")
	rep, err = d2.run(cert.DeployOptions{DryRun: true})
	if err != nil || len(g2.lbWrites()) != 0 ||
		!slices.Contains(reportRows(rep), "gcp-lb/lab/global/proxy-a would_update example-com-old -> cert-example-com-20260401") {
		t.Errorf("dry run: %v %v %v", err, g2.lbWrites(), reportRows(rep))
	}
}

func TestGCPDeployerPrune(t *testing.T) {
	d := newGCPDeploy(t)
	g := d.h.gce
	gone := newPair(t, []string{"gone.com"}, -3)
	used := newPair(t, []string{"used.com"}, -1)
	g.addCert("global", "gone-com", gone.chain)
	g.addCert("us-central1", "used-com", used.chain)
	g.addHTTPSProxy("us-central1", "proxy-u", "lb-u", "used-com")
	rep, err := d.run(cert.DeployOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	rows := reportRows(rep)
	if g.cert("global", "gone-com") != nil || g.cert("us-central1", "used-com") == nil ||
		!slices.Contains(rows, "gcp-lb/lab/global/ssl-certificate/gone-com deleted cert=gone-com expired (2025-12-29)") ||
		!slices.Contains(rows, "gcp-lb/lab/us-central1/ssl-certificate/used-com skipped cert=used-com expired (2025-12-31); still used by proxy-u") {
		t.Errorf("rows = %v", rows)
	}
}

func TestCertInUseWithoutReason(t *testing.T) {
	regional := &googleapi.Error{Code: 400, Message: "The ssl_certificate resource 'projects/p/regions/r/sslCertificates/old' is already being used by 'projects/p/regions/r/targetHttpsProxies/px'"}
	if !certInUse(regional) || inUseBy(regional) != "px" {
		t.Errorf("regional in-use error not recognized: %v", regional)
	}
	if certInUse(&googleapi.Error{Code: 400, Message: "invalid"}) || certInUse(nil) {
		t.Error("other errors taken as in use")
	}
}
