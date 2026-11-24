package gcp

import (
	"context"
	"errors"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

// stubStore makes the local store answer with the pair (nil: a dry run
// that would issue the certificate) and records the calls.
func stubStore(t *testing.T, p *pemPair) *[]string {
	t.Helper()
	var calls []string
	old := ensureCert
	t.Cleanup(func() { ensureCert = old })
	ensureCert = func(ctx context.Context, rt *app.Runtime, domain string, days int) (*cert.Result, error) {
		calls = append(calls, domain)
		root, _ := cert.RootDomain(domain)
		if p == nil {
			if !rt.DryRun() {
				return nil, errors.New("would issue outside a dry run")
			}
			return &cert.Result{DryRun: true, Changes: []platform.Change{{Resource: "cert/" + root, Action: platform.WouldCreate, Detail: "no certificate in the store"}}}, nil
		}
		b, err := cert.NewBundle(root, p.chain, p.key)
		if err != nil {
			return nil, err
		}
		return &cert.Result{Bundle: b, Changes: []platform.Change{{Resource: "cert/" + root, Action: platform.Unchanged, Detail: "existing"}}}, nil
	}
	return &calls
}

// regionalLB is lb-web-1 in us-central1: URL map, HTTP proxy and :80 rule,
// HTTPS proxy and :443 rule on one IP, the HTTPS proxy holding certs.
func regionalLB(f *fakeCompute, certs ...string) {
	f.addURLMap("us-central1", "lb-web-1")
	f.addHTTPProxy("us-central1", "proxy-web-1", "lb-web-1")
	f.addRule("us-central1", "fr-web-1", "targetHttpProxies/proxy-web-1", "34.1.2.3", "80-80", nil)
	f.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", certs...)
	f.addRule("us-central1", "fr-https-web-1", "targetHttpsProxies/proxy-https-web-1", "34.1.2.3", "443-443", nil)
}

func TestLBCertSetAddsCertificate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	other := newPair(t, []string{"other.com"}, 90)
	h.gce.addCert("us-central1", "other-com-cert", other.chain)
	regionalLB(h.gce, "other-com-cert")
	p := newPair(t, []string{"example.com", "*.example.com"}, 90)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	want := []string{
		"ssl-certificate/example-com-cert-20260101 created regional, us-central1, expires 2026-04-01",
		"target-https-proxy/proxy-https-web-1 updated certs: + example-com-cert-20260101",
		"forwarding-rule/fr-https-web-1 unchanged :443, ip 34.1.2.3",
	}
	if got := rows(rep); !slices.Equal(got, want) {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	if rep.Target.Region != "us-central1" || rep.Target.Domain != "example.com" || rep.Target.Profile != "lab" {
		t.Errorf("target = %+v", rep.Target)
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST us-central1/sslCertificates", "POST us-central1/targetHttpsProxies/proxy-https-web-1/setSslCertificates"}) {
		t.Errorf("writes = %v", w)
	}
	if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(got, []string{"other-com-cert", "example-com-cert-20260101"}) {
		t.Errorf("certs = %v", got)
	}
	// Again: the proxy holds the leaf, even as PEM text with other line
	// ends; nothing is written.
	h.gce.mu.Lock()
	sc := h.gce.lb().certs["proj/us-central1/example-com-cert-20260101"]
	sc.Certificate = strings.ReplaceAll(sc.Certificate, "\n", "\r\n") + "\n\n"
	h.gce.mu.Unlock()
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile); err != nil {
		t.Fatal(err)
	}
	if w := h.gce.lbWrites(); len(w) != 0 {
		t.Errorf("second run writes = %v", w)
	}
	if got := rows(h.report()); !slices.Contains(got, "target-https-proxy/proxy-https-web-1 unchanged already holds the certificate") {
		t.Errorf("second run = %v", got)
	}
}

func TestLBCertSetReplacesFromStore(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	old := newPair(t, []string{"example.com", "*.example.com"}, 10)
	other := newPair(t, []string{"other.com"}, 90)
	h.gce.addCert("us-central1", "example-com-cert-20251001", old.chain)
	h.gce.addCert("us-central1", "other-com-cert", other.chain)
	regionalLB(h.gce, "example-com-cert-20251001", "other-com-cert")
	nw := newPair(t, []string{"example.com", "*.example.com"}, 90)
	calls := stubStore(t, &nw)
	// Routed by the name of a forwarding rule (the inventory is synced).
	if err := h.run("compute", "load-balancer", "cert", "set", "fr-https-web-1", "--domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"cert/example.com unchanged existing",
		"ssl-certificate/example-com-cert-20260101 created regional, us-central1, expires 2026-04-01",
		"target-https-proxy/proxy-https-web-1 updated certs: example-com-cert-20251001 -> example-com-cert-20260101",
		"forwarding-rule/fr-https-web-1 unchanged :443, ip 34.1.2.3",
		"ssl-certificate/example-com-cert-20251001 deleted old, no longer referenced",
	}
	got := rows(h.report())
	slices.Sort(got[1:])
	slices.Sort(want[1:])
	if !slices.Equal(got, want) || !slices.Equal(*calls, []string{"example.com"}) {
		t.Errorf("report =\n%s\ncalls %v", strings.Join(got, "\n"), *calls)
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST us-central1/sslCertificates", "POST us-central1/targetHttpsProxies/proxy-https-web-1/setSslCertificates",
		"DELETE us-central1/sslCertificates/example-com-cert-20251001"}) {
		t.Errorf("writes = %v", w)
	}
	if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(got, []string{"other-com-cert", "example-com-cert-20260101"}) {
		t.Errorf("certs = %v", got)
	}
}

func TestLBCertSetKeepsCertificatesTheNewOneDoesNotCover(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	apex := newPair(t, []string{"example.com"}, 10)
	wild := newPair(t, []string{"*.example.com"}, 90)
	multi := newPair(t, []string{"example.com", "other.org"}, 90)
	h.gce.addCert("us-central1", "apex-cert", apex.chain)
	h.gce.addCert("us-central1", "wildcard-cert", wild.chain)
	h.gce.addCert("us-central1", "multi-cert", multi.chain)
	regionalLB(h.gce, "apex-cert", "wildcard-cert", "multi-cert")
	nw := newPair(t, []string{"example.com"}, 90)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", nw.certFile, "--key-file", nw.keyFile); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	for _, w := range []string{
		"target-https-proxy/proxy-https-web-1 updated certs: apex-cert -> example-com-cert-20260101",
		"ssl-certificate/wildcard-cert skipped kept on the proxy beside the new certificate: the new certificate does not cover *.example.com",
		"ssl-certificate/multi-cert skipped kept on the proxy beside the new certificate: the new certificate does not cover other.org",
		"ssl-certificate/apex-cert deleted old, no longer referenced",
	} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, strings.Join(got, "\n"))
		}
	}
	if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(got, []string{"wildcard-cert", "multi-cert", "example-com-cert-20260101"}) {
		t.Errorf("certs = %v", got)
	}
}

func TestLBCertSetKeepsACertificateAddedWhileTheNewOneIsCreated(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	old := newPair(t, []string{"example.com", "*.example.com"}, 10)
	late := newPair(t, []string{"late.org"}, 90)
	h.gce.addCert("us-central1", "example-com-old", old.chain)
	h.gce.addCert("us-central1", "late-cert", late.chain)
	regionalLB(h.gce, "example-com-old")
	h.gce.mu.Lock()
	h.gce.lb().afterCertInsert = func(lb *lbFake) {
		p := lb.httpsProxies["proj/us-central1/proxy-https-web-1"]
		p.SslCertificates = append(p.SslCertificates, selfLink("proj", "us-central1", "sslCertificates", "late-cert"))
	}
	h.gce.mu.Unlock()
	nw := newPair(t, []string{"example.com", "*.example.com"}, 90)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", nw.certFile, "--key-file", nw.keyFile); err != nil {
		t.Fatal(err)
	}
	if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(got, []string{"late-cert", "example-com-cert-20260101"}) {
		t.Errorf("certs = %v", got)
	}
}

func TestLBCertSetResumes(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	old := newPair(t, []string{"example.com"}, 10)
	nw := newPair(t, []string{"example.com"}, 90)
	// A run created the new certificate and failed to switch the proxy.
	h.gce.addCert("us-central1", "example-com-cert-20251001", old.chain)
	h.gce.addCert("us-central1", "example-com-cert-20260101", nw.chain)
	regionalLB(h.gce, "example-com-cert-20251001")
	stubStore(t, &nw)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--keep-old"); err != nil {
		t.Fatal(err)
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST us-central1/targetHttpsProxies/proxy-https-web-1/setSslCertificates"}) {
		t.Errorf("writes = %v", w)
	}
	got := rows(h.report())
	if !slices.Contains(got, "ssl-certificate/example-com-cert-20260101 unchanged existing, holds the same certificate (regional, us-central1)") ||
		!slices.Contains(got, "ssl-certificate/example-com-cert-20251001 skipped old, kept (--keep-old)") {
		t.Errorf("report = %v", got)
	}
	// Switched, the old one left behind: unchanged, the leftover stays.
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	if w := h.gce.lbWrites(); len(w) != 0 || h.gce.cert("us-central1", "example-com-cert-20251001") == nil {
		t.Errorf("writes = %v", w)
	}
}

func TestLBCertSetDryRunIssuesNothing(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, nil)
	old := newPair(t, []string{"example.com"}, 10)
	h.gce.addCert("us-central1", "example-com-cert-20251001", old.chain)
	regionalLB(h.gce, "example-com-cert-20251001")
	stubStore(t, nil)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com"); err != nil {
		t.Fatal(err)
	}
	rep := h.report()
	want := []string{
		"cert/example.com would_create no certificate in the store (not issued in dry-run)",
		"ssl-certificate/example-com-cert-20260101 would_create regional, us-central1",
		"target-https-proxy/proxy-https-web-1 would_update certs: example-com-cert-20251001 -> example-com-cert-20260101",
		"forwarding-rule/fr-https-web-1 unchanged :443, ip 34.1.2.3",
		"ssl-certificate/example-com-cert-20251001 would_delete old, after switch",
	}
	if got := rows(rep); !rep.DryRun || !slices.Equal(got, want) {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	if w := h.gce.lbWrites(); len(w) != 0 {
		t.Errorf("writes = %v", w)
	}
}

func TestLBCertSetGlobal(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	old := newPair(t, []string{"example.com"}, 10)
	h.gce.addCert("global", "example-com-old", old.chain)
	h.gce.addURLMap("global", "lb-g")
	h.gce.addHTTPSProxy("global", "proxy-https-g", "lb-g", "example-com-old")
	h.gce.addRule("global", "fr-https-g", "targetHttpsProxies/proxy-https-g", "34.8.8.8", "443", nil)
	nw := newPair(t, []string{"example.com"}, 90)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-g", "--domain", "example.com", "--cert-file", nw.certFile, "--key-file", nw.keyFile); err != nil {
		t.Fatal(err)
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST global/sslCertificates", "POST global/targetHttpsProxies/proxy-https-g/setSslCertificates",
		"DELETE global/sslCertificates/example-com-old"}) {
		t.Errorf("writes = %v", w)
	}
	if got := h.gce.proxyCerts("global", "proxy-https-g"); !slices.Equal(got, []string{"example-com-cert-20260101"}) {
		t.Errorf("certs = %v", got)
	}
	// A global load balancer without an HTTPS proxy is not upgraded.
	h.gce.addURLMap("global", "lb-plain")
	h.gce.addHTTPProxy("global", "proxy-plain", "lb-plain")
	err := h.run("compute", "load-balancer", "cert", "set", "lb-plain", "--domain", "example.com", "--cert-file", nw.certFile, "--key-file", nw.keyFile)
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "regional load balancers only") {
		t.Errorf("global upgrade = %v", err)
	}
}

func TestLBCertSetUpgradesHTTP(t *testing.T) {
	for _, tc := range []struct {
		name   string
		static bool
		newIP  bool
	}{{"ephemeral", false, false}, {"static", true, false}, {"new ip", false, true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGCPHarness(t, app.Flags{}, nil)
			h.gce.addURLMap("us-central1", "lb-web-1")
			h.gce.addHTTPProxy("us-central1", "proxy-web-1", "lb-web-1")
			h.gce.addRule("us-central1", "fr-web-1", "targetHttpProxies/proxy-web-1", "34.1.2.3", "80-80", map[string]string{"polyctl-lb": "lb-web-1"})
			if tc.static {
				h.gce.addAddress("us-central1", &compute.Address{Name: "web-ip", Address: "34.1.2.3", AddressType: addrExternal})
			}
			p := newPair(t, []string{"example.com"}, 90)
			args := []string{"compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile}
			if tc.newIP {
				args = append(args, "--new-ip")
			}
			if err := h.run(args...); err != nil {
				t.Fatal(err)
			}
			writes := []string{"POST us-central1/sslCertificates", "POST us-central1/targetHttpsProxies"}
			if !tc.static && !tc.newIP {
				writes = append(writes, "POST us-central1/addresses")
			}
			writes = append(writes, "POST us-central1/forwardingRules", "POST us-central1/forwardingRules/fr-https-web-1/setLabels")
			if w := h.gce.lbWrites(); !slices.Equal(w, writes) {
				t.Errorf("writes = %v\nwant     %v", w, writes)
			}
			fr := h.gce.rule("us-central1", "fr-https-web-1")
			if fr == nil || fr.PortRange != "443" || lastSegment(fr.Target) != "proxy-https-web-1" || fr.Labels["polyctl-lb"] != "lb-web-1" {
				t.Fatalf("rule = %+v", fr)
			}
			if (fr.IPAddress == "34.1.2.3") == tc.newIP {
				t.Errorf("ip = %s", fr.IPAddress)
			}
			if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(got, []string{"example-com-cert-20260101"}) {
				t.Errorf("https proxy certs = %v", got)
			}
			got := rows(h.report())
			if !tc.static && !tc.newIP {
				if a := h.gce.address("us-central1", "lb-web-1-ip"); a == nil || a.Address != "34.1.2.3" {
					t.Errorf("address = %+v", a)
				}
				if !slices.Contains(got, "address/lb-web-1-ip created promoted from ephemeral 34.1.2.3") {
					t.Errorf("report = %v", got)
				}
			}
			if !tc.newIP && !slices.Contains(got, "forwarding-rule/fr-https-web-1 created :443, ip 34.1.2.3 (same as :80)") {
				t.Errorf("report = %v", got)
			}
			if !strings.Contains(h.stderr.String(), "https://"+fr.IPAddress+"/") {
				t.Errorf("stderr = %s", h.stderr.String())
			}
		})
	}
}

func TestLBCertSetUpgradeDryRun(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, nil)
	h.gce.addURLMap("us-central1", "lb-web-1")
	h.gce.addHTTPProxy("us-central1", "proxy-web-1", "lb-web-1")
	h.gce.addRule("us-central1", "fr-web-1", "targetHttpProxies/proxy-web-1", "34.1.2.3", "80-80", nil)
	p := newPair(t, []string{"example.com"}, 90)
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ssl-certificate/example-com-cert-20260101 would_create regional, us-central1, expires 2026-04-01",
		"target-https-proxy/proxy-https-web-1 would_create URL map lb-web-1, certs: example-com-cert-20260101",
		"address/lb-web-1-ip would_create promote ephemeral 34.1.2.3",
		"forwarding-rule/fr-https-web-1 would_create :443, ip 34.1.2.3 (same as :80)",
	}
	if got := rows(h.report()); !slices.Equal(got, want) || len(h.gce.lbWrites()) != 0 {
		t.Errorf("report =\n%s\nwrites %v", strings.Join(got, "\n"), h.gce.lbWrites())
	}
}

func TestLBCertSetErrors(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	regionalLB(h.gce, "x")
	h.gce.addCert("us-central1", "x", newPair(t, []string{"x.example.org"}, 90).chain)
	p := newPair(t, []string{"example.com"}, 90)
	// The certificate does not cover the domain: nothing is called.
	err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "www.example.com", "--cert-file", p.certFile, "--key-file", p.keyFile)
	if exitClass(err) != "usage" || len(h.gce.calls) != 0 {
		t.Errorf("not covered = %v, calls %v", err, h.gce.calls)
	}
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1"); exitClass(err) != "usage" {
		t.Errorf("no domain = %v", err)
	}
	if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile); exitClass(err) != "usage" {
		t.Errorf("no key = %v", err)
	}
	if err := h.run("compute", "load-balancer", "cert", "set", "nope", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
	// 15 certificates already: exit code 1 before anything is written.
	var many []string
	for i := range 15 {
		n := "c" + string(rune('a'+i))
		h.gce.addCert("us-central1", n, newPair(t, []string{n + ".example.org"}, 90).chain)
		many = append(many, n)
	}
	h.gce.addURLMap("us-central1", "lb-full")
	h.gce.addHTTPSProxy("us-central1", "proxy-https-full", "lb-full", many...)
	err = h.run("compute", "load-balancer", "cert", "set", "lb-full", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile)
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "at most 15") || len(h.gce.lbWrites()) != 0 {
		t.Errorf("full = %v %v", err, h.gce.lbWrites())
	}
	// The store cannot issue the domain: a general failure with a hint.
	old := ensureCert
	t.Cleanup(func() { ensureCert = old })
	ensureCert = func(context.Context, *app.Runtime, string, int) (*cert.Result, error) {
		return nil, errors.Join(platform.ErrNotFound, errors.New("no DNS account hosts example.com"))
	}
	err = h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "--cert-file") {
		t.Errorf("store = %v", err)
	}
}

func TestLBCertSetRouting(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.addProfile()
	regionalLB(h.gce, "x")
	h.gce.addCert("us-central1", "x", newPair(t, []string{"x.example.org"}, 90).chain)
	h.gce.mu.Lock()
	h.gce.lb().urlMaps["other/europe-west1/lb-web-1"] = &compute.UrlMap{Name: "lb-web-1", Region: apiBase + "projects/other/regions/europe-west1"}
	h.gce.mu.Unlock()
	p := newPair(t, []string{"example.com"}, 90)
	args := []string{"compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile}
	if err := h.run(args...); exitClass(err) != "ambiguous" {
		t.Errorf("two projects = %v", err)
	}
	h.rt.Flags.DryRun = true
	defer func() { h.rt.Flags.DryRun = false }()
	if err := h.run(append(args, "--region", "us-central1")...); err != nil {
		t.Errorf("--region = %v", err)
	}
	h.rt.Flags.Profile = "lab"
	defer func() { h.rt.Flags.Profile = "" }()
	if err := h.run(args...); err != nil || h.report().Target.Profile != "lab" {
		t.Errorf("--profile = %v", err)
	}
	h.rt.Flags.Offline = true
	defer func() { h.rt.Flags.Offline = false }()
	if err := h.run(args...); exitClass(err) != "offline" {
		t.Errorf("offline = %v", err)
	}
}

func TestLBCertSetProfileWithoutGCPAccount(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	cfg, err := config.Load(filepath.Join(h.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Profiles["dns"] = &config.Profile{Platforms: map[platform.ID]*config.Account{platform.Cloudflare: {Metadata: map[string]string{}}}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, err := h.rt.ReloadConfig(); err != nil {
		t.Fatal(err)
	}
	p := newPair(t, []string{"example.com"}, 90)
	args := []string{"compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile}
	h.rt.Flags.Profile = "dns"
	defer func() { h.rt.Flags.Profile = "" }()
	if err := h.run(args...); exitClass(err) != "unsupported" {
		t.Errorf("profile without gcp = %v", err)
	}
	h.rt.Flags.Profile = "nope"
	if err := h.run(args...); exitClass(err) != "notfound" {
		t.Errorf("unknown profile = %v", err)
	}
}

// An internal managed load balancer: the :80 IP is an internal address, so
// the :443 rule shares it through an internal SHARED_LOADBALANCER_VIP
// address in the :80 rule's subnetwork, on the upgrade path and on the path
// of an HTTPS proxy without a :443 rule. An internal address with another
// purpose is refused before anything is written.
func TestLBCertSetInternalManaged(t *testing.T) {
	const subnet = apiBase + "projects/proj/regions/us-central1/subnetworks/default"
	internalLB := func(h *gcpHarness) {
		h.gce.addURLMap("us-central1", "lb-web-1")
		h.gce.addHTTPProxy("us-central1", "proxy-web-1", "lb-web-1")
		h.gce.addRule("us-central1", "fr-web-1", "targetHttpProxies/proxy-web-1", "10.128.0.50", "80-80", nil)
		fr := h.gce.rule("us-central1", "fr-web-1")
		h.gce.mu.Lock()
		fr.LoadBalancingScheme, fr.NetworkTier, fr.Subnetwork = "INTERNAL_MANAGED", "", subnet
		h.gce.mu.Unlock()
	}
	for _, tc := range []struct {
		name  string
		proxy bool
	}{{"upgrade", false}, {"proxy without :443 rule", true}} {
		t.Run(tc.name, func(t *testing.T) {
			h := newGCPHarness(t, app.Flags{}, nil)
			internalLB(h)
			if tc.proxy {
				h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1")
			}
			p := newPair(t, []string{"example.com"}, 90)
			if err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile); err != nil {
				t.Fatalf("%v\n%s", err, h.stderr.String())
			}
			a := h.gce.address("us-central1", "lb-web-1-ip")
			if a == nil || a.Address != "10.128.0.50" || a.AddressType != addrInternal || a.Purpose != purposeSharedVIP || a.Subnetwork != subnet || a.NetworkTier != "" {
				t.Errorf("address = %+v", a)
			}
			fr := h.gce.rule("us-central1", "fr-https-web-1")
			if fr == nil || fr.IPAddress != "10.128.0.50" || fr.LoadBalancingScheme != "INTERNAL_MANAGED" || fr.Subnetwork != subnet {
				t.Errorf("rule = %+v", fr)
			}
		})
	}
	h := newGCPHarness(t, app.Flags{}, nil)
	internalLB(h)
	h.gce.addAddress("us-central1", &compute.Address{Name: "web-vip", Address: "10.128.0.50", AddressType: addrInternal, Purpose: "GCE_ENDPOINT", Subnetwork: subnet})
	p := newPair(t, []string{"example.com"}, 90)
	err := h.run("compute", "load-balancer", "cert", "set", "lb-web-1", "--domain", "example.com", "--cert-file", p.certFile, "--key-file", p.keyFile)
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "--new-ip") || len(h.gce.lbWrites()) != 0 {
		t.Errorf("other purpose = %v, writes %v", err, h.gce.lbWrites())
	}
}
