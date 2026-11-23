package gcp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func TestDiscoverHTTPSTargets(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	h.gce.addRule("global", "fr-g", "targetHttpsProxies/proxy-https-g", "34.8.8.8", "443-443", nil)
	h.gce.addRule("us-central1", "fr-range", "targetHttpsProxies/proxy-https-a", "34.1.1.1", "80-443", nil)
	h.gce.addRule("us-central1", "fr-single", "targetHttpsProxies/proxy-https-b", "34.1.1.2", "443", nil)
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
	if want := []string{"global/proxy-https-g", "regional, us-central1/proxy-https-a", "regional, us-central1/proxy-https-b"}; !slices.Equal(got, want) {
		t.Errorf("targets = %v", got)
	}
}

func TestRenewProxyCertificates(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	due := newPair(t, []string{"example.com", "*.example.com"}, 20)
	fresh := newPair(t, []string{"fresh.com"}, 60)
	broken := newPair(t, []string{"broken.com"}, 5)
	nodns := newPair(t, []string{"nodns.com"}, 5)
	h.gce.addCert("us-central1", "example-com-old", due.chain)
	h.gce.addCert("us-central1", "fresh-com", fresh.chain)
	h.gce.addCert("us-central1", "broken-com", broken.chain)
	h.gce.addCert("us-central1", "nodns-com", nodns.chain)
	h.gce.addManagedCert("global", "managed-expired", []string{"www.example.com"}, "2025-12-01T00:00:00.000-08:00")
	h.gce.addManagedCert("global", "managed-ok", []string{"ok.example.com"}, "2026-06-01T00:00:00.000-08:00")
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", "example-com-old", "fresh-com", "broken-com", "nodns-com")
	h.gce.addHTTPSProxy("global", "proxy-https-g", "lb-g", "managed-expired", "managed-ok")
	h.gce.addRule("us-central1", "fr-https-web-1", "targetHttpsProxies/proxy-https-web-1", "34.1.2.3", "443-443", nil)
	h.gce.addRule("global", "fr-https-g", "targetHttpsProxies/proxy-https-g", "34.8.8.8", "443", nil)
	c, err := openProfile(t.Context(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	nw := newPair(t, []string{"example.com", "*.example.com"}, 90)
	var ensured []string
	var notified []string
	var warnings []string
	o := renewOptions{Days: 30, EnsureDays: 35,
		Ensure: func(_ context.Context, domain string, days int) (*platform.CertMaterial, error) {
			ensured = append(ensured, domain)
			if days != 35 {
				t.Errorf("ensure days = %d", days)
			}
			switch domain {
			case "broken.com":
				return nil, errors.New("rate limited")
			case "nodns.com":
				return nil, platform.ErrNotFound
			}
			return platform.ParseCertMaterial(nw.chain, nw.key, harnessNow)
		},
		Notify: func(_ context.Context, domain string, err error) {
			notified = append(notified, domain+": "+err.Error())
		},
		Infof: func(f string, a ...any) { warnings = append(warnings, fmt.Sprintf(f, a...)) },
	}
	// A dry run writes nothing.
	o.DryRun = true
	if _, err := c.renewProxyCertificates(t.Context(), &config.Config{}, o); exitClass(err) != "general" || len(h.gce.lbWrites()) != 0 {
		t.Errorf("dry run = %v %v", err, h.gce.lbWrites())
	}
	o.DryRun = false
	ensured, notified, warnings = nil, nil, nil
	changes, err := c.renewProxyCertificates(t.Context(), &config.Config{}, o)
	var partial *platform.PartialError
	if !errors.As(err, &partial) || partial.Failed != 1 {
		t.Fatalf("err = %v", err)
	}
	if !slices.Equal(ensured, []string{"example.com", "broken.com", "nodns.com"}) {
		t.Errorf("ensured = %v", ensured)
	}
	if len(notified) != 1 || !strings.HasPrefix(notified[0], "broken.com: ") {
		t.Errorf("notified = %v", notified)
	}
	got := rows(platform.Report{Changes: changes})
	if !slices.Contains(got, "ssl-certificate/example-com-cert-20260101 created regional, us-central1, expires 2026-04-01") ||
		!slices.Contains(got, "ssl-certificate/example-com-old deleted old, no longer referenced") {
		t.Errorf("changes = %v", got)
	}
	if certs := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(certs, []string{"fresh-com", "broken-com", "nodns-com", "example-com-cert-20260101"}) {
		t.Errorf("certs = %v", certs)
	}
	// The managed certificates are never touched; the expired one warns.
	if h.gce.cert("global", "managed-expired") == nil || slices.ContainsFunc(h.gce.lbWrites(), func(w string) bool { return strings.HasPrefix(w, "POST global") }) {
		t.Errorf("managed touched: %v", h.gce.lbWrites())
	}
	joined := strings.Join(warnings, "\n")
	if !strings.Contains(joined, "managed certificate") {
		t.Errorf("warnings = %v", warnings)
	}
	j := judgeCert(h.gce.cert("global", "managed-expired"), harnessNow, 30, "proj", "")
	if j.renew || !strings.Contains(j.warning, "expired 31 days ago") || !strings.Contains(j.warning, "lbCertificates/details/managed-expired?project=proj") {
		t.Errorf("judgement = %+v", j)
	}
	if j := judgeCert(h.gce.cert("us-central1", "fresh-com"), harnessNow, 30, "proj", "us-central1"); j.renew || j.warning != "" {
		t.Errorf("fresh = %+v", j)
	}
}
