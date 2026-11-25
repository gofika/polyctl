package gcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// interactiveLB is lbHarness in the interactive flow.
func interactiveLB(t *testing.T) *gcpHarness {
	t.Helper()
	h := lbHarness(t, app.Flags{NonInteractiveSet: true})
	h.rt.Picker = prompttest.New(t)
	return h
}

// ensure without <instance> and --protocol picks a running instance and
// the protocol; https without --ssl-certificate picks a certificate of the
// region, or creates a new one as the first step.
func TestLBEnsureAsks(t *testing.T) {
	h := interactiveLB(t)
	stopped := h.gce.addInstance("proj", "us-central1-a", "old-1", "10.128.0.9", "")
	stopped.Status = statusTerminated
	p := h.answer("http", prompttest.Label("web-1"))
	if err := h.run("compute", "load-balancer", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Labels(p.Find("Instance").Options); strings.Contains(v, "old-1") {
		t.Errorf("instances offered:\n%s", v)
	}
	if h.gce.rule("us-central1", "fr-web-1") == nil {
		t.Errorf("no forwarding rule")
	}

	// https: an expired certificate is not offered; a new one is created
	// first from files.
	h.gce.addCert("us-central1", "old-cert", newPair(t, []string{"example.com"}, -1).chain)
	h.gce.addCert("us-central1", "other-cert", newPair(t, []string{"other.com"}, 30).chain)
	pair := newPair(t, []string{"example.com"}, 90)
	p = h.answer("https", prompttest.Label("Create a new certificate"), pair.certFile, pair.keyFile, prompttest.KeepDefault{})
	if err := h.run("compute", "load-balancer", "ensure", "web-1"); err != nil {
		t.Fatalf("https: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[1].Options); strings.Contains(l, "old-cert") || !strings.Contains(l, "other-cert  us-central1  SELF_MANAGED  other.com") {
		t.Errorf("expired certificate offered:\n%s", l)
	}
	if certs := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(certs, []string{"example-com-cert-20260101"}) {
		t.Errorf("proxy certs %v", certs)
	}

	h.nonInteractive()
	if err := h.run("compute", "load-balancer", "ensure", "web-1"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--protocol") {
		t.Errorf("non-interactive = %v", err)
	}
}

// get and delete without <name> offer the load balancers; cert set offers
// the HTTP(S) ones and the domains of the proxies' certificates.
func TestLBPicks(t *testing.T) {
	h := interactiveLB(t)
	h.gce.addCert("us-central1", "other-com-cert", newPair(t, []string{"other.com"}, 90).chain)
	regionalLB(h.gce, "other-com-cert")
	h.gce.addCheck("us-central1", "check-80", 80)
	h.gce.addGroup("us-central1-a", "ig-db", map[string]int64{"port-3306": 3306})
	h.gce.addBackend("us-central1", "bs-db", "TCP", "port-3306", "check-80", "us-central1-a/ig-db")
	h.gce.addTCPProxy("us-central1", "proxy-tcp-db", "bs-db")
	h.gce.addRule("us-central1", "fr-tcp-db", "targetTcpProxies/proxy-tcp-db", "34.9.9.9", "3306-3306", map[string]string{lbLabel: "lb-tcp-db"})

	p := h.answer(prompttest.Label("lb-web-1"))
	if err := h.run("compute", "load-balancer", "get"); err != nil || !strings.Contains(h.stdout.String(), `"lb-web-1"`) {
		t.Fatalf("get = %v", err)
	}
	if l := prompttest.Labels(p.Find("Load balancer").Options); !strings.Contains(l, "lb-web-1  us-central1  HTTP,HTTPS  34.1.2.3:443, 34.1.2.3:80  project proj  gcp/lab") || !strings.Contains(l, "lb-tcp-db") {
		t.Errorf("load balancers offered:\n%s", l)
	}

	stubStore(t, nil)
	p = h.answer(prompttest.Label("lb-web-1"), "other.com")
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "load-balancer", "cert", "set"); err != nil {
		t.Fatalf("cert set: %v\n%s", err, h.stderr.String())
	}
	h.rt.Flags.DryRun = false
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); strings.Contains(l, "lb-tcp-db") {
		t.Errorf("cert set offered a TCP load balancer:\n%s", l)
	}
	if !strings.Contains(prompttest.Labels(p.Asked[1].Options), "other.com  (on proxy proxy-https-web-1)") {
		t.Errorf("domains offered:\n%s", prompttest.Labels(p.Asked[1].Options))
	}

	// The components: a pick, and several of one name are a pick too.
	p = h.answer(prompttest.Label("bs-db"))
	if err := h.run("compute", "backend-service", "get"); err != nil || !strings.Contains(h.stdout.String(), "bs-db") {
		t.Fatalf("component get = %v", err)
	}
	h.gce.addCheck("europe-west1", "check-80", 80)
	p = h.answer(prompttest.Label("europe-west1"))
	if err := h.run("compute", "health-check", "get", "check-80"); err != nil || !strings.Contains(h.stdout.String(), "europe-west1") {
		t.Fatalf("ambiguous component get = %v", err)
	}
	p.Done()

	h.nonInteractive()
	if err := h.run("compute", "health-check", "get", "check-80"); exitClass(err) != "ambiguous" {
		t.Errorf("non-interactive ambiguous = %v", err)
	}
	if err := h.run("compute", "load-balancer", "delete", "--yes"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive delete = %v", err)
	}
}
