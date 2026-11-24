package aliyun

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// listener cert set without <listener-id> and --cert asks for the load
// balancer, then one of its HTTPS listeners (HTTP ones left out), then an
// unexpired certificate of the CAS store (the current one marked).
func TestALBListenerCertSetPicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, cas, _ := albHarness(t, app.Flags{DryRun: true})
	cas.add(1111, "old", "2026-01-01")
	cas.add(2222, "new", "2027-06-01")
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addGroup("sgp-1", "g", "HTTP", "vpc-site")
	alb.addListener("lsn-1", "alb-1", "HTTP", 80, "sgp-1")
	alb.addListener("lsn-2", "alb-1", "HTTPS", 443, "sgp-1", "1234567")
	p := prompttest.New(t, "alb-1", "lsn-2", "2222")
	h.rt.Picker = p
	if err := h.run("alb", "listener", "cert", "set"); err != nil {
		t.Fatalf("cert set: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[1].Options); v != "lsn-2" {
		t.Errorf("listeners offered %q", v)
	}
	certs := p.Asked[2]
	if l := prompttest.Labels(certs.Options); strings.Contains(l, "1111") || !strings.Contains(l, "1234567  (current)") || certs.Default != "2222" {
		t.Errorf("certificates (default %q):\n%s", certs.Default, l)
	}
}

// acl entry remove without entries offers the entries of the ACL; an ACL
// without entries is nothing to do.
func TestALBACLEntryRemovePick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addACL("acl-1", "office")
	h.rt.Picker = prompttest.New(t, "acl-1")
	if err := h.run("alb", "acl", "entry", "remove"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("no entries = %v", err)
	}
	h.rt.Picker = prompttest.New(t, "acl-1", "bad", "203.0.113.0/24", "")
	if err := h.run("alb", "acl", "entry", "add"); err != nil {
		t.Fatalf("entry add: %v\n%s", err, h.stderr.String())
	}
	if !strings.Contains(h.stdout.String(), "203.0.113.0/24") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("alb", "acl", "entry", "add", "acl-1"); err == nil {
		t.Error("non-interactive entry add without <cidr> succeeded")
	}
}

// cas certificate delete without <cert-id> or --expired offers "All
// expired certificates (N)" and each certificate.
func TestCASDeletePick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := casHarness(t, app.Flags{DryRun: true})
	f.add(1, "one", "2027-01-01")
	f.add(2, "gone", "2020-01-01")
	p := prompttest.New(t, prompttest.Label("All expired certificates (1)"))
	h.rt.Picker = p
	if err := h.run("cas", "certificate", "delete", "--force"); err != nil {
		t.Fatalf("delete: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "cas/certificate/2") || strings.Contains(h.stdout.String(), "cas/certificate/1\"") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

// listener create without flags asks for the load balancer, the listener
// (ports in use left out), the server group and, for HTTPS, the
// certificate.
func TestALBListenerCreatePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addGroup("sgp-1", "g", "HTTP", "vpc-site")
	alb.addListener("lsn-1", "alb-1", "HTTP", 80, "sgp-1")
	p := prompttest.New(t, "alb-1", "https:443", "sgp-1", "1234567")
	h.rt.Picker = p
	if err := h.run("alb", "listener", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[1].Options); strings.Contains(v, "http:80") {
		t.Errorf("listeners offered %q: port 80 is in use", v)
	}
	if !strings.Contains(h.stdout.String(), "listener/https:443") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

// server-group create and acl create ask for what is missing.
func TestALBGroupAndACLCreatePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addGroup("sgp-1", "web", "HTTP", "vpc-site")
	p := prompttest.New(t, "vpc-site", "HTTPS", "web", "api")
	h.rt.Picker = p
	if err := h.run("alb", "server-group", "create"); err != nil {
		t.Fatalf("server-group create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "server-group/api") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	alb.addACL("acl-1", "office")
	p = prompttest.New(t, "office", "home")
	h.rt.Picker = p
	if err := h.run("alb", "acl", "create"); err != nil {
		t.Fatalf("acl create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "acl/home") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

// load-balancer ensure without <domain> and --service asks for the domain
// (checked as typed) and a Running instance of the region.
func TestALBEnsureAsksDomainAndService(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, net, _, _, _ := albHarness(t, app.Flags{DryRun: true})
	in := net.instances[len(net.instances)-1]
	in["Status"] = instRunning
	p := prompttest.New(t, "not a domain", "example.com", "i-site")
	h.rt.Picker = p
	err := h.run("alb", "load-balancer", "ensure", "--listener", "http:80")
	p.Done()
	if err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	if a := p.Asked[2]; a.Title != "Instance" || !strings.Contains(prompttest.Labels(a.Options), "site-a  i-site") {
		t.Errorf("instance pick: %+v", a)
	}
}

// listener update without <listener-id>, --server-group and --cert asks
// for the listener, what to change, then the server group.
func TestALBListenerUpdatePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addGroup("sgp-1", "g1", "HTTP", "vpc-site")
	alb.addGroup("sgp-2", "g2", "HTTP", "vpc-site")
	alb.addListener("lsn-2", "alb-1", "HTTPS", 443, "sgp-1", "1234567")
	p := prompttest.New(t, "alb-1", "lsn-2", "group", "sgp-2")
	h.rt.Picker = p
	if err := h.run("alb", "listener", "update"); err != nil {
		t.Fatalf("update: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), `server group sgp-1 -\u003e sgp-2`) {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}

// load-balancer get and delete without <name|id> offer the load balancers
// of the inventory (synced first); leaving the pick deletes nothing, and
// the non-interactive flow still requires the argument.
func TestALBLoadBalancerArgPick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	p := prompttest.New(t, "alb-1")
	h.rt.Picker = p
	if err := h.run("alb", "load-balancer", "delete"); err != nil {
		t.Fatalf("delete: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(prompttest.Labels(p.Find("Load balancer").Options), "lb-1  alb-1") || !strings.Contains(h.stdout.String(), "load-balancer/lb-1") {
		t.Errorf("pick %+v, stdout = %s", p.Asked, h.stdout.String())
	}
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("alb", "load-balancer", "delete"); !errors.Is(err, prompt.ErrAborted) || len(h.api.callsFor("DeleteLoadBalancer")) != 0 {
		t.Errorf("abort = %v", err)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("alb", "load-balancer", "delete"); err == nil || len(h.api.callsFor("DeleteLoadBalancer")) != 0 {
		t.Errorf("non-interactive delete without <name|id> = %v", err)
	}
}
