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

// server-group update without <name|id> or a change flag picks the group
// and asks what to change; the non-interactive flow still needs both.
func TestALBServerGroupUpdatePicks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addGroup("sgp-1", "web", "HTTP", "vpc-site")
	p := prompttest.New(t, "sgp-1", "health-check", "on", "healthz", "/healthz")
	h.rt.Picker = p
	if err := h.run("alb", "server-group", "update"); err != nil {
		t.Fatalf("update: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if out := h.stdout.String(); !strings.Contains(out, `health check false -\u003e true`) || !strings.Contains(out, "health check path /healthz") {
		t.Errorf("stdout = %s", out)
	}
	p = prompttest.New(t, "sgp-1", "name", "sgp-x", "web", "api")
	h.rt.Picker = p
	if err := h.run("alb", "server-group", "update"); err != nil {
		t.Fatalf("rename: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if out := h.stdout.String(); !strings.Contains(out, `name web -\u003e api`) {
		t.Errorf("stdout = %s", out)
	}
	h.rt.Picker = prompttest.New(t, "sgp-1", prompttest.Abort{})
	if err := h.run("alb", "server-group", "update"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("alb", "server-group", "update", "web"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive update without a change = %v", err)
	}
	if len(h.api.callsFor("UpdateServerGroupAttribute")) != 0 {
		t.Error("a dry run or a cancelled update wrote")
	}
}

// load-balancer create without <name>, --vpc and --zone-mapping asks for
// the name (a taken one asked again), the VPC, then per zone a vSwitch in
// a zone offering ALB (the first zone left out the second time) and an
// idle EIP (the first one's ISP only the second time).
func TestALBLoadBalancerCreateAsks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, net, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addLB("alb-1", "lb-taken", "vpc-site", "Active")
	net.addVSwitch("vsw-b", "sw-b", "vpc-site", "cn-shanghai-b", "172.16.0.0/22")
	net.addVSwitch("vsw-c", "sw-c", "vpc-site", "cn-shanghai-c", "172.16.4.0/22")
	net.addVSwitch("vsw-z", "sw-z", "vpc-site", "cn-shanghai-z", "172.16.8.0/22")
	net.addEIP("eip-1", "203.0.113.1", "Available", "", "", 0, "BGP")
	net.addEIP("eip-2", "203.0.113.2", "Available", "", "", 0, "BGP")
	net.addEIP("eip-3", "203.0.113.3", "Available", "", "", 0, "BGP_PRO")
	net.addEIP("eip-4", "203.0.113.4", "InUse", "i-x", "EcsInstance", 0, "BGP")
	p := prompttest.New(t, "lb-taken", "lb-web", "vpc-site", "vsw-b", "eip-1", "vsw-c", "eip-2")
	h.rt.Picker = p
	if err := h.run("alb", "load-balancer", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[3].Options); !strings.Contains(v, "vsw-b") || !strings.Contains(v, "vsw-c") || strings.Contains(v, "vsw-z") {
		t.Errorf("first vSwitches offered %q (zone z offers no ALB)", v)
	}
	if v := prompttest.Values(p.Asked[4].Options); !strings.Contains(v, "eip-3") || strings.Contains(v, "eip-4") {
		t.Errorf("first EIPs offered %q", v)
	}
	if v := prompttest.Values(p.Asked[5].Options); strings.Contains(v, "vsw-b") {
		t.Errorf("second vSwitches offered %q: zone b is taken", v)
	}
	if v := prompttest.Values(p.Asked[6].Options); v != "eip-2" {
		t.Errorf("second EIPs offered %q: want eip-2 only (same ISP, unused)", v)
	}
	if !strings.Contains(h.stdout.String(), "load-balancer/lb-web") {
		t.Errorf("stdout = %s", h.stdout.String())
	}

	// No second zone to pick: a usage error naming --zone-mapping.
	err := h.run("alb", "load-balancer", "create", "lb-x", "--vpc", "vpc-site", "--zone-mapping", "cn-shanghai-b:vsw-b:eip-1", "--zone-mapping", "cn-shanghai-c:vsw-c:eip-2", "--zone-mapping", "x:vsw-y:eip-9")
	if !errors.Is(err, app.ErrUsage) {
		t.Errorf("three mappings = %v", err)
	}
	h.rt.Picker = prompttest.New(t, "vsw-b")
	err = h.run("alb", "load-balancer", "create", "lb-x", "--vpc", "vpc-site", "--zone-mapping", "cn-shanghai-c:vsw-c:eip-3")
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--zone-mapping") {
		t.Errorf("no other idle EIP of BGP_PRO = %v", err)
	}
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("alb", "load-balancer", "create"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	if len(h.api.callsFor("CreateLoadBalancer")) != 0 {
		t.Error("a dry run or a cancelled create wrote")
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("alb", "load-balancer", "create", "lb-x", "--vpc", "vpc-site"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive without --zone-mapping = %v", err)
	}
}

// The server groups a listener is offered are the Available ones of its
// load balancer's VPC; update leaves out the group it forwards to, and
// create without any is a usage error naming --server-group.
func TestALBListenerGroupPickVPC(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, alb, _, _ := albHarness(t, app.Flags{DryRun: true})
	alb.addLB("alb-1", "lb-1", "vpc-site", "Active")
	alb.addGroup("sgp-1", "g1", "HTTP", "vpc-site")
	alb.addGroup("sgp-2", "g2", "HTTP", "vpc-site")
	alb.addGroup("sgp-9", "other", "HTTP", "vpc-other")
	alb.addListener("lsn-1", "alb-1", "HTTP", 80, "sgp-1")
	p := prompttest.New(t, "alb-1", "lsn-1", "group", "sgp-2")
	h.rt.Picker = p
	if err := h.run("alb", "listener", "update"); err != nil {
		t.Fatalf("update: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[3].Options); v != "sgp-2" {
		t.Errorf("update offered %q, want sgp-2 only", v)
	}
	alb.addLB("alb-3", "lb-3", "vpc-site", "Inactive")
	p = prompttest.New(t, "alb-1", "https:443", "sgp-1", "1234567")
	h.rt.Picker = p
	if err := h.run("alb", "listener", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); strings.Contains(v, "alb-3") {
		t.Errorf("create offered %q: alb-3 is not Active", v)
	}
	if v := prompttest.Values(p.Asked[2].Options); strings.Contains(v, "sgp-9") {
		t.Errorf("create offered %q: sgp-9 is in another VPC", v)
	}
	alb.addLB("alb-2", "lb-2", "vpc-empty", "Active")
	h.rt.Picker = prompttest.New(t, "alb-2", "http:80")
	if err := h.run("alb", "listener", "create"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--server-group") {
		t.Errorf("no group in the VPC = %v", err)
	}
}
