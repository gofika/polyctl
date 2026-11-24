package gcp

import (
	"slices"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// lbHarness is a harness with instance web-1 in us-central1-a and a
// proxy-only subnetwork in us-central1.
func lbHarness(t *testing.T, flags app.Flags) *gcpHarness {
	t.Helper()
	h := newGCPHarness(t, flags, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.2", "34.1.0.2")
	h.gce.addProxyOnlySubnet("us-central1")
	return h
}

func ensureHTTP(t *testing.T, h *gcpHarness, args ...string) platform.Report {
	t.Helper()
	if err := h.run(append([]string{"compute", "load-balancer", "ensure", "web-1", "--protocol", "http"}, args...)...); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	return h.report()
}

func TestLBEnsureCreatesHTTP(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	rep := ensureHTTP(t, h)
	want := []string{
		"firewall/allow-lb-health-check-default created tcp, 4 source ranges, tag lb-health-check",
		"instance/web-1/tag created lb-health-check",
		"health-check/check-80 created regional TCP :80 interval 10s timeout 5s",
		"instance-group/ig-web-1 created zone us-central1-a, named-port http:80",
		"instance-group/ig-web-1/member created web-1",
		"backend-service/bs-web-1 created HTTP, port-name http, EXTERNAL_MANAGED",
		"url-map/lb-web-1 created default -> bs-web-1",
		"target-http-proxy/proxy-web-1 created -> lb-web-1",
	}
	got := rows(rep)
	if len(got) != 11 || !slices.Equal(got[:8], want) || !strings.HasPrefix(got[8], "forwarding-rule/fr-web-1 created 34.9.0.") ||
		got[9] != "forwarding-rule/fr-web-1/labels created polyctl-lb=lb-web-1" || got[10] != "load-balancer/lb-web-1/backend-health unchanged HEALTHY" {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	wantOps := []string{
		"POST global/firewalls",
		"POST zones/us-central1-a/instances/web-1/setTags",
		"POST us-central1/healthChecks",
		"POST zones/us-central1-a/instanceGroups",
		"POST zones/us-central1-a/instanceGroups/ig-web-1/addInstances",
		"POST us-central1/backendServices",
		"POST us-central1/urlMaps",
		"POST us-central1/targetHttpProxies",
		"POST us-central1/forwardingRules",
		"POST us-central1/forwardingRules/fr-web-1/setLabels",
	}
	if ops := h.gce.lbOps(); !slices.Equal(ops, wantOps) {
		t.Errorf("writes =\n%s", strings.Join(ops, "\n"))
	}
	// Every write was waited for.
	waits := 0
	for _, c := range h.gce.calls {
		if strings.Contains(c, "/operations/") {
			waits++
		}
	}
	if waits != len(wantOps) {
		t.Errorf("%d waits for %d writes", waits, len(wantOps))
	}
	bs := h.gce.backend("us-central1", "bs-web-1")
	if bs == nil || bs.PortName != "http" || bs.Protocol != "HTTP" || bs.LoadBalancingScheme != "EXTERNAL_MANAGED" || len(bs.Backends) != 1 ||
		bs.Backends[0].MaxUtilization != 0.8 || bs.Port != 80 {
		t.Errorf("backend service = %+v", bs)
	}
	g := h.gce.group("us-central1-a", "ig-web-1")
	if g == nil || namedPortLabel(g.NamedPorts) != "http:80" {
		t.Errorf("group = %+v", g)
	}
	fr := h.gce.rule("us-central1", "fr-web-1")
	if fr == nil || fr.Labels[lbLabel] != "lb-web-1" || fr.PortRange != "80" || !strings.HasSuffix(fr.Network, "/networks/default") || fr.NetworkTier != "PREMIUM" {
		t.Errorf("rule = %+v", fr)
	}
	var out lbEnsureResult
	h.jsonOut(&out)
	if out.LoadBalancer.Name != "lb-web-1" || out.LoadBalancer.Protocol != "HTTP" || out.LoadBalancer.IPAddress != fr.IPAddress ||
		out.LoadBalancer.URL != "http://"+fr.IPAddress+"/" || out.Target.Region != "us-central1" || out.Target.Profile != "lab" || out.Target.Project != "proj" {
		t.Errorf("result = %+v", out)
	}
	if !strings.Contains(h.stderr.String(), "http://"+fr.IPAddress+"/") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	// The forwarding rule is in the inventory with its load balancer.
	db, err := h.rt.DB()
	if err != nil {
		t.Fatal(err)
	}
	rowsDB, err := db.List(t.Context(), inventory.Query{Platform: platform.GCP, Profile: "lab", Type: platform.ResLoadBalancer})
	if err != nil || len(rowsDB) != 1 || rowsDB[0].Name != "fr-web-1" {
		t.Fatalf("inventory = %+v, %v", rowsDB, err)
	}
	var inv ForwardingRule
	if err := rowsDB[0].Decode(&inv); err != nil || inv.LoadBalancer != "lb-web-1" {
		t.Errorf("inventory row = %+v, %v", inv, err)
	}

	// Again: everything is unchanged and nothing is written.
	rep = ensureHTTP(t, h)
	for _, c := range rep.Changes {
		if c.Action != platform.Unchanged {
			t.Errorf("second run: %s %s %s", c.Resource, c.Action, c.Detail)
		}
	}
	if ops := h.gce.lbOps(); len(ops) != 0 {
		t.Errorf("second run writes %v", ops)
	}
}

func TestLBEnsureDryRun(t *testing.T) {
	h := lbHarness(t, app.Flags{DryRun: true})
	rep := ensureHTTP(t, h)
	want := []string{
		"firewall/allow-lb-health-check-default would_create tcp, 4 source ranges, tag lb-health-check",
		"instance/web-1/tag would_create lb-health-check",
		"health-check/check-80 would_create regional TCP :80 interval 10s timeout 5s",
		"instance-group/ig-web-1 would_create zone us-central1-a, named-port http:80",
		"instance-group/ig-web-1/member would_create web-1",
		"backend-service/bs-web-1 would_create HTTP, port-name http, EXTERNAL_MANAGED",
		"url-map/lb-web-1 would_create default -> bs-web-1",
		"target-http-proxy/proxy-web-1 would_create -> lb-web-1",
		"forwarding-rule/fr-web-1 would_create :80, ip (pending) (ephemeral)",
		"forwarding-rule/fr-web-1/labels would_create polyctl-lb=lb-web-1",
		"load-balancer/lb-web-1/backend-health skipped dry-run",
	}
	if got := rows(rep); !slices.Equal(got, want) || !rep.DryRun {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	if ops := h.gce.lbOps(); len(ops) != 0 {
		t.Errorf("dry run writes %v", ops)
	}
	// --address that does not exist yet would be reserved.
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "tcp", "--port", "3306", "--address", "lb-tcp-web-1-ip"); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	if !slices.Contains(got, "address/lb-tcp-web-1-ip would_create external, premium tier, us-central1") ||
		!slices.Contains(got, "forwarding-rule/fr-tcp-web-1 would_create :3306, ip (pending)") ||
		!slices.Contains(got, "target-tcp-proxy/proxy-tcp-web-1 would_create -> bs-tcp-web-1") {
		t.Errorf("tcp dry run =\n%s", strings.Join(got, "\n"))
	}
}

func TestLBEnsureNeedsProxyOnlySubnet(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, nil)
	h.gce.addInstance("proj", "us-central1-a", "web-1", "10.128.0.2", "34.1.0.2")
	err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "http")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "proxy-only subnetwork") || !strings.Contains(err.Error(), "REGIONAL_MANAGED_PROXY") {
		t.Errorf("err = %v", err)
	}
	if ops := h.gce.lbOps(); len(ops) != 0 {
		t.Errorf("writes %v", ops)
	}
}

func TestLBEnsureUsage(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	for _, args := range [][]string{
		{"web-1"},
		{"web-1", "--protocol", "udp"},
		{"web-1", "--protocol", "tcp"},
		{"web-1", "--protocol", "https"},
		{"web-1", "--protocol", "http", "--ssl-certificate", "c"},
		{"web-1", "--protocol", "http", "--name", "Bad_Name"},
		{"web-1", "--protocol", "http", "--port", "70000"},
		{"web-1", "--protocol", "http", "--backend-protocol", "https"},
		{"web-1", "--protocol", "http", "--health-timeout", "0s"},
	} {
		if err := h.run(append([]string{"compute", "load-balancer", "ensure"}, args...)...); exitClass(err) != "usage" {
			t.Errorf("%v = %v", args, err)
		}
	}
	if len(h.gce.calls) != 0 {
		t.Errorf("calls %v", h.gce.calls)
	}
	if err := h.run("compute", "load-balancer", "ensure", "nope", "--protocol", "http"); exitClass(err) != "notfound" {
		t.Errorf("missing instance = %v", err)
	}
	h.rt.Flags.Offline = true
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "http"); exitClass(err) != "offline" {
		t.Errorf("offline = %v", err)
	}
}

func TestLBEnsurePartial(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	// Only the URL map and the proxy are missing (the rule stays).
	h.gce.mu.Lock()
	delete(h.gce.lb().urlMaps, "proj/us-central1/lb-web-1")
	delete(h.gce.lb().httpProxies, "proj/us-central1/proxy-web-1")
	h.gce.mu.Unlock()
	ensureHTTP(t, h)
	if ops := h.gce.lbOps(); !slices.Equal(ops, []string{"POST us-central1/urlMaps", "POST us-central1/targetHttpProxies"}) {
		t.Errorf("writes %v", ops)
	}
	// The instance left the group: only AddInstances.
	h.gce.mu.Lock()
	h.gce.parts().members["proj/us-central1-a/ig-web-1"] = nil
	h.gce.mu.Unlock()
	ensureHTTP(t, h)
	if ops := h.gce.lbOps(); !slices.Equal(ops, []string{"POST zones/us-central1-a/instanceGroups/ig-web-1/addInstances"}) {
		t.Errorf("writes %v", ops)
	}
	// The named port is gone (other ports stay): only SetNamedPorts, which
	// keeps them; a stale fingerprint is read again once.
	h.gce.mu.Lock()
	g := h.gce.parts().groups["proj/us-central1-a/ig-web-1"]
	g.NamedPorts = nil
	g.NamedPorts = append(g.NamedPorts, &compute.NamedPort{Name: "port-9000", Port: 9000})
	h.gce.parts().staleGroup = true
	h.gce.mu.Unlock()
	rep := ensureHTTP(t, h)
	if ops := h.gce.lbOps(); !slices.Equal(ops, []string{"POST zones/us-central1-a/instanceGroups/ig-web-1/setNamedPorts", "POST zones/us-central1-a/instanceGroups/ig-web-1/setNamedPorts"}) {
		t.Errorf("writes %v", ops)
	}
	if l := namedPortLabel(h.gce.group("us-central1-a", "ig-web-1").NamedPorts); l != "http:80,port-9000:9000" {
		t.Errorf("named ports %s", l)
	}
	if !slices.Contains(rows(rep), "instance-group/ig-web-1 updated +named-port http:80 (kept port-9000:9000)") {
		t.Errorf("report =\n%s", strings.Join(rows(rep), "\n"))
	}
	// The backend service lost its backend: it is patched in.
	h.gce.mu.Lock()
	h.gce.parts().backends["proj/us-central1/bs-web-1"].Backends = nil
	h.gce.mu.Unlock()
	ensureHTTP(t, h)
	if ops := h.gce.lbOps(); !slices.Equal(ops, []string{"PATCH us-central1/backendServices/bs-web-1"}) || len(h.gce.backend("us-central1", "bs-web-1").Backends) != 1 {
		t.Errorf("writes %v", ops)
	}
}

// An existing rule on an ephemeral IP and a missing --address: the address
// is reserved with the rule's IP, and the rule stays as it is.
func TestLBEnsureAddressPromotesRuleIP(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	ip := h.gce.rule("us-central1", "fr-web-1").IPAddress
	rep := ensureHTTP(t, h, "--address", "lb-web-1-ip")
	if !slices.Contains(rows(rep), "address/lb-web-1-ip created reserved "+ip) || !slices.Contains(rows(rep), "forwarding-rule/fr-web-1 unchanged "+ip+":80") {
		t.Errorf("report =\n%s", strings.Join(rows(rep), "\n"))
	}
	if a := h.gce.address("us-central1", "lb-web-1-ip"); a == nil || a.Address != ip {
		t.Errorf("address = %+v, want %s", a, ip)
	}
	if ops := h.gce.lbOps(); !slices.Equal(ops, []string{"POST us-central1/addresses"}) {
		t.Errorf("writes %v", ops)
	}
}

// A rule made outside polyctl on a STANDARD tier IP: the address is
// reserved in that tier, as the IP cannot change pools.
func TestLBEnsureAddressPromotesStandardTier(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	h.gce.mu.Lock()
	for _, fr := range h.gce.forwardingRules["proj"] {
		if fr.Name == "fr-web-1" {
			fr.NetworkTier = "STANDARD"
		}
	}
	h.gce.mu.Unlock()
	h.rt.Flags.DryRun = true
	rep := ensureHTTP(t, h, "--address", "lb-web-1-ip")
	h.rt.Flags.DryRun = false
	if r := strings.Join(rows(rep), "\n"); !strings.Contains(r, "of forwarding rule fr-web-1, standard tier") {
		t.Errorf("dry run =\n%s", r)
	}
	ensureHTTP(t, h, "--address", "lb-web-1-ip")
	if a := h.gce.address("us-central1", "lb-web-1-ip"); a == nil || a.NetworkTier != "STANDARD" {
		t.Errorf("address = %+v, want STANDARD tier", a)
	}
}

func TestLBEnsureTCPReusesGroup(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "tcp", "--port", "3306"); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	for _, w := range []string{
		"health-check/check-3306 created regional TCP :3306 interval 10s timeout 5s",
		"instance-group/ig-web-1 updated +named-port port-3306:3306 (kept http:80)",
		"instance-group/ig-web-1/member unchanged web-1",
		"backend-service/bs-tcp-web-1 created TCP, port-name port-3306, EXTERNAL_MANAGED",
		"target-tcp-proxy/proxy-tcp-web-1 created -> bs-tcp-web-1",
		"forwarding-rule/fr-tcp-web-1/labels created polyctl-lb=lb-tcp-web-1",
	} {
		if !slices.Contains(got, w) {
			t.Errorf("missing %q in\n%s", w, strings.Join(got, "\n"))
		}
	}
	for _, r := range got {
		if strings.HasPrefix(r, "url-map/") || strings.HasPrefix(r, "load-balancer/") {
			t.Errorf("tcp row %s", r)
		}
	}
	for _, op := range h.gce.lbOps() {
		if strings.Contains(op, "urlMaps") {
			t.Errorf("tcp wrote %s", op)
		}
	}
	if l := namedPortLabel(h.gce.group("us-central1-a", "ig-web-1").NamedPorts); l != "http:80,port-3306:3306" {
		t.Errorf("named ports %s", l)
	}
	if bs := h.gce.backend("us-central1", "bs-tcp-web-1"); bs == nil || bs.PortName != "port-3306" || bs.Protocol != "TCP" {
		t.Errorf("tcp backend = %+v", bs)
	}
	var out lbEnsureResult
	h.jsonOut(&out)
	if out.LoadBalancer.Name != "lb-tcp-web-1" || !strings.HasSuffix(out.LoadBalancer.URL, ":3306") {
		t.Errorf("result = %+v", out.LoadBalancer)
	}
}

func TestLBEnsureHTTPS(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "https", "--ssl-certificate", "web-cert"); exitClass(err) != "notfound" || !strings.Contains(err.Error(), "ssl-certificate create") {
		t.Errorf("missing certificate = %v", err)
	}
	h.gce.addCert("us-central1", "web-cert", newPair(t, []string{"example.com"}, 90).chain)
	ensureHTTP(t, h)
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "https", "--ssl-certificate", "web-cert"); err != nil {
		t.Fatal(err)
	}
	// The URL map, backend service and instance group of http are shared.
	if ops := h.gce.lbOps(); !slices.Equal(ops, []string{"POST us-central1/targetHttpsProxies", "POST us-central1/forwardingRules", "POST us-central1/forwardingRules/fr-https-web-1/setLabels"}) {
		t.Errorf("writes %v", ops)
	}
	if certs := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(certs, []string{"web-cert"}) {
		t.Errorf("certs %v", certs)
	}
	fr := h.gce.rule("us-central1", "fr-https-web-1")
	if fr == nil || fr.PortRange != "443" || fr.Labels[lbLabel] != "lb-web-1" {
		t.Errorf("rule %+v", fr)
	}
}

func TestLBEnsureSkipsAnotherInstancesGroup(t *testing.T) {
	h := lbHarness(t, app.Flags{DryRun: true})
	h.gce.addInstance("proj", "us-central1-a", "web", "10.128.0.3", "")
	h.gce.addInstance("proj", "us-central1-a", "web-2", "10.128.0.4", "")
	h.gce.addGroup("us-central1-a", "ig-web-2", map[string]int64{"http": 80}, "web-2")
	h.gce.addCheck("us-central1", "check-80", 80)
	h.gce.addBackend("us-central1", "bs-web-2", "HTTP", "http", "check-80", "us-central1-a/ig-web-2")
	if err := h.run("compute", "load-balancer", "ensure", "web", "--protocol", "http"); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	if !slices.Contains(got, "instance-group/ig-web would_create zone us-central1-a, named-port http:80") {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	// web-2 itself reuses the group its backend service uses.
	if err := h.run("compute", "load-balancer", "ensure", "web-2", "--protocol", "tcp", "--port", "8080"); err != nil {
		t.Fatal(err)
	}
	got = rows(h.report())
	if !slices.Contains(got, "instance-group/ig-web-2 would_update +named-port port-8080:8080 (kept http:80)") ||
		!slices.Contains(got, "instance-group/ig-web-2/member unchanged web-2") {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
}

func TestLBEnsureFirewall(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	h.gce.fail["GET /projects/proj/global/firewalls/"] = fakeErr{403, "forbidden", "Required 'compute.firewalls.get' permission"}
	rep := ensureHTTP(t, h)
	if got := rows(rep); !strings.HasPrefix(got[0], "firewall/allow-lb-health-check-default skipped no permission") || len(got) != 11 {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	h2 := lbHarness(t, app.Flags{})
	h2.gce.fail["GET /projects/proj/global/firewalls/"] = fakeErr{400, "invalid", "bad request"}
	if err := h2.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "http"); exitClass(err) != "general" {
		t.Errorf("400 = %v", err)
	}
	if ops := h2.gce.lbOps(); len(ops) != 0 {
		t.Errorf("writes %v", ops)
	}
}

func TestLBEnsureWaitsForHealth(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	h.gce.parts().health = []string{"", "UNHEALTHY", "HEALTHY"}
	rep := ensureHTTP(t, h)
	if got := rows(rep); got[len(got)-1] != "load-balancer/lb-web-1/backend-health unchanged HEALTHY" || h.gce.parts().healthCalls != 3 {
		t.Errorf("report %v, %d calls", got[len(got)-1], h.gce.parts().healthCalls)
	}
	// Never HEALTHY: skipped with a checklist, exit code 0.
	h.gce.parts().health = []string{"UNHEALTHY"}
	h.gce.parts().healthCalls = 0
	rep = ensureHTTP(t, h, "--health-timeout", "1m")
	if got := rows(rep); got[len(got)-1] != "load-balancer/lb-web-1/backend-health skipped not HEALTHY after 1m0s (last: UNHEALTHY)" {
		t.Errorf("report %v", got[len(got)-1])
	}
	if calls := h.gce.parts().healthCalls; calls != 7 {
		t.Errorf("%d health reads in 1m every 10s", calls)
	}
	if s := h.stderr.String(); !strings.Contains(s, "listens on port 80") || !strings.Contains(s, "allow-lb-health-check-default") {
		t.Errorf("stderr = %s", s)
	}
	// --no-wait does not wait.
	h.gce.parts().healthCalls = 0
	rep = ensureHTTP(t, h, "--no-wait")
	if got := rows(rep); got[len(got)-1] != "load-balancer/lb-web-1/backend-health skipped --no-wait" || h.gce.parts().healthCalls != 0 {
		t.Errorf("report %v", got[len(got)-1])
	}
}

func TestLBEnsureRefusesDifferences(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	// The rule targets another proxy: exit code 1, nothing written.
	h.gce.addHTTPProxy("us-central1", "proxy-other", "lb-web-1")
	h.gce.mu.Lock()
	for _, fr := range h.gce.forwardingRules["proj"] {
		if fr.Name == "fr-web-1" {
			fr.Target = apiBase + "projects/proj/regions/us-central1/targetHttpProxies/proxy-other"
		}
	}
	h.gce.mu.Unlock()
	err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "http")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "forwarding rule fr-web-1 exists with target proxy-other") {
		t.Errorf("err = %v", err)
	}
	if ops := h.gce.lbOps(); len(ops) != 0 {
		t.Errorf("writes %v", ops)
	}
	// A health check on another port is not changed.
	h2 := lbHarness(t, app.Flags{})
	h2.gce.addCheck("us-central1", "check-80", 8080)
	if err := h2.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "http"); exitClass(err) != "general" || !strings.Contains(err.Error(), "--health-check-name") {
		t.Errorf("check = %v", err)
	}
}

func TestLBEnsureRace(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	h.gce.parts().race["backendServices"] = true
	rep := ensureHTTP(t, h)
	if !slices.Contains(rows(rep), "backend-service/bs-web-1 unchanged HTTP, port-name http, EXTERNAL_MANAGED (created meanwhile)") {
		t.Errorf("report =\n%s", strings.Join(rows(rep), "\n"))
	}
	if h.gce.rule("us-central1", "fr-web-1") == nil {
		t.Error("the ensure stopped after the race")
	}
}

func TestLBEnsureNames(t *testing.T) {
	h := newGCPHarness(t, app.Flags{DryRun: true}, nil)
	h.gce.addProxyOnlySubnet("us-central1")
	long := "s" + strings.Repeat("x", 61) + "e"
	h.gce.addInstance("proj", "us-central1-a", "2265-site", "10.128.0.5", "")
	h.gce.addInstance("proj", "us-central1-a", long, "10.128.0.6", "")
	if err := h.run("compute", "load-balancer", "ensure", "2265-site", "--protocol", "tcp", "--port", "8080"); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	for _, w := range []string{"instance-group/ig-2265-site would_create", "backend-service/bs-tcp-2265-site would_create",
		"target-tcp-proxy/proxy-tcp-2265-site would_create", "forwarding-rule/fr-tcp-2265-site would_create", "forwarding-rule/fr-tcp-2265-site/labels would_create polyctl-lb=lb-tcp-2265-site"} {
		if !slices.ContainsFunc(got, func(r string) bool { return strings.HasPrefix(r, w) }) {
			t.Errorf("missing %q in\n%s", w, strings.Join(got, "\n"))
		}
	}
	names := func() []string {
		if err := h.run("compute", "load-balancer", "ensure", long, "--protocol", "tcp", "--port", "8080"); err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, c := range h.report().Changes {
			out = append(out, c.Resource)
		}
		return out
	}
	first := names()
	if !slices.Equal(first, names()) {
		t.Errorf("names are not stable")
	}
	for _, r := range first {
		for _, part := range strings.Split(r, "/")[1:2] {
			if len(part) > 63 || !certNameRe.MatchString(part) {
				t.Errorf("bad name %q", part)
			}
		}
	}
	// --name names the load balancer and the others follow it.
	if err := h.run("compute", "load-balancer", "ensure", "2265-site", "--protocol", "http", "--name", "lb-site"); err != nil {
		t.Fatal(err)
	}
	got = rows(h.report())
	for _, w := range []string{"url-map/lb-site would_create default -> bs-site", "target-http-proxy/proxy-site would_create -> lb-site", "instance-group/ig-site would_create"} {
		if !slices.ContainsFunc(got, func(r string) bool { return strings.HasPrefix(r, w) }) {
			t.Errorf("missing %q in\n%s", w, strings.Join(got, "\n"))
		}
	}
}

func TestLBNameHelpers(t *testing.T) {
	for _, c := range []struct {
		protocol string
		port     int64
		want     string
	}{{"http", 80, "http"}, {"https", 80, "http"}, {"tcp", 80, "port-80"}, {"http", 8080, "port-8080"}} {
		if got := namedPortName(c.protocol, c.port); got != c.want {
			t.Errorf("namedPortName(%s, %d) = %s", c.protocol, c.port, got)
		}
	}
	if normPortRange("80") != "80-80" || normPortRange("80-80") != "80-80" {
		t.Error("normPortRange")
	}
	for _, c := range [][4]string{{"web-1", "", "lb-", "web-1"}, {"web-1", "lb-tcp-db", "lb-", "db"}, {"web-1", "site", "lb-", "site"}, {"web-1", "lb-x", "lb-", "x"}} {
		proto := "http"
		if strings.Contains(c[1], "tcp") {
			proto = "tcp"
		}
		if got := lbBaseName(c[0], c[1], c[2], proto); got != c[3] {
			t.Errorf("lbBaseName(%v) = %s", c, got)
		}
	}
	if accessURL("http", "1.2.3.4", 8080) != "http://1.2.3.4:8080/" || accessURL("https", "1.2.3.4", 443) != "https://1.2.3.4/" || accessURL("tcp", "1.2.3.4", 3306) != "1.2.3.4:3306" {
		t.Error("accessURL")
	}
	if healthSummary(nil) != "no status yet" || healthSummary([]string{"HEALTHY", "UNHEALTHY"}) != "HEALTHY x1, UNHEALTHY x1" {
		t.Error("healthSummary")
	}
}
