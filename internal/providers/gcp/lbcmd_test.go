package gcp

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
)

func TestLBListAndGet(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "tcp", "--port", "3306"); err != nil {
		t.Fatal(err)
	}
	// An older load balancer without the label is named after its URL map.
	h.gce.addCheck("us-central1", "check-old", 80)
	h.gce.addGroup("us-central1-b", "old-ig", map[string]int64{"http": 80})
	h.gce.addBackend("us-central1", "old-bs", "HTTP", "http", "check-old", "us-central1-b/old-ig")
	h.gce.addURLMapTo("us-central1", "old-lb", "old-bs")
	h.gce.addHTTPProxy("us-central1", "old-proxy", "old-lb")
	h.gce.addRule("us-central1", "old-fr", "targetHttpProxies/old-proxy", "34.5.6.7", "80-80", nil)
	if err := h.run("compute", "load-balancer", "list"); err != nil {
		t.Fatal(err)
	}
	var list []lbRow
	h.jsonOut(&list)
	var got []string
	for _, r := range list {
		got = append(got, strings.Join([]string{r.Name, r.Protocol, r.Port, r.ForwardingRule, strings.Join(r.Backends, ","), r.Health}, " "))
	}
	want := []string{
		"lb-tcp-web-1 TCP 3306 fr-tcp-web-1 bs-tcp-web-1 HEALTHY",
		"lb-web-1 HTTP 80 fr-web-1 bs-web-1 HEALTHY",
		"old-lb HTTP 80 old-fr old-bs HEALTHY",
	}
	if !slices.Equal(got, want) {
		t.Errorf("list =\n%s", strings.Join(got, "\n"))
	}
	if err := h.run("compute", "load-balancer", "list", "--global"); err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "no load balancers") {
		t.Errorf("global list = %s / %s", h.stdout.String(), h.stderr.String())
	}
	if err := h.run("compute", "load-balancer", "get", "lb-web-1"); err != nil {
		t.Fatal(err)
	}
	var d lbDetail
	h.jsonOut(&d)
	if len(d.ForwardingRules) != 1 || d.ForwardingRules[0].Name != "fr-web-1" || len(d.Proxies) != 1 || d.Proxies[0].URLMap != "lb-web-1" ||
		len(d.URLMaps) != 1 || len(d.BackendServices) != 1 || d.BackendServices[0].Health != "HEALTHY" || len(d.HealthChecks) != 1 ||
		len(d.InstanceGroups) != 1 || len(d.InstanceGroups[0].Members) != 1 || d.InstanceGroups[0].Members[0].Instance != "web-1" || d.Region != "us-central1" {
		t.Errorf("detail = %+v", d)
	}
	// The TCP load balancer has no resource of its own: its label names it.
	if err := h.run("compute", "load-balancer", "get", "lb-tcp-web-1"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&d)
	if len(d.Proxies) != 1 || d.Proxies[0].Kind != "target-tcp-proxy" || d.Proxies[0].BackendService != "bs-tcp-web-1" {
		t.Errorf("tcp detail = %+v", d)
	}
	// A forwarding rule name stands for its load balancer; an unlabelled one
	// is found through its URL map after a sync.
	if err := h.run("compute", "load-balancer", "get", "old-lb"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&d)
	if d.Name != "old-lb" || len(d.ForwardingRules) != 1 || d.ForwardingRules[0].Name != "old-fr" {
		t.Errorf("old detail = %+v", d)
	}
	if err := h.run("compute", "load-balancer", "get", "nope"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
}

func TestLBGetAmbiguous(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	h.addProfile()
	ensureHTTP(t, h)
	cp := *h.gce.rule("us-central1", "fr-web-1")
	h.gce.mu.Lock()
	cp.SelfLink = strings.Replace(cp.SelfLink, "/proj/", "/other/", 1)
	h.gce.forwardingRules["other"] = append(h.gce.forwardingRules["other"], &cp)
	h.gce.mu.Unlock()
	h.rt.Flags.Refresh = true
	if err := h.run("compute", "load-balancer", "get", "lb-web-1"); exitClass(err) != "ambiguous" {
		t.Errorf("two projects = %v", err)
	}
	h.rt.Flags.Profile = "lab"
	if err := h.run("compute", "load-balancer", "get", "lb-web-1"); err != nil {
		t.Errorf("--profile = %v", err)
	}
}

func TestLBDelete(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	h.gce.addCert("us-central1", "web-cert", newPair(t, []string{"example.com"}, 90).chain)
	ensureHTTP(t, h)
	if err := h.run("compute", "load-balancer", "ensure", "web-1", "--protocol", "https", "--ssl-certificate", "web-cert"); err != nil {
		t.Fatal(err)
	}
	// Another load balancer uses the backend service through a TCP proxy.
	h.gce.addTCPProxy("us-central1", "proxy-shared", "bs-web-1")
	if err := h.run("compute", "load-balancer", "delete", "lb-web-1"); exitClass(err) != "usage" {
		t.Errorf("non-interactive without --yes = %v", err)
	}
	if ops := h.gce.lbOps(); len(ops) != 0 {
		t.Errorf("writes %v", ops)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "load-balancer", "delete", "lb-web-1"); err != nil {
		t.Fatal(err)
	}
	if ops := h.gce.lbOps(); len(ops) != 0 {
		t.Errorf("dry run writes %v", ops)
	}
	h.rt.Flags.DryRun = false
	if err := h.run("compute", "load-balancer", "delete", "lb-web-1", "--yes"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"DELETE us-central1/forwardingRules/fr-https-web-1",
		"DELETE us-central1/forwardingRules/fr-web-1",
		"DELETE us-central1/targetHttpsProxies/proxy-https-web-1",
		"DELETE us-central1/targetHttpProxies/proxy-web-1",
		"DELETE us-central1/urlMaps/lb-web-1",
	}
	if ops := h.gce.lbOps(); !slices.Equal(ops, want) {
		t.Errorf("writes =\n%s", strings.Join(ops, "\n"))
	}
	if got := rows(h.report()); !slices.Contains(got, "backend-service/bs-web-1 skipped used by target-tcp-proxy/proxy-shared") {
		t.Errorf("report =\n%s", strings.Join(got, "\n"))
	}
	// Instance groups and health checks stay.
	if h.gce.group("us-central1-a", "ig-web-1") == nil || h.gce.parts().checks["proj/us-central1/check-80"] == nil {
		t.Error("shared components were deleted")
	}
	// Without the other user the backend service goes too.
	h.gce.mu.Lock()
	delete(h.gce.parts().tcpProxies, "proj/us-central1/proxy-shared")
	h.gce.mu.Unlock()
	ensureHTTP(t, h)
	if err := h.run("compute", "load-balancer", "delete", "lb-web-1", "--yes"); err != nil {
		t.Fatal(err)
	}
	want = []string{"DELETE us-central1/forwardingRules/fr-web-1", "DELETE us-central1/targetHttpProxies/proxy-web-1",
		"DELETE us-central1/urlMaps/lb-web-1", "DELETE us-central1/backendServices/bs-web-1"}
	if ops := h.gce.lbOps(); !slices.Equal(ops, want) {
		t.Errorf("writes =\n%s", strings.Join(ops, "\n"))
	}
}
