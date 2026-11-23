package gcp

import (
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
)

func TestComponentCommands(t *testing.T) {
	h := lbHarness(t, app.Flags{})
	ensureHTTP(t, h)
	for _, c := range []struct {
		kind, name string
		want       string
	}{
		{"backend-service", "bs-web-1", `"port_name": "http"`},
		{"forwarding-rule", "fr-web-1", `"load_balancer": "lb-web-1"`},
		{"health-check", "check-80", `"port": "80"`},
		{"instance-group", "ig-web-1", `"instance": "web-1"`},
	} {
		if err := h.run("compute", c.kind, "list"); err != nil || !strings.Contains(h.stdout.String(), c.name) {
			t.Errorf("%s list = %v %s", c.kind, err, h.stdout.String())
		}
		if err := h.run("compute", c.kind, "get", c.name); err != nil || !strings.Contains(h.stdout.String(), c.want) {
			t.Errorf("%s get = %v %s", c.kind, err, h.stdout.String())
		}
		if err := h.run("compute", c.kind, "get", "nope"); exitClass(err) != "notfound" {
			t.Errorf("%s get nope = %v", c.kind, err)
		}
	}
	// In use: exit code 1 naming the user.
	err := h.run("compute", "health-check", "delete", "check-80", "--yes")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "backend-service/bs-web-1") {
		t.Errorf("in use = %v", err)
	}
	if err := h.run("compute", "instance-group", "delete", "ig-web-1"); exitClass(err) != "usage" {
		t.Errorf("without --yes = %v", err)
	}
	if err := h.run("compute", "forwarding-rule", "delete", "fr-web-1", "--yes"); err != nil {
		t.Fatal(err)
	}
	if h.gce.rule("us-central1", "fr-web-1") != nil {
		t.Error("rule not deleted")
	}
	// A global and a regional health check of one name: the regional one
	// wins without a scope flag; --global picks the other.
	h.gce.addCheck("global", "check-80", 443)
	if err := h.run("compute", "health-check", "get", "check-80"); err != nil || !strings.Contains(h.stdout.String(), `"region": "us-central1"`) {
		t.Errorf("regional first = %v %s", err, h.stdout.String())
	}
	if err := h.run("compute", "health-check", "get", "check-80", "--global"); err != nil || !strings.Contains(h.stdout.String(), `"port": "443"`) {
		t.Errorf("--global = %v %s", err, h.stdout.String())
	}
	// Two regions: ambiguous.
	h.gce.addCheck("europe-west1", "check-80", 80)
	if err := h.run("compute", "health-check", "get", "check-80"); exitClass(err) != "ambiguous" {
		t.Errorf("two regions = %v", err)
	}
}
