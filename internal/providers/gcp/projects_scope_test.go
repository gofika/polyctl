package gcp

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/api/dns/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// The rows a still fresh set holds of a project that is no longer selected
// (the selection changed in config.yaml, by a login or by hand) are out of
// scope: a command neither finds nor changes a resource of a project the
// account was taken off, and the lists do not show it.
func TestRowsOfDeselectedProjectAreOutOfScope(t *testing.T) {
	h := twoProjects(t)
	h.gce.addInstance("proj", "us-central1-a", "own", "10.0.0.1", "")
	h.gce.addInstance("p2", "us-central1-a", "web", "10.0.0.2", "")
	h.addRuleIn("p2", "us-central1", "lb-x", "34.2.2.2")
	if err := h.run("compute", "instance", "get", "web"); err != nil {
		t.Fatal(err)
	}
	if err := h.run("compute", "load-balancer", "get", "lb-x"); err != nil {
		t.Fatal(err)
	}
	// The selection shrinks without the cache being told; the sets stay
	// fresh, and offline nothing can be synced away.
	h.selectProjects("proj", "proj")
	h.rt.Flags.Offline = true
	if err := h.run("compute", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	var res instanceResult
	h.jsonOut(&res)
	if len(res.Instances) != 1 || res.Instances[0].Name != "own" {
		t.Errorf("list = %+v, want the instance of proj alone", res.Instances)
	}
	h.rt.Flags.Offline = false
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "stop", "web", "--yes"); exitClass(err) != "notfound" {
		t.Errorf("stop of an instance of the deselected project = %v, want not found", err)
	}
	if n := h.countCalls("/projects/p2/"); n != 0 {
		t.Errorf("instance stop asked the deselected project %d time(s)", n)
	}
	h.rt.Flags.DryRun = false
	if err := h.run("compute", "load-balancer", "get", "lb-x"); exitClass(err) != "notfound" {
		t.Errorf("load balancer of the deselected project = %v, want not found", err)
	}
	if n := h.countCalls("/projects/p2/"); n != 0 {
		t.Errorf("load-balancer get asked the deselected project %d time(s)", n)
	}
	// --project still reaches it, live.
	if err := h.run("compute", "instance", "get", "web", "--project", "p2"); err != nil {
		t.Errorf("--project p2 = %v", err)
	}
}

// The same for managed zones: the cached zone of a deselected project no
// longer answers to its name.
func TestZoneOfDeselectedProjectIsOutOfScope(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "own", "example.com", "public")
	g.addZone("p2", "main", "example.org", "public")
	g.addRRSet("p2", "main", &dns.ResourceRecordSet{Name: "www.example.org.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})
	if err := h.run("dns", "record", "list", "main"); err != nil {
		t.Fatal(err)
	}
	h.selectProjects("p1", "p1")
	g.reset()
	if err := h.run("dns", "record", "list", "example.org"); exitClass(err) != "notfound" {
		t.Errorf("DNS name of a zone of the deselected project = %v, want not found", err)
	}
	if err := h.run("dns", "record", "list", "main"); exitClass(err) != "notfound" {
		t.Errorf("zone of the deselected project = %v, want not found", err)
	}
	if got := g.projectsCalled(); strings.Contains(got, "p2") {
		t.Errorf("projects asked = %q, want p1 alone", got)
	}
	if err := h.run("dns", "zone", "list"); err != nil || strings.Contains(h.stdout.String(), "example.org") {
		t.Errorf("zone list = %v\n%s", err, h.stdout.String())
	}
}

// A re-login tells the login command which projects left the selection
// (their cached rows are dropped) and whether the selection changed at all.
func TestCoverageChange(t *testing.T) {
	meta := func(def, projects string) map[string]string {
		m := map[string]string{metaProject: def}
		if projects != "" {
			m[metaProjects] = projects
		}
		return m
	}
	p := &provider{}
	var _ platform.CoverageChanger = p
	for _, c := range []struct {
		name          string
		before, after map[string]string
		dropped       []string
		changed       bool
	}{
		{"same single project", meta("a", ""), meta("a", ""), nil, false},
		{"another default of the same selection", meta("a", "a,b"), meta("b", "b,a"), nil, false},
		{"a project added", meta("a", ""), meta("a", "a,b"), nil, true},
		{"a project removed", meta("a", "a,b,c"), meta("a", "a,c"), []string{"b"}, true},
		{"another single project", meta("a", ""), meta("b", ""), []string{"a"}, true},
	} {
		dropped, changed := p.CoverageChange(c.before, c.after)
		if !reflect.DeepEqual(dropped, c.dropped) || changed != c.changed {
			t.Errorf("%s: dropped %v, changed %v; want %v, %v", c.name, dropped, changed, c.dropped, c.changed)
		}
	}
}
