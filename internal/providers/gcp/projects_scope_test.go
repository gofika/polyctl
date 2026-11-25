package gcp

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"google.golang.org/api/dns/v1"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// The rows a still fresh set holds of a project that was disabled since
// (in config.yaml, by a login or by hand) are out of scope: a command
// neither finds nor changes a resource of a project the account was taken
// off, and the lists do not show it.
func TestRowsOfDisabledProjectAreOutOfScope(t *testing.T) {
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
	// The project is disabled without the cache being told; the sets stay
	// fresh, and offline nothing can be synced away.
	h.disableProjects("p2")
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
		t.Errorf("stop of an instance of the disabled project = %v, want not found", err)
	}
	if n := h.countCalls("/projects/p2/"); n != 0 {
		t.Errorf("instance stop asked the disabled project %d time(s)", n)
	}
	h.rt.Flags.DryRun = false
	if err := h.run("compute", "load-balancer", "get", "lb-x"); exitClass(err) != "notfound" {
		t.Errorf("load balancer of the disabled project = %v, want not found", err)
	}
	if n := h.countCalls("/projects/p2/"); n != 0 {
		t.Errorf("load-balancer get asked the disabled project %d time(s)", n)
	}
	// --project still reaches it, live.
	if err := h.run("compute", "instance", "get", "web", "--project", "p2"); err != nil {
		t.Errorf("--project p2 = %v", err)
	}
}

// The same for managed zones: the cached zone of a disabled project no
// longer answers to its name.
func TestZoneOfDisabledProjectIsOutOfScope(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "own", "example.com", "public")
	g.addZone("p2", "main", "example.org", "public")
	g.addRRSet("p2", "main", &dns.ResourceRecordSet{Name: "www.example.org.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})
	if err := h.run("dns", "record", "list", "main"); err != nil {
		t.Fatal(err)
	}
	h.disableProjects("p2")
	g.reset()
	if err := h.run("dns", "record", "list", "example.org"); exitClass(err) != "notfound" {
		t.Errorf("DNS name of a zone of the disabled project = %v, want not found", err)
	}
	if err := h.run("dns", "record", "list", "main"); exitClass(err) != "notfound" {
		t.Errorf("zone of the disabled project = %v, want not found", err)
	}
	if got := g.projectsCalled(); strings.Contains(got, "p2") {
		t.Errorf("projects asked = %q, want p1 alone", got)
	}
	if err := h.run("dns", "zone", "list"); err != nil || strings.Contains(h.stdout.String(), "example.org") {
		t.Errorf("zone list = %v\n%s", err, h.stdout.String())
	}
}

// A re-login tells the login command which projects it disabled (their
// cached rows are dropped) and whether what the account covers changed at
// all: the default, the disabled projects, or, for a login made while an
// account held a selection, everything.
func TestCoverageChange(t *testing.T) {
	meta := func(def, disabled string) map[string]string {
		m := map[string]string{metaProject: def}
		if disabled != "" {
			m[metaDisabledProjects] = disabled
		}
		return m
	}
	legacy := func(def, projects string) map[string]string {
		return map[string]string{metaProject: def, legacyProjects: projects}
	}
	p := &provider{}
	var _ platform.CoverageChanger = p
	for _, c := range []struct {
		name          string
		before, after map[string]string
		dropped       []string
		changed       bool
	}{
		{"nothing changes", meta("a", "x"), meta("a", "x"), nil, false},
		{"the same projects in another order", meta("a", "x,y"), meta("a", "y, x"), nil, false},
		{"another default", meta("a", ""), meta("b", ""), nil, true},
		{"a project disabled", meta("a", "x"), meta("a", "x,y"), []string{"y"}, true},
		{"a project enabled again", meta("a", "x,y"), meta("a", "x"), nil, true},
		{"one disabled and one enabled", meta("a", "x"), meta("a", "y"), []string{"y"}, true},
		{"the default named as disabled is not", meta("a", ""), meta("a", "a"), nil, false},
		{"a login that held a selection", legacy("a", "a,b"), meta("a", ""), nil, true},
		{"a login that held a selection, one disabled", legacy("a", "a,b"), meta("a", "c"), []string{"c"}, true},
	} {
		dropped, changed := p.CoverageChange(c.before, c.after)
		if !reflect.DeepEqual(dropped, c.dropped) || changed != c.changed {
			t.Errorf("%s: dropped %v, changed %v; want %v, %v", c.name, dropped, changed, c.dropped, c.changed)
		}
	}
}

// A zone id names its project; --project must not contradict it, so that a
// call pinned to one project never reads or writes a zone of another.
func TestZoneIDMustBeOfThePinnedProject(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "main", "example.com", "public")
	g.addZone("p2", "main", "example.org", "public")
	g.reset()
	for _, args := range [][]string{
		{"dns", "record", "list", "p2/main", "--project", "p1"},
		{"dns", "record", "upsert", "p2/main", "--type", "A", "--name", "www", "--value", "192.0.2.9", "--project", "p1"},
		{"dns", "record", "delete", "p2/main", "--type", "A", "--name", "www", "--yes", "--project", "p1"},
	} {
		err := h.run(args...)
		if exitClass(err) != "usage" || !has(err, "p2/main", "--project p1") {
			t.Errorf("%v = %v, want a usage error naming both", args[2:], err)
		}
	}
	for _, c := range g.calls {
		if strings.Contains(c, "/changes") || strings.Contains(c, "/projects/p2/") {
			t.Errorf("call %s", c)
		}
	}
	if err := h.run("dns", "record", "list", "p2/main", "--project", "p2"); err != nil {
		t.Errorf("matching --project = %v", err)
	}
}

// A record id whose zone is a bare managed zone name is of the project of
// the zone the command resolved, not of the default project: the record of
// a zone of p2 is deleted by the id polyctl printed before ids carried the
// project.
func TestBareRecordIDIsOfTheZonesProject(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "own", "example.com", "public")
	g.addZone("p2", "main", "example.org", "public")
	g.addRRSet("p2", "main", &dns.ResourceRecordSet{Name: "www.example.org.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})
	if err := h.run("dns", "record", "delete", "main", "--id", "main|A|www.example.org|192.0.2.2", "--yes"); err != nil {
		t.Fatalf("delete by a bare id = %v", err)
	}
	if left := g.rrsets["p2/main"]; len(left) != 0 {
		t.Errorf("record sets left in p2/main: %+v", left)
	}
	// An id that names another zone is refused.
	g.addRRSet("p2", "main", &dns.ResourceRecordSet{Name: "www.example.org.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})
	if err := h.run("dns", "record", "delete", "main", "--id", "p1/own|A|www.example.org|192.0.2.2", "--yes"); err == nil || !has(err, "belongs to managed zone") {
		t.Errorf("an id of another zone = %v", err)
	}
	if left := g.rrsets["p2/main"]; len(left) != 1 {
		t.Errorf("record sets in p2/main: %+v", left)
	}
}

// The live list of a disabled project keeps the instances of the zones
// that answered when one zone is unreachable, as a synced list does.
func TestDisabledProjectListToleratesAnUnreachableZone(t *testing.T) {
	h := twoProjects(t)
	h.disableProjects("p3")
	h.gce.addInstance("p3", "us-central1-a", "solo", "10.0.0.9", "")
	h.gce.unreachable = "zones/europe-west1-b"
	if err := h.run("compute", "instance", "list", "--project", "p3"); err != nil {
		t.Fatalf("list = %v", err)
	}
	var res instanceResult
	h.jsonOut(&res)
	if len(res.Instances) != 1 || res.Instances[0].Name != "solo" || !strings.Contains(h.stderr.String(), "p3/europe-west1-b") {
		t.Errorf("list = %+v, stderr %q", res.Instances, h.stderr.String())
	}
}

// The projects a client covers are asked of it: the enabled projects for
// the client of the account, whatever project it was moved to, and the
// pinned project alone for the client of --project.
func TestClientCoverageAccessors(t *testing.T) {
	h := twoProjects(t)
	ctx := context.Background()
	c, err := openAccount(ctx, h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	for _, pc := range []*client{c, c.inProject("p2"), c.inProject("elsewhere")} {
		if got, err := pc.enabledProjects(ctx); err != nil || strings.Join(got, ",") != "proj,p2" {
			t.Errorf("enabledProjects of the client in %s = %v, %v", pc.project, got, err)
		}
		if got, err := pc.sweep(ctx); err != nil || strings.Join(got, ",") != "proj,p2" {
			t.Errorf("sweep of the client in %s = %v, %v", pc.project, got, err)
		}
	}
	pinned := c.pin("elsewhere")
	if got, err := pinned.sweep(ctx); err != nil || strings.Join(got, ",") != "elsewhere" {
		t.Errorf("sweep of the pinned client = %v, %v", got, err)
	}
	if got, err := pinned.enabledProjects(ctx); err != nil || strings.Join(got, ",") != "proj,p2" {
		t.Errorf("enabledProjects of the pinned client = %v, %v", got, err)
	}
	for project, want := range map[string]bool{"proj": true, "p2": true, "elsewhere": false} {
		if got, err := c.covers(ctx, project); err != nil || got != want {
			t.Errorf("covers(%s) = %v, %v; want %v", project, got, err, want)
		}
		if got := c.inProject(project).cacheable(ctx); got != want {
			t.Errorf("cacheable in %s = %v, want %v", project, got, want)
		}
	}
	if pinned.cacheable(ctx) {
		t.Error("a project outside the enabled ones must not be cached")
	}
	// A cancelled call does not answer: nothing is cached on a guess.
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := c.enabledProjects(cancelled); err == nil {
		t.Error("enabledProjects of a cancelled call = nil error")
	}
	if c.inProject("p2").cacheable(cancelled) {
		t.Error("cacheable of a cancelled call = true")
	}
}

// The scopes of one account share its opened client, and --project is
// that project alone.
func TestScopesShareTheClientOfTheirAccount(t *testing.T) {
	h := twoProjects(t)
	ctx := context.Background()
	scopes, err := gcpScopes(ctx, h.rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(scopes) != 2 || scopes[0].project != "proj" || scopes[1].project != "p2" || scopes[0].c == nil || scopes[0].c != scopes[1].c {
		t.Fatalf("scopes = %+v", scopes)
	}
	for _, sc := range scopes {
		c, err := openScope(ctx, h.rt, sc)
		if err != nil || c.project != sc.project || c.cov != sc.c.cov {
			t.Errorf("openScope(%s) = %+v, %v", sc, c, err)
		}
	}
	h.rt.Flags.Project = "elsewhere"
	if scopes, err = gcpScopes(ctx, h.rt); err != nil || len(scopes) != 1 || scopes[0].project != "elsewhere" {
		t.Fatalf("pinned scopes = %+v, %v", scopes, err)
	}
	if c, err := openScope(ctx, h.rt, scopes[0]); err != nil || !c.pinned || c.project != "elsewhere" {
		t.Errorf("openScope of the pinned scope = %+v, %v", c, err)
	}
	// A scope built without a client opens its account.
	if c, err := openScope(ctx, h.rt, scope{profile: "lab", project: "elsewhere"}); err != nil || c.project != "elsewhere" {
		t.Errorf("openScope without a client = %+v, %v", c, err)
	}
}

// Messages name up to three projects and count them beyond.
func TestProjectsLabelAbbreviates(t *testing.T) {
	h := twoProjects(t)
	ctx := context.Background()
	for _, tc := range []struct {
		selected []string
		label    string
		names    string
	}{
		{[]string{"proj"}, "project proj", "proj"},
		{[]string{"proj", "p2"}, "projects proj, p2", "proj, p2"},
		{[]string{"proj", "p2", "p3"}, "projects proj, p2, p3", "proj, p2, p3"},
		{[]string{"proj", "p2", "p3", "p4"}, "4 projects", "4 projects"},
	} {
		h.enableProjects("proj", tc.selected...)
		c, err := openAccount(ctx, h.rt, "lab")
		if err != nil {
			t.Fatal(err)
		}
		if got := c.projectsLabel(ctx); got != tc.label {
			t.Errorf("projectsLabel of %v = %q, want %q", tc.selected, got, tc.label)
		}
		if got := projectNames(tc.selected); got != tc.names {
			t.Errorf("projectNames(%v) = %q, want %q", tc.selected, got, tc.names)
		}
		if got := c.pin("p9").projectsLabel(ctx); got != "project p9" {
			t.Errorf("projectsLabel of the pinned client = %q", got)
		}
	}
	// A name that is in none of four projects: they are counted.
	h.rt.Flags.Project = ""
	err := h.run("compute", "firewall", "get", "nope")
	if exitClass(err) != "notfound" || !has(err, "in the enabled projects of gcp/lab (4 projects)") {
		t.Errorf("get of a missing rule = %v", err)
	}
}

// What the inventory serves costs no question about the projects of the
// account: an instance and the records of a zone of a project that is not
// the default are found, read and cached again without the list.
func TestCachedLookupsDoNotListProjects(t *testing.T) {
	h := twoProjects(t)
	web := h.gce.addInstance("p2", "us-central1-a", "web", "10.0.0.2", "")
	if err := h.run("compute", "instance", "get", "web"); err != nil {
		t.Fatal(err)
	}
	lists := h.countCalls("GET /v1/projects?")
	if lists == 0 {
		t.Fatal("the first lookup must ask which projects there are")
	}
	web.Status = statusTerminated
	if err := h.run("compute", "instance", "get", "web", "--field", "status"); err != nil || strings.TrimSpace(h.stdout.String()) != statusTerminated {
		t.Fatalf("second get = %q, %v", h.stdout.String(), err)
	}
	// run starts the list of calls anew.
	if n := h.countCalls("GET /v1/projects?"); n != 0 {
		t.Errorf("a lookup served by the inventory listed the projects %d time(s)", n)
	}
	db, err := h.rt.DB()
	if err != nil {
		t.Fatal(err)
	}
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.GCP, Profile: "lab", Type: platform.ResInstance})
	if err != nil || len(rows) != 1 || !strings.Contains(string(rows[0].Data), statusTerminated) {
		t.Errorf("the instance read live was not cached again: %+v, %v", rows, err)
	}

	d, g := multiDNS(t)
	d.nonInteractive()
	g.addZone("p2", "main", "example.org", "public")
	g.addRRSet("p2", "main", &dns.ResourceRecordSet{Name: "www.example.org.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})
	if err := d.run("dns", "record", "list", "main"); err != nil {
		t.Fatal(err)
	}
	g.reset()
	if err := d.run("dns", "record", "list", "main"); err != nil || len(g.calls) != 0 {
		t.Errorf("cached record list = %v, calls %v; want none", err, g.calls)
	}
	if err := d.run("dns", "record", "upsert", "main", "--type", "A", "--name", "api", "--value", "192.0.2.4"); err != nil {
		t.Fatal(err)
	}
	for _, c := range g.calls {
		if c == "GET /v1/projects" {
			t.Errorf("a record change in a cached zone listed the projects: %v", g.calls)
		}
	}
	if got := strings.Join(d.rowsOf(platform.ResDNSRecord), "; "); !strings.Contains(got, "api.example.org") {
		t.Errorf("records after the change = %s, want the new one cached", got)
	}
}
