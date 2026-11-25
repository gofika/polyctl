package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"testing"

	"google.golang.org/api/dns/v1"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// fakeDNS is a Cloud DNS (and Resource Manager) fake that knows several
// projects.
type fakeDNS struct {
	t   *testing.T
	srv *httptest.Server

	mu     sync.Mutex
	zones  map[string][]*dns.ManagedZone       // project
	rrsets map[string][]*dns.ResourceRecordSet // project/zone
	// fail answers the status to every request of a project; disabled
	// answers 403 accessNotConfigured.
	fail     map[string]int
	disabled map[string]bool
	// visible are the projects Resource Manager lists.
	visible []string
	calls   []string
}

func newFakeDNS(t *testing.T) *fakeDNS {
	f := &fakeDNS{t: t, zones: map[string][]*dns.ManagedZone{}, rrsets: map[string][]*dns.ResourceRecordSet{}, fail: map[string]int{}, disabled: map[string]bool{}}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDNS) options() []option.ClientOption {
	return []option.ClientOption{option.WithEndpoint(f.srv.URL + "/")}
}

func (f *fakeDNS) addZone(project, name, dnsName, visibility string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.zones[project] = append(f.zones[project], &dns.ManagedZone{Name: name, DnsName: dnsName + ".", Id: uint64(len(f.zones[project]) + 1), Visibility: visibility})
}

func (f *fakeDNS) addRRSet(project, zone string, rs *dns.ResourceRecordSet) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.rrsets[project+"/"+zone] = append(f.rrsets[project+"/"+zone], rs)
}

// projectsCalled lists the projects asked since the last reset, sorted.
func (f *fakeDNS) projectsCalled() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	seen := map[string]bool{}
	for _, c := range f.calls {
		if _, rest, ok := strings.Cut(c, "/projects/"); ok {
			p, _, _ := strings.Cut(rest, "/")
			seen[p] = true
		}
	}
	var out []string
	for p := range seen {
		out = append(out, p)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

func (f *fakeDNS) reset() {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = nil
}

func (f *fakeDNS) handle(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	path := r.URL.Path
	f.calls = append(f.calls, r.Method+" "+path)
	if path == "/v1/projects" {
		var out []map[string]any
		for i, p := range f.visible {
			out = append(out, map[string]any{"projectId": p, "name": "Project " + p, "projectNumber": fmt.Sprint(100 + i), "lifecycleState": "ACTIVE"})
		}
		writeJSON(w, map[string]any{"projects": out})
		return
	}
	rest, ok := strings.CutPrefix(path, "/dns/v1/projects/")
	if !ok {
		http.NotFound(w, r)
		return
	}
	parts := strings.Split(rest, "/")
	project := parts[0]
	if f.disabled[project] {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403,"message":"Cloud DNS API has not been used in project before or it is disabled","errors":[{"reason":"accessNotConfigured","message":"disabled"}]}}`)
		return
	}
	if code := f.fail[project]; code != 0 {
		w.WriteHeader(code)
		fmt.Fprintf(w, `{"error":{"code":%d,"message":"forced failure of %s"}}`, code, project)
		return
	}
	find := func(name string) *dns.ManagedZone {
		for _, z := range f.zones[project] {
			if z.Name == name {
				return z
			}
		}
		return nil
	}
	switch {
	case len(parts) == 2 && parts[1] == "managedZones":
		writeJSON(w, map[string]any{"managedZones": f.zones[project]})
	case len(parts) == 3 && parts[1] == "managedZones":
		if z := find(parts[2]); z != nil {
			writeJSON(w, z)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"error":{"code":404,"message":"zone not found"}}`)
	case len(parts) == 4 && parts[3] == "rrsets":
		var out []*dns.ResourceRecordSet
		for _, rs := range f.rrsets[project+"/"+parts[2]] {
			if n := r.URL.Query().Get("name"); n != "" && n != rs.Name {
				continue
			}
			if ty := r.URL.Query().Get("type"); ty != "" && ty != rs.Type {
				continue
			}
			out = append(out, rs)
		}
		writeJSON(w, map[string]any{"rrsets": out})
	case len(parts) == 4 && parts[3] == "changes" && r.Method == http.MethodPost:
		var ch dns.Change
		_ = json.NewDecoder(r.Body).Decode(&ch)
		key := project + "/" + parts[2]
		for _, d := range ch.Deletions {
			var kept []*dns.ResourceRecordSet
			for _, rs := range f.rrsets[key] {
				if rs.Name != d.Name || rs.Type != d.Type {
					kept = append(kept, rs)
				}
			}
			f.rrsets[key] = kept
		}
		f.rrsets[key] = append(f.rrsets[key], ch.Additions...)
		writeJSON(w, map[string]any{"status": "done"})
	default:
		http.NotFound(w, r)
	}
}

// selectProjects stores the selection of the lab account: def is the
// default project.
func (h *gcpHarness) selectProjects(def string, selected ...string) {
	h.t.Helper()
	cfg, err := config.Load(filepath.Join(h.dir, "config.yaml"))
	if err != nil {
		h.t.Fatal(err)
	}
	setSelection(cfg.Profiles["lab"].Platforms[platform.GCP].Metadata, def, selected)
	if err := cfg.Save(); err != nil {
		h.t.Fatal(err)
	}
	if _, err := h.rt.ReloadConfig(); err != nil {
		h.t.Fatal(err)
	}
}

// labMeta reads the metadata of the lab account from the config file.
func (h *gcpHarness) labMeta() map[string]string {
	h.t.Helper()
	cfg, err := config.Load(filepath.Join(h.dir, "config.yaml"))
	if err != nil {
		h.t.Fatal(err)
	}
	return cfg.Profiles["lab"].Platforms[platform.GCP].Metadata
}

// multiDNS is a harness whose Cloud DNS calls go to a fakeDNS, with the
// lab account on the projects p1 (default) and p2.
func multiDNS(t *testing.T) (*gcpHarness, *fakeDNS) {
	t.Helper()
	h, _ := interactiveGCP(t, nil)
	g := newFakeDNS(t)
	old := extraOptions
	extraOptions = g.options()
	t.Cleanup(func() { extraOptions = old })
	h.selectProjects("p1", "p1", "p2")
	return h, g
}

// rowsOf lists "id parent" of the cached rows of a type of the lab
// account.
func (h *gcpHarness) rowsOf(rt platform.ResourceType) []string {
	h.t.Helper()
	db, err := h.rt.DB()
	if err != nil {
		h.t.Fatal(err)
	}
	rows, err := db.List(context.Background(), inventory.Query{Platform: platform.GCP, Profile: "lab", Type: rt})
	if err != nil {
		h.t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.ID+" "+r.ParentID)
	}
	sort.Strings(out)
	return out
}

func (h *gcpHarness) sync(types ...platform.ResourceType) ([]app.SyncReport, error) {
	h.t.Helper()
	return h.rt.SyncAccount(context.Background(), config.AccountRef{Profile: "lab", Platform: platform.GCP}, types)
}

func TestSelectedProjects(t *testing.T) {
	for _, tc := range []struct {
		meta map[string]string
		want string
	}{
		{map[string]string{"project": "p1"}, "p1"},
		{map[string]string{"project": "p1", "projects": ""}, "p1"},
		{map[string]string{"project": "p2", "projects": "p1, p2,p3,p1"}, "p2,p1,p3"},
		{map[string]string{"project": "p9", "projects": "p1"}, "p9,p1"},
		{map[string]string{}, ""},
	} {
		if got := strings.Join(selectedProjects(tc.meta), ","); got != tc.want {
			t.Errorf("selectedProjects(%v) = %q, want %q", tc.meta, got, tc.want)
		}
	}
	meta := map[string]string{"project": "old", "projects": "old,x"}
	setSelection(meta, "p1", []string{"p1"})
	if _, ok := meta["projects"]; ok || meta["project"] != "p1" {
		t.Errorf("a selection of the default alone must not store projects: %v", meta)
	}
	setSelection(meta, "p2", []string{"p1", "p2"})
	if meta["projects"] != "p2,p1" {
		t.Errorf("projects = %q, want the default first", meta["projects"])
	}
}

// Two projects hold a managed zone and an instance of the same name: the
// inventory keeps a row of each, with the project in the zone id, in the
// record ids and in every parent.
func TestSyncKeepsSameNamesOfTwoProjectsApart(t *testing.T) {
	h, g := multiDNS(t)
	for _, p := range []string{"p1", "p2"} {
		g.addZone(p, "main", "example.com", "public")
		g.addRRSet(p, "main", &dns.ResourceRecordSet{Name: "www.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.1"}})
	}
	if reps, err := h.sync(platform.ResZone, platform.ResDNSRecord); err != nil || reps[0].Err != nil || reps[1].Err != nil {
		t.Fatalf("sync = %+v, %v", reps, err)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/main p1; p2/main p2" {
		t.Errorf("zones = %s", got)
	}
	want := "p1/main|A|www.example.com|192.0.2.1 p1/main; p2/main|A|www.example.com|192.0.2.1 p2/main"
	if got := strings.Join(h.rowsOf(platform.ResDNSRecord), "; "); got != want {
		t.Errorf("records = %s", got)
	}

	// Instances go to the Compute Engine fake.
	extraOptions = h.gce.options()
	a := h.gce.addInstance("p1", "us-central1-a", "web", "10.0.0.1", "34.0.0.1")
	b := h.gce.addInstance("p2", "us-central1-a", "web", "10.0.0.2", "34.0.0.2")
	if reps, err := h.sync(platform.ResInstance); err != nil || reps[0].Err != nil {
		t.Fatalf("sync instances = %+v, %v", reps, err)
	}
	want = fmt.Sprintf("%d p1/us-central1-a; %d p2/us-central1-a", a.Id, b.Id)
	if got := strings.Join(h.rowsOf(platform.ResInstance), "; "); got != want {
		t.Errorf("instances = %s, want %s", got, want)
	}
}

// A project that fails does not hide the others: their rows are replaced,
// the rows stored for the failed project stay, and the set is due again.
func TestSyncOfFailedProjectKeepsItsRows(t *testing.T) {
	h, g := multiDNS(t)
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	g.zones["p1"] = nil
	g.addZone("p1", "uno", "uno.example", "public")
	g.fail["p2"] = http.StatusInternalServerError
	reps, err := h.sync(platform.ResZone)
	if err != nil || len(reps) != 1 {
		t.Fatalf("sync = %+v, %v", reps, err)
	}
	rse := platform.AsRegionSyncError(reps[0].Err)
	if rse == nil || len(rse.Failures) != 1 || rse.Failures[0].Region != "p2" || !rse.Failures[0].Tree {
		t.Fatalf("error = %v, want a tree failure of p2", reps[0].Err)
	}
	if msg := reps[0].Err.Error(); !strings.Contains(msg, "polyctl gcp project remove p2") || strings.Contains(msg, "region(s)") {
		t.Errorf("message = %s", msg)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/uno p1; p2/two p2" {
		t.Errorf("zones = %s, want the new zone of p1 and the kept one of p2", got)
	}
	db, _ := h.rt.DB()
	st, err := db.GetState(context.Background(), inventory.Set{Platform: platform.GCP, Profile: "lab", Type: platform.ResZone})
	if err != nil || st == nil || st.Fresh(st.SyncedAt.Add(1)) {
		t.Errorf("state = %+v, %v; want the set due at once", st, err)
	}

	// Every project failing is a plain failure: nothing is replaced.
	g.fail["p1"] = http.StatusInternalServerError
	reps, err = h.sync(platform.ResZone)
	if err != nil || reps[0].Err == nil || platform.AsRegionSyncError(reps[0].Err) != nil {
		t.Fatalf("all failed: %+v, %v; want a plain error", reps, err)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/uno p1; p2/two p2" {
		t.Errorf("zones after a failed sync = %s", got)
	}
}

// A selected project without the API of a type holds nothing of the type;
// it does not make the sync of the type fail for ever.
func TestSyncCountsDisabledAPIAsEmpty(t *testing.T) {
	h, g := multiDNS(t)
	g.addZone("p1", "one", "one.example", "public")
	g.disabled["p2"] = true
	reps, err := h.sync(platform.ResZone)
	if err != nil || reps[0].Err != nil || reps[0].Count != 1 {
		t.Fatalf("sync = %+v, %v; want one zone and no error", reps, err)
	}
	// With that project alone selected the answer is the error it is.
	h.selectProjects("p2", "p2")
	if reps, err = h.sync(platform.ResZone); err == nil && reps[0].Err == nil {
		t.Errorf("one project, API disabled: %+v, %v; want an error", reps, err)
	}
}

// An account without a stored selection (every login before the selection
// existed) has exactly its one project selected.
func TestAccountWithoutSelectionUsesItsProject(t *testing.T) {
	h, g := multiDNS(t)
	h.selectProjects("p1", "p1")
	if _, ok := h.labMeta()["projects"]; ok {
		t.Fatalf("metadata = %v, want no projects key", h.labMeta())
	}
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	g.reset()
	if _, err := h.sync(platform.ResZone, platform.ResDNSRecord); err != nil {
		t.Fatal(err)
	}
	if got := g.projectsCalled(); got != "p1" {
		t.Errorf("projects asked = %s, want p1 alone", got)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1" {
		t.Errorf("zones = %s", got)
	}
}

// Ids built before a zone id carried its project (a bare managed zone
// name) still name the zone of the client's project.
func TestBareZoneAndRecordIDsAreOfTheClientsProject(t *testing.T) {
	h, g := multiDNS(t)
	g.addZone("p1", "main", "example.com", "public")
	g.addRRSet("p1", "main", &dns.ResourceRecordSet{Name: "www.example.com.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.1", "192.0.2.2"}})
	c, err := openAccount(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	recs, err := c.ListRecords(context.Background(), "main")
	if err != nil || len(recs) != 2 || recs[0].ZoneID != "p1/main" || !strings.HasPrefix(recs[0].ID, "p1/main|A|") {
		t.Fatalf("records = %+v, %v", recs, err)
	}
	if err := c.DeleteRecord(context.Background(), "main", "main|A|www.example.com|192.0.2.1"); err != nil {
		t.Fatalf("delete by a bare id: %v", err)
	}
	if rs := g.rrsets["p1/main"]; len(rs) != 1 || len(rs[0].Rrdatas) != 1 || rs[0].Rrdatas[0] != "192.0.2.2" {
		t.Errorf("rrsets = %+v", rs)
	}
	r, err := c.UpdateRecord(context.Background(), "p1/main", platform.Record{ID: "main|A|www.example.com|192.0.2.2", Value: "192.0.2.9"})
	if err != nil || r.ID != "p1/main|A|www.example.com|192.0.2.9" {
		t.Errorf("update by a bare id = %+v, %v", r, err)
	}
	// A zone of another project is reached through its id by any client.
	g.addZone("p2", "main", "example.org", "public")
	if z, err := c.GetZone(context.Background(), "p2/main"); err != nil || z.Name != "example.org" || z.ID != "p2/main" {
		t.Errorf("zone of p2 = %+v, %v", z, err)
	}
	if err := c.DeleteRecord(context.Background(), "p2/main", "p1/main|A|www.example.com|192.0.2.9"); err == nil || !strings.Contains(err.Error(), "belongs to managed zone") {
		t.Errorf("record of another zone = %v", err)
	}
}

// The same managed zone name in two projects: the interactive flow asks
// which one this call means; the non-interactive flow fails with exit code
// 5, lists both and names --project; --project and the zone id pin one.
func TestZoneOfTwoProjectsIsAmbiguous(t *testing.T) {
	h, g := multiDNS(t)
	g.addZone("p1", "main", "example.com", "public")
	g.addZone("p2", "main", "example.org", "public")
	g.addRRSet("p2", "main", &dns.ResourceRecordSet{Name: "www.example.org.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})

	p := h.answer(prompttest.Label("project p2"))
	if err := h.run("dns", "record", "list", "main"); err != nil || !strings.Contains(h.stdout.String(), "www.example.org") {
		t.Fatalf("interactive = %v\n%s", err, h.stdout.String())
	}
	p.Done()
	a := p.Asked[0]
	if l := prompttest.Labels(a.Options); !strings.Contains(a.Title, `managed zone "main"`) ||
		!strings.Contains(l, "main  example.com  public  0 nameservers  project p1") || !strings.Contains(l, "main  example.org  public  0 nameservers  project p2") {
		t.Errorf("pick %q:\n%s", a.Title, l)
	}

	h.nonInteractive()
	err := h.run("dns", "record", "list", "main")
	if exitClass(err) != "ambiguous" {
		t.Fatalf("non-interactive = %v, want ambiguous", err)
	}
	for _, want := range []string{"gcp/lab project p1 (zone main, example.com  public)", "gcp/lab project p2 (zone main, example.org  public)",
		"pass --project <id>, or the zone id <project>/<managed zone>, to choose"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not hold %q", err, want)
		}
	}
	if err := h.run("dns", "record", "list", "main", "--project", "p2"); err != nil || !strings.Contains(h.stdout.String(), "www.example.org") {
		t.Errorf("--project p2 = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "record", "list", "p2/main"); err != nil || !strings.Contains(h.stdout.String(), "www.example.org") {
		t.Errorf("zone id = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "zone", "get", "main", "--project", "p1"); err != nil || !strings.Contains(h.stdout.String(), `"p1/main"`) {
		t.Errorf("zone get --project p1 = %v\n%s", err, h.stdout.String())
	}
	// A DNS name that one zone answers to is not ambiguous.
	if err := h.run("dns", "record", "list", "example.org"); err != nil {
		t.Errorf("dns name = %v", err)
	}
	if err := h.run("dns", "zone", "get", "main", "--project", "a/b"); exitClass(err) != "general" && exitClass(err) != "usage" {
		t.Errorf("bad --project = %v", err)
	}
}

// A public and a private zone of one DNS name in one project: the DNS name
// stands for both, so it is ambiguous too, instead of the first one being
// taken silently. The managed zone name tells them apart.
func TestSplitHorizonDNSNameIsAmbiguous(t *testing.T) {
	h, g := multiDNS(t)
	h.selectProjects("p1", "p1")
	g.addZone("p1", "pub", "example.com", "public")
	g.addZone("p1", "priv", "example.com", "private")
	h.nonInteractive()
	err := h.run("dns", "zone", "get", "example.com")
	if exitClass(err) != "ambiguous" || !strings.Contains(err.Error(), "zone priv") || !strings.Contains(err.Error(), "zone pub") ||
		!strings.Contains(err.Error(), "pass the zone id <project>/<managed zone> to choose") {
		t.Fatalf("dns name of a split-horizon pair = %v", err)
	}
	if err := h.run("dns", "zone", "get", "priv"); err != nil || !strings.Contains(h.stdout.String(), `"private"`) {
		t.Errorf("managed zone name = %v\n%s", err, h.stdout.String())
	}
	p := h.answer(prompttest.Label("private"))
	h.rt.Flags.NonInteractive = false
	if err := h.run("dns", "zone", "get", "example.com"); err != nil || !strings.Contains(h.stdout.String(), `"p1/priv"`) {
		t.Errorf("interactive = %v\n%s", err, h.stdout.String())
	}
	p.Done()
}

// --project may name a project outside the selection: it is read live and
// nothing of it is written to the inventory.
func TestUnselectedProjectIsReadLiveAndNotCached(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p3", "three", "three.example", "public")
	g.addRRSet("p3", "three", &dns.ResourceRecordSet{Name: "www.three.example.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.3"}})
	if err := h.run("dns", "zone", "list", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), "three.example") || strings.Contains(h.stdout.String(), "one.example") {
		t.Fatalf("zone list --project p3 = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "record", "list", "three", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), "192.0.2.3") {
		t.Fatalf("record list --project p3 = %v\n%s", err, h.stdout.String())
	}
	if z, r := h.rowsOf(platform.ResZone), h.rowsOf(platform.ResDNSRecord); len(z)+len(r) != 0 {
		t.Errorf("rows of an unselected project were cached: %v %v", z, r)
	}
	if err := h.run("dns", "zone", "get", "nosuch", "--project", "p3"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing zone = %v", err)
	}
	// A selected pin reads the cache of the whole selection and shows its
	// own project only.
	if err := h.run("dns", "zone", "list", "--project", "p1"); err != nil || !strings.Contains(h.stdout.String(), "one.example") {
		t.Fatalf("zone list --project p1 = %v\n%s", err, h.stdout.String())
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1" {
		t.Errorf("cache after a selected pin = %s", got)
	}
}

// project list marks the selection and the default; current names both.
func TestProjectListMarksSelection(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.visible = []string{"p0", "p1", "p3"}
	if err := h.run("project", "list"); err != nil {
		t.Fatal(err)
	}
	var rows []projectRow
	h.jsonOut(&rows)
	got := ""
	for _, r := range rows {
		got += fmt.Sprintf("%s:%v:%v ", r.ProjectID, r.Selected, r.Default)
	}
	// p2 is selected but not listed: it is appended.
	if got != "p0:false:false p1:true:true p3:false:false p2:true:false " {
		t.Errorf("rows = %s", got)
	}
	grid := projectGrid(rows)
	if strings.Join(grid.Headers, " ") != "PROJECT_ID NAME NUMBER STATE SELECTED" || strings.Join(grid.Rows[1], "|") != "p1 *|Project p1|101|ACTIVE|yes" ||
		strings.Join(grid.Rows[3], "|") != "p2||||yes" || strings.Join(grid.Rows[0], "|") != "p0|Project p0|100|ACTIVE|" {
		t.Errorf("grid = %+v", grid)
	}
	if err := h.run("project", "current"); err != nil {
		t.Fatal(err)
	}
	var cur currentProject
	h.jsonOut(&cur)
	if cur.Project != "p1" || strings.Join(cur.Projects, ",") != "p1,p2" {
		t.Errorf("current = %+v", cur)
	}
	if err := h.run("project", "list", "--project", "p1"); err == nil {
		t.Error("gcp project takes no --project")
	}
}

// use, add and remove change the selection without a login; the cache of
// the account is made due, and the rows of a removed project are dropped.
func TestProjectUseAddRemove(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	g.addZone("p3", "three", "three.example", "public")
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	fresh := func() bool {
		db, _ := h.rt.DB()
		st, err := db.GetState(context.Background(), inventory.Set{Platform: platform.GCP, Profile: "lab", Type: platform.ResZone})
		if err != nil || st == nil {
			t.Fatalf("state = %+v, %v", st, err)
		}
		return st.ExpiresAt.After(st.SyncedAt)
	}
	meta := func() string { m := h.labMeta(); return m["project"] + " [" + m["projects"] + "]" }
	if !fresh() {
		t.Fatal("the set must be fresh after the sync")
	}

	// use: a selected project becomes the default.
	if err := h.run("project", "use", "p2"); err != nil || meta() != "p2 [p2,p1]" {
		t.Fatalf("use p2 = %v, %s", err, meta())
	}
	if fresh() {
		t.Error("use must make the cached sets due")
	}
	// use: an unselected one is added, after its access was checked.
	g.fail["p9"] = http.StatusForbidden
	if err := h.run("project", "use", "p9"); exitClass(err) != "auth" || meta() != "p2 [p2,p1]" {
		t.Errorf("use of an unreachable project = %v, %s", err, meta())
	}
	h.rt.Flags.Offline = true
	if err := h.run("project", "use", "p9"); err != nil || meta() != "p9 [p9,p2,p1]" || !strings.Contains(h.stderr.String(), "was not checked") {
		t.Errorf("use --offline = %v, %s / %s", err, meta(), h.stderr.String())
	}
	h.rt.Flags.Offline = false
	if err := h.run("project", "use", "p9"); err != nil || !strings.Contains(h.stderr.String(), "already the default") {
		t.Errorf("use of the default = %v / %s", err, h.stderr.String())
	}

	// add: several at once; one that is selected already is nothing to do.
	if err := h.run("project", "add", "p3", "p1"); err != nil || meta() != "p9 [p9,p2,p1,p3]" {
		t.Errorf("add = %v, %s", err, meta())
	}
	if err := h.run("project", "add", "p3"); exitClass(err) != "nothing" {
		t.Errorf("add again = %v", err)
	}
	if err := h.run("project", "add", "p8"); err != nil {
		t.Errorf("add p8 = %v", err)
	}
	if err := h.run("project", "add", "a/b"); exitClass(err) != "usage" {
		t.Errorf("add of a bad id = %v", err)
	}
	if err := h.run("project", "add"); err == nil {
		t.Error("add without an id must fail in the non-interactive flow")
	}

	// remove: not selected is not found; the default needs --default; all
	// of them is a usage error.
	if err := h.run("project", "remove", "nosuch"); exitClass(err) != "notfound" {
		t.Errorf("remove of an unselected project = %v", err)
	}
	if err := h.run("project", "remove", "p9"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--default <id>") {
		t.Errorf("remove of the default = %v", err)
	}
	if err := h.run("project", "remove", "p9", "--default", "p9"); exitClass(err) != "usage" {
		t.Errorf("--default of a removed project = %v", err)
	}
	if err := h.run("project", "remove", "p9", "p8", "--default", "p1"); err != nil || meta() != "p1 [p1,p2,p3]" {
		t.Errorf("remove with --default = %v, %s", err, meta())
	}
	if err := h.run("project", "remove", "p1", "p2", "p3"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "auth logout") {
		t.Errorf("remove of every project = %v", err)
	}
	// The rows of a removed project go, the others stay; --offline works.
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1; p2/two p2; p3/three p3" {
		t.Fatalf("zones = %s", got)
	}
	h.rt.Flags.Offline = true
	if err := h.run("project", "remove", "p2", "p3"); err != nil || meta() != "p1 []" {
		t.Errorf("remove = %v, %s", err, meta())
	}
	h.rt.Flags.Offline = false
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1" {
		t.Errorf("zones after remove = %s", got)
	}
	for _, sub := range []string{"use", "add", "remove"} {
		if c, _, err := Command(h.rt).Find([]string{"project", sub}); err != nil || c.Annotations[app.NoDryRunAnnotation] == "" {
			t.Errorf("project %s must refuse --dry-run", sub)
		}
	}
}

// Without arguments the interactive flow picks from a list: the visible
// projects for use and add, the selected ones for remove, and the new
// default when the default goes.
func TestProjectCommandsPick(t *testing.T) {
	h, g := multiDNS(t)
	g.visible = []string{"p1", "p2", "p3", "p4"}
	meta := func() string { m := h.labMeta(); return m["project"] + " [" + m["projects"] + "]" }

	p := h.answer("p3")
	if err := h.run("project", "use"); err != nil || meta() != "p3 [p3,p1,p2]" {
		t.Fatalf("use = %v, %s", err, meta())
	}
	p.Done()
	if a := p.Asked[0]; a.Default != "p1" || !strings.Contains(prompttest.Labels(a.Options), "p1  Project p1  default") || !strings.Contains(prompttest.Labels(a.Options), "p2  Project p2  selected") {
		t.Errorf("use asked %+v", a)
	}

	p = h.answer([]string{"p4"})
	if err := h.run("project", "add"); err != nil || meta() != "p3 [p3,p1,p2,p4]" {
		t.Fatalf("add = %v, %s", err, meta())
	}
	if a := p.Asked[0]; a.Kind != "multi" || prompttest.Values(a.Options) != "p4" {
		t.Errorf("add offered %+v", a)
	}

	p = h.answer([]string{"p3", "p4"}, "p2")
	if err := h.run("project", "remove"); err != nil || meta() != "p2 [p2,p1]" {
		t.Fatalf("remove = %v, %s", err, meta())
	}
	p.Done()
	if a := p.Asked[0]; prompttest.Values(a.Options) != "p3 p1 p2 p4" || !strings.Contains(prompttest.Labels(a.Options), "p3  default") {
		t.Errorf("remove offered %+v", a)
	}
	if a := p.Asked[1]; a.Title != "New default project" || prompttest.Values(a.Options) != "p1 p2" {
		t.Errorf("new default asked %+v", a)
	}
}
