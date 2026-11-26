package gcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"
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
	// billingOff answers 403 with a BILLING_DISABLED detail.
	billingOff map[string]bool
	// visible are the projects Resource Manager lists; listFail answers
	// the list with that status instead.
	visible  []string
	listFail int
	calls    []string
}

func newFakeDNS(t *testing.T) *fakeDNS {
	f := &fakeDNS{t: t, zones: map[string][]*dns.ManagedZone{}, rrsets: map[string][]*dns.ResourceRecordSet{}, fail: map[string]int{}, disabled: map[string]bool{}, billingOff: map[string]bool{}}
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
		if f.listFail != 0 {
			w.WriteHeader(f.listFail)
			fmt.Fprintf(w, `{"error":{"code":%d,"message":"forced failure of the project list"}}`, f.listFail)
			return
		}
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
	if f.billingOff[project] {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprint(w, `{"error":{"code":403,"message":"This API method requires billing to be enabled. Please enable billing on the project.","errors":[{"reason":"forbidden","message":"billing"}],"details":[{"@type":"type.googleapis.com/google.rpc.ErrorInfo","reason":"BILLING_DISABLED","domain":"googleapis.com"}]}}`)
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

// enableProjects makes def the default project of the lab account and
// visible the projects its credentials list (on the Compute Engine fake):
// all of them are enabled, but the ones disableProjects names.
func (h *gcpHarness) enableProjects(def string, visible ...string) {
	h.t.Helper()
	h.gce.mu.Lock()
	h.gce.visible = visible
	h.gce.mu.Unlock()
	h.editMeta(func(meta map[string]string) { setProjects(meta, def, disabledProjects(meta)) })
}

// disableProjects stores the disabled projects of the lab account.
func (h *gcpHarness) disableProjects(ids ...string) {
	h.t.Helper()
	h.editMeta(func(meta map[string]string) { setProjects(meta, meta[metaProject], ids) })
}

// editMeta changes the stored metadata of the lab account.
func (h *gcpHarness) editMeta(edit func(meta map[string]string)) {
	h.t.Helper()
	cfg, err := config.Load(filepath.Join(h.dir, "config.yaml"))
	if err != nil {
		h.t.Fatal(err)
	}
	edit(cfg.Profiles["lab"].Platforms[platform.GCP].Metadata)
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
	h.enableOn(g, "p1", "p1", "p2")
	return h, g
}

// enableOn is enableProjects for a harness whose projects are listed by a
// fakeDNS: both fakes list the same projects.
func (h *gcpHarness) enableOn(g *fakeDNS, def string, visible ...string) {
	h.t.Helper()
	g.mu.Lock()
	g.visible = visible
	g.mu.Unlock()
	h.enableProjects(def, visible...)
}

// labProjects is "<default> [<disabled projects>]" of the lab account.
func (h *gcpHarness) labProjects() string {
	m := h.labMeta()
	return m[metaProject] + " [" + m[metaDisabledProjects] + "]"
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

// Only the disabled projects are stored. The default project is never one
// of them, and the key of the former selection is neither read nor kept.
func TestDisabledProjects(t *testing.T) {
	for _, tc := range []struct {
		meta map[string]string
		want string
	}{
		{map[string]string{"project": "p1"}, ""},
		{map[string]string{"project": "p1", "disabled_projects": ""}, ""},
		{map[string]string{"project": "p1", "disabled_projects": "p3, p2,p3,,p2"}, "p3,p2"},
		{map[string]string{"project": "p1", "disabled_projects": "p1,p2"}, "p2"},
		{map[string]string{"project": "p1", "projects": "p1,p2"}, ""},
		{map[string]string{}, ""},
	} {
		if got := strings.Join(disabledProjects(tc.meta), ","); got != tc.want {
			t.Errorf("disabledProjects(%v) = %q, want %q", tc.meta, got, tc.want)
		}
	}
	meta := map[string]string{"project": "old", "projects": "old,x", "disabled_projects": "a"}
	setProjects(meta, "p1", nil)
	if len(meta) != 1 || meta["project"] != "p1" {
		t.Errorf("nothing disabled must store the default alone: %v", meta)
	}
	setProjects(meta, "p2", []string{"z", "p2", "a", "z"})
	if meta["disabled_projects"] != "a,z" || meta["project"] != "p2" {
		t.Errorf("metadata = %v, want the disabled projects sorted, once, without the default", meta)
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
	if msg := reps[0].Err.Error(); !strings.Contains(msg, "polyctl gcp project disable p2 --profile lab") || strings.Contains(msg, "region(s)") {
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

// A project in which the API of the type is not enabled, or whose billing
// is off, holds nothing of the type: it never fails a sync, also when it
// is the only project, it is asked once per run, and the user is told
// once which projects were skipped.
func TestSyncCountsDisabledAPIAsEmpty(t *testing.T) {
	h, g := multiDNS(t)
	g.addZone("p1", "one", "one.example", "public")
	g.addRRSet("p1", "one", &dns.ResourceRecordSet{Name: "www.one.example.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.1"}})
	g.disabled["p2"] = true
	g.reset()
	reps, err := h.sync(platform.ResZone, platform.ResDNSRecord)
	if err != nil || reps[0].Err != nil || reps[0].Count != 1 || reps[1].Err != nil || reps[1].Count != 1 {
		t.Fatalf("sync = %+v, %v; want one zone, one record and no error", reps, err)
	}
	// The record sync reuses the zones of p1 and does not ask p2 again.
	g.mu.Lock()
	calls := strings.Join(g.calls, "\n")
	g.mu.Unlock()
	if n := strings.Count(calls, "/projects/p2/"); n != 1 {
		t.Errorf("p2 was asked %d times in one run, want once:\n%s", n, calls)
	}
	if n := strings.Count(calls, "GET /dns/v1/projects/p1/managedZones\n"); n != 1 {
		t.Errorf("the zones of p1 were listed %d times in one run, want once:\n%s", n, calls)
	}
	want := "note: gcp/lab: skipped 1 project(s) in which an API is not enabled or billing is off: p2 (Cloud DNS API); they hold nothing there. To stop asking them: polyctl gcp project disable p2 --profile lab\n"
	if got := h.stderr.String(); got != want {
		t.Errorf("stderr = %q\nwant     %q", got, want)
	}
	// A second sweep of the same run does not tell it again.
	h.stderr.Reset()
	if _, err := h.sync(platform.ResZone); err != nil || h.stderr.Len() != 0 {
		t.Errorf("second sync = %v, stderr %q; want nothing told twice", err, h.stderr.String())
	}

	// The only project of the account: still no failure, and no hint to
	// disable the default project.
	resetOffNotes()
	h.enableOn(g, "p2", "p2")
	reps, err = h.sync(platform.ResZone, platform.ResDNSRecord)
	if err != nil || reps[0].Err != nil || reps[0].Count != 0 || reps[1].Err != nil || reps[1].Count != 0 {
		t.Fatalf("one project, API not enabled: %+v, %v; want nothing and no error", reps, err)
	}
	want = "note: gcp/lab: skipped 1 project(s) in which an API is not enabled or billing is off: p2 (Cloud DNS API); they hold nothing there.\n"
	if got := h.stderr.String(); got != want {
		t.Errorf("stderr = %q\nwant     %q", got, want)
	}

	// Billing off is the same case; several projects are one note.
	resetOffNotes()
	h.stderr.Reset()
	g.billingOff["p3"] = true
	h.enableOn(g, "p1", "p1", "p2", "p3")
	if reps, err = h.sync(platform.ResZone); err != nil || reps[0].Err != nil || reps[0].Count != 1 {
		t.Fatalf("billing off: %+v, %v; want one zone and no error", reps, err)
	}
	want = "note: gcp/lab: skipped 2 project(s) in which an API is not enabled or billing is off: p2 (Cloud DNS API), p3 (an API); they hold nothing there. To stop asking them: polyctl gcp project disable p2 p3 --profile lab\n"
	if got := h.stderr.String(); got != want {
		t.Errorf("stderr = %q\nwant     %q", got, want)
	}

	// A real failure stays one: nothing is skipped.
	resetOffNotes()
	h.stderr.Reset()
	delete(g.billingOff, "p3")
	g.fail["p3"] = 403
	if reps, err = h.sync(platform.ResZone); err != nil || reps[0].Err == nil || strings.Contains(h.stderr.String(), "p3") {
		t.Errorf("permission denied in p3: %+v, %v, stderr %q; want a partial failure", reps, err, h.stderr.String())
	}
}

// The zone list and the lookup of a managed zone name skip a project
// without Cloud DNS, also the only one; a list pinned to it and read live
// keeps the error.
func TestZoneListSkipsProjectWithoutTheAPI(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	h.enableOn(g, "p2", "p2")
	g.disabled["p2"] = true
	if err := h.run("dns", "zone", "list"); err != nil {
		t.Fatalf("zone list = %v, want no error", err)
	}
	if !strings.Contains(h.stderr.String(), "skipped 1 project(s)") || strings.Contains(h.stderr.String(), "project disable") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	c, err := openAccount(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if zones, err := c.ListZones(context.Background()); err != nil || len(zones) != 0 {
		t.Errorf("ListZones = %v, %v; want none and no error", zones, err)
	}
	if _, err := c.pin("p2").ListZones(context.Background()); exitClass(err) != "auth" {
		t.Errorf("pinned ListZones = %v, want the error of the project", err)
	}
	if err := h.run("dns", "record", "list", "main"); exitClass(err) != "notfound" {
		t.Errorf("record list of an unknown zone = %v, want not found", err)
	}
}

// An account covers every active project its credentials see, the default
// first: nothing has to be chosen, and a login made while an account held a
// selection (the metadata "projects") covers the projects that were not
// selected as well.
func TestAccountCoversEveryVisibleProject(t *testing.T) {
	h, g := multiDNS(t)
	h.enableOn(g, "p2", "p1", "p2", "p3")
	h.editMeta(func(meta map[string]string) { meta[legacyProjects] = "p2" })
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	g.addZone("p3", "three", "three.example", "public")
	g.reset()
	if _, err := h.sync(platform.ResZone, platform.ResDNSRecord); err != nil {
		t.Fatal(err)
	}
	if got := g.projectsCalled(); got != "p1,p2,p3" {
		t.Errorf("projects asked = %s, want all three", got)
	}
	g.mu.Lock()
	lists := strings.Count(strings.Join(g.calls, "\n")+"\n", "GET /v1/projects\n")
	g.mu.Unlock()
	if lists != 1 {
		t.Errorf("the projects were listed %d times in one sync of two types, want once", lists)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1; p2/two p2; p3/three p3" {
		t.Errorf("zones = %s", got)
	}
	c, err := openAccount(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if got, err := c.enabledProjects(context.Background()); err != nil || strings.Join(got, ",") != "p2,p1,p3" {
		t.Errorf("enabledProjects = %v, %v; want the default first", got, err)
	}
}

// A project that appears is covered by the next sync without anything
// being configured, and one that disappears loses its rows there.
func TestProjectsThatAppearAndDisappear(t *testing.T) {
	h, g := multiDNS(t)
	for _, p := range []string{"p1", "p2", "p3"} {
		g.addZone(p, "main", p+".example", "public")
	}
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/main p1; p2/main p2" {
		t.Fatalf("zones = %s", got)
	}
	h.enableOn(g, "p1", "p1", "p3")
	reps, err := h.sync(platform.ResZone)
	if err != nil || reps[0].Err != nil {
		t.Fatalf("sync = %+v, %v", reps, err)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/main p1; p3/main p3" {
		t.Errorf("zones = %s, want p3 added and p2 gone", got)
	}
}

// A disabled project is never asked; with all but the default disabled the
// account behaves as one of a single project. The default project named as
// disabled (a config.yaml edited by hand) stays enabled.
func TestDisabledProjectsAreNotSynced(t *testing.T) {
	h, g := multiDNS(t)
	h.enableOn(g, "p1", "p1", "p2", "p3")
	for _, p := range []string{"p1", "p2", "p3"} {
		g.addZone(p, "main", p+".example", "public")
	}
	h.disableProjects("p3")
	g.reset()
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	if got := g.projectsCalled(); got != "p1,p2" {
		t.Errorf("projects asked = %s, want p1 and p2", got)
	}
	h.editMeta(func(meta map[string]string) { meta[metaDisabledProjects] = "p1,p2,p3" })
	g.reset()
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	if got := g.projectsCalled(); got != "p1" {
		t.Errorf("projects asked = %s, want the default alone", got)
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/main p1" {
		t.Errorf("zones = %s", got)
	}
	c, err := openAccount(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if id, err := c.Verify(context.Background()); err != nil || id.Extra[metaDisabledProjects] != "p2,p3" {
		t.Errorf("identity = %+v, %v; want the disabled projects without the default", id, err)
	}
}

// Credentials that cannot list projects (a service account without the
// permission), or that list none, work on the default project alone. A
// list that fails for another reason fails the sync: falling back to the
// default alone would drop the rows of every other project.
func TestCredentialsThatCannotListProjects(t *testing.T) {
	h, g := multiDNS(t)
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	if _, err := h.sync(platform.ResZone); err != nil {
		t.Fatal(err)
	}
	for _, code := range []int{http.StatusInternalServerError, http.StatusTooManyRequests, http.StatusUnauthorized} {
		g.listFail = code
		reps, err := h.sync(platform.ResZone)
		if err == nil && len(reps) == 1 {
			err = reps[0].Err
		}
		if err == nil || platform.AsRegionSyncError(err) != nil || !strings.Contains(err.Error(), "list the projects of gcp/lab") ||
			(code == http.StatusUnauthorized) != (exitClass(err) == "auth") {
			t.Fatalf("list answering %d: %+v, %v; want a plain failure naming the list", code, reps, err)
		}
		if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1; p2/two p2" {
			t.Errorf("zones after a failed list = %s, want them kept", got)
		}
	}
	g.listFail = http.StatusForbidden
	g.reset()
	if reps, err := h.sync(platform.ResZone); err != nil || reps[0].Err != nil {
		t.Fatalf("sync without the permission to list = %+v, %v", reps, err)
	}
	if got := g.projectsCalled(); got != "p1" {
		t.Errorf("projects asked = %s, want the default alone", got)
	}
	g.listFail = 0
	h.enableOn(g, "p1")
	g.reset()
	if _, err := h.sync(platform.ResZone); err != nil || g.projectsCalled() != "p1" {
		t.Errorf("sync with an empty list = %v, asked %s", err, g.projectsCalled())
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
	h.enableOn(g, "p1", "p1")
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

// --project may name a disabled project: it is read live and nothing of
// it is written to the inventory.
func TestDisabledProjectIsReadLiveAndNotCached(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	h.enableOn(g, "p1", "p1", "p2", "p3")
	h.disableProjects("p3")
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p3", "three", "three.example", "public")
	g.addRRSet("p3", "three", &dns.ResourceRecordSet{Name: "www.three.example.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.3"}})
	g.reset()
	if err := h.run("dns", "zone", "list", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), "three.example") || strings.Contains(h.stdout.String(), "one.example") {
		t.Fatalf("zone list --project p3 = %v\n%s", err, h.stdout.String())
	}
	if got := g.projectsCalled(); got != "p3" {
		t.Errorf("projects asked = %s, want the disabled one alone", got)
	}
	if err := h.run("dns", "record", "list", "three", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), "192.0.2.3") {
		t.Fatalf("record list --project p3 = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "record", "upsert", "three", "--project", "p3", "--type", "A", "--name", "api", "--value", "192.0.2.4"); err != nil {
		t.Fatalf("record upsert --project p3 = %v", err)
	}
	if z, r := h.rowsOf(platform.ResZone), h.rowsOf(platform.ResDNSRecord); len(z)+len(r) != 0 {
		t.Errorf("rows of a disabled project were cached: %v %v", z, r)
	}
	if err := h.run("dns", "zone", "get", "nosuch", "--project", "p3"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing zone = %v", err)
	}
	// Without --project the zone of the disabled project is not found.
	if err := h.run("dns", "record", "list", "three"); exitClass(err) != "notfound" {
		t.Errorf("zone of a disabled project without --project = %v", err)
	}
	// A pin that is enabled reads the cache of the account and shows its
	// own project only.
	if err := h.run("dns", "zone", "list", "--project", "p1"); err != nil || !strings.Contains(h.stdout.String(), "one.example") {
		t.Fatalf("zone list --project p1 = %v\n%s", err, h.stdout.String())
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1" {
		t.Errorf("cache after an enabled pin = %s", got)
	}
	// With --offline the disabled project cannot be read.
	h.rt.Flags.Offline = true
	if err := h.run("dns", "zone", "list", "--project", "p3"); exitClass(err) != "offline" {
		t.Errorf("zone list --project p3 --offline = %v", err)
	}
}

// A service account that cannot list projects works on its default
// project; another project it reaches is named with --project, read live
// and never cached, since no sync of the account covers it.
func TestUnlistedProjectIsReadLiveAndNotCached(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.listFail = http.StatusForbidden
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p3", "three", "three.example", "public")
	g.addRRSet("p3", "three", &dns.ResourceRecordSet{Name: "www.three.example.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.3"}})
	if err := h.run("dns", "zone", "list"); err != nil || !strings.Contains(h.stdout.String(), "one.example") || strings.Contains(h.stdout.String(), "three.example") {
		t.Fatalf("zone list = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "zone", "list", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), "three.example") || strings.Contains(h.stdout.String(), "one.example") {
		t.Fatalf("zone list --project p3 = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "record", "list", "three", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), "192.0.2.3") {
		t.Fatalf("record list --project p3 = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("dns", "record", "upsert", "three", "--project", "p3", "--type", "A", "--name", "api", "--value", "192.0.2.4"); err != nil {
		t.Fatalf("record upsert --project p3 = %v", err)
	}
	if z, r := h.rowsOf(platform.ResZone), h.rowsOf(platform.ResDNSRecord); strings.Join(z, "; ") != "p1/one p1" || len(r) != 0 {
		t.Errorf("cached rows = %v %v, want the zone of the default project alone", z, r)
	}
	// The default project pinned is served from the cache, without asking
	// which projects there are.
	g.reset()
	if err := h.run("dns", "zone", "list", "--project", "p1"); err != nil || !strings.Contains(h.stdout.String(), "one.example") {
		t.Fatalf("zone list --project p1 = %v\n%s", err, h.stdout.String())
	}
	if n := len(g.calls); n != 0 {
		t.Errorf("a cached list of the default project made %d call(s): %v", n, g.calls)
	}
	// The list of projects says why it cannot be shown.
	if err := h.run("project", "list"); exitClass(err) != "auth" || !has(err, "cannot list projects", "default project p1 alone") {
		t.Errorf("project list = %v", err)
	}
	if err := h.run("project", "enable", "p3"); exitClass(err) != "notfound" || !has(err, "--project", "polyctl gcp project use p3") {
		t.Errorf("enable of a project that cannot be listed = %v", err)
	}
	if err := h.run("project", "disable", "p1"); exitClass(err) != "usage" || !has(err, "disable every project") {
		t.Errorf("disable of the default of such an account = %v", err)
	}
}

// project list says which projects are enabled and marks the default;
// current names the default and the disabled ones.
func TestProjectListMarksEnabled(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	h.enableOn(g, "p1", "p0", "p1", "p3")
	h.disableProjects("p3", "p2")
	if err := h.run("project", "list"); err != nil {
		t.Fatal(err)
	}
	var rows []projectRow
	h.jsonOut(&rows)
	got := ""
	for _, r := range rows {
		got += fmt.Sprintf("%s:%v:%v ", r.ProjectID, r.Enabled, r.Default)
		if r.Selected != r.Enabled {
			t.Errorf("%s: selected %v, enabled %v; the deprecated field must say the same", r.ProjectID, r.Selected, r.Enabled)
		}
	}
	// p2 is disabled but not listed: it is appended.
	if got != "p0:true:false p1:true:true p3:false:false p2:false:false " {
		t.Errorf("rows = %s", got)
	}
	if out := h.stdout.String(); !strings.Contains(out, `"enabled": true`) || !strings.Contains(out, `"selected": true`) {
		t.Errorf("JSON = %s", out)
	}
	wantErr := "note: disabled project p2 is not visible to the credentials (to forget it: polyctl gcp project enable p2)\n4 project(s) via gcp/lab, 2 enabled, 2 disabled\n"
	if h.stderr.String() != wantErr {
		t.Errorf("stderr = %q\nwant     %q", h.stderr.String(), wantErr)
	}
	grid := projectGrid(rows)
	if strings.Join(grid.Headers, " ") != "PROJECT_ID NAME NUMBER STATE ENABLED" || strings.Join(grid.Rows[1], "|") != "p1 *|Project p1|101|ACTIVE|yes" ||
		strings.Join(grid.Rows[3], "|") != "p2||||no" || strings.Join(grid.Rows[0], "|") != "p0|Project p0|100|ACTIVE|yes" || strings.Join(grid.Rows[2], "|") != "p3|Project p3|102|ACTIVE|no" {
		t.Errorf("grid = %+v", grid)
	}
	if err := h.run("project", "current"); err != nil {
		t.Fatal(err)
	}
	var cur currentProject
	h.jsonOut(&cur)
	if cur.Project != "p1" || strings.Join(cur.Disabled, ",") != "p2,p3" || strings.Contains(h.stdout.String(), `"projects"`) {
		t.Errorf("current = %+v\n%s", cur, h.stdout.String())
	}
	// With nothing disabled the field is an empty list, never null.
	h.disableProjects()
	if err := h.run("project", "current"); err != nil || !strings.Contains(h.stdout.String(), `"disabled_projects": []`) {
		t.Errorf("current = %v\n%s", err, h.stdout.String())
	}
	// A default project the credentials do not list is shown, enabled.
	h.enableOn(g, "p1", "p0")
	if err := h.run("project", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&rows)
	if len(rows) != 2 || rows[1].ProjectID != "p1" || !rows[1].Enabled || !rows[1].Default || rows[1].Name != "" {
		t.Errorf("rows = %+v", rows)
	}
	// current asks nothing of Google Cloud.
	g.reset()
	h.rt.Flags.Offline = true
	if err := h.run("project", "current"); err != nil || len(g.calls) != 0 {
		t.Errorf("current --offline = %v, calls %v", err, g.calls)
	}
	if err := h.run("project", "list"); exitClass(err) != "offline" {
		t.Errorf("list --offline = %v", err)
	}
	h.rt.Flags.Offline = false
	if err := h.run("project", "list", "--project", "p1"); err == nil {
		t.Error("gcp project takes no --project")
	}
}

// use, enable and disable change the account without a login: the rows of
// a disabled project are dropped, and the cache of the account is made due
// when a project is enabled again or the default changes.
func TestProjectUseEnableDisable(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	h.enableOn(g, "p1", "p1", "p2", "p3")
	h.editMeta(func(meta map[string]string) { meta[legacyProjects] = "p1,p2" })
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	g.addZone("p3", "three", "three.example", "public")
	sync := func() {
		t.Helper()
		if _, err := h.sync(platform.ResZone); err != nil {
			t.Fatal(err)
		}
	}
	fresh := func() bool {
		db, _ := h.rt.DB()
		st, err := db.GetState(context.Background(), inventory.Set{Platform: platform.GCP, Profile: "lab", Type: platform.ResZone})
		if err != nil || st == nil {
			t.Fatalf("state = %+v, %v", st, err)
		}
		return st.ExpiresAt.After(st.SyncedAt)
	}
	run := func(args ...string) error {
		h.stderr.Reset()
		return h.run(append([]string{"project"}, args...)...)
	}
	sync()
	if !fresh() {
		t.Fatal("the set must be fresh after the sync")
	}

	// use: another project becomes the default; the key of the former
	// selection goes with the first save.
	if err := run("use", "p2"); err != nil || h.labProjects() != "p2 []" {
		t.Fatalf("use p2 = %v, %s", err, h.labProjects())
	}
	if _, ok := h.labMeta()[legacyProjects]; ok || fresh() {
		t.Errorf("use must drop the former selection and make the cached sets due: %v", h.labMeta())
	}
	// use: the credentials must reach the project.
	g.fail["p9"] = http.StatusForbidden
	if err := run("use", "p9"); exitClass(err) != "auth" || h.labProjects() != "p2 []" {
		t.Errorf("use of an unreachable project = %v, %s", err, h.labProjects())
	}
	h.rt.Flags.Offline = true
	if err := run("use", "p9"); err != nil || h.labProjects() != "p9 []" || !strings.Contains(h.stderr.String(), "was not checked") {
		t.Errorf("use --offline = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}
	h.rt.Flags.Offline = false
	if err := run("use", "p9"); err != nil || !strings.Contains(h.stderr.String(), "already the default") {
		t.Errorf("use of the default = %v / %s", err, h.stderr.String())
	}
	if err := run("use", "p1"); err != nil || h.labProjects() != "p1 []" {
		t.Fatalf("use p1 = %v, %s", err, h.labProjects())
	}

	// disable: several at once. Their rows go, the others stay, and the
	// sets are not made due: nothing has to be read again.
	sync()
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1; p2/two p2; p3/three p3" {
		t.Fatalf("zones = %s", got)
	}
	if err := run("disable", "p3", "p2"); err != nil || h.labProjects() != "p1 [p2,p3]" || !strings.Contains(h.stderr.String(), "disabled p2, p3 for gcp/lab") {
		t.Fatalf("disable = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}
	if got := strings.Join(h.rowsOf(platform.ResZone), "; "); got != "p1/one p1" || !fresh() {
		t.Errorf("zones after disable = %s (fresh %v), want the rows of p1 in a set that is still fresh", got, fresh())
	}
	var cur currentProject
	h.jsonOut(&cur)
	if cur.Project != "p1" || strings.Join(cur.Disabled, ",") != "p2,p3" {
		t.Errorf("disable printed %+v", cur)
	}
	if err := run("disable", "p3"); exitClass(err) != "nothing" || !has(err, "already disabled for gcp/lab") {
		t.Errorf("disable again = %v", err)
	}
	if err := run("disable", "nosuch"); exitClass(err) != "notfound" || !has(err, "project nosuch is not visible to the credentials of gcp/lab") {
		t.Errorf("disable of a project that is not visible = %v", err)
	}
	if err := run("disable", "a/b"); exitClass(err) != "usage" {
		t.Errorf("disable of a bad id = %v", err)
	}
	for _, sub := range []string{"enable", "add"} {
		if err := run(sub); err == nil || !has(err, "arg(s)") {
			t.Errorf("%s without an id in the non-interactive flow = %v, want the error of a missing argument", sub, err)
		}
	}
	// disable, and remove, its former name, say where the list is.
	for _, sub := range []string{"disable", "remove"} {
		if err := run(sub); exitClass(err) != "usage" || !has(err, noProjectsToDisable) {
			t.Errorf("%s without an id in the non-interactive flow = %v, want the usage error that names the list", sub, err)
		}
	}

	// enable: back in every sync; the sets are due. One that is enabled
	// already is nothing to do, one the credentials do not see not found.
	g.reset()
	if err := run("enable", "p3"); err != nil || h.labProjects() != "p1 [p2]" || !strings.Contains(h.stderr.String(), "enabled p3 for gcp/lab") || fresh() {
		t.Errorf("enable = %v, %s / %s (fresh %v)", err, h.labProjects(), h.stderr.String(), fresh())
	}
	if len(g.calls) != 0 {
		t.Errorf("enabling a disabled project asked Google Cloud: %v", g.calls)
	}
	if err := run("enable", "p3", "p1"); exitClass(err) != "nothing" || !has(err, "already enabled for gcp/lab") {
		t.Errorf("enable again = %v", err)
	}
	if err := run("enable", "nosuch"); exitClass(err) != "notfound" || !has(err, "nothing to enable", "--project", "polyctl gcp project use nosuch") {
		t.Errorf("enable of a project that is not visible = %v", err)
	}

	// add and remove are the names enable and disable had: hidden, and
	// still working.
	if err := run("add", "p2"); err != nil || h.labProjects() != "p1 []" {
		t.Errorf("add = %v, %s", err, h.labProjects())
	}
	if err := run("remove", "p2"); err != nil || h.labProjects() != "p1 [p2]" {
		t.Errorf("remove = %v, %s", err, h.labProjects())
	}

	// The default project needs --default, naming one that stays enabled.
	if err := run("disable", "p1"); exitClass(err) != "usage" || !has(err, "p1 is the default project of gcp/lab", "--default <id>", "(one of: p3)") {
		t.Errorf("disable of the default = %v", err)
	}
	for _, def := range []string{"p1", "p2", "nosuch"} {
		if err := run("disable", "p1", "--default", def); exitClass(err) != "usage" || !has(err, "--default "+def+": not one of the projects that stay enabled (p3)") {
			t.Errorf("--default %s = %v", def, err)
		}
	}
	if err := run("disable", "p1", "--default", "p3"); err != nil || h.labProjects() != "p3 [p1,p2]" || !strings.Contains(h.stderr.String(), "project p3 is now the default project of gcp/lab") || fresh() {
		t.Errorf("disable with --default = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}
	if err := run("disable", "p3"); exitClass(err) != "usage" || !has(err, "disable every project of gcp/lab", "auth logout gcp --profile lab") {
		t.Errorf("disable of every project = %v", err)
	}
	// use: a disabled project that becomes the default is enabled again.
	if err := run("use", "p2"); err != nil || h.labProjects() != "p2 [p1]" || !strings.Contains(h.stderr.String(), "project p2 was disabled and is enabled again") {
		t.Errorf("use of a disabled project = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}

	// --offline: nothing is checked, which is said; a disabled project is
	// enabled without the network.
	h.rt.Flags.Offline = true
	if err := run("disable", "p3", "p7"); err != nil || h.labProjects() != "p2 [p1,p3,p7]" || !strings.Contains(h.stderr.String(), "was not checked") {
		t.Errorf("disable --offline = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}
	if err := run("enable", "p1"); err != nil || h.labProjects() != "p2 [p3,p7]" {
		t.Errorf("enable --offline = %v, %s", err, h.labProjects())
	}
	if err := run("disable", "p2"); exitClass(err) != "usage" || !has(err, "--default <id>") {
		t.Errorf("disable of the default --offline = %v", err)
	}
	// The projects that stay enabled are not known offline: the message
	// names none, without empty parentheses.
	if err := run("disable", "p2", "--default", "p3"); exitClass(err) != "usage" || !has(err, "--default p3: not one of the projects that stay enabled") || has(err, "()") {
		t.Errorf("--default of a disabled project --offline = %v", err)
	}
	// --default is applied when the call disables a project, also when
	// the default is not one of them; when nothing is disabled nothing is
	// written and a note says the flag was not applied.
	h.stderr.Reset()
	if err := run("disable", "p3", "--default", "p9"); exitClass(err) != "nothing" || h.labProjects() != "p2 [p3,p7]" ||
		!strings.Contains(h.stderr.String(), "note: --default p9 was not applied: nothing was disabled (to set the default: polyctl gcp project use p9)") {
		t.Errorf("disable of a disabled project with --default = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}
	if err := run("disable", "p5", "--default", "p9"); err != nil || h.labProjects() != "p9 [p3,p5,p7]" {
		t.Errorf("disable of another project with --default = %v, %s", err, h.labProjects())
	}
	if err := run("use", "p2"); err != nil {
		t.Fatal(err)
	}
	if err := run("enable", "p5"); err != nil || h.labProjects() != "p2 [p3,p7]" {
		t.Fatalf("restore = %v, %s", err, h.labProjects())
	}
	h.rt.Flags.Offline = false
	// A disabled project that is no longer visible is forgotten by enable.
	if err := run("enable", "p7"); err != nil || h.labProjects() != "p2 [p3]" {
		t.Errorf("enable of a disabled project that is not visible = %v, %s", err, h.labProjects())
	}

	root := Command(h.rt)
	for sub, hidden := range map[string]bool{"use": false, "enable": false, "disable": false, "add": true, "remove": true} {
		c, _, err := root.Find([]string{"project", sub})
		if err != nil || c.Name() != sub || c.Hidden != hidden {
			t.Errorf("project %s: %v, hidden %v, want %v", sub, err, c.Hidden, hidden)
			continue
		}
		// Only use refuses --dry-run: it has nothing to report but itself.
		if refuses := c.Annotations[app.NoDryRunAnnotation] != ""; refuses != (sub == "use") {
			t.Errorf("project %s refuses --dry-run = %v", sub, refuses)
		}
		if sub != "use" && c.Flags().Lookup("default") == nil {
			t.Errorf("project %s has no --default", sub)
		}
		// The usage line shows the project ids as optional where the
		// command opens the list without them, and the help of remove,
		// which still opens it, does not repeat that disable never does.
		list := sub != "disable"
		if optional := strings.Contains(c.Use, "[<project-id>"); sub != "use" && optional != list {
			t.Errorf("project %s: usage %q", sub, c.Use)
		}
		long := strings.Join(strings.Fields(c.Long), " ")
		if sub != "use" && strings.Contains(long, "on a terminal too") == list {
			t.Errorf("project %s: help says a project is required on a terminal = %v:\n%s", sub, !list, c.Long)
		}
		if sub == "remove" && (strings.Contains(long, "it does the same.") || !strings.Contains(long, `still opens the list of "polyctl gcp project enable"`)) {
			t.Errorf("project remove: %s", c.Long)
		}
	}
}

// Without arguments the interactive flow picks from a list: use the
// default among the visible projects; enable a list of every project, the
// enabled ones ticked, whose result is applied in both directions. A
// default that was unticked is asked again, or taken when one project is
// left or --default names it. disable never opens the list.
func TestProjectCommandsPick(t *testing.T) {
	h, g := multiDNS(t)
	h.enableOn(g, "p1", "p1", "p2", "p3", "p4")
	h.disableProjects("p2")

	p := h.answer("p3")
	if err := h.run("project", "use"); err != nil || h.labProjects() != "p3 [p2]" {
		t.Fatalf("use = %v, %s", err, h.labProjects())
	}
	p.Done()
	if a := p.Asked[0]; a.Default != "p1" || !strings.Contains(prompttest.Labels(a.Options), "p1  Project p1  default") || !strings.Contains(prompttest.Labels(a.Options), "p2  Project p2  disabled") {
		t.Errorf("use asked %+v", a)
	}

	// p9 is disabled and not visible to the credentials any more.
	h.disableProjects("p2", "p9")
	const title = "Enabled projects of gcp/lab (ticked: synced and searched)"
	offered := func(sub string, a prompttest.Asked, preset string) {
		t.Helper()
		labels := prompttest.Labels(a.Options)
		if a.Kind != "multi" || a.Title != title || prompttest.Values(a.Options) != "p1 p2 p3 p4 p9" || strings.Join(a.Preset, " ") != preset ||
			!strings.Contains(labels, "p3  Project p3  default") || !strings.Contains(labels, "not visible") || strings.Contains(labels, "disabled") {
			t.Errorf("%s offered %+v", sub, a)
		}
	}
	// enable: p2 is ticked and p4 unticked in the same list.
	p = h.answer([]string{"p1", "p2", "p3"})
	if err := h.run("project", "enable"); err != nil || h.labProjects() != "p3 [p4,p9]" {
		t.Fatalf("enable = %v, %s", err, h.labProjects())
	}
	p.Done()
	offered("enable", p.Asked[0], "p1 p3 p4")
	for _, want := range []string{"disabled p4 for gcp/lab", "enabled p2 for gcp/lab"} {
		if !strings.Contains(h.stderr.String(), want) {
			t.Errorf("enable said %q, want %q", h.stderr.String(), want)
		}
	}

	// The default and p4 are unticked, and p9, ticked, is forgotten
	// without becoming a candidate of the new default. remove, the name
	// disable had in polyctl 0.4.0, asked on a terminal: it opens the same
	// list.
	h.disableProjects("p9")
	p = h.answer([]string{"p1", "p2", "p9"}, "p2")
	if err := h.run("project", "remove"); err != nil || h.labProjects() != "p2 [p3,p4]" {
		t.Fatalf("remove = %v, %s", err, h.labProjects())
	}
	p.Done()
	offered("remove", p.Asked[0], "p1 p2 p3 p4")
	if a := p.Asked[1]; a.Title != "New default project" || prompttest.Values(a.Options) != "p1 p2" {
		t.Errorf("new default asked %+v", a)
	}

	// What is ticked already: nothing to do, nothing written.
	before := h.labMeta()
	p = h.answer([]string{"p1", "p2"})
	if err := h.run("project", "enable"); exitClass(err) != "nothing" || !has(err, "unchanged") {
		t.Errorf("unchanged ticks = %v", err)
	}
	p.Done()
	// Nothing ticked is leaving the list, not disabling every project.
	h.answer([]string{})
	if err := h.run("project", "enable"); exitClass(err) != "nothing" || !has(err, "nothing was selected") {
		t.Errorf("nothing ticked = %v", err)
	}
	// A list without a visible project left for the default is refused.
	h.disableProjects("p3", "p4", "p9")
	h.answer([]string{"p9"})
	if err := h.run("project", "enable"); exitClass(err) != "usage" || !has(err, "this would disable every project of gcp/lab") {
		t.Errorf("only an invisible project ticked = %v", err)
	}
	h.disableProjects("p3", "p4")
	if !reflect.DeepEqual(h.labMeta(), before) {
		t.Errorf("metadata = %v, want %v", h.labMeta(), before)
	}

	// --default names the new default without a question, and must stay
	// ticked.
	h.answer([]string{"p1", "p3"})
	if err := h.run("project", "enable", "--default", "p4"); exitClass(err) != "usage" || !has(err, "--default p4: not one of the projects that stay enabled (p1, p3)") {
		t.Errorf("--default of an unticked project = %v", err)
	}
	p = h.answer([]string{"p1", "p3"})
	if err := h.run("project", "enable", "--default", "p3"); err != nil || h.labProjects() != "p3 [p2,p4]" {
		t.Fatalf("pick with --default = %v, %s", err, h.labProjects())
	}
	p.Done()
	// One project left: it becomes the default without a question.
	p = h.answer([]string{"p1"})
	if err := h.run("project", "enable"); err != nil || h.labProjects() != "p1 [p2,p3,p4]" {
		t.Fatalf("one project left = %v, %s", err, h.labProjects())
	}
	p.Done()

	// disable never opens the list: without a project it is a usage error
	// on a terminal too, which says where the list is, and asks nothing.
	before = h.labMeta()
	p = h.answer()
	for _, args := range [][]string{{"disable"}, {"disable", "--default", "p2"}} {
		if err := h.run(append([]string{"project"}, args...)...); exitClass(err) != "usage" || !has(err, noProjectsToDisable) {
			t.Errorf("project %v on a terminal = %v, want the usage error that names the list", args, err)
		}
	}
	if len(p.Asked) != 0 || !reflect.DeepEqual(h.labMeta(), before) {
		t.Errorf("disable without a project asked %v, metadata %v", p.Titles(), h.labMeta())
	}

	// The non-interactive flow needs the ids.
	h.nonInteractive()
	for _, sub := range []string{"enable", "add"} {
		if err := h.run("project", sub); !has(err, "accepts between 1 and 100 arg(s), received 0") {
			t.Errorf("project %s without an id, non-interactive = %v", sub, err)
		}
	}
	for _, sub := range []string{"disable", "remove"} {
		if err := h.run("project", sub); exitClass(err) != "usage" || !has(err, noProjectsToDisable) {
			t.Errorf("project %s without an id, non-interactive = %v", sub, err)
		}
	}
}

// noProjectsToDisable is the usage error of disable without a project.
const noProjectsToDisable = `name the projects to disable, or choose from the list with "polyctl gcp project enable"`

// --dry-run of enable and disable (and of add and remove, their former
// names) reports the projects that would be disabled and enabled and the
// new default, and writes nothing: the configuration and the inventory
// stay as they are.
func TestProjectEnableDisableDryRun(t *testing.T) {
	h, g := multiDNS(t)
	h.enableOn(g, "p1", "p1", "p2", "p3", "p4")
	h.disableProjects("p4")
	g.addZone("p2", "two", "two.example", "public")
	h.nonInteractive()
	if err := h.run("dns", "zone", "list"); err != nil {
		t.Fatal(err)
	}
	zones := h.rowsOf(platform.ResZone)
	listed := func() int {
		g.mu.Lock()
		defer g.mu.Unlock()
		n := 0
		for _, c := range g.calls {
			if strings.Contains(c, "managedZones") {
				n++
			}
		}
		return n
	}
	synced := listed()
	h.rt.Flags.DryRun = true
	check := func(what string, err error, want ...string) {
		t.Helper()
		if err != nil {
			t.Fatalf("%s = %v", what, err)
		}
		rep := h.report()
		if got := rows(rep); !rep.DryRun || rep.Target.Platform != platform.GCP || rep.Target.Profile != "lab" || !reflect.DeepEqual(got, want) {
			t.Errorf("%s reported %+v %v, want %v", what, rep.Target, got, want)
		}
		if h.labProjects() != "p1 [p4]" || !reflect.DeepEqual(h.rowsOf(platform.ResZone), zones) {
			t.Errorf("%s changed the account: %s, zones %v", what, h.labProjects(), h.rowsOf(platform.ResZone))
		}
	}
	for _, sub := range []string{"disable", "remove"} {
		check(sub, h.run("project", sub, "p2", "p3"), "project/p2 would_update disabled", "project/p3 would_update disabled")
		check(sub+" of the default", h.run("project", sub, "p1", "p2", "--default", "p3"),
			"project/p1 would_update disabled", "project/p2 would_update disabled", "project/p3 would_update default")
	}
	for _, sub := range []string{"enable", "add"} {
		check(sub, h.run("project", sub, "p4"), "project/p4 would_update enabled")
	}
	if !strings.Contains(h.stderr.String(), "dry run: would update project/p4 (enabled)") {
		t.Errorf("stderr = %q", h.stderr.String())
	}
	// Nothing to do stays nothing to do, and a usage error a usage error.
	if err := h.run("project", "disable", "p4"); exitClass(err) != "nothing" {
		t.Errorf("dry run of a disabled project = %v", err)
	}
	if err := h.run("project", "disable", "p1"); exitClass(err) != "usage" {
		t.Errorf("dry run of the default without --default = %v", err)
	}
	// The pick reports what its ticks would change, in both directions.
	h.interactive([]string{"p2", "p4"}, "p4")
	check("pick", h.run("project", "enable"), "project/p1 would_update disabled", "project/p3 would_update disabled",
		"project/p4 would_update enabled", "project/p4 would_update default")
	// The cached sets were not made due: the next list is served by them.
	h.nonInteractive()
	h.rt.Flags.DryRun = false
	if err := h.run("dns", "zone", "list"); err != nil || listed() != synced {
		t.Errorf("zone list after the dry runs = %v, %d zone listing(s), want %d", err, listed(), synced)
	}

	// The table of the report.
	ht := newGCPHarness(t, app.Flags{Output: "table", NonInteractive: true, NonInteractiveSet: true, DryRun: true}, nil)
	ht.enableProjects("p1", "p1", "p2")
	if err := ht.run("project", "disable", "p2"); err != nil {
		t.Fatal(err)
	}
	out := strings.Join(strings.Fields(ht.stdout.String()), " ")
	if !strings.Contains(out, "RESOURCE ACTION DETAIL project/p2 would update disabled") || ht.labProjects() != "p1 []" {
		t.Errorf("table = %q, account %s", out, ht.labProjects())
	}
}

// Domain routing (the platform-neutral dns commands) finds a zone in any
// enabled project and reads its records there. The same DNS name in two
// projects is a pick in the interactive flow and exit code 5 otherwise,
// with a hint that names --project and the zone id.
func TestDomainRoutingCoversEnabledProjects(t *testing.T) {
	h, g := multiDNS(t)
	h.nonInteractive()
	g.addZone("p1", "one", "one.example", "public")
	g.addZone("p2", "two", "two.example", "public")
	g.addRRSet("p2", "two", &dns.ResourceRecordSet{Name: "www.two.example.", Type: "A", Ttl: 300, Rrdatas: []string{"192.0.2.2"}})
	ctx := context.Background()
	tg, err := h.rt.ResolveDomain(ctx, "www.two.example", platform.ResZone)
	if err != nil || tg.ResourceID != "p2/two" || tg.Profile != "lab" {
		t.Fatalf("target = %+v, %v; want the zone of p2", tg, err)
	}
	recs, _, err := h.rt.ZoneRecords(ctx, tg)
	if err != nil || len(recs) != 1 || recs[0].Value != "192.0.2.2" || recs[0].ZoneID != "p2/two" {
		t.Fatalf("records = %+v, %v", recs, err)
	}

	g.addZone("p1", "dup", "dup.example", "public")
	g.addZone("p2", "dup", "dup.example", "public")
	h.rt.Flags.Refresh = true
	_, err = h.rt.ResolveDomain(ctx, "dup.example", platform.ResZone)
	if exitClass(err) != "ambiguous" || !strings.Contains(err.Error(), "p1/dup") || !strings.Contains(err.Error(), "p2/dup") ||
		!strings.Contains(err.Error(), "gcp dns ... --project <id>") || !strings.Contains(err.Error(), "<project>/<managed zone>") {
		t.Fatalf("same DNS name in two projects = %v", err)
	}
	p := h.answer(prompttest.Label("p2/dup"))
	h.rt.Flags.NonInteractive = false
	tg, err = h.rt.ResolveDomain(ctx, "dup.example", platform.ResZone)
	if err != nil || tg.ResourceID != "p2/dup" {
		t.Errorf("interactive = %+v, %v", tg, err)
	}
	p.Done()
}

// The help of every dns and compute command that looks a resource up by
// its name says what happens to a name several projects hold; a command
// that creates what it names, and a list, do not.
func TestHelpOfNameLookupsNamesProjectAmbiguity(t *testing.T) {
	h, _ := multiDNS(t)
	says := map[string]bool{}
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if !c.HasSubCommands() {
			says[strings.TrimPrefix(c.CommandPath(), "gcp ")] = strings.Contains(c.Long, "exit code 5") && strings.Contains(c.Long, "--project <id>") && strings.Contains(c.Long, "asked on a\nterminal")
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(Command(h.rt))
	for _, path := range []string{
		"dns zone get", "dns record list", "dns record upsert", "dns record delete",
		"compute instance get", "compute instance start", "compute instance stop", "compute instance delete", "compute instance resize",
		"compute instance reboot", "compute instance update", "compute instance password",
		"compute instance ssh-key list", "compute instance ssh-key add", "compute instance ssh-key remove",
		"compute firewall get", "compute firewall update", "compute firewall delete", "compute network get",
		"compute ssl-certificate update", "compute ssl-certificate delete",
		"compute load-balancer get", "compute load-balancer delete", "compute load-balancer ensure", "compute load-balancer cert set",
		"compute backend-service get", "compute backend-service delete", "compute forwarding-rule get", "compute forwarding-rule delete",
		"compute health-check get", "compute health-check delete", "compute instance-group get", "compute instance-group delete",
	} {
		if v, ok := says[path]; !ok || !v {
			t.Errorf("gcp %s: the help does not say what a name of several projects does (command exists: %v)", path, ok)
		}
		delete(says, path)
	}
	for path, v := range says {
		if v {
			t.Errorf("gcp %s looks nothing up by name, but its help says what a name of several projects does", path)
		}
	}
}

// Disabling the default project when one other project stays enabled: the
// non-interactive flow still needs --default (nothing is assumed), the
// interactive flow makes the one that stays the default without a
// question. Without a project id use and enable list the visible projects,
// which --offline cannot.
func TestProjectDisableDefaultWithOneLeft(t *testing.T) {
	h, _ := multiDNS(t)
	h.nonInteractive()
	err := h.run("project", "disable", "p1")
	if exitClass(err) != "usage" || !has(err, "--default <id>", "one of: p2") || h.labProjects() != "p1 []" {
		t.Fatalf("non-interactive disable of the default = %v, %s", err, h.labProjects())
	}
	p := h.interactive()
	if err := h.run("project", "disable", "p1"); err != nil || h.labProjects() != "p2 [p1]" || !strings.Contains(h.stderr.String(), "project p2 is now the default project") {
		t.Fatalf("interactive disable of the default = %v, %s / %s", err, h.labProjects(), h.stderr.String())
	}
	if len(p.Asked) != 0 {
		t.Errorf("asked %v", p.Titles())
	}
	h.rt.Flags.Offline = true
	for _, sub := range []string{"use", "enable"} {
		if err := h.run("project", sub); exitClass(err) != "offline" {
			t.Errorf("project %s --offline without an id = %v", sub, err)
		}
	}
}
