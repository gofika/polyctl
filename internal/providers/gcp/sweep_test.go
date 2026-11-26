package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/googleapi"
)

// sweepClient is a client of an account whose credentials list the
// projects p0.., all enabled, which asks no API.
func sweepClient(n int) *client {
	cov := &coverage{profile: "lab", def: "p0", listed: true, canList: true}
	for i := range n {
		cov.visible = append(cov.visible, &cloudresourcemanager.Project{ProjectId: fmt.Sprintf("p%d", i)})
	}
	return &client{project: "p0", cov: cov}
}

// captureNotes collects the notes about skipped projects of a test.
func captureNotes(t *testing.T) *[]string {
	t.Helper()
	var mu sync.Mutex
	var notes []string
	old := notef
	notef = func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		notes = append(notes, fmt.Sprintf(format, args...))
	}
	resetOffNotes()
	t.Cleanup(func() { notef = old; resetOffNotes() })
	return &notes
}

// A live sweep reads several projects at the same time, never more than
// projectConcurrency, and returns their rows in the order of the
// projects whatever order they answered in.
func TestSweepProjectsIsBoundedAndOrdered(t *testing.T) {
	captureNotes(t)
	c := sweepClient(11)
	var running, peak atomic.Int32
	rows, err := sweepProjects(context.Background(), c, func(ctx context.Context, pc *client) ([]string, error) {
		n := running.Add(1)
		defer running.Add(-1)
		for {
			if p := peak.Load(); n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		// The first projects answer last.
		var i int
		fmt.Sscanf(pc.project, "p%d", &i)
		time.Sleep(time.Duration(12-i) * time.Millisecond)
		return []string{pc.project + "/a", pc.project + "/b"}, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	var want []string
	for i := range 11 {
		want = append(want, fmt.Sprintf("p%d/a", i), fmt.Sprintf("p%d/b", i))
	}
	if strings.Join(rows, " ") != strings.Join(want, " ") {
		t.Errorf("rows = %v\nwant   %v", rows, want)
	}
	if p := peak.Load(); p > projectConcurrency || p < 2 {
		t.Errorf("%d projects were read at the same time, want several and at most %d", p, projectConcurrency)
	}
}

// A run that finds two APIs switched off, each in another project, tells
// each project once, in the note of the listing that skipped it: the
// notes are not gathered into one.
func TestSweepsOfTwoAPIsNoteEachProjectOnce(t *testing.T) {
	notes := captureNotes(t)
	off := func(api string) error {
		return computeErr(&googleapi.Error{Code: 403, Message: api + " has not been used in project 7 before or it is disabled.", Errors: []googleapi.ErrorItem{{Reason: "accessNotConfigured"}}})
	}
	c := sweepClient(4)
	sweep := func(fail map[string]error) {
		t.Helper()
		if _, err := sweepProjects(context.Background(), c, func(ctx context.Context, pc *client) ([]string, error) {
			return []string{pc.project}, fail[pc.project]
		}); err != nil {
			t.Fatal(err)
		}
	}
	sweep(map[string]error{"p1": off("Cloud DNS API")})
	// p1 has neither API: it was told already.
	sweep(map[string]error{"p1": off("Compute Engine API"), "p2": off("Compute Engine API"), "p3": off("Compute Engine API")})
	want := []string{
		"note: gcp/lab: skipped 1 project(s) in which an API is not enabled or billing is off: p1 (Cloud DNS API); they hold nothing there. To stop asking them: polyctl gcp project disable p1",
		"note: gcp/lab: skipped 2 project(s) in which an API is not enabled or billing is off: p2 (Compute Engine API), p3 (Compute Engine API); they hold nothing there. To stop asking them: polyctl gcp project disable p2 p3",
	}
	if strings.Join(*notes, "\n") != strings.Join(want, "\n") {
		t.Errorf("notes = %q\nwant    %q", *notes, want)
	}
}

// A project whose API is not enabled is skipped and named in one note; a
// project that fails for another reason fails the sweep, named after it;
// the project of --project is never skipped.
func TestSweepProjectsSkipsAndFails(t *testing.T) {
	notes := captureNotes(t)
	off := &googleapi.Error{Code: 403, Message: "Compute Engine API has not been used in project 7 before or it is disabled.", Errors: []googleapi.ErrorItem{{Reason: "accessNotConfigured"}}}
	denied := &googleapi.Error{Code: 403, Message: "Required 'compute.networks.list' permission", Errors: []googleapi.ErrorItem{{Reason: "forbidden"}}}
	c := sweepClient(6)
	answer := func(fail map[string]error) func(ctx context.Context, pc *client) ([]string, error) {
		return func(ctx context.Context, pc *client) ([]string, error) {
			if err := fail[pc.project]; err != nil {
				return nil, computeErr(err)
			}
			return []string{pc.project}, nil
		}
	}
	rows, err := sweepProjects(context.Background(), c, answer(map[string]error{"p0": off, "p2": off, "p5": off}))
	if err != nil || strings.Join(rows, ",") != "p1,p3,p4" {
		t.Fatalf("sweep = %v, %v", rows, err)
	}
	want := "note: gcp/lab: skipped 3 project(s) in which an API is not enabled or billing is off: p0 (Compute Engine API), p2 (Compute Engine API), p5 (Compute Engine API); they hold nothing there. To stop asking them: polyctl gcp project disable p2 p5"
	if len(*notes) != 1 || (*notes)[0] != want {
		t.Errorf("notes = %q\nwant    %q", *notes, want)
	}
	// Told once per run.
	if _, err := sweepProjects(context.Background(), c, answer(map[string]error{"p2": off})); err != nil || len(*notes) != 1 {
		t.Errorf("second sweep = %v, notes %q", err, *notes)
	}

	// The first failing project, in the order of the projects, is the
	// error, whichever answered first.
	_, err = sweepProjects(context.Background(), c, answer(map[string]error{"p1": off, "p3": denied, "p4": errors.New("boom")}))
	if err == nil || !strings.HasPrefix(err.Error(), "project p3: ") || exitClass(err) != "auth" {
		t.Errorf("failing sweep = %v, want the error of p3", err)
	}

	// One project: its error as it is; pinned: the API answer too.
	one := sweepClient(1)
	if _, err := sweepProjects(context.Background(), one, answer(map[string]error{"p0": denied})); err == nil || strings.HasPrefix(err.Error(), "project ") {
		t.Errorf("one project = %v, want its error without a project prefix", err)
	}
	if rows, err := sweepProjects(context.Background(), one, answer(map[string]error{"p0": off})); err != nil || len(rows) != 0 {
		t.Errorf("one project without the API = %v, %v; want nothing and no error", rows, err)
	}
	pinned := c.pin("p2")
	if _, err := sweepProjects(context.Background(), pinned, answer(map[string]error{"p2": off})); exitClass(err) != "auth" {
		t.Errorf("pinned sweep = %v, want the error of the project", err)
	}
	if rows, err := sweepProjects(context.Background(), pinned, answer(nil)); err != nil || strings.Join(rows, ",") != "p2" {
		t.Errorf("pinned sweep = %v, %v; want p2 alone", rows, err)
	}

	// A cancelled call is its error, not a partial list.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if rows, err := sweepProjects(ctx, c, answer(nil)); !errors.Is(err, context.Canceled) || rows != nil {
		t.Errorf("cancelled sweep = %v, %v", rows, err)
	}
}

// The project named with --project keeps the answer of an API that is not
// enabled (exit code 3) on the readers served from the inventory too: the
// sync over the enabled projects skips the project, so the inventory
// holds nothing of it, and the command reads it live instead of answering
// with an empty list or "not found". A second run, with the sets fresh,
// answers the same. --offline asks nothing.
func TestPinnedProjectWithoutTheAPIKeepsTheErrorOnCachedReaders(t *testing.T) {
	t.Run("dns", func(t *testing.T) {
		h, g := multiDNS(t)
		h.nonInteractive()
		g.addZone("p1", "one", "one.example", "public")
		g.disabled["p2"] = true
		for i := range 2 {
			if err := h.run("dns", "zone", "list", "--project", "p2"); exitClass(err) != "auth" {
				t.Errorf("run %d: zone list --project p2 = %v, want the error of the project (exit code 3)", i, err)
			}
		}
		// The sweep over the enabled projects still skips it.
		if err := h.run("dns", "zone", "list"); err != nil {
			t.Errorf("zone list = %v, want no error", err)
		}
		// A project that has the API and holds nothing is an empty list.
		g.disabled["p2"] = false
		if err := h.run("dns", "zone", "list", "--project", "p2"); err != nil {
			t.Errorf("zone list of an empty project = %v, want no error", err)
		}
		g.disabled["p2"] = true
		h.rt.Flags.Offline = true
		if err := h.run("dns", "zone", "list", "--project", "p2"); err != nil {
			t.Errorf("offline zone list --project p2 = %v, want the (empty) inventory", err)
		}
	})
	t.Run("compute", func(t *testing.T) {
		h := twoProjects(t)
		h.gce.addInstance("proj", "us-central1-a", "web-1", "10.0.0.1", "34.0.0.1")
		h.gce.fail = map[string]fakeErr{"/projects/p2/": {code: 403, reason: "accessNotConfigured",
			message: "Compute Engine API has not been used in project p2 before or it is disabled."}}
		for i := range 2 {
			if err := h.run("compute", "instance", "list", "--project", "p2"); exitClass(err) != "auth" {
				t.Errorf("run %d: instance list --project p2 = %v, want the error of the project (exit code 3)", i, err)
			}
		}
		if err := h.run("compute", "instance", "get", "web-1", "--project", "p2"); exitClass(err) != "auth" {
			t.Errorf("instance get --project p2 = %v, want the error of the project (exit code 3)", err)
		}
		if err := h.run("compute", "instance", "list"); err != nil {
			t.Errorf("instance list = %v, want no error", err)
		}
		if err := h.run("compute", "instance", "get", "web-1"); err != nil {
			t.Errorf("instance get = %v, want the instance of proj", err)
		}
	})
}
