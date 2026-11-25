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

	"google.golang.org/api/googleapi"
)

// sweepClient is a client of an account with n selected projects p0..,
// which asks no API.
func sweepClient(n int) *client {
	cov := &coverage{profile: "lab", def: "p0"}
	for i := range n {
		cov.selected = append(cov.selected, fmt.Sprintf("p%d", i))
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
	want := "note: gcp/lab: skipped 3 project(s) in which an API is not enabled or billing is off: p0 (Compute Engine API), p2 (Compute Engine API), p5 (Compute Engine API); they hold nothing there. To stop asking them: polyctl gcp project remove p2 p5"
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
