package platform

import (
	"context"
	"errors"
	"testing"
)

// fakeCloud is an in-memory platform that counts its writes.
type fakeCloud struct {
	vpc, vswitch string
	writes       int
}

func (f *fakeCloud) plan() *Plan {
	p := &Plan{}
	p.Add(Step{
		Resource: "vpc/main", Action: Created, Desc: "10.0.0.0/16",
		Check: func(ctx context.Context) (Change, bool, error) {
			return Change{ID: f.vpc}, f.vpc != "", nil
		},
		Apply: func(ctx context.Context) (Change, error) {
			f.writes++
			f.vpc = "vpc-1"
			return Change{ID: f.vpc}, nil
		},
	}, Step{
		Resource: "vswitch/main-a", Action: Created,
		Check: func(ctx context.Context) (Change, bool, error) {
			return Change{ID: f.vswitch}, f.vswitch != "", nil
		},
		Apply: func(ctx context.Context) (Change, error) {
			f.writes++
			f.vswitch = "vsw-1"
			return Change{ID: f.vswitch, Detail: "in " + p.ID("vpc/main")}, nil
		},
	})
	return p
}

func actions(chs []Change) []Action {
	var out []Action
	for _, c := range chs {
		out = append(out, c.Action)
	}
	return out
}

func TestPlanCreateThenUnchanged(t *testing.T) {
	f := &fakeCloud{}
	chs, err := f.plan().Run(t.Context(), false)
	if err != nil || len(chs) != 2 || chs[0].Action != Created || chs[1].Action != Created || chs[0].ID != "vpc-1" || chs[1].Detail != "in vpc-1" {
		t.Fatalf("first run = %+v, %v", chs, err)
	}
	if chs[0].Detail != "10.0.0.0/16" {
		t.Errorf("detail not filled from the step: %+v", chs[0])
	}
	// Idempotent: the second run writes nothing.
	f.writes = 0
	chs, err = f.plan().Run(t.Context(), false)
	if err != nil || f.writes != 0 || actions(chs)[0] != Unchanged || actions(chs)[1] != Unchanged || chs[0].ID != "vpc-1" {
		t.Fatalf("second run = %+v, %v (writes %d)", chs, err, f.writes)
	}
}

func TestPlanPartialAndDryRun(t *testing.T) {
	f := &fakeCloud{vpc: "vpc-9"}
	chs, err := f.plan().Run(t.Context(), true)
	if err != nil || f.writes != 0 {
		t.Fatalf("dry run wrote: %d, %v", f.writes, err)
	}
	if chs[0].Action != Unchanged || chs[1].Action != WouldCreate || chs[1].ID != Pending {
		t.Errorf("dry run changes = %+v", chs)
	}
	// Only the missing part is created.
	chs, err = f.plan().Run(t.Context(), false)
	if err != nil || f.writes != 1 || chs[0].Action != Unchanged || chs[1].Action != Created || chs[1].Detail != "in vpc-9" {
		t.Errorf("partial = %+v, %v (writes %d)", chs, err, f.writes)
	}
}

func TestPlanDryRunUsesPendingIDs(t *testing.T) {
	f := &fakeCloud{}
	p := f.plan()
	var seen string
	p.Add(Step{Resource: "x", Action: Updated, Apply: func(context.Context) (Change, error) { return Change{}, nil },
		Check: func(context.Context) (Change, bool, error) { seen = p.ID("vpc/main"); return Change{}, false, nil }})
	chs, err := p.Run(t.Context(), true)
	if err != nil || seen != Pending || chs[2].Action != WouldUpdate || f.writes != 0 {
		t.Errorf("dry run = %+v, %v, id %q", chs, err, seen)
	}
}

func TestPlanFailures(t *testing.T) {
	boom := errors.New("boom")
	fail := func(context.Context) (Change, error) { return Change{}, boom }
	ok := func(context.Context) (Change, error) { return Change{}, nil }
	p := &Plan{Steps: []Step{{Resource: "a", Action: Deleted, Apply: fail}, {Resource: "b", Action: Deleted, Apply: ok}}}
	chs, err := p.Run(t.Context(), false)
	if !errors.Is(err, boom) || len(chs) != 1 || chs[0].Action != Failed || chs[0].Detail != "boom" {
		t.Errorf("stop on error = %+v, %v", chs, err)
	}
	p = &Plan{ContinueOnError: true, Steps: []Step{{Resource: "a", Action: Deleted, Apply: fail}, {Resource: "b", Action: Deleted, Apply: ok}}}
	chs, err = p.Run(t.Context(), false)
	var pe *PartialError
	if !errors.As(err, &pe) || pe.Failed != 1 || pe.Total != 2 || !errors.Is(err, boom) || len(chs) != 2 || chs[1].Action != Deleted {
		t.Errorf("continue on error = %+v, %v", chs, err)
	}
	// A report-only step keeps its action, in a dry run too.
	p = &Plan{Steps: []Step{{Resource: "c", Action: Skipped, Desc: "read only"}}}
	if chs, _ := p.Run(t.Context(), true); chs[0].Action != Skipped || chs[0].Detail != "read only" {
		t.Errorf("report step = %+v", chs)
	}
}

func TestActionForms(t *testing.T) {
	if Created.DryRun() != WouldCreate || Deleted.DryRun() != WouldDelete || Updated.DryRun() != WouldUpdate || Skipped.DryRun() != Skipped {
		t.Error("DryRun forms")
	}
	if WouldCreate.Label() != "would create" || !WouldDelete.Writes() || Unchanged.Writes() {
		t.Error("labels")
	}
}
