package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Action is what happened (or, in a dry run, would happen) to one resource
// of a write command: the ACTION column of a change report.
type Action string

const (
	// Created: the resource did not exist and was created.
	Created Action = "created"
	// Updated: the resource existed and was changed.
	Updated Action = "updated"
	// Unchanged: the resource already was as requested.
	Unchanged Action = "unchanged"
	// Skipped: the resource was deliberately left alone (the detail says why).
	Skipped Action = "skipped"
	// Deleted: the resource was removed.
	Deleted Action = "deleted"
	// Failed: the step for the resource failed (the detail holds the error).
	Failed Action = "failed"
	// WouldCreate, WouldUpdate and WouldDelete are the dry-run forms of
	// Created, Updated and Deleted: nothing was written.
	WouldCreate Action = "would_create"
	WouldUpdate Action = "would_update"
	WouldDelete Action = "would_delete"
)

// Label is the action as a table shows it ("would create").
func (a Action) Label() string { return strings.ReplaceAll(string(a), "_", " ") }

// DryRun returns the dry-run form of a write action (Created becomes
// WouldCreate, ...). Every other action is returned as it is.
func (a Action) DryRun() Action {
	switch a {
	case Created:
		return WouldCreate
	case Updated:
		return WouldUpdate
	case Deleted:
		return WouldDelete
	}
	return a
}

// Writes reports whether the action is (or would be) a write to the
// platform.
func (a Action) Writes() bool {
	switch a {
	case Created, Updated, Deleted, WouldCreate, WouldUpdate, WouldDelete:
		return true
	}
	return false
}

// Pending is the id of a resource that a dry run would create: later steps
// that need the id of an earlier one get this placeholder instead of an
// error.
const Pending = "(pending)"

// Change describes the outcome of one step of a write command.
type Change struct {
	// Resource names the resource, as kind/name with sub-resources appended
	// ("security-group/web", "load-balancer/site-lb/listener/tcp:80").
	Resource string `json:"resource" yaml:"resource"`
	Action   Action `json:"action" yaml:"action"`
	// ID is the platform id of the resource, when known.
	ID string `json:"id,omitempty" yaml:"id,omitempty"`
	// Detail is a short human explanation.
	Detail string `json:"detail,omitempty" yaml:"detail,omitempty"`
	// Attrs are extra fields for the json / yaml output.
	Attrs map[string]string `json:"attrs,omitempty" yaml:"attrs,omitempty"`
}

// Target names the account (and, where it matters, the region or zone) a
// change report is about.
type Target struct {
	Platform ID     `json:"platform" yaml:"platform"`
	Profile  string `json:"profile" yaml:"profile"`
	Region   string `json:"region,omitempty" yaml:"region,omitempty"`
	Zone     string `json:"zone,omitempty" yaml:"zone,omitempty"`
	Domain   string `json:"domain,omitempty" yaml:"domain,omitempty"`
}

// Report is the result of a write command: what it changed, or in a dry
// run what it would change. It is the json / yaml shape of every ensure
// command and of every write command run with --dry-run.
type Report struct {
	Target  Target   `json:"target" yaml:"target"`
	DryRun  bool     `json:"dry_run" yaml:"dry_run"`
	Changes []Change `json:"changes" yaml:"changes"`
}

// Step is one unit of work of a Plan.
type Step struct {
	// Resource names the resource (see Change.Resource).
	Resource string
	// Action is what Apply does (Created, Updated or Deleted; Updated when
	// empty); a dry run reports its WouldXxx form. A step without Check
	// and Apply reports Action as it is (Unchanged when empty, Skipped...).
	Action Action
	// Desc is the detail of the change; a dry run prints it.
	Desc string
	// ID is the id reported when the step has no Apply, or in a dry run
	// (where it defaults to Pending for a step that creates).
	ID string
	// Attrs are the attrs of the change when the step's own change has
	// none (a dry run reports them too).
	Attrs map[string]string
	// Check, when set, is read-only and runs in a dry run too. It returns
	// done=true when the resource already is as requested; the change it
	// returns is then reported (Unchanged when its Action is empty) and
	// Apply is not called.
	Check func(ctx context.Context) (change Change, done bool, err error)
	// Apply performs the write. It is never called in a dry run. The change
	// it returns is reported; empty fields are filled from the step.
	Apply func(ctx context.Context) (Change, error)
	// ContinueOnError records a failure of this step as a Failed change and
	// goes on with the next step instead of stopping the plan.
	ContinueOnError bool
}

// Plan is an ordered list of steps: ensure commands first observe the
// current state (read-only), compute the steps that bring it to the desired
// state, then run the plan, which writes or, in a dry run, only reports.
// Every write of such a command goes through Step.Apply, so --dry-run
// cannot be bypassed.
type Plan struct {
	Steps []Step
	// ContinueOnError applies Step.ContinueOnError to every step: a batch
	// goes on after a failed item and fails as a whole at the end.
	ContinueOnError bool

	ids map[string]string
}

// Add appends steps to the plan.
func (p *Plan) Add(steps ...Step) { p.Steps = append(p.Steps, steps...) }

// ID returns the id a step that already ran reported for resource: the real
// id, or Pending when a dry run would create it. It is how a later step
// uses the id of an earlier one ("create the vswitch in the VPC created
// above").
func (p *Plan) ID(resource string) string { return p.ids[resource] }

// PartialError is returned by Plan.Run when steps that continue on error
// failed: the others ran, and the report lists every outcome.
type PartialError struct {
	Failed, Total int
	First         error
}

func (e *PartialError) Error() string {
	return fmt.Sprintf("%d of %d step(s) failed; first error: %v", e.Failed, e.Total, e.First)
}

func (e *PartialError) Unwrap() error { return e.First }

// Run executes the steps in order and returns the changes. With dryRun no
// Apply is called: write steps are reported in their WouldXxx form, while
// Check (read-only) still runs. A failing step stops the plan, unless it
// continues on error; the changes so far are returned with the error either
// way, the failed step included as a Failed change.
func (p *Plan) Run(ctx context.Context, dryRun bool) ([]Change, error) {
	if p.ids == nil {
		p.ids = map[string]string{}
	}
	var changes []Change
	failed := 0
	var first error
	for _, s := range p.Steps {
		if err := ctx.Err(); err != nil {
			return changes, err
		}
		ch, err := p.runStep(ctx, s, dryRun)
		if err != nil {
			changes = append(changes, Change{Resource: s.Resource, Action: Failed, ID: ch.ID, Detail: err.Error()})
			if !(s.ContinueOnError || p.ContinueOnError) || errors.Is(err, context.Canceled) {
				return changes, err
			}
			failed++
			if first == nil {
				first = err
			}
			continue
		}
		if ch.ID != "" {
			p.ids[ch.Resource] = ch.ID
		}
		changes = append(changes, ch)
	}
	if failed > 0 {
		return changes, &PartialError{Failed: failed, Total: len(p.Steps), First: first}
	}
	return changes, nil
}

func (p *Plan) runStep(ctx context.Context, s Step, dryRun bool) (Change, error) {
	fill := func(ch Change, def Action) Change {
		if ch.Resource == "" {
			ch.Resource = s.Resource
		}
		if ch.Action == "" {
			ch.Action = def
		}
		if ch.ID == "" {
			ch.ID = s.ID
		}
		if ch.Detail == "" {
			ch.Detail = s.Desc
		}
		if ch.Attrs == nil {
			ch.Attrs = s.Attrs
		}
		return ch
	}
	if s.Check != nil {
		ch, done, err := s.Check(ctx)
		if err != nil {
			return ch, err
		}
		if done {
			return fill(ch, Unchanged), nil
		}
	}
	if s.Apply == nil {
		act := s.Action
		if act == "" {
			act = Unchanged
		}
		if dryRun {
			act = act.DryRun()
		}
		return fill(Change{}, act), nil
	}
	// A write step that does not say what it does is an update: its
	// change report row never goes without an action.
	act := s.Action
	if act == "" {
		act = Updated
	}
	if dryRun {
		ch := fill(Change{}, act.DryRun())
		if ch.ID == "" && s.Action == Created {
			ch.ID = Pending
		}
		return ch, nil
	}
	ch, err := s.Apply(ctx)
	if err != nil {
		return ch, err
	}
	return fill(ch, act), nil
}
