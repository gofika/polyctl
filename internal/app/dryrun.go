package app

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// DryRun reports whether --dry-run was given: write commands report what
// they would change and write nothing. Read-only commands ignore it.
func (rt *Runtime) DryRun() bool { return rt.Flags.DryRun }

// ReportTarget converts a routing target to the target of a change report.
func (t Target) ReportTarget() platform.Target {
	return platform.Target{Platform: t.Platform, Profile: t.Profile, Domain: t.Domain}
}

// ChangeGrid is the table of a change report: RESOURCE, ACTION, DETAIL. The
// detail column falls back to the resource id.
func ChangeGrid(changes []platform.Change) output.Grid {
	g := output.Grid{Headers: []string{"RESOURCE", "ACTION", "DETAIL"}}
	for _, c := range changes {
		detail := c.Detail
		if detail == "" {
			detail = c.ID
		}
		g.Rows = append(g.Rows, []string{c.Resource, c.Action.Label(), detail})
	}
	return g
}

// RenderReport prints a change report: the table of ChangeGrid, or the
// report itself ({target, dry_run, changes[]}) in json and yaml. An empty
// report still prints its header, or "changes": [].
func (rt *Runtime) RenderReport(rep platform.Report) error {
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	return rt.Render(rep, func() output.Grid { return ChangeGrid(rep.Changes) })
}

// WouldWrite is the --dry-run gate of a write command that does not build a
// Plan (single-record writes, power actions). Without --dry-run it returns
// false and the command goes on to write. With --dry-run it prints the
// report of the changes in their dry-run form ("would create ...") and a
// note on stderr, and returns true: the command must then return the error
// (nil) without writing anything and without asking for a confirmation.
// Call it after the read-only work that tells what would change, and
// before any confirmation.
func (rt *Runtime) WouldWrite(target platform.Target, changes ...platform.Change) (bool, error) {
	if !rt.Flags.DryRun {
		return false, nil
	}
	rep := platform.Report{Target: target, DryRun: true, Changes: make([]platform.Change, 0, len(changes))}
	for _, c := range changes {
		c.Action = c.Action.DryRun()
		rep.Changes = append(rep.Changes, c)
		rt.Infof("dry run: %s %s%s", c.Action.Label(), c.Resource, detailNote(c))
	}
	if len(changes) == 0 {
		rt.Infof("dry run: nothing would change")
	}
	return true, rt.RenderReport(rep)
}

func detailNote(c platform.Change) string {
	if c.Detail != "" {
		return " (" + c.Detail + ")"
	}
	if c.ID != "" {
		return " (" + c.ID + ")"
	}
	return ""
}

// RunPlan runs plan in the flow of the command (a dry run with --dry-run)
// and returns the report. The report is filled also when the plan fails, so
// that what was done before the failure can still be shown.
func (rt *Runtime) RunPlan(ctx context.Context, target platform.Target, plan *platform.Plan) (platform.Report, error) {
	changes, err := plan.Run(ctx, rt.Flags.DryRun)
	return platform.Report{Target: target, DryRun: rt.Flags.DryRun, Changes: changes}, err
}

// Ensure runs plan and prints its report: the common tail of every ensure
// command. The report is printed when the plan failed too, before the
// error is returned. A failure (not in a dry run, not a usage error) is
// also sent to hooks.on_failure as the event "<event>.failed"; event names
// the command, dot-separated ("aws.rds.instance.ensure").
func (rt *Runtime) Ensure(ctx context.Context, event string, target platform.Target, plan *platform.Plan) error {
	rep, err := rt.RunPlan(ctx, target, plan)
	if rerr := rt.RenderReport(rep); rerr != nil && err == nil {
		err = rerr
	}
	if err != nil && !rep.DryRun && !errors.Is(err, ErrUsage) {
		rt.NotifyFailure(ctx, Failure{Event: event + ".failed", Platform: string(target.Platform), Profile: target.Profile,
			Domain: target.Domain, Error: err.Error(), Changes: rep.Changes})
	}
	return err
}

// WaitFlags are the --wait / --no-wait / --timeout flags of a command that
// starts an asynchronous change.
type WaitFlags struct {
	Wait    bool
	Timeout time.Duration
	noWait  bool
}

// DefaultWaitTimeout is the default --timeout of a wait.
const DefaultWaitTimeout = 10 * time.Minute

// AddWaitFlags registers --wait and --timeout on cmd. ensure commands wait
// by default (defaultWait true) and also get --no-wait; every other command
// waits only with --wait.
func AddWaitFlags(cmd *cobra.Command, w *WaitFlags, defaultWait bool, defaultTimeout time.Duration) {
	if defaultTimeout <= 0 {
		defaultTimeout = DefaultWaitTimeout
	}
	help := "wait until the change has completed"
	if defaultWait {
		help += " (default; --no-wait or --wait=false returns at once)"
	}
	cmd.Flags().BoolVar(&w.Wait, "wait", defaultWait, help)
	if defaultWait {
		cmd.Flags().BoolVar(&w.noWait, "no-wait", false, "return as soon as the change was requested, without waiting for it to complete")
	}
	cmd.Flags().DurationVar(&w.Timeout, "timeout", defaultTimeout, "upper bound of the wait (a Go duration such as 90s or 10m)")
}

// Resolve validates the flags and returns whether to wait and for how long.
func (w *WaitFlags) Resolve(cmd *cobra.Command) (bool, time.Duration, error) {
	if w.noWait && cmd.Flags().Changed("wait") && w.Wait {
		return false, 0, UsageErrf("--wait and --no-wait contradict each other")
	}
	if w.Timeout <= 0 {
		return false, 0, UsageErrf("--timeout must be a positive duration, got %s", w.Timeout)
	}
	return w.Wait && !w.noWait, w.Timeout, nil
}

// RecordResource names a DNS record in a change report: record/<fqdn>/<TYPE>.
func RecordResource(fqdn, typ string) string {
	return "record/" + platform.NormalizeDomain(fqdn) + "/" + strings.ToUpper(typ)
}

// NameserverChange is the change of a nameserver update at a registrar.
func NameserverChange(domain string, ns []string) platform.Change {
	return platform.Change{Resource: "domain/" + platform.NormalizeDomain(domain) + "/nameservers", Action: platform.Updated, Detail: strings.Join(ns, ",")}
}

// ResourceChange is the change of a write to one resource of a platform
// tree: kind/name with action and detail. A shortcut for the single-resource
// write commands' dry runs.
func ResourceChange(kind, name string, action platform.Action, detail string) platform.Change {
	return platform.Change{Resource: kind + "/" + name, Action: action, Detail: detail}
}
