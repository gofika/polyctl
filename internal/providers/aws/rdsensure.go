package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// dbSkipStatus reports the statuses ensure does not act on: the instance
// is being created or deleted, or is broken. They count as failures.
func dbSkipStatus(status string) bool {
	return status == dbCreating || dbFatal(status) || status == ""
}

// dbSkipError is the failure of an instance ensure leaves alone.
type dbSkipError struct{ id, status string }

func (e *dbSkipError) Error() string {
	return fmt.Sprintf("RDS instance %s is %s: left alone", e.id, e.status)
}

// dbEnsure is the observed state of one instance of `rds instance ensure`.
type dbEnsure struct {
	ref string
	l   *locatedDB
	err error
}

func (e *dbEnsure) resource() string {
	if e.l != nil {
		return e.l.resource()
	}
	return "db-instance/" + e.ref
}

// ensureEnv is what the steps of ensure share.
type ensureEnv struct {
	rt      *app.Runtime
	running bool
	wait    bool
	timeout time.Duration
}

func (env ensureEnv) want() string {
	if env.running {
		return dbAvailable
	}
	return dbStopped
}

// waitStatus waits until the instance is in status want.
func (env ensureEnv) waitStatus(ctx context.Context, l *locatedDB, want string, interval time.Duration) error {
	fatal := dbFatal
	if want == dbAvailable {
		fatal = func(s string) bool { return dbFatal(s) || s == dbStopped && !env.running }
	}
	db, err := l.c.waitDB(ctx, dbWait{region: l.region, id: l.id(), want: want, interval: interval, timeout: env.timeout,
		done: statusIs(want), goneFails: true, fatal: fatal})
	if awssdk.ToString(db.DBInstanceIdentifier) != "" {
		l.db = db
		l.store(ctx, env.rt)
	}
	return err
}

// power sends the start or stop of the target state and, with --wait,
// waits for it.
func (env ensureEnv) power(ctx context.Context, l *locatedDB, was string) (platform.Change, error) {
	var got string
	var err error
	if env.running {
		got, err = l.c.startDB(ctx, l.region, l.id())
	} else {
		got, err = l.c.stopDB(ctx, l.region, l.id())
	}
	if err != nil {
		return platform.Change{}, err
	}
	l.db.DBInstanceStatus = awssdk.String(got)
	l.store(ctx, env.rt)
	ch := platform.Change{Action: platform.Updated, Detail: got + " (was " + was + ")"}
	if env.wait {
		if err := env.waitStatus(ctx, l, env.want(), dbPowerPoll); err != nil {
			return ch, err
		}
		ch.Detail = env.want() + " (was " + was + ")"
	}
	return ch, nil
}

// step plans one instance: the table of the design, for stopped and the
// mirror image for running.
func (env ensureEnv) step(e *dbEnsure) platform.Step {
	s := platform.Step{Resource: e.resource()}
	if e.err != nil {
		err := e.err
		s.Check = func(context.Context) (platform.Change, bool, error) { return platform.Change{}, false, err }
		return s
	}
	l := e.l
	s.ID = l.id()
	st := l.status()
	want, going, opposite, opposing := dbStopped, dbStopping, dbAvailable, dbStarting
	verb := "stop"
	if env.running {
		want, going, opposite, opposing = dbAvailable, dbStarting, dbStopped, dbStopping
		verb = "start"
	}
	switch {
	case l.aurora() != nil:
		err := l.aurora()
		s.Check = func(context.Context) (platform.Change, bool, error) { return platform.Change{}, false, err }
	case st == want:
		s.Action, s.Desc = platform.Unchanged, "already "+st
	case st == going:
		s.Check = func(ctx context.Context) (platform.Change, bool, error) {
			ch := platform.Change{Action: platform.Unchanged, Detail: "already " + going}
			if env.wait && !env.rt.DryRun() {
				if err := env.waitStatus(ctx, l, want, dbPowerPoll); err != nil {
					return ch, false, err
				}
				ch.Detail += "; now " + want
			}
			return ch, true, nil
		}
	case st == opposite:
		s.Action, s.Desc = platform.Updated, verb+" (was "+st+")"
		s.Apply = func(ctx context.Context) (platform.Change, error) { return env.power(ctx, l, st) }
	case dbSkipStatus(st):
		err := &dbSkipError{id: l.id(), status: st}
		e.err = err
		s.Check = func(context.Context) (platform.Change, bool, error) { return platform.Change{}, false, err }
	case env.running && st != opposing:
		// A transitional status of a running instance (modifying,
		// backing-up, ...): it is running; wait until it settles.
		s.Check = func(ctx context.Context) (platform.Change, bool, error) {
			ch := platform.Change{Action: platform.Unchanged, Detail: st + " (running)"}
			if env.wait && !env.rt.DryRun() {
				if err := env.waitStatus(ctx, l, dbAvailable, dbSettlePoll); err != nil {
					return ch, false, err
				}
				ch.Detail = "available (was " + st + ")"
			}
			return ch, true, nil
		}
	default:
		// Starting, modifying, backing-up, ... on the way to stopped, or
		// stopping on the way to running: wait until the instance settles
		// in the status the action needs, then act. This is how an
		// instance AWS started again after 7 days (starting for a few
		// minutes) is stopped on the same run.
		settle := opposite
		s.Action, s.Desc = platform.Updated, fmt.Sprintf("wait for %s, then %s (now %s)", settle, verb, st)
		s.Apply = func(ctx context.Context) (platform.Change, error) {
			env.rt.Infof("RDS instance %s is %s; waiting until it is %s...", l.id(), st, settle)
			if err := env.waitStatus(ctx, l, settle, dbSettlePoll); err != nil {
				return platform.Change{}, err
			}
			return env.power(ctx, l, st)
		}
	}
	return s
}

func rdsEnsureCmd(rt *app.Runtime) *cobra.Command {
	var state, region string
	var continueOnError bool
	var wf app.WaitFlags
	cmd := &cobra.Command{
		Use:   "ensure <id|endpoint-dns>... --state stopped|running",
		Short: "Keep RDS instances stopped (or running); run it daily",
		Long: `Bring RDS instances to a state and keep them there; a second run changes
nothing. --state stopped stops available instances; stopped and stopping ones
are unchanged; an instance that is starting, modifying, backing up or the like
is waited for until it is available, then stopped. --state running (alias
available) is the mirror image. Instances being created or deleted, failed or
otherwise broken are skipped and count as failures. ensure waits until the
state is reached (--no-wait returns once the request is sent; --timeout 30m
bounds each wait).

AWS starts a stopped instance again after 7 days, so one run is not enough:
run ensure --state stopped every day, for example from cron:

  0 3 * * * polyctl aws rds instance ensure db-test-01 db-test-02 --state stopped

Every instance is handled even when one fails (--continue-on-error=false stops
at the first failure); the failures are listed at the end. Exit code: 0 when
all are as asked, 4 when every failure is a missing instance, 1 otherwise.
A failure is sent to hooks.on_failure.`,
		Example: "  polyctl aws rds instance ensure db-test-01 db-test-02 --state stopped\n  polyctl aws rds instance ensure db-test-01 --state stopped --dry-run -o json",
		Args:    cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			var running bool
			switch strings.ToLower(strings.TrimSpace(state)) {
			case "stopped":
			case "running", dbAvailable:
				running = true
			case "":
				return app.UsageErrf("ensure needs --state stopped or --state running")
			default:
				return app.UsageErrf("--state %q: expected stopped or running", state)
			}
			wait, timeout, err := wf.Resolve(cmd)
			if err != nil {
				return err
			}
			env := ensureEnv{rt: rt, running: running, wait: wait, timeout: timeout}
			// Observe every instance first (read-only), then run the plan.
			var observed []*dbEnsure
			seen := map[string]bool{}
			for _, ref := range args {
				e := &dbEnsure{ref: strings.TrimSpace(ref)}
				e.l, e.err = resolveDB(ctx, rt, ref, region)
				if e.err != nil && (errors.Is(e.err, app.ErrUsage) || errors.Is(e.err, app.ErrOffline) || errors.Is(e.err, context.Canceled)) {
					return e.err
				}
				if e.l != nil {
					key := e.l.profile + "|" + dbKey(e.l.region, e.l.id())
					if seen[key] {
						continue
					}
					seen[key] = true
					e.l.store(ctx, rt)
				}
				observed = append(observed, e)
			}
			plan := &platform.Plan{ContinueOnError: continueOnError}
			for _, e := range observed {
				plan.Add(env.step(e))
			}
			target := ensureTarget(observed)
			rep, err := rt.RunPlan(ctx, target, plan)
			// A skipped instance is reported as skipped, with its status.
			var failed []string
			allMissing := true
			for i, c := range rep.Changes {
				if c.Action != platform.Failed {
					continue
				}
				name := strings.TrimPrefix(c.Resource, "db-instance/")
				failed = append(failed, name)
				for _, e := range observed {
					var skipErr *dbSkipError
					if e.resource() == c.Resource && errors.As(e.err, &skipErr) {
						rep.Changes[i].Action, rep.Changes[i].Detail = platform.Skipped, skipErr.status
					}
				}
				if !isMissing(observed, c.Resource) {
					allMissing = false
				}
			}
			if rerr := rt.RenderReport(rep); rerr != nil && err == nil {
				err = rerr
			}
			if err == nil {
				return nil
			}
			if errors.Is(err, context.Canceled) {
				return err
			}
			summary := fmt.Sprintf("the following %d instance(s) failed: %s", len(failed), strings.Join(failed, ", "))
			var final error
			switch {
			case len(failed) == 0:
				final = err
			case allMissing:
				final = fmt.Errorf("%w: %s", platform.ErrNotFound, summary)
			default:
				final = fmt.Errorf("%s (first error: %s)", summary, firstErrText(err))
			}
			if !rep.DryRun {
				rt.NotifyFailure(ctx, app.Failure{Event: "aws.rds.instance.ensure.failed", Platform: string(platform.AWS), Profile: target.Profile,
					Error: final.Error(), Changes: rep.Changes})
			}
			return final
		},
	}
	cmd.Flags().StringVar(&state, "state", "", "the state to bring the instances to: stopped or running (required)")
	cmd.Flags().BoolVar(&continueOnError, "continue-on-error", true, "go on with the other instances after a failure")
	cmd.Flags().StringVar(&region, "region", "", "region of the instances (default: look them up in the inventory of every account)")
	app.AddWaitFlags(cmd, &wf, true, rdsEnsureTimeout)
	return cmd
}

// isMissing reports whether the instance of resource failed as not found.
func isMissing(observed []*dbEnsure, resource string) bool {
	for _, e := range observed {
		if e.resource() == resource && errors.Is(e.err, platform.ErrNotFound) {
			return true
		}
	}
	return false
}

func firstErrText(err error) string {
	var pe *platform.PartialError
	if errors.As(err, &pe) && pe.First != nil {
		return pe.First.Error()
	}
	return err.Error()
}

// ensureTarget is the target of the report: the account and region of the
// instances when they share them.
func ensureTarget(observed []*dbEnsure) platform.Target {
	t := platform.Target{Platform: platform.AWS}
	first := true
	for _, e := range observed {
		if e.l == nil {
			continue
		}
		if first {
			t.Profile, t.Region, first = e.l.profile, e.l.region, false
			continue
		}
		if t.Profile != e.l.profile {
			t.Profile = ""
		}
		if t.Region != e.l.region {
			t.Region = ""
		}
	}
	return t
}
