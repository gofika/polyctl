package aliyun

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// Timing of the instance waits and retries. A new instance is Running
// 3 to 7 seconds after RunInstances returns, so polls are 2 seconds apart.
const (
	instanceWaitInterval = 2 * time.Second
	// stoppedGrace is how long a new instance may read Stopped before it
	// counts as stopped by someone: it briefly reads Stopped on its way
	// to Running.
	stoppedGrace = 30 * time.Second
	// rebootGrace is how long a reboot may read Running without ever
	// leaving it before the wait accepts Running.
	rebootGrace = 30 * time.Second
	// initializingRetry bounds the retries of a delete refused while a new
	// instance initializes (about 45 seconds after its creation).
	initializingRetry      = 2 * time.Minute
	defaultInstanceTimeout = app.DefaultWaitTimeout
)

// storeInstance records an instance in the inventory.
func storeInstance(ctx context.Context, rt *app.Runtime, profile string, in Instance) {
	if in.ID == "" {
		return
	}
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResInstance}, instanceResource(in), cfg.TTLFor(platform.ResInstance))
}

// dropInstance removes an instance from the inventory.
func dropInstance(ctx context.Context, rt *app.Runtime, profile, id string) {
	if db, err := rt.DB(); err == nil {
		_ = db.Delete(ctx, inventory.Set{Platform: platform.Aliyun, Profile: profile, Type: platform.ResInstance}, platform.ResInstance, id)
	}
}

// pollStatus reads the status of an instance for a wait: "NotFound" (and
// no error) while it is not listed, which a wait reads as "not there yet".
func pollStatus(ctx context.Context, s *ecsScope, id string) (string, error) {
	st, err := s.c.instanceStatus(ctx, s.region, id)
	if err != nil {
		return "", err
	}
	if st == "" {
		return statusNotFound, nil
	}
	return st, nil
}

// waitInstanceRunning waits until the instance is Running and returns how
// long that took. Stopped is a transient status of a new instance: it is
// accepted for stoppedGrace, but once Running was seen a Stopped instance
// was stopped by someone, and the wait fails.
func waitInstanceRunning(ctx context.Context, s *ecsScope, id, label string, timeout time.Duration) (time.Duration, error) {
	clock := netClock()
	start := clock.Now()
	sw := &platform.StatusWait{Target: instRunning, Transient: map[string]time.Duration{instStopped: stoppedGrace}}
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "instance/" + label, Want: instRunning, Timeout: timeout,
		Interval: instanceWaitInterval, Clock: clock}, func(ctx context.Context) (platform.WaitState, string, error) {
		st, err := pollStatus(ctx, s, id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if sw.Observe(clock.Now(), st) == platform.WaitFailed {
			return platform.KeepWaiting, st, fmt.Errorf("instance %s (%s) is %s: it was stopped while polyctl waited for Running; start it with `polyctl aliyun ecs instance start %s`", label, id, st, id)
		}
		if st == instRunning {
			return platform.WaitDone, st, nil
		}
		return platform.KeepWaiting, st, nil
	})
	return clock.Now().Sub(start), err
}

// waitInstanceStatus waits until the instance reads want.
func waitInstanceStatus(ctx context.Context, s *ecsScope, id, label, want string, timeout time.Duration) error {
	return platform.WaitUntil(ctx, platform.WaitOptions{Resource: "instance/" + label, Want: want, Timeout: timeout,
		Interval: instanceWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		st, err := pollStatus(ctx, s, id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if st == want {
			return platform.WaitDone, st, nil
		}
		return platform.KeepWaiting, st, nil
	})
}

// waitInstanceSettled waits until the instance is Running or Stopped (it
// is Pending, Starting or Stopping) and returns that status.
func waitInstanceSettled(ctx context.Context, s *ecsScope, id, label string, timeout time.Duration) (string, error) {
	var last string
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "instance/" + label, Want: instRunning + " or " + instStopped, Timeout: timeout,
		Interval: instanceWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		st, err := pollStatus(ctx, s, id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		last = st
		if st == instRunning || st == instStopped {
			return platform.WaitDone, st, nil
		}
		if st == statusNotFound {
			return platform.KeepWaiting, st, fmt.Errorf("%w: instance %s (%s) is gone", platform.ErrNotFound, label, id)
		}
		return platform.KeepWaiting, st, nil
	})
	return last, err
}

// waitRebooted waits for a rebooted instance to be Running again. A read
// right after RebootInstance may still say Running, so Running counts only
// after another status was seen, or once rebootGrace has passed.
func waitRebooted(ctx context.Context, s *ecsScope, id, label string, timeout time.Duration) (time.Duration, error) {
	clock := netClock()
	start := clock.Now()
	left := false
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "instance/" + label, Want: instRunning, Timeout: timeout,
		Interval: instanceWaitInterval, Clock: clock}, func(ctx context.Context) (platform.WaitState, string, error) {
		st, err := pollStatus(ctx, s, id)
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		if st != instRunning {
			if left && st == instStopped {
				// Stopping, Starting, then Stopped: someone stopped it.
				return platform.KeepWaiting, st, fmt.Errorf("instance %s (%s) is %s after the reboot; start it with `polyctl aliyun ecs instance start %s`", label, id, st, id)
			}
			if st != statusNotFound {
				left = true
			}
			return platform.KeepWaiting, st, nil
		}
		if left || clock.Now().Sub(start) >= rebootGrace {
			return platform.WaitDone, st, nil
		}
		return platform.KeepWaiting, st, nil
	})
	return clock.Now().Sub(start), err
}

// retryInitializing runs fn again while ECS refuses it because the
// instance is still initializing (IncorrectInstanceStatus.Initializing,
// about 45 seconds after its creation), 3 to 5 seconds apart, for at most
// two minutes.
func retryInitializing(ctx context.Context, fn func(ctx context.Context) error) error {
	return platform.Retry(ctx, platform.RetryPolicy{Codes: []string{errInstanceInitializing}, Initial: 3 * time.Second,
		Max: 5 * time.Second, Multiplier: 1.5, Timeout: initializingRetry, Clock: netClock()}, fn)
}

// newInstanceListing bounds how long an instance RunInstances answered may
// be missing from DescribeInstances before it counts as gone. A new
// instance is listed within about 2 seconds.
const newInstanceListing = 30 * time.Second

// lookupNewInstance reads the instance RunInstances answered, waiting while
// it is not listed yet. It is platform.ErrNotFound when it never shows up:
// the request matched an earlier one of the same content (the ClientToken)
// whose instance was deleted since.
func lookupNewInstance(ctx context.Context, s *ecsScope, id string) (*Instance, error) {
	var in *Instance
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "instance/" + id, Want: "listed", Timeout: newInstanceListing,
		Interval: instanceWaitInterval, Clock: netClock()}, func(ctx context.Context) (platform.WaitState, string, error) {
		got, err := s.c.describeInstance(ctx, s.region, id)
		if errors.Is(err, platform.ErrNotFound) {
			return platform.KeepWaiting, statusNotFound, nil
		}
		if err != nil {
			return platform.KeepWaiting, "", err
		}
		in = got
		return platform.WaitDone, got.Status, nil
	})
	var te *platform.WaitTimeoutError
	if errors.As(err, &te) {
		return nil, fmt.Errorf("%w: instance %s that RunInstances answered is not listed", platform.ErrNotFound, id)
	}
	return in, err
}
