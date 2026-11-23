package platform

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// fakeClock advances only when slept on.
type fakeClock struct {
	now    time.Time
	sleeps []time.Duration
}

func newFakeClock() *fakeClock { return &fakeClock{now: time.Unix(1_700_000_000, 0)} }

func (c *fakeClock) Now() time.Time { return c.now }

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

func TestWaitUntil(t *testing.T) {
	clock := newFakeClock()
	n := 0
	err := WaitUntil(t.Context(), WaitOptions{Resource: "instance/a", Timeout: time.Minute, Interval: 2 * time.Second, Clock: clock},
		func(context.Context) (WaitState, string, error) {
			n++
			if n == 3 {
				return WaitDone, "Running", nil
			}
			return KeepWaiting, "Pending", nil
		})
	if err != nil || n != 3 || len(clock.sleeps) != 2 {
		t.Fatalf("wait = %v after %d polls, sleeps %v", err, n, clock.sleeps)
	}

	clock = newFakeClock()
	err = WaitUntil(t.Context(), WaitOptions{Resource: "instance/a", Want: "Running", Timeout: 5 * time.Second, Interval: 2 * time.Second, Clock: clock},
		func(context.Context) (WaitState, string, error) { return KeepWaiting, "Starting", nil })
	var te *WaitTimeoutError
	if !errors.As(err, &te) || te.LastStatus != "Starting" || !strings.Contains(err.Error(), "instance/a") || !strings.Contains(err.Error(), "Starting") {
		t.Fatalf("timeout = %v", err)
	}
	if clock.now.Sub(time.Unix(1_700_000_000, 0)) != 5*time.Second {
		t.Errorf("waited %s, want exactly the timeout", clock.now.Sub(time.Unix(1_700_000_000, 0)))
	}

	err = WaitUntil(t.Context(), WaitOptions{Resource: "lb/x", Want: "Active", Clock: newFakeClock()},
		func(context.Context) (WaitState, string, error) { return WaitFailed, "Failed", nil })
	if err == nil || !strings.Contains(err.Error(), "entered status Failed") {
		t.Errorf("failed state = %v", err)
	}
	boom := errors.New("boom")
	if err := WaitUntil(t.Context(), WaitOptions{Clock: newFakeClock()}, func(context.Context) (WaitState, string, error) { return 0, "", boom }); !errors.Is(err, boom) {
		t.Errorf("poll error = %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if err := WaitUntil(ctx, WaitOptions{Clock: newFakeClock()}, func(context.Context) (WaitState, string, error) { return KeepWaiting, "", nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled = %v", err)
	}
}

func TestStatusWaitToleratesTransientStopped(t *testing.T) {
	t0 := time.Unix(0, 0)
	w := &StatusWait{Target: "Running", Transient: map[string]time.Duration{"Stopped": 30 * time.Second}}
	for i, s := range []string{"Pending", "Stopped", "Starting"} {
		if got := w.Observe(t0.Add(time.Duration(i)*2*time.Second), s); got != KeepWaiting {
			t.Fatalf("%s = %v", s, got)
		}
	}
	if w.Observe(t0.Add(8*time.Second), "Running") != WaitDone {
		t.Fatal("Running not done")
	}
	// Stopped for longer than its grace is a failure.
	w = &StatusWait{Target: "Running", Transient: map[string]time.Duration{"Stopped": 30 * time.Second}}
	w.Observe(t0, "Stopped")
	if w.Observe(t0.Add(20*time.Second), "Stopped") != KeepWaiting || w.Observe(t0.Add(31*time.Second), "Stopped") != WaitFailed {
		t.Error("lasting Stopped must fail after its grace")
	}
	// Stopped after Running was seen is a failure at once.
	w = &StatusWait{Target: "Running", Stable: 2, Transient: map[string]time.Duration{"Stopped": 30 * time.Second}, Failed: []string{"Deleted"}}
	if w.Observe(t0, "Running") != KeepWaiting || w.Observe(t0.Add(time.Second), "Stopped") != WaitFailed {
		t.Error("Stopped after Running must fail")
	}
	if (&StatusWait{Target: "Running", Failed: []string{"Deleted"}}).Observe(t0, "Deleted") != WaitFailed {
		t.Error("failed status")
	}
}

type codeErr string

func (e codeErr) Error() string     { return string(e) }
func (e codeErr) ErrorCode() string { return string(e) }

func TestRetry(t *testing.T) {
	clock := newFakeClock()
	n := 0
	err := Retry(t.Context(), RetryPolicy{Codes: RetryableCodes, Clock: clock}, func(context.Context) error {
		n++
		if n < 4 {
			return codeErr("IncorrectInstanceStatus.Initializing")
		}
		return nil
	})
	if err != nil || n != 4 {
		t.Fatalf("retry = %v after %d", err, n)
	}
	if want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second}; len(clock.sleeps) != 3 || clock.sleeps[0] != want[0] || clock.sleeps[2] != want[2] {
		t.Errorf("backoff = %v", clock.sleeps)
	}
	// Other errors are returned at once.
	n = 0
	err = Retry(t.Context(), DefaultRetry(), func(context.Context) error { n++; return codeErr("InvalidParameter") })
	if n != 1 || codeOf(err) != "InvalidParameter" {
		t.Errorf("non-retryable: %d, %v", n, err)
	}
	// The budget ends the retries with the last error.
	clock = newFakeClock()
	n = 0
	err = Retry(t.Context(), RetryPolicy{Codes: []string{"DependencyViolation"}, Timeout: 20 * time.Second, Max: 5 * time.Second, Clock: clock}, func(context.Context) error {
		n++
		return codeErr("DependencyViolation")
	})
	if codeOf(err) != "DependencyViolation" || clock.now.Sub(time.Unix(1_700_000_000, 0)) > 20*time.Second {
		t.Errorf("budget: %v after %d, %v", err, n, clock.sleeps)
	}
	n = 0
	_ = Retry(t.Context(), RetryPolicy{Codes: []string{"DependencyViolation"}, MaxAttempts: 2, Clock: newFakeClock()}, func(context.Context) error { n++; return codeErr("DependencyViolation") })
	if n != 2 {
		t.Errorf("MaxAttempts: %d", n)
	}
}

func codeOf(err error) string { return ErrorCode(err) }

func TestIgnoreCodesAndClientToken(t *testing.T) {
	if IgnoreCodes(codeErr("InvalidAllocationId.NotFound"), "InvalidAllocationId.NotFound") != nil {
		t.Error("ignored code")
	}
	if IgnoreCodes(codeErr("X"), "Y") == nil {
		t.Error("other code kept")
	}
	a, b := ClientToken("RunInstances", map[string]any{"name": "web", "n": 1}), ClientToken("RunInstances", map[string]any{"n": 1, "name": "web"})
	if a != b || len(a) != 64 {
		t.Errorf("token not stable: %s %s", a, b)
	}
	if a == ClientToken("RunInstances", map[string]any{"name": "web", "n": 2}) {
		t.Error("different request, same token")
	}
}
