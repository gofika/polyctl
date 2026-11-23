package platform

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Clock is the time source of waits and retries. Tests inject one that
// advances instantly, so no test really sleeps.
type Clock interface {
	Now() time.Time
	// Sleep waits for d or until ctx is done, whichever comes first.
	Sleep(ctx context.Context, d time.Duration) error
}

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

func (realClock) Sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

// RealClock is the wall clock.
var RealClock Clock = realClock{}

// WaitState is the verdict of one poll of a wait.
type WaitState int

const (
	// KeepWaiting: not there yet, poll again.
	KeepWaiting WaitState = iota
	// WaitDone: the resource reached the awaited state.
	WaitDone
	// WaitFailed: the resource reached a state it will not come back from.
	WaitFailed
)

// Poll reports the state of the awaited resource: the verdict, and the
// platform's status string, which a timeout or a failure quotes.
type Poll func(ctx context.Context) (state WaitState, status string, err error)

// WaitOptions configure WaitUntil.
type WaitOptions struct {
	// Resource names what is awaited ("instance/web-1"), for the errors.
	Resource string
	// Want describes the awaited state ("Running"), for the errors.
	Want string
	// Timeout bounds the whole wait; zero means no bound other than ctx.
	Timeout time.Duration
	// Interval is the pause between polls (default 2s).
	Interval time.Duration
	// Clock defaults to RealClock.
	Clock Clock
}

// WaitTimeoutError is returned when a wait runs out of time. It maps to the
// general failure exit code.
type WaitTimeoutError struct {
	Resource, Want, LastStatus string
	Timeout                    time.Duration
}

func (e *WaitTimeoutError) Error() string {
	msg := fmt.Sprintf("timed out after %s waiting for %s", e.Timeout, e.Resource)
	if e.Want != "" {
		msg += " to become " + e.Want
	}
	if e.LastStatus != "" {
		msg += " (last status " + e.LastStatus + ")"
	}
	return msg
}

// WaitUntil polls until poll reports WaitDone, WaitFailed or an error, the
// timeout passes, or ctx ends. The first poll happens at once. With a
// timeout, the context handed to poll carries it as a deadline too, so a
// poll that hangs (an API call that does not answer) cannot stretch the
// wait beyond it.
func WaitUntil(ctx context.Context, o WaitOptions, poll Poll) error {
	clock := o.Clock
	if clock == nil {
		clock = RealClock
	}
	interval := o.Interval
	if interval <= 0 {
		interval = 2 * time.Second
	}
	start := clock.Now()
	last := ""
	wctx := ctx
	if o.Timeout > 0 {
		var cancel context.CancelFunc
		wctx, cancel = context.WithTimeout(ctx, o.Timeout)
		defer cancel()
	}
	timedOut := func(err error) error {
		if wctx.Err() != nil && ctx.Err() == nil {
			return &WaitTimeoutError{Resource: o.Resource, Want: o.Want, LastStatus: last, Timeout: o.Timeout}
		}
		return err
	}
	for {
		state, status, err := poll(wctx)
		if err != nil {
			return timedOut(err)
		}
		if status != "" {
			last = status
		}
		switch state {
		case WaitDone:
			return nil
		case WaitFailed:
			msg := fmt.Sprintf("%s entered status %s", o.Resource, last)
			if o.Want != "" {
				msg += " while waiting for " + o.Want
			}
			return errors.New(msg)
		}
		next := interval
		if o.Timeout > 0 {
			left := o.Timeout - clock.Now().Sub(start)
			if left <= 0 {
				return &WaitTimeoutError{Resource: o.Resource, Want: o.Want, LastStatus: last, Timeout: o.Timeout}
			}
			if left < next {
				next = left
			}
		}
		if err := clock.Sleep(wctx, next); err != nil {
			return timedOut(err)
		}
	}
}

// StatusWait turns a stream of status strings into wait verdicts, with
// room for transient states: Alibaba Cloud ECS, for one, briefly reports a
// new instance as Stopped before it becomes Running, so Stopped must not be
// a failure at once.
type StatusWait struct {
	// Target is the awaited status.
	Target string
	// Stable is how many consecutive Target observations count as done
	// (default 1).
	Stable int
	// Transient lists statuses that may show up on the way, each with how
	// long it may last in a row before it counts as a failure. Once Target
	// has been seen, a transient status is a failure right away.
	Transient map[string]time.Duration
	// Failed lists statuses that are failures at once.
	Failed []string

	seenTarget bool
	streak     int
	since      time.Time
	current    string
}

// Observe classifies one status observed at now.
func (w *StatusWait) Observe(now time.Time, status string) WaitState {
	if status != w.current {
		w.current, w.since = status, now
	}
	if status == w.Target {
		w.seenTarget = true
		w.streak++
		stable := w.Stable
		if stable < 1 {
			stable = 1
		}
		if w.streak >= stable {
			return WaitDone
		}
		return KeepWaiting
	}
	w.streak = 0
	if slices.Contains(w.Failed, status) {
		return WaitFailed
	}
	if grace, ok := w.Transient[status]; ok {
		if w.seenTarget || now.Sub(w.since) > grace {
			return WaitFailed
		}
	}
	return KeepWaiting
}

// RetryPolicy decides which failed writes are tried again and how often.
// Some platform states clear by themselves: a new Alibaba Cloud instance
// cannot be deleted for about 45 seconds (IncorrectInstanceStatus.Initializing),
// a listener that is being configured refuses writes (IncorrectStatus.Listener),
// and a security group stays in use for half a minute after the load
// balancer that used it was deleted (DependencyViolation).
type RetryPolicy struct {
	// Codes are the platform error codes (exact match) worth retrying.
	Codes []string
	// Match, when set, is consulted too.
	Match func(error) bool
	// Initial is the first pause (default 2s); each pause is Multiplier
	// (default 2) times the previous one, capped at Max (default 30s).
	Initial, Max time.Duration
	Multiplier   float64
	// Timeout bounds the time spent retrying (default 2m); MaxAttempts, when
	// set, bounds the number of attempts.
	Timeout     time.Duration
	MaxAttempts int
	Clock       Clock
}

// RetryableCodes are the codes of transient states verified on real
// accounts.
var RetryableCodes = []string{
	"IncorrectInstanceStatus.Initializing",
	"IncorrectStatus.Listener",
	"DependencyViolation",
	"DependencyViolation.VSwitch",
}

// DefaultRetry retries RetryableCodes with exponential backoff.
func DefaultRetry() RetryPolicy { return RetryPolicy{Codes: RetryableCodes} }

func (p RetryPolicy) retryable(err error) bool {
	if HasErrorCode(err, p.Codes...) {
		return true
	}
	return p.Match != nil && p.Match(err)
}

// Retry runs fn until it succeeds, fails with an error the policy does not
// retry, or the policy's budget is spent; then it returns the last error.
func Retry(ctx context.Context, p RetryPolicy, fn func(ctx context.Context) error) error {
	clock := p.Clock
	if clock == nil {
		clock = RealClock
	}
	pause := p.Initial
	if pause <= 0 {
		pause = 2 * time.Second
	}
	max := p.Max
	if max <= 0 {
		max = 30 * time.Second
	}
	mult := p.Multiplier
	if mult < 1 {
		mult = 2
	}
	timeout := p.Timeout
	if timeout <= 0 {
		timeout = 2 * time.Minute
	}
	start := clock.Now()
	for attempt := 1; ; attempt++ {
		err := fn(ctx)
		if err == nil || !p.retryable(err) {
			return err
		}
		if p.MaxAttempts > 0 && attempt >= p.MaxAttempts {
			return err
		}
		if clock.Now().Add(pause).Sub(start) > timeout {
			return err
		}
		if serr := clock.Sleep(ctx, pause); serr != nil {
			return err
		}
		pause = time.Duration(float64(pause) * mult)
		if pause > max {
			pause = max
		}
	}
}

// IgnoreCodes returns nil when err carries one of codes and err otherwise:
// for calls whose "already done" answer is an error (Alibaba Cloud
// ReleaseEipAddress on a released EIP answers InvalidAllocationId.NotFound).
func IgnoreCodes(err error, codes ...string) error {
	if HasErrorCode(err, codes...) {
		return nil
	}
	return err
}

// ClientToken derives an idempotency token from the content of a request:
// the same request always gets the same token, so a retried create returns
// the resource the first attempt made instead of a second one, and a
// different request never reuses it. The token is 64 hexadecimal
// characters (the Alibaba Cloud limit is 64 ASCII characters).
func ClientToken(parts ...any) string {
	b, err := json.Marshal(parts)
	if err != nil {
		b = []byte(fmt.Sprint(parts...))
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
