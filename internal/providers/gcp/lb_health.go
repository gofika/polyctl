package gcp

import (
	"context"
	"errors"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// lbHealthInterval is the pause between two reads of the backend health;
// tests replace instanceClock, so nothing really sleeps.
var lbHealthInterval = 10 * time.Second

// healthSummary renders the health states of the instances behind a
// backend ("HEALTHY", "UNHEALTHY", "HEALTHY x1, UNHEALTHY x1"); an empty
// list, what a backend that just joined reports, is "no status yet".
func healthSummary(states []string) string {
	if len(states) == 0 {
		return "no status yet"
	}
	count := map[string]int{}
	for _, s := range states {
		if s == "" {
			s = "UNKNOWN"
		}
		count[s]++
	}
	if len(count) == 1 {
		for s := range count {
			return s
		}
	}
	keys := make([]string, 0, len(count))
	for s := range count {
		keys = append(keys, s)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, s := range keys {
		parts = append(parts, s+" x"+strconv.Itoa(count[s]))
	}
	return strings.Join(parts, ", ")
}

// waitBackendHealthy reads the health of group behind the backend service
// bs every interval until one instance is HEALTHY or timeout passes.
// Anything else, the empty list included (a backend that just joined
// answers with no status for about two minutes before it turns HEALTHY),
// keeps the wait going. It returns whether a HEALTHY instance was seen
// and the last state read. A permission error ends the wait with that
// error; other read errors are retried until the timeout.
func (s certScope) waitBackendHealthy(ctx context.Context, bs, group string, timeout, interval time.Duration, clock platform.Clock) (bool, string, error) {
	last := ""
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "backend-service/" + bs, Want: "HEALTHY", Timeout: timeout, Interval: interval, Clock: clock},
		func(ctx context.Context) (platform.WaitState, string, error) {
			list, err := s.backendHealth(ctx, bs, group)
			if err != nil {
				if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrNotFound) {
					return platform.KeepWaiting, "", err
				}
				if ctx.Err() != nil {
					return platform.KeepWaiting, "", ctx.Err()
				}
				last = "read failed: " + err.Error()
				return platform.KeepWaiting, last, nil
			}
			var states []string
			for _, h := range list {
				states = append(states, h.HealthState)
				if h.HealthState == "HEALTHY" {
					last = "HEALTHY"
					return platform.WaitDone, last, nil
				}
			}
			last = healthSummary(states)
			return platform.KeepWaiting, last, nil
		})
	var te *platform.WaitTimeoutError
	switch {
	case err == nil:
		return true, last, nil
	case errors.As(err, &te):
		return false, last, nil
	}
	return false, last, err
}
