package godaddy

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// GoDaddy allows about 60 requests per minute per credential and answers
// HTTP 429 with a RateLimit-Reset header (seconds until the window opens
// again) and no body. The generic httpx retry loop uses a short fixed
// backoff that ignores the header, so the GoDaddy client wraps its
// transport to wait for the announced delay instead.
const (
	// syncPace is the delay between per-domain record listings in Sync
	// (50 requests per minute, below GoDaddy's 60/minute limit).
	syncPace = 1200 * time.Millisecond
	// rateLimitMaxWait caps a single wait on a 429 so a bogus header cannot
	// stall the process indefinitely.
	rateLimitMaxWait = 2 * time.Minute
	// rateLimitRetries is how many announced waits are honoured per request.
	rateLimitRetries = 3
)

// rateLimitTransport retries 429 responses after the server-announced delay.
type rateLimitTransport struct {
	base    http.RoundTripper
	maxWait time.Duration
	retries int
	now     func() time.Time
}

func newRateLimitTransport(base http.RoundTripper) *rateLimitTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &rateLimitTransport{base: base, maxWait: rateLimitMaxWait, retries: rateLimitRetries, now: time.Now}
}

// RoundTrip implements http.RoundTripper.
func (t *rateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for attempt := 0; ; attempt++ {
		resp, err := t.base.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || attempt >= t.retries {
			return resp, err
		}
		wait := retryDelay(resp.Header, t.now())
		if wait <= 0 {
			// No usable hint: leave it to the caller's generic backoff.
			return resp, nil
		}
		if wait > t.maxWait {
			wait = t.maxWait
		}
		// A body may only be replayed through GetBody (set by
		// http.NewRequest for in-memory bodies).
		if req.Body != nil && req.Body != http.NoBody && req.GetBody == nil {
			return resp, nil
		}
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
		resp.Body.Close()
		ctx := req.Context()
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
		next := req.Clone(ctx)
		if req.GetBody != nil {
			body, err := req.GetBody()
			if err != nil {
				return nil, err
			}
			next.Body = body
		}
		req = next
	}
}

// retryDelay reads the delay a 429 response asks for. RateLimit-Reset
// (GoDaddy) and X-RateLimit-Reset are seconds; Retry-After is seconds or
// an HTTP date. 0 means no hint. A zero value in the header is rounded up
// to one second so a retry does not hit the same window.
func retryDelay(h http.Header, now time.Time) time.Duration {
	for _, name := range []string{"Retry-After", "RateLimit-Reset", "X-RateLimit-Reset"} {
		v := strings.TrimSpace(h.Get(name))
		if v == "" {
			continue
		}
		if secs, err := strconv.ParseFloat(v, 64); err == nil {
			if secs < 0 {
				continue
			}
			if secs < 1 {
				secs = 1
			}
			return time.Duration(secs * float64(time.Second))
		}
		if at, err := http.ParseTime(v); err == nil {
			d := at.Sub(now)
			if d < time.Second {
				d = time.Second
			}
			return d
		}
	}
	return 0
}
