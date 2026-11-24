package httpx

import (
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Rate-limited APIs (Cloudflare about 1200 requests per 5 minutes, GoDaddy
// about 60 per minute, name.com per second and per hour) answer HTTP 429,
// usually with a header saying when to come back. The short backoff of
// Client.Do (about 7 s in all) is far shorter than such a window, so every
// Client's transport waits for the announced delay instead.
const (
	// RateLimitMaxWait caps a single wait on a 429 so a bogus header cannot
	// stall the process indefinitely.
	RateLimitMaxWait = 2 * time.Minute
	// rateLimitRetries is how many announced waits are honoured per request.
	rateLimitRetries = 3
)

// RateLimitTransport retries 429 responses after the server-announced
// delay (Retry-After, RateLimit-Reset or X-RateLimit-Reset). A 429 without
// a usable hint is returned as it is, for the caller's generic backoff.
type RateLimitTransport struct {
	Base    http.RoundTripper
	MaxWait time.Duration
	Retries int
	now     func() time.Time
}

// NewRateLimitTransport wraps base (nil means http.DefaultTransport).
func NewRateLimitTransport(base http.RoundTripper) *RateLimitTransport {
	if base == nil {
		base = http.DefaultTransport
	}
	return &RateLimitTransport{Base: base, MaxWait: RateLimitMaxWait, Retries: rateLimitRetries, now: time.Now}
}

// RoundTrip implements http.RoundTripper.
func (t *RateLimitTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	now := t.now
	if now == nil {
		now = time.Now
	}
	for attempt := 0; ; attempt++ {
		resp, err := t.Base.RoundTrip(req)
		if err != nil || resp.StatusCode != http.StatusTooManyRequests || attempt >= t.Retries {
			return resp, err
		}
		wait := RetryDelay(resp.Header, now())
		if wait <= 0 {
			// No usable hint: leave it to the caller's generic backoff.
			return resp, nil
		}
		if t.MaxWait > 0 && wait > t.MaxWait {
			wait = t.MaxWait
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

// RetryDelay reads the delay a 429 response asks for. RateLimit-Reset
// (GoDaddy) and X-RateLimit-Reset are seconds; Retry-After (Cloudflare,
// name.com) is seconds or an HTTP date. 0 means no hint. A zero value in
// the header is rounded up to one second so a retry does not hit the same
// window.
func RetryDelay(h http.Header, now time.Time) time.Duration {
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
