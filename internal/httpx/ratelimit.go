package httpx

import (
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Rate-limited APIs (Cloudflare about 1200 requests per 5 minutes, GoDaddy
// about 60 per minute, name.com per second and per hour) answer HTTP 429,
// usually with a header saying when to come back. The short backoff of
// Client.Do (about 7 s in all) is far shorter than such a window, so Do
// waits for the announced delay instead. The wait happens between requests,
// outside the http.Client timeout, which would otherwise cut it short.
const (
	// RateLimitMaxWait caps a single wait on a 429 so a bogus header cannot
	// stall the process indefinitely.
	RateLimitMaxWait = 2 * time.Minute
	// rateLimitRetries is how many announced waits are honoured per call.
	rateLimitRetries = 3
)

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
