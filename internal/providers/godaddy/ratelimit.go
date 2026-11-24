package godaddy

import "time"

// GoDaddy allows about 60 requests per minute per credential and answers
// HTTP 429 with a RateLimit-Reset header (seconds until the window opens
// again) and no body. The httpx transport waits for that delay; Sync also
// paces its per-domain requests to stay below the limit.
const (
	// syncPace is the delay between per-domain record listings in Sync
	// (50 requests per minute, below GoDaddy's 60/minute limit).
	syncPace = 1200 * time.Millisecond
)
