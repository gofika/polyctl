package namecom

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// A 429 with Retry-After is waited out, not given up on after the short
// generic backoff.
func TestClientHonoursRetryAfter(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	c := newClient(srv.URL, envTest, testUser, testToken)
	c.api.MaxRetries = 0 // the retry must come from the Retry-After wait
	if err := c.api.Do(context.Background(), http.MethodDelete, "/x", nil, nil, nil); err != nil || hits.Load() != 2 {
		t.Errorf("Do = %v after %d attempts, want success after 2", err, hits.Load())
	}
}
