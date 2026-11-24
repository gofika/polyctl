package cloudflare

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// Cloudflare refuses requests for the rest of its 5-minute window once the
// account limit is hit; the client must wait for Retry-After instead of
// giving up after its short generic backoff.
func TestAPIHonoursRetryAfter(t *testing.T) {
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
	a := newAPI(srv.URL, "tok", "acc")
	a.http.MaxRetries = 0 // the retry must come from the Retry-After wait
	if err := a.http.Do(context.Background(), http.MethodDelete, "/x", nil, nil, nil); err != nil || hits.Load() != 2 {
		t.Errorf("Do = %v after %d attempts, want success after 2", err, hits.Load())
	}
}
