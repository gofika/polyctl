package httpx

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestRetryDelay(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	h := http.Header{}
	if d := RetryDelay(h, now); d != 0 {
		t.Errorf("no header: %s", d)
	}
	h.Set("RateLimit-Reset", "7")
	if d := RetryDelay(h, now); d != 7*time.Second {
		t.Errorf("RateLimit-Reset: %s", d)
	}
	h.Set("RateLimit-Reset", "0")
	if d := RetryDelay(h, now); d != time.Second {
		t.Errorf("zero rounds up: %s", d)
	}
	h = http.Header{}
	h.Set("Retry-After", now.Add(90*time.Second).UTC().Format(http.TimeFormat))
	if d := RetryDelay(h, now); d != 90*time.Second {
		t.Errorf("Retry-After date: %s", d)
	}
	h.Set("Retry-After", "garbage")
	h.Set("RateLimit-Reset", "3")
	if d := RetryDelay(h, now); d != 3*time.Second {
		t.Errorf("fallback to RateLimit-Reset: %s", d)
	}
}

// Every Client (Cloudflare, name.com, GoDaddy) waits for the Retry-After of
// a 429 instead of giving up after its short generic backoff.
func TestClientHonoursRetryAfter(t *testing.T) {
	var hits atomic.Int32
	var long atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if long.Load() {
			w.Header().Set("Retry-After", "60")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	c.MaxRetries = 0 // the retry must come from the transport
	var out struct {
		OK bool `json:"ok"`
	}
	start := time.Now()
	if err := c.Do(context.Background(), http.MethodPost, "/x", nil, map[string]string{"a": "b"}, &out); err != nil || !out.OK {
		t.Fatalf("Do = %v, %+v", err, out)
	}
	if hits.Load() != 2 {
		t.Errorf("%d attempts, want 2", hits.Load())
	}
	if el := time.Since(start); el < 900*time.Millisecond {
		t.Errorf("did not wait for Retry-After (took %s)", el)
	}

	// A cancelled context ends the wait.
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	long.Store(true)
	start = time.Now()
	if err := c.Do(ctx, http.MethodGet, "/x", nil, nil, nil); err == nil || time.Since(start) > 5*time.Second {
		t.Errorf("cancelled wait = %v after %s", err, time.Since(start))
	}
}

// The wait for Retry-After is not part of one request: the client's
// per-request timeout must not cut a wait that is longer than it.
func TestRetryAfterWaitOutlastsRequestTimeout(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.Header().Set("Retry-After", "1")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	c.HTTP.Timeout = 300 * time.Millisecond
	c.MaxRetries = 0
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.Do(context.Background(), http.MethodDelete, "/x", nil, nil, &out); err != nil || !out.OK {
		t.Fatalf("Do = %v, %+v; want success after waiting out Retry-After", err, out)
	}
	if hits.Load() != 2 {
		t.Errorf("%d attempts, want 2", hits.Load())
	}
}

// Announced waits are capped per call, so a server that keeps answering
// 429 does not hold the command forever.
func TestRetryAfterWaitsAreCapped(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "0")
		w.WriteHeader(http.StatusTooManyRequests)
	}))
	defer srv.Close()
	c := New(srv.URL, nil)
	c.MaxRetries = 0
	if err := c.Do(context.Background(), http.MethodGet, "/x", nil, nil, nil); err == nil {
		t.Fatal("Do succeeded against a server that only answers 429")
	}
	if got := hits.Load(); got != 1+rateLimitRetries {
		t.Errorf("%d attempts, want %d", got, 1+rateLimitRetries)
	}
}
