package httpx

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func newClient(srv *httptest.Server) *Client {
	c := New(srv.URL, nil)
	c.MaxRetries = 2
	return c
}

func TestRetryOnlyIdempotentMethodsAfter5xx(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusBadGateway)
	}))
	defer srv.Close()
	c := newClient(srv)

	for _, tc := range []struct {
		method string
		want   int32
	}{
		{http.MethodGet, 3},
		{http.MethodPut, 3},
		{http.MethodDelete, 3},
		{http.MethodPost, 1},
		{http.MethodPatch, 1},
	} {
		hits.Store(0)
		err := c.Do(context.Background(), tc.method, "/x", nil, map[string]string{"a": "b"}, nil)
		var he *Error
		if !errors.As(err, &he) || he.Status != http.StatusBadGateway {
			t.Fatalf("%s: err = %v", tc.method, err)
		}
		if got := hits.Load(); got != tc.want {
			t.Errorf("%s: %d attempts, want %d", tc.method, got, tc.want)
		}
	}
}

func TestRetry429ForEveryMethod(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		w.Write([]byte(`{"ok":true}`))
	}))
	defer srv.Close()
	c := newClient(srv)
	var out struct {
		OK bool `json:"ok"`
	}
	if err := c.Do(context.Background(), http.MethodPost, "/x", nil, map[string]string{}, &out); err != nil || !out.OK {
		t.Fatalf("POST after 429: %v %+v", err, out)
	}
	if hits.Load() != 2 {
		t.Errorf("attempts = %d, want 2", hits.Load())
	}
}

func TestRedirectsAreNotFollowed(t *testing.T) {
	var followed atomic.Bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/target" {
			followed.Store(true)
			w.Write([]byte(`{}`))
			return
		}
		http.Redirect(w, r, "/target", http.StatusFound)
	}))
	defer srv.Close()
	c := newClient(srv)
	err := c.Do(context.Background(), http.MethodPost, "/x", nil, map[string]string{}, nil)
	var he *Error
	if !errors.As(err, &he) || he.Status != http.StatusFound {
		t.Fatalf("err = %v, want HTTP 302 error", err)
	}
	if followed.Load() {
		t.Error("redirect was followed")
	}
}
