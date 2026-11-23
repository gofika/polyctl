// Package loopback receives the redirect of an OAuth authorization-code
// flow on a listener bound to 127.0.0.1. It is the part every browser login
// of polyctl shares: the listener, the one-shot callback handler, the state
// check and the bounded wait. Building the authorization URL and exchanging
// the code stay with the provider.
package loopback

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"time"
)

// Errors of Wait. A cancelled context is returned as the context's own
// error.
var (
	// ErrTimeout: nothing arrived on the callback path in time.
	ErrTimeout = errors.New("no authorization received in time")
	// ErrState: the callback carried another state than the one sent, so it
	// does not answer this login (a stale browser tab, or a forged request).
	ErrState = errors.New("the authorization response does not belong to this login (state mismatch)")
	// ErrNoCode: the callback carried neither a code nor an error.
	ErrNoCode = errors.New("the authorization response carries no code")
)

// DeniedError is an error redirect of the authorization server
// (error=access_denied and the like).
type DeniedError struct {
	// Code is the OAuth error code, reduced to printable ASCII.
	Code string
	// Description is the optional error_description, reduced the same way.
	Description string
}

func (e *DeniedError) Error() string {
	msg := "the authorization was not granted: " + e.Code
	if e.Code == "access_denied" {
		msg = "the authorization was denied in the browser"
	}
	if e.Description != "" {
		msg += " (" + e.Description + ")"
	}
	return msg
}

// The pages shown in the browser are fixed texts: nothing of the request is
// written back, and they load nothing.
const (
	pageOK     = `<!doctype html><html><head><meta charset="utf-8"><title>polyctl</title></head><body><h2>Login complete</h2><p>You can close this window and return to the terminal.</p></body></html>`
	pageFailed = `<!doctype html><html><head><meta charset="utf-8"><title>polyctl</title></head><body><h2>Login failed</h2><p>Return to the terminal for the details.</p></body></html>`
)

type result struct {
	code string
	err  error
}

// Server is a listener waiting for one authorization response.
type Server struct {
	// State is the random value to send as the state parameter of the
	// authorization request.
	State string

	ln      net.Listener
	path    string
	srv     *http.Server
	results chan result
	served  atomic.Bool
	closed  atomic.Bool
}

// Listen binds a random port on 127.0.0.1 (never another interface) and
// starts serving the callback at path, which must match exactly.
func Listen(path string) (*Server, error) {
	state, err := RandomToken()
	if err != nil {
		return nil, err
	}
	ln, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return nil, fmt.Errorf("start loopback listener: %w", err)
	}
	s := &Server{State: state, ln: ln, path: path, results: make(chan result, 1)}
	s.srv = &http.Server{Handler: http.HandlerFunc(s.handle), ReadHeaderTimeout: 10 * time.Second}
	go s.srv.Serve(ln) //nolint:errcheck
	return s, nil
}

// RedirectURL is the redirect URI of this listener:
// http://127.0.0.1:<port><path>.
func (s *Server) RedirectURL() string {
	return "http://" + s.ln.Addr().String() + s.path
}

func (s *Server) handle(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != s.path {
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	// Exactly one response is taken: a second request (a reloaded tab, or
	// anything else on this machine) finds nothing to answer.
	if !s.served.CompareAndSwap(false, true) {
		http.Error(w, "this login was already answered", http.StatusGone)
		return
	}
	q := r.URL.Query()
	var res result
	switch {
	case subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(s.State)) != 1:
		res.err = ErrState
	case q.Get("error") != "":
		res.err = &DeniedError{Code: clean(q.Get("error"), 64), Description: clean(q.Get("error_description"), 200)}
	case q.Get("code") == "":
		res.err = ErrNoCode
	default:
		res.code = q.Get("code")
	}
	h := w.Header()
	h.Set("Content-Type", "text/html; charset=utf-8")
	h.Set("Cache-Control", "no-store")
	h.Set("Content-Security-Policy", "default-src 'none'")
	h.Set("Referrer-Policy", "no-referrer")
	h.Set("X-Content-Type-Options", "nosniff")
	if res.err != nil {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, pageFailed)
	} else {
		_, _ = io.WriteString(w, pageOK)
	}
	s.results <- res
}

// clean reduces a value taken from the redirect to printable ASCII of a
// bounded length, so that it can be shown on a terminal.
func clean(v string, max int) string {
	var b strings.Builder
	for _, r := range v {
		if b.Len() >= max {
			break
		}
		if r >= 0x20 && r < 0x7f {
			b.WriteRune(r)
		}
	}
	return strings.TrimSpace(b.String())
}

// Wait returns the authorization code of the one response the listener
// takes. It ends with ErrTimeout after timeout (0 waits without a limit),
// with the context's error when ctx is done, and with ErrState, ErrNoCode
// or a *DeniedError when the response is not a grant.
func (s *Server) Wait(ctx context.Context, timeout time.Duration) (string, error) {
	var expired <-chan time.Time
	if timeout > 0 {
		timer := time.NewTimer(timeout)
		defer timer.Stop()
		expired = timer.C
	}
	select {
	case res := <-s.results:
		return res.code, res.err
	case <-expired:
		return "", ErrTimeout
	case <-ctx.Done():
		return "", ctx.Err()
	}
}

// Close stops the listener. It lets a response in flight finish, so the
// browser still gets its page.
func (s *Server) Close() {
	if !s.closed.CompareAndSwap(false, true) {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := s.srv.Shutdown(ctx); err != nil {
		_ = s.srv.Close()
	}
}

// RandomToken returns 32 random bytes in unpadded URL-safe base64 (43
// characters): a state value, or a PKCE code verifier (RFC 7636 section 4.1).
func RandomToken() (string, error) {
	b := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}
