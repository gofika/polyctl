package loopback

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"
)

func listen(t *testing.T) *Server {
	t.Helper()
	s, err := Listen("/oauth/callback")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(s.Close)
	return s
}

// get requests a URL of the listener and returns the status and the page.
func get(t *testing.T, u string) (int, string) {
	t.Helper()
	resp, err := http.Get(u)
	if err != nil {
		t.Fatalf("GET %s: %v", u, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(body)
}

func callback(s *Server, q url.Values) string { return s.RedirectURL() + "?" + q.Encode() }

func TestRedirectURLIsLoopback(t *testing.T) {
	s := listen(t)
	u, err := url.Parse(s.RedirectURL())
	if err != nil {
		t.Fatal(err)
	}
	if u.Scheme != "http" || u.Hostname() != "127.0.0.1" || u.Port() == "" || u.Port() == "0" || u.Path != "/oauth/callback" {
		t.Fatalf("redirect URL = %s", s.RedirectURL())
	}
	if len(s.State) < 32 {
		t.Fatalf("state %q is too short", s.State)
	}
	other := listen(t)
	if other.State == s.State {
		t.Fatal("two listeners share a state")
	}
}

func TestWaitReturnsCode(t *testing.T) {
	s := listen(t)
	status, page := get(t, callback(s, url.Values{"state": {s.State}, "code": {"the-code"}}))
	if status != http.StatusOK || !strings.Contains(page, "return to the terminal") {
		t.Fatalf("page: %d %q", status, page)
	}
	if strings.Contains(page, "the-code") || strings.Contains(page, s.State) {
		t.Fatalf("the page reflects the request: %q", page)
	}
	if strings.Contains(page, "http://") || strings.Contains(page, "https://") || strings.Contains(page, "<script") {
		t.Fatalf("the page loads something: %q", page)
	}
	code, err := s.Wait(context.Background(), time.Second)
	if err != nil || code != "the-code" {
		t.Fatalf("Wait = %q, %v", code, err)
	}
}

func TestStateMismatch(t *testing.T) {
	s := listen(t)
	status, page := get(t, callback(s, url.Values{"state": {"<b>forged</b>"}, "code": {"stolen"}}))
	if status != http.StatusBadRequest || strings.Contains(page, "forged") || strings.Contains(page, "stolen") {
		t.Fatalf("page: %d %q", status, page)
	}
	if _, err := s.Wait(context.Background(), time.Second); !errors.Is(err, ErrState) {
		t.Fatalf("Wait = %v, want ErrState", err)
	}
}

func TestErrorRedirect(t *testing.T) {
	s := listen(t)
	_, page := get(t, callback(s, url.Values{"state": {s.State}, "error": {"access_denied"}, "error_description": {"<script>x</script>\x1b[31m"}}))
	if strings.Contains(page, "script>x") || strings.Contains(page, "access_denied") {
		t.Fatalf("the page reflects the error: %q", page)
	}
	_, err := s.Wait(context.Background(), time.Second)
	var denied *DeniedError
	if !errors.As(err, &denied) || denied.Code != "access_denied" {
		t.Fatalf("Wait = %v, want a DeniedError", err)
	}
	if strings.ContainsRune(err.Error(), 0x1b) || !strings.Contains(err.Error(), "denied in the browser") {
		t.Fatalf("message: %q", err.Error())
	}
}

func TestCallbackWithoutCode(t *testing.T) {
	s := listen(t)
	get(t, callback(s, url.Values{"state": {s.State}}))
	if _, err := s.Wait(context.Background(), time.Second); !errors.Is(err, ErrNoCode) {
		t.Fatalf("Wait = %v, want ErrNoCode", err)
	}
}

// Requests on other paths are not the answer: they get a 404 and the
// listener keeps waiting for the real one.
func TestWrongPathIsIgnored(t *testing.T) {
	s := listen(t)
	base := strings.TrimSuffix(s.RedirectURL(), "/oauth/callback")
	q := url.Values{"state": {s.State}, "code": {"elsewhere"}}.Encode()
	for _, path := range []string{"/", "/callback", "/oauth/callback/", "/oauth/callback/x", "/favicon.ico"} {
		if status, _ := get(t, base+path+"?"+q); status != http.StatusNotFound {
			t.Errorf("GET %s = %d, want 404", path, status)
		}
	}
	resp, err := http.Post(callback(s, url.Values{"state": {s.State}, "code": {"posted"}}), "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("POST = %d, want 405", resp.StatusCode)
	}
	if _, err := s.Wait(context.Background(), 50*time.Millisecond); !errors.Is(err, ErrTimeout) {
		t.Fatalf("Wait = %v, want ErrTimeout: nothing arrived on the callback path", err)
	}
	get(t, callback(s, url.Values{"state": {s.State}, "code": {"real"}}))
	if code, err := s.Wait(context.Background(), time.Second); err != nil || code != "real" {
		t.Fatalf("Wait = %q, %v", code, err)
	}
}

// Exactly one request is taken as the answer.
func TestSecondRequestIsRefused(t *testing.T) {
	s := listen(t)
	get(t, callback(s, url.Values{"state": {s.State}, "code": {"first"}}))
	if status, page := get(t, callback(s, url.Values{"state": {s.State}, "code": {"second"}})); status != http.StatusGone || strings.Contains(page, "second") {
		t.Fatalf("second request: %d %q", status, page)
	}
	if code, err := s.Wait(context.Background(), time.Second); err != nil || code != "first" {
		t.Fatalf("Wait = %q, %v", code, err)
	}
}

func TestWaitCancelled(t *testing.T) {
	s := listen(t)
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(20*time.Millisecond, cancel)
	start := time.Now()
	if _, err := s.Wait(ctx, time.Minute); !errors.Is(err, context.Canceled) {
		t.Fatalf("Wait = %v, want context.Canceled", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("Wait did not end with the context")
	}
}

func TestCloseStopsListening(t *testing.T) {
	s := listen(t)
	u := callback(s, url.Values{"state": {s.State}, "code": {"late"}})
	s.Close()
	s.Close() // twice is fine
	if resp, err := http.Get(u); err == nil {
		resp.Body.Close()
		t.Fatal("the listener still answers after Close")
	}
}
