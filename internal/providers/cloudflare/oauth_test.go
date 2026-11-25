package cloudflare

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

func containsString(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

// fakeAS is Cloudflare's authorization server as far as polyctl uses it:
// the consent step (approve, standing in for the page in the browser), the
// token endpoint with PKCE, revocation and userinfo.
type fakeAS struct {
	t   *testing.T
	srv *httptest.Server
	mu  sync.Mutex

	// granted is what the person approves; nil approves everything asked.
	granted []string
	// omitScope and omitExpiry leave the fields out of token responses.
	omitScope, omitExpiry bool
	expiresIn             int
	// rotate makes every refresh return a new refresh token and spend the
	// old one.
	rotate bool
	// failExchange and failRefresh are OAuth error codes to answer with.
	failExchange, failRefresh string
	// refreshStatus overrides the status of a failed refresh (default 400).
	refreshStatus int
	refreshDelay  time.Duration
	revokeStatus  int
	// userinfoEmail is reported by the userinfo endpoint; empty answers 403.
	userinfoEmail string

	n          int
	codes      map[string]pendingCode
	access     map[string][]string // access token -> scopes
	refresh    map[string][]string // refresh token -> scopes
	exchanges  int
	refreshes  int
	revoked    []string
	userinfos  int
	authQuery  url.Values
	lastVerify string
}

type pendingCode struct {
	challenge, redirect string
	scopes              []string
}

func newFakeAS(t *testing.T) *fakeAS {
	as := &fakeAS{t: t, expiresIn: 3600, codes: map[string]pendingCode{}, access: map[string][]string{}, refresh: map[string][]string{}, userinfoEmail: "ops@example.com"}
	as.srv = httptest.NewServer(as)
	t.Cleanup(as.srv.Close)
	old := oauthEP
	oauthEP = oauthEndpoints{Auth: as.srv.URL + "/oauth2/auth", Token: as.srv.URL + "/oauth2/token", Revoke: as.srv.URL + "/oauth2/revoke", Userinfo: as.srv.URL + "/oauth2/userinfo"}
	t.Cleanup(func() { oauthEP = old })
	return as
}

func (as *fakeAS) accessScopes(token string) ([]string, bool) {
	as.mu.Lock()
	defer as.mu.Unlock()
	s, ok := as.access[token]
	return s, ok
}

func (as *fakeAS) expire(access string) {
	as.mu.Lock()
	defer as.mu.Unlock()
	delete(as.access, access)
}

func (as *fakeAS) counts() (exchanges, refreshes int) {
	as.mu.Lock()
	defer as.mu.Unlock()
	return as.exchanges, as.refreshes
}

// approve is the consent page: it checks the authorization request and
// returns the redirect back to polyctl, carrying a code.
func (as *fakeAS) approve(authURL string) (*url.URL, error) {
	as.mu.Lock()
	defer as.mu.Unlock()
	u, err := url.Parse(authURL)
	if err != nil {
		return nil, err
	}
	if got := u.Scheme + "://" + u.Host + u.Path; got != as.srv.URL+"/oauth2/auth" {
		return nil, fmt.Errorf("authorization endpoint = %s", got)
	}
	q := u.Query()
	as.authQuery = q
	switch {
	case q.Get("response_type") != "code":
		return nil, fmt.Errorf("response_type = %q", q.Get("response_type"))
	case q.Get("client_id") != oauthClientID:
		return nil, fmt.Errorf("client_id = %q", q.Get("client_id"))
	case q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43:
		return nil, fmt.Errorf("PKCE: method %q, challenge %q", q.Get("code_challenge_method"), q.Get("code_challenge"))
	case len(q.Get("state")) < 32:
		return nil, fmt.Errorf("state = %q", q.Get("state"))
	case q.Get("client_secret") != "":
		return nil, errors.New("a client secret was sent")
	}
	red, err := url.Parse(q.Get("redirect_uri"))
	if err != nil {
		return nil, err
	}
	// What Cloudflare has registered: the loopback address with any port,
	// and exactly this path.
	if red.Scheme != "http" || red.Hostname() != "127.0.0.1" || red.Port() == "" || red.Path != "/oauth/callback" || red.RawQuery != "" {
		return nil, fmt.Errorf("redirect_uri = %s", red)
	}
	scopes := as.granted
	if scopes == nil {
		scopes = strings.Fields(q.Get("scope"))
	}
	as.n++
	code := fmt.Sprintf("code-%d-secret", as.n)
	as.codes[code] = pendingCode{challenge: q.Get("code_challenge"), redirect: q.Get("redirect_uri"), scopes: scopes}
	red.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
	return red, nil
}

func (as *fakeAS) issue(scopes []string, withRefresh bool) map[string]any {
	as.n++
	access := fmt.Sprintf("at-%d-secret", as.n)
	as.access[access] = scopes
	out := map[string]any{"access_token": access, "token_type": "bearer"}
	if !as.omitExpiry {
		out["expires_in"] = as.expiresIn
	}
	if !as.omitScope {
		out["scope"] = strings.Join(scopes, " ")
	}
	if withRefresh {
		refresh := fmt.Sprintf("rt-%d-secret", as.n)
		as.refresh[refresh] = scopes
		out["refresh_token"] = refresh
	}
	return out
}

func (as *fakeAS) oauthErr(w http.ResponseWriter, status int, code string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{"error": code, "error_description": "the request was refused"})
}

func (as *fakeAS) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/oauth2/userinfo":
		as.mu.Lock()
		as.userinfos++
		email := as.userinfoEmail
		_, ok := as.access[strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")]
		as.mu.Unlock()
		if !ok || email == "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"sub": "user-1", "email": email})
		return
	case "/oauth2/token", "/oauth2/revoke":
	default:
		http.NotFound(w, r)
		return
	}
	if r.Method != http.MethodPost || !strings.HasPrefix(r.Header.Get("Content-Type"), "application/x-www-form-urlencoded") {
		as.t.Errorf("%s: %s with content type %q", r.URL.Path, r.Method, r.Header.Get("Content-Type"))
	}
	if r.Header.Get("Authorization") != "" {
		as.t.Errorf("%s: the public client sent an Authorization header", r.URL.Path)
	}
	if err := r.ParseForm(); err != nil {
		as.t.Errorf("%s: %v", r.URL.Path, err)
	}
	f := r.PostForm
	if f.Get("client_id") != oauthClientID || f.Get("client_secret") != "" {
		as.t.Errorf("%s: client_id %q, client_secret %q", r.URL.Path, f.Get("client_id"), f.Get("client_secret"))
	}
	if r.URL.Path == "/oauth2/revoke" {
		as.mu.Lock()
		defer as.mu.Unlock()
		if as.revokeStatus != 0 {
			as.oauthErr(w, as.revokeStatus, "server_error")
			return
		}
		tok := f.Get("token")
		as.revoked = append(as.revoked, f.Get("token_type_hint")+":"+tok)
		delete(as.access, tok)
		delete(as.refresh, tok)
		w.WriteHeader(http.StatusOK)
		return
	}
	switch f.Get("grant_type") {
	case "authorization_code":
		as.mu.Lock()
		defer as.mu.Unlock()
		as.exchanges++
		if as.failExchange != "" {
			as.oauthErr(w, 400, as.failExchange)
			return
		}
		pc, ok := as.codes[f.Get("code")]
		delete(as.codes, f.Get("code")) // single use
		as.lastVerify = f.Get("code_verifier")
		if !ok || pkceChallenge(f.Get("code_verifier")) != pc.challenge || f.Get("redirect_uri") != pc.redirect {
			as.oauthErr(w, 400, "invalid_grant")
			return
		}
		_ = json.NewEncoder(w).Encode(as.issue(pc.scopes, true))
	case "refresh_token":
		if as.refreshDelay > 0 {
			time.Sleep(as.refreshDelay)
		}
		as.mu.Lock()
		defer as.mu.Unlock()
		as.refreshes++
		if as.failRefresh != "" {
			status := as.refreshStatus
			if status == 0 {
				status = 400
			}
			as.oauthErr(w, status, as.failRefresh)
			return
		}
		scopes, ok := as.refresh[f.Get("refresh_token")]
		if !ok {
			as.oauthErr(w, 400, "invalid_grant")
			return
		}
		if as.rotate {
			delete(as.refresh, f.Get("refresh_token"))
		}
		_ = json.NewEncoder(w).Encode(as.issue(scopes, as.rotate))
	default:
		as.oauthErr(w, 400, "unsupported_grant_type")
	}
}

// oauthEnv is a fake API whose tokens come from a fake authorization
// server, and a provider talking to both.
type oauthEnv struct {
	as  *fakeAS
	cf  *fakeCF
	srv *httptest.Server
	p   *provider
}

func newOAuthEnv(t *testing.T) *oauthEnv {
	t.Helper()
	t.Setenv(tokenEnv, "")
	as := newFakeAS(t)
	cf, srv := newFake(t)
	cf.oauth = as
	// One account, as an authorization usually covers.
	cf.accounts = cf.accounts[:1]
	cf.zones = cf.zones[:1]
	return &oauthEnv{as: as, cf: cf, srv: srv, p: &provider{baseURL: srv.URL}}
}

// browser returns an OpenBrowser hook that plays the person: it approves on
// the consent page and follows the redirect back to polyctl. edit may
// change the redirect first.
func (e *oauthEnv) browser(t *testing.T, edit func(red *url.URL)) func(string) error {
	return func(authURL string) error {
		red, err := e.as.approve(authURL)
		if err != nil {
			t.Errorf("authorization request: %v", err)
			return nil
		}
		if edit != nil {
			edit(red)
		}
		resp, err := http.Get(red.String())
		if err != nil {
			t.Errorf("redirect to polyctl: %v", err)
			return nil
		}
		io.Copy(io.Discard, resp.Body) //nolint:errcheck
		resp.Body.Close()
		return nil
	}
}

func (e *oauthEnv) login(t *testing.T, ctx context.Context, opts map[string]string, existing map[string]string, open func(string) error) (*platform.LoginResult, string, error) {
	t.Helper()
	var stderr bytes.Buffer
	if opts == nil {
		opts = map[string]string{"method": "oauth"}
	}
	res, err := e.p.Login(ctx, platform.LoginInput{
		ProfileName: "work", Interactive: true, Options: opts, Existing: existing,
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: &stderr,
		OpenBrowser: open,
	})
	return res, stderr.String(), err
}

// secrets lists every value of a login that must never be shown.
func (e *oauthEnv) secrets() []string {
	e.as.mu.Lock()
	defer e.as.mu.Unlock()
	out := []string{e.as.lastVerify}
	for k := range e.as.access {
		out = append(out, k)
	}
	for k := range e.as.refresh {
		out = append(out, k)
	}
	for i := 1; i <= e.as.n; i++ {
		out = append(out, fmt.Sprintf("code-%d-secret", i), fmt.Sprintf("at-%d-secret", i), fmt.Sprintf("rt-%d-secret", i))
	}
	return out
}

func assertNoSecrets(t *testing.T, what, text string, secrets []string) {
	t.Helper()
	for _, s := range secrets {
		if s != "" && strings.Contains(text, s) {
			t.Errorf("%s shows the secret %q:\n%s", what, s, text)
		}
	}
}

// The whole flow, with the browser played by the OpenBrowser hook.
func TestOAuthLogin(t *testing.T) {
	e := newOAuthEnv(t)
	res, stderr, err := e.login(t, context.Background(), nil, nil, e.browser(t, nil))
	if err != nil {
		t.Fatalf("login: %v\n%s", err, stderr)
	}
	wantScopes := append(append([]string{}, OAuthRequiredScopes...), OAuthOptionalScopes...)
	if got := strings.Fields(e.as.authQuery.Get("scope")); !reflect.DeepEqual(got, wantScopes) {
		t.Errorf("requested scopes = %v, want %v", got, wantScopes)
	}
	sort.Strings(wantScopes)
	tok := tokenFromSecret(res.Secret)
	if _, ok := e.as.accessScopes(tok.Access); !ok {
		t.Errorf("the stored access token is not the issued one: %+v", res.Secret)
	}
	if _, ok := e.as.refresh[tok.Refresh]; !ok {
		t.Errorf("the stored refresh token is not the issued one")
	}
	if d := time.Until(tok.Expiry); d < 59*time.Minute || d > 61*time.Minute {
		t.Errorf("expiry = %v (in %s), want in about an hour", res.Secret[secretExpiry], d)
	}
	if _, err := time.Parse(time.RFC3339, res.Secret[secretExpiry]); err != nil {
		t.Errorf("expiry %q is not RFC 3339", res.Secret[secretExpiry])
	}
	if !reflect.DeepEqual(tok.Scopes, wantScopes) {
		t.Errorf("stored scopes = %v, want %v", tok.Scopes, wantScopes)
	}
	if _, ok := res.Secret[secretToken]; ok {
		t.Errorf("a browser login stores no API token: %v", res.Secret)
	}
	wantMeta := map[string]string{metaMethod: "oauth", metaAccountID: "acc1", metaAccountName: "Acme", metaEmail: "ops@example.com", metaScopes: strings.Join(wantScopes, " ")}
	if !reflect.DeepEqual(res.Metadata, wantMeta) {
		t.Errorf("metadata = %v, want %v", res.Metadata, wantMeta)
	}
	if res.Label != "ops@example.com" {
		t.Errorf("label = %q", res.Label)
	}
	// Nothing sensitive is in the metadata or on the terminal.
	meta, _ := json.Marshal(res.Metadata)
	assertNoSecrets(t, "metadata", string(meta), e.secrets())
	assertNoSecrets(t, "stderr", stderr, e.secrets())
	// An OAuth token is never checked at the API-token endpoint.
	if n := e.cf.count("GET /user/tokens/verify") + e.cf.count("GET /accounts/acc1/tokens/verify"); n != 0 {
		t.Errorf("the login asked the token verify endpoint %d time(s): %v", n, e.cf.requests)
	}
	if ex, _ := e.as.counts(); ex != 1 {
		t.Errorf("%d code exchanges, want 1", ex)
	}
	if !strings.Contains(stderr, "not published yet") {
		t.Errorf("the login does not say the client is private: %q", stderr)
	}
}

// With --no-browser nothing is opened: the URL is printed and the listener
// waits for the person to open it on this machine.
func TestOAuthLoginNoBrowser(t *testing.T) {
	e := newOAuthEnv(t)
	pr, pw := io.Pipe()
	opened := 0
	done := make(chan struct{})
	go func() {
		defer close(done)
		buf := make([]byte, 0, 4096)
		tmp := make([]byte, 1024)
		followed := false
		for {
			n, err := pr.Read(tmp)
			buf = append(buf, tmp[:n]...)
			if !followed {
				if i := strings.Index(string(buf), oauthEP.Auth); i >= 0 {
					if j := strings.IndexByte(string(buf[i:]), '\n'); j >= 0 {
						followed = true
						go e.browser(t, nil)(string(buf[i : i+j])) //nolint:errcheck
					}
				}
			}
			if err != nil {
				return
			}
		}
	}()
	res, err := e.p.Login(context.Background(), platform.LoginInput{
		ProfileName: "work", Interactive: true, NoBrowser: true, Options: map[string]string{"method": "oauth"},
		Stdin: strings.NewReader(""), Stdout: &bytes.Buffer{}, Stderr: pw,
		OpenBrowser: func(string) error { opened++; return nil },
	})
	pw.Close()
	<-done
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if opened != 0 {
		t.Errorf("--no-browser opened a browser %d time(s)", opened)
	}
	if res.Metadata[metaMethod] != "oauth" || res.Secret[secretRefreshToken] == "" {
		t.Errorf("result: %+v", res.Metadata)
	}
}

func TestOAuthLoginCallbackFailures(t *testing.T) {
	t.Run("state mismatch", func(t *testing.T) {
		e := newOAuthEnv(t)
		_, stderr, err := e.login(t, context.Background(), nil, nil, e.browser(t, func(red *url.URL) {
			q := red.Query()
			q.Set("state", "someone-elses-state")
			red.RawQuery = q.Encode()
		}))
		if !errors.Is(err, platform.ErrLoginCancelled) || !strings.Contains(err.Error(), "state mismatch") {
			t.Fatalf("err = %v", err)
		}
		if ex, _ := e.as.counts(); ex != 0 {
			t.Errorf("a code with a wrong state was exchanged")
		}
		assertNoSecrets(t, "stderr", stderr+err.Error(), e.secrets())
	})
	t.Run("denied", func(t *testing.T) {
		e := newOAuthEnv(t)
		_, _, err := e.login(t, context.Background(), nil, nil, e.browser(t, func(red *url.URL) {
			red.RawQuery = url.Values{"state": {red.Query().Get("state")}, "error": {"access_denied"}}.Encode()
		}))
		if !errors.Is(err, platform.ErrLoginCancelled) || !strings.Contains(err.Error(), "denied in the browser") {
			t.Fatalf("err = %v", err)
		}
		if ex, _ := e.as.counts(); ex != 0 {
			t.Errorf("the token endpoint was asked after a denial")
		}
	})
	t.Run("other error redirect", func(t *testing.T) {
		e := newOAuthEnv(t)
		_, _, err := e.login(t, context.Background(), nil, nil, e.browser(t, func(red *url.URL) {
			red.RawQuery = url.Values{"state": {red.Query().Get("state")}, "error": {"invalid_scope"}, "error_description": {"unknown scope"}}.Encode()
		}))
		if !errors.Is(err, platform.ErrLoginCancelled) || !strings.Contains(err.Error(), "invalid_scope") || !strings.Contains(err.Error(), "unknown scope") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("timeout", func(t *testing.T) {
		e := newOAuthEnv(t)
		old := oauthWait
		oauthWait = 40 * time.Millisecond
		t.Cleanup(func() { oauthWait = old })
		_, _, err := e.login(t, context.Background(), nil, nil, func(string) error { return nil })
		if !errors.Is(err, platform.ErrLoginCancelled) || !strings.Contains(err.Error(), "no approval arrived") {
			t.Fatalf("err = %v", err)
		}
	})
	t.Run("cancel", func(t *testing.T) {
		e := newOAuthEnv(t)
		ctx, cancel := context.WithCancel(context.Background())
		start := time.Now()
		_, _, err := e.login(t, ctx, nil, nil, func(string) error { time.AfterFunc(20*time.Millisecond, cancel); return nil })
		// Ctrl-C leaves the login like any other question of it.
		if !errors.Is(err, prompt.ErrAborted) {
			t.Fatalf("err = %v, want prompt.ErrAborted", err)
		}
		if time.Since(start) > 10*time.Second {
			t.Errorf("the wait did not end with the context")
		}
	})
	t.Run("browser cannot be opened", func(t *testing.T) {
		e := newOAuthEnv(t)
		old := oauthWait
		oauthWait = 40 * time.Millisecond
		t.Cleanup(func() { oauthWait = old })
		_, stderr, err := e.login(t, context.Background(), nil, nil, func(string) error { return errors.New("no display") })
		if !errors.Is(err, platform.ErrLoginCancelled) || !strings.Contains(stderr, "open the URL above manually") {
			t.Fatalf("err = %v, stderr %q", err, stderr)
		}
	})
}

// A request on another path is not the answer; the right one still is.
func TestOAuthLoginWrongPath(t *testing.T) {
	e := newOAuthEnv(t)
	follow := e.browser(t, nil)
	res, _, err := e.login(t, context.Background(), nil, nil, func(authURL string) error {
		u, _ := url.Parse(authURL)
		red, _ := url.Parse(u.Query().Get("redirect_uri"))
		for _, path := range []string{"/", "/callback", "/oauth/callback/extra"} {
			resp, err := http.Get("http://" + red.Host + path + "?code=forged&state=" + u.Query().Get("state"))
			if err != nil {
				t.Errorf("GET %s: %v", path, err)
				continue
			}
			resp.Body.Close()
			if resp.StatusCode != http.StatusNotFound {
				t.Errorf("GET %s = %d, want 404", path, resp.StatusCode)
			}
		}
		return follow(authURL)
	})
	if err != nil || res.Secret[secretAccessToken] == "" {
		t.Fatalf("login: %v", err)
	}
}

func TestOAuthLoginExchangeFailure(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.failExchange = "invalid_grant"
	_, stderr, err := e.login(t, context.Background(), nil, nil, e.browser(t, nil))
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("err = %v", err)
	}
	assertNoSecrets(t, "the error", err.Error()+stderr, e.secrets())
	if n := len(e.cf.requests); n != 0 {
		t.Errorf("the API was called without a token: %v", e.cf.requests)
	}
}

// The token endpoint may answer in a form polyctl does not know.
func TestOAuthLoginExchangeOddAnswers(t *testing.T) {
	as := newFakeAS(t)
	odd := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		switch r.URL.Query().Get("case") {
		case "html":
			w.WriteHeader(502)
			fmt.Fprint(w, "<html>bad gateway</html>")
		case "echo":
			w.WriteHeader(400)
			_ = json.NewEncoder(w).Encode(map[string]string{"error": "invalid_request", "error_description": "bad code " + r.PostForm.Get("code") + " verifier " + r.PostForm.Get("code_verifier")})
		case "empty":
			fmt.Fprint(w, "{}")
		}
	}))
	t.Cleanup(odd.Close)
	_ = as
	for name, want := range map[string]string{"html": "HTTP 502", "echo": "[redacted]", "empty": "no access token"} {
		oauthEP.Token = odd.URL + "/?case=" + name
		_, err := requestToken(context.Background(), url.Values{"grant_type": {"authorization_code"}, "code": {"code-secret-value"}, "code_verifier": {"verifier-secret-value"}}, oauthToken{})
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%s: err = %v, want %q", name, err, want)
		}
		if err != nil && (strings.Contains(err.Error(), "code-secret-value") || strings.Contains(err.Error(), "verifier-secret-value")) {
			t.Errorf("%s: the error shows a secret: %v", name, err)
		}
	}
}

// Which method a login uses, for both values of the switch that says the
// OAuth client is public, in both flows.
func TestLoginMethodMatrix(t *testing.T) {
	oauthAcct := map[string]string{metaMethod: "oauth"}
	tokenAcct := map[string]string{metaMethod: "api_token"}
	legacyAcct := map[string]string{metaAccountID: "acc1"} // stored by 0.1.x: no method
	cases := []struct {
		name        string
		public      bool
		interactive bool
		opts        map[string]string
		env         string
		existing    map[string]string
		want        string // method, or "" for a usage error
		wantToken   string
		wantErr     []string
	}{
		// The client is private (today): exactly the token login of before.
		{name: "private, interactive", interactive: true, want: methodToken},
		{name: "private, non-interactive", wantErr: []string{"--set token=-", tokenEnv}},
		{name: "private, token option", opts: map[string]string{"token": "t"}, want: methodToken, wantToken: "t"},
		{name: "private, token from env", env: "e", want: methodToken, wantToken: "e"},
		{name: "private, interactive, token from env", interactive: true, env: "e", want: methodToken, wantToken: "e"},
		{name: "private, explicit oauth", interactive: true, opts: map[string]string{"method": "oauth"}, want: methodOAuth},
		{name: "private, explicit oauth, non-interactive", opts: map[string]string{"method": "oauth"}, wantErr: []string{"interactive flow only", "--set token=-", tokenEnv}},
		{name: "private, explicit token", interactive: true, opts: map[string]string{"method": "token"}, want: methodToken},
		{name: "private, explicit token, non-interactive", opts: map[string]string{"method": "token"}, wantErr: []string{"--set token=-"}},
		// Once public: the browser is the interactive default only.
		{name: "public, interactive", public: true, interactive: true, want: methodOAuth},
		{name: "public, non-interactive", public: true, wantErr: []string{"--set token=-", tokenEnv}},
		{name: "public, interactive, token option", public: true, interactive: true, opts: map[string]string{"token": "t"}, want: methodToken, wantToken: "t"},
		{name: "public, interactive, token from env", public: true, interactive: true, env: "e", want: methodToken, wantToken: "e"},
		{name: "public, non-interactive, token from env", public: true, env: "e", want: methodToken, wantToken: "e"},
		{name: "public, explicit token", public: true, interactive: true, opts: map[string]string{"method": "token"}, want: methodToken},
		{name: "public, explicit oauth, non-interactive", public: true, opts: map[string]string{"method": "oauth"}, wantErr: []string{"interactive flow only"}},
		// The option wins over the environment; a token given with it is a
		// contradiction.
		{name: "explicit oauth with env token", interactive: true, opts: map[string]string{"method": "oauth"}, env: "e", want: methodOAuth},
		{name: "explicit oauth with token option", interactive: true, opts: map[string]string{"method": "oauth", "token": "t"}, wantErr: []string{"does not take --set token"}},
		{name: "explicit token with both", opts: map[string]string{"method": "token", "token": "t"}, env: "e", want: methodToken, wantToken: "t"},
		{name: "method is case-insensitive", interactive: true, opts: map[string]string{"method": " OAuth "}, want: methodOAuth},
		{name: "unknown method", interactive: true, opts: map[string]string{"method": "browser"}, wantErr: []string{`unknown cloudflare login method "browser"`, "oauth", "token"}},
		{name: "old spelling is not input", interactive: true, opts: map[string]string{"method": "api_token"}, wantErr: []string{"unknown cloudflare login method"}},
		{name: "unknown method with a token", opts: map[string]string{"method": "pat", "token": "t"}, wantErr: []string{"unknown cloudflare login method"}},
		// Logging in again keeps the method of the account.
		{name: "again: oauth stays oauth", interactive: true, existing: oauthAcct, want: methodOAuth},
		{name: "again: oauth, non-interactive", existing: oauthAcct, wantErr: []string{"authorized in a browser", "--set token=-"}},
		{name: "again: oauth, token given", existing: oauthAcct, opts: map[string]string{"token": "t"}, want: methodToken, wantToken: "t"},
		{name: "again: oauth, explicit token", interactive: true, existing: oauthAcct, opts: map[string]string{"method": "token"}, want: methodToken},
		{name: "again: token stays token when public", public: true, interactive: true, existing: tokenAcct, want: methodToken},
		{name: "again: 0.1.x account stays token when public", public: true, interactive: true, existing: legacyAcct, want: methodToken},
		{name: "again: token to oauth on request", interactive: true, existing: tokenAcct, opts: map[string]string{"method": "oauth"}, want: methodOAuth},
		{name: "again: token, non-interactive", public: true, existing: tokenAcct, wantErr: []string{"--set token=-"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			old := oauthClientPublic
			oauthClientPublic = tc.public
			t.Cleanup(func() { oauthClientPublic = old })
			t.Setenv(tokenEnv, tc.env)
			in := platform.LoginInput{Interactive: tc.interactive, Options: tc.opts, Existing: tc.existing,
				Stdin: refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
			method, token, err := loginMethod(in, in.IO(context.Background()))
			if len(tc.wantErr) > 0 {
				if !errors.Is(err, app.ErrUsage) {
					t.Fatalf("got %q, %v; want a usage error", method, err)
				}
				for _, w := range tc.wantErr {
					if !strings.Contains(err.Error(), w) {
						t.Errorf("the usage error does not name %q: %v", w, err)
					}
				}
				return
			}
			if err != nil || method != tc.want || token != tc.wantToken {
				t.Fatalf("got %q, token %q, %v; want %q, token %q", method, token, err, tc.want, tc.wantToken)
			}
		})
	}
}

// The switch is off as shipped: only members of the publisher's account
// could approve.
func TestOAuthClientIsNotPublicYet(t *testing.T) {
	if oauthClientPublic {
		t.Skip("the OAuth client is public")
	}
	p := &provider{}
	if !strings.Contains(p.LoginHelp(), "not published yet") {
		t.Errorf("the login help does not say that method=oauth is limited: %q", p.LoginHelp())
	}
	if !reflect.DeepEqual(p.LoginOptions(), []string{"method", "token", "account_id", "accounts"}) {
		t.Errorf("login options = %v", p.LoginOptions())
	}
}

// The non-interactive flow refuses the browser login before anything
// listens, opens or is printed.
func TestOAuthLoginNonInteractiveRefused(t *testing.T) {
	e := newOAuthEnv(t)
	for _, public := range []bool{false, true} {
		old := oauthClientPublic
		oauthClientPublic = public
		var stderr bytes.Buffer
		opened := 0
		_, err := e.p.Login(context.Background(), platform.LoginInput{
			Options: map[string]string{"method": "oauth"},
			Stdin:   refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &stderr,
			OpenBrowser: func(string) error { opened++; return nil },
		})
		oauthClientPublic = old
		if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set token=-") {
			t.Errorf("public=%v: err = %v, want a usage error naming the token", public, err)
		}
		if opened != 0 || stderr.Len() != 0 {
			t.Errorf("public=%v: browser opened %d time(s), stderr %q", public, opened, stderr.String())
		}
	}
	if ex, _ := e.as.counts(); ex != 0 || len(e.cf.requests) != 0 {
		t.Errorf("the refused login used the network")
	}
}

// Once the client is public the interactive login goes to the browser by
// itself, and an API token still works when one is given.
func TestOAuthLoginIsInteractiveDefaultWhenPublic(t *testing.T) {
	e := newOAuthEnv(t)
	old := oauthClientPublic
	oauthClientPublic = true
	t.Cleanup(func() { oauthClientPublic = old })
	res, stderr, err := e.login(t, context.Background(), map[string]string{}, nil, e.browser(t, nil))
	if err != nil || res.Metadata[metaMethod] != "oauth" {
		t.Fatalf("login: %v %+v", err, res)
	}
	if strings.Contains(stderr, "not published yet") {
		t.Errorf("a public client is described as private: %q", stderr)
	}
}

// --- accounts and scopes at login ---------------------------------------

func TestOAuthLoginSeveralAccounts(t *testing.T) {
	e := newOAuthEnv(t)
	e.cf.accounts = append(e.cf.accounts, map[string]any{"id": "acc2", "name": "Beta", "type": "standard"})
	// --set account_id picks one without a question.
	res, _, err := e.login(t, context.Background(), map[string]string{"method": "oauth", "account_id": "acc2"}, nil, e.browser(t, nil))
	if err != nil || res.Metadata[metaAccountID] != "acc2" || res.Metadata[metaAccountName] != "Beta" {
		t.Fatalf("--set account_id: %v %+v", err, res)
	}
	// One that the authorization does not cover is an error.
	if _, _, err := e.login(t, context.Background(), map[string]string{"method": "oauth", "account_id": "nope"}, nil, e.browser(t, nil)); err == nil || !strings.Contains(err.Error(), "not visible to this authorization") {
		t.Fatalf("unknown account: %v", err)
	}
	// --set accounts selects several, the first being the default unless
	// --set account_id names it.
	res, stderrText, err := e.login(t, context.Background(), map[string]string{"method": "oauth", "accounts": "acc1,acc2"}, nil, e.browser(t, nil))
	if err != nil || res.Metadata[metaAccountID] != "acc1" || res.Metadata[metaAccounts] != "acc1,acc2" || !strings.Contains(stderrText, "using acc1 as the default account") {
		t.Fatalf("--set accounts: %v %+v %q", err, res, stderrText)
	}
	// Otherwise the interactive flow asks which accounts and, with several,
	// which one is the default.
	ask := func(stdin string, existing map[string]string) (*platform.LoginResult, string, error) {
		var stderr bytes.Buffer
		res, err := e.p.Login(context.Background(), platform.LoginInput{
			ProfileName: "work", Interactive: true, Options: map[string]string{"method": "oauth"}, Existing: existing,
			Stdin: strings.NewReader(stdin), Stdout: &bytes.Buffer{}, Stderr: &stderr, OpenBrowser: e.browser(t, nil),
		})
		return res, stderr.String(), err
	}
	res, stderrText, err = ask("acc2\n", nil)
	if err != nil || res.Metadata[metaAccountID] != "acc2" || res.Metadata[metaAccounts] != "" || !strings.Contains(stderrText, "Cloudflare accounts to work on") {
		t.Fatalf("one chosen: %v %+v %q", err, res, stderrText)
	}
	if strings.Contains(stderrText, "Default account") {
		t.Errorf("one account chosen and the default is asked: %q", stderrText)
	}
	res, stderrText, err = ask("acc1,acc2\n2\n", nil)
	if err != nil || res.Metadata[metaAccountID] != "acc2" || res.Metadata[metaAccountName] != "Beta" || res.Metadata[metaAccounts] != "acc2,acc1" || !strings.Contains(stderrText, "Default account") {
		t.Fatalf("two chosen: %v %+v %q", err, res, stderrText)
	}
	if res.Label != "ops@example.com (account Beta, +1 more)" {
		t.Errorf("label = %q", res.Label)
	}
	// The selection of the previous login is ticked: accepting it keeps it,
	// default included.
	prev := map[string]string{metaMethod: "oauth", metaAccountID: "acc2", metaAccounts: "acc2,acc1"}
	res, _, err = ask("\n\n", prev)
	if err != nil || res.Metadata[metaAccountID] != "acc2" || res.Metadata[metaAccounts] != "acc2,acc1" {
		t.Fatalf("previous selection: %v %+v", err, res)
	}
	// The default account of the previous login is not a reason to fail
	// when the person approved another one this time; a selected account
	// that is gone is left out, which is said.
	e.cf.accounts = e.cf.accounts[:1]
	res, stderrText, err = ask("", map[string]string{metaMethod: "oauth", metaAccountID: "acc2"})
	if err != nil || res.Metadata[metaAccountID] != "acc1" || !strings.Contains(stderrText, "not covered by this authorization") {
		t.Fatalf("previous account gone: %v %+v %q", err, res, stderrText)
	}
	res, stderrText, err = ask("", map[string]string{metaMethod: "oauth", metaAccountID: "acc1", metaAccounts: "acc1,acc2"})
	if err != nil || res.Metadata[metaAccountID] != "acc1" || res.Metadata[metaAccounts] != "" || !strings.Contains(stderrText, "account acc2 of the previous selection is not visible to this authorization and was left out") {
		t.Fatalf("selected account gone: %v %+v %q", err, res, stderrText)
	}
}

// Without the scope that lists accounts they are read off the zones, which
// shows the accounts with a zone only: a selected account that list lacks
// stays offered, and ticked.
func TestOAuthLoginKeepsAccountsTheZonesDoNotShow(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.granted = OAuthRequiredScopes
	var stderr bytes.Buffer
	res, err := e.p.Login(context.Background(), platform.LoginInput{
		ProfileName: "work", Interactive: true, Options: map[string]string{"method": "oauth"},
		Existing: map[string]string{metaMethod: "oauth", metaAccountID: "acc1", metaAccounts: "acc1,acc9"},
		Stdin:    strings.NewReader("\n\n"), Stdout: &bytes.Buffer{}, Stderr: &stderr, OpenBrowser: e.browser(t, nil),
	})
	if err != nil || res.Metadata[metaAccountID] != "acc1" || res.Metadata[metaAccounts] != "acc1,acc9" {
		t.Fatalf("login: %v %+v %q", err, res, stderr.String())
	}
	if strings.Contains(stderr.String(), "left out") {
		t.Errorf("an account the zones do not show was left out: %q", stderr.String())
	}
}

// Declined optional scopes do not fail the login: the accounts are read off
// the zones and the e-mail comes from the userinfo endpoint, or is left out.
func TestOAuthLoginWithOptionalScopesDeclined(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.granted = OAuthRequiredScopes
	res, stderr, err := e.login(t, context.Background(), nil, nil, e.browser(t, nil))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if res.Metadata[metaAccountID] != "acc1" || res.Metadata[metaAccountName] != "Acme" {
		t.Errorf("account from the zones: %+v", res.Metadata)
	}
	if res.Metadata[metaEmail] != "ops@example.com" {
		t.Errorf("e-mail from userinfo: %+v", res.Metadata)
	}
	if e.cf.count("GET /accounts") != 0 || e.cf.count("GET /user") != 0 {
		t.Errorf("endpoints of declined scopes were called: %v", e.cf.requests)
	}
	for _, s := range OAuthOptionalScopes {
		if !strings.Contains(stderr, s) {
			t.Errorf("the login does not say that %s was not granted: %q", s, stderr)
		}
	}
	if got := strings.Fields(res.Metadata[metaScopes]); len(got) != len(OAuthRequiredScopes) {
		t.Errorf("metadata scopes = %v", got)
	}

	// No userinfo either: the login still succeeds, labelled by the account.
	e.as.userinfoEmail = ""
	res, _, err = e.login(t, context.Background(), nil, nil, e.browser(t, nil))
	if err != nil || res.Metadata[metaEmail] != "" || res.Label != "Acme" {
		t.Fatalf("without userinfo: %v %+v label %q", err, res, res.Label)
	}
}

// A token response without scope and expires_in still gives a working
// login: the scopes are unknown and the expiry is left to the API.
func TestOAuthLoginSparseTokenResponse(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.omitScope, e.as.omitExpiry = true, true
	res, _, err := e.login(t, context.Background(), nil, nil, e.browser(t, nil))
	if err != nil {
		t.Fatalf("login: %v", err)
	}
	if _, ok := res.Secret[secretExpiry]; ok || res.Secret[secretScopes] != "" {
		t.Errorf("secret = %v", keys(res.Secret))
	}
	if _, ok := res.Metadata[metaScopes]; ok {
		t.Errorf("metadata claims scopes: %v", res.Metadata)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// --- use of a stored browser login --------------------------------------

// stored is a browser login as the credential store holds it, with what
// UpdateSecret and RefreshSecret did to it.
type stored struct {
	mu      sync.Mutex
	secret  map[string]string
	updates int
}

func (s *stored) get() map[string]string {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := map[string]string{}
	for k, v := range s.secret {
		out[k] = v
	}
	return out
}

func (s *stored) profile(meta map[string]string) platform.Profile {
	if meta == nil {
		meta = map[string]string{metaMethod: "oauth", metaAccountID: "acc1"}
	}
	return platform.Profile{Name: "work", Platform: platform.Cloudflare, Metadata: meta, Secret: s.get(),
		UpdateSecret: func(m map[string]string) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			s.secret, s.updates = m, s.updates+1
			return nil
		},
		RefreshSecret: func(fn func(map[string]string) (map[string]string, error)) error {
			s.mu.Lock()
			defer s.mu.Unlock()
			cur := map[string]string{}
			for k, v := range s.secret {
				cur[k] = v
			}
			next, err := fn(cur)
			if err != nil || next == nil {
				return err
			}
			s.secret, s.updates = next, s.updates+1
			return nil
		}}
}

// grant issues tokens as a finished login would have stored them.
func (e *oauthEnv) grant(scopes []string, expiry time.Time) *stored {
	if scopes == nil {
		scopes = append(append([]string{}, OAuthRequiredScopes...), OAuthOptionalScopes...)
	}
	scopes = append([]string(nil), scopes...)
	sort.Strings(scopes)
	e.as.mu.Lock()
	body := e.as.issue(scopes, true)
	e.as.mu.Unlock()
	tok := oauthToken{Access: body["access_token"].(string), Refresh: body["refresh_token"].(string), Expiry: expiry, Scopes: scopes}
	return &stored{secret: tok.secret(nil)}
}

func (e *oauthEnv) open(t *testing.T, prof platform.Profile) *Client {
	t.Helper()
	c, err := e.p.Open(context.Background(), prof)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	return c.(*Client)
}

func TestOAuthUsesAccessToken(t *testing.T) {
	e := newOAuthEnv(t)
	st := e.grant(nil, time.Now().Add(time.Hour))
	c := e.open(t, st.profile(nil))
	zones, err := c.ListZones(context.Background())
	if err != nil || len(zones) != 1 {
		t.Fatalf("zones: %v %v", zones, err)
	}
	if _, refreshes := e.as.counts(); refreshes != 0 || st.updates != 0 {
		t.Errorf("a valid token was renewed (%d refreshes, %d writes)", refreshes, st.updates)
	}
	// Opening asks nothing.
	e.cf.requests = nil
	e.open(t, st.profile(nil))
	if len(e.cf.requests) != 0 {
		t.Errorf("Open used the network: %v", e.cf.requests)
	}
	// A profile whose metadata lost the method is still recognised by its
	// secret; one without any token is not opened.
	if c := e.open(t, st.profile(map[string]string{})); c.api.oauth == nil {
		t.Errorf("a secret with OAuth tokens was opened as an API token")
	}
	if _, err := e.p.Open(context.Background(), platform.Profile{Name: "work", Metadata: map[string]string{metaMethod: "oauth"}, Secret: map[string]string{}}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("open without tokens = %v", err)
	}
}

// An access token that has expired, or is about to, is renewed before the
// request, and the result is stored.
func TestOAuthRefreshesExpiredToken(t *testing.T) {
	for name, expiry := range map[string]time.Time{"expired": time.Now().Add(-time.Minute), "within the skew": time.Now().Add(30 * time.Second)} {
		t.Run(name, func(t *testing.T) {
			e := newOAuthEnv(t)
			st := e.grant(nil, expiry)
			before := st.get()
			e.as.expire(before[secretAccessToken])
			c := e.open(t, st.profile(nil))
			if _, err := c.ListZones(context.Background()); err != nil {
				t.Fatalf("zones: %v", err)
			}
			after := st.get()
			if _, refreshes := e.as.counts(); refreshes != 1 || st.updates != 1 {
				t.Fatalf("%d refreshes, %d writes; want 1 and 1", refreshes, st.updates)
			}
			if after[secretAccessToken] == before[secretAccessToken] || after[secretAccessToken] == "" {
				t.Errorf("the access token was not replaced")
			}
			// No rotation: the server returned no refresh token, the old
			// one is kept.
			if after[secretRefreshToken] != before[secretRefreshToken] {
				t.Errorf("the refresh token changed without rotation: %q -> %q", before[secretRefreshToken], after[secretRefreshToken])
			}
			if exp, err := time.Parse(time.RFC3339, after[secretExpiry]); err != nil || time.Until(exp) < 50*time.Minute {
				t.Errorf("new expiry = %q", after[secretExpiry])
			}
			if after[secretScopes] != before[secretScopes] {
				t.Errorf("scopes changed: %q -> %q", before[secretScopes], after[secretScopes])
			}
			if n := e.cf.count("GET /zones"); n != 1 {
				t.Errorf("%d zone requests, want 1 (none with the expired token)", n)
			}
			// The next request reuses the new token.
			if _, err := c.ListZones(context.Background()); err != nil {
				t.Fatal(err)
			}
			if _, refreshes := e.as.counts(); refreshes != 1 {
				t.Errorf("renewed again: %d refreshes", refreshes)
			}
		})
	}
}

// A rotated refresh token replaces the stored one.
func TestOAuthRefreshRotation(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.rotate = true
	st := e.grant(nil, time.Now().Add(-time.Minute))
	before := st.get()
	c := e.open(t, st.profile(nil))
	if _, err := c.ListZones(context.Background()); err != nil {
		t.Fatalf("zones: %v", err)
	}
	after := st.get()
	if after[secretRefreshToken] == before[secretRefreshToken] || after[secretRefreshToken] == "" {
		t.Fatalf("the rotated refresh token was not stored: %q", after[secretRefreshToken])
	}
	if _, ok := e.as.refresh[after[secretRefreshToken]]; !ok {
		t.Errorf("the stored refresh token is not the valid one")
	}
	// A process that starts now, from the store, can renew again.
	st.mu.Lock()
	st.secret[secretExpiry] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	st.mu.Unlock()
	if _, err := e.open(t, st.profile(nil)).ListZones(context.Background()); err != nil {
		t.Fatalf("second renewal: %v", err)
	}
}

// The API refuses a token whose expiry polyctl believed (clock skew, a
// revoked access token): renew once and repeat the request.
func TestOAuthRetriesOnceAfter401(t *testing.T) {
	e := newOAuthEnv(t)
	st := e.grant(nil, time.Now().Add(time.Hour))
	e.as.expire(st.get()[secretAccessToken])
	c := e.open(t, st.profile(nil))
	rec, err := c.CreateRecord(context.Background(), "zone1", platform.Record{Name: "new.example.com", Type: "A", Value: "10.1.1.1"})
	if err != nil || rec.ID == "" {
		t.Fatalf("create after 401: %v", err)
	}
	if _, refreshes := e.as.counts(); refreshes != 1 || st.updates != 1 {
		t.Errorf("%d refreshes, %d writes; want 1 and 1", refreshes, st.updates)
	}
	if n := e.cf.count("POST /zones/zone1/dns_records"); n != 2 {
		t.Errorf("%d create requests, want 2 (refused, then repeated)", n)
	}
	if n := len(e.cf.records["zone1"]); n != 9 {
		t.Errorf("%d records, want 9: the refused request must not have created one", n)
	}

	// A token that is refused again after the renewal is not renewed in a
	// loop.
	e.cf.badTokenStatus = 401
	e.cf.oauth = newFakeAS(t) // an API that knows none of the tokens
	oauthEP = oauthEndpoints{Token: e.as.srv.URL + "/oauth2/token"}
	for i := 0; i < 3; i++ {
		if _, err := c.ListZones(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
			t.Fatalf("zones with a refused token = %v", err)
		}
	}
	if _, refreshes := e.as.counts(); refreshes != 2 {
		t.Errorf("%d refreshes, want 2: one more try, then no loop", refreshes)
	}
}

// Without a known expiry the API is what says that the token is over, in
// whatever form.
func TestOAuthRenewsOnAuthFailureWithoutExpiry(t *testing.T) {
	e := newOAuthEnv(t)
	e.cf.badTokenStatus = 400
	st := e.grant(nil, time.Time{})
	e.as.expire(st.get()[secretAccessToken])
	c := e.open(t, st.profile(nil))
	if _, err := c.ListZones(context.Background()); err != nil {
		t.Fatalf("zones: %v", err)
	}
	if _, refreshes := e.as.counts(); refreshes != 1 {
		t.Errorf("%d refreshes, want 1", refreshes)
	}
}

// invalid_grant: the authorization is gone. The person is told to log in
// again; nothing is retried.
func TestOAuthRefreshInvalidGrant(t *testing.T) {
	for _, code := range []string{"invalid_grant", "some_unknown_code"} {
		e := newOAuthEnv(t)
		st := e.grant(nil, time.Now().Add(-time.Minute))
		before := st.get()
		e.as.failRefresh = code
		c := e.open(t, st.profile(nil))
		_, err := c.ListZones(context.Background())
		if !errors.Is(err, platform.ErrUnauthorized) {
			t.Fatalf("%s: err = %v, want ErrUnauthorized", code, err)
		}
		for _, want := range []string{"polyctl auth login cloudflare --profile work", "revoked or has expired", code} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error does not say %q: %v", code, want, err)
			}
		}
		assertNoSecrets(t, "the error", err.Error(), []string{before[secretAccessToken], before[secretRefreshToken]})
		if st.updates != 0 || len(e.cf.requests) != 0 {
			t.Errorf("%s: %d writes, API requests %v", code, st.updates, e.cf.requests)
		}
	}
}

// The authorization server is down: that is not a revoked login.
func TestOAuthRefreshServerError(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.failRefresh, e.as.refreshStatus = "server_error", 503
	// Expired: nothing to work with.
	st := e.grant(nil, time.Now().Add(-time.Minute))
	_, err := e.open(t, st.profile(nil)).ListZones(context.Background())
	if err == nil || errors.Is(err, platform.ErrUnauthorized) || strings.Contains(err.Error(), "auth login") {
		t.Fatalf("expired: err = %v, want a plain failure", err)
	}
	// About to expire, but still valid: the request goes out with it.
	st = e.grant(nil, time.Now().Add(30*time.Second))
	if _, err := e.open(t, st.profile(nil)).ListZones(context.Background()); err != nil {
		t.Fatalf("still valid: %v", err)
	}
}

// The request that renews starts from the stored secret: when another
// process renewed in the meantime, its tokens are taken over and the
// refresh token this process loaded, spent by then, is not used.
func TestOAuthRefreshTakesOverStoredToken(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.rotate = true
	st := e.grant(nil, time.Now().Add(-time.Minute))
	stale := st.profile(nil) // loaded before the other process renewed
	if _, err := e.open(t, st.profile(nil)).ListZones(context.Background()); err != nil {
		t.Fatalf("the other process: %v", err)
	}
	if _, err := e.open(t, stale).ListZones(context.Background()); err != nil {
		t.Fatalf("this process, with a spent refresh token in memory: %v", err)
	}
	if _, refreshes := e.as.counts(); refreshes != 1 || st.updates != 1 {
		t.Errorf("%d refreshes, %d writes; want 1 and 1", refreshes, st.updates)
	}
}

// Two polyctl processes whose access token expired renew at the same time.
// The lock of the credential store makes them take turns, so the rotating
// refresh token is spent once and neither run fails.
func TestOAuthConcurrentRefreshAcrossProcesses(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.rotate = true
	e.as.refreshDelay = 80 * time.Millisecond
	st := e.grant(nil, time.Now().Add(-time.Minute))

	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	cfgYAML := "credential_store: file\nprofiles:\n  work:\n    platforms:\n      cloudflare:\n        credential_backend: file\n        metadata:\n          method: oauth\n          account_id: acc1\n"
	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte(cfgYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	key := creds.Key("work", string(platform.Cloudflare))
	if err := creds.NewFile(dir).Set(key, st.get()); err != nil {
		t.Fatal(err)
	}

	const procs = 4
	var wg sync.WaitGroup
	errs := make([]error, procs)
	clients := make([]*Client, procs)
	for i := range clients {
		// Each runtime has its own store object, like a process of its own.
		rt := app.New(app.Flags{ConfigDir: dir}, strings.NewReader(""), io.Discard, io.Discard)
		t.Cleanup(func() { _ = rt.Close() })
		prof, err := rt.LoadProfile("work", platform.Cloudflare)
		if err != nil {
			t.Fatal(err)
		}
		if prof.RefreshSecret == nil {
			t.Fatal("a loaded profile has no RefreshSecret")
		}
		clients[i] = e.open(t, prof)
	}
	for i := range clients {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, errs[i] = clients[i].ListZones(context.Background())
		}()
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Errorf("process %d: %v", i, err)
		}
	}
	if _, refreshes := e.as.counts(); refreshes != 1 {
		t.Errorf("%d refreshes, want 1: the others must take over the stored token", refreshes)
	}
	final, err := creds.NewFile(dir).Get(key)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := e.as.refresh[final[secretRefreshToken]]; !ok {
		t.Errorf("the stored refresh token is not the one that is valid now")
	}
	if _, ok := e.as.accessScopes(final[secretAccessToken]); !ok {
		t.Errorf("the stored access token is not valid")
	}
	// Nothing of it reached config.yaml.
	cfgText, _ := os.ReadFile(filepath.Join(dir, "config.yaml"))
	assertNoSecrets(t, "config.yaml", string(cfgText), e.secrets())
}

// Requests of one process that run together renew once as well.
func TestOAuthConcurrentRefreshInOneProcess(t *testing.T) {
	e := newOAuthEnv(t)
	e.as.rotate = true
	e.as.refreshDelay = 30 * time.Millisecond
	st := e.grant(nil, time.Now().Add(-time.Minute))
	c := e.open(t, st.profile(nil))
	var wg sync.WaitGroup
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := c.ListRecords(context.Background(), "zone1"); err != nil {
				t.Errorf("records: %v", err)
			}
		}()
	}
	wg.Wait()
	if _, refreshes := e.as.counts(); refreshes != 1 {
		t.Errorf("%d refreshes, want 1", refreshes)
	}
}

// A profile that cannot store (no credential store behind it) still works
// for the run.
func TestOAuthRefreshWithoutStore(t *testing.T) {
	e := newOAuthEnv(t)
	st := e.grant(nil, time.Now().Add(-time.Minute))
	prof := st.profile(nil)
	prof.UpdateSecret, prof.RefreshSecret = nil, nil
	if _, err := e.open(t, prof).ListZones(context.Background()); err != nil {
		t.Fatalf("zones: %v", err)
	}
	// With UpdateSecret only (no lock to take), the result is stored.
	prof = st.profile(nil)
	prof.RefreshSecret = nil
	if _, err := e.open(t, prof).ListZones(context.Background()); err != nil || st.updates != 1 {
		t.Fatalf("zones: %v, %d writes", err, st.updates)
	}
	// A store that fails to write does not fail the request.
	var warned []string
	oldWarn := warnf
	warnf = func(format string, args ...any) { warned = append(warned, fmt.Sprintf(format, args...)) }
	t.Cleanup(func() { warnf = oldWarn })
	st.mu.Lock()
	st.secret[secretExpiry] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	st.mu.Unlock()
	prof = st.profile(nil)
	prof.RefreshSecret = nil
	prof.UpdateSecret = func(map[string]string) error { return errors.New("keyring locked") }
	if _, err := e.open(t, prof).ListZones(context.Background()); err != nil {
		t.Fatalf("zones with a failing store: %v", err)
	}
	if len(warned) != 1 || !strings.Contains(warned[0], "could not be stored") {
		t.Errorf("warnings = %q", warned)
	}
	assertNoSecrets(t, "the warning", strings.Join(warned, "\n"), e.secrets())
}

// --- scopes ----------------------------------------------------------------

func TestScopeFor(t *testing.T) {
	cases := []struct{ method, path, want string }{
		{"GET", "/zones", scopeZoneRead},
		{"GET", "/zones/z1", scopeZoneRead},
		{"GET", "/zones/z1/dns_records", scopeDNSRead},
		{"POST", "/zones/z1/dns_records", scopeDNSWrite},
		{"PUT", "/zones/z1/dns_records/r1", scopeDNSWrite},
		{"DELETE", "/zones/z1/dns_records/r1", scopeDNSWrite},
		{"POST", "/zones/z1/purge_cache", scopeCachePurge},
		{"GET", "/zones/z1/settings/ssl", scopeZoneSettingsRead},
		{"PATCH", "/zones/z1/settings/development_mode", scopeZoneSettingsWrite},
		{"GET", "/accounts", scopeAccountRead},
		{"GET", "/user", scopeUserRead},
		{"GET", "/user/tokens/verify", scopeUserRead},
		{"GET", "/something/else", ""},
	}
	for _, c := range cases {
		if got := scopeFor(c.method, c.path); got != c.want {
			t.Errorf("scopeFor(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
	// Every scope a mapped request needs is one the login asks for.
	asked := append(append([]string{}, OAuthRequiredScopes...), OAuthOptionalScopes...)
	for _, c := range cases {
		if c.want != "" && !containsString(asked, c.want) {
			t.Errorf("%s %s needs %q, which the login does not ask for", c.method, c.path, c.want)
		}
	}
	// And every optional scope is needed by a request polyctl makes.
	for _, s := range OAuthOptionalScopes {
		used := false
		for _, c := range cases {
			used = used || c.want == s
		}
		if !used {
			t.Errorf("optional scope %q is asked for and never needed", s)
		}
	}
	seen := map[string]bool{}
	for _, s := range asked {
		if seen[s] {
			t.Errorf("scope %q is listed twice", s)
		}
		seen[s] = true
	}
}

// A command whose optional scope was declined names the scope and the way
// to get it.
func TestOAuthMissingOptionalScope(t *testing.T) {
	e := newOAuthEnv(t)
	st := e.grant(OAuthRequiredScopes, time.Now().Add(time.Hour))
	c := e.open(t, st.profile(nil))
	ctx := context.Background()
	checks := map[string]func() error{
		scopeCachePurge: func() error {
			_, err := c.api.purgeCache(ctx, "zone1", purgeRequest{PurgeEverything: true})
			return err
		},
		scopeZoneSettingsRead:  func() error { _, err := c.api.getSetting(ctx, "zone1", "ssl"); return err },
		scopeZoneSettingsWrite: func() error { _, err := c.api.setSetting(ctx, "zone1", "development_mode", "on"); return err },
		scopeAccountRead:       func() error { _, err := c.api.listAccounts(ctx); return err },
	}
	for scope, call := range checks {
		err := call()
		if !errors.Is(err, platform.ErrUnauthorized) {
			t.Errorf("%s: err = %v, want ErrUnauthorized", scope, err)
			continue
		}
		var ce *Error
		if !errors.As(err, &ce) || ce.Status != 403 {
			t.Errorf("%s: the API error is lost: %v", scope, err)
		}
		for _, want := range []string{`"` + scope + `" scope was not granted`, "polyctl auth login cloudflare --profile work"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("%s: the error does not say %q: %v", scope, want, err)
			}
		}
	}
	// A permission failure is not a reason to renew: the expiry is known.
	if _, refreshes := e.as.counts(); refreshes != 0 {
		t.Errorf("%d refreshes after permission failures", refreshes)
	}
	// What the required scopes cover still works.
	if _, err := c.ListRecords(ctx, "zone1"); err != nil {
		t.Errorf("records: %v", err)
	}

	// Granted, and refused all the same (the member's role, a zone outside
	// the account): the API error stands as it is.
	st = e.grant(nil, time.Now().Add(time.Hour))
	c = e.open(t, st.profile(nil))
	e.cf.forbidRecords["zone1"] = true
	if _, err := c.ListRecords(ctx, "zone1"); !errors.Is(err, platform.ErrUnauthorized) || strings.Contains(err.Error(), "scope") {
		t.Errorf("granted scope: err = %v", err)
	}

	// Scopes unknown (Cloudflare did not say): the hint is conditional.
	e.as.omitScope = true
	st = e.grant(nil, time.Now().Add(time.Hour))
	sec := st.get()
	sec[secretScopes] = ""
	st.secret = sec
	c = e.open(t, st.profile(nil))
	if _, err := c.ListRecords(ctx, "zone1"); err == nil || !strings.Contains(err.Error(), `if it was declined at the login`) || !strings.Contains(err.Error(), scopeDNSRead) {
		t.Errorf("unknown scopes: err = %v", err)
	}
}

// --- verify ------------------------------------------------------------------

func TestOAuthVerify(t *testing.T) {
	e := newOAuthEnv(t)
	st := e.grant(nil, time.Now().Add(time.Hour))
	meta := map[string]string{metaMethod: "oauth", metaAccountID: "acc1", metaAccountName: "Acme", metaEmail: "ops@example.com"}
	id, err := e.open(t, st.profile(meta)).Verify(context.Background())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if id.Account != "acc1" || id.User != "ops@example.com" || id.Extra["method"] != "oauth" || id.Extra["account_name"] != "Acme" {
		t.Errorf("identity = %+v", id)
	}
	if !strings.Contains(id.Extra["scopes"], scopeDNSWrite) || id.Extra["access_token_expires_on"] == "" {
		t.Errorf("extra = %v", id.Extra)
	}
	if _, has := id.Extra["token_id"]; has {
		t.Errorf("an OAuth identity reports an API token id: %v", id.Extra)
	}
	if n := e.cf.count("GET /user/tokens/verify"); n != 0 {
		t.Errorf("verify asked the API-token endpoint %d time(s)", n)
	}
	if n := e.cf.count("GET /zones?"); n != 1 || len(e.cf.requests) != 1 {
		t.Errorf("verify made %v, want one cheap zone request", e.cf.requests)
	}
	if !strings.Contains(e.cf.requests[0], "per_page=1") || !strings.Contains(e.cf.requests[0], "account.id=acc1") {
		t.Errorf("the check is %q", e.cf.requests[0])
	}
	blob, _ := json.Marshal(id)
	assertNoSecrets(t, "the identity", string(blob), e.secrets())

	// Without the user details scope and without a stored e-mail the
	// userinfo endpoint is asked; when that fails too, verify still passes.
	st = e.grant(OAuthRequiredScopes, time.Now().Add(time.Hour))
	meta = map[string]string{metaMethod: "oauth"}
	id, err = e.open(t, st.profile(meta)).Verify(context.Background())
	if err != nil || id.User != "ops@example.com" {
		t.Fatalf("verify through userinfo: %v %+v", err, id)
	}
	if e.cf.count("GET /user") != 0 {
		t.Errorf("/user was asked without the scope")
	}
	e.as.userinfoEmail = ""
	id, err = e.open(t, st.profile(meta)).Verify(context.Background())
	if err != nil || id.User != "" {
		t.Fatalf("verify without userinfo: %v %+v", err, id)
	}

	// An expired access token is renewed by the check.
	st = e.grant(nil, time.Now().Add(-time.Minute))
	if _, err := e.open(t, st.profile(nil)).Verify(context.Background()); err != nil || st.updates != 1 {
		t.Fatalf("verify with an expired token: %v (%d writes)", err, st.updates)
	}
	// A revoked authorization fails it, as unauthorized.
	e.as.failRefresh = "invalid_grant"
	st = e.grant(nil, time.Now().Add(-time.Minute))
	if _, err := e.open(t, st.profile(nil)).Verify(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("verify of a revoked login = %v", err)
	}
}

// --- revocation -------------------------------------------------------------

func TestOAuthRevoke(t *testing.T) {
	e := newOAuthEnv(t)
	var rv platform.Revoker = e.p
	st := e.grant(nil, time.Now().Add(time.Hour))
	prof := st.profile(nil)
	if !rv.CanRevoke(prof) {
		t.Fatal("a browser login cannot be revoked")
	}
	if err := rv.Revoke(context.Background(), prof); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	want := []string{"refresh_token:" + prof.Secret[secretRefreshToken], "access_token:" + prof.Secret[secretAccessToken]}
	if !reflect.DeepEqual(e.as.revoked, want) {
		t.Errorf("revoked = %v, want the refresh token, then the access token", e.as.revoked)
	}
	if _, ok := e.as.accessScopes(prof.Secret[secretAccessToken]); ok {
		t.Errorf("the access token still works")
	}

	// A failure is reported without the tokens.
	e.as.revokeStatus = 503
	st = e.grant(nil, time.Now().Add(time.Hour))
	prof = st.profile(nil)
	err := rv.Revoke(context.Background(), prof)
	if err == nil || !strings.Contains(err.Error(), "HTTP 503") {
		t.Fatalf("revoke against a failing server = %v", err)
	}
	assertNoSecrets(t, "the error", err.Error(), []string{prof.Secret[secretRefreshToken], prof.Secret[secretAccessToken]})

	// An unreachable server likewise.
	oauthEP.Revoke = "http://127.0.0.1:1/oauth2/revoke"
	err = rv.Revoke(context.Background(), prof)
	if err == nil {
		t.Fatal("revoke against an unreachable server succeeded")
	}
	assertNoSecrets(t, "the error", err.Error(), []string{prof.Secret[secretRefreshToken], prof.Secret[secretAccessToken]})

	// API-token accounts have nothing to revoke: the token is the person's.
	tokenProf := platform.Profile{Name: "t", Metadata: map[string]string{metaMethod: "api_token"}, Secret: map[string]string{secretToken: "good-token"}}
	legacyProf := platform.Profile{Name: "t", Metadata: map[string]string{}, Secret: map[string]string{secretToken: "good-token"}}
	for _, p := range []platform.Profile{tokenProf, legacyProf} {
		if rv.CanRevoke(p) {
			t.Errorf("an API-token account is revocable: %+v", p.Metadata)
		}
		if err := rv.Revoke(context.Background(), p); err != nil {
			t.Errorf("revoke of an API-token account = %v", err)
		}
	}
}

// --- API tokens are untouched -----------------------------------------------

// An API-token account never talks to the authorization server, whatever
// the API answers.
func TestTokenAccountsNeverUseOAuth(t *testing.T) {
	as := newFakeAS(t)
	_, srv := newFake(t)
	c := openClient(t, srv, "bad-token", "")
	if _, err := c.ListZones(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	c = openClient(t, srv, "good-token", "")
	if _, err := c.Verify(context.Background()); err != nil {
		t.Fatal(err)
	}
	if ex, refreshes := as.counts(); ex != 0 || refreshes != 0 || as.userinfos != 0 {
		t.Errorf("an API-token account reached the authorization server")
	}
	if c.api.oauth != nil {
		t.Errorf("an API-token client carries an OAuth session")
	}
}
