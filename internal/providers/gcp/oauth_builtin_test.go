package gcp

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"maps"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/oauth2"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// The tests of this package run without a built-in OAuth client, whatever
// oauth_builtin.go holds: they describe both states of the binary, and the
// ones that need a client set one with withBuiltinClient.
func init() { builtinClient = oauthClient{} }

// The constants are filled in together: half a client is no client, and
// would silently keep the fallback of a build without one.
func TestBuiltinClientConstants(t *testing.T) {
	if (builtinClientID == "") != (builtinClientSecret == "") {
		t.Error("builtinClientID and builtinClientSecret must both be set or both be empty")
	}
	if (oauthClient{ID: "id"}).set() || (oauthClient{Secret: "s"}).set() || !(oauthClient{ID: "id", Secret: "s"}).set() {
		t.Error("a client is set when it has an id and a secret")
	}
}

var testBuiltin = oauthClient{ID: "builtin-id.apps.googleusercontent.com", Secret: "builtin-secret"}

func withBuiltinClient(t *testing.T, c oauthClient) {
	t.Helper()
	old := builtinClient
	builtinClient = c
	t.Cleanup(func() { builtinClient = old })
}

// withoutADC makes the lookup of Application Default Credentials fail.
func withoutADC(t *testing.T) {
	t.Helper()
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", filepath.Join(t.TempDir(), "missing.json"))
}

func withLookPath(t *testing.T, found bool) {
	t.Helper()
	old := lookPath
	lookPath = func(name string) (string, error) {
		if found {
			return "/usr/bin/" + name, nil
		}
		return "", exec.ErrNotFound
	}
	t.Cleanup(func() { lookPath = old })
}

// fakeOAuth is Google's token endpoint: it records the form of every
// request, answers a code with a refresh token and a refresh token with an
// access token.
type fakeOAuth struct {
	srv *httptest.Server

	mu    sync.Mutex
	forms []url.Values
	// scope is the scope field of the answers ("": none).
	scope string
}

func newFakeOAuth(t *testing.T) *fakeOAuth {
	t.Helper()
	o := &fakeOAuth{}
	o.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/token" || r.ParseForm() != nil {
			http.NotFound(w, r)
			return
		}
		o.mu.Lock()
		o.forms = append(o.forms, r.PostForm)
		scope := o.scope
		o.mu.Unlock()
		out := map[string]any{"access_token": "access-1", "token_type": "Bearer", "expires_in": 3600}
		if scope != "" {
			out["scope"] = scope
		}
		if r.PostForm.Get("grant_type") == "authorization_code" {
			out["refresh_token"] = "refresh-1"
		}
		writeJSON(w, out)
	}))
	t.Cleanup(o.srv.Close)
	old := oauthEndpoint
	oauthEndpoint = oauth2.Endpoint{AuthURL: "https://accounts.google.com/o/oauth2/auth", TokenURL: o.srv.URL + "/token", AuthStyle: oauth2.AuthStyleInParams}
	t.Cleanup(func() { oauthEndpoint = old })
	return o
}

// last returns the form of the latest token request.
func (o *fakeOAuth) last(t *testing.T) url.Values {
	t.Helper()
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.forms) == 0 {
		t.Fatal("no request reached the token endpoint")
	}
	return o.forms[len(o.forms)-1]
}

func (o *fakeOAuth) count() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.forms)
}

// approve plays the person in the browser: it grants the request of the
// authorization URL by returning to its redirect URI with a code, and
// keeps the parameters of the request.
type approval struct {
	mu    sync.Mutex
	query url.Values
	calls int
}

func (a *approval) open(authURL string) error {
	u, err := url.Parse(authURL)
	if err != nil {
		return err
	}
	q := u.Query()
	a.mu.Lock()
	a.query = q
	a.calls++
	a.mu.Unlock()
	resp, err := http.Get(q.Get("redirect_uri") + "?" + url.Values{"state": {q.Get("state")}, "code": {"the-code"}}.Encode())
	if err != nil {
		return err
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.Body.Close()
}

func (a *approval) request() (url.Values, int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.query, a.calls
}

// browserLogin is an interactive login whose browser is a.
func browserLogin(stdin string, opts map[string]string, a *approval) (platform.LoginInput, *bytes.Buffer) {
	in, errBuf := loginInput(stdin, opts)
	in.Interactive, in.NoBrowser, in.OpenBrowser = true, false, a.open
	return in, errBuf
}

func s256(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// The default login on a terminal, with a built-in client: the browser,
// no question about the method, PKCE on a loopback redirect, and nothing
// of the client in what is stored.
func TestLoginBuiltinClient(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	o := newFakeOAuth(t)
	withBuiltinClient(t, testBuiltin)
	// Credentials on the machine do not change the default.
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", writeServiceAccountKey(t, f, "adc-proj"))
	p := &provider{}
	ctx := context.Background()

	a := &approval{}
	in, errBuf := browserLogin("", map[string]string{"project": "proj"}, a)
	res, err := p.Login(ctx, in)
	if err != nil {
		t.Fatalf("login: %v\n%s", err, errBuf.String())
	}
	if !maps.Equal(res.Secret, map[string]string{"refresh_token": "refresh-1"}) {
		t.Errorf("the built-in client stores the refresh token only, got the keys of %d entries: %v", len(res.Secret), keys(res.Secret))
	}
	if !maps.Equal(res.Metadata, map[string]string{"method": methodOAuth, "project": "proj", "email": "me@example.com", "oauth_client": oauthClientBuiltin}) {
		t.Errorf("metadata: %v", res.Metadata)
	}
	for _, m := range []map[string]string{res.Secret, res.Metadata} {
		for k, v := range m {
			if strings.Contains(v, testBuiltin.Secret) || strings.Contains(v, testBuiltin.ID) {
				t.Errorf("%s holds the built-in client", k)
			}
		}
	}
	if s := errBuf.String(); strings.Contains(s, "How do you want") || strings.Contains(s, "OAuth client id") || !strings.Contains(s, "Google Auth Library") {
		t.Errorf("stderr: %q", s)
	}

	// The authorization request: this client, a loopback redirect, PKCE.
	q, calls := a.request()
	if calls != 1 {
		t.Fatalf("the browser was opened %d time(s)", calls)
	}
	red, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || red.Scheme != "http" || red.Hostname() != "127.0.0.1" || red.Port() == "" || red.Path != "/callback" {
		t.Errorf("redirect_uri = %q, want http://127.0.0.1:<port>/callback", q.Get("redirect_uri"))
	}
	if q.Get("client_id") != testBuiltin.ID || q.Get("response_type") != "code" || q.Get("access_type") != "offline" || q.Get("state") == "" {
		t.Errorf("authorization request: %v", q)
	}
	if q.Get("code_challenge_method") != "S256" || len(q.Get("code_challenge")) != 43 {
		t.Errorf("PKCE: code_challenge_method=%q code_challenge=%q", q.Get("code_challenge_method"), q.Get("code_challenge"))
	}
	if q.Get("client_secret") != "" {
		t.Error("the authorization URL carries the client secret")
	}
	form := o.last(t)
	if form.Get("grant_type") != "authorization_code" || form.Get("code") != "the-code" || form.Get("client_id") != testBuiltin.ID || form.Get("client_secret") != testBuiltin.Secret || form.Get("redirect_uri") != q.Get("redirect_uri") {
		t.Errorf("code exchange: grant_type=%q code=%q client_id=%q redirect_uri=%q", form.Get("grant_type"), form.Get("code"), form.Get("client_id"), form.Get("redirect_uri"))
	}
	if v := form.Get("code_verifier"); len(v) < 43 || s256(v) != q.Get("code_challenge") {
		t.Errorf("the code verifier of the exchange does not match the challenge of the request")
	}

	// The refresh takes the client from the binary.
	prof := platform.Profile{Name: "me", Platform: platform.GCP, Metadata: res.Metadata, Secret: res.Secret}
	refresh := func(want oauthClient) {
		t.Helper()
		c, err := p.Open(ctx, prof)
		if err != nil {
			t.Fatalf("open: %v", err)
		}
		before := o.count()
		if id, err := c.Verify(ctx); err != nil || id.User != "me@example.com" {
			t.Fatalf("verify: %v %+v", err, id)
		}
		form := o.last(t)
		if o.count() == before || form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != "refresh-1" {
			t.Fatalf("no refresh request: grant_type=%q", form.Get("grant_type"))
		}
		if form.Get("client_id") != want.ID || form.Get("client_secret") != want.Secret {
			t.Errorf("refresh with client %q, want %q", form.Get("client_id"), want.ID)
		}
	}
	refresh(testBuiltin)
	// A later release with another client: the stored account follows it.
	rotated := oauthClient{ID: "rotated-id", Secret: "rotated-secret"}
	withBuiltinClient(t, rotated)
	refresh(rotated)
	// A build without the client cannot refresh, and says what to do.
	withBuiltinClient(t, oauthClient{})
	if _, err := p.Open(ctx, prof); !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "built-in OAuth client") || !strings.Contains(err.Error(), "polyctl auth login gcp --profile me") {
		t.Errorf("open without a built-in client: %v", err)
	}
}

func keys(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// A client of the user is stored and used as before, whether or not the
// binary has one of its own.
func TestLoginOwnClientUnchanged(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	o := newFakeOAuth(t)
	p := &provider{}
	ctx := context.Background()
	own := map[string]string{"client_id": "own-id", "client_secret": "own-secret", "refresh_token": "refresh-1"}

	for _, builtin := range []oauthClient{{}, testBuiltin} {
		withBuiltinClient(t, builtin)
		a := &approval{}
		in, errBuf := browserLogin("", map[string]string{"method": "oauth", "client_id": "own-id", "client_secret": "own-secret", "project": "proj"}, a)
		res, err := p.Login(ctx, in)
		if err != nil {
			t.Fatalf("login: %v\n%s", err, errBuf.String())
		}
		if !maps.Equal(res.Secret, own) {
			t.Errorf("secret keys: %v", keys(res.Secret))
		}
		if !maps.Equal(res.Metadata, map[string]string{"method": methodOAuth, "project": "proj", "email": "me@example.com"}) {
			t.Errorf("metadata: %v", res.Metadata)
		}
		if q, _ := a.request(); q.Get("client_id") != "own-id" || q.Get("code_challenge_method") != "S256" {
			t.Errorf("authorization request: client_id=%q code_challenge_method=%q", q.Get("client_id"), q.Get("code_challenge_method"))
		}
		if form := o.last(t); form.Get("client_id") != "own-id" || form.Get("client_secret") != "own-secret" || form.Get("code_verifier") == "" {
			t.Errorf("code exchange with client %q", form.Get("client_id"))
		}
		c, err := p.Open(ctx, platform.Profile{Name: "me", Platform: platform.GCP, Metadata: res.Metadata, Secret: res.Secret})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := c.Verify(ctx); err != nil {
			t.Fatal(err)
		}
		if form := o.last(t); form.Get("grant_type") != "refresh_token" || form.Get("client_id") != "own-id" || form.Get("client_secret") != "own-secret" {
			t.Errorf("refresh: grant_type=%q client_id=%q", form.Get("grant_type"), form.Get("client_id"))
		}
	}

	// With a built-in client, a re-login of the account of an own client
	// does not move it to the built-in one: the client is needed again.
	withBuiltinClient(t, testBuiltin)
	in, errBuf := loginInput("", nil)
	in.Existing = map[string]string{"method": methodOAuth, "project": "proj"}
	in.ProfileName = "me"
	if _, err := p.Login(ctx, in); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set client_id=<id>") || strings.Contains(errBuf.String(), "Open this URL") {
		t.Errorf("re-login of an own client: %v / %q", err, errBuf.String())
	} else if !strings.Contains(err.Error(), "polyctl auth logout gcp --profile me") {
		t.Errorf("the error does not say how to move to the built-in client: %v", err)
	}
	a := &approval{}
	in, errBuf = browserLogin("own-id\nown-secret\n\n", nil, a)
	in.Existing = map[string]string{"method": methodOAuth, "project": "proj"}
	res, err := p.Login(ctx, in)
	if err != nil || !maps.Equal(res.Secret, own) || res.Metadata["oauth_client"] != "" {
		t.Errorf("interactive re-login of an own client: %v (stderr %q)", err, errBuf.String())
	}
	if !strings.Contains(errBuf.String(), "OAuth client id") || !strings.Contains(errBuf.String(), "polyctl auth logout gcp") {
		t.Errorf("the client was not asked for, or the way to the built-in client not named: %q", errBuf.String())
	}
	// A build without a built-in client has nothing to move to.
	withBuiltinClient(t, oauthClient{})
	in, _ = loginInput("", nil)
	in.Existing = map[string]string{"method": methodOAuth, "project": "proj"}
	if _, err := p.Login(ctx, in); !errors.Is(err, app.ErrUsage) || strings.Contains(err.Error(), "auth logout") {
		t.Errorf("re-login of an own client without a built-in one: %v", err)
	}
}

// Without --set method a re-login keeps the method of the account, also
// when the binary has a built-in client.
func TestReloginKeepsMethod(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	o := newFakeOAuth(t)
	withBuiltinClient(t, testBuiltin)
	t.Setenv("GOOGLE_APPLICATION_CREDENTIALS", writeServiceAccountKey(t, f, "proj"))
	p := &provider{}
	ctx := context.Background()

	// adc, also for an account from before the method was recorded.
	for _, existing := range []map[string]string{{"method": methodADC, "project": "proj"}, {"project": "proj"}} {
		a := &approval{}
		in, errBuf := browserLogin("\n", nil, a)
		in.Existing = existing
		res, err := p.Login(ctx, in)
		if err != nil || res.Metadata["method"] != methodADC || len(res.Secret) != 0 {
			t.Errorf("re-login of %v: %v %+v (stderr %q)", existing, err, res, errBuf.String())
		}
		if _, calls := a.request(); calls != 0 || o.count() != 0 {
			t.Errorf("re-login of %v went through the browser", existing)
		}
	}

	// An account of the built-in client stays with it, in either flow.
	builtinAccount := map[string]string{"method": methodOAuth, "project": "proj", "oauth_client": oauthClientBuiltin}
	a := &approval{}
	in, errBuf := browserLogin("\n", nil, a)
	in.Existing = builtinAccount
	res, err := p.Login(ctx, in)
	if err != nil || res.Metadata["oauth_client"] != oauthClientBuiltin || res.Metadata["project"] != "proj" || len(res.Secret) != 1 {
		t.Errorf("re-login of a built-in account: %v (stderr %q)", err, errBuf.String())
	}
	if q, _ := a.request(); q.Get("client_id") != testBuiltin.ID {
		t.Errorf("re-login used client %q", q.Get("client_id"))
	}

	// --set method wins over the stored one.
	a = &approval{}
	in, _ = browserLogin("\n", map[string]string{"method": "adc"}, a)
	in.Existing = builtinAccount
	if res, err := p.Login(ctx, in); err != nil || res.Metadata["method"] != methodADC || res.Metadata["oauth_client"] != "" {
		t.Errorf("--set method=adc over a stored oauth: %v %+v", err, res)
	}
	a = &approval{}
	in, _ = browserLogin("\n", map[string]string{"method": "oauth"}, a)
	in.Existing = map[string]string{"method": methodADC, "project": "proj"}
	if res, err := p.Login(ctx, in); err != nil || res.Metadata["oauth_client"] != oauthClientBuiltin {
		t.Errorf("--set method=oauth over a stored adc: %v %+v", err, res)
	}
}

// lockedBuffer is a stderr that the test reads while the login writes.
type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuffer) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

var printedURL = regexp.MustCompile(`(?m)^    (https://\S+)$`)

// With --no-browser, and in the non-interactive flow, no browser is opened:
// the URL is printed and the loopback listener still takes the code.
func TestLoginBuiltinClientNoBrowser(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	newFakeOAuth(t)
	withBuiltinClient(t, testBuiltin)
	withoutADC(t)
	p := &provider{}

	for _, interactive := range []bool{true, false} {
		opts := map[string]string{"project": "proj"}
		if !interactive {
			// The non-interactive default stays adc.
			opts["method"] = "oauth"
		}
		stderr := &lockedBuffer{}
		opened := 0
		in, _ := loginInput("", opts)
		in.Interactive, in.Stderr = interactive, stderr
		in.NoBrowser, in.OpenBrowser = true, func(string) error { opened++; return nil }
		type outcome struct {
			res *platform.LoginResult
			err error
		}
		done := make(chan outcome, 1)
		go func() { res, err := p.Login(context.Background(), in); done <- outcome{res, err} }()

		// The person copies the URL from the terminal.
		var authURL string
		for deadline := time.Now().Add(10 * time.Second); authURL == "" && time.Now().Before(deadline); time.Sleep(5 * time.Millisecond) {
			if m := printedURL.FindStringSubmatch(stderr.String()); m != nil {
				authURL = m[1]
			}
		}
		if authURL == "" {
			t.Fatalf("interactive=%v: no URL was printed: %q", interactive, stderr.String())
		}
		a := &approval{}
		if err := a.open(authURL); err != nil {
			t.Fatal(err)
		}
		select {
		case out := <-done:
			if out.err != nil || out.res.Metadata["oauth_client"] != oauthClientBuiltin || out.res.Secret["refresh_token"] != "refresh-1" {
				t.Errorf("interactive=%v: %v (stderr %q)", interactive, out.err, stderr.String())
			}
		case <-time.After(10 * time.Second):
			t.Fatalf("interactive=%v: the login did not return", interactive)
		}
		if q, _ := a.request(); opened != 0 || q.Get("client_id") != testBuiltin.ID || q.Get("code_challenge_method") != "S256" {
			t.Errorf("interactive=%v: browser opened %d time(s), client_id=%q", interactive, opened, q.Get("client_id"))
		}
	}
}

// The non-interactive oauth login with a built-in client needs the project
// only; without one it needs the client as before.
func TestLoginOAuthNonInteractiveRequirements(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	p := &provider{}

	in, errBuf := loginInput("", map[string]string{"method": "oauth"})
	_, err := p.Login(context.Background(), in)
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set client_id=<id>") || !strings.Contains(err.Error(), "--set client_secret=-") || !strings.Contains(err.Error(), "--set project=<id>") {
		t.Errorf("without a built-in client: %v", err)
	}
	withBuiltinClient(t, testBuiltin)
	in, errBuf = loginInput("", map[string]string{"method": "oauth"})
	_, err = p.Login(context.Background(), in)
	if !errors.Is(err, app.ErrUsage) || strings.Contains(err.Error(), "client_id") || strings.Contains(err.Error(), "client_secret") || !strings.Contains(err.Error(), "--set project=<id>") {
		t.Errorf("with a built-in client: %v", err)
	}
	if errBuf.Len() != 0 {
		t.Errorf("stderr: %q", errBuf.String())
	}
	// Half a client is a client of the user: the other half is missing.
	in, _ = loginInput("", map[string]string{"method": "oauth", "client_id": "own-id", "project": "proj"})
	if _, err = p.Login(context.Background(), in); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set client_secret=-") || strings.Contains(err.Error(), "client_id") {
		t.Errorf("client_id without client_secret: %v", err)
	}
}

// What --set says of the projects is refused before the browser is asked
// for anything: an id that cannot be one, and a default project that is
// named as disabled, also the default a re-login keeps.
func TestLoginOAuthChecksProjectOptionsBeforeTheBrowser(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	withBuiltinClient(t, testBuiltin)
	p := &provider{}
	for _, tc := range []struct {
		opts     map[string]string
		existing map[string]string
		interact bool
		want     string
	}{
		{opts: map[string]string{"project": "p-one", "disabled_projects": "p-one,p-two"}, want: "--set disabled_projects names p-one, the default project"},
		{opts: map[string]string{"disabled_projects": "p-one"}, existing: map[string]string{"project": "p-one"}, want: "--set disabled_projects names p-one, the default project"},
		{opts: map[string]string{"project": "p-one", "disabled_projects": "Not An Id"}, want: "--set disabled_projects=<id>,<id>,..."},
		{opts: map[string]string{"project": "Not An Id"}, want: "--set project=<id>"},
		{opts: map[string]string{"project": "p-one", "disabled_projects": "p-one"}, interact: true, want: "--set disabled_projects names p-one, the default project"},
	} {
		tc.opts["method"] = "oauth"
		in, errBuf := loginInput("", tc.opts)
		if tc.interact {
			in, errBuf = loginInput("\n", tc.opts)
		}
		in.Existing = tc.existing
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		_, err := p.Login(ctx, in)
		cancel()
		if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v: %v", tc.opts, err)
		}
		if strings.Contains(errBuf.String(), "http") || strings.Contains(errBuf.String(), "note:") {
			t.Errorf("%v: stderr %q", tc.opts, errBuf.String())
		}
	}
}

// A build without a built-in client, on a terminal, with no method given
// and no previous login: Application Default Credentials when the machine
// has them (TestLoginADC), else a question instead of a failure.
func TestLoginAsksMethodWithoutBuiltinClientAndADC(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	o := newFakeOAuth(t)
	withoutADC(t)
	withLookPath(t, true)
	p := &provider{}
	ctx := context.Background()
	const question = "How do you want to log in to Google Cloud?"

	// 1: a service account key file.
	keyPath := writeServiceAccountKey(t, f, "proj")
	in, errBuf := loginInput("1\n"+keyPath+"\n", nil)
	res, err := p.Login(ctx, in)
	if err != nil || res.Metadata["method"] != methodServiceAccount || res.Secret["service_account_json"] == "" {
		t.Fatalf("service account choice: %v (stderr %q)", err, errBuf.String())
	}
	for _, want := range []string{"No Application Default Credentials were found", question, "1) Service account key file", "2) Browser login with an OAuth client of your own", "3) Application Default Credentials"} {
		if !strings.Contains(errBuf.String(), want) {
			t.Errorf("stderr lacks %q: %q", want, errBuf.String())
		}
	}

	// The default answer is the service account key.
	in, _ = loginInput("\n"+keyPath+"\n", nil)
	if res, err := p.Login(ctx, in); err != nil || res.Metadata["method"] != methodServiceAccount {
		t.Errorf("default choice: %v", err)
	}

	// 2: an OAuth client of the user.
	a := &approval{}
	in, errBuf = browserLogin("2\nown-id\nown-secret\n", map[string]string{"project": "proj"}, a)
	res, err = p.Login(ctx, in)
	if err != nil || res.Secret["client_id"] != "own-id" || res.Metadata["method"] != methodOAuth || res.Metadata["oauth_client"] != "" {
		t.Fatalf("own client choice: %v (stderr %q)", err, errBuf.String())
	}
	if form := o.last(t); form.Get("client_id") != "own-id" || form.Get("code_verifier") == "" {
		t.Errorf("code exchange with client %q", form.Get("client_id"))
	}

	// 3: how to get the credentials with gcloud. Nothing failed, and no
	// account was added.
	for _, installed := range []bool{true, false} {
		withLookPath(t, installed)
		in, errBuf = loginInput("3\n", nil)
		res, err = p.Login(ctx, in)
		if res != nil || !errors.Is(err, platform.ErrNothingToDo) || !strings.Contains(err.Error(), "--set method=adc") {
			t.Errorf("gcloud choice: %v %+v", err, res)
		}
		s := errBuf.String()
		if !strings.Contains(s, "    gcloud auth application-default login") || strings.Contains(s, "not installed") == installed {
			t.Errorf("gcloud installed=%v: %q", installed, s)
		}
	}

	// --set method=adc is not asked about: it fails as it always did.
	in, errBuf = loginInput("1\n", map[string]string{"method": "adc"})
	if _, err := p.Login(ctx, in); !errors.Is(err, platform.ErrUnauthorized) || strings.Contains(errBuf.String(), question) {
		t.Errorf("--set method=adc without credentials: %v / %q", err, errBuf.String())
	}
}

// The non-interactive default stays Application Default Credentials and
// fails without them, with or without a built-in client. The message names
// the other methods, and says so when gcloud is not installed.
func TestLoginNonInteractiveWithoutADC(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	o := newFakeOAuth(t)
	withoutADC(t)
	p := &provider{}

	for _, builtin := range []oauthClient{{}, testBuiltin} {
		for _, installed := range []bool{true, false} {
			withBuiltinClient(t, builtin)
			withLookPath(t, installed)
			in, errBuf := loginInput("", nil)
			opened := 0
			in.NoBrowser, in.OpenBrowser = false, func(string) error { opened++; return nil }
			_, err := p.Login(context.Background(), in)
			if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "application default credentials not found") || !strings.Contains(err.Error(), "method=service_account") || !strings.Contains(err.Error(), "method=oauth") {
				t.Errorf("builtin=%v installed=%v: %v", builtin.set(), installed, err)
			}
			s := errBuf.String()
			for _, want := range []string{
				"No Application Default Credentials were found",
				"    gcloud auth application-default login",
				"polyctl auth login gcp --set method=service_account --set key_file=<path to the JSON key>",
				"polyctl auth login gcp --set method=oauth",
			} {
				if !strings.Contains(s, want) {
					t.Errorf("builtin=%v installed=%v: stderr lacks %q: %q", builtin.set(), installed, want, s)
				}
			}
			if strings.Contains(s, "which is not installed on this machine") == installed {
				t.Errorf("builtin=%v installed=%v: %q", builtin.set(), installed, s)
			}
			// The own client is only asked of a build without one.
			if strings.Contains(s, "--set client_id=<id>") == builtin.set() {
				t.Errorf("builtin=%v: the oauth alternative: %q", builtin.set(), s)
			}
			if opened != 0 || o.count() != 0 || strings.Contains(s, "How do you want") || strings.Contains(s, "Open this URL") {
				t.Errorf("builtin=%v installed=%v: browser opened %d time(s), stderr %q", builtin.set(), installed, opened, s)
			}
		}
	}
}

// lookPath is the real lookup outside tests.
func TestLookPathDefault(t *testing.T) {
	if _, err := lookPath("polyctl-no-such-program-on-path"); err == nil {
		t.Error("lookPath found a program that does not exist")
	}
}

// A login in which the person did not tick the Google Cloud permission on
// the consent screen is refused (exit code 3) and adds no account; one that
// granted it, in any order, is taken.
func TestLoginWithoutCloudScope(t *testing.T) {
	f := newFake(t)
	withFakeEndpoints(t, f)
	o := newFakeOAuth(t)
	withBuiltinClient(t, testBuiltin)
	p := &provider{}

	o.scope = "openid https://www.googleapis.com/auth/userinfo.email"
	in, errBuf := browserLogin("", map[string]string{"project": "proj"}, &approval{})
	_, err := p.Login(context.Background(), in)
	if !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "without access to Google Cloud") {
		t.Fatalf("err = %v\n%s", err, errBuf.String())
	}

	o.scope = "https://www.googleapis.com/auth/userinfo.email " + scopeCloudPlatform + " openid"
	in, errBuf = browserLogin("", map[string]string{"project": "proj"}, &approval{})
	if _, err := p.Login(context.Background(), in); err != nil {
		t.Fatalf("login: %v\n%s", err, errBuf.String())
	}
}
