package cloudflare_test

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/providers/cloudflare"
)

// terminal is a Picker that is never asked anything: its presence is what
// makes a run interactive, as a terminal on stdin and stderr would.
type terminal struct{ t *testing.T }

func (p terminal) Select(title string, _ []prompt.Option, _ string) (string, error) {
	p.t.Errorf("unexpected question %q", title)
	return "", prompt.ErrAborted
}
func (p terminal) MultiSelect(title string, _ []prompt.Option) ([]string, error) {
	p.t.Errorf("unexpected question %q", title)
	return nil, prompt.ErrAborted
}
func (p terminal) Confirm(title string, _ bool) (bool, error) {
	p.t.Errorf("unexpected question %q", title)
	return false, prompt.ErrAborted
}
func (p terminal) Input(title, _ string, _ func(string) error) (string, error) {
	p.t.Errorf("unexpected question %q", title)
	return "", prompt.ErrAborted
}

// watcher is a stderr that tells when a line starting with prefix (after
// its indentation) is complete.
type watcher struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	prefix string
	found  func(line string)
	done   bool
}

func (w *watcher) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if w.done || w.found == nil {
		return len(p), nil
	}
	for _, line := range strings.Split(w.buf.String(), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, w.prefix) && strings.Contains(w.buf.String(), line+"\n") {
			w.done = true
			go w.found(line)
			break
		}
	}
	return len(p), nil
}

func (w *watcher) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

type cliEnv struct {
	t   *testing.T
	dir string
	x   *cloudflare.E2E
}

func newCLIEnv(t *testing.T) *cliEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	t.Setenv(app.EnvNonInteractive, "")
	return &cliEnv{t: t, dir: dir, x: cloudflare.NewE2E(t)}
}

// run executes the command line. An interactive run has a person at it:
// when a login prints its authorization URL, they approve it in a browser.
func (e *cliEnv) run(interactive bool, args ...string) (code int, stdout, stderr string) {
	e.t.Helper()
	return e.runWith(context.Background(), interactive, e.x.Approve, args...)
}

// runWith is run with the context of the command and with what the person
// does once the authorization URL is printed.
func (e *cliEnv) runWith(ctx context.Context, interactive bool, onURL func(authURL string), args ...string) (code int, stdout, stderr string) {
	e.t.Helper()
	var out bytes.Buffer
	errw := &watcher{}
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, errw)
	if interactive {
		rt.Picker = terminal{e.t}
		errw.prefix, errw.found = e.x.AuthEndpoint(), onURL
	}
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
	root.SetIn(strings.NewReader(""))
	root.SetOut(&out)
	root.SetErr(errw)
	err := root.ExecuteContext(ctx)
	_ = rt.Close()
	text := errw.String()
	if err != nil {
		text += "error: " + err.Error() + "\n"
	}
	return cli.ExitCodeFor(err), out.String(), text
}

func (e *cliEnv) secret(key string) map[string]string {
	e.t.Helper()
	s, err := creds.NewFile(e.dir).Get(key)
	if err != nil {
		e.t.Fatalf("secret %s: %v", key, err)
	}
	return s
}

// noSecrets fails when a token or code shows up where it must not: the
// output of a command, or config.yaml.
func (e *cliEnv) noSecrets(what string, texts ...string) {
	e.t.Helper()
	cfg, _ := os.ReadFile(filepath.Join(e.dir, "config.yaml"))
	texts = append(texts, string(cfg))
	for _, s := range e.x.Secrets() {
		for _, text := range texts {
			if s != "" && strings.Contains(text, s) {
				e.t.Errorf("%s: the secret %q is shown:\n%s", what, s, text)
			}
		}
	}
}

// The browser login through the command line, and what follows from it:
// use, renewal, rename, missing scope, logout. Every command runs with -v,
// and no token or code may appear in its output or in config.yaml.
func TestCLIBrowserLogin(t *testing.T) {
	e := newCLIEnv(t)

	// Without a terminal the browser login is refused up front.
	code, stdout, stderr := e.run(false, "auth", "login", "cloudflare", "--set", "method=oauth", "--profile", "work")
	if code != cli.ExitUsage || !strings.Contains(stderr, "--set token=-") || stdout != "" {
		t.Fatalf("non-interactive: exit %d, stderr %q", code, stderr)
	}
	if _, err := os.Stat(filepath.Join(e.dir, "credentials.json")); err == nil {
		t.Fatal("a refused login stored credentials")
	}
	// An unknown method is a usage error naming the two.
	if code, _, stderr := e.run(true, "auth", "login", "cloudflare", "--set", "method=sso"); code != cli.ExitUsage || !strings.Contains(stderr, "expected oauth or token") {
		t.Fatalf("unknown method: exit %d, stderr %q", code, stderr)
	}

	// On a terminal, with --no-browser: the URL is printed, the person
	// opens it, the listener takes the answer.
	code, stdout, stderr = e.run(true, "-v", "auth", "login", "cloudflare", "--set", "method=oauth", "--no-browser", "--profile", "work")
	if code != cli.ExitOK {
		t.Fatalf("login: exit %d, stderr %q", code, stderr)
	}
	if stdout != "" || !strings.Contains(stderr, `logged in to Cloudflare in profile "work" (ops@example.com)`) {
		t.Errorf("stdout %q, stderr %q", stdout, stderr)
	}
	e.noSecrets("login", stdout, stderr)
	sec := e.secret("work/cloudflare")
	if sec[cloudflare.SecretAccessToken] == "" || sec[cloudflare.SecretRefreshToken] == "" || sec[cloudflare.SecretExpiry] == "" || sec[cloudflare.SecretScopes] == "" || len(sec) != 4 {
		t.Errorf("stored secret has the keys %v", keysOf(sec))
	}
	cfg, err := config.Load(filepath.Join(e.dir, "config.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	meta := cfg.Profiles["work"].Platforms["cloudflare"].Metadata
	if meta["method"] != "oauth" || meta["account_id"] != "acc1" || meta["email"] != "ops@example.com" || !strings.Contains(meta["scopes"], "dns.write") {
		t.Errorf("metadata = %v", meta)
	}

	// The account is used like any other.
	code, stdout, stderr = e.run(false, "-v", "cloudflare", "whoami", "--profile", "work", "-o", "json")
	if code != cli.ExitOK {
		t.Fatalf("whoami: exit %d, stderr %q", code, stderr)
	}
	var who struct {
		Identity struct {
			Account string            `json:"account"`
			User    string            `json:"user"`
			Extra   map[string]string `json:"extra"`
		} `json:"identity"`
	}
	if err := json.Unmarshal([]byte(stdout), &who); err != nil || who.Identity.Account != "acc1" || who.Identity.User != "ops@example.com" || who.Identity.Extra["method"] != "oauth" {
		t.Errorf("whoami = %s (%v)", stdout, err)
	}
	e.noSecrets("whoami", stdout, stderr)
	code, stdout, stderr = e.run(false, "-v", "auth", "status")
	if code != cli.ExitOK || !strings.Contains(stdout, "ok") {
		t.Errorf("auth status: exit %d, %q %q", code, stdout, stderr)
	}
	e.noSecrets("auth status", stdout, stderr)
	_, stdout, stderr = e.run(false, "-v", "auth", "list", "-o", "yaml")
	e.noSecrets("auth list", stdout, stderr)

	// An expired access token is renewed by the next command, and stored.
	sec[cloudflare.SecretExpiry] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := creds.NewFile(e.dir).Set("work/cloudflare", sec); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr = e.run(false, "-v", "cloudflare", "zone", "list", "--refresh")
	if code != cli.ExitOK || !strings.Contains(stdout, "example.com") {
		t.Fatalf("zone list: exit %d, %q %q", code, stdout, stderr)
	}
	e.noSecrets("zone list", stdout, stderr)
	renewed := e.secret("work/cloudflare")
	if e.x.Refreshes() != 1 || renewed[cloudflare.SecretAccessToken] == sec[cloudflare.SecretAccessToken] {
		t.Errorf("%d refreshes; the stored access token changed: %v", e.x.Refreshes(), renewed[cloudflare.SecretAccessToken] != sec[cloudflare.SecretAccessToken])
	}
	// --offline serves the cache and renews nothing.
	renewed[cloudflare.SecretExpiry] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := creds.NewFile(e.dir).Set("work/cloudflare", renewed); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := e.run(false, "--offline", "cloudflare", "zone", "list"); code != cli.ExitOK || !strings.Contains(stdout, "example.com") {
		t.Fatalf("offline zone list: exit %d, %q %q", code, stdout, stderr)
	}
	if code, _, stderr := e.run(false, "--offline", "auth", "status"); code != cli.ExitOK {
		t.Fatalf("offline auth status: exit %d, %q", code, stderr)
	}
	if e.x.Refreshes() != 1 {
		t.Errorf("--offline renewed the token (%d refreshes)", e.x.Refreshes())
	}

	// A rename moves the secret whole.
	if code, _, stderr := e.run(false, "auth", "rename", "work", "acme"); code != cli.ExitOK {
		t.Fatalf("rename: exit %d, %q", code, stderr)
	}
	if got := e.secret("acme/cloudflare"); !reflect.DeepEqual(got, renewed) {
		t.Errorf("secret after the rename has the keys %v, want it unchanged", keysOf(got))
	}
	if code, _, stderr := e.run(false, "cloudflare", "dns", "list", "example.com", "--profile", "acme"); code != cli.ExitOK {
		t.Fatalf("dns list after the rename: exit %d, %q", code, stderr)
	}

	// A second login, where the person declines the optional scopes: the
	// command that needs one says which, and how to get it.
	e.x.Grant(cloudflare.OAuthRequiredScopes)
	code, _, stderr = e.run(true, "-v", "auth", "login", "cloudflare", "--set", "method=oauth", "--no-browser", "--profile", "limited")
	if code != cli.ExitOK || !strings.Contains(stderr, "not granted: cache.purge") {
		t.Fatalf("limited login: exit %d, %q", code, stderr)
	}
	e.noSecrets("limited login", stderr)
	code, stdout, stderr = e.run(false, "-v", "cloudflare", "cache", "purge", "example.com", "--everything", "--profile", "limited")
	if code != cli.ExitAuth || !strings.Contains(stderr, `"cache.purge" scope was not granted`) || !strings.Contains(stderr, "polyctl auth login cloudflare --profile limited") {
		t.Errorf("purge without the scope: exit %d, %q", code, stderr)
	}
	e.noSecrets("cache purge", stdout, stderr)

	// Logging in again keeps the method: no --set method needed, and the
	// non-interactive flow says why it cannot.
	if code, _, stderr := e.run(false, "auth", "login", "cloudflare", "--profile", "limited"); code != cli.ExitUsage || !strings.Contains(stderr, "authorized in a browser") {
		t.Errorf("non-interactive re-login: exit %d, %q", code, stderr)
	}
	e.x.Grant(nil)
	if code, _, stderr := e.run(true, "auth", "login", "cloudflare", "--no-browser", "--profile", "limited"); code != cli.ExitOK {
		t.Fatalf("re-login: exit %d, %q", code, stderr)
	}
	if code, _, stderr := e.run(false, "cloudflare", "cache", "purge", "example.com", "--everything", "--profile", "limited"); code != cli.ExitOK {
		t.Errorf("purge after approving the scope: exit %d, %q", code, stderr)
	}

	// --offline logout cannot tell Cloudflare: a note, and the account goes.
	before := len(e.x.Revoked())
	code, _, stderr = e.run(false, "-v", "--offline", "auth", "logout", "--profile", "limited")
	if code != cli.ExitOK || !strings.Contains(stderr, "could not be revoked") || !strings.Contains(stderr, `profile "limited" removed`) {
		t.Errorf("offline logout: exit %d, %q", code, stderr)
	}
	if len(e.x.Revoked()) != before {
		t.Errorf("--offline revoked: %v", e.x.Revoked())
	}
	e.noSecrets("offline logout", stderr)

	// Logout revokes the refresh token and the access token.
	last := e.secret("acme/cloudflare")
	code, _, stderr = e.run(false, "-v", "auth", "logout", "--profile", "acme")
	if code != cli.ExitOK || strings.Contains(stderr, "could not be revoked") {
		t.Fatalf("logout: exit %d, %q", code, stderr)
	}
	want := []string{"refresh_token:" + last[cloudflare.SecretRefreshToken], "access_token:" + last[cloudflare.SecretAccessToken]}
	if got := e.x.Revoked(); !reflect.DeepEqual(got[len(got)-2:], want) {
		t.Errorf("revoked = %d request(s), want the refresh token then the access token of the account", len(got))
	}
	e.noSecrets("logout", stderr)
	if _, err := creds.NewFile(e.dir).Get("acme/cloudflare"); err == nil {
		t.Error("the secret is still stored after the logout")
	}
}

// Ctrl-C while the login waits for the browser leaves it like any other
// question: "cancelled", exit code 0, nothing stored.
func TestCLIBrowserLoginCancelled(t *testing.T) {
	e := newCLIEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	start := time.Now()
	code, stdout, stderr := e.runWith(ctx, true, func(string) { cancel() }, "auth", "login", "cloudflare", "--set", "method=oauth", "--no-browser")
	if code != cli.ExitOK || stdout != "" || !strings.HasSuffix(strings.TrimSpace(stderr), "cancelled") {
		t.Fatalf("exit %d, stdout %q, stderr %q", code, stdout, stderr)
	}
	if time.Since(start) > 30*time.Second {
		t.Errorf("the login did not end with the interrupt")
	}
	for _, name := range []string{"credentials.json", "config.yaml"} {
		if _, err := os.Stat(filepath.Join(e.dir, name)); err == nil {
			t.Errorf("a cancelled login wrote %s", name)
		}
	}
}

// A revocation endpoint that fails does not keep the account.
func TestCLILogoutWhenRevocationFails(t *testing.T) {
	e := newCLIEnv(t)
	if code, _, stderr := e.run(true, "auth", "login", "cloudflare", "--set", "method=oauth", "--no-browser"); code != cli.ExitOK {
		t.Fatalf("login: exit %d, %q", code, stderr)
	}
	e.x.FailRevocation(503)
	code, _, stderr := e.run(false, "-v", "auth", "logout", "--profile", "default")
	if code != cli.ExitOK || !strings.Contains(stderr, "could not be revoked (revoke the refresh token: HTTP 503") || !strings.Contains(stderr, `profile "default" removed`) {
		t.Fatalf("logout: exit %d, %q", code, stderr)
	}
	e.noSecrets("logout", stderr)
	if _, err := creds.NewFile(e.dir).Get("default/cloudflare"); err == nil {
		t.Error("the secret is still stored")
	}
}

// A browser login stored in the pre-0.2 layout (one platform per profile,
// the secret under the bare profile name) is moved with every field, and
// then renewed under its new key.
func TestCLILegacyLayoutKeepsBrowserLogin(t *testing.T) {
	e := newCLIEnv(t)
	legacy := "credential_store: file\nprofiles:\n  old:\n    platform: cloudflare\n    credential_backend: file\n    metadata:\n      method: oauth\n      account_id: acc1\n"
	if err := os.WriteFile(filepath.Join(e.dir, "config.yaml"), []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	secret := e.x.Issue(time.Now().Add(time.Hour))
	if err := creds.NewFile(e.dir).Set("old", secret); err != nil {
		t.Fatal(err)
	}
	if code, stdout, stderr := e.run(false, "-v", "cloudflare", "zone", "list", "--profile", "old"); code != cli.ExitOK || !strings.Contains(stdout, "example.com") {
		t.Fatalf("zone list: exit %d, %q %q", code, stdout, stderr)
	}
	if got := e.secret("old/cloudflare"); !reflect.DeepEqual(got, secret) {
		t.Errorf("migrated secret has the keys %v, want it unchanged", keysOf(got))
	}
	if _, err := creds.NewFile(e.dir).Get("old"); err == nil {
		t.Error("the legacy entry survived")
	}
	secret[cloudflare.SecretExpiry] = time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	if err := creds.NewFile(e.dir).Set("old/cloudflare", secret); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := e.run(false, "-v", "cloudflare", "zone", "list", "--refresh", "--profile", "old"); code != cli.ExitOK || e.x.Refreshes() != 1 {
		t.Fatalf("zone list after the move: exit %d, %d refreshes, %q", code, e.x.Refreshes(), stderr)
	}
	e.noSecrets("legacy", "")
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}
