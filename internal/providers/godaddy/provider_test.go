package godaddy

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func TestProviderRegistered(t *testing.T) {
	p, err := platform.Get(platform.GoDaddy)
	if err != nil {
		t.Fatal(err)
	}
	if p.DisplayName() != "GoDaddy" || len(p.ResourceTypes()) != 3 {
		t.Errorf("provider: %s %v", p.DisplayName(), p.ResourceTypes())
	}
	if !strings.Contains(p.LoginHelp(), keysURL) || !strings.Contains(p.LoginHelp(), "Personal Access Token") || !strings.Contains(p.LoginHelp(), "--set token=") {
		t.Errorf("login help should describe PATs at %s: %q", keysURL, p.LoginHelp())
	}
	if strings.Contains(p.LoginHelp(), "Discount Domain Club") || strings.Contains(p.LoginHelp(), "10+") {
		t.Errorf("login help states the outdated access policy: %q", p.LoginHelp())
	}
	if keysURL != "https://developer.godaddy.com/personal-access-token" {
		t.Errorf("keysURL must point at the PAT page: %s", keysURL)
	}
}

func TestLoginNonInteractivePAT(t *testing.T) {
	f, srv := newFake(t, testKey, testSecret)
	f.addDomain("first.example")
	var stderr bytes.Buffer
	opened := ""
	in := platform.LoginInput{
		ProfileName: "gd",
		Options:     map[string]string{"token": testToken, "env": "ote", "base_url": srv.URL},
		Stdin:       strings.NewReader(""),
		Stdout:      &bytes.Buffer{},
		Stderr:      &stderr,
		OpenBrowser: func(u string) error { opened = u; return nil },
	}
	res, err := (&provider{}).Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "" {
		t.Error("no browser should open when the token is given")
	}
	if res.Secret["token"] != testToken || len(res.Secret) != 1 {
		t.Errorf("secret must hold only the token: %v", keysOf(res.Secret))
	}
	if res.Metadata["env"] != "ote" || res.Metadata["method"] != "pat" || res.Metadata["key_prefix"] != fingerprint(testToken) || res.Metadata["base_url"] != srv.URL {
		t.Errorf("metadata: %+v", res.Metadata)
	}
	for k, v := range res.Metadata {
		if v == testToken || (len(v) >= 4 && strings.Contains(testToken, v)) {
			t.Errorf("metadata %s leaks (part of) the token: %q", k, v)
		}
	}
	if !strings.Contains(res.Label, "first.example") || !strings.Contains(res.Label, "fingerprint "+fingerprint(testToken)) || !strings.Contains(res.Label, "personal access token") {
		t.Errorf("label: %q", res.Label)
	}
	if strings.Contains(res.Label, testToken[:6]) {
		t.Errorf("label leaks the token prefix: %q", res.Label)
	}
	if strings.Contains(stderr.String(), testToken) {
		t.Error("token printed to stderr")
	}
	// The token must be sent as a Bearer header (the fake rejects anything else).
	if got := f.callsMatching("GET /v1/domains?"); len(got) != 1 {
		t.Errorf("verify call: %v", got)
	}
}

func TestLoginNonInteractiveLegacyKey(t *testing.T) {
	f, srv := newFake(t, testKey, testSecret)
	f.addDomain("first.example")
	var stderr bytes.Buffer
	opened := ""
	in := platform.LoginInput{
		ProfileName: "gd",
		Options:     map[string]string{"api_key": testKey, "api_secret": testSecret, "env": "ote", "base_url": srv.URL},
		Stdin:       strings.NewReader(""),
		Stdout:      &bytes.Buffer{},
		Stderr:      &stderr,
		OpenBrowser: func(u string) error { opened = u; return nil },
	}
	res, err := (&provider{}).Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if opened != "" {
		t.Error("no browser should open when key and secret are given")
	}
	if res.Secret["key"] != testKey || res.Secret["secret"] != testSecret || res.Secret["token"] != "" {
		t.Error("secret must hold key and secret")
	}
	if res.Metadata["env"] != "ote" || res.Metadata["method"] != "api_key" || res.Metadata["key_prefix"] != "key123" || res.Metadata["base_url"] != srv.URL {
		t.Errorf("metadata: %+v", res.Metadata)
	}
	for k, v := range res.Metadata {
		if v == testSecret || v == testKey {
			t.Errorf("metadata %s leaks a credential", k)
		}
	}
	if !strings.Contains(res.Label, "first.example") || !strings.Contains(res.Label, "key123...") {
		t.Errorf("label: %q", res.Label)
	}
	if strings.Contains(stderr.String(), testSecret) {
		t.Error("secret printed to stderr")
	}
	// Only one half of the pair is an error, not a prompt.
	in.Options = map[string]string{"api_key": testKey, "env": "ote", "base_url": srv.URL}
	in.Stdin = strings.NewReader("")
	if _, err := (&provider{}).Login(context.Background(), in); err == nil {
		t.Error("a key without a secret (and no stdin) must fail")
	}
}

func TestLoginInteractiveAndVerify(t *testing.T) {
	f, srv := newFake(t, testKey, testSecret)
	f.addDomain("first.example")
	var stderr, stdout bytes.Buffer
	opened := ""
	in := platform.LoginInput{
		Options:     map[string]string{"base_url": srv.URL},
		Existing:    map[string]string{"env": "ote"},
		Interactive: true,
		Stdin:       strings.NewReader(testToken + "\n"),
		Stdout:      &stdout,
		Stderr:      &stderr,
		OpenBrowser: func(u string) error { opened = u; return errors.New("no browser here") },
	}
	res, err := (&provider{}).Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if opened != keysURL {
		t.Errorf("browser should be opened at %s, got %q", keysURL, opened)
	}
	if !strings.Contains(stderr.String(), keysURL) || !strings.Contains(stderr.String(), "Personal Access Token") {
		t.Errorf("guidance missing on stderr: %q", stderr.String())
	}
	if strings.Contains(stderr.String(), "API secret") {
		t.Errorf("the default flow must not ask for an API secret: %q", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("prompts must go to stderr, stdout got %q", stdout.String())
	}
	if res.Metadata["env"] != "ote" || res.Metadata["method"] != "pat" {
		t.Errorf("existing env should be reused and method recorded: %+v", res.Metadata)
	}
	if res.Secret["token"] != testToken {
		t.Error("prompted token not stored")
	}

	// --no-browser: URL is printed, browser never called.
	opened = ""
	stderr.Reset()
	in.Stdin = strings.NewReader(testToken + "\n")
	in.NoBrowser = true
	if _, err := (&provider{}).Login(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	if opened != "" || !strings.Contains(stderr.String(), keysURL) {
		t.Errorf("--no-browser: opened=%q stderr=%q", opened, stderr.String())
	}

	// Wrong token fails verification with ErrUnauthorized.
	in.Stdin = strings.NewReader("wrong\n")
	_, err = (&provider{}).Login(context.Background(), in)
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("wrong token: expected ErrUnauthorized, got %v", err)
	}

	// Legacy pair, asked for explicitly: prompts key then secret.
	stderr.Reset()
	in.Options = map[string]string{"base_url": srv.URL, "method": "api_key"}
	in.Stdin = strings.NewReader(testKey + "\n" + testSecret + "\n")
	res, err = (&provider{}).Login(context.Background(), in)
	if err != nil {
		t.Fatal(err)
	}
	if res.Secret["key"] != testKey || res.Secret["secret"] != testSecret || res.Metadata["method"] != "api_key" {
		t.Errorf("legacy login: secret keys %v metadata %+v", keysOf(res.Secret), res.Metadata)
	}
	if !strings.Contains(stderr.String(), "API key") || !strings.Contains(stderr.String(), "API secret") {
		t.Errorf("legacy prompts missing: %q", stderr.String())
	}

	// Re-authenticating a legacy profile keeps the legacy method.
	in.Options = map[string]string{"base_url": srv.URL}
	in.Existing = map[string]string{"env": "ote", "method": "api_key"}
	in.Stdin = strings.NewReader(testKey + "\n" + testSecret + "\n")
	if res, err = (&provider{}).Login(context.Background(), in); err != nil || res.Metadata["method"] != "api_key" {
		t.Errorf("re-login of legacy profile: %v %+v", err, res)
	}

	// Unknown environment / method are rejected before any prompt.
	in.Options = map[string]string{"env": "staging"}
	if _, err := (&provider{}).Login(context.Background(), in); err == nil || !strings.Contains(err.Error(), "staging") {
		t.Errorf("bad env: %v", err)
	}
	in.Options = map[string]string{"method": "oauth"}
	if _, err := (&provider{}).Login(context.Background(), in); err == nil || !strings.Contains(err.Error(), "oauth") {
		t.Errorf("bad method: %v", err)
	}
}

func keysOf(m map[string]string) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

func TestOpen(t *testing.T) {
	_, srv := newFake(t, testKey, testSecret)
	p := &provider{}
	if _, err := p.Open(context.Background(), platform.Profile{Name: "gd", Platform: platform.GoDaddy}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("missing secret: %v", err)
	}
	if _, err := p.Open(context.Background(), platform.Profile{Name: "gd", Platform: platform.GoDaddy, Secret: map[string]string{"key": testKey}}); !errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("half a key pair: %v", err)
	}
	// PAT layout.
	c, err := p.Open(context.Background(), platform.Profile{Name: "gd", Platform: platform.GoDaddy, Metadata: map[string]string{"env": "ote", "base_url": srv.URL, "method": "pat"}, Secret: map[string]string{"token": testToken}})
	if err != nil {
		t.Fatal(err)
	}
	gc := c.(*client)
	if gc.env != envOTE || gc.api.http.BaseURL != srv.URL || gc.cred.method() != methodPAT {
		t.Errorf("client: env=%s base=%s method=%s", gc.env, gc.api.http.BaseURL, gc.cred.method())
	}
	id, err := c.Verify(context.Background())
	if err != nil || id.Extra["env"] != "ote" || id.Extra["domains"] != "none" || id.Extra["method"] != "pat" {
		t.Errorf("verify: %v %+v", err, id)
	}
	// Legacy layout.
	lc, err := p.Open(context.Background(), platform.Profile{Name: "gd", Platform: platform.GoDaddy, Metadata: map[string]string{"env": "ote", "base_url": srv.URL}, Secret: map[string]string{"key": testKey, "secret": testSecret}})
	if err != nil {
		t.Fatal(err)
	}
	if id, err := lc.Verify(context.Background()); err != nil || id.Extra["method"] != "api_key" {
		t.Errorf("legacy verify: %v %+v", err, id)
	}
	if _, ok := c.(platform.DNSService); !ok {
		t.Error("client must implement DNSService")
	}
	if _, ok := c.(platform.RegistrarService); !ok {
		t.Error("client must implement RegistrarService")
	}
	// Default environment resolves to production.
	c2, _ := p.Open(context.Background(), platform.Profile{Secret: map[string]string{"token": "t"}})
	if c2.(*client).api.http.BaseURL != prodBaseURL {
		t.Errorf("default base url: %s", c2.(*client).api.http.BaseURL)
	}
	if baseURLFor(envOTE) != oteBaseURL {
		t.Error("ote base url")
	}
}

func TestCommandTree(t *testing.T) {
	cmd := Command(nil)
	if cmd.Use != "godaddy" {
		t.Errorf("use: %s", cmd.Use)
	}
	want := map[string][]string{
		"domain": {"list", "get", "ns", "lock", "unlock", "autorenew", "check"},
		"dns":    {"list", "add", "upsert", "delete"},
	}
	for name, subs := range want {
		sub, _, err := cmd.Find([]string{name})
		if err != nil || sub.Name() != name {
			t.Fatalf("missing %s: %v", name, err)
		}
		for _, s := range subs {
			if c, _, err := sub.Find([]string{s}); err != nil || c.Name() != s {
				t.Errorf("missing %s %s", name, s)
			}
		}
	}
	for _, path := range [][]string{{"dns", "add"}, {"dns", "upsert"}, {"dns", "delete"}, {"dns", "list"}} {
		c, _, _ := cmd.Find(path)
		for _, flag := range []string{"type", "name"} {
			if c.Flags().Lookup(flag) == nil {
				t.Errorf("%v lacks --%s", path, flag)
			}
		}
	}
	// Nameservers are positional, and the identity check sits at the top.
	if c, _, _ := cmd.Find([]string{"domain", "ns", "set"}); c == nil || c.Flags().Lookup("ns") != nil || c.Use != "set <domain> <nameserver>..." {
		t.Errorf("domain ns set: %+v", c)
	}
	if c, _, err := cmd.Find([]string{"whoami"}); err != nil || c.Name() != "whoami" {
		t.Errorf("missing whoami: %v", err)
	}
	// The names that were replaced are gone, not aliased.
	for _, path := range [][]string{{"domain", "available"}, {"dns", "replace"}} {
		if c, _, _ := cmd.Find(path); c != nil && c.Name() == path[len(path)-1] {
			t.Errorf("%v still exists", path)
		}
	}
}

// refusingReader fails the test when the login reads stdin.
type refusingReader struct{ t *testing.T }

func (r refusingReader) Read([]byte) (int, error) {
	r.t.Error("stdin was read")
	return 0, io.EOF
}

// The non-interactive flow asks nothing and reads nothing: a missing
// credential is a usage error naming its --set key.
func TestLoginNonInteractiveNeverAsks(t *testing.T) {
	_, srv := newFake(t, testKey, testSecret)
	for _, tc := range []struct {
		name    string
		opts    map[string]string
		want    []string
		wantNot string
	}{
		{"no token", map[string]string{}, []string{"--set token=-"}, "--set key"},
		{"api key pair without values", map[string]string{"method": "api_key"}, []string{"--set api_key=<api key>", "--set api_secret=-"}, "--set token"},
		{"api key without its secret", map[string]string{"api_key": testKey}, []string{"--set api_secret=-"}, "--set api_key="},
		{"api secret without its key", map[string]string{"api_secret": testSecret}, []string{"--set api_key=<api key>"}, "--set api_secret="},
	} {
		tc.opts["base_url"], tc.opts["env"] = srv.URL, "ote"
		var stderr bytes.Buffer
		opened := 0
		_, err := (&provider{}).Login(context.Background(), platform.LoginInput{
			Options: tc.opts, Stdin: refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &stderr,
			OpenBrowser: func(string) error { opened++; return nil },
		})
		if !errors.Is(err, app.ErrUsage) {
			t.Errorf("%s: %v, want a usage error", tc.name, err)
			continue
		}
		for _, w := range tc.want {
			if !strings.Contains(err.Error(), w) {
				t.Errorf("%s: the error does not name %q: %v", tc.name, w, err)
			}
		}
		if strings.Contains(err.Error(), tc.wantNot) {
			t.Errorf("%s: the error names %q: %v", tc.name, tc.wantNot, err)
		}
		if opened != 0 || stderr.Len() != 0 {
			t.Errorf("%s: browser opened %d time(s), stderr %q; want neither", tc.name, opened, stderr.String())
		}
	}
}

// Login options have one spelling per value; the aliases polyctl 0.1.x
// accepted are usage errors now. Metadata stored with such an alias still
// loads.
func TestLoginOptionValuesAreCanonical(t *testing.T) {
	for _, opts := range []map[string]string{
		{"env": "prod"}, {"env": "test"}, {"env": "staging"},
		{"method": "token"}, {"method": "key"}, {"method": "sso-key"}, {"method": "sso_key"}, {"method": "oauth"},
	} {
		in := platform.LoginInput{Options: opts, Stdin: refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
		_, err := (&provider{}).Login(context.Background(), in)
		want := "expected production or ote"
		if opts["method"] != "" {
			want = "expected pat or api_key"
		}
		if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), want) {
			t.Errorf("%v = %v; want a usage error with %q", opts, err, want)
		}
	}
	// A credential given along with the method does not hide an unknown
	// method, and a method that contradicts the credential is refused.
	for _, tc := range []struct {
		opts map[string]string
		want string
	}{
		{map[string]string{"method": "key", "api_key": testKey, "api_secret": testSecret}, "expected pat or api_key"},
		{map[string]string{"method": "keys", "token": testToken}, "expected pat or api_key"},
		{map[string]string{"method": "token", "token": testToken}, "expected pat or api_key"},
		{map[string]string{"method": "api_key", "token": testToken}, "--set method=api_key does not take --set token"},
		{map[string]string{"method": "pat", "api_key": testKey, "api_secret": testSecret}, "--set method=pat does not take --set api_key"},
		{map[string]string{"token": testToken, "api_key": testKey, "api_secret": testSecret}, "not both"},
	} {
		// base_url points nowhere: the login must fail before any request.
		tc.opts["base_url"] = "http://127.0.0.1:1"
		in := platform.LoginInput{Options: tc.opts, Stdin: refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
		if _, err := (&provider{}).Login(context.Background(), in); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%v = %v; want a usage error with %q", tc.opts, err, tc.want)
		}
	}
	// The old key names of the legacy pair are not login options any more:
	// `auth login` refuses them by the list the provider declares.
	for _, k := range []string{"key", "secret", "bogus"} {
		if err := platform.CheckLoginOption(&provider{}, k); err == nil || !strings.Contains(err.Error(), "valid: method, token, api_key, api_secret, env, base_url") {
			t.Errorf("CheckLoginOption(%q) = %v", k, err)
		}
	}
	for _, k := range []string{"method", "token", "api_key", "api_secret", "env", "base_url"} {
		if err := platform.CheckLoginOption(&provider{}, k); err != nil {
			t.Errorf("CheckLoginOption(%q) = %v", k, err)
		}
	}
	in := platform.LoginInput{Options: map[string]string{"key": testKey, "secret": testSecret}, Stdin: refusingReader{t}, Stdout: &bytes.Buffer{}, Stderr: &bytes.Buffer{}}
	if _, err := (&provider{}).Login(context.Background(), in); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--set token=-") {
		t.Errorf("--set key/secret = %v; want the login to see no credential", err)
	}

	for in, want := range map[string]string{"": "", "production": envProduction, "prod": envProduction, "ote": envOTE, "test": envOTE, "OTE": envOTE} {
		if got := storedEnv(in); got != want {
			t.Errorf("storedEnv(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"": "", "pat": methodPAT, "token": methodPAT, "api_key": methodAPIKey, "key": methodAPIKey, "sso-key": methodAPIKey, "sso_key": methodAPIKey} {
		if got := storedMethod(in); got != want {
			t.Errorf("storedMethod(%q) = %q, want %q", in, got, want)
		}
	}
	// An account stored with the old env alias opens against the OTE API,
	// and its key pair is read from the names 0.1.x stored it under.
	c, err := (&provider{}).Open(context.Background(), platform.Profile{Name: "gd", Platform: platform.GoDaddy,
		Metadata: map[string]string{"env": "test"}, Secret: map[string]string{"key": testKey, "secret": testSecret}})
	if err != nil || c.(*client).env != envOTE || c.(*client).cred.method() != methodAPIKey {
		t.Errorf("Open with stored env=test: %+v, %v", c, err)
	}
}
