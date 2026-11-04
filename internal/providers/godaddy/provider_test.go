package godaddy

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

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
	if res.Metadata["env"] != "ote" || res.Metadata["method"] != "pat" || res.Metadata["key_prefix"] != keyPrefix(testToken) || res.Metadata["base_url"] != srv.URL {
		t.Errorf("metadata: %+v", res.Metadata)
	}
	for k, v := range res.Metadata {
		if v == testToken {
			t.Errorf("metadata %s leaks the token", k)
		}
	}
	if !strings.Contains(res.Label, "first.example") || !strings.Contains(res.Label, keyPrefix(testToken)+"...") || !strings.Contains(res.Label, "personal access token") {
		t.Errorf("label: %q", res.Label)
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
		Options:     map[string]string{"key": testKey, "secret": testSecret, "env": "ote", "base_url": srv.URL},
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
	in.Options = map[string]string{"key": testKey, "env": "ote", "base_url": srv.URL}
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
		"domain": {"list", "get", "ns", "lock", "unlock", "autorenew", "available"},
		"dns":    {"list", "add", "replace", "delete"},
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
	for _, path := range [][]string{{"dns", "add"}, {"dns", "replace"}, {"dns", "delete"}, {"dns", "list"}} {
		c, _, _ := cmd.Find(path)
		for _, flag := range []string{"type", "name"} {
			if c.Flags().Lookup(flag) == nil {
				t.Errorf("%v lacks --%s", path, flag)
			}
		}
	}
	if c, _, _ := cmd.Find([]string{"domain", "ns", "set"}); c == nil || c.Flags().Lookup("ns") == nil {
		t.Error("domain ns set lacks --ns")
	}
}
