package cli

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

// cliIssuer is the CA of the cert command tests: it presents both
// challenges through the provider (so that the DNS writes go to the fake
// platform), cleans them up and signs the key of the request.
type cliIssuer struct {
	ca  *certtest.CA
	err error

	mu        sync.Mutex
	accounts  map[string]string
	registers int
	obtains   int
	directory string
}

func (c *cliIssuer) id(a *cert.Account) string {
	der, _ := x509.MarshalPKIXPublicKey(a.Key.Public())
	return string(der)
}

func (c *cliIssuer) ResolveAccount(ctx context.Context, a *cert.Account) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if u, ok := c.accounts[c.id(a)]; ok {
		return u, nil
	}
	return "", cert.ErrAccountNotFound
}

func (c *cliIssuer) Register(ctx context.Context, a *cert.Account) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.registers++
	u := fmt.Sprintf("https://ca.test/acme/acct/%d", 500+c.registers)
	c.accounts[c.id(a)] = u
	return u, nil
}

func (c *cliIssuer) Obtain(ctx context.Context, a *cert.Account, req cert.ObtainRequest) ([]byte, error) {
	c.mu.Lock()
	c.obtains++
	c.mu.Unlock()
	if c.err != nil {
		return nil, c.err
	}
	root := req.Domains[0]
	for i := range req.Domains {
		if err := req.Provider.Present(root, fmt.Sprint("t", i), fmt.Sprint("ka", i)); err != nil {
			return nil, err
		}
	}
	for i := range req.Domains {
		_ = req.Provider.CleanUp(root, fmt.Sprint("t", i), fmt.Sprint("ka", i))
	}
	now := time.Now()
	return c.ca.Issue(req.Key.Public(), []string{"*." + root, root}, now.Add(-time.Minute), now.Add(64*24*time.Hour)), nil
}

// certSetup is a zone example.com on the fake platform, a local resolver
// for every DNS query of the cert commands, and the fake CA.
func certSetup(t *testing.T) (dir, cfgPath string, fc *fakeClient, iss *cliIssuer) {
	t.Helper()
	dir, cfgPath, fc = ensureZone(t)
	resolver := dnstest.Start(t, nil)
	cfg := loadConfig(t, cfgPath)
	cfg.Cert.DNS.Resolvers = []string{resolver.Addr}
	cfg.Cert.DNS.MinResolvers = 1
	cfg.DNS.Resolvers = []string{resolver.Addr}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	iss = &cliIssuer{ca: certtest.New("Fake R1"), accounts: map[string]string{}}
	old := cert.NewIssuer
	cert.NewIssuer = func(directory string, _ func(string, ...any)) cert.Issuer {
		iss.mu.Lock()
		iss.directory = directory
		iss.mu.Unlock()
		return iss
	}
	t.Cleanup(func() { cert.NewIssuer = old })
	return dir, cfgPath, fc, iss
}

type certReport struct {
	Target  cert.ReportTarget `json:"target"`
	DryRun  bool              `json:"dry_run"`
	Changes []platform.Change `json:"changes"`
}

func decodeCertReport(t *testing.T, out string) certReport {
	t.Helper()
	var r certReport
	if err := json.Unmarshal([]byte(out), &r); err != nil {
		t.Fatalf("report %q: %v", out, err)
	}
	return r
}

func TestCertEnsureIssuesAndGetShowsIt(t *testing.T) {
	dir, cfgPath, fc, iss := certSetup(t)
	out, stderr, err := run(t, cfgPath, "cert", "ensure", "www.example.com", "--email", "ops@example.net", "--agree-tos", "-o", "json")
	if err != nil {
		t.Fatalf("ensure: %v (%s)", err, stderr)
	}
	rep := decodeCertReport(t, out)
	if rep.Target.Store != filepath.Join(dir, "certs") || rep.Target.ACME != cert.LetsEncryptProduction || rep.Target.DNS != string(fakePlatform)+"/a" || rep.DryRun {
		t.Errorf("target = %+v", rep.Target)
	}
	if len(rep.Changes) != 2 || rep.Changes[0].Resource != "acme-account/letsencrypt" || rep.Changes[0].Action != platform.Created || rep.Changes[0].ID != "501" ||
		rep.Changes[1].Resource != "cert/example.com" || rep.Changes[1].Action != platform.Created || rep.Changes[1].Attrs["names"] != "example.com,*.example.com" {
		t.Fatalf("changes = %+v", rep.Changes)
	}
	if fc.count("CreateRecord:_acme-challenge.example.com:TXT") != 2 || fc.count("DeleteRecord") != 2 || len(fc.records["z1"]) != 0 {
		t.Errorf("dns calls = %v", fc.calls)
	}
	// Unchanged on the next run: no DNS call, no order.
	before := len(fc.calls)
	out, _, err = run(t, cfgPath, "cert", "ensure", "example.com")
	if err != nil || !strings.HasPrefix(out, "RESOURCE") || !strings.Contains(out, "unchanged") || iss.obtains != 1 || len(fc.calls) != before {
		t.Fatalf("second run = %q, %v (obtains %d, calls %v)", out, err, iss.obtains, fc.calls[before:])
	}

	// cert get: a name below the root finds it; json fields.
	out, _, err = run(t, cfgPath, "cert", "get", "api.example.com", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var v map[string]any
	if err := json.Unmarshal([]byte(out), &v); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"domain", "names", "subject", "issuer", "serial", "not_before", "not_after", "days_left", "key_type", "fingerprint_sha256", "path"} {
		if _, ok := v[k]; !ok {
			t.Errorf("json lacks %s: %s", k, out)
		}
	}
	if v["domain"] != "example.com" || v["key_type"] != "ecdsa-p256" || v["days_left"].(float64) != 63 || v["serial"] != rep.Changes[1].ID {
		t.Errorf("view = %v", v)
	}
	out, _, err = run(t, cfgPath, "cert", "get", "example.com")
	if err != nil || !strings.Contains(out, "DAYS LEFT") || !strings.Contains(out, "example.com, *.example.com") || strings.Contains(out, "PRIVATE KEY") {
		t.Errorf("table = %q, %v", out, err)
	}
	out, stderr, err = run(t, cfgPath, "cert", "get", "example.com", "--print", "fullchain")
	if err != nil || strings.Count(out, "BEGIN CERTIFICATE") != 3 || stderr != "" {
		t.Errorf("fullchain = %q, %q, %v", out, stderr, err)
	}
	out, stderr, err = run(t, cfgPath, "cert", "get", "example.com", "--print", "privkey")
	if err != nil || !strings.HasPrefix(out, "-----BEGIN PRIVATE KEY-----") || !strings.Contains(stderr, "private key") {
		t.Errorf("privkey = %q, %q, %v", out, stderr, err)
	}
	// The inventory knows the certificate.
	out, _, err = run(t, cfgPath, "inventory", "list", "--type", "certificate")
	if err != nil || !strings.Contains(out, "local") || !strings.Contains(out, "example.com") {
		t.Errorf("inventory = %q, %v", out, err)
	}
}

func TestCertEnsureDryRunWritesNothing(t *testing.T) {
	dir, cfgPath, fc, iss := certSetup(t)
	out, stderr, err := run(t, cfgPath, "cert", "ensure", "example.com", "--dry-run", "-o", "json")
	if err != nil {
		t.Fatalf("dry run: %v (%s)", err, stderr)
	}
	rep := decodeCertReport(t, out)
	if !rep.DryRun || len(rep.Changes) != 2 || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[1].Action != platform.WouldCreate {
		t.Fatalf("report = %+v", rep)
	}
	if writes(fc) != 0 || iss.registers+iss.obtains != 0 {
		t.Errorf("dry run wrote: %v", fc.calls)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs")); !os.IsNotExist(err) {
		t.Error("dry run created the store")
	}
}

func TestCertEnsureAccountQuestions(t *testing.T) {
	_, cfgPath, fc, iss := certSetup(t)
	// Non-interactive: both the address and the agreement are required.
	if _, _, err := run(t, cfgPath, "cert", "ensure", "example.com", "--agree-tos"); ExitCodeFor(err) != ExitUsage || !strings.Contains(err.Error(), "cert.email") {
		t.Fatalf("no email = %v", err)
	}
	if _, _, err := run(t, cfgPath, "cert", "ensure", "example.com", "--email", "ops@example.net"); ExitCodeFor(err) != ExitUsage || !strings.Contains(err.Error(), "--agree-tos") {
		t.Fatalf("no agreement = %v", err)
	}
	if writes(fc) != 0 || iss.registers != 0 {
		t.Fatal("wrote before the questions were answered")
	}
	// Interactive: asked, then issued.
	picker := &scriptedPicker{T: t, Answers: []any{"not-an-address", "ops@example.net", true}}
	res := runFlow(t, context.Background(), cfgPath, picker, strings.NewReader(""), "cert", "ensure", "example.com")
	if res.code != ExitOK || iss.registers != 1 || len(picker.Asked) != 3 {
		t.Fatalf("interactive = %+v, asked %v", res, picker.Asked)
	}
	// Declining the terms of service is not a failure.
	_, cfgPath2, _, iss2 := certSetup(t)
	picker = &scriptedPicker{T: t, Answers: []any{"ops@example.net", false}}
	res = runFlow(t, context.Background(), cfgPath2, picker, strings.NewReader(""), "cert", "ensure", "example.com")
	if res.code != ExitOK || iss2.registers != 0 || !errors.Is(res.err, platform.ErrNothingToDo) {
		t.Fatalf("declined = %+v", res)
	}
	// cert.email and cert.agree_tos in the config are enough.
	_, cfgPath3, _, _ := certSetup(t)
	cfg := loadConfig(t, cfgPath3)
	cfg.Cert.Email, cfg.Cert.AgreeTOS = "ops@example.net", true
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := run(t, cfgPath3, "cert", "ensure", "example.com"); err != nil {
		t.Fatalf("config: %v (%s)", err, stderr)
	}
}

func TestCertEnsureRouting(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	const zoneName = "both.example"
	zones := []platform.Zone{{ID: "z-" + zoneName, Name: zoneName}}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, zoneName)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, zoneName)
	cf, gd := client("a"), clientOn("a", fakePlatform2)
	cf.zones, gd.zones = zones, zones
	resolver := dnstest.Start(t, nil)
	cfg := loadConfig(t, cfgPath)
	cfg.Cert.DNS.Resolvers, cfg.Cert.DNS.MinResolvers = []string{resolver.Addr}, 1
	cfg.Cert.Email, cfg.Cert.AgreeTOS = "ops@example.net", true
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	iss := &cliIssuer{ca: certtest.New("Fake R1"), accounts: map[string]string{}}
	old := cert.NewIssuer
	cert.NewIssuer = func(string, func(string, ...any)) cert.Issuer { return iss }
	t.Cleanup(func() { cert.NewIssuer = old })

	_, _, err := run(t, cfgPath, "cert", "ensure", zoneName)
	if ExitCodeFor(err) != ExitAmbiguous || writes(cf)+writes(gd) != 0 {
		t.Fatalf("ambiguous = %v (writes %d)", err, writes(cf)+writes(gd))
	}
	_, _, err = run(t, cfgPath, "cert", "ensure", "nohost.example")
	if ExitCodeFor(err) != ExitNotFound || !strings.Contains(err.Error(), "domain ns check") {
		t.Fatalf("not hosted = %v", err)
	}
	out, stderr, err := run(t, cfgPath, "cert", "ensure", zoneName, "--platform", string(fakePlatform2), "-o", "json")
	if err != nil {
		t.Fatalf("--platform: %v (%s)", err, stderr)
	}
	if rep := decodeCertReport(t, out); rep.Target.DNS != string(fakePlatform2)+"/a" || writes(cf) != 0 || gd.count("CreateRecord") != 2 {
		t.Errorf("report %+v, cf %v, gd %v", rep, cf.calls, gd.calls)
	}
}

func TestCertEnsureFailures(t *testing.T) {
	dir, cfgPath, _, iss := certSetup(t)
	marker := filepath.Join(t.TempDir(), "hook")
	cfg := loadConfig(t, cfgPath)
	cfg.Hooks.OnFailure = "cat > " + marker
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	iss.err = errors.New("CA unavailable")
	out, _, err := run(t, cfgPath, "cert", "ensure", "example.com", "--email", "ops@example.net", "--agree-tos", "-o", "json")
	if ExitCodeFor(err) != ExitError || !strings.Contains(err.Error(), "CA unavailable") || !strings.Contains(err.Error(), "pending") {
		t.Fatalf("failure = %v", err)
	}
	if rep := decodeCertReport(t, out); rep.Changes[len(rep.Changes)-1].Action != platform.Failed {
		t.Errorf("report = %+v", rep)
	}
	hook, rerr := os.ReadFile(marker)
	if rerr != nil || !strings.Contains(string(hook), `"event":"cert.ensure.failed"`) || !strings.Contains(string(hook), `"domain":"example.com"`) {
		t.Errorf("hook = %q, %v", hook, rerr)
	}
	// A usage error notifies nobody.
	_ = os.Remove(marker)
	if _, _, err := run(t, cfgPath, "cert", "ensure", "example.com", "--days", "-1"); ExitCodeFor(err) != ExitUsage {
		t.Fatalf("days = %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("hook called for a usage error")
	}
	if _, _, err := run(t, cfgPath, "cert", "ensure", "example.com", "--offline"); ExitCodeFor(err) != ExitOffline {
		t.Errorf("offline = %v", err)
	}
	for _, args := range [][]string{
		{"cert", "ensure", "example.com", "--key-type", "ec521"},
		{"cert", "ensure", "com"},
		{"cert", "ensure", "example.com", "--timeout", "0s"},
		{"cert", "ensure"},
		{"cert", "get", "example.com", "--print", "pfx"},
	} {
		if _, _, err := run(t, cfgPath, args...); ExitCodeFor(err) != ExitUsage {
			t.Errorf("%v = %v", args, err)
		}
	}
	if _, _, err := run(t, cfgPath, "cert", "get", "example.com"); ExitCodeFor(err) != ExitNotFound || !strings.Contains(err.Error(), "cert ensure example.com") {
		t.Errorf("get missing = %v", err)
	}
	cfg = loadConfig(t, cfgPath)
	cfg.Cert.ACMEDirectory = "https://acme.example.net/directory"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, cfgPath, "cert", "ensure", "example.com", "--staging"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("staging with a custom directory = %v", err)
	}
	_ = dir
}

func TestCertStagingIsSeparate(t *testing.T) {
	dir, cfgPath, _, iss := certSetup(t)
	if _, stderr, err := run(t, cfgPath, "cert", "ensure", "example.com", "--staging", "--email", "ops@example.net", "--agree-tos"); err != nil {
		t.Fatalf("staging: %v (%s)", err, stderr)
	}
	if iss.directory != cert.LetsEncryptStaging {
		t.Errorf("directory = %s", iss.directory)
	}
	if _, err := os.Stat(filepath.Join(dir, "certs", "ca", "acme-staging-v02.api.letsencrypt.org", "live", "example.com")); err != nil {
		t.Errorf("staging store: %v", err)
	}
	if _, _, err := run(t, cfgPath, "cert", "get", "example.com"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("production store sees staging: %v", err)
	}
	if out, _, err := run(t, cfgPath, "cert", "get", "example.com", "--staging"); err != nil || !strings.Contains(out, "example.com") {
		t.Errorf("get --staging = %q, %v", out, err)
	}
}
