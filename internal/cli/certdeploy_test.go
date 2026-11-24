package cli

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

// cliDeployer is a deployer of the fake platform: one target per entry,
// each holding a certificate of its domain that expires at its time.
type cliDeployer struct {
	targets map[string]*cliTarget
	order   []string
	writes  []string
	fail    error
}

type cliTarget struct {
	domain   string
	notAfter time.Time
	serial   string
}

func (d *cliDeployer) ID() string            { return "fake-lb" }
func (d *cliDeployer) Platform() platform.ID { return fakePlatform }

func (d *cliDeployer) Discover(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.DeployTarget, []platform.Change, error) {
	var out []platform.DeployTarget
	for _, id := range d.order {
		t := d.targets[id]
		out = append(out, platform.DeployTarget{Deployer: d.ID(), Platform: fakePlatform, Profile: acct.Profile, Kind: "fake", ID: id, Name: id,
			CurrentCertID: "c-" + t.serial, CurrentDomains: []string{t.domain}, CurrentNotAfter: t.notAfter, CurrentSerial: t.serial})
	}
	return out, nil, nil
}

func (d *cliDeployer) Plan(ctx context.Context, acct *platform.DeployAccount, t platform.DeployTarget, c *platform.DeployCert, o platform.DeployOptions) ([]platform.Step, error) {
	id := t.ID
	return []platform.Step{{Resource: t.Resource(), Action: platform.Updated, Desc: "bind " + c.Root, Attrs: map[string]string{"cert_name": "n-" + c.Root},
		Apply: func(ctx context.Context) (platform.Change, error) {
			if d.fail != nil {
				return platform.Change{}, d.fail
			}
			d.writes = append(d.writes, "bind "+id)
			d.targets[id].serial, d.targets[id].notAfter = c.Serial, c.NotAfter
			return platform.Change{}, nil
		}}}, nil
}

func (d *cliDeployer) Prune(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.Step, error) {
	return []platform.Step{{Resource: platform.DeployResource(d.ID(), acct.Profile, "cert/old"), Action: platform.Deleted, Desc: "expired",
		Apply: func(ctx context.Context) (platform.Change, error) {
			d.writes = append(d.writes, "delete old")
			return platform.Change{}, nil
		}}}, nil
}

// deploySetup is certSetup with an ACME account configured and the fake
// deployer installed with one due target of example.com.
func deploySetup(t *testing.T) (dir, cfgPath string, d *cliDeployer, iss *cliIssuer) {
	t.Helper()
	dir, cfgPath, _, iss = certSetup(t)
	cfg := loadConfig(t, cfgPath)
	cfg.Cert.Email, cfg.Cert.AgreeTOS = "ops@example.net", true
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	d = &cliDeployer{targets: map[string]*cliTarget{
		"lb-1": {domain: "www.example.com", notAfter: time.Now().Add(5 * 24 * time.Hour), serial: "01"},
	}, order: []string{"lb-1"}}
	t.Cleanup(platform.OverrideDeployer(d))
	return dir, cfgPath, d, iss
}

type deployJSON struct {
	Target  cert.DeployScope  `json:"target"`
	DryRun  bool              `json:"dry_run"`
	Changes []platform.Change `json:"changes"`
}

func TestCertDeployIssuesDeploysAndIsIdempotent(t *testing.T) {
	dir, cfgPath, d, iss := deploySetup(t)
	out, stderr, err := run(t, cfgPath, "cert", "deploy", "--all", "--deployer", "fake-lb", "-o", "json")
	if err != nil {
		t.Fatalf("deploy: %v (%s)", err, stderr)
	}
	var rep deployJSON
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	if rep.Target.Scope != "all" || rep.Target.Days != 30 || rep.DryRun {
		t.Errorf("target = %+v", rep.Target)
	}
	var rows []string
	for _, c := range rep.Changes {
		rows = append(rows, c.Resource+" "+string(c.Action))
	}
	if !slices.Equal(rows, []string{"acme-account/letsencrypt created", "cert/example.com created", "fake-lb/a/lb-1 updated"}) || iss.obtains != 1 {
		t.Fatalf("rows = %v (obtains %d)", rows, iss.obtains)
	}
	if a := rep.Changes[2].Attrs; a["deployer"] != "fake-lb" || a["profile"] != "a" || a["domain"] != "example.com" || a["cert_name"] != "n-example.com" {
		t.Errorf("attrs = %v", a)
	}
	hist, err := os.ReadFile(filepath.Join(dir, "certs", "history.log"))
	if err != nil || !strings.Contains(string(hist), `"target":"fake-lb/a/lb-1"`) || !strings.Contains(string(hist), `"deployer":"fake-lb"`) {
		t.Errorf("history = %s, %v", hist, err)
	}
	// Nothing due any more: no order, no write; the table has its header.
	out, _, err = run(t, cfgPath, "cert", "deploy", "--all")
	if err != nil || !strings.HasPrefix(out, "RESOURCE") || !strings.Contains(out, "unchanged") || iss.obtains != 1 || len(d.writes) != 1 {
		t.Errorf("second run = %q, %v (obtains %d, writes %v)", out, err, iss.obtains, d.writes)
	}
	// A named domain: the current certificate is already there.
	out, _, err = run(t, cfgPath, "cert", "deploy", "www.example.com", "-o", "json")
	if err != nil || !strings.Contains(out, "holds the current certificate") || len(d.writes) != 1 {
		t.Errorf("domain run = %q, %v", out, err)
	}
	// --prune-expired --yes deletes without asking.
	if _, stderr, err := run(t, cfgPath, "cert", "deploy", "--all", "--prune-expired", "--yes"); err != nil || !slices.Contains(d.writes, "delete old") {
		t.Errorf("prune = %v (%s) %v", err, stderr, d.writes)
	}
}

func TestCertDeployDryRunAndFailures(t *testing.T) {
	dir, cfgPath, d, iss := deploySetup(t)
	out, stderr, err := run(t, cfgPath, "cert", "deploy", "example.com", "--dry-run", "-o", "json")
	if err != nil {
		t.Fatalf("dry run: %v (%s)", err, stderr)
	}
	var rep deployJSON
	_ = json.Unmarshal([]byte(out), &rep)
	if !rep.DryRun || rep.Target.Scope != "domain" || rep.Target.Domain != "example.com" || len(d.writes) != 0 || iss.obtains+iss.registers != 0 {
		t.Fatalf("dry run = %+v writes %v", rep, d.writes)
	}
	if last := rep.Changes[len(rep.Changes)-1]; last.Resource != "fake-lb/a/lb-1" || last.Action != platform.WouldUpdate {
		t.Errorf("changes = %+v", rep.Changes)
	}
	// A failing target: exit code 1, the hook told once; not in a dry run.
	marker := filepath.Join(dir, "hook.json")
	cfg := loadConfig(t, cfgPath)
	cfg.Hooks.OnFailure = "cat > " + marker
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	d.fail = errors.New("IncorrectStatus.Listener")
	if _, _, err := run(t, cfgPath, "cert", "deploy", "--all", "--dry-run"); err != nil {
		t.Errorf("dry run with a failing target = %v", err)
	}
	if _, err := os.Stat(marker); !os.IsNotExist(err) {
		t.Error("a dry run notified")
	}
	out, _, err = run(t, cfgPath, "cert", "deploy", "--all")
	if ExitCodeFor(err) != ExitError || !strings.Contains(out, "failed") {
		t.Fatalf("failure = %v %q", err, out)
	}
	body, err := os.ReadFile(marker)
	if err != nil || !strings.Contains(string(body), `"event":"cert.deploy.failed"`) || !strings.Contains(string(body), `"deployer":"fake-lb"`) ||
		!strings.Contains(string(body), `"target":"lb-1"`) {
		t.Errorf("hook = %s, %v", body, err)
	}
}

func TestCertDeployUsage(t *testing.T) {
	_, cfgPath, _, _ := deploySetup(t)
	for _, tc := range []struct {
		args []string
		code int
	}{
		{[]string{"cert", "deploy"}, ExitUsage},
		{[]string{"cert", "deploy", "example.com", "--all"}, ExitUsage},
		{[]string{"cert", "deploy", "a.com", "b.com"}, ExitUsage},
		{[]string{"cert", "deploy", "--all", "--prune-expired"}, ExitUsage},
		{[]string{"cert", "deploy", "--all", "--deployer", "nosuch"}, ExitUsage},
		{[]string{"cert", "deploy", "--all", "--days", "-1"}, ExitUsage},
		{[]string{"cert", "deploy", "--all", "--wait", "--no-wait"}, ExitUsage},
		{[]string{"cert", "deploy", "--all", "--platform", "godaddy"}, ExitNotSupported},
		{[]string{"cert", "deploy", "--all", "--platform", "aws", "--deployer", "fake-lb"}, ExitUsage},
		{[]string{"cert", "deploy", "--all", "--offline"}, ExitOffline},
		{[]string{"cert", "deploy", "--all", "--profile", "nosuch"}, ExitNotFound},
		{[]string{"cert", "deploy", "unknown-domain.org"}, ExitNotFound},
	} {
		if _, _, err := run(t, cfgPath, tc.args...); ExitCodeFor(err) != tc.code {
			t.Errorf("%v = %v (exit %d), want exit %d", tc.args, err, ExitCodeFor(err), tc.code)
		}
	}
	// A dry run of --prune-expired needs no --yes.
	if _, _, err := run(t, cfgPath, "cert", "deploy", "--all", "--prune-expired", "--dry-run"); err != nil {
		t.Errorf("dry-run prune = %v", err)
	}
	// cert.skip_accounts naming an unknown deployer is reported.
	cfg := loadConfig(t, cfgPath)
	cfg.Cert.SkipAccounts = []string{"a:nosuch"}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, cfgPath, "cert", "deploy", "--all"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("bad skip_accounts = %v", err)
	}
	cfg.Cert.SkipAccounts = []string{"a"}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if out, stderr, err := run(t, cfgPath, "cert", "deploy", "--all", "-o", "json"); err != nil || !strings.Contains(out, `"changes": []`) || !strings.Contains(stderr, "nothing to deploy") {
		t.Errorf("skipped account = %q %q %v", out, stderr, err)
	}
}

// A root domain whose zone two DNS accounts hold: cert deploy points at
// cert.dns_accounts (its --profile / --platform select deploy accounts),
// and cert.dns_accounts routes the renewal to the account it names.
func TestCertDeployDNSAccountsPicksTheDNSAccount(t *testing.T) {
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
	d := &cliDeployer{targets: map[string]*cliTarget{
		"lb-1": {domain: zoneName, notAfter: time.Now().Add(5 * 24 * time.Hour), serial: "01"},
	}, order: []string{"lb-1"}}
	t.Cleanup(platform.OverrideDeployer(d))

	out, _, err := run(t, cfgPath, "cert", "deploy", zoneName, "--deployer", "fake-lb", "-o", "json")
	if ExitCodeFor(err) != ExitError || !strings.Contains(out, "set cert.dns_accounts: {both.example: ") ||
		strings.Contains(out, "pass --platform") || len(d.writes) != 0 {
		t.Fatalf("ambiguous: %v %s (writes %v)", err, out, d.writes)
	}

	cfg = loadConfig(t, cfgPath)
	cfg.Cert.DNSAccounts = map[string]string{zoneName: string(fakePlatform2) + "/a"}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := run(t, cfgPath, "cert", "deploy", zoneName, "--deployer", "fake-lb"); err != nil {
		t.Fatalf("pinned: %v (%s)", err, stderr)
	}
	if writes(cf) != 0 || gd.count("CreateRecord") != 2 || !slices.Equal(d.writes, []string{"bind lb-1"}) {
		t.Errorf("cf %v, gd %v, writes %v", cf.calls, gd.calls, d.writes)
	}

	// An entry that is not "profile" or "platform/profile" is a usage error.
	cfg.Cert.DNSAccounts = map[string]string{"www." + zoneName: "a"}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, cfgPath, "cert", "deploy", zoneName, "--deployer", "fake-lb"); ExitCodeFor(err) != ExitUsage || !strings.Contains(err.Error(), "is not a root domain") {
		t.Errorf("bad key: %v", err)
	}
}
