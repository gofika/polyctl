package cli

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/miekg/dns"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

var (
	cfNS  = []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	oldNS = []string{"ns1.old-dns.example", "ns2.old-dns.example"}
	aliNS = []string{"ns1.alidns.com", "ns2.alidns.com"}
)

// addFakeAccount gives profile an account on a fake platform with token as
// its secret ("" makes opening it an authentication failure).
func addFakeAccount(t *testing.T, dir, cfgPath, profile string, id platform.ID, token string) {
	t.Helper()
	cfg := loadConfig(t, cfgPath)
	p := cfg.Profiles[profile]
	if p == nil {
		p = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
		cfg.Profiles[profile] = p
	}
	p.Platforms[id] = &config.Account{CredentialBackend: "file"}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if err := creds.NewFile(dir).Set(creds.Key(profile, string(id)), map[string]string{"token": token}); err != nil {
		t.Fatal(err)
	}
}

// nsSetup: profile a hosts example.com on the fake Cloudflare (zone NS
// zoneNS, status) and registers it on the fake GoDaddy (registrar NS
// regNS); the fake resolver returns liveNS.
func nsSetup(t *testing.T, zoneNS []string, status string, regNS, liveNS []string) (dir, cfgPath string, srv *dnstest.Server) {
	t.Helper()
	dir, cfgPath = setup(t, true)
	addFakeAccount(t, dir, cfgPath, "a", fakePlatform2, "secret")
	if zoneNS != nil {
		client("a").zones = []platform.Zone{{ID: "z1", Name: "example.com", Nameservers: zoneNS, Status: status}}
	}
	if regNS != nil {
		clientOn("a", fakePlatform2).domains = []platform.Domain{{Name: "example.com", Nameservers: regNS}}
	}
	answers := map[string]dnstest.Answer{}
	if liveNS != nil {
		answers["example.com"] = dnstest.Answer{NS: liveNS}
	}
	return dir, cfgPath, dnstest.Start(t, answers)
}

func nsCheck(t *testing.T, cfgPath string, srv *dnstest.Server, args ...string) (*app.NSCheckResult, string, error) {
	t.Helper()
	full := append([]string{"domain", "ns", "check"}, args...)
	if srv != nil {
		full = append(full, "--resolver", srv.Addr)
	}
	out, stderr, err := run(t, cfgPath, append(full, "-o", "json")...)
	if err != nil && out == "" {
		return nil, stderr, err
	}
	var res app.NSCheckResult
	if jerr := json.Unmarshal([]byte(out), &res); jerr != nil {
		t.Fatalf("json %q: %v (stderr %s)", out, jerr, stderr)
	}
	return &res, stderr, err
}

func TestDomainNSCheckOK(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", []string{"BOB.ns.cloudflare.com.", "alice.ns.cloudflare.com"}, []string{"ALICE.ns.cloudflare.com.", "bob.ns.cloudflare.com"})
	out, stderr, err := run(t, cfgPath, "domain", "ns", "check", "example.com", "--resolver", srv.Addr, "-o", "json", "--non-interactive")
	if err != nil {
		t.Fatalf("check: %v (%s)", err, stderr)
	}
	var raw map[string]any
	if err := json.Unmarshal([]byte(out), &raw); err != nil {
		t.Fatal(err)
	}
	for _, k := range []string{"domain", "checked_domain", "registrar", "zone", "zones", "live", "provider_guess", "match", "status", "message"} {
		if _, ok := raw[k]; !ok {
			t.Errorf("json lacks %q: %s", k, out)
		}
	}
	var res app.NSCheckResult
	if err := json.Unmarshal([]byte(out), &res); err != nil {
		t.Fatal(err)
	}
	if res.Status != "ok" || res.ProviderGuess != "cloudflare" || res.Live.Resolver != srv.Addr || res.Zone.Status != "active" || res.Zone.Platform != fakePlatform || res.Registrar.Platform != fakePlatform2 {
		t.Errorf("result = %+v", res)
	}
	if strings.Join(res.Registrar.NS, ",") != strings.Join(cfNS, ",") || strings.Join(res.Live.NS, ",") != strings.Join(cfNS, ",") {
		t.Errorf("nameservers not normalized: %+v %+v", res.Registrar.NS, res.Live.NS)
	}
	if m := res.Match; m.RegistrarVsZone == nil || !*m.RegistrarVsZone || m.LiveVsZone == nil || !*m.LiveVsZone || m.RegistrarVsLive == nil || !*m.RegistrarVsLive {
		t.Errorf("match = %+v", m)
	}
	// Read-only: --dry-run is accepted and changes nothing, nothing is written.
	again, _, err := run(t, cfgPath, "domain", "ns", "check", "example.com", "--resolver", srv.Addr, "-o", "json", "--dry-run")
	if err != nil || again != out {
		t.Errorf("--dry-run output differs: %v\n%s\n%s", err, again, out)
	}
	if writes(client("a"))+writes(clientOn("a", fakePlatform2)) != 0 {
		t.Errorf("writes: %v %v", client("a").calls, clientOn("a", fakePlatform2).calls)
	}
	// The table is a key-value block on stdout.
	table, _, err := run(t, cfgPath, "domain", "ns", "check", "example.com", "--resolver", srv.Addr)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"DOMAIN", "STATUS", "OK", "REGISTRAR NS", "ZONE NS", "zone status=active", "LIVE NS", "PROVIDER GUESS", "cloudflare", "CONCLUSION"} {
		if !strings.Contains(table, want) {
			t.Errorf("table lacks %q:\n%s", want, table)
		}
	}
}

// A pending Cloudflare zone the registrar does not point to yet is a
// mismatch; the report still exits 0.
func TestDomainNSCheckMismatchIsAReport(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "pending", oldNS, oldNS)
	res, _, err := nsCheck(t, cfgPath, srv, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Status != "mismatch" || res.Zone.Status != "pending" || !strings.Contains(res.Message, "set the nameservers at the registrar") || *res.Match.RegistrarVsLive != true {
		t.Errorf("result = %+v", res)
	}
	table, _, _ := run(t, cfgPath, "domain", "ns", "check", "example.com", "--resolver", srv.Addr)
	if !strings.Contains(table, "MISMATCH") || !strings.Contains(table, "live != zone") {
		t.Errorf("table:\n%s", table)
	}
}

func TestDomainNSCheckPartial(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", cfNS, []string{cfNS[0], oldNS[0]})
	if res, _, err := nsCheck(t, cfgPath, srv, "example.com"); err != nil || res.Status != "partial" {
		t.Errorf("partial = %+v, %v", res, err)
	}
}

// Several hosted zones are all listed, not ambiguous; --platform narrows.
func TestDomainNSCheckListsEveryZone(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", nil, aliNS)
	clientOn("a", fakePlatform2).zones = []platform.Zone{{ID: "example.com", Name: "example.com", Nameservers: aliNS}}
	res, _, err := nsCheck(t, cfgPath, srv, "example.com")
	if err != nil {
		t.Fatalf("two zones: %v", err)
	}
	if len(res.Zones) != 2 || res.Zone.Platform != fakePlatform2 || res.Status != "ok" || res.ProviderGuess != "aliyun" || res.Registrar.Available {
		t.Errorf("result = %+v", res)
	}
	for _, z := range res.Zones {
		want := map[platform.ID]string{fakePlatform: "none", fakePlatform2: "equal"}[z.Platform]
		if z.LiveMatch != want {
			t.Errorf("zone %s live_match = %q, want %q", z.Platform, z.LiveMatch, want)
		}
	}
	res, _, err = nsCheck(t, cfgPath, srv, "example.com", "--platform", "cloudflare")
	if err != nil || len(res.Zones) != 1 || res.Zone.Platform != fakePlatform || res.Status != "mismatch" {
		t.Errorf("--platform cloudflare = %+v, %v", res, err)
	}
}

func TestDomainNSCheckNoZone(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, nil, "", oldNS, oldNS)
	res, _, err := nsCheck(t, cfgPath, srv, "example.com")
	if err != nil || res.Status != "no-zone" || res.Zone.Available || len(res.Zones) != 0 {
		t.Errorf("no zone = %+v, %v", res, err)
	}
	// On a named platform that holds nothing, the domain is not found.
	clientOn("a", fakePlatform2).domains = nil
	if _, _, err := nsCheck(t, cfgPath, srv, "example.com", "--platform", "godaddy", "--refresh"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("--platform without the domain = %v", err)
	}
}

func TestDomainNSCheckLiveOutcomes(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", cfNS, nil)
	res, _, err := nsCheck(t, cfgPath, srv, "example.com")
	if err != nil || res.Status != "no-live" || res.Live.Result != "NXDOMAIN" || !res.Live.Available || len(res.Live.NS) != 0 || res.ProviderGuess != "cloudflare" {
		t.Errorf("nxdomain = %+v, %v", res, err)
	}
	srv.Set("example.com", dnstest.Answer{Rcode: dns.RcodeServerFailure})
	if res, _, err := nsCheck(t, cfgPath, srv, "example.com"); err != nil || res.Status != "no-live" || !strings.Contains(res.Live.Reason, "DNSSEC") {
		t.Errorf("servfail = %+v, %v", res, err)
	}
	srv.Set("example.com", dnstest.Answer{SOA: "example.com"})
	if res, _, err := nsCheck(t, cfgPath, srv, "example.com"); err != nil || res.Status != "no-live" || res.Live.Result != "NODATA" {
		t.Errorf("nodata = %+v, %v", res, err)
	}
	// Every resolver times out: the live side is unavailable, which is
	// not no-live, and the command still succeeds.
	res, _, err = nsCheck(t, cfgPath, nil, "example.com", "--resolver", dnstest.Silent(t)+","+dnstest.Silent(t), "--timeout", "100ms")
	if err != nil || res.Live.Available || res.Live.Result != "TIMEOUT" || res.Status != "unknown" {
		t.Errorf("timeouts = %+v, %v", res, err)
	}
	// The first resolver times out, the second answers.
	srv.Set("example.com", dnstest.Answer{NS: cfNS})
	res, _, err = nsCheck(t, cfgPath, nil, "example.com", "--resolver", dnstest.Silent(t), "--resolver", srv.Addr, "--timeout", "100ms")
	if err != nil || res.Status != "ok" || res.Live.Resolver != srv.Addr {
		t.Errorf("second resolver = %+v, %v", res, err)
	}
}

// dns.resolvers and dns.timeout replace the built-in defaults.
func TestDomainNSCheckConfiguredResolvers(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", cfNS, cfNS)
	cfg := loadConfig(t, cfgPath)
	cfg.DNS = config.DNSSettings{Resolvers: []string{srv.Addr}, Timeout: config.Duration(2e9)}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if res, _, err := nsCheck(t, cfgPath, nil, "example.com"); err != nil || res.Status != "ok" || res.Live.Resolver != srv.Addr {
		t.Errorf("configured resolver = %+v, %v", res, err)
	}
}

func TestDomainNSCheckSubdomainAndSkips(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", cfNS, cfNS)
	res, stderr, err := nsCheck(t, cfgPath, srv, "WWW.Example.com.")
	if err != nil || res.Domain != "www.example.com" || res.CheckedDomain != "example.com" || res.Status != "ok" || !strings.Contains(stderr, "registered domain example.com") {
		t.Errorf("subdomain = %+v, %v, %s", res, err, stderr)
	}
	res, _, err = nsCheck(t, cfgPath, srv, "example.com", "--no-registrar")
	if err != nil || !res.Registrar.Skipped || res.Registrar.Available || res.Status != "ok" || clientOn("a", fakePlatform2).count("GetDomain") != 1 {
		t.Errorf("--no-registrar = %+v, %v", res, err)
	}
	res, _, err = nsCheck(t, cfgPath, srv, "example.com", "--no-zone")
	if err != nil || !res.Zone.Skipped || res.Status != "unknown" || res.Match.RegistrarVsLive == nil || !*res.Match.RegistrarVsLive {
		t.Errorf("--no-zone = %+v, %v", res, err)
	}
	// A registrar that does not hold the domain is a fact, not an error.
	clientOn("a", fakePlatform2).domains = nil
	res, _, err = nsCheck(t, cfgPath, srv, "example.com", "--refresh")
	if err != nil || res.Registrar.Available || !strings.Contains(res.Registrar.Reason, "not in a registrar account") || res.Status != "ok" {
		t.Errorf("no registrar = %+v, %v", res, err)
	}
}

func TestDomainNSCheckUsage(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", cfNS, cfNS)
	cases := map[string][]string{
		"both skipped":  {"example.com", "--no-registrar", "--no-zone", "--resolver", srv.Addr},
		"localhost":     {"localhost", "--resolver", srv.Addr},
		"ip":            {"1.2.3.4", "--resolver", srv.Addr},
		"bare suffix":   {"co.uk", "--resolver", srv.Addr},
		"url":           {"https://example.com", "--resolver", srv.Addr},
		"with port":     {"example.com:443", "--resolver", srv.Addr},
		"bad resolver":  {"example.com", "--resolver", "dns.google"},
		"zero timeout":  {"example.com", "--resolver", srv.Addr, "--timeout", "0s"},
		"no domain":     {},
		"two domains":   {"example.com", "example.org"},
		"bad platform":  {"example.com", "--platform", "nosuch"},
		"empty resolve": {"example.com", "--resolver", ""},
	}
	for name, args := range cases {
		if _, _, err := run(t, cfgPath, append([]string{"domain", "ns", "check"}, args...)...); ExitCodeFor(err) != ExitUsage {
			t.Errorf("%s: %v, want a usage error", name, err)
		}
	}
	if _, _, err := run(t, cfgPath, "domain", "ns", "check", "example.com", "--offline"); ExitCodeFor(err) != ExitOffline {
		t.Errorf("--offline = %v", err)
	}
	// GCP holds no registered domains: with --no-zone nothing is left.
	if _, _, err := run(t, cfgPath, "domain", "ns", "check", "example.com", "--platform", "gcp", "--no-zone"); ExitCodeFor(err) != ExitNotSupported {
		t.Errorf("--platform gcp --no-zone = %v", err)
	}
	if _, _, err := run(t, cfgPath, "domain", "ns", "check", "example.com", "--profile", "nosuch"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("unknown profile = %v", err)
	}
}

func TestDomainNSCheckFailures(t *testing.T) {
	_, cfgPath, srv := nsSetup(t, cfNS, "active", cfNS, cfNS)
	// Index both sides first.
	if _, _, err := nsCheck(t, cfgPath, srv, "example.com"); err != nil {
		t.Fatal(err)
	}
	boom := errors.New("api exploded")
	client("a").zoneErr = boom
	// One side fails: reported, exit 0.
	res, _, err := nsCheck(t, cfgPath, srv, "example.com")
	if err != nil || res.Zone.Available || res.Status != "unknown" || !strings.Contains(res.Zone.Reason, "api exploded") || !res.Registrar.Available {
		t.Errorf("zone failure = %+v, %v", res, err)
	}
	// Every side fails: the report is printed and the exit code is 1.
	clientOn("a", fakePlatform2).domainErr = boom
	res, _, err = nsCheck(t, cfgPath, nil, "example.com", "--resolver", dnstest.Silent(t), "--timeout", "100ms")
	if ExitCodeFor(err) != ExitError || res == nil || res.Registrar.Available || res.Live.Available {
		t.Errorf("all failed = %+v, %v", res, err)
	}
}

// An account that cannot authenticate leaves its side unavailable; it is
// an authentication error only when the user selected the accounts.
func TestDomainNSCheckAuthFailure(t *testing.T) {
	dir, cfgPath := setup(t, true)
	addFakeAccount(t, dir, cfgPath, "a", fakePlatform2, "")
	if err := creds.NewFile(dir).Set(creds.Key("a", string(fakePlatform)), map[string]string{"token": ""}); err != nil {
		t.Fatal(err)
	}
	srv := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: cfNS}})
	res, _, err := nsCheck(t, cfgPath, srv, "example.com")
	if err != nil || res.Registrar.Available || res.Zone.Available || res.Status != "unknown" {
		t.Errorf("unselected = %+v, %v", res, err)
	}
	if _, _, err := nsCheck(t, cfgPath, srv, "example.com", "--profile", "a"); ExitCodeFor(err) != ExitAuth {
		t.Errorf("--profile a = %v, want an authentication error", err)
	}
}
