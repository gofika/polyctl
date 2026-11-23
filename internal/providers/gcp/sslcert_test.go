package gcp

import (
	"crypto"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// harnessNow is the time of the harness clock.
var harnessNow = time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)

var testCA = certtest.New("Test Issuer")

// pemPair is a certificate chain and its key, written to files.
type pemPair struct {
	chain, key []byte
	certFile   string
	keyFile    string
	fp         string
}

// newPair issues a certificate of names valid until days after the
// harness clock, written to dir.
func newPair(t *testing.T, names []string, days int) pemPair {
	t.Helper()
	k := certtest.Key()
	return pairWith(t, k, k, names, days)
}

func pairWith(t *testing.T, certKey, fileKey crypto.Signer, names []string, days int) pemPair {
	t.Helper()
	chain := testCA.Issue(certKey.Public(), names, harnessNow.Add(-24*time.Hour), harnessNow.Add(time.Duration(days)*24*time.Hour))
	key := certtest.KeyPEM(fileKey)
	dir := t.TempDir()
	p := pemPair{chain: chain, key: key, certFile: filepath.Join(dir, "fullchain.pem"), keyFile: filepath.Join(dir, "privkey.pem")}
	if err := os.WriteFile(p.certFile, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p.keyFile, key, 0o600); err != nil {
		t.Fatal(err)
	}
	_, p.fp, _ = platform.LeafOf(string(chain))
	return p
}

func TestCertSlugAndBaseName(t *testing.T) {
	cfg := &config.Config{}
	day := time.Date(2026, 11, 17, 12, 0, 0, 0, time.UTC)
	for domain, want := range map[string]string{
		"163.com":         "cert-163-com-cert-20261117",
		"*.example.com":   "wildcard-example-com-cert-20261117",
		"Example.COM.":    "example-com-cert-20261117",
		"*.163.com":       "wildcard-163-com-cert-20261117",
		"a_b.example.com": "a-b-example-com-cert-20261117",
	} {
		if got, err := certBaseName(cfg, domain, day); err != nil || got != want {
			t.Errorf("certBaseName(%q) = %q, %v; want %q", domain, got, err, want)
		}
	}
	long := strings.Repeat("abcdefghij.", 6) + "example.com"
	got, err := certBaseName(cfg, long, day)
	if err != nil || len(got) > 60 || !strings.HasSuffix(got, "-cert-20261117") || checkCertName(got+"-99") != nil {
		t.Errorf("long = %q (%d), %v", got, len(got), err)
	}
	if again, _ := certBaseName(cfg, long, day); again != got {
		t.Errorf("long name is not stable: %q vs %q", again, got)
	}
	if n := certNameN("x-cert-20261117", 3); n != "x-cert-20261117-3" || certNameN("x", 1) != "x" {
		t.Errorf("certNameN = %q", n)
	}
	custom := &config.Config{Naming: map[string]string{"gcp_ssl_certificate": "{name}-x"}}
	if _, err := certBaseName(custom, "example.com", day); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("custom template = %v", err)
	}
	custom.Naming["gcp_ssl_certificate"] = "lb-{slug}-{date}"
	if got, err := certBaseName(custom, "example.com", day); err != nil || got != "lb-example-com-20261117" {
		t.Errorf("custom = %q, %v", got, err)
	}
}

func TestPortRangeCovers(t *testing.T) {
	for pr, want := range map[string]bool{"443-443": true, "80-443": true, "443": true, "80-80": false, "": false, "444-500": false, "x": false} {
		if got := portRangeCovers(pr, 443); got != want {
			t.Errorf("portRangeCovers(%q) = %v", pr, got)
		}
	}
}

func TestSSLCertificateCreate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	p := newPair(t, []string{"example.com", "*.example.com"}, 90)
	if err := h.run("compute", "ssl-certificate", "create", "example-com-cert-20260101", "--cert-file", p.certFile, "--key-file", p.keyFile, "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if got := rows(h.report()); len(got) != 1 || !strings.HasPrefix(got[0], "ssl-certificate/example-com-cert-20260101 created regional, us-central1, example.com,*.example.com, expires 2026-04-01") {
		t.Errorf("report = %v", got)
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST us-central1/sslCertificates"}) {
		t.Errorf("writes = %v", w)
	}
	sc := h.gce.cert("us-central1", "example-com-cert-20260101")
	if sc == nil || sc.Description != "SSL certificate for example.com" || sc.Type != certSelfManaged {
		t.Fatalf("cert = %+v", sc)
	}
	// The inventory knows it.
	db, _ := h.rt.DB()
	inv, _ := db.List(t.Context(), inventory.Query{Platform: platform.GCP, Profile: "lab", Type: platform.ResCertificate})
	if len(inv) != 1 || inv[0].ID != "us-central1/example-com-cert-20260101" {
		t.Errorf("inventory = %+v", inv)
	}
	// Again: exists, a general failure.
	err := h.run("compute", "ssl-certificate", "create", "example-com-cert-20260101", "--cert-file", p.certFile, "--key-file", p.keyFile, "--region", "us-central1")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "already exists") {
		t.Errorf("again = %v", err)
	}
	// Global.
	if err := h.run("compute", "ssl-certificate", "create", "g1", "--cert-file", p.certFile, "--key-file", p.keyFile, "--global", "--description", "mine"); err != nil {
		t.Fatal(err)
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST global/sslCertificates"}) || h.gce.cert("global", "g1").Description != "mine" {
		t.Errorf("global writes = %v", w)
	}
}

func TestSSLCertificateCreateChecksLocally(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	good := newPair(t, []string{"example.com"}, 90)
	expired := newPair(t, []string{"example.com"}, -1)
	mismatch := pairWith(t, certtest.Key(), certtest.Key(), []string{"example.com"}, 90)
	enc := filepath.Join(t.TempDir(), "enc.pem")
	_ = os.WriteFile(enc, []byte("-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----\n"), 0o600)
	for name, args := range map[string][]string{
		"no scope":   {"c1", "--cert-file", good.certFile, "--key-file", good.keyFile},
		"both scope": {"c1", "--cert-file", good.certFile, "--key-file", good.keyFile, "--global", "--region", "us-central1"},
		"bad name":   {"163-com-cert", "--cert-file", good.certFile, "--key-file", good.keyFile, "--global"},
		"dot name":   {"example.com", "--cert-file", good.certFile, "--key-file", good.keyFile, "--global"},
		"expired":    {"c1", "--cert-file", expired.certFile, "--key-file", expired.keyFile, "--global"},
		"mismatch":   {"c1", "--cert-file", mismatch.certFile, "--key-file", mismatch.keyFile, "--global"},
		"encrypted":  {"c1", "--cert-file", good.certFile, "--key-file", enc, "--global"},
		"no key":     {"c1", "--cert-file", good.certFile, "--global"},
		"missing":    {"c1", "--cert-file", "/nonexistent.pem", "--key-file", good.keyFile, "--global"},
	} {
		err := h.run(append([]string{"compute", "ssl-certificate", "create"}, args...)...)
		if exitClass(err) != "usage" {
			t.Errorf("%s: err = %v, want a usage error", name, err)
		}
		if len(h.gce.calls) != 0 {
			t.Errorf("%s: API calls %v", name, h.gce.calls)
		}
	}
}

func TestSSLCertificateCreateFromStdin(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	p := newPair(t, []string{"example.com"}, 90)
	h.rt.Stdin = strings.NewReader(string(p.chain) + string(p.key))
	if err := h.run("compute", "ssl-certificate", "create", "c1", "--cert-file", "@-", "--key-file", "@-", "--global"); err != nil {
		t.Fatal(err)
	}
	if sc := h.gce.cert("global", "c1"); sc == nil || strings.Contains(sc.Certificate, "PRIVATE") {
		t.Errorf("cert = %+v", sc)
	}
}

func TestSSLCertificateList(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	a := newPair(t, []string{"example.com", "*.example.com"}, 90)
	b := newPair(t, []string{"other.com"}, 20)
	h.gce.addCert("us-central1", "web-example-com-cert", a.chain)
	h.gce.addCert("us-central1", "orphan-cert", b.chain)
	h.gce.addManagedCert("global", "managed-cert-1", []string{"www.example.com"}, "")
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", "web-example-com-cert")
	h.gce.addHTTPSProxy("global", "global-https-proxy", "lb-g", "managed-cert-1")
	var list []sslCertView
	if err := h.run("compute", "ssl-certificate", "list"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&list)
	if len(list) != 3 {
		t.Fatalf("list = %+v", list)
	}
	byName := map[string]sslCertView{}
	for _, v := range list {
		byName[v.Name] = v
	}
	w := byName["web-example-com-cert"]
	if w.Scope != "regional" || w.Region != "us-central1" || w.Type != certSelfManaged || w.DaysRemaining == nil || *w.DaysRemaining != 90 ||
		!slices.Equal(w.UsedBy, []string{"proxy-https-web-1"}) || w.ExpireTime != "2026-04-01T00:00:00Z" || len(w.Domains) != 2 {
		t.Errorf("web = %+v", w)
	}
	m := byName["managed-cert-1"]
	if m.Scope != "global" || m.Type != certManaged || m.DaysRemaining != nil || !slices.Equal(m.UsedBy, []string{"global-https-proxy"}) {
		t.Errorf("managed = %+v", m)
	}
	if !strings.Contains(h.stderr.String(), "* 1 self-managed") {
		t.Errorf("stderr = %s", h.stderr.String())
	}
	if err := h.run("compute", "ssl-certificate", "list", "--expiring-in", "30"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&list)
	if len(list) != 1 || list[0].Name != "orphan-cert" {
		t.Errorf("expiring = %+v", list)
	}
	if err := h.run("compute", "ssl-certificate", "list", "--global", "--expiring-in", "30"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" ||
		!strings.Contains(h.stderr.String(), "no certificate expires within 30 days") {
		t.Errorf("empty = %v %s", err, h.stdout.String())
	}
	if err := h.run("compute", "ssl-certificate", "list", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&list)
	if len(list) != 2 {
		t.Errorf("regional = %+v", list)
	}
}

func TestSSLCertificateListTable(t *testing.T) {
	h := newGCPHarness(t, app.Flags{Output: "table"}, nil)
	a := newPair(t, []string{"example.com"}, 90)
	h.gce.addCert("us-central1", "web-example-com-cert", a.chain)
	h.gce.addCert("us-central1", "orphan-cert", a.chain)
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", "web-example-com-cert")
	if err := h.run("compute", "ssl-certificate", "list", "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if out := h.stdout.String(); !strings.Contains(out, "orphan-cert *") || strings.Contains(out, "web-example-com-cert *") || !strings.Contains(out, "USED-BY") {
		t.Errorf("table = %s", out)
	}
}

func TestSSLCertificateUpdate(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	old := newPair(t, []string{"example.com", "*.example.com"}, 10)
	other := newPair(t, []string{"other.com"}, 90)
	h.gce.addCert("us-central1", "example-com-cert-20251001", old.chain)
	h.gce.addCert("us-central1", "other-com-cert", other.chain)
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", "example-com-cert-20251001", "other-com-cert")
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-2", "lb-web-2", "example-com-cert-20251001")
	h.gce.addHTTPSProxy("us-central1", "proxy-https-unrelated", "lb-x", "other-com-cert")
	nw := newPair(t, []string{"example.com", "*.example.com"}, 90)
	// A dry run writes nothing.
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "ssl-certificate", "update", "example-com-cert-20251001", "--cert-file", nw.certFile, "--key-file", nw.keyFile, "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = false
	rep := h.report()
	if !rep.DryRun || len(h.gce.lbWrites()) != 0 || !slices.Contains(rows(rep), "ssl-certificate/example-com-cert-20251001 would_delete old, after switch") {
		t.Errorf("dry run = %v %v", rows(rep), h.gce.lbWrites())
	}
	if err := h.run("compute", "ssl-certificate", "update", "example-com-cert-20251001", "--cert-file", nw.certFile, "--key-file", nw.keyFile, "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	want := []string{
		"ssl-certificate/example-com-cert-20260101 created regional, us-central1, expires 2026-04-01",
		"target-https-proxy/proxy-https-web-1 updated certs: example-com-cert-20251001 -> example-com-cert-20260101",
		"target-https-proxy/proxy-https-web-2 updated certs: example-com-cert-20251001 -> example-com-cert-20260101",
		"ssl-certificate/example-com-cert-20251001 deleted old, no longer referenced",
	}
	if got := rows(h.report()); !slices.Equal(got, want) {
		t.Errorf("report =\n%s\nwant\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	if w := h.gce.lbWrites(); !slices.Equal(w, []string{"POST us-central1/sslCertificates", "POST us-central1/targetHttpsProxies/proxy-https-web-1/setSslCertificates",
		"POST us-central1/targetHttpsProxies/proxy-https-web-2/setSslCertificates", "DELETE us-central1/sslCertificates/example-com-cert-20251001"}) {
		t.Errorf("writes = %v", w)
	}
	// The other certificate stays, in front of the new one.
	if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); !slices.Equal(got, []string{"other-com-cert", "example-com-cert-20260101"}) {
		t.Errorf("proxy certs = %v", got)
	}
	// The same certificate again: unchanged, nothing written.
	if err := h.run("compute", "ssl-certificate", "update", "example-com-cert-20260101", "--cert-file", nw.certFile, "--key-file", nw.keyFile, "--region", "us-central1"); err != nil {
		t.Fatal(err)
	}
	if got := rows(h.report()); len(got) != 1 || !strings.Contains(got[0], "unchanged") || len(h.gce.lbWrites()) != 0 {
		t.Errorf("again = %v", got)
	}
	// Another certificate the same day takes -2.
	third := newPair(t, []string{"example.com"}, 120)
	if err := h.run("compute", "ssl-certificate", "update", "example-com-cert-20260101", "--cert-file", third.certFile, "--key-file", third.keyFile, "--region", "us-central1", "--keep-old"); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	if !strings.HasPrefix(got[0], "ssl-certificate/example-com-cert-20260101-2 created") || got[len(got)-1] != "ssl-certificate/example-com-cert-20260101 skipped old, kept (--keep-old)" {
		t.Errorf("third = %v", got)
	}
	if h.gce.cert("us-central1", "example-com-cert-20260101") == nil {
		t.Error("--keep-old deleted the old certificate")
	}
	// Missing.
	if err := h.run("compute", "ssl-certificate", "update", "nope", "--cert-file", nw.certFile, "--key-file", nw.keyFile, "--region", "us-central1"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
}

func TestSSLCertificateUpdateOldStillInUse(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	old := newPair(t, []string{"example.com"}, 10)
	h.gce.addCert("global", "example-com-old", old.chain)
	h.gce.mu.Lock()
	h.gce.lb().inUseFails = 5
	h.gce.mu.Unlock()
	nw := newPair(t, []string{"example.com"}, 90)
	if err := h.run("compute", "ssl-certificate", "update", "example-com-old", "--cert-file", nw.certFile, "--key-file", nw.keyFile, "--global"); err != nil {
		t.Fatal(err)
	}
	got := rows(h.report())
	if len(got) != 2 || got[1] != "ssl-certificate/example-com-old skipped old, still used by proxy-elsewhere" {
		t.Errorf("report = %v", got)
	}
	deletes := 0
	for _, w := range h.gce.lbWrites() {
		if strings.HasPrefix(w, "DELETE global/sslCertificates/example-com-old") {
			deletes++
		}
	}
	if deletes != 3 {
		t.Errorf("deletes = %d, want 3 attempts", deletes)
	}
}

func TestSSLCertificateDelete(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	p := newPair(t, []string{"example.com"}, 90)
	h.gce.addCert("us-central1", "used", p.chain)
	h.gce.addCert("us-central1", "free", p.chain)
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", "used")
	err := h.run("compute", "ssl-certificate", "delete", "used", "--region", "us-central1", "--yes")
	if exitClass(err) != "general" || !strings.Contains(err.Error(), "proxy-https-web-1") {
		t.Errorf("used = %v", err)
	}
	if err := h.run("compute", "ssl-certificate", "delete", "free", "--region", "us-central1"); exitClass(err) != "usage" {
		t.Errorf("no --yes = %v", err)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "ssl-certificate", "delete", "free", "--region", "us-central1"); err != nil || len(h.gce.lbWrites()) != 0 {
		t.Errorf("dry run = %v %v", err, h.gce.lbWrites())
	}
	h.rt.Flags.DryRun = false
	if err := h.run("compute", "ssl-certificate", "delete", "free", "--region", "us-central1", "--yes"); err != nil {
		t.Fatal(err)
	}
	if h.gce.cert("us-central1", "free") != nil || !slices.Equal(rows(h.report()), []string{"ssl-certificate/free deleted regional, us-central1"}) {
		t.Errorf("deleted = %v", rows(h.report()))
	}
	if err := h.run("compute", "ssl-certificate", "delete", "free", "--region", "us-central1", "--yes"); exitClass(err) != "notfound" {
		t.Errorf("missing = %v", err)
	}
	if err := h.run("compute", "ssl-certificate", "delete", "free"); exitClass(err) != "usage" {
		t.Errorf("no scope = %v", err)
	}
}

func TestSSLCertificateDeleteInteractive(t *testing.T) {
	h := newGCPHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = &scriptedPicker{t: t}
	p := newPair(t, []string{"example.com"}, 90)
	h.gce.addCert("global", "free", p.chain)
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("compute", "ssl-certificate", "delete", "free", "--global"); exitClass(err) != "nothing" || h.gce.cert("global", "free") == nil {
		t.Errorf("declined = %v", err)
	}
}

func TestSSLCertificateErrorsAndSync(t *testing.T) {
	h := newGCPHarness(t, app.Flags{}, nil)
	p := newPair(t, []string{"example.com"}, 90)
	h.gce.fail["POST /projects/proj/regions/us-central1/sslCertificates"] = fakeErr{403, "forbidden", "Required 'compute.regionSslCertificates.create' permission for 'projects/proj'"}
	err := h.run("compute", "ssl-certificate", "create", "c1", "--cert-file", p.certFile, "--key-file", p.keyFile, "--region", "us-central1")
	if exitClass(err) != "auth" || !strings.Contains(err.Error(), "compute.sslCertificates") {
		t.Errorf("403 = %v", err)
	}
	h.gce.addCert("us-central1", "a", p.chain)
	h.gce.addCert("global", "b", p.chain)
	c, err := openProfile(t.Context(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	res, err := c.Sync(t.Context(), platform.ResCertificate)
	if err != nil || len(res) != 2 || res[0].ID != "global/b" || res[1].ID != "us-central1/a" {
		t.Errorf("sync = %+v, %v", res, err)
	}
}
