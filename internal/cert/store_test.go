package cert

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/platform"
)

func TestRootDomain(t *testing.T) {
	for in, want := range map[string]string{
		"example.com":       "example.com",
		"www.example.com":   "example.com",
		"*.example.com":     "example.com",
		"WWW.Example.COM.":  "example.com",
		"a.b.example.co.uk": "example.co.uk",
		"foo.github.io":     "foo.github.io",
		"例子.com":            "xn--fsqu00a.com",
	} {
		got, err := RootDomain(in)
		if err != nil || got != want {
			t.Errorf("RootDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, bad := range []string{"", "com", "localhost", "203.0.113.1", "https://example.com/", "example.com:443"} {
		if _, err := RootDomain(bad); !errors.Is(err, platform.ErrInvalidInput) {
			t.Errorf("RootDomain(%q) = %v, want invalid input", bad, err)
		}
	}
}

// testBundle issues a certificate of names valid until notAfter.
func testBundle(t *testing.T, ca *certtest.CA, root string, names []string, notAfter time.Time) *Bundle {
	t.Helper()
	key := certtest.Key()
	chain := ca.Issue(key.Public(), names, time.Now().Add(-time.Hour), notAfter)
	b, err := NewBundle(root, chain, certtest.KeyPEM(key))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestBundleFields(t *testing.T) {
	ca := certtest.New("Fake R1")
	now := time.Now()
	b := testBundle(t, ca, "example.com", []string{"*.example.com", "example.com"}, now.Add(63*24*time.Hour+time.Hour))
	if !slices.Equal(b.Names, []string{"example.com", "*.example.com"}) || !b.CoversRoot() {
		t.Errorf("names = %v", b.Names)
	}
	if b.DaysLeft(now) != 63 || b.KeyType != KeyEC256 || KeyLabel(b.KeyType) != "ecdsa-p256" {
		t.Errorf("days %d key %s", b.DaysLeft(now), b.KeyType)
	}
	// Serial: byte-aligned hex, the leading zero of 0x0a.. kept.
	if !strings.HasPrefix(b.Serial, "0a") || len(b.Serial)%2 != 0 {
		t.Errorf("serial = %q", b.Serial)
	}
	if len(b.Fingerprint) != 64 || b.Subject != "CN=*.example.com" || !strings.Contains(b.Issuer, "CN=Fake R1") || b.Staging() {
		t.Errorf("bundle = %+v", b)
	}
	if strings.Count(string(b.ChainPEM), "BEGIN CERTIFICATE") != 2 || strings.Count(string(b.CertPEM), "BEGIN CERTIFICATE") != 1 ||
		strings.Count(string(b.FullchainPEM), "BEGIN CERTIFICATE") != 3 || !strings.Contains(string(b.PrivKeyPEM), "BEGIN PRIVATE KEY") {
		t.Errorf("pem split wrong")
	}
	for host, want := range map[string]bool{"example.com": true, "www.example.com": true, "a.b.example.com": false, "example.org": false, "WWW.EXAMPLE.COM.": true} {
		if b.Covers(host) != want {
			t.Errorf("Covers(%q) != %v", host, want)
		}
	}
	if !testBundle(t, certtest.New("(STAGING) Fake"), "example.com", Names("example.com"), now.Add(time.Hour)).Staging() {
		t.Error("staging issuer not recognized")
	}
	// Expired: days left is negative, not 0.
	exp := testBundle(t, ca, "example.com", Names("example.com"), now.Add(-time.Hour))
	if exp.DaysLeft(now) != -1 {
		t.Errorf("expired days = %d", exp.DaysLeft(now))
	}
}

func TestBundleRejectsForeignKey(t *testing.T) {
	ca := certtest.New("Fake R1")
	chain := ca.Issue(certtest.Key().Public(), Names("example.com"), time.Now(), time.Now().Add(time.Hour))
	if _, err := NewBundle("example.com", chain, certtest.KeyPEM(certtest.Key())); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("err = %v", err)
	}
}

func mode(t *testing.T, path string) os.FileMode {
	t.Helper()
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return fi.Mode().Perm()
}

func TestStoreSaveLoadArchive(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "certs")
	s := OpenStore(dir, LetsEncryptProduction)
	if b, err := s.Load("example.com", true); err != nil || b != nil {
		t.Fatalf("empty store: %v %v", b, err)
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("loading created the store")
	}
	ca := certtest.New("Fake R1")
	for i := range 5 {
		b := testBundle(t, ca, "example.com", Names("example.com"), time.Now().Add(time.Duration(i+1)*24*time.Hour))
		if i == 0 {
			if err := s.SavePendingKey("example.com", b.Key); err != nil {
				t.Fatal(err)
			}
		}
		at := time.Date(2026, 1, 1, 0, 0, i, 0, time.UTC)
		s.Now = func() time.Time { return at }
		if err := s.Save(b); err != nil {
			t.Fatal(err)
		}
	}
	live := s.LivePath("example.com")
	for _, f := range []string{fileFullchain, fileCert, fileChain, filePrivKey, fileMeta} {
		if _, err := os.Stat(filepath.Join(live, f)); err != nil {
			t.Errorf("missing %s", f)
		}
	}
	if runtime.GOOS != "windows" {
		if m := mode(t, filepath.Join(live, filePrivKey)); m != 0o600 {
			t.Errorf("privkey mode %o", m)
		}
		if m := mode(t, dir); m != 0o700 {
			t.Errorf("store mode %o", m)
		}
		if m := mode(t, live); m != 0o700 {
			t.Errorf("live mode %o", m)
		}
	}
	if names, _ := s.archiveNames("example.com"); len(names) != archiveKeep {
		t.Errorf("archive = %v", names)
	}
	if _, err := os.Stat(s.PendingKeyPath("example.com")); !os.IsNotExist(err) {
		t.Error("pending key kept after save")
	}
	b, err := s.Load("example.com", true)
	if err != nil || b == nil || b.Path != live || b.ACMEDirectory != LetsEncryptProduction || b.IssuedAt.IsZero() {
		t.Fatalf("load = %+v, %v", b, err)
	}
	if roots, _ := s.List(); !slices.Equal(roots, []string{"example.com"}) {
		t.Errorf("list = %v", roots)
	}
}

func TestStoreRestoresArchiveAndFixesMode(t *testing.T) {
	s := OpenStore(t.TempDir(), LetsEncryptProduction)
	var warnings []string
	s.Warnf = func(f string, a ...any) { warnings = append(warnings, f) }
	ca := certtest.New("Fake R1")
	for range 2 {
		if err := s.Save(testBundle(t, ca, "example.com", Names("example.com"), time.Now().Add(48*time.Hour))); err != nil {
			t.Fatal(err)
		}
	}
	live := s.LivePath("example.com")
	if err := os.RemoveAll(live); err != nil {
		t.Fatal(err)
	}
	// Read-only: reported, nothing written.
	b, err := s.Load("example.com", false)
	if err != nil || b == nil || !strings.Contains(b.Path, "archive") || len(warnings) != 1 {
		t.Fatalf("read-only load = %+v, %v, %v", b, err, warnings)
	}
	if _, err := os.Stat(live); !os.IsNotExist(err) {
		t.Fatal("read-only load restored the archive")
	}
	b, err = s.Load("example.com", true)
	if err != nil || b == nil || b.Path != live || len(warnings) != 2 {
		t.Fatalf("repair load = %+v, %v, %v", b, err, warnings)
	}
	if runtime.GOOS == "windows" {
		return
	}
	key := filepath.Join(live, filePrivKey)
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load("example.com", false); err != nil || mode(t, key) != 0o644 {
		t.Fatalf("read-only load changed the mode")
	}
	if _, err := s.Load("example.com", true); err != nil || mode(t, key) != 0o600 {
		t.Fatalf("mode not fixed: %o", mode(t, key))
	}
}

func TestStoreCorruptAndMigration(t *testing.T) {
	s := OpenStore(t.TempDir(), LetsEncryptProduction)
	ca := certtest.New("Fake R1")
	b := testBundle(t, ca, "example.com", Names("example.com"), time.Now().Add(48*time.Hour))
	live := s.LivePath("example.com")
	if err := os.MkdirAll(live, 0o700); err != nil {
		t.Fatal(err)
	}
	// What a copy from certbot leaves: fullchain and privkey only.
	_ = os.WriteFile(filepath.Join(live, fileFullchain), b.FullchainPEM, 0o644)
	_ = os.WriteFile(filepath.Join(live, filePrivKey), b.PrivKeyPEM, 0o600)
	got, err := s.Load("example.com", false)
	if err != nil || got.Serial != b.Serial {
		t.Fatalf("migrated load = %v", err)
	}
	_ = os.WriteFile(filepath.Join(live, filePrivKey), certtest.KeyPEM(certtest.Key()), 0o600)
	if _, err := s.Load("example.com", false); !errors.Is(err, ErrCorrupt) {
		t.Fatalf("foreign key: %v", err)
	}
}

func TestStagingStoreIsSeparate(t *testing.T) {
	dir := t.TempDir()
	staging := OpenStore(dir, LetsEncryptStaging)
	if staging.Base != filepath.Join(dir, "ca", "acme-staging-v02.api.letsencrypt.org") {
		t.Fatalf("base = %s", staging.Base)
	}
	ca := certtest.New("(STAGING) Fake")
	if err := staging.Save(testBundle(t, ca, "example.com", Names("example.com"), time.Now().Add(48*time.Hour))); err != nil {
		t.Fatal(err)
	}
	if b, err := OpenStore(dir, LetsEncryptProduction).Load("example.com", false); err != nil || b != nil {
		t.Fatalf("production store sees the staging certificate: %v %v", b, err)
	}
}

func TestAccounts(t *testing.T) {
	s := OpenStore(t.TempDir(), LetsEncryptStaging)
	if a, err := s.LoadAccount("ops@example.net"); err != nil || a != nil {
		t.Fatalf("no account: %v %v", a, err)
	}
	a, err := s.NewAccount("ops@example.net")
	if err != nil {
		t.Fatal(err)
	}
	a.URI = "https://acme.test/acme/acct/12345"
	a.RegisteredAt = time.Now()
	if err := s.SaveAccount(a); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && mode(t, filepath.Join(a.Dir, fileAccountKey)) != 0o600 {
		t.Error("account key mode")
	}
	got, err := s.LoadAccount("OPS@example.net")
	if err != nil || got == nil || got.URI != a.URI || got.ID() != "12345" || !samePublicKey(got.Key.Public(), a.Key.Public()) {
		t.Fatalf("load = %+v, %v", got, err)
	}
	all, err := s.Accounts()
	if err != nil || len(all) != 1 || all[0].Email != "ops@example.net" {
		t.Fatalf("accounts = %v, %v", all, err)
	}
	if !strings.Contains(a.Dir, filepath.Join("accounts", "acme-staging-v02.api.letsencrypt.org")) {
		t.Errorf("dir = %s", a.Dir)
	}
}

func TestLock(t *testing.T) {
	old := lockRetry
	lockRetry = 10 * time.Millisecond
	t.Cleanup(func() { lockRetry = old })
	s := OpenStore(t.TempDir(), LetsEncryptProduction)
	unlock, err := s.Lock(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	// Another root is not blocked.
	other, err := s.Lock(context.Background(), "example.org")
	if err != nil {
		t.Fatal(err)
	}
	other()
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	if _, err := s.Lock(ctx, "example.com"); err == nil || !strings.Contains(err.Error(), "another polyctl process") {
		t.Fatalf("second lock: %v", err)
	}
	unlock()
	again, err := s.Lock(context.Background(), "example.com")
	if err != nil {
		t.Fatal(err)
	}
	again()
}
