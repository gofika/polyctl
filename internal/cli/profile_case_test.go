package cli

import (
	"strings"
	"testing"

	"github.com/zalando/go-keyring"

	"github.com/gofika/polyctl/internal/creds"
)

// foldingKeyring makes the keyring match entry names regardless of letter
// case, as Windows Credential Manager does.
func foldingKeyring(t *testing.T) {
	t.Helper()
	keyring.MockInit()
	fold := func(user string) string { return strings.ToLower(user) }
	t.Cleanup(creds.UseKeyring(
		func(service, user string) (string, error) { return keyring.Get(service, fold(user)) },
		func(service, user, password string) error { return keyring.Set(service, fold(user), password) },
		func(service, user string) error { return keyring.Delete(service, fold(user)) },
	))
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "keyring")
}

// Profile names that differ only in letter case would share one Windows
// Credential Manager entry: creating one next to the other is refused.
func TestProfileNamesDifferingOnlyInCase(t *testing.T) {
	_, cfgPath := setupMulti(t)
	for _, args := range [][]string{
		{"auth", "rename", "b", "A"},
		{"auth", "login", string(fakePlatform), "--profile", "B"},
	} {
		code, _, stderr := mainRun(cfgPath, args...)
		if code != ExitUsage || !strings.Contains(stderr, "differ only in letter case") {
			t.Errorf("%q: exit %d, stderr %q; want a usage error", args, code, stderr)
		}
	}
	cfg := loadConfig(t, cfgPath)
	if accountNames(cfg) != "a/"+p1+" a/"+p2+" b/"+p2 {
		t.Errorf("accounts = %q", accountNames(cfg))
	}
}

// A rename that changes only the letter case keeps the credentials, also in
// a keyring that holds one entry for both names.
func TestAuthRenameOnlyTheCase(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	foldingKeyring(t)
	if code, _, stderr := mainRun(cfgPath, "auth", "rename", "a", "A"); code != ExitOK {
		t.Fatalf("rename: exit %d (stderr %q)", code, stderr)
	}
	store, err := creds.Open("keyring", dir, "")
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{p1, p2} {
		if s, err := store.Get(creds.Key("A", id)); err != nil || s["token"] == "" {
			t.Errorf("credentials of A/%s = %v, %v", id, s, err)
		}
	}
	if code, _, stderr := mainRun(cfgPath, "auth", "status", "--profile", "A"); code != ExitOK {
		t.Errorf("status of the renamed profile: exit %d (stderr %q)", code, stderr)
	}
}
