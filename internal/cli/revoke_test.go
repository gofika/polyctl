package cli

import (
	"errors"
	"reflect"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
)

// grantSecret is a secret shaped like a browser login: several fields, one
// of which is the authorization the platform knows.
func grantSecret(grant string) map[string]string {
	return map[string]string{"token": "access-" + grant, "grant": grant, "expiry": "2030-01-02T03:04:05Z", "scopes": "a b c"}
}

// setupGrants is setupMulti with a/fakePlatform holding a grant; the other
// two accounts keep their plain tokens.
func setupGrants(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir, cfgPath = setupMulti(t)
	if err := creds.NewFile(dir).Set(creds.Key("a", p1), grantSecret("g1")); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath
}

// Removing an account withdraws its authorization on the platform first.
func TestAuthLogoutRevokesAuthorization(t *testing.T) {
	dir, cfgPath := setupGrants(t)
	code, stdout, stderr := mainRun(cfgPath, "auth", "logout", p1, "--profile", "a")
	if code != ExitOK || stdout != "" {
		t.Fatalf("logout: exit %d (stdout %q, stderr %q)", code, stdout, stderr)
	}
	if got := revokedGrants(); !reflect.DeepEqual(got, []string{"a/" + p1 + ":g1"}) {
		t.Errorf("revoked = %v", got)
	}
	if strings.Contains(stderr, "could not be revoked") {
		t.Errorf("stderr = %q", stderr)
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "a/"+p2+" b/"+p2 {
		t.Errorf("accounts = %q", got)
	}
	if got := token(t, dir, creds.Key("a", p1)); got != "" {
		t.Errorf("the secret is still stored: %q", got)
	}

	// Accounts without an authorization (API tokens) are removed as before:
	// the platform is not asked.
	resetFake()
	if code, _, stderr := mainRun(cfgPath, "auth", "logout", "--profile", "b"); code != ExitOK {
		t.Fatalf("logout b: exit %d (stderr %q)", code, stderr)
	}
	if got := revokedGrants(); len(got) != 0 {
		t.Errorf("a token account was revoked: %v", got)
	}
}

// -v says that the authorization was revoked; nothing of the secret is
// printed either way.
func TestAuthLogoutRevokeVerbose(t *testing.T) {
	_, cfgPath := setupGrants(t)
	code, stdout, stderr := mainRun(cfgPath, "-v", "auth", "logout", p1, "--profile", "a")
	if code != ExitOK {
		t.Fatalf("logout: exit %d (stderr %q)", code, stderr)
	}
	if !strings.Contains(stderr, "revoked the "+p1+` authorization of profile "a"`) {
		t.Errorf("stderr = %q", stderr)
	}
	for _, secret := range []string{"access-g1", "g1\n", "2030-01-02"} {
		if strings.Contains(stdout+stderr, secret) {
			t.Errorf("the output shows %q: %q %q", secret, stdout, stderr)
		}
	}
}

// The platform cannot be told: a note, and the account is removed all the
// same, with exit code 0.
func TestAuthLogoutRevokeFailureStillRemoves(t *testing.T) {
	dir, cfgPath := setupGrants(t)
	fakeMu.Lock()
	fakeRevokeErr = errors.New("connection refused")
	fakeMu.Unlock()
	code, _, stderr := mainRun(cfgPath, "auth", "logout", p1, "--profile", "a")
	if code != ExitOK {
		t.Fatalf("logout: exit %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{"note: the " + p1 + ` authorization of profile "a" could not be revoked (connection refused)`, "stays valid on the platform", p1 + ` account removed from profile "a"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr does not say %q: %q", want, stderr)
		}
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "a/"+p2+" b/"+p2 {
		t.Errorf("accounts = %q", got)
	}
	if got := token(t, dir, creds.Key("a", p1)); got != "" {
		t.Errorf("the secret is still stored: %q", got)
	}
}

// --offline never reaches the platform: the same note, without a call.
func TestAuthLogoutOfflineDoesNotRevoke(t *testing.T) {
	dir, cfgPath := setupGrants(t)
	code, _, stderr := mainRun(cfgPath, "--offline", "auth", "logout", "--profile", "a")
	if code != ExitOK {
		t.Fatalf("logout: exit %d (stderr %q)", code, stderr)
	}
	if got := revokedGrants(); len(got) != 0 {
		t.Errorf("--offline called the platform: %v", got)
	}
	if n := strings.Count(stderr, "could not be revoked"); n != 1 || !strings.Contains(stderr, "--offline") {
		t.Errorf("stderr = %q, want one note naming --offline (the token account needs none)", stderr)
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "b/"+p2 {
		t.Errorf("accounts = %q", got)
	}
	if got := token(t, dir, creds.Key("a", p1)); got != "" {
		t.Errorf("the secret is still stored: %q", got)
	}
}

// The interactive removal goes through the same path.
func TestAuthLogoutPickedAccountIsRevoked(t *testing.T) {
	_, cfgPath := setupGrants(t)
	_, stderr, err, _ := runPick(t, cfgPath, []any{[]string{(config.AccountRef{Profile: "a", Platform: fakePlatform}).String()}, true}, "auth", "logout", "--keep-inventory")
	if err != nil {
		t.Fatalf("logout: %v (stderr %q)", err, stderr)
	}
	if got := revokedGrants(); !reflect.DeepEqual(got, []string{"a/" + p1 + ":g1"}) {
		t.Errorf("revoked = %v (stderr %q)", got, stderr)
	}
}

// A rename moves the secret as it is: every field of a browser login
// arrives under the new name, and nothing is revoked.
func TestAuthRenameKeepsEveryFieldOfTheSecret(t *testing.T) {
	dir, cfgPath := setupGrants(t)
	if _, stderr, err := run(t, cfgPath, "auth", "rename", "a", "acme"); err != nil {
		t.Fatalf("rename: %v (stderr %q)", err, stderr)
	}
	got, err := creds.NewFile(dir).Get(creds.Key("acme", p1))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(got, grantSecret("g1")) {
		t.Errorf("secret after the rename = %v", got)
	}
	if _, err := creds.NewFile(dir).Get(creds.Key("a", p1)); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("the old entry is still there: %v", err)
	}
	if got := revokedGrants(); len(got) != 0 {
		t.Errorf("a rename revoked: %v", got)
	}
}
