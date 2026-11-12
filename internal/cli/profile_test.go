package cli

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// setupMulti prepares a config with three accounts in two profiles:
// a/fakePlatform (from setup), a/fakePlatform2 and b/fakePlatform2.
func setupMulti(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir, cfgPath = setup(t, true)
	cfg := loadConfig(t, cfgPath)
	cfg.Profiles["a"].Platforms[fakePlatform2] = &config.Account{CredentialBackend: "file", Metadata: map[string]string{"account": "acct-a2"}}
	cfg.Profiles["b"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
		fakePlatform2: {CredentialBackend: "file", Metadata: map[string]string{"account": "acct-b"}},
	}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	store := creds.NewFile(dir)
	for _, ref := range []config.AccountRef{{Profile: "a", Platform: fakePlatform2}, {Profile: "b", Platform: fakePlatform2}} {
		if err := store.Set(creds.Key(ref.Profile, string(ref.Platform)), map[string]string{"token": "secret-" + ref.String()}); err != nil {
			t.Fatal(err)
		}
	}
	return dir, cfgPath
}

func loadConfig(t *testing.T, cfgPath string) *config.Config {
	t.Helper()
	cfg, err := config.Load(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

// accountNames lists the configured accounts as "profile/platform".
func accountNames(cfg *config.Config) string {
	var out []string
	for _, ref := range cfg.Accounts("") {
		out = append(out, ref.String())
	}
	return strings.Join(out, " ")
}

// token returns the stored token under a credential key, or "" when the key
// does not exist.
func token(t *testing.T, dir, key string) string {
	t.Helper()
	s, err := creds.NewFile(dir).Get(key)
	if errors.Is(err, creds.ErrNotFound) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return s["token"]
}

// seedZone writes one zone for an account into the inventory.
func seedZone(t *testing.T, dir string, ref config.AccountRef, zone string) {
	t.Helper()
	db := openInventory(t, dir)
	defer db.Close()
	set := inventory.Set{Platform: ref.Platform, Profile: ref.Profile, Type: platform.ResZone}
	if err := db.Replace(context.Background(), set, app.ZoneResources([]platform.Zone{{ID: "z-" + zone, Name: zone}}), time.Hour); err != nil {
		t.Fatal(err)
	}
}

// inventoryOwners lists the accounts that still own inventory rows, sync
// state or index entries, as sorted "profile/platform" names.
func inventoryOwners(t *testing.T, dir string) string {
	t.Helper()
	db := openInventory(t, dir)
	defer db.Close()
	ctx := context.Background()
	seen := map[string]bool{}
	rows, err := db.List(ctx, inventory.Query{})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		seen[r.Profile+"/"+string(r.Platform)] = true
	}
	entries, err := db.IndexEntries(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		seen[e.Profile+"/"+string(e.Platform)] = true
	}
	stats, err := db.Stats(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stats {
		seen[s.Profile+"/"+string(s.Platform)] = true
	}
	var out []string
	for _, ref := range []string{"a/" + string(fakePlatform), "a/" + string(fakePlatform2), "b/" + string(fakePlatform2)} {
		if seen[ref] {
			out = append(out, ref)
			delete(seen, ref)
		}
	}
	for k := range seen {
		out = append(out, "unexpected:"+k)
	}
	return strings.Join(out, " ")
}

func TestAuthLoginCreatesDefaultProfile(t *testing.T) {
	dir, cfgPath := setup(t, false)

	_, stderr, err := run(t, cfgPath, "auth", "login", string(fakePlatform), "--set", "account=acct-1")
	if err != nil {
		t.Fatalf("first login: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, `in profile "default"`) || strings.Contains(stderr, "re-authenticating") {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "default/"+string(fakePlatform) {
		t.Fatalf("accounts = %q", got)
	}
	if config.DefaultProfile != "default" || cfg.CurrentProfile != "default" {
		t.Errorf("current_profile = %q, want default", cfg.CurrentProfile)
	}
	acct := cfg.Profiles["default"].Platforms[fakePlatform]
	if acct.CredentialBackend != "file" || acct.Metadata["account"] != "acct-1" || acct.LegacySecret || acct.CreatedAt.IsZero() || acct.UpdatedAt.IsZero() {
		t.Errorf("account = %+v", acct)
	}
	if token(t, dir, creds.Key("default", string(fakePlatform))) != "fake" {
		t.Error("secret is not stored under the profile/platform key")
	}
	if token(t, dir, "default") != "" || token(t, dir, string(fakePlatform)) != "" {
		t.Error("secret stored under a bare profile or platform name")
	}

	// A second platform joins the current profile instead of opening a
	// profile of its own.
	_, stderr, err = run(t, cfgPath, "auth", "login", string(fakePlatform2))
	if err != nil {
		t.Fatalf("second login: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, `in profile "default"`) || strings.Contains(stderr, "re-authenticating") {
		t.Errorf("stderr = %q", stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "default/"+string(fakePlatform)+" default/"+string(fakePlatform2) {
		t.Fatalf("accounts = %q", got)
	}
	if len(cfg.Profiles) != 1 || cfg.CurrentProfile != "default" {
		t.Errorf("profiles = %d, current = %q", len(cfg.Profiles), cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("default", string(fakePlatform2))) != "fake" || token(t, dir, creds.Key("default", string(fakePlatform))) != "fake" {
		t.Error("both accounts must keep their own secret")
	}
	if got := cfg.Profiles["default"].Platforms[fakePlatform].Metadata["account"]; got != "acct-1" {
		t.Errorf("first account metadata changed to %q", got)
	}

	// The saved file uses the per-platform layout.
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"platforms:", string(fakePlatform) + ":", string(fakePlatform2) + ":"} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("config lacks %q:\n%s", want, raw)
		}
	}
	if strings.Contains(string(raw), "legacy_secret") || strings.Contains(string(raw), "platform: ") {
		t.Errorf("config has legacy keys:\n%s", raw)
	}
}

func TestAuthLoginWithProfileFlag(t *testing.T) {
	dir, cfgPath := setup(t, false)
	if _, _, err := run(t, cfgPath, "auth", "login", string(fakePlatform)); err != nil {
		t.Fatal(err)
	}
	_, stderr, err := run(t, cfgPath, "auth", "login", string(fakePlatform), "--profile", "x", "--set", "account=acct-x")
	if err != nil {
		t.Fatalf("login --profile x: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, `in profile "x"`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "default/"+string(fakePlatform)+" x/"+string(fakePlatform) {
		t.Fatalf("accounts = %q", got)
	}
	if cfg.CurrentProfile != "default" {
		t.Errorf("--profile must not change current_profile, got %q", cfg.CurrentProfile)
	}
	if cfg.Profiles["x"].Platforms[fakePlatform].Metadata["account"] != "acct-x" {
		t.Errorf("x account = %+v", cfg.Profiles["x"].Platforms[fakePlatform])
	}
	if token(t, dir, creds.Key("x", string(fakePlatform))) != "fake" {
		t.Error("secret of profile x missing")
	}

	// --profile on an empty config creates that profile and makes it current.
	_, cfgPath2 := setup(t, false)
	if _, _, err := run(t, cfgPath2, "auth", "login", string(fakePlatform2), "-p", "proj"); err != nil {
		t.Fatal(err)
	}
	cfg = loadConfig(t, cfgPath2)
	if got := accountNames(cfg); got != "proj/"+string(fakePlatform2) || cfg.CurrentProfile != "proj" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	// Without --profile the next account lands in the current profile, not
	// in "default".
	if _, _, err := run(t, cfgPath2, "auth", "login", string(fakePlatform)); err != nil {
		t.Fatal(err)
	}
	cfg = loadConfig(t, cfgPath2)
	if got := accountNames(cfg); got != "proj/"+string(fakePlatform)+" proj/"+string(fakePlatform2) {
		t.Errorf("accounts = %q", got)
	}

	// Profile names become part of the credential key.
	for _, bad := range []string{"a/b", "a b", `a\b`} {
		if _, _, err := run(t, cfgPath2, "auth", "login", string(fakePlatform), "--profile", bad); ExitCodeFor(err) != ExitUsage {
			t.Errorf("login --profile %q = %v (exit %d)", bad, err, ExitCodeFor(err))
		}
	}
	if _, _, err := run(t, cfgPath2, "auth", "login", "nosuchplatform"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("login nosuchplatform = %v", err)
	}
}

func TestAuthLoginAgainUpdatesAccount(t *testing.T) {
	dir, cfgPath := setup(t, false)
	if _, _, err := run(t, cfgPath, "auth", "login", string(fakePlatform), "--set", "account=acct-1"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, cfgPath, "auth", "login", string(fakePlatform2), "--set", "account=acct-2"); err != nil {
		t.Fatal(err)
	}
	before := loadConfig(t, cfgPath)
	created := before.Profiles["default"].Platforms[fakePlatform].CreatedAt
	other := *before.Profiles["default"].Platforms[fakePlatform2]

	_, stderr, err := run(t, cfgPath, "auth", "login", string(fakePlatform), "--set", "token=rotated")
	if err != nil {
		t.Fatalf("re-login: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, "re-authenticating the "+string(fakePlatform)+` account of profile "default"`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "default/"+string(fakePlatform)+" default/"+string(fakePlatform2) {
		t.Fatalf("accounts = %q", got)
	}
	acct := cfg.Profiles["default"].Platforms[fakePlatform]
	if !acct.CreatedAt.Equal(created) {
		t.Errorf("created_at changed: %v -> %v", created, acct.CreatedAt)
	}
	if acct.UpdatedAt.Before(created) {
		t.Errorf("updated_at %v is before created_at %v", acct.UpdatedAt, created)
	}
	// The provider saw the existing metadata.
	if acct.Metadata["account"] != "acct-1" {
		t.Errorf("metadata = %v", acct.Metadata)
	}
	if token(t, dir, creds.Key("default", string(fakePlatform))) != "rotated" {
		t.Error("secret was not replaced")
	}
	// The sibling account is untouched.
	sib := cfg.Profiles["default"].Platforms[fakePlatform2]
	if !sib.UpdatedAt.Equal(other.UpdatedAt) || sib.Metadata["account"] != "acct-2" || token(t, dir, creds.Key("default", string(fakePlatform2))) != "fake" {
		t.Errorf("sibling account changed: %+v", sib)
	}
}

func TestAuthListRowsPerAccount(t *testing.T) {
	_, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := run(t, cfgPath, "auth", "list")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 || !strings.Contains(lines[0], "PROFILE") || !strings.Contains(lines[0], "PLATFORM") {
		t.Fatalf("table = %q", stdout)
	}
	want := [][]string{
		{"*", "a", string(fakePlatform), "file", "account=acct-a"},
		{"*", "a", string(fakePlatform2), "file", "account=acct-a2"},
		{"b", string(fakePlatform2), "file", "account=acct-b"},
	}
	for i, w := range want {
		if got := strings.Fields(lines[i+1]); strings.Join(got, "|") != strings.Join(w, "|") {
			t.Errorf("row %d = %q, want %q", i, got, w)
		}
	}

	stdout, _, err = run(t, cfgPath, "auth", "list", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	var rows []profileRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("json %q: %v", stdout, err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	type key struct {
		name     string
		platform platform.ID
		current  bool
		account  string
	}
	wantRows := []key{
		{"a", fakePlatform, true, "acct-a"},
		{"a", fakePlatform2, true, "acct-a2"},
		{"b", fakePlatform2, false, "acct-b"},
	}
	for i, w := range wantRows {
		r := rows[i]
		if got := (key{r.Name, r.Platform, r.Current, r.Metadata["account"]}); got != w || r.Backend != "file" {
			t.Errorf("row %d = %+v, want %+v", i, r, w)
		}
	}
}

func TestAuthStatusRowsPerAccount(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "b"); err != nil {
		t.Fatal(err)
	}

	stdout, stderr, err := run(t, cfgPath, "auth", "status", "-o", "json")
	if err != nil {
		t.Fatalf("auth status: %v (stderr %q)", err, stderr)
	}
	var rows []statusRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
		t.Fatalf("json %q: %v", stdout, err)
	}
	if len(rows) != 3 {
		t.Fatalf("rows = %+v", rows)
	}
	wantRefs := []config.AccountRef{{Profile: "a", Platform: fakePlatform}, {Profile: "a", Platform: fakePlatform2}, {Profile: "b", Platform: fakePlatform2}}
	for i, ref := range wantRefs {
		r := rows[i]
		if r.Name != ref.Profile || r.Platform != ref.Platform || !r.OK || !r.Verified || r.Identity == nil || r.Error != "" || r.Current != (ref.Profile == "b") {
			t.Errorf("row %d = %+v, want ok %s", i, r, ref)
		}
		if clientOn(ref.Profile, ref.Platform).count("Verify") != 1 {
			t.Errorf("%s: Verify calls = %d", ref, clientOn(ref.Profile, ref.Platform).count("Verify"))
		}
	}
	// Every account is opened with its own secret.
	if client("a").count("Open:secret") != 1 || clientOn("a", fakePlatform2).count("Open:secret-a/"+string(fakePlatform2)) != 1 ||
		clientOn("b", fakePlatform2).count("Open:secret-b/"+string(fakePlatform2)) != 1 {
		t.Error("an account was opened with another account's secret")
	}

	stdout, _, err = run(t, cfgPath, "auth", "status")
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 4 {
		t.Fatalf("table = %q", stdout)
	}
	want := [][]string{
		{"a", string(fakePlatform), "ok", "fake-account"},
		{"a", string(fakePlatform2), "ok", "fake-account"},
		{"*", "b", string(fakePlatform2), "ok", "fake-account"},
	}
	for i, w := range want {
		if got := strings.Fields(lines[i+1]); strings.Join(got, "|") != strings.Join(w, "|") {
			t.Errorf("row %d = %q, want %q", i, got, w)
		}
	}

	// --profile restricts the rows to that profile's accounts.
	stdout, _, err = run(t, cfgPath, "auth", "status", "--profile", "a", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	rows = nil
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil || len(rows) != 2 || rows[0].Name != "a" || rows[1].Name != "a" ||
		rows[0].Platform != fakePlatform || rows[1].Platform != fakePlatform2 {
		t.Errorf("--profile a rows = %+v, %v", rows, err)
	}
	if _, _, err := run(t, cfgPath, "auth", "status", "--profile", "nope"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("status --profile nope = %v (exit %d)", err, ExitCodeFor(err))
	}

	// One account without credentials fails only its own row.
	if err := creds.NewFile(dir).Delete(creds.Key("a", string(fakePlatform2))); err != nil {
		t.Fatal(err)
	}
	stdout, _, err = run(t, cfgPath, "auth", "status", "-o", "json")
	if ExitCodeFor(err) != ExitAuth {
		t.Fatalf("status with a missing secret = %v (exit %d)", err, ExitCodeFor(err))
	}
	rows = nil
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil || len(rows) != 3 {
		t.Fatalf("rows = %q, %v", stdout, err)
	}
	if !rows[0].OK || rows[1].OK || !rows[2].OK {
		t.Errorf("rows = %+v, want only a/%s failed", rows, fakePlatform2)
	}
	if !strings.Contains(rows[1].Error, "auth login "+string(fakePlatform2)+" --profile a") {
		t.Errorf("error = %q, want a login hint for the account", rows[1].Error)
	}
	stdout, _, _ = run(t, cfgPath, "auth", "status")
	if strings.Count(stdout, "FAILED") != 1 || strings.Count(stdout, " ok ") != 2 {
		t.Errorf("table = %q", stdout)
	}
}

func TestAuthLogoutPlatformRemovesOnlyThatAccount(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, "two.example")
	seedZone(t, dir, config.AccountRef{Profile: "b", Platform: fakePlatform2}, "three.example")
	all := "a/" + string(fakePlatform) + " a/" + string(fakePlatform2) + " b/" + string(fakePlatform2)
	if got := inventoryOwners(t, dir); got != all {
		t.Fatalf("seeded inventory = %q", got)
	}

	// Errors leave everything in place.
	var out, errb bytes.Buffer
	code := Main([]string{"--config", cfgPath, "auth", "logout", string(fakePlatform), "--profile", "b"}, strings.NewReader(""), &out, &errb)
	if code != 4 {
		t.Fatalf("logout of a missing platform: exit %d, want 4 (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), `profile "b" has no `+string(fakePlatform)+" account") {
		t.Errorf("stderr = %q", errb.String())
	}
	if _, _, err := run(t, cfgPath, "auth", "logout", "nosuchplatform", "--profile", "a"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("logout nosuchplatform = %v (exit %d)", err, ExitCodeFor(err))
	}
	if _, _, err := run(t, cfgPath, "auth", "logout", string(fakePlatform)); ExitCodeFor(err) != ExitUsage {
		t.Errorf("logout <platform> without --profile = %v (exit %d)", err, ExitCodeFor(err))
	}
	if _, _, err := run(t, cfgPath, "auth", "logout", string(fakePlatform), "--profile", "nope"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("logout of a missing profile = %v (exit %d)", err, ExitCodeFor(err))
	}
	if _, _, err := run(t, cfgPath, "auth", "logout", string(fakePlatform), string(fakePlatform2), "--profile", "a"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("logout with two platforms = %v (exit %d)", err, ExitCodeFor(err))
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != all {
		t.Fatalf("accounts after failed logouts = %q", got)
	}
	if got := inventoryOwners(t, dir); got != all {
		t.Fatalf("inventory after failed logouts = %q", got)
	}

	_, stderr, err := run(t, cfgPath, "auth", "logout", string(fakePlatform2), "--profile", "a")
	if err != nil {
		t.Fatalf("logout: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, string(fakePlatform2)+` account removed from profile "a"`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+string(fakePlatform)+" b/"+string(fakePlatform2) {
		t.Errorf("accounts = %q", got)
	}
	if cfg.CurrentProfile != "a" {
		t.Errorf("current_profile = %q, the profile still exists", cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("a", string(fakePlatform2))) != "" {
		t.Error("secret of the removed account survived")
	}
	if token(t, dir, creds.Key("a", string(fakePlatform))) != "secret" || token(t, dir, creds.Key("b", string(fakePlatform2))) == "" {
		t.Error("secret of another account was removed")
	}
	if got := inventoryOwners(t, dir); got != "a/"+string(fakePlatform)+" b/"+string(fakePlatform2) {
		t.Errorf("inventory = %q", got)
	}
	// The remaining account still works.
	if _, _, err := run(t, cfgPath, "auth", "status", "--profile", "a"); err != nil {
		t.Errorf("status after logout: %v", err)
	}

	// Removing the last account removes the profile and clears the default.
	_, stderr, err = run(t, cfgPath, "auth", "logout", string(fakePlatform), "--profile", "a", "--keep-inventory")
	if err != nil {
		t.Fatalf("logout of the last account: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, `profile "a" removed`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "b/"+string(fakePlatform2) || len(cfg.Profiles) != 1 || cfg.CurrentProfile != "" {
		t.Errorf("accounts = %q, profiles = %d, current = %q", got, len(cfg.Profiles), cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("a", string(fakePlatform))) != "" {
		t.Error("secret of the last account survived")
	}
	// --keep-inventory keeps the cached rows.
	if got := inventoryOwners(t, dir); got != "a/"+string(fakePlatform)+" b/"+string(fakePlatform2) {
		t.Errorf("inventory with --keep-inventory = %q", got)
	}
}

func TestAuthLogoutProfileRemovesEveryAccount(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, "two.example")
	seedZone(t, dir, config.AccountRef{Profile: "b", Platform: fakePlatform2}, "three.example")

	_, stderr, err := run(t, cfgPath, "auth", "logout", "--profile", "a")
	if err != nil {
		t.Fatalf("logout: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, `profile "a" removed`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "b/"+string(fakePlatform2) || len(cfg.Profiles) != 1 || cfg.CurrentProfile != "" {
		t.Errorf("accounts = %q, profiles = %d, current = %q", got, len(cfg.Profiles), cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("a", string(fakePlatform))) != "" || token(t, dir, creds.Key("a", string(fakePlatform2))) != "" {
		t.Error("a secret of the removed profile survived")
	}
	if token(t, dir, creds.Key("b", string(fakePlatform2))) == "" {
		t.Error("secret of profile b was removed")
	}
	if got := inventoryOwners(t, dir); got != "b/"+string(fakePlatform2) {
		t.Errorf("inventory = %q", got)
	}
	if _, _, err := run(t, cfgPath, "auth", "logout", "--profile", "a"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("second logout = %v (exit %d)", err, ExitCodeFor(err))
	}
}

func TestSyncSelectsAccounts(t *testing.T) {
	_, cfgPath := setupMulti(t)
	refs := []config.AccountRef{{Profile: "a", Platform: fakePlatform}, {Profile: "a", Platform: fakePlatform2}, {Profile: "b", Platform: fakePlatform2}}
	// syncs runs sync with args and returns the accounts that were synced,
	// in order, after checking that exactly those clients were opened.
	syncs := func(args ...string) string {
		t.Helper()
		resetFake()
		for _, ref := range refs {
			clientOn(ref.Profile, ref.Platform).zones = []platform.Zone{{ID: "z1", Name: ref.Profile + "-" + string(ref.Platform) + ".example"}}
		}
		stdout, stderr, err := run(t, cfgPath, append([]string{"sync", "-o", "json"}, args...)...)
		if err != nil {
			t.Fatalf("sync %v: %v (stderr %q)", args, err, stderr)
		}
		var reports []app.SyncReport
		if err := json.Unmarshal([]byte(stdout), &reports); err != nil {
			t.Fatalf("sync %v: json %q: %v", args, stdout, err)
		}
		var got []string
		perAccount := map[string]int{}
		for _, r := range reports {
			name := r.Profile + "/" + string(r.Platform)
			if perAccount[name] == 0 {
				got = append(got, name)
			}
			perAccount[name]++
			if r.Error != "" {
				t.Errorf("sync %v: report %+v", args, r)
			}
		}
		for name, n := range perAccount {
			if n != 3 {
				t.Errorf("sync %v: %d reports for %s, want one per resource type", args, n, name)
			}
		}
		for _, ref := range refs {
			opened := clientOn(ref.Profile, ref.Platform).count("Open") > 0
			if opened != (perAccount[ref.String()] > 0) {
				t.Errorf("sync %v: %s opened = %v", args, ref, opened)
			}
		}
		return strings.Join(got, " ")
	}
	p1, p2 := string(fakePlatform), string(fakePlatform2)
	if got := syncs(); got != "a/"+p1+" a/"+p2+" b/"+p2 {
		t.Errorf("sync = %q", got)
	}
	if got := syncs("--profile", "a"); got != "a/"+p1+" a/"+p2 {
		t.Errorf("sync --profile a = %q", got)
	}
	if got := syncs("--profile", "b"); got != "b/"+p2 {
		t.Errorf("sync --profile b = %q", got)
	}
	if got := syncs("--platform", p2); got != "a/"+p2+" b/"+p2 {
		t.Errorf("sync --platform %s = %q", p2, got)
	}
	if got := syncs("--platform", p1); got != "a/"+p1 {
		t.Errorf("sync --platform %s = %q", p1, got)
	}
	if got := syncs("--profile", "a", "--platform", p2); got != "a/"+p2 {
		t.Errorf("sync --profile a --platform %s = %q", p2, got)
	}

	if _, _, err := run(t, cfgPath, "sync", "--profile", "nope"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("sync --profile nope = %v (exit %d)", err, ExitCodeFor(err))
	}
	// A selection that names no account leaves nothing to do, which is not
	// an error: exit code 0 and an empty report.
	stdout, _, err := run(t, cfgPath, "sync", "--profile", "b", "--platform", p1, "-o", "json")
	if !errors.Is(err, errNothingToDo) || ExitCodeFor(err) != ExitOK || !strings.Contains(err.Error(), `profile "b" has no account on `+p1) || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("sync of an account that does not exist = %v (exit %d, stdout %q)", err, ExitCodeFor(err), stdout)
	}
	stdout, _, err = run(t, cfgPath, "sync", "--platform", "aws", "-o", "json")
	if !errors.Is(err, errNothingToDo) || ExitCodeFor(err) != ExitOK || !strings.Contains(err.Error(), "no account on aws is configured") || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("sync of a platform without accounts = %v (exit %d, stdout %q)", err, ExitCodeFor(err), stdout)
	}
	// So do accounts that exist but cannot hold the requested type.
	stdout, _, err = run(t, cfgPath, "sync", "--profile", "b", "--type", "instance", "-o", "json")
	if !errors.Is(err, errNothingToDo) || ExitCodeFor(err) != ExitOK || !strings.Contains(err.Error(), "no selected account supports the requested resource types") || strings.TrimSpace(stdout) != "[]" {
		t.Errorf("sync of a type no selected account supports = %v (exit %d, stdout %q)", err, ExitCodeFor(err), stdout)
	}

	// domain index follows the same selection.
	resetFake()
	if _, _, err := run(t, cfgPath, "domain", "index", "--profile", "b"); err != nil {
		t.Fatalf("domain index --profile b: %v", err)
	}
	if clientOn("b", fakePlatform2).count("Sync:") != 2 || client("a").count("Open") != 0 || clientOn("a", fakePlatform2).count("Open") != 0 {
		t.Error("domain index --profile b touched accounts of another profile")
	}
	resetFake()
	if _, _, err := run(t, cfgPath, "domain", "index"); err != nil {
		t.Fatalf("domain index: %v", err)
	}
	for _, ref := range refs {
		if clientOn(ref.Profile, ref.Platform).count("Sync:") != 2 {
			t.Errorf("domain index: %s synced %d sets, want zones and domains", ref, clientOn(ref.Profile, ref.Platform).count("Sync:"))
		}
	}
}

// TestDNSRoutesToAccountInsideProfile checks that a profile holding two
// accounts routes a domain to the account that owns it.
func TestDNSRoutesToAccountInsideProfile(t *testing.T) {
	_, cfgPath := setupMulti(t)
	client("a").zones = []platform.Zone{{ID: "z1", Name: "one.example"}}
	gd := clientOn("a", fakePlatform2)
	gd.zones = []platform.Zone{{ID: "z2", Name: "two.example"}}
	if _, _, err := run(t, cfgPath, "domain", "index"); err != nil {
		t.Fatal(err)
	}

	_, stderr, err := run(t, cfgPath, "dns", "update", "two.example", "--type", "A", "--name", "www", "--value", "192.0.2.1")
	if err != nil {
		t.Fatalf("dns update: %v (stderr %q)", err, stderr)
	}
	if gd.count("CreateRecord:www.two.example:A") != 1 || client("a").count("CreateRecord") != 0 || clientOn("b", fakePlatform2).count("CreateRecord") != 0 {
		t.Errorf("record created on the wrong account (stderr %q)", stderr)
	}
	if !strings.Contains(stderr, "via "+string(fakePlatform2)+"/a") {
		t.Errorf("stderr = %q", stderr)
	}
	// --profile b has no account that owns the zone.
	if _, _, err := run(t, cfgPath, "dns", "list", "one.example", "--profile", "b", "--offline"); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("dns list via a profile that lacks the zone = %v (exit %d)", err, ExitCodeFor(err))
	}
}

const legacyConfig = `current_profile: old
credential_store: file
profiles:
  old:
    platform: cloudflare
    metadata:
      account: acct-old
    credential_backend: file
    created_at: 2026-01-02T03:04:05Z
    updated_at: 2026-02-03T04:05:06Z
  reg:
    platform: godaddy
    credential_backend: file
`

// writeLegacy writes a config in the one-platform-per-profile layout with
// its secrets under the bare profile names.
func writeLegacy(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir, cfgPath = setup(t, false)
	if err := os.WriteFile(cfgPath, []byte(legacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	store := creds.NewFile(dir)
	if err := store.Set("old", map[string]string{"token": "legacy-old"}); err != nil {
		t.Fatal(err)
	}
	if err := store.Set("reg", map[string]string{"token": "legacy-reg"}); err != nil {
		t.Fatal(err)
	}
	return dir, cfgPath
}

func TestLegacyConfigEndToEnd(t *testing.T) {
	dir, cfgPath := writeLegacy(t)

	// A command that does not need credentials reads the old layout as is.
	stdout, _, err := run(t, cfgPath, "auth", "list", "-o", "json")
	if err != nil {
		t.Fatalf("auth list: %v", err)
	}
	var list []profileRow
	if err := json.Unmarshal([]byte(stdout), &list); err != nil || len(list) != 2 {
		t.Fatalf("auth list = %q, %v", stdout, err)
	}
	if list[0].Name != "old" || list[0].Platform != platform.Cloudflare || !list[0].Current || list[0].Metadata["account"] != "acct-old" ||
		list[1].Name != "reg" || list[1].Platform != platform.GoDaddy || list[1].Current {
		t.Errorf("auth list rows = %+v", list)
	}

	// A command that needs credentials works and migrates file and secrets.
	client("old").zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	stdout, stderr, err := run(t, cfgPath, "sync", "--profile", "old", "-o", "json")
	if err != nil {
		t.Fatalf("sync: %v (stderr %q)", err, stderr)
	}
	var reports []app.SyncReport
	if err := json.Unmarshal([]byte(stdout), &reports); err != nil || len(reports) != 3 {
		t.Fatalf("reports = %q, %v", stdout, err)
	}
	if client("old").count("Open:legacy-old") != 1 {
		t.Errorf("client was not opened with the legacy secret: %v", client("old").calls)
	}

	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "legacy_secret") || strings.Contains(string(raw), "platform: ") || strings.Count(string(raw), "platforms:") != 2 {
		t.Errorf("config was not rewritten in the current layout:\n%s", raw)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "old/cloudflare reg/godaddy" || cfg.CurrentProfile != "old" || cfg.CredentialStore != "file" {
		t.Errorf("accounts = %q, current = %q, store = %q", got, cfg.CurrentProfile, cfg.CredentialStore)
	}
	acct := cfg.Profiles["old"].Platforms[platform.Cloudflare]
	if acct.LegacySecret || acct.Metadata["account"] != "acct-old" || acct.CredentialBackend != "file" ||
		!acct.CreatedAt.Equal(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)) || !acct.UpdatedAt.Equal(time.Date(2026, 2, 3, 4, 5, 6, 0, time.UTC)) {
		t.Errorf("migrated account = %+v", acct)
	}
	if cfg.Profiles["reg"].Platforms[platform.GoDaddy].LegacySecret {
		t.Error("the account of the other profile kept its legacy mark")
	}
	// Every legacy secret moved to its profile/platform key, including the
	// one of the profile the command did not use.
	if token(t, dir, "old") != "" || token(t, dir, "reg") != "" {
		t.Error("a secret is still stored under a bare profile name")
	}
	if token(t, dir, creds.Key("old", "cloudflare")) != "legacy-old" || token(t, dir, creds.Key("reg", "godaddy")) != "legacy-reg" {
		t.Error("a secret did not reach its profile/platform key")
	}

	// The migrated config keeps working, and takes a second platform.
	if _, _, err := run(t, cfgPath, "auth", "status"); err != nil {
		t.Errorf("auth status after migration: %v", err)
	}
	// godaddy is configured in profile reg only: without --profile the login
	// must not quietly add a second godaddy account to the current profile.
	if _, _, err := run(t, cfgPath, "auth", "login", "godaddy"); ExitCodeFor(err) != ExitUsage {
		t.Fatalf("login of a platform held by another profile = %v (exit %d)", err, ExitCodeFor(err))
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "old/cloudflare reg/godaddy" {
		t.Errorf("accounts after the refused login = %q", got)
	}
	if _, _, err := run(t, cfgPath, "auth", "login", "godaddy", "--profile", "old"); err != nil {
		t.Fatal(err)
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "old/cloudflare old/godaddy reg/godaddy" {
		t.Errorf("accounts after a second login = %q", got)
	}
	if token(t, dir, creds.Key("reg", "godaddy")) != "legacy-reg" {
		t.Error("login into profile old changed the secret of profile reg")
	}
}

func TestLegacyConfigOtherEntryPoints(t *testing.T) {
	// Offline verification only reads the store, and still migrates.
	dir, cfgPath := writeLegacy(t)
	stdout, _, err := run(t, cfgPath, "auth", "status", "--offline", "-o", "json")
	if err != nil {
		t.Fatalf("auth status --offline: %v", err)
	}
	var rows []statusRow
	if err := json.Unmarshal([]byte(stdout), &rows); err != nil || len(rows) != 2 || !rows[0].OK || !rows[1].OK {
		t.Fatalf("rows = %q, %v", stdout, err)
	}
	if token(t, dir, "old") != "" || token(t, dir, creds.Key("old", "cloudflare")) != "legacy-old" {
		t.Error("offline status did not migrate the secret")
	}

	// Re-login of a legacy account replaces the secret and drops the bare key.
	dir, cfgPath = writeLegacy(t)
	if _, _, err := run(t, cfgPath, "auth", "login", "cloudflare", "--set", "token=new"); err != nil {
		t.Fatal(err)
	}
	if token(t, dir, "old") != "" || token(t, dir, creds.Key("old", "cloudflare")) != "new" {
		t.Errorf("re-login: bare = %q, keyed = %q", token(t, dir, "old"), token(t, dir, creds.Key("old", "cloudflare")))
	}
	cfg := loadConfig(t, cfgPath)
	if a := cfg.Profiles["old"].Platforms[platform.Cloudflare]; a.LegacySecret || a.Metadata["account"] != "acct-old" {
		t.Errorf("account after re-login = %+v", a)
	}

	// Logout of a legacy profile removes the secret wherever it lives.
	dir, cfgPath = writeLegacy(t)
	if _, _, err := run(t, cfgPath, "auth", "logout", "--profile", "old"); err != nil {
		t.Fatal(err)
	}
	if token(t, dir, "old") != "" || token(t, dir, creds.Key("old", "cloudflare")) != "" {
		t.Error("logout left a secret of the legacy profile behind")
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "reg/godaddy" || cfg.CurrentProfile != "" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("reg", "godaddy")) != "legacy-reg" {
		t.Error("the other legacy profile lost its secret")
	}

	// A legacy account whose secret is missing reports a login hint.
	dir, cfgPath = writeLegacy(t)
	if err := creds.NewFile(dir).Delete("reg"); err != nil {
		t.Fatal(err)
	}
	_, _, err = run(t, cfgPath, "sync", "--profile", "reg")
	if ExitCodeFor(err) != ExitAuth {
		t.Errorf("sync without stored credentials = %v (exit %d)", err, ExitCodeFor(err))
	}
}

// mainRun runs the CLI through Main and returns the exit code with the
// captured streams, so tests can check what the user is told on stderr.
func mainRun(cfgPath string, args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Main(append([]string{"--config", cfgPath}, args...), strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

// TestDNSPlatformFlagPicksAccountInsideProfile covers a zone held by both
// accounts of one profile: only --platform can choose between them.
func TestDNSPlatformFlagPicksAccountInsideProfile(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	p1, p2 := string(fakePlatform), string(fakePlatform2)
	const zoneName = "both.example"
	zones := []platform.Zone{{ID: "z-" + zoneName, Name: zoneName}}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, zoneName)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, zoneName)
	seedZone(t, dir, config.AccountRef{Profile: "b", Platform: fakePlatform2}, "other.example")
	cf, gd := client("a"), clientOn("a", fakePlatform2)
	cf.zones, gd.zones = zones, zones

	// No flag: ambiguous, the candidates name platform/profile and the hint
	// names the one flag that tells them apart.
	code, _, stderr := mainRun(cfgPath, "dns", "list", zoneName, "--offline")
	if code != ExitAmbiguous {
		t.Fatalf("dns list without --platform: exit %d, want %d (stderr %q)", code, ExitAmbiguous, stderr)
	}
	for _, want := range []string{p1 + "/a (zone z-" + zoneName + ")", p2 + "/a (zone z-" + zoneName + ")", "pass --platform <platform> to choose"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %q", want, stderr)
		}
	}
	if strings.Contains(stderr, "--profile") {
		t.Errorf("--profile cannot tell two accounts of one profile apart: %q", stderr)
	}
	// --profile alone does not help either.
	if code, _, stderr := mainRun(cfgPath, "dns", "list", zoneName, "--offline", "--profile", "a"); code != ExitAmbiguous || !strings.Contains(stderr, "--platform <platform>") {
		t.Errorf("dns list --profile a: exit %d (stderr %q)", code, stderr)
	}

	// --platform routes reads and writes to the chosen account. The flag is
	// accepted after the subcommand and on the group, by id or by alias.
	_, stderr, err := run(t, cfgPath, "dns", "list", zoneName, "--platform", p2)
	if err != nil || !strings.Contains(stderr, "zone "+zoneName+" via "+p2+"/a") {
		t.Errorf("dns list --platform %s: %v (stderr %q)", p2, err, stderr)
	}
	if gd.count("ListRecords:z-"+zoneName) != 1 || cf.count("") != 0 {
		t.Errorf("records listed on the wrong account: godaddy %v, cloudflare %v", gd.calls, cf.calls)
	}
	_, stderr, err = run(t, cfgPath, "dns", "update", zoneName, "--type", "A", "--name", "www", "--value", "192.0.2.1", "--platform", "gd")
	if err != nil {
		t.Fatalf("dns update --platform gd: %v (stderr %q)", err, stderr)
	}
	if gd.count("CreateRecord:www."+zoneName+":A") != 1 || cf.count("") != 0 {
		t.Errorf("record created on the wrong account: godaddy %v, cloudflare %v", gd.calls, cf.calls)
	}
	if !strings.Contains(stderr, "via "+p2+"/a") {
		t.Errorf("stderr = %q", stderr)
	}
	_, stderr, err = run(t, cfgPath, "dns", "--platform", "cf", "update", zoneName, "--type", "A", "--name", "www", "--value", "192.0.2.2", "--profile", "a")
	if err != nil {
		t.Fatalf("dns --platform cf update: %v (stderr %q)", err, stderr)
	}
	if cf.count("CreateRecord:www."+zoneName+":A") != 1 || gd.count("CreateRecord") != 1 {
		t.Errorf("record created on the wrong account: godaddy %v, cloudflare %v", gd.calls, cf.calls)
	}
	if !strings.Contains(stderr, "via "+p1+"/a") {
		t.Errorf("stderr = %q", stderr)
	}
	if n := clientOn("b", fakePlatform2).count(""); n != 0 {
		t.Errorf("profile b was reached: %v", clientOn("b", fakePlatform2).calls)
	}
	_, _, err = run(t, cfgPath, "dns", "delete", zoneName, "--type", "A", "--name", "www", "--platform", p2)
	if err != nil || gd.count("DeleteRecord") != 1 || cf.count("DeleteRecord") != 0 || len(cf.records["z-"+zoneName]) != 1 {
		t.Errorf("dns delete --platform %s: %v (godaddy %v, cloudflare %v)", p2, err, gd.calls, cf.calls)
	}

	// The zone on a platform that does not hold it is not found.
	if _, _, err := run(t, cfgPath, "dns", "list", "other.example", "--offline", "--platform", p1); ExitCodeFor(err) != ExitNotFound {
		t.Errorf("dns list on the wrong platform = %v (exit %d)", err, ExitCodeFor(err))
	}
	// A platform without any account says so, without a login hint.
	code, _, stderr = mainRun(cfgPath, "dns", "list", zoneName, "--platform", "aws")
	if code != ExitNotFound || !strings.Contains(stderr, "no account selected by --profile / --platform is able to manage zones") || strings.Contains(stderr, "auth login") {
		t.Errorf("dns list --platform aws: exit %d (stderr %q)", code, stderr)
	}

	// A third owner in another profile: both flags can narrow it down; with
	// --platform given, --profile is what is left to choose.
	seedZone(t, dir, config.AccountRef{Profile: "b", Platform: fakePlatform2}, zoneName)
	code, _, stderr = mainRun(cfgPath, "dns", "list", zoneName, "--offline")
	if code != ExitAmbiguous || !strings.Contains(stderr, "pass --profile <name> and/or --platform <platform> to choose") || !strings.Contains(stderr, p2+"/b (zone z-"+zoneName+")") {
		t.Errorf("three owners: exit %d (stderr %q)", code, stderr)
	}
	code, _, stderr = mainRun(cfgPath, "dns", "list", zoneName, "--offline", "--platform", p2)
	if code != ExitAmbiguous || !strings.Contains(stderr, "pass --profile <name> to choose") || strings.Contains(stderr, "--platform <platform>") || strings.Contains(stderr, p1+"/a") {
		t.Errorf("--platform %s with two owners: exit %d (stderr %q)", p2, code, stderr)
	}
	clientOn("b", fakePlatform2).zones = zones
	_, stderr, err = run(t, cfgPath, "dns", "list", zoneName, "--platform", p2, "-p", "b")
	if err != nil || !strings.Contains(stderr, "via "+p2+"/b") || clientOn("b", fakePlatform2).count("ListRecords") != 1 {
		t.Errorf("--platform %s -p b: %v (stderr %q)", p2, err, stderr)
	}
}

func TestDomainPlatformFlag(t *testing.T) {
	_, cfgPath := setupMulti(t)
	p1, p2 := string(fakePlatform), string(fakePlatform2)
	refs := []config.AccountRef{{Profile: "a", Platform: fakePlatform}, {Profile: "a", Platform: fakePlatform2}, {Profile: "b", Platform: fakePlatform2}}
	// The same registered domain in both accounts of profile a.
	for _, ref := range refs[:2] {
		clientOn(ref.Profile, ref.Platform).domains = []platform.Domain{{Name: "both.example", Nameservers: []string{"ns1." + string(ref.Platform) + ".example"}}}
	}

	// domain index --platform scans the accounts of that platform only.
	if _, _, err := run(t, cfgPath, "domain", "index", "--platform", p2); err != nil {
		t.Fatalf("domain index --platform %s: %v", p2, err)
	}
	if client("a").count("") != 0 || clientOn("a", fakePlatform2).count("Sync:") != 2 || clientOn("b", fakePlatform2).count("Sync:") != 2 {
		t.Errorf("domain index --platform %s reached the wrong accounts", p2)
	}
	if _, _, err := run(t, cfgPath, "domain", "index", "--platform", p2, "--profile", "b"); err != nil || clientOn("a", fakePlatform2).count("Sync:") != 2 || clientOn("b", fakePlatform2).count("Sync:") != 4 {
		t.Errorf("domain index --platform %s --profile b: %v", p2, err)
	}
	// No account on the platform: nothing is indexed, which is not an error.
	code, stdout, stderr := mainRun(cfgPath, "domain", "index", "--platform", "aws")
	if code != ExitOK || stderr != "nothing to do: no domain-capable account matches --profile / --platform\n" || stdout != "PLATFORM  PROFILE  TYPE  COUNT  STATUS\n" {
		t.Errorf("domain index --platform aws: exit %d (stdout %q, stderr %q)", code, stdout, stderr)
	}
	if _, _, err := run(t, cfgPath, "domain", "index"); err != nil {
		t.Fatal(err)
	}

	// Registrar lookups are ambiguous inside profile a until --platform is given.
	code, _, stderr = mainRun(cfgPath, "domain", "ns", "get", "both.example", "--offline")
	if code != ExitAmbiguous || !strings.Contains(stderr, "pass --platform <platform> to choose") || strings.Contains(stderr, "--profile") ||
		!strings.Contains(stderr, p1+"/a (domain both.example)") || !strings.Contains(stderr, p2+"/a (domain both.example)") {
		t.Errorf("domain ns get without --platform: exit %d (stderr %q)", code, stderr)
	}
	for _, id := range []string{p1, p2} {
		stdout, stderr, err := run(t, cfgPath, "domain", "ns", "get", "both.example", "--offline", "--platform", id)
		if err != nil || !strings.Contains(stdout, "ns1."+id+".example") || !strings.Contains(stderr, "via "+id+"/a") {
			t.Errorf("domain ns get --platform %s: %v (stdout %q, stderr %q)", id, err, stdout, stderr)
		}
	}
	resetFake()
	for _, ref := range refs[:2] {
		clientOn(ref.Profile, ref.Platform).domains = []platform.Domain{{Name: "both.example"}}
	}
	if _, stderr, err := run(t, cfgPath, "domain", "ns", "set", "both.example", "--ns", "ns1.new.example,ns2.new.example", "--platform", p2, "--yes"); err != nil {
		t.Fatalf("domain ns set --platform %s: %v (stderr %q)", p2, err, stderr)
	}
	if clientOn("a", fakePlatform2).count("SetNameservers:both.example") != 1 || client("a").count("") != 0 {
		t.Errorf("nameservers set on the wrong account: godaddy %v, cloudflare %v", clientOn("a", fakePlatform2).calls, client("a").calls)
	}
}

func TestInvalidPlatformFlagIsUsageError(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")
	cases := [][]string{
		{"dns", "list", "one.example", "--platform", "nosuch"},
		{"dns", "list", "one.example", "--platform", "nosuch", "--offline"},
		{"dns", "update", "one.example", "--type", "A", "--name", "www", "--value", "192.0.2.1", "--platform", "nosuch"},
		{"dns", "delete", "one.example", "--type", "A", "--name", "www", "--platform", "nosuch"},
		{"domain", "ns", "get", "one.example", "--platform", "nosuch"},
		{"domain", "index", "--platform", "nosuch"},
		{"domain", "list", "--refresh", "--platform", "nosuch"},
	}
	for _, args := range cases {
		code, stdout, stderr := mainRun(cfgPath, args...)
		if code != ExitUsage {
			t.Errorf("%v: exit %d, want %d (stderr %q)", args, code, ExitUsage, stderr)
		}
		if !strings.Contains(stderr, `unknown platform "nosuch"`) || stdout != "" {
			t.Errorf("%v: stdout %q, stderr %q", args, stdout, stderr)
		}
	}
	for _, ref := range []config.AccountRef{{Profile: "a", Platform: fakePlatform}, {Profile: "a", Platform: fakePlatform2}, {Profile: "b", Platform: fakePlatform2}} {
		if n := clientOn(ref.Profile, ref.Platform).count(""); n != 0 {
			t.Errorf("%s was reached despite the invalid flag: %v", ref, clientOn(ref.Profile, ref.Platform).calls)
		}
	}
	// The routing flag belongs to the dns and domain groups only.
	if code, _, stderr := mainRun(cfgPath, "auth", "list", "--platform", string(fakePlatform)); code != ExitUsage || !strings.Contains(stderr, "unknown flag") {
		t.Errorf("auth list --platform: exit %d (stderr %q)", code, stderr)
	}
}

func TestAuthLoginRequiresProfileWhenPlatformLivesElsewhere(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	p1, p2 := string(fakePlatform), string(fakePlatform2)
	all := "a/" + p1 + " a/" + p2 + " b/" + p2
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}

	// No current profile: the target would be "default", which lacks the
	// platform while a and b have it.
	code, stdout, stderr := mainRun(cfgPath, "auth", "login", p2)
	if code != ExitUsage {
		t.Fatalf("login without --profile: exit %d, want %d (stderr %q)", code, ExitUsage, stderr)
	}
	for _, want := range []string{"usage error", p2 + " is already configured in profile(s) a, b", "--profile <name>", "--profile default"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %q", want, stderr)
		}
	}
	if stdout != "" {
		t.Errorf("stdout = %q", stdout)
	}
	if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
		t.Errorf("a refused login rewrote the config:\n%s", after)
	}
	if token(t, dir, creds.Key("default", p2)) != "" {
		t.Error("a refused login stored a secret")
	}

	// The current profile lacks the platform that another profile has.
	if _, _, err := run(t, cfgPath, "auth", "use", "b"); err != nil {
		t.Fatal(err)
	}
	code, _, stderr = mainRun(cfgPath, "auth", "login", p1)
	if code != ExitUsage || !strings.Contains(stderr, p1+" is already configured in profile(s) a;") || !strings.Contains(stderr, "--profile b") {
		t.Errorf("login of a platform the current profile lacks: exit %d (stderr %q)", code, stderr)
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != all {
		t.Errorf("accounts after refused logins = %q", got)
	}

	// The current profile has the platform: plain re-authentication.
	_, stderr, err = run(t, cfgPath, "auth", "login", p2, "--set", "token=rotated")
	if err != nil || !strings.Contains(stderr, "re-authenticating the "+p2+` account of profile "b"`) {
		t.Fatalf("re-login of the current profile: %v (stderr %q)", err, stderr)
	}
	if token(t, dir, creds.Key("b", p2)) != "rotated" || token(t, dir, creds.Key("a", p2)) != "secret-a/"+p2 {
		t.Error("re-login must replace the secret of the current profile only")
	}

	// --profile makes the intent explicit: add to the named profile...
	_, stderr, err = run(t, cfgPath, "auth", "login", p1, "--profile", "b")
	if err != nil || !strings.Contains(stderr, `in profile "b"`) || strings.Contains(stderr, "re-authenticating") {
		t.Fatalf("login --profile b: %v (stderr %q)", err, stderr)
	}
	// ...re-authenticate one that has it...
	_, stderr, err = run(t, cfgPath, "auth", "login", p1, "--profile", "a")
	if err != nil || !strings.Contains(stderr, "re-authenticating the "+p1+` account of profile "a"`) {
		t.Fatalf("login --profile a: %v (stderr %q)", err, stderr)
	}
	// ...or open a new profile next to the existing ones.
	if _, _, err := run(t, cfgPath, "auth", "login", p2, "--profile", "default"); err != nil {
		t.Fatalf("login --profile default: %v", err)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" a/"+p2+" b/"+p1+" b/"+p2+" default/"+p2 {
		t.Errorf("accounts = %q", got)
	}
	if cfg.CurrentProfile != "b" {
		t.Errorf("current_profile = %q", cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("default", p2)) != "fake" || token(t, dir, creds.Key("b", p1)) != "fake" {
		t.Error("the new accounts have no secret")
	}
}

// TestAuthLogoutSavesAfterEachAccount makes the removal of the second account
// of a profile fail and checks that the first one is already gone from the
// saved config, so the file never lists an account whose secret was removed.
func TestAuthLogoutSavesAfterEachAccount(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	p1, p2 := string(fakePlatform), string(fakePlatform2)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, "two.example")

	// Accounts are removed in platform order, so the purge of the second one
	// (fakePlatform2) is the step that fails.
	if fakePlatform >= fakePlatform2 {
		t.Fatal("this test needs fakePlatform to sort before fakePlatform2")
	}
	raw, err := sql.Open("sqlite", openInventoryPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER block_purge BEFORE DELETE ON resources WHEN OLD.platform = '` + p2 + `' BEGIN SELECT RAISE(ABORT, 'purge blocked'); END`); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := mainRun(cfgPath, "auth", "logout", "--profile", "a")
	if code != ExitError || !strings.Contains(stderr, "purge blocked") {
		t.Fatalf("logout with a failing purge: exit %d (stderr %q)", code, stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p2+" b/"+p2 {
		t.Errorf("accounts on disk after the failure = %q, want the first account gone and the second kept", got)
	}
	if cfg.CurrentProfile != "a" {
		t.Errorf("current_profile = %q, profile a still exists", cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("a", p1)) != "" {
		t.Error("the secret of the removed account survived")
	}
	if got := inventoryOwners(t, dir); got != "a/"+p2 {
		t.Errorf("inventory after the failure = %q", got)
	}
	if token(t, dir, creds.Key("b", p2)) == "" {
		t.Error("profile b lost its secret")
	}

	// Once the purge works again a second logout finishes the job.
	if _, err := raw.Exec(`DROP TRIGGER block_purge`); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := run(t, cfgPath, "auth", "logout", "--profile", "a"); err != nil || !strings.Contains(stderr, `profile "a" removed`) {
		t.Fatalf("second logout: %v (stderr %q)", err, stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "b/"+p2 || cfg.CurrentProfile != "" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if got := inventoryOwners(t, dir); got != "" {
		t.Errorf("inventory = %q", got)
	}
}

func openInventoryPath(dir string) string { return filepath.Join(dir, "inventory.db") }
