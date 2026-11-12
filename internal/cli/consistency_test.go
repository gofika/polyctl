package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
)

// addHollow adds a profile without accounts, as a hand-edited config or a
// removed last account may leave one.
func addHollow(t *testing.T, cfgPath string, current bool) {
	t.Helper()
	cfg := loadConfig(t, cfgPath)
	cfg.Profiles["hollow"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	if current {
		cfg.CurrentProfile = "hollow"
	}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}

// currentRows returns the profile names of the table rows marked current.
func currentRows(table string) []string {
	var out []string
	for _, line := range strings.Split(table, "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "*" {
			out = append(out, f[1])
		}
	}
	return out
}

// A profile without accounts can be current, renamed and removed, so the
// listing must show it, and with it the current marker.
func TestAuthListShowsProfilesWithoutAccounts(t *testing.T) {
	_, cfgPath := setup(t, true)
	addHollow(t, cfgPath, true)

	stdout, _, err := run(t, cfgPath, "auth", "list")
	if err != nil {
		t.Fatal(err)
	}
	var hollow string
	for _, line := range strings.Split(stdout, "\n") {
		if strings.Contains(line, "hollow") {
			hollow = line
		}
	}
	if f := strings.Fields(hollow); len(f) < 2 || f[0] != "*" || f[1] != "hollow" || !strings.Contains(hollow, "(no accounts)") {
		t.Errorf("row of the profile without accounts = %q in:\n%s", hollow, stdout)
	}
	if got := currentRows(stdout); len(got) != 1 || got[0] != "hollow" {
		t.Errorf("rows marked current = %v", got)
	}

	for _, format := range []string{"json", "yaml"} {
		stdout, _, err = run(t, cfgPath, "auth", "list", "-o", format)
		if err != nil {
			t.Fatal(err)
		}
		if format == "yaml" {
			if !strings.Contains(stdout, "name: hollow\n  current: true\n") || strings.Contains(stdout, "0001-01-01") {
				t.Errorf("yaml = %s", stdout)
			}
			continue
		}
		var rows []map[string]any
		if err := json.Unmarshal([]byte(stdout), &rows); err != nil {
			t.Fatalf("json %q: %v", stdout, err)
		}
		if len(rows) != 2 {
			t.Fatalf("json rows = %v, want the account and the empty profile", rows)
		}
		acct, empty := rows[0], rows[1]
		if acct["name"] != "a" || acct["platform"] != p1 || acct["current"] != false || acct["updated_at"] == nil {
			t.Errorf("account row = %v", acct)
		}
		if empty["name"] != "hollow" || empty["current"] != true {
			t.Errorf("empty profile row = %v", empty)
		}
		for _, k := range []string{"platform", "updated_at", "credential_backend"} {
			if _, ok := empty[k]; ok {
				t.Errorf("empty profile row has %q: %v", k, empty)
			}
		}
	}

	// Only such a profile: it is listed, not reported as nothing configured.
	_, cfgPath = setup(t, false)
	addHollow(t, cfgPath, false)
	stdout, _, err = run(t, cfgPath, "auth", "list")
	if err != nil || !strings.Contains(stdout, "hollow") || strings.Contains(stdout, "no accounts configured") {
		t.Errorf("auth list with only an empty profile = %q, %v", stdout, err)
	}
	// No profile at all keeps the hint.
	_, cfgPath = setup(t, false)
	stdout, _, err = run(t, cfgPath, "auth", "list")
	if err != nil || !strings.Contains(stdout, "no accounts configured") {
		t.Errorf("auth list without profiles = %q, %v", stdout, err)
	}
}

// The table of `auth manage` shows what its menu can act on.
func TestAuthManageShowsProfilesWithoutAccounts(t *testing.T) {
	_, cfgPath := setup(t, false)
	addHollow(t, cfgPath, true)
	_, stderr, err, p := runPick(t, cfgPath, []any{actQuit}, "auth", "manage")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stderr, "no accounts configured") || !strings.Contains(stderr, "(no accounts)") {
		t.Errorf("table = %q", stderr)
	}
	if got := currentRows(stderr); len(got) != 1 || got[0] != "hollow" {
		t.Errorf("rows marked current = %v in %q", got, stderr)
	}
	if got := values(p.asked[0].Options); got != strings.Join([]string{actUse, actLogin, actRename, actRemove, actQuit}, " ") {
		t.Errorf("menu = %q", got)
	}
}

// A current_profile that names no profile (hand-edited config) must not make
// `auth login` create a profile of that name.
func TestAuthLoginIgnoresStaleCurrentProfile(t *testing.T) {
	dir, cfgPath := setup(t, true)
	cfg := loadConfig(t, cfgPath)
	cfg.CurrentProfile = "ghost"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := mainRun(cfgPath, "auth", "login", p2)
	if code != ExitOK {
		t.Fatalf("auth login: exit %d (stderr %q)", code, stderr)
	}
	if !strings.Contains(stderr, `the current profile "ghost" does not exist`) || !strings.Contains(stderr, `in profile "default"`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" default/"+p2 {
		t.Errorf("accounts = %q, want the account in profile default and no profile ghost", got)
	}
	if cfg.CurrentProfile != "default" {
		t.Errorf("current_profile = %q, want the stale value replaced by default", cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("ghost", p2)) != "" || token(t, dir, creds.Key("default", p2)) != "fake" {
		t.Error("the secret was stored under the stale name")
	}

	// With --profile the name is the user's choice, stale current or not.
	cfg.CurrentProfile = "ghost"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := mainRun(cfgPath, "auth", "login", p2, "--profile", "ghost"); code != ExitOK || strings.Contains(stderr, "does not exist") {
		t.Fatalf("auth login --profile ghost: exit %d (stderr %q)", code, stderr)
	}
	if cfg = loadConfig(t, cfgPath); cfg.Profiles["ghost"] == nil || cfg.CurrentProfile != "ghost" {
		t.Errorf("profiles = %v, current = %q", cfg.ProfileNames(), cfg.CurrentProfile)
	}
}

// breakSaves makes saving the config fail on every operating system: a
// non-empty directory takes the place of the file, which the save cannot
// rename its temporary file over. The returned function puts the file back.
func breakSaves(t *testing.T, cfgPath string) (restore func()) {
	t.Helper()
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfgPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgPath, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	return func() {
		t.Helper()
		if err := os.RemoveAll(cfgPath); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(cfgPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

// A change whose save failed must not stay in the config held in memory: a
// long-running command (auth manage) would show it as done, and its next
// successful save would write it after all.
func TestFailedSaveIsUndoneInMemory(t *testing.T) {
	ctx := context.Background()
	login := func(profile string, id platform.ID) func(*app.Runtime) error {
		return func(rt *app.Runtime) error {
			prov, err := platform.Get(id)
			if err != nil {
				return err
			}
			return loginAccount(ctx, rt, prov, profile, true, map[string]string{"token": "new", "account": "changed"})
		}
	}
	for name, change := range map[string]func(*app.Runtime) error{
		"use":                  func(rt *app.Runtime) error { return useProfile(rt, "b") },
		"remove empty profile": func(rt *app.Runtime) error { return removeEmptyProfile(rt, "hollow") },
		"remove account": func(rt *app.Runtime) error {
			return removeAccount(ctx, rt, config.AccountRef{Profile: "a", Platform: fakePlatform2}, false)
		},
		"remove last account": func(rt *app.Runtime) error {
			return removeAccount(ctx, rt, config.AccountRef{Profile: "b", Platform: fakePlatform2}, true)
		},
		"login to a new profile": login("fresh", fakePlatform),
		"login to a new account": login("b", fakePlatform),
		"login again":            login("a", fakePlatform),
	} {
		t.Run(name, func(t *testing.T) {
			dir, cfgPath := setupMulti(t)
			addHollow(t, cfgPath, true)
			before, err := os.ReadFile(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			rt := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
			defer rt.Close()
			if _, err := rt.Creds(); err != nil {
				t.Fatal(err)
			}
			restore := breakSaves(t, cfgPath)
			err = change(rt)
			restore()
			if err == nil || !strings.Contains(err.Error(), "save config") {
				t.Fatalf("change with a config that cannot be saved = %v", err)
			}
			cfg, err := rt.Config()
			if err != nil {
				t.Fatal(err)
			}
			if got, want := accountNames(cfg), "a/"+p1+" a/"+p2+" b/"+p2; got != want || cfg.CurrentProfile != "hollow" || cfg.Profiles["hollow"] == nil {
				t.Errorf("config in memory: accounts %q, current %q, profiles %v", got, cfg.CurrentProfile, cfg.ProfileNames())
			}
			// The next save writes exactly what the file held before.
			if err := cfg.Save(); err != nil {
				t.Fatal(err)
			}
			if after, _ := os.ReadFile(cfgPath); !bytes.Equal(before, after) {
				t.Errorf("the failed change reached the file with the next save:\n%s", after)
			}
			// A secret of an account that is not in the config is not kept.
			for _, key := range []string{creds.Key("fresh", p1), creds.Key("b", p1)} {
				if token(t, dir, key) != "" {
					t.Errorf("secret %s was left behind", key)
				}
			}
		})
	}
}

// In `auth manage` a failed action must not be shown as done.
func TestAuthManageDoesNotShowAFailedSwitch(t *testing.T) {
	_, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	var restore func()
	_, stderr, err, _ := runPick(t, cfgPath, []any{
		actUse,
		// The config becomes unwritable while the profile list is open, and
		// writable again while the menu is shown the next time.
		then{do: func() { restore = breakSaves(t, cfgPath) }, answer: "b"},
		then{do: func() { restore() }, answer: actQuit},
	}, "auth", "manage")
	if err != nil {
		t.Fatalf("auth manage: %v (stderr %q)", err, stderr)
	}
	i := strings.Index(stderr, "error: save config")
	if i < 0 || strings.Contains(stderr, `current profile set to "b"`) {
		t.Fatalf("stderr = %q, want the failed save reported", stderr)
	}
	if got := currentRows(stderr[i:]); len(got) != 2 || got[0] != "a" || got[1] != "a" {
		t.Errorf("rows marked current after the failed switch = %v in %q", got, stderr[i:])
	}
	if cfg := loadConfig(t, cfgPath); cfg.CurrentProfile != "a" {
		t.Errorf("current_profile on disk = %q", cfg.CurrentProfile)
	}
}

// While the menu of `auth manage` is open another polyctl process may change
// the config. The next action must build on that, not on the copy loaded
// when the menu was started.
func TestAuthManageKeepsChangesOfOtherProcesses(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	elsewhere := func() {
		// What `auth login` and `auth use` in another terminal do.
		cfg := loadConfig(t, cfgPath)
		cfg.Profiles["added"] = &config.Profile{Platforms: map[platform.ID]*config.Account{fakePlatform: {CredentialBackend: "file"}}}
		cfg.CurrentProfile = "added"
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}
		if err := creds.NewFile(dir).Set(creds.Key("added", p1), map[string]string{"token": "theirs"}); err != nil {
			t.Fatal(err)
		}
	}
	_, stderr, err, p := runPick(t, cfgPath, []any{
		then{do: elsewhere, answer: actRename}, "b", "b2",
		actQuit,
	}, "auth", "manage")
	if err != nil {
		t.Fatalf("auth manage: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, `profile "b" renamed to "b2"`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" a/"+p2+" added/"+p1+" b2/"+p2 || cfg.CurrentProfile != "added" {
		t.Errorf("accounts = %q, current = %q; the other process's changes were lost", got, cfg.CurrentProfile)
	}
	// The profile list offered for the rename already shows the new profile.
	if got := values(p.find("Rename which profile?").Options); got != "a added b" {
		t.Errorf("profiles offered = %q", got)
	}

	// A change made while a question of the action itself is open cannot be
	// merged; the action is refused instead of undoing it.
	_, cfgPath = setupMulti(t)
	removeB := func() {
		cfg := loadConfig(t, cfgPath)
		delete(cfg.Profiles, "b")
		cfg.Profiles["added"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
		if err := cfg.Save(); err != nil {
			t.Fatal(err)
		}
	}
	_, stderr, err, _ = runPick(t, cfgPath, []any{
		actUse, then{do: removeB, answer: "b"},
		actQuit,
	}, "auth", "manage")
	if err != nil {
		t.Fatalf("auth manage: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, "error: save config: "+config.ErrChanged.Error()) {
		t.Errorf("stderr = %q, want the save refused", stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if _, ok := cfg.Profiles["b"]; ok || cfg.Profiles["added"] == nil || cfg.CurrentProfile == "b" {
		t.Errorf("profiles = %v, current = %q; the other process's changes were undone", cfg.ProfileNames(), cfg.CurrentProfile)
	}
	// The table drawn after the error comes from the file again.
	if tail := stderr[strings.Index(stderr, "error: save config"):]; !strings.Contains(tail, "added") || strings.Contains(tail, "acct-b") {
		t.Errorf("table after the refused save = %q", tail)
	}
}

// An account of the pre-0.2 layout whose old entry sits in a backend that is
// out of reach (the keyring, on a session without one) can be logged in to
// again. The mark that the old entry still has to be removed must survive
// that, together with the name of the backend that holds it.
func TestAuthLoginKeepsLegacyMarkWhileOldBackendIsAway(t *testing.T) {
	dir, cfgPath := setup(t, false)
	legacy := "current_profile: old\nprofiles:\n  old:\n    platform: " + p1 + "\n    credential_backend: keyring\n"
	if err := os.WriteFile(cfgPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	account := func() *config.Account {
		t.Helper()
		a, err := loadConfig(t, cfgPath).Account("old", fakePlatform)
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	check := func(when string) {
		t.Helper()
		if a := account(); !a.LegacySecret || a.LegacySecretBackend() != "keyring" || a.CredentialBackend != "file" {
			t.Errorf("%s: legacy_secret %v, legacy backend %q, credential_backend %q; want true, keyring, file", when, a.LegacySecret, a.LegacySecretBackend(), a.CredentialBackend)
		}
	}
	if code, _, stderr := mainRun(cfgPath, "auth", "login", p1, "--profile", "old", "--set", "token=new"); code != ExitOK {
		t.Fatalf("auth login: exit %d (stderr %q)", code, stderr)
	}
	check("after the login")
	if token(t, dir, creds.Key("old", p1)) != "new" {
		t.Error("the new secret was not stored")
	}
	// Later runs that open the store must not drop the mark either.
	for _, args := range [][]string{{"auth", "status", "--offline"}, {"auth", "list"}, {"sync"}} {
		mainRun(cfgPath, args...)
		check("after " + strings.Join(args, " "))
	}
	// The profile cannot be renamed while the old entry would stay behind
	// under its name.
	if code, _, stderr := mainRun(cfgPath, "auth", "rename", "old", "new"); code != ExitError || !strings.Contains(stderr, `"keyring"`) {
		t.Errorf("auth rename: exit %d (stderr %q)", code, stderr)
	}
	// Removing the account says that the old entry was not removed.
	code, _, stderr := mainRun(cfgPath, "auth", "logout", "--profile", "old")
	if code != ExitOK || !strings.Contains(stderr, "is in the keyring backend, which is not available now, and was not removed") {
		t.Errorf("auth logout: exit %d (stderr %q)", code, stderr)
	}
	if strings.Contains(stderr, "are stored in the keyring backend") {
		t.Errorf("the current secret is in the file store and was removed: %q", stderr)
	}
	if token(t, dir, creds.Key("old", p1)) != "" || len(loadConfig(t, cfgPath).Profiles) != 0 {
		t.Error("the account was not removed")
	}
}

// A --profile / --platform selection that names no account is an error of
// the selection, online and offline, and not an empty or incomplete index.
func TestDomainCommandsCheckTheSelection(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")

	for _, args := range [][]string{
		{"domain", "list", "--profile", "nope"},
		{"domain", "list", "--profile", "nope", "--offline"},
		{"dns", "list", "one.example", "--profile", "nope", "--offline"},
		{"domain", "info", "one.example", "--profile", "nope", "--offline"},
		{"domain", "ns", "get", "one.example", "--profile", "nope", "--offline"},
	} {
		code, stdout, stderr := mainRun(cfgPath, args...)
		if code != ExitNotFound || stdout != "" || !strings.Contains(stderr, `profile "nope" not found`) || strings.Contains(stderr, "domain index") {
			t.Errorf("%v: exit %d (stdout %q, stderr %q), want the profile reported as not found", args, code, stdout, stderr)
		}
	}
	// Profile b has no account on the first platform.
	for _, args := range [][]string{
		{"domain", "list", "--profile", "b", "--platform", p1},
		{"domain", "info", "one.example", "--profile", "b", "--platform", p1, "--offline"},
		{"dns", "list", "one.example", "--profile", "b", "--platform", p1, "--offline"},
	} {
		code, stdout, stderr := mainRun(cfgPath, args...)
		if code != ExitNotFound || stdout != "" || !strings.Contains(stderr, "--profile / --platform") || strings.Contains(stderr, "when online") {
			t.Errorf("%v: exit %d (stdout %q, stderr %q), want the selection reported", args, code, stdout, stderr)
		}
	}
	// A valid selection without indexed rows says which filter was applied.
	stdout, _, err := run(t, cfgPath, "domain", "list", "--profile", "b")
	if err != nil || !strings.Contains(stdout, "no indexed domain or zone matches --profile / --platform") {
		t.Errorf("domain list --profile b = %q, %v", stdout, err)
	}
	// One with rows lists them, and offline misses still point at the index.
	stdout, _, err = run(t, cfgPath, "domain", "list", "--profile", "a", "--platform", p1)
	if err != nil || !strings.Contains(stdout, "one.example") {
		t.Errorf("domain list --profile a --platform %s = %q, %v", p1, stdout, err)
	}
	if code, _, stderr := mainRun(cfgPath, "dns", "list", "two.example", "--profile", "a", "--offline"); code != ExitNotFound || !strings.Contains(stderr, "run `polyctl domain index` when online") {
		t.Errorf("offline miss of a valid selection: exit %d (stderr %q)", code, stderr)
	}
	// Without a filter an empty index keeps its own text.
	_, cfgPath = setupMulti(t)
	if stdout, _, err := run(t, cfgPath, "domain", "list"); err != nil || !strings.Contains(stdout, "index is empty") {
		t.Errorf("domain list on an empty index = %q, %v", stdout, err)
	}
}

// A login flow can wait for the user for minutes. What another polyctl
// process saved meanwhile must survive, and the login must still succeed
// instead of being refused as a stale write.
func TestAuthLoginKeepsConcurrentConfigChanges(t *testing.T) {
	_, cfgPath := setupMulti(t)
	fakeMu.Lock()
	fakeLoginHook = func() {
		cfg := loadConfig(t, cfgPath)
		cfg.Profiles["other"] = &config.Profile{Platforms: map[platform.ID]*config.Account{
			fakePlatform2: {CredentialBackend: "file"},
		}}
		cfg.CurrentProfile = "other"
		if err := cfg.Save(); err != nil {
			t.Error(err)
		}
	}
	fakeMu.Unlock()
	_, stderr, err := run(t, cfgPath, "auth", "login", string(fakePlatform), "--profile", "fresh", "--set", "account=acct-fresh")
	if err != nil {
		t.Fatalf("auth login: %v (stderr %q)", err, stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if _, err := cfg.Account("other", fakePlatform2); err != nil {
		t.Errorf("the profile saved by the other process is gone: %v", err)
	}
	if cfg.CurrentProfile != "other" {
		t.Errorf("current_profile = %q, want the other process's choice kept", cfg.CurrentProfile)
	}
	if a, err := cfg.Account("fresh", fakePlatform); err != nil || a.Metadata["account"] != "acct-fresh" {
		t.Errorf("the new account was not saved: %+v, %v", a, err)
	}
}
