package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
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
		if acct["name"] != "a" || acct["platform"] != p1 || acct["current"] != false {
			t.Errorf("account row = %v", acct)
		}
		// The account has no timestamp: none is printed, as in YAML.
		if _, ok := acct["updated_at"]; ok || strings.Contains(stdout, "0001-01-01") {
			t.Errorf("json prints a zero timestamp: %s", stdout)
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
			// A removal notices before it removes anything.
			if err == nil || !strings.Contains(err.Error(), "save config") && !strings.Contains(err.Error(), "read config") {
				t.Fatalf("change with a config that cannot be saved = %v", err)
			}
			for _, key := range []string{creds.Key("a", p2), creds.Key("b", p2)} {
				if token(t, dir, key) == "" {
					t.Errorf("secret %s was removed although the account stays", key)
				}
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

// An unknown --profile, and a --profile / --platform selection that names no
// account able to hold the domain, are errors of the selection, online and
// offline, and not a domain missing from the index. `domain list` with a
// selection that names no account has nothing to list, which is no error.
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
	code, stdout, stderr := mainRun(cfgPath, "domain", "list", "--profile", "b", "--platform", p1)
	if code != ExitOK || !strings.Contains(stdout, "no indexed domain or zone matches --profile / --platform") || strings.Contains(stdout, "one.example") || stderr != "" {
		t.Errorf("domain list of a selection without accounts: exit %d (stdout %q, stderr %q), want nothing listed", code, stdout, stderr)
	}
	code, stdout, stderr = mainRun(cfgPath, "domain", "list", "--profile", "b", "--platform", p1, "-o", "json")
	var listed []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &listed); code != ExitOK || err != nil || len(listed) != 0 || strings.Contains(stderr, "error:") {
		t.Errorf("domain list -o json of a selection without accounts: exit %d (stdout %q, stderr %q, %v), want an empty list", code, stdout, stderr, err)
	}
	for _, args := range [][]string{
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

// `auth list` prints the same keys in JSON and YAML: an account without a
// timestamp has no updated_at in either, and never the zero time.
func TestAuthListOmitsMissingTimestamp(t *testing.T) {
	_, cfgPath := setupMulti(t)
	cfg := loadConfig(t, cfgPath)
	stamp := time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)
	cfg.Profiles["a"].Platforms[fakePlatform].UpdatedAt = stamp
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	jsonOut, _, err := run(t, cfgPath, "auth", "list", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	yamlOut, _, err := run(t, cfgPath, "auth", "list", "-o", "yaml")
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON, fromYAML []map[string]any
	if err := json.Unmarshal([]byte(jsonOut), &fromJSON); err != nil {
		t.Fatalf("json %q: %v", jsonOut, err)
	}
	if err := yaml.Unmarshal([]byte(yamlOut), &fromYAML); err != nil {
		t.Fatalf("yaml %q: %v", yamlOut, err)
	}
	if len(fromJSON) != 3 || len(fromYAML) != 3 {
		t.Fatalf("rows: json %d, yaml %d; want 3", len(fromJSON), len(fromYAML))
	}
	for i, row := range fromJSON {
		_, inJSON := row["updated_at"]
		_, inYAML := fromYAML[i]["updated_at"]
		if want := i == 0; inJSON != want || inYAML != want {
			t.Errorf("row %d (%v/%v): updated_at in json %v, in yaml %v; want %v", i, row["name"], row["platform"], inJSON, inYAML, want)
		}
		if len(row) != len(fromYAML[i]) {
			t.Errorf("row %d: json keys %v, yaml keys %v", i, row, fromYAML[i])
		}
	}
	if got := fromJSON[0]["updated_at"]; got != stamp.Format(time.RFC3339) {
		t.Errorf("updated_at = %v, want %s", got, stamp.Format(time.RFC3339))
	}
	for format, out := range map[string]string{"json": jsonOut, "yaml": yamlOut} {
		if strings.Contains(out, "0001-01-01") {
			t.Errorf("%s prints the zero time:\n%s", format, out)
		}
	}
}

// `domain which` lists every owner whatever --profile says, but a profile
// that does not exist is an error and not silently ignored.
func TestDomainWhichValidatesProfile(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")
	for _, extra := range [][]string{nil, {"--offline"}} {
		for _, domain := range []string{"one.example", "missing.example"} {
			args := append([]string{"domain", "which", domain, "--profile", "nosuch"}, extra...)
			code, stdout, stderr := mainRun(cfgPath, args...)
			if code != ExitNotFound || !strings.Contains(stderr, `profile "nosuch" not found`) || stdout != "" {
				t.Errorf("%v: exit %d, stdout %q, stderr %q; want the unknown profile reported", args, code, stdout, stderr)
			}
		}
		args := append([]string{"domain", "which", "one.example", "--platform", "bogus"}, extra...)
		if code, _, stderr := mainRun(cfgPath, args...); code != ExitUsage {
			t.Errorf("%v: exit %d (stderr %q), want a usage error", args, code, stderr)
		}
	}
	// A profile that exists narrows nothing: the owner in another profile
	// is still listed.
	stdout, _, err := run(t, cfgPath, "domain", "which", "one.example", "--profile", "b", "--offline")
	if err != nil || !strings.Contains(stdout, "one.example") {
		t.Errorf("domain which --profile b = %q, %v", stdout, err)
	}
}

// syncHeader is the table an empty sync report is rendered as.
const syncHeader = "PLATFORM  PROFILE  TYPE  COUNT  STATUS\n"

// wantNothingToDo checks a run that found nothing to act on: exit code 0 and
// exactly one line on stderr, the note, which is not printed as an error.
func wantNothingToDo(t *testing.T, what string, code int, stderr, note string) {
	t.Helper()
	if code != ExitOK {
		t.Errorf("%s: exit %d, want 0 (stderr %q)", what, code, stderr)
	}
	if want := "nothing to do: " + note + "\n"; stderr != want {
		t.Errorf("%s: stderr = %q, want %q", what, stderr, want)
	}
	if strings.Contains(stderr, "error:") {
		t.Errorf("%s: the note is printed as an error: %q", what, stderr)
	}
}

// wantEmptyJSONList checks that stdout holds a JSON list without elements,
// and not null or nothing at all, so a script can always parse it.
func wantEmptyJSONList(t *testing.T, what, stdout string) {
	t.Helper()
	var list []json.RawMessage
	if err := json.Unmarshal([]byte(stdout), &list); err != nil || list == nil || len(list) != 0 {
		t.Errorf("%s: stdout = %q (%v), want an empty JSON list", what, stdout, err)
	}
}

// With nothing configured the two bulk commands give the same answer: there
// is nothing to do, which is a note on stderr, an empty report on stdout and
// exit code 0.
func TestBulkCommandsWithoutAccounts(t *testing.T) {
	_, cfgPath := setup(t, false)
	notes := map[string]string{
		"sync":  "no accounts configured (run `polyctl auth login <platform>`)",
		"index": "no domain-capable accounts configured (run `polyctl auth login <platform>`)",
	}
	for _, args := range [][]string{{"sync"}, {"domain", "index"}} {
		what := strings.Join(args, " ") + " without accounts"
		note := notes[args[len(args)-1]]
		code, stdout, stderr := mainRun(cfgPath, args...)
		wantNothingToDo(t, what, code, stderr, note)
		if stdout != syncHeader {
			t.Errorf("%s: stdout = %q, want the empty report %q", what, stdout, syncHeader)
		}
		code, stdout, stderr = mainRun(cfgPath, append(args, "-o", "json")...)
		wantNothingToDo(t, what+" -o json", code, stderr, note)
		wantEmptyJSONList(t, what+" -o json", stdout)
	}
}

// A selection that names no account, or no account able to hold the
// requested types, leaves the bulk commands nothing to do as well; a profile
// that does not exist is still an error.
func TestBulkCommandsWithoutSelectedAccounts(t *testing.T) {
	_, cfgPath := setupMulti(t)
	for _, c := range []struct {
		args []string
		note string
	}{
		{[]string{"sync", "--profile", "b", "--platform", p1}, `profile "b" has no account on ` + p1 + " (see `polyctl auth list`)"},
		{[]string{"sync", "--platform", "aws"}, "no account on aws is configured (see `polyctl auth list`)"},
		{[]string{"sync", "--profile", "b", "--type", "instance"}, "no selected account supports the requested resource types"},
		{[]string{"domain", "index", "--platform", "aws"}, "no domain-capable account matches --profile / --platform"},
		{[]string{"domain", "index", "--profile", "b", "--platform", p1}, "no domain-capable account matches --profile / --platform"},
	} {
		what := strings.Join(c.args, " ")
		code, stdout, stderr := mainRun(cfgPath, c.args...)
		wantNothingToDo(t, what, code, stderr, c.note)
		if stdout != syncHeader {
			t.Errorf("%s: stdout = %q, want the empty report %q", what, stdout, syncHeader)
		}
		code, stdout, stderr = mainRun(cfgPath, append(c.args, "-o", "json")...)
		wantNothingToDo(t, what+" -o json", code, stderr, c.note)
		wantEmptyJSONList(t, what+" -o json", stdout)
	}
	for _, id := range []platform.ID{fakePlatform, fakePlatform2} {
		for _, profile := range []string{"a", "b"} {
			if n := clientOn(profile, id).count("Sync:"); n != 0 {
				t.Errorf("%s/%s was synced %d time(s) by commands with nothing to do", id, profile, n)
			}
		}
	}
	for _, args := range [][]string{
		{"sync", "--profile", "nope"},
		{"sync", "--profile", "nope", "-o", "json"},
		{"domain", "index", "--profile", "nope"},
	} {
		code, stdout, stderr := mainRun(cfgPath, args...)
		if code != ExitNotFound || stdout != "" || !strings.HasPrefix(stderr, "error: ") || !strings.Contains(stderr, `profile "nope" not found`) {
			t.Errorf("%v: exit %d (stdout %q, stderr %q), want the unknown profile reported as an error", args, code, stdout, stderr)
		}
	}
	for _, args := range [][]string{{"sync", "--platform", "bogus"}, {"sync", "--type", "bogus"}, {"domain", "index", "--platform", "bogus"}} {
		if code, _, stderr := mainRun(cfgPath, args...); code != ExitUsage || !strings.HasPrefix(stderr, "error: ") {
			t.Errorf("%v: exit %d (stderr %q), want a usage error", args, code, stderr)
		}
	}
}

// Main prints a nothing-to-do note as it is, and every other error with the
// "error:" prefix.
func TestMainPrintsNothingToDoAsNote(t *testing.T) {
	if !errors.Is(nothingToDo("no %s", "accounts"), errNothingToDo) || nothingToDo("no %s", "accounts").Error() != "nothing to do: no accounts" {
		t.Errorf("nothingToDo = %v", nothingToDo("no %s", "accounts"))
	}
	_, cfgPath := setup(t, false)
	code, _, stderr := mainRun(cfgPath, "sync")
	if code != ExitOK || !strings.HasPrefix(stderr, "nothing to do: ") || strings.Contains(stderr, "error") {
		t.Errorf("sync with nothing to do: exit %d, stderr %q", code, stderr)
	}
	code, _, stderr = mainRun(cfgPath, "sync", "--profile", "nope")
	if code != ExitNotFound || !strings.HasPrefix(stderr, "error: ") || strings.Contains(stderr, "nothing to do") {
		t.Errorf("sync of an unknown profile: exit %d, stderr %q", code, stderr)
	}
}

// otherProcessSaves changes the config file the way another polyctl process
// would while this one is running.
func otherProcessSaves(t *testing.T, cfgPath string, change func(*config.Config)) {
	t.Helper()
	cfg := loadConfig(t, cfgPath)
	change(cfg)
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}

// A removal from a stale copy of the config must stop before it removes
// anything: the save at its end would be refused, with the secret and the
// cached resources already gone and the account still listed.
func TestRemoveAccountChecksForChangesFirst(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	ref := config.AccountRef{Profile: "a", Platform: fakePlatform2}
	seedZone(t, dir, ref, "two.example")
	rt := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	defer rt.Close()
	if _, err := rt.Creds(); err != nil {
		t.Fatal(err)
	}
	otherProcessSaves(t, cfgPath, func(cfg *config.Config) { cfg.CurrentProfile = "b" })

	err := removeAccount(context.Background(), rt, ref, false)
	if !errors.Is(err, config.ErrChanged) || !strings.Contains(err.Error(), "nothing was removed") || strings.Contains(err.Error(), "nothing was saved") {
		t.Fatalf("removeAccount on a stale config = %v", err)
	}
	if token(t, dir, creds.Key("a", p2)) == "" {
		t.Error("the secret was removed")
	}
	if got := inventoryOwners(t, dir); !strings.Contains(got, "a/"+p2) {
		t.Errorf("the cached resources were purged: owners %q", got)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" a/"+p2+" b/"+p2 || cfg.CurrentProfile != "b" {
		t.Errorf("config on disk: accounts %q, current %q", got, cfg.CurrentProfile)
	}

	// With the config read again the same removal goes through.
	if _, err := rt.ReloadConfig(); err != nil {
		t.Fatal(err)
	}
	if err := removeAccount(context.Background(), rt, ref, false); err != nil {
		t.Fatal(err)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" b/"+p2 || cfg.CurrentProfile != "b" || token(t, dir, creds.Key("a", p2)) != "" {
		t.Errorf("after the retry: accounts %q, current %q", got, cfg.CurrentProfile)
	}
}

// `auth logout --profile` started on a copy of the config that another
// process has replaced since (two commands started together) removes from
// the file as it is now.
func TestAuthLogoutOnAConfigChangedSinceStart(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &out, &errb)
	defer rt.Close()
	if _, err := rt.Config(); err != nil {
		t.Fatal(err)
	}
	otherProcessSaves(t, cfgPath, func(cfg *config.Config) {
		cfg.Profiles["added"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	})
	root := NewRoot(rt)
	root.SetArgs([]string{"--config", cfgPath, "auth", "logout", "--profile", "a"})
	root.SetOut(&out)
	root.SetErr(&errb)
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("auth logout: %v (stderr %q)", err, errb.String())
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "b/"+p2 || cfg.Profiles["added"] == nil {
		t.Errorf("accounts %q, profiles %v; want a removed and the other process's profile kept", got, cfg.ProfileNames())
	}
	if token(t, dir, creds.Key("a", p1)) != "" || token(t, dir, creds.Key("a", p2)) != "" {
		t.Error("a secret of the removed profile is left")
	}
}

// While the questions of an interactive removal are open another polyctl
// process may save the config. The removal then works on the file as it is:
// that change is kept, what was chosen and still exists is removed, and
// nothing is half removed by a refused save.
func TestInteractiveRemovalAfterAChangeDuringThePrompts(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	addHollow(t, cfgPath, false)
	change := func() {
		otherProcessSaves(t, cfgPath, func(cfg *config.Config) {
			cfg.CurrentProfile = "b"
			// One chosen account and the chosen empty profile are gone.
			delete(cfg.Profiles["a"].Platforms, fakePlatform)
			delete(cfg.Profiles, "hollow")
			cfg.Profiles["added"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
		})
	}
	_, stderr, err, _ := runPick(t, cfgPath, []any{
		[]string{"a/" + p1, "a/" + p2, "b/" + p2, "hollow/"},
		true,
		then{do: change, answer: false},
	}, "auth", "logout")
	if err != nil {
		t.Fatalf("auth logout: %v (stderr %q)", err, stderr)
	}
	for _, want := range []string{
		"the " + p1 + ` account of profile "a" is no longer configured; skipped`,
		p2 + ` account removed from profile "a"`,
		p2 + ` account removed from profile "b"`,
		`profile "hollow" no longer exists; skipped`,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %q", want, stderr)
		}
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "" || cfg.Profiles["added"] == nil || len(cfg.Profiles) != 1 {
		t.Errorf("accounts %q, profiles %v; want only the profile the other process added", got, cfg.ProfileNames())
	}
	for _, key := range []string{creds.Key("a", p2), creds.Key("b", p2)} {
		if token(t, dir, key) != "" {
			t.Errorf("secret %s is left", key)
		}
	}
}

// An account of the pre-0.2 layout that has no secret anywhere the backend
// on record could hold one has nothing left to move: the mark goes, and the
// profile can be renamed like any other account without a secret.
func TestAuthRenameLegacyAccountWithoutSecret(t *testing.T) {
	dir, cfgPath := setup(t, false)
	legacy := "current_profile: lost\nprofiles:\n  lost:\n    platform: " + p1 + "\n    credential_backend: file\n    metadata:\n      account: acct-lost\n"
	if err := os.WriteFile(cfgPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	if code, _, stderr := mainRun(cfgPath, "auth", "status", "--offline"); code != ExitAuth {
		t.Fatalf("auth status without a secret: exit %d (stderr %q)", code, stderr)
	}
	raw, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "legacy_secret") || !strings.Contains(string(raw), "platforms:") {
		t.Errorf("config after the first run that opened the store:\n%s", raw)
	}
	if code, _, stderr := mainRun(cfgPath, "auth", "rename", "lost", "found"); code != ExitOK || !strings.Contains(stderr, `profile "lost" renamed to "found"`) {
		t.Fatalf("auth rename: exit %d (stderr %q)", code, stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "found/"+p1 || cfg.CurrentProfile != "found" || cfg.Profiles["found"].Platforms[fakePlatform].LegacySecret {
		t.Errorf("accounts %q, current %q", got, cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("found", p1)) != "" || token(t, dir, "lost") != "" {
		t.Error("a secret appeared")
	}
}

// leavingReader is a stdin on which nothing is ever typed: the first read
// calls leave, which is to end the prompt that reads, and then blocks until
// the test is over.
func leavingReader(t *testing.T, leave func()) io.Reader {
	t.Helper()
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	return readerFunc(func([]byte) (int, error) {
		leave()
		<-release
		return 0, io.EOF
	})
}

type readerFunc func([]byte) (int, error)

func (f readerFunc) Read(b []byte) (int, error) { return f(b) }

// A declined or left confirmation of `dns delete` deletes nothing and is not
// an error: the command exits 0 with a note.
func TestDNSDeleteDeclinedIsNotAnError(t *testing.T) {
	dir, cfgPath := setup(t, true)
	recs := []platform.Record{
		{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Content: "1.2.3.4"},
		{ID: "r2", ZoneID: "z1", Name: "www.example.com", Type: "A", Content: "5.6.7.8"},
	}
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{"z1": recs})
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.records["z1"] = append([]platform.Record(nil), recs...)
	cached := func() int {
		db := openInventory(t, dir)
		defer db.Close()
		rows, err := db.List(context.Background(), inventory.Query{Type: platform.ResDNSRecord})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	args := []string{"dns", "delete", "example.com", "--type", "A", "--name", "www"}
	deleted := func() bool { return fc.count("DeleteRecord") != 0 || len(fc.records["z1"]) != 2 || cached() != 2 }

	// The question belongs to the interactive flow. "n", and an empty
	// answer: the default is no.
	for _, answer := range []string{"n\n", "no\n", "\n"} {
		r := runFlow(t, context.Background(), cfgPath, &scriptedPicker{t: t}, strings.NewReader(answer), args...)
		if r.code != ExitOK || !errors.Is(r.err, errNothingToDo) || r.err.Error() != "nothing to do: no record was deleted" || strings.Contains(r.stderr, "deleted www") {
			t.Errorf("answer %q: %v, exit %d (stderr %q), want the note and exit code 0", answer, r.err, r.code, r.stderr)
		}
		if !strings.Contains(r.stderr, "delete 2 records in zone example.com (y/N)") || !strings.Contains(r.stderr, "1.2.3.4") || !strings.Contains(r.stderr, "5.6.7.8") {
			t.Errorf("answer %q: the records were not shown with the question: %q", answer, r.stderr)
		}
		if r.stdout != "" {
			t.Errorf("answer %q: stdout = %q, want nothing", answer, r.stdout)
		}
		if deleted() {
			t.Errorf("answer %q: records were deleted: calls %v, records %+v, %d cached", answer, fc.calls, fc.records["z1"], cached())
		}
	}

	// Leaving the question, here by interrupting the command while it
	// waits for the answer, is a no as well.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := runFlow(t, ctx, cfgPath, &scriptedPicker{t: t}, leavingReader(t, cancel), args...)
	if !errors.Is(r.err, errNothingToDo) || r.code != ExitOK || r.err.Error() != "nothing to do: no record was deleted" {
		t.Errorf("left confirmation = %v (exit %d), want nothing to do", r.err, r.code)
	}
	if r.stdout != "" || strings.Contains(r.stderr, "deleted www") || deleted() {
		t.Errorf("left confirmation: stdout %q, stderr %q, calls %v", r.stdout, r.stderr, fc.calls)
	}

	// The same through Main: the note is printed without "error:".
	// (Main has no terminal here, so it is the non-interactive flow: no
	// question, no read of stdin, a usage error that asks for --yes. A
	// piped "y" is data, not an answer.)
	var out, errb bytes.Buffer
	code := Main(append([]string{"--config", cfgPath}, args...), strings.NewReader("y\n"), &out, &errb)
	if code != ExitUsage || !strings.Contains(errb.String(), "error: usage error: confirmation required: pass --yes to proceed (would delete 2 records in zone example.com)") || strings.Contains(errb.String(), "(y/N)") || deleted() {
		t.Errorf("dns delete without a terminal: exit %d (stderr %q)", code, errb.String())
	}
	if !strings.Contains(errb.String(), "1.2.3.4") || !strings.Contains(errb.String(), "5.6.7.8") || out.Len() != 0 {
		t.Errorf("the refusal must show the affected records on stderr: stdout %q, stderr %q", out.String(), errb.String())
	}

	// No matching record is still an error.
	code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "--type", "A", "--name", "nope")
	if code != ExitNotFound || !strings.HasPrefix(stderr, "error: ") || strings.Contains(stderr, "nothing to do") {
		t.Errorf("dns delete without a match: exit %d (stderr %q)", code, stderr)
	}

	// Answering yes deletes both.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{t: t}, strings.NewReader("y\n"), args...)
	if r.code != ExitOK || r.err != nil || strings.Contains(r.stderr, "nothing to do") {
		t.Fatalf("confirmed dns delete: %v, exit %d (stderr %q)", r.err, r.code, r.stderr)
	}
	if fc.count("DeleteRecord") != 2 || len(fc.records["z1"]) != 0 || cached() != 0 {
		t.Errorf("confirmed dns delete: calls %v, records %+v, %d cached", fc.calls, fc.records["z1"], cached())
	}
}

// An action of `auth manage` that finds nothing to act on, because the
// config changed while the menu was open, prints a note and not an error.
func TestAuthManageNothingToDoIsANote(t *testing.T) {
	_, cfgPath := setup(t, true)
	hollow := func() {
		otherProcessSaves(t, cfgPath, func(cfg *config.Config) {
			cfg.Profiles["a"].Platforms = map[platform.ID]*config.Account{}
		})
	}
	empty := func() {
		otherProcessSaves(t, cfgPath, func(cfg *config.Config) {
			cfg.Profiles = map[string]*config.Profile{}
			cfg.CurrentProfile = ""
		})
	}
	stdout, stderr, err, p := runPick(t, cfgPath, []any{
		then{do: hollow, answer: actDetails},
		then{do: empty, answer: actUse},
		actQuit,
	}, "auth", "manage")
	if err != nil || stdout != "" {
		t.Fatalf("auth manage: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	for _, note := range []string{
		"\nnothing to do: no accounts configured\n",
		"\nnothing to do: no profiles configured (run `polyctl auth login <platform> [--profile <name>]`)\n",
	} {
		if strings.Count(stderr, note) != 1 {
			t.Errorf("stderr lacks the note %q: %q", note, stderr)
		}
	}
	if strings.Contains(stderr, "error:") {
		t.Errorf("a note was reported as an error: %q", stderr)
	}
	// The menu went on after each note, and nothing else was asked.
	if len(p.asked) != 3 || p.asked[0].Title != menuTitle || p.asked[1].Title != menuTitle || p.asked[2].Title != menuTitle {
		t.Fatalf("prompts = %v, want the menu three times", p.titles())
	}
	if got := values(p.asked[2].Options); got != actLogin+" "+actQuit {
		t.Errorf("menu after the config was emptied = %q", got)
	}
}
