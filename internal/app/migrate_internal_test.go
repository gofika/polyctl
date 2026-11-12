package app

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
)

// These tests drive migrateSecrets directly so the credential store can be a
// creds.Multi with a secondary backend, which Runtime.Creds only builds when
// the system keyring is in use.

const migrateLegacyConfig = `credential_store: file
profiles:
  old:
    platform: namecom
    credential_backend: file
`

// failingStore fails every call, like a keyring that cannot be reached.
type failingStore struct{ err error }

func (failingStore) Name() string                            { return "file" }
func (s failingStore) Get(string) (map[string]string, error) { return nil, s.err }
func (s failingStore) Set(string, map[string]string) error   { return s.err }
func (s failingStore) Delete(string) error                   { return s.err }

// stickyStore is a file store whose Delete can be made to fail.
type stickyStore struct {
	*creds.File
	deleteErr error
}

func (s *stickyStore) Delete(key string) error {
	if s.deleteErr != nil {
		return s.deleteErr
	}
	return s.File.Delete(key)
}

type migrateEnv struct {
	t         *testing.T
	rt        *Runtime
	cfg       *config.Config
	cfgPath   string
	primary   *creds.File
	secondary *creds.File
	stderr    *bytes.Buffer
}

func newMigrateEnv(t *testing.T) *migrateEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_OUTPUT", "")
	cfgPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfgPath, []byte(migrateLegacyConfig), 0o600); err != nil {
		t.Fatal(err)
	}
	e := &migrateEnv{t: t, cfgPath: cfgPath, stderr: &bytes.Buffer{},
		primary: creds.NewFile(t.TempDir()), secondary: creds.NewFile(t.TempDir())}
	e.rt = New(Flags{ConfigPath: cfgPath, Verbose: true}, strings.NewReader(""), &bytes.Buffer{}, e.stderr)
	cfg, err := e.rt.Config()
	if err != nil {
		t.Fatal(err)
	}
	e.cfg = cfg
	if !e.account().LegacySecret {
		t.Fatal("the legacy account must start with its mark")
	}
	return e
}

func (e *migrateEnv) multi() *creds.Multi {
	return &creds.Multi{Primary: e.primary, Others: []creds.Store{e.secondary}}
}

func (e *migrateEnv) account() *config.Account {
	e.t.Helper()
	a, err := e.cfg.Account("old", platform.NameCom)
	if err != nil {
		e.t.Fatal(err)
	}
	return a
}

// markedOnDisk reports whether the saved config still carries the legacy mark.
func (e *migrateEnv) markedOnDisk() bool {
	e.t.Helper()
	disk, err := config.Load(e.cfgPath)
	if err != nil {
		e.t.Fatal(err)
	}
	a, err := disk.Account("old", platform.NameCom)
	if err != nil {
		e.t.Fatal(err)
	}
	return a.LegacySecret
}

func tokenIn(t *testing.T, s creds.Store, key string) string {
	t.Helper()
	sec, err := s.Get(key)
	if errors.Is(err, creds.ErrNotFound) {
		return ""
	}
	if err != nil {
		t.Fatal(err)
	}
	return sec["token"]
}

func setToken(t *testing.T, s creds.Store, key, token string) {
	t.Helper()
	if err := s.Set(key, map[string]string{"token": token}); err != nil {
		t.Fatal(err)
	}
}

const newKey = "old/namecom"

func TestMigrateSecretsFromSecondaryBackend(t *testing.T) {
	e := newMigrateEnv(t)
	setToken(t, e.secondary, "old", "legacy")

	e.rt.migrateSecrets(e.cfg, e.multi())

	if got := tokenIn(t, e.primary, newKey); got != "legacy" {
		t.Errorf("primary[%s] = %q, want the migrated secret", newKey, got)
	}
	if tokenIn(t, e.secondary, "old") != "" || tokenIn(t, e.primary, "old") != "" {
		t.Error("the legacy key survived in a backend")
	}
	if tokenIn(t, e.secondary, newKey) != "" {
		t.Error("the migrated secret was written to the secondary backend")
	}
	a := e.account()
	if a.LegacySecret || e.markedOnDisk() {
		t.Error("the mark must be cleared in memory and on disk after the move")
	}
	if a.CredentialBackend != "file" {
		t.Errorf("credential_backend = %q, want the backend that now holds the secret", a.CredentialBackend)
	}
	if e.stderr.Len() != 0 {
		t.Errorf("unexpected verbose output %q", e.stderr.String())
	}
}

func TestMigrateSecretsKeepsMarkWhenNoSecretIsFound(t *testing.T) {
	e := newMigrateEnv(t)

	e.rt.migrateSecrets(e.cfg, e.multi())

	if !e.account().LegacySecret {
		t.Error("a missing secret does not prove there is nothing to move: the mark must stay")
	}
	if raw, _ := os.ReadFile(e.cfgPath); string(raw) != migrateLegacyConfig {
		t.Errorf("config must not be rewritten when nothing was migrated:\n%s", raw)
	}
	if tokenIn(t, e.primary, newKey) != "" || tokenIn(t, e.secondary, newKey) != "" {
		t.Error("a secret appeared under the new key")
	}
	// Not found is the normal case and stays silent, even with --verbose.
	if e.stderr.Len() != 0 {
		t.Errorf("unexpected verbose output %q", e.stderr.String())
	}

	// The secret turns up later (its backend became reachable): the kept mark
	// lets the next run finish the migration.
	setToken(t, e.secondary, "old", "late")
	e.rt.migrateSecrets(e.cfg, e.multi())
	if tokenIn(t, e.primary, newKey) != "late" || e.account().LegacySecret || e.markedOnDisk() {
		t.Errorf("late migration: new key %q, marked %v", tokenIn(t, e.primary, newKey), e.account().LegacySecret)
	}
}

func TestMigrateSecretsNeverOverwritesNewKey(t *testing.T) {
	// The new key in the primary backend, the legacy copy in either backend.
	for _, where := range []string{"primary", "secondary"} {
		t.Run("legacy in "+where, func(t *testing.T) {
			e := newMigrateEnv(t)
			setToken(t, e.primary, newKey, "refreshed")
			legacy := creds.Store(e.primary)
			if where == "secondary" {
				legacy = e.secondary
			}
			setToken(t, legacy, "old", "stale")

			e.rt.migrateSecrets(e.cfg, e.multi())

			if got := tokenIn(t, e.primary, newKey); got != "refreshed" {
				t.Errorf("new key = %q, the stale legacy copy overwrote it", got)
			}
			if tokenIn(t, e.primary, "old") != "" || tokenIn(t, e.secondary, "old") != "" {
				t.Error("the legacy copy must be removed once the new key exists")
			}
			a := e.account()
			if a.LegacySecret || e.markedOnDisk() {
				t.Error("the mark must be cleared")
			}
			if a.CredentialBackend != "file" {
				t.Errorf("credential_backend = %q, nothing was written so it must not change", a.CredentialBackend)
			}
		})
	}

	// The new key only in the secondary backend: it is found there and left
	// where it is.
	e := newMigrateEnv(t)
	setToken(t, e.secondary, newKey, "refreshed")
	setToken(t, e.primary, "old", "stale")
	e.rt.migrateSecrets(e.cfg, e.multi())
	if tokenIn(t, e.secondary, newKey) != "refreshed" || tokenIn(t, e.primary, newKey) != "" {
		t.Errorf("new key: secondary %q, primary %q", tokenIn(t, e.secondary, newKey), tokenIn(t, e.primary, newKey))
	}
	if tokenIn(t, e.primary, "old") != "" || e.account().LegacySecret {
		t.Error("the legacy copy and the mark must go once the new key exists")
	}

	// The new key exists and no legacy copy is left: only the mark is cleared.
	e = newMigrateEnv(t)
	setToken(t, e.primary, newKey, "refreshed")
	e.rt.migrateSecrets(e.cfg, e.multi())
	if tokenIn(t, e.primary, newKey) != "refreshed" || e.account().LegacySecret || e.markedOnDisk() {
		t.Errorf("new key %q, marked %v", tokenIn(t, e.primary, newKey), e.account().LegacySecret)
	}
}

func TestMigrateSecretsKeepsMarkWhenBackendUnreachable(t *testing.T) {
	e := newMigrateEnv(t)
	setToken(t, e.secondary, "old", "legacy")
	boom := errors.New("keyring locked")
	st := &creds.Multi{Primary: failingStore{err: boom}, Others: []creds.Store{e.secondary}}

	e.rt.migrateSecrets(e.cfg, st)

	if !e.account().LegacySecret {
		t.Error("the mark must stay when the store cannot be read")
	}
	if raw, _ := os.ReadFile(e.cfgPath); string(raw) != migrateLegacyConfig {
		t.Errorf("config must not be rewritten:\n%s", raw)
	}
	if tokenIn(t, e.secondary, "old") != "legacy" {
		t.Error("the legacy secret must be left alone")
	}
	if got := e.stderr.String(); !strings.Contains(got, "migrate credentials of namecom/old: keyring locked") {
		t.Errorf("verbose output = %q", got)
	}
}

func TestMigrateSecretsRetriesLegacyRemoval(t *testing.T) {
	e := newMigrateEnv(t)
	setToken(t, e.secondary, "old", "legacy")
	sticky := &stickyStore{File: e.secondary, deleteErr: errors.New("read-only")}
	st := &creds.Multi{Primary: e.primary, Others: []creds.Store{sticky}}

	e.rt.migrateSecrets(e.cfg, st)

	// Multi.Set removes stale copies from the other backends and reports the
	// failure, so the secret may or may not have reached the primary; either
	// way the legacy copy is intact and the mark is kept.
	if tokenIn(t, e.secondary, "old") != "legacy" || !e.account().LegacySecret {
		t.Fatalf("legacy copy %q, marked %v", tokenIn(t, e.secondary, "old"), e.account().LegacySecret)
	}
	if raw, _ := os.ReadFile(e.cfgPath); string(raw) != migrateLegacyConfig {
		t.Errorf("config must not be rewritten:\n%s", raw)
	}
	if !strings.Contains(e.stderr.String(), "credentials of namecom/old: ") {
		t.Errorf("verbose output = %q", e.stderr.String())
	}

	// Once the backend accepts deletes again the next run finishes the job.
	sticky.deleteErr = nil
	e.rt.migrateSecrets(e.cfg, st)
	if tokenIn(t, e.primary, newKey) != "legacy" || tokenIn(t, e.secondary, "old") != "" || e.account().LegacySecret || e.markedOnDisk() {
		t.Errorf("after the retry: new key %q, legacy %q, marked %v", tokenIn(t, e.primary, newKey), tokenIn(t, e.secondary, "old"), e.account().LegacySecret)
	}
}

// A secret recorded in a backend that is not part of the store opened for
// this run (the keyring on a headless session) cannot be moved or removed:
// the mark must survive, and a later run with that backend finishes the job.
func TestMigrateSecretsSkipsUnreachableBackend(t *testing.T) {
	e := newMigrateEnv(t)
	e.account().CredentialBackend = "keyring"
	before, err := os.ReadFile(e.cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	e.rt.migrateSecrets(e.cfg, &creds.Multi{Primary: e.primary})
	if !e.account().LegacySecret {
		t.Fatal("the mark must survive while the recorded backend is out of reach")
	}
	if after, _ := os.ReadFile(e.cfgPath); string(after) != string(before) {
		t.Error("the config must not be rewritten")
	}
	// Even with a secret already under the new key (a login in between).
	if err := e.primary.Set(creds.Key("old", "namecom"), map[string]string{"token": "new"}); err != nil {
		t.Fatal(err)
	}
	e.rt.migrateSecrets(e.cfg, &creds.Multi{Primary: e.primary})
	if !e.account().LegacySecret {
		t.Fatal("the mark must survive: the legacy entry in the other backend was not removed")
	}
}
