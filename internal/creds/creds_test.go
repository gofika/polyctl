package creds_test

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"

	"github.com/gofika/polyctl/internal/creds"
)

func TestKey(t *testing.T) {
	if got := creds.Key("acme", "cloudflare"); got != "acme/cloudflare" {
		t.Errorf("Key = %q, want acme/cloudflare", got)
	}
	// Keys of one profile differ per platform and never equal the bare
	// profile name used by the legacy layout.
	a, b := creds.Key("acme", "cloudflare"), creds.Key("acme", "aws")
	if a == b || a == "acme" || b == "acme" {
		t.Errorf("keys collide: %q, %q", a, b)
	}
}

// Accounts of one profile are stored independently, next to a secret still
// kept under the bare profile name by the legacy layout.
func TestFileStoreKeepsAccountsOfAProfileApart(t *testing.T) {
	f := creds.NewFile(t.TempDir())
	cf, aws := creds.Key("acme", "cloudflare"), creds.Key("acme", "aws")
	if err := f.Set("acme", map[string]string{"token": "legacy"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Set(cf, map[string]string{"token": "cf"}); err != nil {
		t.Fatal(err)
	}
	if err := f.Set(aws, map[string]string{"access_key": "ak"}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]map[string]string{
		"acme": {"token": "legacy"},
		cf:     {"token": "cf"},
		aws:    {"access_key": "ak"},
	} {
		got, err := f.Get(key)
		if err != nil {
			t.Fatalf("Get(%q): %v", key, err)
		}
		if !reflect.DeepEqual(got, want) {
			t.Errorf("Get(%q) = %v, want %v", key, got, want)
		}
	}
	if err := f.Delete(cf); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get(cf); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	if _, err := f.Get(aws); err != nil {
		t.Errorf("Delete removed another account of the profile: %v", err)
	}
	if _, err := f.Get("acme"); err != nil {
		t.Errorf("Delete removed the legacy key: %v", err)
	}
	// A reopened store reads the same file.
	if got, err := creds.NewFile(filepath.Dir(f.Path)).Get(aws); err != nil || got["access_key"] != "ak" {
		t.Errorf("reopened Get = %v, %v", got, err)
	}
}

func TestFileStoreSetGetDelete(t *testing.T) {
	dir := t.TempDir()
	f := creds.NewFile(dir)
	if f.Name() != "file" {
		t.Fatalf("Name() = %q", f.Name())
	}
	if f.Path != filepath.Join(dir, "credentials.json") {
		t.Fatalf("Path = %q", f.Path)
	}

	if _, err := f.Get("missing"); !errors.Is(err, creds.ErrNotFound) {
		t.Fatalf("Get(missing) = %v, want ErrNotFound", err)
	}
	// Deleting an unknown profile is not an error.
	if err := f.Delete("missing"); err != nil {
		t.Fatalf("Delete(missing) = %v", err)
	}

	secret := map[string]string{"token": "abc", "username": "me"}
	if err := f.Set("p1", secret); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if err := f.Set("p2", map[string]string{"key": "k"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if runtime.GOOS != "windows" {
		fi, err := os.Stat(f.Path)
		if err != nil {
			t.Fatal(err)
		}
		if fi.Mode().Perm() != 0o600 {
			t.Errorf("credentials file mode = %o, want 0600", fi.Mode().Perm())
		}
	}
	if _, err := os.Stat(f.Path + ".tmp"); !os.IsNotExist(err) {
		t.Errorf("temporary file left behind: %v", err)
	}

	got, err := f.Get("p1")
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if !reflect.DeepEqual(got, secret) {
		t.Errorf("Get = %v, want %v", got, secret)
	}

	// Overwrite replaces the whole secret.
	if err := f.Set("p1", map[string]string{"token": "new"}); err != nil {
		t.Fatal(err)
	}
	got, _ = f.Get("p1")
	if !reflect.DeepEqual(got, map[string]string{"token": "new"}) {
		t.Errorf("after overwrite Get = %v", got)
	}

	if err := f.Delete("p1"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := f.Get("p1"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("Get after Delete = %v, want ErrNotFound", err)
	}
	if _, err := f.Get("p2"); err != nil {
		t.Errorf("Delete removed an unrelated profile: %v", err)
	}
}

func TestFileStoreRejectsCorruptFile(t *testing.T) {
	dir := t.TempDir()
	f := creds.NewFile(dir)
	if err := os.WriteFile(f.Path, []byte("{not json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get("x"); err == nil || !strings.Contains(err.Error(), "parse") {
		t.Fatalf("Get on corrupt file = %v, want parse error", err)
	}
	// An empty file is treated as an empty store.
	if err := os.WriteFile(f.Path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := f.Get("x"); !errors.Is(err, creds.ErrNotFound) {
		t.Fatalf("Get on empty file = %v, want ErrNotFound", err)
	}
}

// errStore is a Store whose reads fail with a non-ErrNotFound error.
type errStore struct{ err error }

func (errStore) Name() string                            { return "err" }
func (s errStore) Get(string) (map[string]string, error) { return nil, s.err }
func (s errStore) Set(string, map[string]string) error   { return s.err }
func (s errStore) Delete(string) error                   { return s.err }

func TestMultiFallbackReadsFromOthers(t *testing.T) {
	primary := creds.NewFile(t.TempDir())
	other := creds.NewFile(t.TempDir())
	m := &creds.Multi{Primary: primary, Others: []creds.Store{other}}
	if m.Name() != "file" {
		t.Fatalf("Name() = %q", m.Name())
	}

	if err := other.Set("legacy", map[string]string{"token": "old"}); err != nil {
		t.Fatal(err)
	}
	got, err := m.Get("legacy")
	if err != nil {
		t.Fatalf("Get via fallback: %v", err)
	}
	if got["token"] != "old" {
		t.Errorf("Get via fallback = %v", got)
	}
	if _, err := m.Get("nobody"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("Get(nobody) = %v, want ErrNotFound", err)
	}

	// Writes go to the primary only.
	if err := m.Set("fresh", map[string]string{"token": "new"}); err != nil {
		t.Fatal(err)
	}
	if _, err := primary.Get("fresh"); err != nil {
		t.Errorf("primary does not hold the new secret: %v", err)
	}
	if _, err := other.Get("fresh"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("fallback store must not receive writes: %v", err)
	}
	// The primary wins when both hold the profile.
	if err := other.Set("fresh", map[string]string{"token": "stale"}); err != nil {
		t.Fatal(err)
	}
	if got, _ := m.Get("fresh"); got["token"] != "new" {
		t.Errorf("Get must prefer the primary: %v", got)
	}

	// Delete removes from every backend.
	if err := m.Delete("fresh"); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if _, err := primary.Get("fresh"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("primary still holds the profile after Delete: %v", err)
	}
	if _, err := other.Get("fresh"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("fallback still holds the profile after Delete: %v", err)
	}
	if err := m.Delete("legacy"); err != nil {
		t.Fatalf("Delete(legacy): %v", err)
	}
	if _, err := m.Get("legacy"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("legacy still readable after Delete: %v", err)
	}
}

func TestMultiPropagatesPrimaryErrors(t *testing.T) {
	boom := errors.New("boom")
	other := creds.NewFile(t.TempDir())
	_ = other.Set("p", map[string]string{"token": "x"})
	m := &creds.Multi{Primary: errStore{err: boom}, Others: []creds.Store{other}}
	if _, err := m.Get("p"); !errors.Is(err, boom) {
		t.Fatalf("Get = %v, want the primary error (no silent fallback)", err)
	}
	if err := m.Delete("p"); !errors.Is(err, boom) {
		t.Fatalf("Delete = %v, want the first error", err)
	}
	// The other backends are still cleaned even when the primary fails.
	if _, err := other.Get("p"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("Delete did not reach the fallback store: %v", err)
	}
}

func TestOpenFileMode(t *testing.T) {
	dir := t.TempDir()
	m, err := creds.Open("file", dir)
	if err != nil {
		t.Fatalf("Open(file): %v", err)
	}
	if m.Name() != "file" || m.Warning != "" || len(m.Others) != 0 {
		t.Fatalf("Open(file) = %+v", m)
	}
	if err := m.Set("p", map[string]string{"token": "t"}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "credentials.json")); err != nil {
		t.Fatalf("file store not written under config dir: %v", err)
	}
	if _, err := creds.Open("vault", dir); err == nil || !strings.Contains(err.Error(), "unknown credential_store") {
		t.Fatalf("Open(vault) = %v, want unknown mode error", err)
	}
}

func TestMultiSetRemovesStaleCopies(t *testing.T) {
	primary := creds.NewFile(t.TempDir())
	other := creds.NewFile(t.TempDir())
	m := &creds.Multi{Primary: primary, Others: []creds.Store{other}}
	// A secret that once landed in the fallback (keyring unavailable then).
	if err := other.Set("p", map[string]string{"token": "old"}); err != nil {
		t.Fatal(err)
	}
	if err := m.Set("p", map[string]string{"token": "new"}); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got, _ := primary.Get("p"); got["token"] != "new" {
		t.Errorf("primary = %v", got)
	}
	if _, err := other.Get("p"); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("stale copy must be removed from the fallback store: %v", err)
	}
}

func TestFileStoreLeavesNoTempFiles(t *testing.T) {
	dir := t.TempDir()
	f := creds.NewFile(dir)
	for i := 0; i < 3; i++ {
		if err := f.Set("p", map[string]string{"token": "t"}); err != nil {
			t.Fatal(err)
		}
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, e := range entries {
		names = append(names, e.Name())
	}
	// The lock file stays: removing it would race with a process that has
	// just opened it.
	if want := []string{"credentials.json", "credentials.lock"}; !reflect.DeepEqual(names, want) {
		t.Errorf("directory contents = %v, want %v", names, want)
	}
}

// Two File values on one path stand for two polyctl processes: each has its
// own mutex, so only the lock file keeps their read-change-write cycles from
// dropping each other's entries.
func TestFileStoreSerialisesWritersOnOnePath(t *testing.T) {
	dir := t.TempDir()
	const writers, rounds = 4, 25
	bare := func(i int) string { return fmt.Sprintf("p%d", i) }
	seed := creds.NewFile(dir)
	for i := 0; i < rounds; i++ {
		if err := seed.Set(bare(i), map[string]string{"token": bare(i)}); err != nil {
			t.Fatal(err)
		}
	}
	// Every writer moves every secret from its bare key to the new one, the
	// way the migration of the pre-0.2 layout does.
	var wg sync.WaitGroup
	errs := make(chan error, writers*rounds)
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m := &creds.Multi{Primary: creds.NewFile(dir)}
			for i := 0; i < rounds; i++ {
				errs <- m.Locked(func() error {
					key := creds.Key(bare(i), "cloudflare")
					if _, err := m.Get(key); err == nil {
						return m.Delete(bare(i))
					}
					secret, err := m.Get(bare(i))
					if err != nil {
						return err
					}
					if err := m.Set(key, secret); err != nil {
						return err
					}
					return m.Delete(bare(i))
				})
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < rounds; i++ {
		if s, err := seed.Get(creds.Key(bare(i), "cloudflare")); err != nil || s["token"] != bare(i) {
			t.Errorf("secret %d under the new key = %v, %v", i, s, err)
		}
		if _, err := seed.Get(bare(i)); !errors.Is(err, creds.ErrNotFound) {
			t.Errorf("bare key %d survived: %v", i, err)
		}
	}
}

// Plain concurrent Set calls through separate File values must all land.
func TestFileStoreConcurrentSetsKeepEveryKey(t *testing.T) {
	dir := t.TempDir()
	const writers, keys = 4, 20
	var wg sync.WaitGroup
	for w := 0; w < writers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			f := creds.NewFile(dir)
			for i := 0; i < keys; i++ {
				if err := f.Set(fmt.Sprintf("w%d/k%d", w, i), map[string]string{"token": "t"}); err != nil {
					t.Error(err)
				}
			}
		}()
	}
	wg.Wait()
	f := creds.NewFile(dir)
	for w := 0; w < writers; w++ {
		for i := 0; i < keys; i++ {
			if _, err := f.Get(fmt.Sprintf("w%d/k%d", w, i)); err != nil {
				t.Errorf("w%d/k%d: %v", w, i, err)
			}
		}
	}
}

func TestFileStoreWithLockIsReentrant(t *testing.T) {
	f := creds.NewFile(t.TempDir())
	err := f.WithLock(func() error {
		return f.WithLock(func() error { return f.Set("p/aws", map[string]string{"token": "t"}) })
	})
	if err != nil {
		t.Fatal(err)
	}
	if s, err := f.Get("p/aws"); err != nil || s["token"] != "t" {
		t.Errorf("Get = %v, %v", s, err)
	}
	// The lock is released: another File on the path can write.
	if err := creds.NewFile(filepath.Dir(f.Path)).Set("q/aws", map[string]string{"token": "u"}); err != nil {
		t.Fatal(err)
	}
}

// A lock file that cannot be opened makes writes fail and leaves reads alone.
func TestFileStoreWriteFailsWithoutLock(t *testing.T) {
	dir := t.TempDir()
	f := creds.NewFile(dir)
	if err := f.Set("p/aws", map[string]string{"token": "t"}); err != nil {
		t.Fatal(err)
	}
	lock := filepath.Join(dir, "credentials.lock")
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(lock, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := f.Set("p/aws", map[string]string{"token": "new"}); err == nil || !strings.Contains(err.Error(), "lock ") {
		t.Errorf("Set without a usable lock file = %v, want a lock error", err)
	}
	if err := f.Delete("p/aws"); err == nil {
		t.Error("Delete without a usable lock file must fail")
	}
	if s, err := f.Get("p/aws"); err != nil || s["token"] != "t" {
		t.Errorf("Get = %v, %v; the secret must be untouched", s, err)
	}
}

func TestMultiBackend(t *testing.T) {
	primary, other := creds.NewFile(t.TempDir()), creds.NewFile(t.TempDir())
	m := &creds.Multi{Primary: named{primary, "keyring"}, Others: []creds.Store{other}}
	if err := other.Set("a/aws", map[string]string{"token": "t"}); err != nil {
		t.Fatal(err)
	}
	if err := primary.Set("b/aws", map[string]string{"token": "t"}); err != nil {
		t.Fatal(err)
	}
	for key, want := range map[string]string{"a/aws": "file", "b/aws": "keyring", "c/aws": ""} {
		if got := m.Backend(key); got != want {
			t.Errorf("Backend(%q) = %q, want %q", key, got, want)
		}
	}
}

// named gives a store another backend name.
type named struct {
	creds.Store
	name string
}

func (n named) Name() string { return n.name }

// namedStore gives a store another backend name.
type namedStore struct {
	creds.Store
	name string
}

func (s namedStore) Name() string { return s.name }

// Lacks is true only when the backend itself says it has no such key.
func TestMultiLacks(t *testing.T) {
	file := creds.NewFile(t.TempDir())
	if err := file.Set("held", map[string]string{"token": "x"}); err != nil {
		t.Fatal(err)
	}
	fileOnly := &creds.Multi{Primary: file}
	both := &creds.Multi{Primary: namedStore{creds.NewFile(t.TempDir()), "keyring"}, Others: []creds.Store{file}}
	broken := &creds.Multi{Primary: namedStore{creds.NewFile(t.TempDir()), "keyring"}, Others: []creds.Store{errStore{errors.New("unreadable")}}}
	for _, tc := range []struct {
		name    string
		m       *creds.Multi
		backend string
		key     string
		want    bool
	}{
		{"absent from the named backend", fileOnly, "file", "missing", true},
		{"held by the named backend", fileOnly, "file", "held", false},
		{"backend not part of the store", fileOnly, "keyring", "missing", false},
		{"unknown backend, not every backend in reach", fileOnly, "", "missing", false},
		{"unknown backend, absent everywhere", both, "", "missing", true},
		{"unknown backend, held by one", both, "", "held", false},
		{"only the named backend is asked", both, "keyring", "held", true},
		{"a backend that fails proves nothing", broken, errStore{}.Name(), "missing", false},
	} {
		if got := tc.m.Lacks(tc.backend, tc.key); got != tc.want {
			t.Errorf("%s: Lacks(%q, %q) = %v, want %v", tc.name, tc.backend, tc.key, got, tc.want)
		}
	}
}
