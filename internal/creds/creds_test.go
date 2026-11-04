package creds_test

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/creds"
)

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
