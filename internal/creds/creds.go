// Package creds stores account secrets, preferring the OS keychain and
// falling back to a 0600 JSON file under the config directory.
package creds

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/zalando/go-keyring"
)

const service = "polyctl"

// ErrNotFound is returned when no secret exists under a key.
var ErrNotFound = errors.New("credentials not found")

// Key is the store key of a profile's account on a platform. Profile names
// cannot contain a slash, so the key is unambiguous and never collides with
// the bare profile names used before profiles could hold several platforms.
func Key(profile, platform string) string { return profile + "/" + platform }

// Store persists secrets keyed by Key(profile, platform). Secrets written
// before 0.2 are keyed by the bare profile name.
type Store interface {
	Name() string
	Get(key string) (map[string]string, error)
	Set(key string, secret map[string]string) error
	Delete(key string) error
}

// Keyring uses the OS credential manager via go-keyring.
type Keyring struct{}

func (Keyring) Name() string { return "keyring" }

func (Keyring) Get(key string) (map[string]string, error) {
	s, err := keyring.Get(service, key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return decode(s)
}

func (Keyring) Set(key string, secret map[string]string) error {
	b, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	if err := keyring.Set(service, key, string(b)); err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	return nil
}

func (Keyring) Delete(key string) error {
	err := keyring.Delete(service, key)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keyring: %w", err)
	}
	return nil
}

// Probe checks that the keyring is usable on this machine.
func (k Keyring) Probe() error {
	_, err := keyring.Get(service, "__polyctl_probe__")
	if err == nil || errors.Is(err, keyring.ErrNotFound) {
		return nil
	}
	return err
}

// File stores secrets in a JSON file with 0600 permissions. Changes are
// serialised between processes by an advisory lock on a file next to it
// (credentials.lock): without it two polyctl processes that each read, change
// and rewrite the file would drop each other's entries.
type File struct {
	Path string
	mu   sync.Mutex
	// held is set while WithLock holds the cross-process lock.
	held bool
}

// NewFile returns a file store at dir/credentials.json.
func NewFile(dir string) *File { return &File{Path: filepath.Join(dir, "credentials.json")} }

func (f *File) Name() string { return "file" }

func (f *File) load() (map[string]map[string]string, error) {
	out := map[string]map[string]string{}
	b, err := os.ReadFile(f.Path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return out, nil
		}
		return nil, err
	}
	if len(b) == 0 {
		return out, nil
	}
	if err := json.Unmarshal(b, &out); err != nil {
		return nil, fmt.Errorf("parse %s: %w", f.Path, err)
	}
	return out, nil
}

// save writes the file atomically: a fresh private temporary file (O_EXCL,
// 0600 from creation, so no permission window, no symlink following and no
// clash between concurrent writers), fsync, then rename over the target.
func (f *File) save(all map[string]map[string]string) error {
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(all, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".credentials.json.*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), f.Path)
}

// WithLock runs fn while holding the cross-process lock of the file, so
// that a sequence of reads and writes is not interleaved with the writes of
// another polyctl process. The store's own calls made by fn run under the
// same lock.
func (f *File) WithLock(fn func() error) error {
	f.mu.Lock()
	if f.held {
		f.mu.Unlock()
		return fn()
	}
	dir := filepath.Dir(f.Path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		f.mu.Unlock()
		return err
	}
	unlock, err := lockFile(filepath.Join(dir, "credentials.lock"))
	if err != nil {
		f.mu.Unlock()
		return fmt.Errorf("lock %s: %w", f.Path, err)
	}
	f.held = true
	f.mu.Unlock()
	defer func() {
		f.mu.Lock()
		f.held = false
		f.mu.Unlock()
		unlock()
	}()
	return fn()
}

func (f *File) Get(key string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.load()
	if err != nil {
		return nil, err
	}
	s, ok := all[key]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

// update reads the file, applies change and writes it back, as one step
// with regard to other processes.
func (f *File) update(change func(all map[string]map[string]string)) error {
	return f.WithLock(func() error {
		f.mu.Lock()
		defer f.mu.Unlock()
		all, err := f.load()
		if err != nil {
			return err
		}
		change(all)
		return f.save(all)
	})
}

func (f *File) Set(key string, secret map[string]string) error {
	return f.update(func(all map[string]map[string]string) { all[key] = secret })
}

func (f *File) Delete(key string) error {
	return f.update(func(all map[string]map[string]string) { delete(all, key) })
}

func decode(s string) (map[string]string, error) {
	m := map[string]string{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("decode stored credentials: %w", err)
	}
	return m, nil
}

// Multi routes reads to whichever backend holds the key and writes to the
// primary. It lets secrets stored in the file fallback keep working after
// the keyring becomes available (and vice versa).
type Multi struct {
	Primary Store
	Others  []Store
	// Warn is called once when the primary backend was downgraded.
	Warning string
}

func (m *Multi) Name() string { return m.Primary.Name() }

func (m *Multi) stores() []Store { return append([]Store{m.Primary}, m.Others...) }

// Has reports whether a backend with this name is part of the store. An
// empty name (backend unknown) counts as present.
func (m *Multi) Has(backend string) bool {
	if backend == "" {
		return true
	}
	for _, s := range m.stores() {
		if s.Name() == backend {
			return true
		}
	}
	return false
}

// Backend returns the name of the backend a Get of key is served from, or ""
// when no backend holds it (or it cannot be read).
func (m *Multi) Backend(key string) string {
	for _, s := range m.stores() {
		if _, err := s.Get(key); err == nil {
			return s.Name()
		}
	}
	return ""
}

// Locked runs fn while holding the cross-process lock of every backend that
// has one (the file store), so that a check followed by a write is not
// interleaved with another polyctl process doing the same. Set and Delete
// take the lock by themselves; calls nested in fn share it.
func (m *Multi) Locked(fn func() error) error {
	for _, s := range m.stores() {
		if l, ok := s.(interface{ WithLock(func() error) error }); ok {
			inner := fn
			fn = func() error { return l.WithLock(inner) }
		}
	}
	return fn()
}

func (m *Multi) Get(key string) (map[string]string, error) {
	s, err := m.Primary.Get(key)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	for _, o := range m.Others {
		if s, err := o.Get(key); err == nil {
			return s, nil
		}
	}
	return nil, ErrNotFound
}

// Set writes to the primary backend and removes any stale copy of the key
// from the other backends, so a secret that once landed in the file fallback
// does not linger in plain text after the keyring took over.
func (m *Multi) Set(key string, secret map[string]string) error {
	return m.Locked(func() error {
		if err := m.Primary.Set(key, secret); err != nil {
			return err
		}
		for _, o := range m.Others {
			if err := o.Delete(key); err != nil && !errors.Is(err, ErrNotFound) {
				return fmt.Errorf("remove stale copy from %s: %w", o.Name(), err)
			}
		}
		return nil
	})
}

func (m *Multi) Delete(key string) error {
	return m.Locked(func() error {
		var firstErr error
		for _, s := range m.stores() {
			if err := s.Delete(key); err != nil && firstErr == nil {
				firstErr = err
			}
		}
		return firstErr
	})
}

// Open selects a store. mode is "auto", "keyring" or "file".
func Open(mode, configDir string) (*Multi, error) {
	file := NewFile(configDir)
	switch mode {
	case "file":
		return &Multi{Primary: file}, nil
	case "keyring":
		if err := (Keyring{}).Probe(); err != nil {
			return nil, fmt.Errorf("keyring unavailable: %w", err)
		}
		return &Multi{Primary: Keyring{}, Others: []Store{file}}, nil
	case "", "auto":
		if err := (Keyring{}).Probe(); err != nil {
			return &Multi{
				Primary: file,
				Warning: fmt.Sprintf("system keyring unavailable (%v); storing credentials in %s (mode 0600)", err, file.Path),
			}, nil
		}
		return &Multi{Primary: Keyring{}, Others: []Store{file}}, nil
	}
	return nil, fmt.Errorf("unknown credential_store %q (expected auto, keyring or file)", mode)
}
