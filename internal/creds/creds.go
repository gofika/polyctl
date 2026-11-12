// Package creds stores profile secrets, preferring the OS keychain and
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

// Store persists secrets keyed by Key(profile, platform).
type Store interface {
	Name() string
	Get(profile string) (map[string]string, error)
	Set(profile string, secret map[string]string) error
	Delete(profile string) error
}

// Keyring uses the OS credential manager via go-keyring.
type Keyring struct{}

func (Keyring) Name() string { return "keyring" }

func (Keyring) Get(profile string) (map[string]string, error) {
	s, err := keyring.Get(service, profile)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return decode(s)
}

func (Keyring) Set(profile string, secret map[string]string) error {
	b, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	if err := keyring.Set(service, profile, string(b)); err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	return nil
}

func (Keyring) Delete(profile string) error {
	err := keyring.Delete(service, profile)
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

// File stores secrets in a JSON file with 0600 permissions.
type File struct {
	Path string
	mu   sync.Mutex
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

func (f *File) Get(profile string) (map[string]string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.load()
	if err != nil {
		return nil, err
	}
	s, ok := all[profile]
	if !ok {
		return nil, ErrNotFound
	}
	return s, nil
}

func (f *File) Set(profile string, secret map[string]string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.load()
	if err != nil {
		return err
	}
	all[profile] = secret
	return f.save(all)
}

func (f *File) Delete(profile string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	all, err := f.load()
	if err != nil {
		return err
	}
	delete(all, profile)
	return f.save(all)
}

func decode(s string) (map[string]string, error) {
	m := map[string]string{}
	if err := json.Unmarshal([]byte(s), &m); err != nil {
		return nil, fmt.Errorf("decode stored credentials: %w", err)
	}
	return m, nil
}

// Multi routes reads to whichever backend holds the profile and writes to
// the primary. It lets profiles stored in the file fallback keep working
// after the keyring becomes available (and vice versa).
type Multi struct {
	Primary Store
	Others  []Store
	// Warn is called once when the primary backend was downgraded.
	Warning string
}

func (m *Multi) Name() string { return m.Primary.Name() }

// Has reports whether a backend with this name is part of the store. An
// empty name (backend unknown) counts as present.
func (m *Multi) Has(backend string) bool {
	if backend == "" || m.Primary.Name() == backend {
		return true
	}
	for _, o := range m.Others {
		if o.Name() == backend {
			return true
		}
	}
	return false
}

func (m *Multi) Get(profile string) (map[string]string, error) {
	s, err := m.Primary.Get(profile)
	if err == nil {
		return s, nil
	}
	if !errors.Is(err, ErrNotFound) {
		return nil, err
	}
	for _, o := range m.Others {
		if s, err := o.Get(profile); err == nil {
			return s, nil
		}
	}
	return nil, ErrNotFound
}

// Set writes to the primary backend and removes any stale copy of the
// profile from the other backends, so a secret that once landed in the file
// fallback does not linger in plain text after the keyring took over.
func (m *Multi) Set(profile string, secret map[string]string) error {
	if err := m.Primary.Set(profile, secret); err != nil {
		return err
	}
	for _, o := range m.Others {
		if err := o.Delete(profile); err != nil && !errors.Is(err, ErrNotFound) {
			return fmt.Errorf("remove stale copy from %s: %w", o.Name(), err)
		}
	}
	return nil
}

func (m *Multi) Delete(profile string) error {
	var firstErr error
	for _, s := range append([]Store{m.Primary}, m.Others...) {
		if err := s.Delete(profile); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
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
