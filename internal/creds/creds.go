// Package creds stores account secrets, preferring the OS keychain and
// falling back to a 0600 JSON file under the config directory.
package creds

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"unicode/utf8"

	"github.com/zalando/go-keyring"

	"github.com/gofika/polyctl/internal/fsutil"
)

// Service is the keyring service of the default configuration directory.
// Other configuration directories use ServiceFor, so that two directories
// with a profile of the same name do not share (and overwrite or delete)
// each other's entries.
const Service = "polyctl"

// ServiceFor returns the keyring service of the configuration directory
// dir: Service for the default directory (defaultDir), else
// "polyctl:<first 16 hex digits of the SHA-256 of dir's absolute path>".
func ServiceFor(dir, defaultDir string) string {
	if dir == "" || samePath(dir, defaultDir) {
		return Service
	}
	sum := sha256.Sum256([]byte(canonical(dir)))
	return Service + ":" + hex.EncodeToString(sum[:8])
}

// canonical returns the absolute, cleaned form of path with symbolic links
// resolved when possible.
func canonical(path string) string {
	if abs, err := filepath.Abs(path); err == nil {
		path = abs
	}
	if real, err := filepath.EvalSymlinks(path); err == nil {
		path = real
	}
	return filepath.Clean(path)
}

// CanonicalDir is the form of a directory's path that ServiceFor hashes.
func CanonicalDir(dir string) string { return canonical(dir) }

// samePath reports whether a and b name the same directory: the same
// canonical path, or, on a case-insensitive file system such as the macOS
// default, the same directory spelled in another case.
func samePath(a, b string) bool {
	if a == "" || b == "" {
		return false
	}
	if canonical(a) == canonical(b) {
		return true
	}
	ai, err := os.Stat(a)
	if err != nil {
		return false
	}
	bi, err := os.Stat(b)
	return err == nil && os.SameFile(ai, bi)
}

// IsDirService reports whether s is a service ServiceFor returns for a
// directory other than the default one.
func IsDirService(s string) bool {
	h, ok := strings.CutPrefix(s, Service+":")
	if !ok || len(h) != 16 {
		return false
	}
	_, err := hex.DecodeString(h)
	return err == nil
}

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

// Keyring uses the OS credential manager via go-keyring. Service is the
// keyring service its entries are stored under ("" means Service).
type Keyring struct {
	Service string
	// Sources are the services where entries of the same configuration
	// directory may have been stored before (by earlier releases, or before
	// the directory moved), most recent first; Adopt reads them. nil means
	// the shared service Service, for every service but Service itself.
	Sources []string
}

func (k Keyring) sources() []string {
	src := k.Sources
	if src == nil && !k.Shared() {
		src = []string{Service}
	}
	var out []string
	for _, s := range src {
		if s != k.service() {
			out = append(out, s)
		}
	}
	return out
}

func (Keyring) Name() string { return "keyring" }

func (k Keyring) service() string {
	if k.Service == "" {
		return Service
	}
	return k.Service
}

// The keyring functions, replaced by tests that need a size limit.
var (
	keyringGet    = keyring.Get
	keyringSet    = keyring.Set
	keyringDelete = keyring.Delete
)

// partsField is the only field of the entry of a secret too big for one
// keyring entry (Windows Credential Manager takes at most 2560 bytes, the
// macOS keychain tool a command line of 4096). Its value "<gen>:<n>" names
// the n entries that hold the JSON of the secret, in order. No secret of an
// account or the data key has a field of this name.
const partsField = "polyctl:parts"

// partSize is the length in bytes of the parts a secret too big for one
// entry is split into: well below every keyring's limit.
const partSize = 1024

func partKey(key, gen string, i int) string { return fmt.Sprintf("%s/part/%s/%d", key, gen, i) }

// parts returns the part keys named by the raw entry s, nil when s is a
// whole secret.
func parts(key, s string) []string {
	var m map[string]string
	if json.Unmarshal([]byte(s), &m) != nil || len(m) != 1 {
		return nil
	}
	v, ok := m[partsField]
	if !ok {
		return nil
	}
	gen, n, ok := strings.Cut(v, ":")
	count, err := strconv.Atoi(n)
	if !ok || err != nil || count < 1 || count > 1000 {
		return nil
	}
	out := make([]string, count)
	for i := range out {
		out[i] = partKey(key, gen, i)
	}
	return out
}

// raw returns the JSON of the secret under key, joined from its parts when
// it was split.
func (k Keyring) raw(key string) (string, error) {
	s, err := keyringGet(k.service(), key)
	if err != nil {
		return "", err
	}
	ps := parts(key, s)
	if ps == nil {
		return s, nil
	}
	var b strings.Builder
	for _, p := range ps {
		v, err := keyringGet(k.service(), p)
		if err != nil {
			if errors.Is(err, keyring.ErrNotFound) {
				return "", fmt.Errorf("part %q of the entry %q is missing", p, key)
			}
			return "", err
		}
		b.WriteString(v)
	}
	return b.String(), nil
}

func (k Keyring) Get(key string) (map[string]string, error) {
	s, err := k.raw(key)
	if err != nil {
		if errors.Is(err, keyring.ErrNotFound) {
			return nil, ErrNotFound
		}
		return nil, fmt.Errorf("keyring: %w", err)
	}
	return decode(s)
}

// Set stores the secret as one entry, or, when the keyring refuses it as too
// big, as parts written before the entry that names them: an interrupted
// write leaves the previous secret readable. The parts of the previous
// secret are removed afterwards.
func (k Keyring) Set(key string, secret map[string]string) error {
	b, err := json.Marshal(secret)
	if err != nil {
		return err
	}
	var old []string
	if s, err := keyringGet(k.service(), key); err == nil {
		old = parts(key, s)
	}
	err = keyringSet(k.service(), key, string(b))
	if errors.Is(err, keyring.ErrSetDataTooBig) {
		err = k.setParts(key, string(b))
	}
	if err != nil {
		return fmt.Errorf("keyring: %w", err)
	}
	for _, p := range old {
		_ = keyringDelete(k.service(), p)
	}
	return nil
}

func (k Keyring) setParts(key, s string) error {
	g := make([]byte, 4)
	if _, err := rand.Read(g); err != nil {
		return err
	}
	gen := hex.EncodeToString(g)
	var chunks []string
	for len(s) > 0 {
		n := min(partSize, len(s))
		// Split on a character boundary: every part is valid UTF-8.
		for n < len(s) && n > 0 && !utf8.RuneStart(s[n]) {
			n--
		}
		chunks = append(chunks, s[:n])
		s = s[n:]
	}
	written := 0
	undo := func() {
		for i := range written {
			_ = keyringDelete(k.service(), partKey(key, gen, i))
		}
	}
	for i, c := range chunks {
		if err := keyringSet(k.service(), partKey(key, gen, i), c); err != nil {
			undo()
			return err
		}
		written++
	}
	head, _ := json.Marshal(map[string]string{partsField: fmt.Sprintf("%s:%d", gen, len(chunks))})
	if err := keyringSet(k.service(), key, string(head)); err != nil {
		undo()
		return err
	}
	return nil
}

func (k Keyring) Delete(key string) error {
	var ps []string
	if s, err := keyringGet(k.service(), key); err == nil {
		ps = parts(key, s)
	}
	err := keyringDelete(k.service(), key)
	if err != nil && !errors.Is(err, keyring.ErrNotFound) {
		return fmt.Errorf("keyring: %w", err)
	}
	for _, p := range ps {
		_ = keyringDelete(k.service(), p)
	}
	return nil
}

// Shared reports whether the keyring uses the service shared by the default
// configuration directory and earlier polyctl releases.
func (k Keyring) Shared() bool { return k.service() == Service }

// Adopt copies to the keyring's own service the entries under keys that it
// lacks and that exist under one of its sources (Sources; by default the
// shared service Service, where earlier releases stored the entries of every
// configuration directory). The source entries stay: they may belong to the
// default directory. It does nothing for the default directory's keyring. It
// returns the keys copied.
func (k Keyring) Adopt(keys []string) (copied []string, err error) {
	src := k.sources()
	if len(src) == 0 {
		return nil, nil
	}
	for _, key := range keys {
		_, err := k.Get(key)
		if err == nil {
			continue
		}
		if !errors.Is(err, ErrNotFound) {
			return copied, err
		}
		for _, svc := range src {
			s, err := (Keyring{Service: svc}).Get(key)
			if errors.Is(err, ErrNotFound) {
				continue
			}
			if err != nil {
				return copied, err
			}
			if err := k.Set(key, s); err != nil {
				return copied, err
			}
			copied = append(copied, key)
			break
		}
	}
	return copied, nil
}

// SourceValues returns the values the sources of the keyring (Sources) hold
// under key, most recent source first. Sources that fail to answer are
// skipped.
func (k Keyring) SourceValues(key string) []map[string]string {
	var out []map[string]string
	for _, svc := range k.sources() {
		if v, err := (Keyring{Service: svc}).Get(key); err == nil {
			out = append(out, v)
		}
	}
	return out
}

// Probe checks that the keyring is usable on this machine.
func (k Keyring) Probe() error {
	_, err := keyringGet(k.service(), "__polyctl_probe__")
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
// clash between concurrent writers), fsync, then rename over the target. On
// Windows the rename is retried for about a second while the target is open
// elsewhere (another process reading it, an antivirus), so that a rotated
// token is not lost to a reader that holds the file for a moment.
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
	return fsutil.Rename(tmp.Name(), f.Path)
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

// Keyring returns the keyring backend of the store, when it has one.
func (m *Multi) Keyring() (Keyring, bool) {
	for _, s := range m.stores() {
		if k, ok := s.(Keyring); ok {
			return k, true
		}
	}
	return Keyring{}, false
}

// File returns the file backend of the store, when it has one.
func (m *Multi) File() (*File, bool) {
	for _, s := range m.stores() {
		if f, ok := s.(*File); ok {
			return f, true
		}
	}
	return nil, false
}

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

// Lacks reports whether it is certain that the backend with this name holds
// no secret under key: the backend is part of the store and says so itself.
// A backend that is out of reach, or that fails to answer, proves nothing.
// An empty name (backend unknown) stands for every backend polyctl has, all
// of which must then be within reach.
func (m *Multi) Lacks(backend, key string) bool {
	if backend == "" {
		for _, known := range []string{Keyring{}.Name(), (&File{}).Name()} {
			if !m.Has(known) {
				return false
			}
		}
	}
	asked := false
	for _, s := range m.stores() {
		if backend != "" && s.Name() != backend {
			continue
		}
		asked = true
		if _, err := s.Get(key); !errors.Is(err, ErrNotFound) {
			return false
		}
	}
	return asked
}

// GetEach returns the secret stored under key by each backend that holds
// one, primary first, then the copies under the keyring's sources (where
// earlier releases, or the directory before it moved, stored it). Backends
// that fail to answer are skipped.
func (m *Multi) GetEach(key string) []map[string]string {
	var out []map[string]string
	for _, s := range m.stores() {
		if v, err := s.Get(key); err == nil {
			out = append(out, v)
		}
	}
	if k, ok := m.Keyring(); ok {
		out = append(out, k.SourceValues(key)...)
	}
	return out
}

// Adopt copies the entry under key from the keyring's sources to its own
// service when the keyring lacks it (Keyring.Adopt), and reports whether it
// did. A store without a keyring copies nothing.
func (m *Multi) Adopt(key string) (bool, error) {
	k, ok := m.Keyring()
	if !ok {
		return false, nil
	}
	copied, err := k.Adopt([]string{key})
	return len(copied) > 0, err
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

// Open selects a store for the configuration directory configDir. mode is
// "auto", "keyring" or "file". defaultDir is the default configuration
// directory: its keyring entries use Service, those of any other directory
// a service of their own (ServiceFor).
func Open(mode, configDir, defaultDir string) (*Multi, error) {
	return OpenKeyring(mode, configDir, Keyring{Service: ServiceFor(configDir, defaultDir)})
}

// OpenKeyring is Open with the keyring backend given: its service, and the
// services its entries may be adopted from.
func OpenKeyring(mode, configDir string, kr Keyring) (*Multi, error) {
	file := NewFile(configDir)
	switch mode {
	case "file":
		return &Multi{Primary: file}, nil
	case "keyring":
		if err := kr.Probe(); err != nil {
			return nil, fmt.Errorf("keyring unavailable: %w", err)
		}
		return &Multi{Primary: kr, Others: []Store{file}}, nil
	case "", "auto":
		if err := kr.Probe(); err != nil {
			return &Multi{
				Primary: file,
				Warning: fmt.Sprintf("system keyring unavailable (%v); storing credentials in %s (mode 0600)", err, file.Path),
			}, nil
		}
		return &Multi{Primary: kr, Others: []Store{file}}, nil
	}
	return nil, fmt.Errorf("unknown credential_store %q (expected auto, keyring or file)", mode)
}
