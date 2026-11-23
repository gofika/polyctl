package cert

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Account is an ACME account of the store: its key, the e-mail address it
// was registered with and, once registered, its URI at the CA.
type Account struct {
	Email        string
	Key          crypto.Signer
	URI          string
	RegisteredAt time.Time
	// Dir is the directory of the account in the store.
	Dir string
}

// ID is the last path segment of the account URI (the account number of
// Let's Encrypt), or "" before registration.
func (a *Account) ID() string {
	if a == nil || a.URI == "" {
		return ""
	}
	u := strings.TrimRight(a.URI, "/")
	return u[strings.LastIndexByte(u, '/')+1:]
}

// accountFile is account.json.
type accountFile struct {
	URI          string `json:"uri"`
	Email        string `json:"email"`
	RegisteredAt string `json:"registered_at,omitempty"`
}

const (
	fileAccountKey  = "account.key"
	fileAccountJSON = "account.json"
)

// accountsDir is accounts/<host of the ACME directory>.
func (s *Store) accountsDir() string {
	host := directorySlug(s.Directory)
	if u, err := url.Parse(s.Directory); err == nil && u.Host != "" {
		host = strings.ToLower(u.Hostname())
	}
	return filepath.Join(s.Base, "accounts", host)
}

// AccountDir is the directory of the account registered with email: the
// first 12 hex digits of the SHA-256 of the lowercased address.
func (s *Store) AccountDir(email string) string {
	sum := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(email))))
	return filepath.Join(s.accountsDir(), hex.EncodeToString(sum[:])[:12])
}

// LoadAccount returns the account of email, or nil when the store has no
// key for it. An account whose key exists but was never registered (the
// registration failed after the key was written) has an empty URI.
func (s *Store) LoadAccount(email string) (*Account, error) {
	return s.loadAccountDir(s.AccountDir(email), email)
}

func (s *Store) loadAccountDir(dir, email string) (*Account, error) {
	data, err := os.ReadFile(filepath.Join(dir, fileAccountKey))
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKey(data)
	if err != nil {
		return nil, fmt.Errorf("account key %s: %w", dir, err)
	}
	a := &Account{Email: email, Key: key, Dir: dir}
	if data, err := os.ReadFile(filepath.Join(dir, fileAccountJSON)); err == nil {
		var f accountFile
		if err := json.Unmarshal(data, &f); err != nil {
			return nil, fmt.Errorf("%w: %s: %v", ErrCorrupt, filepath.Join(dir, fileAccountJSON), err)
		}
		a.URI = f.URI
		if a.Email == "" {
			a.Email = f.Email
		}
		a.RegisteredAt, _ = time.Parse(time.RFC3339, f.RegisteredAt)
	}
	return a, nil
}

// Accounts returns every account of the store's ACME directory.
func (s *Store) Accounts() ([]*Account, error) {
	entries, err := os.ReadDir(s.accountsDir())
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	var out []*Account
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		a, err := s.loadAccountDir(filepath.Join(s.accountsDir(), e.Name()), "")
		if err != nil {
			return nil, err
		}
		if a != nil {
			out = append(out, a)
		}
	}
	return out, nil
}

// NewAccount creates the key of a new account of email and writes it to
// the store (before the account is registered, so that a registration
// that succeeds never loses its key).
func (s *Store) NewAccount(email string) (*Account, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	a := &Account{Email: email, Key: key, Dir: s.AccountDir(email)}
	data, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	if err := mkdirs(s.Dir, a.Dir); err != nil {
		return nil, err
	}
	if err := writeFileSync(filepath.Join(a.Dir, fileAccountKey), data, 0o600); err != nil {
		return nil, err
	}
	return a, s.SaveAccount(a)
}

// SaveAccount writes account.json of a.
func (s *Store) SaveAccount(a *Account) error {
	f := accountFile{URI: a.URI, Email: a.Email}
	if !a.RegisteredAt.IsZero() {
		f.RegisteredAt = a.RegisteredAt.UTC().Format(time.RFC3339)
	}
	data, err := json.MarshalIndent(f, "", "  ")
	if err != nil {
		return err
	}
	if err := mkdirs(s.Dir, a.Dir); err != nil {
		return err
	}
	return writeFileSync(filepath.Join(a.Dir, fileAccountJSON), append(data, '\n'), 0o600)
}
