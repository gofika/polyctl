// Package secrets keeps the login secrets of the instances polyctl creates
// (the Windows user name and password, and for AWS the private key that
// decrypts it) in the inventory database, sealed with AES-256-GCM.
//
// The 32-byte data key is generated on first use and kept in the credential
// store (the OS keyring, else credentials.json) under DataKeyName, never in
// the database. Every write uses a fresh random nonce, and the ciphertext is
// bound to its row (platform, location, instance id and user), so
// a sealed secret copied to another row does not open. Losing the data key
// makes the stored secrets unreadable; that is reported, never papered over.
package secrets

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// DataKeyName is the credential store key of the data key. It starts with
// a slash, which no profile name and no profile/platform key can, so it
// never collides with the secret of an account.
const DataKeyName = "/instance-secrets"

const (
	dataKeyField   = "key"
	dataKeyVersion = "v"
	dataKeyV1      = "1"
	dataKeyBytes   = 32
	aadPrefix      = "polyctl-instance-secret-v1"
)

// KeyStore is the part of the credential store the data key lives in
// (*creds.Multi).
type KeyStore interface {
	Get(key string) (map[string]string, error)
	Set(key string, secret map[string]string) error
	// Locked runs fn under the cross-process lock of the store, so that
	// two processes creating the data key at once do not each write one.
	Locked(fn func() error) error
	Name() string
}

// Ref names the stored credentials of one instance.
type Ref struct {
	Platform platform.ID `json:"platform" yaml:"platform"`
	Profile  string      `json:"profile" yaml:"profile"`
	// Location is the region, or the zone where instances live in one.
	Location   string `json:"location" yaml:"location"`
	InstanceID string `json:"id" yaml:"id"`
}

// Credentials are the login credentials of an instance.
type Credentials struct {
	Ref
	// Name is the instance name when it was stored.
	Name string `json:"instance" yaml:"instance"`
	User string `json:"user" yaml:"user"`
	// Password is the login password ("" while it is not known yet: an
	// AWS instance whose password is still being generated).
	Password string `json:"password" yaml:"password"`
	// PrivateKey is the PEM private key that decrypts an AWS Windows
	// password, when polyctl created the key pair. It is never shown.
	PrivateKey string    `json:"-" yaml:"-"`
	CreatedAt  time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt  time.Time `json:"updated_at" yaml:"updated_at"`
}

// sealed is what is encrypted.
type sealed struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
}

// ErrKeyLost is wrapped by the error of a read when secrets are stored but
// the data key is gone (or is another one): they cannot be decrypted. It
// is a general failure (exit code 1), not "not found".
var ErrKeyLost = errors.New("the data key of the stored instance secrets is missing or has changed")

// Store reads and writes sealed instance credentials.
type Store struct {
	db   *inventory.DB
	keys KeyStore
	key  []byte
}

// New returns a store on db, whose data key lives in keys.
func New(db *inventory.DB, keys KeyStore) *Store { return &Store{db: db, keys: keys} }

// dataKey returns the data key; create says a missing one may be generated
// (writes), otherwise a missing key is ErrKeyLost.
func (s *Store) dataKey(create bool) ([]byte, error) {
	if s.key != nil {
		return s.key, nil
	}
	var key []byte
	read := func() error {
		m, err := s.keys.Get(DataKeyName)
		if err != nil {
			return err
		}
		k, err := base64.StdEncoding.DecodeString(m[dataKeyField])
		if err != nil || len(k) != dataKeyBytes {
			return fmt.Errorf("%w: the entry %q in the credential store is not a %d-byte key", ErrKeyLost, DataKeyName, dataKeyBytes)
		}
		key = k
		return nil
	}
	err := read()
	switch {
	case err == nil:
	case errors.Is(err, creds.ErrNotFound) && create:
		err = s.keys.Locked(func() error {
			// Another process may have created it meanwhile.
			if err := read(); !errors.Is(err, creds.ErrNotFound) {
				return err
			}
			k := make([]byte, dataKeyBytes)
			if _, err := rand.Read(k); err != nil {
				return err
			}
			if err := s.keys.Set(DataKeyName, map[string]string{dataKeyField: base64.StdEncoding.EncodeToString(k), dataKeyVersion: dataKeyV1}); err != nil {
				return fmt.Errorf("store the data key of instance secrets: %w", err)
			}
			key = k
			return nil
		})
		if err != nil {
			return nil, err
		}
	case errors.Is(err, creds.ErrNotFound):
		return nil, fmt.Errorf("%w: no entry %q in the credential store (%s)", ErrKeyLost, DataKeyName, s.keys.Name())
	default:
		return nil, err
	}
	s.key = key
	return key, nil
}

func aad(r Ref, user string) []byte {
	// The profile is left out: it is a local name, which auth rename
	// changes on the rows.
	b, _ := json.Marshal([]string{aadPrefix, string(r.Platform), r.Location, r.InstanceID, user})
	return b
}

func gcm(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (r Ref) key() inventory.SecretKey {
	return inventory.SecretKey{Platform: r.Platform, Profile: r.Profile, Location: r.Location, InstanceID: r.InstanceID}
}

func (r Ref) check() error {
	if r.Platform == "" || r.Profile == "" || r.InstanceID == "" {
		return fmt.Errorf("instance secret: platform, profile and instance id are required")
	}
	return nil
}

// Ready makes sure secrets can be written: the data key is read, or
// created when there is none yet.
func (s *Store) Ready() error {
	_, err := s.dataKey(true)
	return err
}

// Put seals and stores the credentials of an instance, replacing any
// stored before.
func (s *Store) Put(ctx context.Context, c Credentials) error {
	if err := c.Ref.check(); err != nil {
		return err
	}
	key, err := s.dataKey(true)
	if err != nil {
		return err
	}
	aead, err := gcm(key)
	if err != nil {
		return err
	}
	plain, err := json.Marshal(sealed{Password: c.Password, PrivateKey: c.PrivateKey})
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ct := aead.Seal(nil, nonce, plain, aad(c.Ref, c.User))
	clear(plain)
	return s.db.PutSecret(ctx, inventory.SecretRow{SecretKey: c.Ref.key(), Name: c.Name, User: c.User, Nonce: nonce, Sealed: ct})
}

// open decrypts a row.
func (s *Store) open(row inventory.SecretRow) (Credentials, error) {
	ref := Ref{Platform: row.Platform, Profile: row.Profile, Location: row.Location, InstanceID: row.InstanceID}
	c := Credentials{Ref: ref, Name: row.Name, User: row.User, CreatedAt: row.CreatedAt, UpdatedAt: row.UpdatedAt}
	key, err := s.dataKey(false)
	if err != nil {
		return c, fmt.Errorf("cannot read the stored credentials of instance %s: %w", row.InstanceID, err)
	}
	aead, err := gcm(key)
	if err != nil {
		return c, err
	}
	if len(row.Nonce) != aead.NonceSize() {
		return c, fmt.Errorf("cannot read the stored credentials of instance %s: the stored nonce is malformed", row.InstanceID)
	}
	plain, err := aead.Open(nil, row.Nonce, row.Sealed, aad(ref, row.User))
	if err != nil {
		return c, fmt.Errorf("cannot decrypt the stored credentials of instance %s: %w (they were sealed with another data key, or the row was altered)", row.InstanceID, ErrKeyLost)
	}
	var v sealed
	err = json.Unmarshal(plain, &v)
	clear(plain)
	if err != nil {
		return c, fmt.Errorf("cannot read the stored credentials of instance %s: malformed content", row.InstanceID)
	}
	c.Password, c.PrivateKey = v.Password, v.PrivateKey
	return c, nil
}

// Get returns the credentials stored for an instance; none stored is an
// error wrapping platform.ErrNotFound.
func (s *Store) Get(ctx context.Context, r Ref) (*Credentials, error) {
	row, err := s.db.GetSecret(ctx, r.key())
	if err != nil {
		return nil, err
	}
	if row == nil {
		return nil, fmt.Errorf("%w: no credentials stored for instance %s", platform.ErrNotFound, r.InstanceID)
	}
	c, err := s.open(*row)
	if err != nil {
		return nil, err
	}
	return &c, nil
}

// Find returns the credentials stored for the instances of a profile whose
// id or name is ref, in location ("" for every location). Nothing stored
// is an empty list, not an error.
func (s *Store) Find(ctx context.Context, p platform.ID, profile, location, ref string) ([]Credentials, error) {
	rows, err := s.db.FindSecrets(ctx, p, profile, location, ref)
	if err != nil {
		return nil, err
	}
	// An id match wins over name matches: ids are unique, names are not.
	for _, r := range rows {
		if r.InstanceID == ref {
			rows = []inventory.SecretRow{r}
			break
		}
	}
	out := make([]Credentials, 0, len(rows))
	for _, row := range rows {
		c, err := s.open(row)
		if err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, nil
}

// Delete removes the credentials stored for an instance. Nothing stored is
// not an error. It needs no data key.
func (s *Store) Delete(ctx context.Context, r Ref) error {
	return s.db.DeleteSecret(ctx, r.key())
}
