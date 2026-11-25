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
	"bytes"
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
	PrivateKey string `json:"-" yaml:"-"`
	// KeyPair is the name of the key pair polyctl created for the
	// instance (an AWS Windows instance launched without a key of the
	// user's), so that deleting the instance deletes it too; "" when the
	// key pair is the user's, which polyctl never deletes.
	KeyPair string `json:"-" yaml:"-"`
	// Detached says the credentials were stored for an account that was
	// logged out of the profile (inventory.DetachSecrets): the account now
	// under the profile's name may be another one.
	Detached  bool      `json:"-" yaml:"-"`
	CreatedAt time.Time `json:"created_at" yaml:"created_at"`
	UpdatedAt time.Time `json:"updated_at" yaml:"updated_at"`
}

// sealed is what is encrypted.
type sealed struct {
	Password   string `json:"password,omitempty"`
	PrivateKey string `json:"private_key,omitempty"`
	KeyPair    string `json:"key_pair,omitempty"`
}

// ErrKeyLost is wrapped by the error of a read when secrets are stored but
// the data key is gone (or is another one): they cannot be decrypted. It
// is a general failure (exit code 1), not "not found".
var ErrKeyLost = errors.New("the data key of the stored instance secrets is missing or has changed")

// Optional parts of a KeyStore (*creds.Multi has them).
type (
	// lacker reports whether it is certain that no backend holds key:
	// every backend polyctl has is within reach and says so.
	lacker interface {
		Lacks(backend, key string) bool
	}
	// eacher returns the copy of key held by each backend.
	eacher interface {
		GetEach(key string) []map[string]string
	}
	// adopter copies key from where earlier releases stored it, when the
	// store lacks it, and reports whether it did.
	adopter interface {
		Adopt(key string) (bool, error)
	}
	// haser reports whether a backend is part of the store.
	haser interface {
		Has(backend string) bool
	}
)

// Store reads and writes sealed instance credentials.
type Store struct {
	db   *inventory.DB
	keys KeyStore
	key  []byte
	// others are the data keys other backends hold, when they differ
	// from key (a store forked by an earlier release); nil until a row
	// fails to open with key.
	others [][]byte
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
		k, err := decodeKey(m)
		if err != nil {
			return err
		}
		key = k
		return nil
	}
	err := read()
	if errors.Is(err, creds.ErrNotFound) {
		// A configuration directory other than the default one keeps the
		// key under a keyring service of its own; earlier releases (or the
		// directory before it moved) stored it under another one.
		if a, ok := s.keys.(adopter); ok {
			if copied, aerr := a.Adopt(DataKeyName); aerr == nil && copied {
				err = read()
			}
		}
	}
	switch {
	case err == nil:
	case errors.Is(err, creds.ErrNotFound) && create:
		err = s.keys.Locked(func() error {
			// Another process may have created it meanwhile.
			if err := read(); !errors.Is(err, creds.ErrNotFound) {
				return err
			}
			if err := s.mayCreateKey(); err != nil {
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
		return nil, fmt.Errorf("%w: no entry %q in the credential store (%s)%s", ErrKeyLost, DataKeyName, s.keys.Name(), s.keyringHint())
	default:
		return nil, err
	}
	s.key = key
	return key, nil
}

func decodeKey(m map[string]string) ([]byte, error) {
	k, err := base64.StdEncoding.DecodeString(m[dataKeyField])
	if err != nil || len(k) != dataKeyBytes {
		return nil, fmt.Errorf("%w: the entry %q in the credential store is not a %d-byte key", ErrKeyLost, DataKeyName, dataKeyBytes)
	}
	return k, nil
}

// mayCreateKey reports, as an error, why a new data key must not be
// generated. A missing key may be created when no secret is stored yet, or
// when every backend polyctl has is within reach and none holds it (the key
// is lost; a new one at least serves new secrets). Otherwise the key may well
// be in a backend this run cannot reach, such as a keyring that is locked or
// missing in an SSH or cron session: a second key would leave the stored
// secrets split between two keys, each readable in one kind of session only.
func (s *Store) mayCreateKey() error {
	n, err := s.db.CountSecrets(context.Background())
	if err != nil {
		return err
	}
	if n == 0 {
		return nil
	}
	if l, ok := s.keys.(lacker); ok && l.Lacks("", DataKeyName) {
		return nil
	}
	return fmt.Errorf("%w: %d instance secrets are stored, but the credential store this run can reach (%s) has no entry %q, and no new key is created while it may be in a backend out of reach%s",
		ErrKeyLost, n, s.keys.Name(), DataKeyName, s.keyringHint())
}

// keyringHint is the advice added to a missing data key error when the
// system keyring is not part of the store in this run.
func (s *Store) keyringHint() string {
	if h, ok := s.keys.(haser); ok && !h.Has(creds.Keyring{}.Name()) {
		return "; the system keyring is not available in this run: run polyctl where it is (a desktop session), or set credential_store / POLYCTL_CREDENTIAL_STORE to the store that holds the key"
	}
	return ""
}

// otherKeys returns the data keys held by backends other than the one key
// was read from, when they differ from it.
func (s *Store) otherKeys() [][]byte {
	if s.others != nil {
		return s.others
	}
	s.others = [][]byte{}
	e, ok := s.keys.(eacher)
	if !ok {
		return s.others
	}
	for _, m := range e.GetEach(DataKeyName) {
		if k, err := decodeKey(m); err == nil && !bytes.Equal(k, s.key) {
			s.others = append(s.others, k)
		}
	}
	return s.others
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
	plain, err := json.Marshal(sealed{Password: c.Password, PrivateKey: c.PrivateKey, KeyPair: c.KeyPair})
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
		// Sealed with the key another backend holds: a store forked by an
		// earlier release while the keyring was out of reach.
		for _, k := range s.otherKeys() {
			if a, gerr := gcm(k); gerr == nil {
				if plain, err = a.Open(nil, row.Nonce, row.Sealed, aad(ref, row.User)); err == nil {
					break
				}
			}
		}
	}
	if err != nil {
		return c, fmt.Errorf("cannot decrypt the stored credentials of instance %s: %w (they were sealed with another data key, or the row was altered)", row.InstanceID, ErrKeyLost)
	}
	var v sealed
	err = json.Unmarshal(plain, &v)
	clear(plain)
	if err != nil {
		return c, fmt.Errorf("cannot read the stored credentials of instance %s: malformed content", row.InstanceID)
	}
	c.Password, c.PrivateKey, c.KeyPair = v.Password, v.PrivateKey, v.KeyPair
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

// Lookup returns the credentials stored for an instance under its profile,
// or else those detached from the profile by a logout (marked Detached).
// The caller must know the instance to be the account's (the platform's
// API showed it): an instance id identifies one instance, and the detached
// row then is the one of this very instance. Nothing stored is an error
// wrapping platform.ErrNotFound.
func (s *Store) Lookup(ctx context.Context, r Ref) (*Credentials, error) {
	c, err := s.Get(ctx, r)
	if err == nil || !errors.Is(err, platform.ErrNotFound) {
		return c, err
	}
	d := r
	d.Profile = inventory.DetachedProfile(r.Profile)
	row, derr := s.db.GetSecret(ctx, d.key())
	if derr != nil {
		return nil, derr
	}
	if row == nil {
		return nil, err
	}
	got, err := s.open(*row)
	if err != nil {
		return nil, err
	}
	got.Ref.Profile = r.Profile
	got.Detached = true
	return &got, nil
}

// Find returns the credentials stored for the instances of a profile whose
// id or name is ref, in location ("" for every location). Nothing stored
// is an empty list, not an error. When nothing of the profile matches, the
// credentials of instance id ref detached from the profile by a logout are
// returned, marked Detached; a name never matches those.
func (s *Store) Find(ctx context.Context, p platform.ID, profile, location, ref string) ([]Credentials, error) {
	rows, err := s.db.FindSecrets(ctx, p, profile, location, ref)
	if err != nil {
		return nil, err
	}
	detached := false
	if len(rows) == 0 {
		if rows, err = s.db.FindDetachedSecret(ctx, p, profile, location, ref); err != nil {
			return nil, err
		}
		detached = len(rows) > 0
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
		c.Detached = detached
		out = append(out, c)
	}
	return out, nil
}

// Delete removes the credentials stored for an instance. Nothing stored is
// not an error. It needs no data key.
func (s *Store) Delete(ctx context.Context, r Ref) error {
	return s.db.DeleteSecret(ctx, r.key())
}

// Forget removes the credentials stored for an instance that was deleted:
// those under its profile and those detached from the profile by a logout
// (see Lookup for why the detached row is the instance's). Nothing stored
// is not an error. It needs no data key.
func (s *Store) Forget(ctx context.Context, r Ref) error {
	if err := s.Delete(ctx, r); err != nil {
		return err
	}
	d := r
	d.Profile = inventory.DetachedProfile(r.Profile)
	return s.db.DeleteSecret(ctx, d.key())
}
