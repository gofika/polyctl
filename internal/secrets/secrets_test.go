package secrets

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/zalando/go-keyring"
)

// memKeys is an in-memory credential store.
type memKeys struct {
	mu   sync.Mutex
	m    map[string]map[string]string
	sets int
}

func newMemKeys() *memKeys { return &memKeys{m: map[string]map[string]string{}} }

func (k *memKeys) Name() string { return "memory" }
func (k *memKeys) Get(key string) (map[string]string, error) {
	k.mu.Lock()
	defer k.mu.Unlock()
	v, ok := k.m[key]
	if !ok {
		return nil, creds.ErrNotFound
	}
	return v, nil
}
func (k *memKeys) Set(key string, v map[string]string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	k.m[key] = v
	k.sets++
	return nil
}
func (k *memKeys) Locked(fn func() error) error { return fn() }

func openDB(t *testing.T) (*inventory.DB, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "inventory.db")
	db, err := inventory.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db, path
}

var ref = Ref{Platform: platform.Aliyun, Profile: "acme", Location: "cn-hongkong", InstanceID: "i-1"}

func TestRoundTripAndNoPlaintext(t *testing.T) {
	ctx := context.Background()
	db, path := openDB(t)
	keys := newMemKeys()
	s := New(db, keys)
	const pw = "Zq7-secret-PASSWORD:x"
	const pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEsecretkeymaterial\n-----END RSA PRIVATE KEY-----"
	if err := s.Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: pw, PrivateKey: pem, KeyPair: "win-1-win"}); err != nil {
		t.Fatal(err)
	}
	if keys.sets != 1 {
		t.Fatalf("data key writes = %d", keys.sets)
	}
	got, err := s.Get(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != pw || got.PrivateKey != pem || got.KeyPair != "win-1-win" || got.User != "Administrator" || got.Name != "win-1" || got.CreatedAt.IsZero() {
		t.Fatalf("got %+v", got)
	}
	// A second store (another process) reads it with the same data key.
	again, err := New(db, keys).Find(ctx, platform.Aliyun, "acme", "", "win-1")
	if err != nil || len(again) != 1 || again[0].Password != pw {
		t.Fatalf("find by name = %+v, %v", again, err)
	}
	if byID, err := s.Find(ctx, platform.Aliyun, "acme", "cn-hongkong", "i-1"); err != nil || len(byID) != 1 {
		t.Fatalf("find by id = %+v, %v", byID, err)
	}
	if other, err := s.Find(ctx, platform.Aliyun, "acme", "cn-shanghai", "win-1"); err != nil || len(other) != 0 {
		t.Fatalf("other location = %+v, %v", other, err)
	}
	if keys.sets != 1 {
		t.Fatalf("data key written again: %d", keys.sets)
	}
	db.Close()
	for _, f := range []string{path, path + "-wal"} {
		b, err := os.ReadFile(f)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		for _, secret := range []string{pw, "secretkeymaterial", "PRIVATE KEY"} {
			if bytes.Contains(b, []byte(secret)) {
				t.Errorf("%s holds %q in plain text", filepath.Base(f), secret)
			}
		}
	}
}

func TestFreshNoncePerWrite(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	s := New(db, newMemKeys())
	c := Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: "same"}
	if err := s.Put(ctx, c); err != nil {
		t.Fatal(err)
	}
	first, _ := db.GetSecret(ctx, ref.key())
	if err := s.Put(ctx, c); err != nil {
		t.Fatal(err)
	}
	second, _ := db.GetSecret(ctx, ref.key())
	if bytes.Equal(first.Nonce, second.Nonce) || bytes.Equal(first.Sealed, second.Sealed) {
		t.Error("two writes share a nonce or a ciphertext")
	}
	if !second.CreatedAt.Equal(first.CreatedAt) {
		t.Error("a replaced row lost its creation time")
	}
}

func TestLostOrChangedKey(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	if err := New(db, newMemKeys()).Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	// The data key is gone: a read neither generates one nor says "not found".
	empty := newMemKeys()
	_, err := New(db, empty).Get(ctx, ref)
	if !errors.Is(err, ErrKeyLost) || errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("lost key = %v", err)
	}
	if empty.sets != 0 {
		t.Error("a read created a data key")
	}
	if _, err := New(db, empty).Find(ctx, platform.Aliyun, "acme", "", "win-1"); !errors.Is(err, ErrKeyLost) {
		t.Fatalf("find with a lost key = %v", err)
	}
	// Another key: the row does not open.
	other := newMemKeys()
	other.m[DataKeyName] = map[string]string{"key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "v": "1"}
	if _, err := New(db, other).Get(ctx, ref); !errors.Is(err, ErrKeyLost) {
		t.Fatalf("other key = %v", err)
	}
	// A malformed entry.
	bad := newMemKeys()
	bad.m[DataKeyName] = map[string]string{"key": "short"}
	if _, err := New(db, bad).Get(ctx, ref); !errors.Is(err, ErrKeyLost) {
		t.Fatalf("malformed key = %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "pw") {
		t.Errorf("error shows the secret: %v", err)
	}
}

func TestSealedRowIsBoundToItsInstance(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	s := New(db, newMemKeys())
	if err := s.Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	row, _ := db.GetSecret(ctx, ref.key())
	moved := *row
	moved.InstanceID = "i-2"
	if err := db.PutSecret(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, Ref{Platform: ref.Platform, Profile: ref.Profile, Location: ref.Location, InstanceID: "i-2"}); !errors.Is(err, ErrKeyLost) {
		t.Fatalf("copied row = %v", err)
	}
	renamed := *row
	renamed.User = "root"
	if err := db.PutSecret(ctx, renamed); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, ref); err == nil {
		t.Fatal("a row whose user was changed still opens")
	}
}

func TestMissingDeleteAndProfileMoves(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	s := New(db, newMemKeys())
	if _, err := s.Get(ctx, ref); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("missing = %v", err)
	}
	if err := s.Put(ctx, Credentials{Ref: Ref{Platform: ref.Platform, Profile: ref.Profile}}); err == nil {
		t.Error("a row without an instance id was stored")
	}
	if err := s.Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	// logout purges the cache but keeps the secrets; a rename moves them.
	if err := db.Purge(ctx, platform.Aliyun, "acme"); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Get(ctx, ref); err != nil {
		t.Fatalf("after purge: %v", err)
	}
	if err := db.RenameProfile(ctx, platform.Aliyun, "acme", "corp"); err != nil {
		t.Fatal(err)
	}
	moved := ref
	moved.Profile = "corp"
	if got, err := s.Get(ctx, moved); err != nil || got.Password != "pw" {
		t.Fatalf("after rename: %+v, %v", got, err)
	}
	if _, err := s.Get(ctx, ref); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("old profile after rename: %v", err)
	}
	if err := s.Delete(ctx, moved); err != nil {
		t.Fatal(err)
	}
	if n, _ := db.CountSecrets(ctx); n != 0 {
		t.Errorf("rows left = %d", n)
	}
	if err := s.Delete(ctx, moved); err != nil {
		t.Errorf("deleting nothing = %v", err)
	}
}

func TestGeneratePassword(t *testing.T) {
	seen := map[string]bool{}
	for range 2000 {
		p, err := GeneratePassword()
		if err != nil {
			t.Fatal(err)
		}
		if !ValidPassword(p) {
			t.Fatalf("invalid password shape: %d characters", len(p))
		}
		if strings.ContainsAny(p, "\"'`\\ $%^&|<>!*?();~/[]{}") {
			t.Fatal("a generated password holds a character outside the safe set")
		}
		if seen[p] {
			t.Fatal("a password repeated")
		}
		seen[p] = true
	}
	for _, p := range []string{"", "short", "-Abcdefghijk2345678x", "abcdefghijkmnopqrst2", "ABCDEFGHJKLMNPQRS2:x" + "y"} {
		if ValidPassword(p) {
			t.Errorf("ValidPassword(%q) = true", p)
		}
	}
}

// fakeKeyring is an in-memory store standing in for the system keyring.
type fakeKeyring struct{ *memKeys }

func (fakeKeyring) Name() string { return "keyring" }
func (k fakeKeyring) Delete(key string) error {
	k.mu.Lock()
	defer k.mu.Unlock()
	delete(k.m, key)
	return nil
}

// A run without the keyring (SSH, cron) sees only credentials.json. While
// secrets are stored, it must not create a second data key there: the key is
// probably in the keyring it cannot reach.
func TestNoSecondDataKeyWhileTheKeyringIsOutOfReach(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	kr := fakeKeyring{newMemKeys()}
	file := creds.NewFile(t.TempDir())
	desktop := &creds.Multi{Primary: kr, Others: []creds.Store{file}}
	headless := &creds.Multi{Primary: file}
	if err := New(db, desktop).Put(ctx, Credentials{Ref: ref, User: "Administrator", Password: "old"}); err != nil {
		t.Fatal(err)
	}
	ref2 := ref
	ref2.InstanceID = "i-2"
	err := New(db, headless).Put(ctx, Credentials{Ref: ref2, User: "Administrator", Password: "new"})
	if !errors.Is(err, ErrKeyLost) || !strings.Contains(err.Error(), "keyring is not available") {
		t.Fatalf("headless Put = %v, want a refusal naming the keyring", err)
	}
	if err := New(db, headless).Ready(); !errors.Is(err, ErrKeyLost) {
		t.Errorf("headless Ready = %v, want a refusal", err)
	}
	if _, err := file.Get(DataKeyName); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("a second data key was written to the file: %v", err)
	}
	if got, err := New(db, desktop).Get(ctx, ref); err != nil || got.Password != "old" {
		t.Errorf("desktop Get = %+v, %v", got, err)
	}
}

// With no secret stored yet, a run without the keyring may create the key in
// the file; with both backends within reach and neither holding it, the key
// is lost and a new one is created for new secrets.
func TestDataKeyCreatedWhenNothingCanBeSplit(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	file := creds.NewFile(t.TempDir())
	if err := New(db, &creds.Multi{Primary: file}).Put(ctx, Credentials{Ref: ref, User: "u", Password: "p"}); err != nil {
		t.Fatalf("first Put without keyring = %v", err)
	}
	db2, _ := openDB(t)
	kr := fakeKeyring{newMemKeys()}
	file2 := creds.NewFile(t.TempDir())
	both := &creds.Multi{Primary: kr, Others: []creds.Store{file2}}
	if err := New(db2, both).Put(ctx, Credentials{Ref: ref, User: "u", Password: "p"}); err != nil {
		t.Fatal(err)
	}
	if err := kr.Delete(DataKeyName); err != nil {
		t.Fatal(err)
	}
	ref2 := ref
	ref2.InstanceID = "i-2"
	if err := New(db2, both).Put(ctx, Credentials{Ref: ref2, User: "u", Password: "p"}); err != nil {
		t.Errorf("Put after the key is lost everywhere = %v, want a new key", err)
	}
}

// A store forked by an earlier release (one key in the keyring, another in
// the file) still reads every row, whichever backend's key sealed it.
func TestRowsSealedWithEitherForkedKeyOpen(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	kr := fakeKeyring{newMemKeys()}
	file := creds.NewFile(t.TempDir())
	ref2 := ref
	ref2.InstanceID = "i-2"
	// Seal i-2 with a key in the file alone, then i-1 with a key in the
	// keyring alone, as two kinds of session did before.
	if err := New(db, &creds.Multi{Primary: file}).Put(ctx, Credentials{Ref: ref2, User: "u", Password: "file"}); err != nil {
		t.Fatal(err)
	}
	if err := New(db, &creds.Multi{Primary: kr}).Ready(); err == nil {
		t.Fatal("a keyring-only store created a key while secrets are stored")
	}
	k := make([]byte, dataKeyBytes)
	k[0] = 1
	if err := kr.Set(DataKeyName, map[string]string{dataKeyField: base64.StdEncoding.EncodeToString(k), dataKeyVersion: dataKeyV1}); err != nil {
		t.Fatal(err)
	}
	if err := New(db, &creds.Multi{Primary: kr}).Put(ctx, Credentials{Ref: ref, User: "u", Password: "keyring"}); err != nil {
		t.Fatal(err)
	}
	desktop := New(db, &creds.Multi{Primary: kr, Others: []creds.Store{file}})
	for _, c := range []struct {
		r    Ref
		want string
	}{{ref, "keyring"}, {ref2, "file"}} {
		got, err := desktop.Get(ctx, c.r)
		if err != nil || got.Password != c.want {
			t.Errorf("Get(%s) = %+v, %v; want %q", c.r.InstanceID, got, err, c.want)
		}
	}
}

// After a logout the credentials are found by instance id only, marked as
// detached; the name no longer matches.
func TestFindDetachedByIDOnly(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	s := New(db, newMemKeys())
	if err := s.Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: "pw"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DetachSecrets(ctx, ref.Platform, ref.Profile); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Find(ctx, ref.Platform, ref.Profile, "", "win-1"); err != nil || len(got) != 0 {
		t.Errorf("Find by name = %+v, %v; want nothing", got, err)
	}
	got, err := s.Find(ctx, ref.Platform, ref.Profile, "", ref.InstanceID)
	if err != nil || len(got) != 1 || !got[0].Detached || got[0].Password != "pw" {
		t.Errorf("Find by id = %+v, %v; want the detached credentials", got, err)
	}
}

// A configuration directory other than the default one keeps the data key
// under a keyring service of its own. When the key is still only under the
// shared service of earlier releases (a directory whose first run did not
// copy it), it is copied on use instead of a new key being created, and a
// key there that differs from the directory's own still opens its rows.
func TestDataKeyAdoptedFromTheSharedService(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	db, _ := openDB(t)
	shared := &creds.Multi{Primary: creds.Keyring{}}
	if err := New(db, shared).Put(ctx, Credentials{Ref: ref, User: "u", Password: "shared"}); err != nil {
		t.Fatal(err)
	}
	own := creds.Keyring{Service: "polyctl:0123456789abcdef"}
	store := &creds.Multi{Primary: own, Others: []creds.Store{creds.NewFile(t.TempDir())}}
	if got, err := New(db, store).Get(ctx, ref); err != nil || got.Password != "shared" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if _, err := own.Get(DataKeyName); err != nil {
		t.Errorf("the data key was not copied: %v", err)
	}
	// A key of its own that differs (forked): rows sealed with the shared
	// one still open.
	k := make([]byte, dataKeyBytes)
	k[0] = 7
	if err := own.Set(DataKeyName, map[string]string{dataKeyField: base64.StdEncoding.EncodeToString(k), dataKeyVersion: dataKeyV1}); err != nil {
		t.Fatal(err)
	}
	ref2 := ref
	ref2.InstanceID = "i-2"
	if err := New(db, store).Put(ctx, Credentials{Ref: ref2, User: "u", Password: "own"}); err != nil {
		t.Fatal(err)
	}
	for _, c := range []struct {
		r    Ref
		want string
	}{{ref, "shared"}, {ref2, "own"}} {
		if got, err := New(db, store).Get(ctx, c.r); err != nil || got.Password != c.want {
			t.Errorf("Get(%s) = %+v, %v; want %q", c.r.InstanceID, got, err, c.want)
		}
	}
}

// When the shared service of earlier releases cannot be read, the data key
// it may hold is not replaced by a new one.
func TestNoDataKeyCreatedWhileTheSharedServiceFails(t *testing.T) {
	keyring.MockInit()
	ctx := context.Background()
	db, _ := openDB(t)
	if err := New(db, &creds.Multi{Primary: creds.Keyring{}}).Put(ctx, Credentials{Ref: ref, User: "u", Password: "shared"}); err != nil {
		t.Fatal(err)
	}
	broken := errors.New("keyring locked")
	restore := creds.UseKeyring(func(service, user string) (string, error) {
		if service == creds.Service {
			return "", broken
		}
		return keyring.Get(service, user)
	}, keyring.Set, keyring.Delete)
	defer restore()
	own := creds.Keyring{Service: "polyctl:0123456789abcdef"}
	store := &creds.Multi{Primary: own, Others: []creds.Store{creds.NewFile(t.TempDir())}}
	if err := New(db, store).Ready(); !errors.Is(err, broken) {
		t.Errorf("Ready = %v, want the keyring error", err)
	}
	if _, err := own.Get(DataKeyName); !errors.Is(err, creds.ErrNotFound) {
		t.Errorf("a data key was created: %v", err)
	}
}

// Lookup finds the login of an instance detached by a logout, and Forget
// (a deleted instance) removes it with the one under the profile.
func TestLookupAndForgetDetached(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	s := New(db, newMemKeys())
	if err := s.Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: "pw", KeyPair: "kp"}); err != nil {
		t.Fatal(err)
	}
	if err := db.DetachSecrets(ctx, ref.Platform, ref.Profile); err != nil {
		t.Fatal(err)
	}
	got, err := s.Lookup(ctx, ref)
	if err != nil || !got.Detached || got.KeyPair != "kp" || got.Profile != ref.Profile {
		t.Fatalf("Lookup = %+v, %v", got, err)
	}
	if err := s.Forget(ctx, ref); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Lookup(ctx, ref); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("Lookup after Forget = %v, want not found", err)
	}
}
