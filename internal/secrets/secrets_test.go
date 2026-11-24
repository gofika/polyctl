package secrets

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
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
	if err := s.Put(ctx, Credentials{Ref: ref, Name: "win-1", User: "Administrator", Password: pw, PrivateKey: pem}); err != nil {
		t.Fatal(err)
	}
	if keys.sets != 1 {
		t.Fatalf("data key writes = %d", keys.sets)
	}
	got, err := s.Get(ctx, ref)
	if err != nil {
		t.Fatal(err)
	}
	if got.Password != pw || got.PrivateKey != pem || got.User != "Administrator" || got.Name != "win-1" || got.CreatedAt.IsZero() {
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
