package gcp

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"
	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// testPublicKey returns a fresh ED25519 public key line with a comment.
func testPublicKey(t *testing.T, comment string) string {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sp, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(sp)))
	if comment != "" {
		line += " " + comment
	}
	return line
}

func TestParseSSHKey(t *testing.T) {
	withMail := testPublicKey(t, "alice@example.com")
	k, err := parseSSHKey(withMail, "", "--ssh-key")
	if err != nil || k.User != "alice" {
		t.Fatalf("user from the comment = %+v, %v", k, err)
	}
	if !strings.HasPrefix(k.Line(), "alice:ssh-ed25519 AAAA") || !strings.HasSuffix(k.Line(), " alice@example.com") {
		t.Errorf("line = %q", k.Line())
	}
	// A user: prefix wins over --ssh-user and the comment.
	if k, err := parseSSHKey("ops:"+withMail, "bob", "--ssh-key"); err != nil || k.User != "ops" {
		t.Errorf("prefix = %+v, %v", k, err)
	}
	if k, err := parseSSHKey(withMail, "bob", "--ssh-key"); err != nil || k.User != "bob" {
		t.Errorf("--ssh-user = %+v, %v", k, err)
	}
	// No user anywhere: usage error naming the prefix.
	noMail := testPublicKey(t, "laptop")
	if _, err := parseSSHKey(noMail, "", "--ssh-key"); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "user:") {
		t.Errorf("no user = %v", err)
	}
	// A path is refused with a hint to use --ssh-key-file.
	path := filepath.Join(t.TempDir(), "id.pub")
	if err := os.WriteFile(path, []byte(withMail+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := parseSSHKey(path, "", "--ssh-key"); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "--ssh-key-file") {
		t.Errorf("path = %v", err)
	}
	if _, err := parseSSHKey("not a key", "", "--ssh-key"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("garbage = %v", err)
	}
	if _, err := parseSSHKey("bad user:"+withMail, "", "--ssh-key"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("bad user = %v", err)
	}
}

func TestLoadSSHKeyFile(t *testing.T) {
	a, b := testPublicKey(t, "alice@example.com"), testPublicKey(t, "laptop")
	path := filepath.Join(t.TempDir(), "keys.pub")
	if err := os.WriteFile(path, []byte("# comment\n"+a+"\n\nops:"+b+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	keys, err := loadSSHKeyFile(path, "")
	if err != nil || len(keys) != 2 || keys[0].User != "alice" || keys[1].User != "ops" {
		t.Fatalf("keys = %+v, %v", keys, err)
	}
	// --ssh-user names the user of lines without a prefix.
	if keys, err := loadSSHKeyFile(path, "deploy"); err != nil || keys[0].User != "deploy" || keys[1].User != "ops" {
		t.Errorf("--ssh-user = %+v, %v", keys, err)
	}
	priv := filepath.Join(t.TempDir(), "id")
	_ = os.WriteFile(priv, []byte("-----BEGIN OPENSSH PRIVATE KEY-----\nx\n"), 0o600)
	if _, err := loadSSHKeyFile(priv, ""); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "private key") {
		t.Errorf("private key = %v", err)
	}
	empty := filepath.Join(t.TempDir(), "empty.pub")
	_ = os.WriteFile(empty, []byte("# nothing\n"), 0o600)
	if _, err := loadSSHKeyFile(empty, ""); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("empty = %v", err)
	}
	if _, err := loadSSHKeyFile(filepath.Join(t.TempDir(), "missing.pub"), ""); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("missing = %v", err)
	}
}

func TestCollectSSHKeysAndMetadata(t *testing.T) {
	a, b := testPublicKey(t, "alice@example.com"), testPublicKey(t, "bob@example.com")
	path := filepath.Join(t.TempDir(), "a.pub")
	_ = os.WriteFile(path, []byte(a+"\n"), 0o600)
	keys, err := collectSSHKeys([]string{a, b}, []string{path}, []string{"alice:" + a}, "")
	if err != nil || len(keys) != 2 {
		t.Fatalf("keys = %+v, %v", keys, err)
	}
	item := sshKeysMetadata(keys)
	if item.Key != "ssh-keys" || strings.Count(*item.Value, "\n") != 1 || !strings.HasPrefix(*item.Value, "alice:") {
		t.Errorf("metadata = %q", *item.Value)
	}
	// Keys already in the project metadata are recognised by user and key.
	project := &compute.Metadata{Items: []*compute.MetadataItems{
		{Key: "ssh-keys", Value: strPtr("alice:" + a + "\ngarbage\nother:" + b)},
		{Key: "enable-oslogin", Value: strPtr("TRUE")},
	}}
	pk := metadataKeys(project)
	if len(pk) != 2 || !keys[0].presentIn(pk) || keys[1].presentIn(pk) {
		t.Errorf("present = %v %v (%d keys)", keys[0].presentIn(pk), keys[1].presentIn(pk), len(pk))
	}
	if !osLoginEnabled(project) || osLoginEnabled(&compute.Metadata{}) || osLoginEnabled(nil) {
		t.Error("enable-oslogin")
	}
}

func strPtr(s string) *string { return &s }
