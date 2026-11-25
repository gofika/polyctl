package app_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

type kpLister []platform.KeyPair

func (l kpLister) ListKeyPairs(context.Context) ([]platform.KeyPair, error) { return l, nil }

func writeSSHKey(t *testing.T, dir, name string) ssh.PublicKey {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	if err := os.WriteFile(filepath.Join(dir, name), ssh.MarshalAuthorizedKey(k), 0o600); err != nil {
		t.Fatal(err)
	}
	return k
}

// The key pair question of the interactive flow: existing key pairs with
// their fingerprints, the one holding a local key marked and preselected,
// and "Import a new key pair..." last, which asks for a file (labelled with
// type and fingerprint) and a name with no default.
func TestKeyPairPicker(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(app.EnvNonInteractive, "")
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	mine := writeSSHKey(t, sshDir, "id_ed25519.pub")
	writeSSHKey(t, sshDir, "work.pub")
	pairs := kpLister{{Name: "other", Fingerprint: "ab:cd"}, {Name: "laptop", PublicKey: mine}}

	run := func(answers ...any) (platform.KeyPairPlan, *prompttest.Picker, error) {
		rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		p := prompttest.New(t, answers...)
		rt.Picker = p
		in, err := rt.KeyInput(&app.KeyFlags{}, platform.KeyInput{Match: platform.MatchByPublicKey, AllowedTypes: platform.AWSKeyTypes})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := platform.ResolveKeyPair(t.Context(), pairs, in)
		p.Done()
		return plan, p, err
	}

	plan, p, err := run("other")
	if err != nil || plan.Name != "other" || plan.Create {
		t.Fatalf("existing = %+v, %v", plan, err)
	}
	a := p.Find("Key pair")
	labels := prompttest.Labels(a.Options)
	if a.Default != "laptop" || !strings.Contains(labels, "laptop  SHA256:") || !strings.Contains(labels, "  [matches ~/.ssh/id_ed25519.pub]\n") ||
		!strings.Contains(labels, "other  ab:cd") || a.Options[len(a.Options)-2].Label != "Import a new key pair from a public key file..." ||
		a.Options[len(a.Options)-1].Label != "Import a new key pair by entering its public key..." {
		t.Errorf("key pair options (default %q):\n%s", a.Default, labels)
	}

	plan, p, err = run(prompttest.Label("Import a new key pair"), filepath.Join(sshDir, "work.pub"), "", "laptop", "work")
	if err != nil || !plan.Create || plan.Name != "work" {
		t.Fatalf("create = %+v, %v", plan, err)
	}
	f := p.Find("Public key to import")
	fl := prompttest.Labels(f.Options)
	if f.Default != filepath.Join(sshDir, "work.pub") || !strings.Contains(fl, "~/.ssh/id_ed25519.pub  ed25519  SHA256:") || !strings.Contains(fl, "…  -  [already key pair laptop]\n") ||
		!strings.HasSuffix(fl, "Another file...\nEnter a public key...") {
		t.Errorf("file options (default %q):\n%s", f.Default, fl)
	}
	if n := p.Find("Name of the new key pair"); n.Default != "" {
		t.Errorf("a default name was offered: %q", n.Default)
	}

	// Leaving the question cancels.
	if _, _, err = run(prompttest.Abort{}); err == nil || !strings.Contains(err.Error(), "aborted") {
		t.Errorf("abort = %v", err)
	}
}

func authorizedKey(t *testing.T, comment string) (string, ssh.PublicKey) {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " " + comment, k
}

// "Enter a public key..." takes the key itself (for a machine created for
// someone else), checked as it is typed: not a key, a private key, a file
// path and a type the platform refuses stay on the question with a reason.
// A key a key pair already holds is pointed out, never imported again
// unless asked to.
func TestKeyPairPickerTypedKey(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(app.EnvNonInteractive, "")
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	writeSSHKey(t, sshDir, "id_ed25519.pub")
	friend, friendKey := authorizedKey(t, "friend@example.com")
	registered, registeredKey := authorizedKey(t, "ops@example.com")
	pairs := kpLister{{Name: "ops", PublicKey: registeredKey}, {Name: "ops-copy", PublicKey: registeredKey}, {Name: "other", Fingerprint: "ab:cd"}}
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	eck, _ := ssh.NewPublicKey(&ec.PublicKey)
	ecdsaLine := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(eck)))
	path := filepath.Join(sshDir, "id_ed25519.pub")

	run := func(answers ...any) (platform.KeyPairPlan, *prompttest.Picker, error) {
		rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		p := prompttest.New(t, answers...)
		rt.Picker = p
		in, err := rt.KeyInput(&app.KeyFlags{}, platform.KeyInput{Match: platform.MatchByPublicKey, AllowedTypes: platform.AWSKeyTypes})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := platform.ResolveKeyPair(t.Context(), pairs, in)
		p.Done()
		return plan, p, err
	}

	// From the key pair list straight to the key; rejected answers first.
	plan, p, err := run(prompttest.Label("by entering its public key"),
		"not a key", "-----BEGIN OPENSSH PRIVATE KEY-----", path, ecdsaLine, friend, "friend")
	if err != nil || !plan.Create || plan.Name != "friend" || !plan.Key.Equal(friendKey) || !strings.Contains(plan.Change.Detail, "import from typed public key") {
		t.Fatalf("typed = %+v, %v", plan, err)
	}
	var keyAsks []string
	for _, a := range p.Asked {
		if a.Kind == "input" && strings.HasPrefix(a.Title, "Public key") {
			keyAsks = append(keyAsks, a.Title)
		}
	}
	if len(keyAsks) != 5 || slices.Contains(p.Titles(), "select:Public key to import") {
		t.Errorf("key questions = %q (the file list should not be shown)", keyAsks)
	}

	// The same entry of the file list; a registered key is pointed out with
	// one entry per key pair holding it, the first preselected.
	plan, p, err = run(prompttest.Label("from a public key file"), prompttest.Label("Enter a public key"), registered, "ops-copy")
	if err != nil || plan.Create || plan.Name != "ops-copy" {
		t.Fatalf("use existing = %+v, %v", plan, err)
	}
	r := p.Find("This public key is already registered as key pairs \"ops\", \"ops-copy\"")
	if r.Default != "ops" || prompttest.Labels(r.Options) != "Use the existing key pair ops\nUse the existing key pair ops-copy\nImport it again under a new name" {
		t.Errorf("registered question (default %q):\n%s", r.Default, prompttest.Labels(r.Options))
	}

	// Import it again: a new name, not one of the holders.
	plan, _, err = run(prompttest.Label("by entering its public key"), registered, prompttest.Label("Import it again"), "ops", "ops-2")
	if err != nil || !plan.Create || plan.Name != "ops-2" {
		t.Fatalf("import again = %+v, %v", plan, err)
	}

	// Leaving any new question cancels, with nothing planned.
	for _, answers := range [][]any{
		{prompttest.Label("by entering its public key"), prompttest.Abort{}},
		{prompttest.Label("by entering its public key"), registered, prompttest.Abort{}},
		{prompttest.Label("from a public key file"), prompttest.Abort{}},
	} {
		if _, _, err := run(answers...); !errors.Is(err, prompt.ErrAborted) {
			t.Errorf("abort after %d answers = %v", len(answers)-1, err)
		}
	}
}

// A key read from a file, a ~/.ssh/*.pub or another one, that a key pair
// already holds is pointed out like a typed one: the existing key pair is
// preselected, and importing it again asks for a new name.
func TestKeyPairPickerRegisteredFile(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv(app.EnvNonInteractive, "")
	sshDir := filepath.Join(home, ".ssh")
	_ = os.MkdirAll(sshDir, 0o700)
	mine := writeSSHKey(t, sshDir, "id_ed25519.pub")
	elsewhere := filepath.Join(home, "keys")
	_ = os.MkdirAll(elsewhere, 0o700)
	theirs := writeSSHKey(t, elsewhere, "friend.pub")
	pairs := kpLister{{Name: "laptop", PublicKey: mine}, {Name: "friend", PublicKey: theirs}}

	run := func(answers ...any) (platform.KeyPairPlan, *prompttest.Picker, error) {
		rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
		p := prompttest.New(t, answers...)
		rt.Picker = p
		in, err := rt.KeyInput(&app.KeyFlags{}, platform.KeyInput{Match: platform.MatchByPublicKey, AllowedTypes: platform.AWSKeyTypes})
		if err != nil {
			t.Fatal(err)
		}
		plan, err := platform.ResolveKeyPair(t.Context(), pairs, in)
		p.Done()
		return plan, p, err
	}

	// A registered ~/.ssh/*.pub: the existing key pair is used.
	plan, p, err := run(prompttest.Label("from a public key file"), filepath.Join(sshDir, "id_ed25519.pub"), prompttest.Label("Use the existing key pair laptop"))
	if err != nil || plan.Create || plan.Name != "laptop" {
		t.Fatalf("local file = %+v, %v", plan, err)
	}
	if r := p.Find(`This public key is already registered as key pair "laptop"`); r.Default != "laptop" {
		t.Errorf("registered question default = %q", r.Default)
	}

	// Another file holding a registered key: imported again under a new
	// name, the holder's name refused.
	plan, p, err = run(prompttest.Label("from a public key file"), prompttest.Label("Another file"), filepath.Join(elsewhere, "friend.pub"),
		prompttest.Label("Import it again"), "friend", "friend-2")
	if err != nil || !plan.Create || plan.Name != "friend-2" || !plan.Key.Equal(theirs) {
		t.Fatalf("other file = %+v, %v", plan, err)
	}
	p.Find(`This public key is already registered as key pair "friend"`)
}
