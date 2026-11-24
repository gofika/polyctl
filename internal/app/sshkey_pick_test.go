package app_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
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
	if a.Default != "laptop" || !strings.Contains(labels, "laptop  SHA256:") || !strings.Contains(labels, "[matches ~/.ssh/id_ed25519.pub]") ||
		!strings.Contains(labels, "other  ab:cd") || a.Options[len(a.Options)-1].Label != "Import a new key pair from a public key file..." {
		t.Errorf("key pair options (default %q):\n%s", a.Default, labels)
	}

	plan, p, err = run(prompttest.Label("Import a new key pair"), filepath.Join(sshDir, "work.pub"), "", "laptop", "work")
	if err != nil || !plan.Create || plan.Name != "work" {
		t.Fatalf("create = %+v, %v", plan, err)
	}
	f := p.Find("Public key file to import")
	fl := prompttest.Labels(f.Options)
	if f.Default != filepath.Join(sshDir, "work.pub") || !strings.Contains(fl, "~/.ssh/id_ed25519.pub  ed25519 SHA256:") || !strings.Contains(fl, "[already key pair laptop]") {
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
