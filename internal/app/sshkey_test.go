package app

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// keyPicker answers Select with the first option or "other", and Input
// with the scripted values.
type keyPicker struct {
	selects []string
	inputs  []string
	titles  []string
}

func (p *keyPicker) Select(title string, opts []prompt.Option, _ string) (string, error) {
	p.titles = append(p.titles, title)
	if len(p.selects) == 0 {
		return "", prompt.ErrAborted
	}
	v := p.selects[0]
	p.selects = p.selects[1:]
	if v == "other" {
		return otherKeyFile, nil
	}
	return v, nil
}
func (p *keyPicker) MultiSelect(string, []prompt.Option) ([]string, error) {
	return nil, prompt.ErrAborted
}
func (p *keyPicker) Confirm(string, bool) (bool, error) { return false, prompt.ErrAborted }
func (p *keyPicker) Input(title, _ string, _ func(string) error) (string, error) {
	p.titles = append(p.titles, title)
	if len(p.inputs) == 0 {
		return "", prompt.ErrAborted
	}
	v := p.inputs[0]
	p.inputs = p.inputs[1:]
	return v, nil
}

type listKP []platform.KeyPair

func (l listKP) ListKeyPairs(context.Context) ([]platform.KeyPair, error) { return l, nil }

func keyFile(t *testing.T) string {
	t.Helper()
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	k, _ := ssh.NewPublicKey(pub)
	p := filepath.Join(t.TempDir(), "k.pub")
	if err := os.WriteFile(p, ssh.MarshalAuthorizedKey(k), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestKeyInputFlags(t *testing.T) {
	t.Setenv(EnvNonInteractive, "")
	rt := New(Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	file := keyFile(t)
	in, err := rt.KeyInput(&KeyFlags{SSHKeyFile: file, KeyPair: "laptop"}, platform.KeyInput{Match: platform.MatchByPublicKey})
	if err != nil || in.Key == nil || in.Name != "laptop" || in.Interactive || in.Prompter != nil {
		t.Fatalf("KeyInput = %+v, %v", in, err)
	}
	if _, err := rt.KeyInput(&KeyFlags{SSHKey: "x", SSHKeyFile: file}, platform.KeyInput{}); !errors.Is(err, ErrUsage) {
		t.Errorf("both = %v", err)
	}
	if _, err := rt.KeyInput(&KeyFlags{SSHKey: file}, platform.KeyInput{}); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("path in --ssh-key = %v", err)
	}
	if (&KeyFlags{}).Given() || !(&KeyFlags{KeyPair: "x"}).Given() {
		t.Error("Given")
	}

	// The interactive flow asks for the file (another path), then the name.
	picker := &keyPicker{selects: []string{"other"}, inputs: []string{file, "laptop"}}
	rt.Picker = picker
	t.Setenv("HOME", filepath.Dir(file)) // ~/.ssh does not exist: no candidates
	in, err = rt.KeyInput(&KeyFlags{}, platform.KeyInput{Match: platform.MatchByPublicKey})
	if err != nil || !in.Interactive || in.Prompter == nil {
		t.Fatalf("interactive KeyInput = %+v, %v", in, err)
	}
	plan, err := platform.ResolveKeyPair(t.Context(), listKP{}, in)
	if err != nil || !plan.Create || plan.Name != "laptop" {
		t.Fatalf("interactive plan = %+v, %v (asked %v)", plan, err, picker.titles)
	}
	// Leaving a question is "nothing to do".
	rt.Picker = &keyPicker{}
	in, _ = rt.KeyInput(&KeyFlags{SSHKeyFile: file}, platform.KeyInput{Match: platform.MatchByPublicKey})
	if _, err := platform.ResolveKeyPair(t.Context(), listKP{}, in); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("left question = %v", err)
	}
}

// Both key flags together are a usage error (exit code 2), raised by the
// command's own check rather than by cobra.
func TestKeyFlagsMutuallyExclusive(t *testing.T) {
	var f KeyFlags
	ran := false
	cmd := &cobra.Command{Use: "x", RunE: func(*cobra.Command, []string) error {
		ran = true
		_, err := f.PublicKey()
		return err
	}}
	AddKeyFlags(cmd, &f)
	cmd.SetArgs([]string{"--ssh-key", "ssh-ed25519 AAAA", "--ssh-key-file", "k.pub"})
	cmd.SetOut(&bytes.Buffer{})
	cmd.SetErr(&bytes.Buffer{})
	err := cmd.Execute()
	if !ran || !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "mutually exclusive") {
		t.Errorf("both flags: ran=%v err=%v", ran, err)
	}
}

// AddPublicKeyFlags registers the key flags without --key-pair.
func TestAddPublicKeyFlags(t *testing.T) {
	var f KeyFlags
	cmd := &cobra.Command{Use: "x"}
	AddPublicKeyFlags(cmd, &f)
	if cmd.Flags().Lookup("ssh-key") == nil || cmd.Flags().Lookup("ssh-key-file") == nil || cmd.Flags().Lookup("key-pair") != nil {
		t.Errorf("flags: ssh-key %v, ssh-key-file %v, key-pair %v", cmd.Flags().Lookup("ssh-key") != nil,
			cmd.Flags().Lookup("ssh-key-file") != nil, cmd.Flags().Lookup("key-pair") != nil)
	}
	full := &cobra.Command{Use: "y"}
	AddKeyFlags(full, &f)
	if full.Flags().Lookup("key-pair") == nil || full.Flags().Lookup("ssh-key") == nil {
		t.Error("AddKeyFlags must register --key-pair and the key flags")
	}
}
