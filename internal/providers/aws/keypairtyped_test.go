package aws

import (
	"errors"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// A public key typed on a terminal (a machine for someone else) that a key
// pair of the region already holds is pointed out: ensure uses that key
// pair, or imports the key again under a new name when asked to.
func TestKeyPairEnsureTypedKeyAlreadyRegistered(t *testing.T) {
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	t.Setenv("HOME", h.dir)
	t.Setenv("USERPROFILE", h.dir) // os.UserHomeDir on Windows
	k := genED25519(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " friend@example.com"
	h.add("ap-east-1", newFakeKeyPair("friend", k))

	p := prompttest.New(t, prompttest.Label("by entering its public key"), "not a key", line, "friend")
	h.rt.Picker = p
	if err := h.run("ec2", "key-pair", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	r := p.Find(`This public key is already registered as key pair "friend"`)
	if r.Default != "friend" || prompttest.Labels(r.Options) != "Use the existing key pair friend\nImport it again under a new name" {
		t.Errorf("registered question (default %q):\n%s", r.Default, prompttest.Labels(r.Options))
	}
	if n := h.ec2.count("ImportKeyPair"); n != 0 {
		t.Errorf("the existing key pair was chosen, but ImportKeyPair ran %d times", n)
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Resource != "key-pair/friend" || rep.Changes[0].Action != platform.Unchanged {
		t.Errorf("report = %+v", rep)
	}

	h.ec2.reset()
	p = prompttest.New(t, prompttest.Label("by entering its public key"), line, prompttest.Label("Import it again"), "friend", "friend-2")
	h.rt.Picker = p
	if err := h.run("ec2", "key-pair", "ensure"); err != nil {
		t.Fatalf("ensure: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Resource != "key-pair/friend-2" || rep.Changes[0].Action != platform.Created || h.ec2.count("ImportKeyPair") != 1 {
		t.Errorf("import again = %+v (%d imports)", rep, h.ec2.count("ImportKeyPair"))
	}
}

// key-pair import on a terminal: a typed key that a key pair already holds
// is pointed out, and using that key pair imports nothing (unchanged, exit
// code 0); leaving a new question imports nothing either.
func TestKeyPairImportTypedKeyAlreadyRegistered(t *testing.T) {
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	t.Setenv("HOME", h.dir)
	t.Setenv("USERPROFILE", h.dir) // os.UserHomeDir on Windows
	k := genED25519(t)
	line := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k))) + " friend@example.com"
	h.add("ap-east-1", newFakeKeyPair("friend", k))

	p := prompttest.New(t, prompttest.Label("Enter a public key"), "-----BEGIN OPENSSH PRIVATE KEY-----", line, "friend")
	h.rt.Picker = p
	if err := h.run("ec2", "key-pair", "import"); err != nil {
		t.Fatalf("import: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if n := h.ec2.count("ImportKeyPair"); n != 0 {
		t.Errorf("ImportKeyPair ran %d times for a registered key", n)
	}
	if rep := h.report(); len(rep.Changes) != 1 || rep.Changes[0].Resource != "key-pair/friend" || rep.Changes[0].Action != platform.Unchanged || rep.Changes[0].ID != "key-0friend" {
		t.Errorf("report = %+v", rep)
	}

	for _, answers := range [][]any{
		{prompttest.Label("Enter a public key"), prompttest.Abort{}},
		{prompttest.Label("Enter a public key"), line, prompttest.Abort{}},
	} {
		h.rt.Picker = prompttest.New(t, answers...)
		h.ec2.reset()
		if err := h.run("ec2", "key-pair", "import", "new-name"); !errors.Is(err, prompt.ErrAborted) || h.ec2.count("ImportKeyPair") != 0 {
			t.Errorf("abort = %v", err)
		}
	}

	// A typed key that is not registered is imported under the name asked.
	other := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(genED25519(t))))
	h.ec2.reset()
	p = prompttest.New(t, prompttest.Label("Enter a public key"), other, "friend", "colleague")
	h.rt.Picker = p
	if err := h.run("ec2", "key-pair", "import"); err != nil {
		t.Fatalf("import: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if rep := h.report(); rep.Changes[0].Resource != "key-pair/colleague" || h.ec2.count("ImportKeyPair") != 1 {
		t.Errorf("typed import = %+v", rep)
	}
}
