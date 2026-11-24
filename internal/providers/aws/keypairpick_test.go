package aws

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// key-pair import without the key and the name asks for the public key
// file (~/.ssh/*.pub, those registered marked) and a free name.
func TestKeyPairImportAsks(t *testing.T) {
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	t.Setenv("HOME", h.dir)
	t.Setenv("USERPROFILE", h.dir) // os.UserHomeDir on Windows
	ssh := filepath.Join(h.dir, ".ssh")
	if err := os.MkdirAll(ssh, 0o700); err != nil {
		t.Fatal(err)
	}
	registered := genED25519(t)
	h.add("ap-east-1", newFakeKeyPair("taken", registered))
	writeKeyFile(t, ssh, "id_rsa.pub", registered)
	file := writeKeyFile(t, ssh, "id_ed25519.pub", genED25519(t))

	p := prompttest.New(t, file, "taken", "laptop")
	h.rt.Picker = p
	if err := h.run("ec2", "key-pair", "import"); err != nil {
		t.Fatalf("import: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "[already key pair taken]") || !strings.Contains(l, "Another file...") {
		t.Errorf("key file labels: %s", l)
	}
	if rep := h.report(); rep.Changes[0].Resource != "key-pair/laptop" {
		t.Errorf("report = %+v", rep)
	}

	// Leaving the question imports nothing.
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	h.ec2.reset()
	if err := h.run("ec2", "key-pair", "import", "other"); !errors.Is(err, prompt.ErrAborted) || h.ec2.count("ImportKeyPair") != 0 {
		t.Errorf("abort = %v", err)
	}

	// The non-interactive flow still needs the key, before any call.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	h.ec2.reset()
	if err := h.run("ec2", "key-pair", "import", "x1"); !errors.Is(err, app.ErrUsage) || len(h.ec2.calls()) != 0 {
		t.Errorf("non-interactive = %v", err)
	}
}
