package aliyun

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// A name several VPCs share is a pick in the interactive flow and exit
// code 5 in the non-interactive flow; leaving the pick is a cancel.
func TestAmbiguousVPCNameIsAPick(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := netHarness(t, app.Flags{})
	f.addVPCFull("vpc-a", "dup", "10.0.0.0/16", false)
	f.addVPCFull("vpc-b", "dup", "10.1.0.0/16", false)

	p := prompttest.New(t, "vpc-b")
	h.rt.Picker = p
	if err := h.run("vpc", "vpc", "get", "dup"); err != nil {
		t.Fatalf("get: %v", err)
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), `"vpc-b"`) || strings.Contains(h.stdout.String(), `"vpc-a"`) {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	a := p.Asked[0]
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "dup  vpc-a  10.0.0.0/16") || !strings.Contains(l, "dup  vpc-b  10.1.0.0/16") {
		t.Errorf("labels:\n%s", l)
	}

	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("vpc", "vpc", "get", "dup"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("vpc", "vpc", "get", "dup"); !errors.As(err, &amb) {
		t.Errorf("non-interactive = %v, want an ambiguous error", err)
	}
}
