package platform_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// LoginInput.Select uses the arrow-key picker when there is one and falls
// back to a numbered list of the labels, returning the value either way.
func TestLoginInputSelect(t *testing.T) {
	opts := []prompt.Option{{Label: "Acme (a1)", Value: "a1"}, {Label: "Beta (b2)", Value: "b2"}}
	p := prompttest.New(t, "b2")
	in := platform.LoginInput{Interactive: true, Picker: p}
	if v, err := in.Select(nil, "Account", opts, "a1"); err != nil || v != "b2" {
		t.Errorf("picker: %q, %v", v, err)
	}
	if a := p.Find("Account"); a.Default != "a1" {
		t.Errorf("default %q", a.Default)
	}
	var errb bytes.Buffer
	in = platform.LoginInput{Interactive: true}
	io := prompt.New(strings.NewReader("2\n"), &bytes.Buffer{}, &errb).WithInteractive(true)
	if v, err := in.Select(io, "Account", opts, "a1"); err != nil || v != "b2" {
		t.Errorf("fallback: %q, %v (%s)", v, err, errb.String())
	}
}
