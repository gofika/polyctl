package aws

import (
	"bytes"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// The Identity Center region is picked from the commercial regions (the
// previous one preselected), or typed and checked.
func TestAskSSORegion(t *testing.T) {
	p := prompttest.New(t, "eu-west-1")
	in := platform.LoginInput{Interactive: true, Picker: p}
	io := prompt.New(strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{}).WithInteractive(true)
	if r, err := askSSORegion(in, io, "us-east-1"); err != nil || r != "eu-west-1" {
		t.Fatalf("pick = %q, %v", r, err)
	}
	if p.Asked[0].Default != "us-east-1" || !prompttest.HasValue(p.Asked[0].Options, "ap-east-1") {
		t.Errorf("asked %+v", p.Asked[0])
	}
	var errOut bytes.Buffer
	in.Picker = prompttest.New(t, prompttest.Label("Another region"))
	io = prompt.New(strings.NewReader("nowhere\nxx-new-9\n"), &bytes.Buffer{}, &errOut).WithInteractive(true)
	if r, err := askSSORegion(in, io, "us-east-1"); err != nil || r != "xx-new-9" {
		t.Errorf("typed = %q, %v (stderr %q)", r, err, errOut.String())
	}
	if !strings.Contains(errOut.String(), "not a region name") {
		t.Errorf("stderr = %q", errOut.String())
	}
}
