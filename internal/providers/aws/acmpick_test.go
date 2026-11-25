package aws

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// get without the argument offers the certificates of the inventory.
func TestACMGetPick(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	c := h.addCert(&fakeCert{region: "ap-east-1", domain: "example.com", status: acmIssued, notAfter: expires(2027)})
	p := prompttest.New(t, c.arn)
	h.rt.Picker = p
	if err := h.run("acm", "certificate", "get"); err != nil {
		t.Fatalf("get: %v\n%s", err, h.stderr.String())
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "example.com  ISSUED  expires 2027") || !strings.Contains(l, "aws/lab/ap-east-1") {
		t.Errorf("labels: %s", l)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("acm", "certificate", "get"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v", err)
	}
}

// import without <domain> offers the unexpired certificates of the store;
// several imported certificates of the domain are a pick, with "Import as a
// new certificate".
func TestACMImportPicks(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	ca := certtest.New("Test Issuer")
	b, _, _ := issue(t, ca, "example.com", nil, time.Now().Add(90*24*time.Hour))
	storeBundle(t, h, b)
	old, _, _ := issue(t, ca, "old.org", nil, time.Now().Add(-time.Minute))
	storeBundle(t, h, old)
	// Two imported certificates of example.com, neither of them holding
	// the certificate of the store.
	for i := 0; i < 3; i++ {
		if i < 2 {
			if err := h.run("acm", "certificate", "import", "example.com", "--new"); err != nil {
				t.Fatal(err)
			}
		}
		b, _, _ = issue(t, ca, "example.com", nil, time.Now().Add(time.Duration(91+i)*24*time.Hour))
		storeBundle(t, h, b)
	}
	h.rt.Flags.NonInteractive = false
	p := prompttest.New(t, "example.com", prompttest.Label("Import as a new certificate"))
	h.rt.Picker = p
	if err := h.run("acm", "certificate", "import"); err != nil {
		t.Fatalf("import: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if v := prompttest.Values(p.Asked[0].Options); v != "example.com" {
		t.Errorf("store offered %q, want no expired certificate", v)
	}
	if a := actions(h.importOut().Report); a["certificate/example.com created"] != 1 {
		t.Errorf("report = %v", a)
	}

	b, _, _ = issue(t, ca, "example.com", nil, time.Now().Add(95*24*time.Hour))
	storeBundle(t, h, b)
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("acm", "certificate", "import", "example.com"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
}

// request without <domain> offers the indexed domains and "Another
// domain..."; with an empty index the domain is typed and checked.
func TestACMRequestAsksDomain(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{NonInteractiveSet: true, DryRun: true}, nil)
	p := prompttest.New(t, "not a domain", "example.com")
	h.rt.Picker = p
	if err := h.run("acm", "certificate", "request"); err != nil {
		t.Fatalf("request: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if !strings.Contains(h.stdout.String(), "example.com") {
		t.Errorf("stdout = %s", h.stdout.String())
	}
}
