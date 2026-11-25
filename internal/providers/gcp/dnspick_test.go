package gcp

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// dnsHarness is an interactive harness whose Cloud DNS calls go to the
// fake of client_test.go.
func dnsHarness(t *testing.T) (*gcpHarness, *fakeGoogle) {
	t.Helper()
	h, _ := interactiveGCP(t, nil)
	g := newFake(t)
	old := extraOptions
	extraOptions = g.options()
	t.Cleanup(func() { extraOptions = old })
	return h, g
}

// zone get and record list without <zone> offer the managed zones; none
// is nothing to do (upsert: a usage error naming <zone>); leaving the pick
// is cancelled; the non-interactive flow still needs <zone>.
func TestDNSZonePick(t *testing.T) {
	h, g := dnsHarness(t)
	p := h.answer("proj/third-zone")
	if err := h.run("dns", "zone", "get"); err != nil || !strings.Contains(h.stdout.String(), `"third.example"`) {
		t.Fatalf("zone get = %v\n%s", err, h.stdout.String())
	}
	p.Done()
	a := p.Find("Managed zone")
	if l := prompttest.Labels(a.Options); !strings.Contains(l, "example-zone  example.com  public  1 nameservers") || !strings.Contains(l, "internal-zone  corp.internal  private") {
		t.Errorf("zones offered:\n%s", l)
	}

	h.answer(prompttest.Abort{})
	if err := h.run("dns", "record", "list"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}

	g.zones = nil
	h.rt.Flags.Refresh = true
	h.answer()
	if err := h.run("dns", "zone", "get"); exitClass(err) != "nothing" {
		t.Errorf("no zones: get = %v", err)
	}
	if err := h.run("dns", "record", "upsert", "--type", "A", "--value", "192.0.2.1"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "<zone>") {
		t.Errorf("no zones: upsert = %v", err)
	}

	h.nonInteractive()
	if err := h.run("dns", "zone", "get"); err == nil || !strings.Contains(err.Error(), "arg") {
		t.Errorf("non-interactive = %v", err)
	}
}

// upsert without --type / --value asks them, the current value of the set
// proposed and the value checked as it is typed; the non-interactive flow
// still names --type and --value.
func TestDNSRecordUpsertAsks(t *testing.T) {
	h, g := dnsHarness(t)
	p := h.answer("proj/example-zone", "A", "not-an-ip", "192.0.2.7")
	if err := h.run("dns", "record", "upsert", "--name", "www"); err != nil {
		t.Fatalf("upsert: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if in := p.Asked[len(p.Asked)-1]; in.Kind != "input" || in.Default != "1.1.1.1" {
		t.Errorf("value prompt %+v", in)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || strings.Join(rs.Rrdatas, ",") != "192.0.2.7" {
		t.Errorf("rrset = %+v", rs)
	}
	h.nonInteractive()
	if err := h.run("dns", "record", "upsert", "example-zone", "--name", "www"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--type") {
		t.Errorf("non-interactive = %v", err)
	}
}

// delete without --name/--type offers the record sets of the zone (the
// apex SOA and NS left out), then the whole set or one value.
func TestDNSRecordDeletePicks(t *testing.T) {
	h, g := dnsHarness(t)
	p := h.answer("proj/example-zone", prompttest.Label("www.example.com  A"), prompttest.Label("Only 2.2.2.2"))
	if err := h.run("dns", "record", "delete"); err != nil {
		t.Fatalf("delete: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	l := prompttest.Labels(p.Find("Record set to delete").Options)
	if strings.Contains(l, "SOA") || strings.Contains(l, "example.com  NS") || !strings.Contains(l, "www.example.com  A  1.1.1.1  ttl 300  +1 more") ||
		!strings.Contains(l, "example.com  MX  10 mail.example.com  ttl 3600") {
		t.Errorf("sets offered:\n%s", l)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || strings.Join(rs.Rrdatas, ",") != "1.1.1.1" {
		t.Errorf("rrset = %+v", rs)
	}

	// The MX set has one value: it goes whole.
	p = h.answer("proj/example-zone", prompttest.Label("MX"))
	h.rt.Stdin = strings.NewReader("y\n") // the confirmation of the whole set
	if err := h.run("dns", "record", "delete"); err != nil {
		t.Fatalf("delete mx: %v", err)
	}
	p.Done()
	if rs := g.rrset("example-zone", "example.com.", "MX"); rs != nil {
		t.Errorf("mx still there: %+v", rs)
	}

	h.nonInteractive()
	if err := h.run("dns", "record", "delete", "example-zone"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--name and --type") {
		t.Errorf("non-interactive = %v", err)
	}
}

// Deleting a whole record set lists its values and asks first (default
// no); the non-interactive flow needs --yes before anything is read; a
// missing set is not found before the question; one value (--value) is
// removed without a question.
func TestDNSRecordDeleteSetConfirms(t *testing.T) {
	h, g := dnsHarness(t)
	h.answer()
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "www", "--type", "A"); exitClass(err) != "nothing" {
		t.Fatalf("declined = %v", err)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || len(rs.Rrdatas) != 2 || !strings.Contains(h.stderr.String(), "2.2.2.2") {
		t.Errorf("declined: rrset %+v, stderr %q", rs, h.stderr.String())
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "nope", "--type", "A"); exitClass(err) != "notfound" {
		t.Errorf("missing set = %v", err)
	}
	// A routing-policy set cannot be deleted here: refused before the
	// question, not after a "yes".
	h.stderr.Reset()
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "geo", "--type", "A"); !errors.Is(err, platform.ErrNotSupported) || strings.Contains(h.stderr.String(), "Delete the") {
		t.Errorf("routing-policy set = %v, stderr %q", err, h.stderr.String())
	}

	h.nonInteractive()
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "www", "--type", "A"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no --yes = %v", err)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil {
		t.Fatal("deleted without --yes")
	}
	h.rt.Flags.DryRun = true
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "www", "--type", "A"); err != nil || g.rrset("example-zone", "www.example.com.", "A") == nil {
		t.Errorf("dry run = %v", err)
	}
	h.rt.Flags.DryRun = false
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "www", "--type", "A", "--value", "2.2.2.2"); err != nil {
		t.Errorf("one value without --yes = %v", err)
	}
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "www", "--type", "A", "--yes"); err != nil || g.rrset("example-zone", "www.example.com.", "A") != nil {
		t.Errorf("--yes = %v", err)
	}
}

// --id selects one value: --name, --type, --value or --priority beside it
// would be ignored, so the combination is a usage error and nothing is
// deleted.
func TestDNSRecordDeleteIDWithFilters(t *testing.T) {
	h, g := dnsHarness(t)
	h.nonInteractive()
	id := "example-zone|A|www.example.com|1.1.1.1"
	for _, extra := range [][]string{
		{"--name", "mail", "--type", "MX"},
		{"--name", "www"},
		{"--type", "A"},
		{"--value", "2.2.2.2"},
		{"--priority", "10"},
	} {
		args := append([]string{"dns", "record", "delete", "example-zone", "--id", id, "--yes"}, extra...)
		if err := h.run(args...); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--id") {
			t.Errorf("%v = %v", extra, err)
		}
		if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || len(rs.Rrdatas) != 2 {
			t.Fatalf("%v: rrset %+v", extra, rs)
		}
	}
	// The id alone still deletes its value.
	if err := h.run("dns", "record", "delete", "example-zone", "--id", id); err != nil {
		t.Fatalf("--id alone = %v", err)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || len(rs.Rrdatas) != 1 {
		t.Errorf("after --id: rrset %+v", rs)
	}
}
