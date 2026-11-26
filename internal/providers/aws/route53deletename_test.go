package aws

import (
	"errors"
	"strings"
	"testing"

	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// nameHarness is positionalHarness with a name of two types (mail) and the
// NS set of the apex beside its TXT set.
func nameHarness(t *testing.T) (*awsHarness, *fakeRoute53, func()) {
	t.Helper()
	h, r53, _ := positionalHarness(t)
	reset := func() {
		r53.sets["Z3"] = []r53types.ResourceRecordSet{
			valueSet("www.other.org.", "A", 300, "198.51.100.7", "198.51.100.8"),
			valueSet("mail.other.org.", "A", 300, "198.51.100.9"),
			valueSet("mail.other.org.", "TXT", 300, `"v=spf1 -all"`),
			valueSet("other.org.", "NS", 300, "ns1.example.net."),
			valueSet("other.org.", "TXT", 300, `"apex"`),
		}
		r53.changes = nil
	}
	reset()
	return h, r53, reset
}

// A name with one record set needs no <type>, in both forms; the NS and SOA
// sets of the apex are not meant by the name alone.
func TestRoute53RecordDeleteByNameOfOneSet(t *testing.T) {
	h, r53, reset := nameHarness(t)
	h.rt.Flags.Yes = true
	for _, c := range []struct {
		args []string
		gone string
	}{
		{[]string{"www"}, "www.other.org. A"},
		{[]string{"--name", "www"}, "www.other.org. A"},
		{[]string{"@"}, "other.org. TXT"},
	} {
		reset()
		if err := h.run(append([]string{"route53", "record", "delete", "other.org"}, c.args...)...); err != nil {
			t.Fatalf("%v: %v\n%s", c.args, err, h.stderr.String())
		}
		if left := "," + setsOf(r53, "Z3"); strings.Contains(left, ","+c.gone) || len(r53.sets["Z3"]) != 4 {
			t.Errorf("%v left %s", c.args, left)
		}
	}
	reset()
	if err := h.run("route53", "record", "delete", "other.org", "nope"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("no record of the name = %v", err)
	}
	// Without --yes the non-interactive flow is refused before anything is read.
	h.rt.Flags.Yes = false
	r53.listCalls = 0
	if err := h.run("route53", "record", "delete", "other.org", "www"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "would delete the record set of www") || r53.listCalls != 0 {
		t.Errorf("no --yes = %v after %d read(s)", err, r53.listCalls)
	}
	// A dry run reports the set and asks nothing.
	h.rt.Flags.DryRun = true
	if err := h.run("route53", "record", "delete", "other.org", "www"); err != nil || len(r53.changes) != 0 || !strings.Contains(h.stderr.String(), "dry run: would delete") {
		t.Errorf("dry run = %v, changes %v, stderr %q", err, r53.changes, h.stderr.String())
	}
}

// A name with record sets of several types is exit code 5 where nothing can
// be asked, also with --yes, and nothing is deleted.
func TestRoute53RecordDeleteByNameOfSeveralTypesIsAmbiguous(t *testing.T) {
	h, r53, _ := nameHarness(t)
	before := setsOf(r53, "Z3")
	for _, yes := range []bool{true, false} {
		h.rt.Flags.Yes, h.rt.Flags.DryRun = yes, !yes
		for arg, form := range map[string][]string{"<type>": {"mail"}, "--type": {"--name", "mail"}} {
			err := h.run(append([]string{"route53", "record", "delete", "other.org"}, form...)...)
			if !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "mail.other.org has records of 2 types in zone other.org (A, TXT); give "+arg) {
				t.Errorf("%v (yes %v) = %v", form, yes, err)
			}
		}
	}
	if len(r53.changes) != 0 || setsOf(r53, "Z3") != before {
		t.Errorf("wrote: %s", setsOf(r53, "Z3"))
	}
}

// On a terminal the record sets of such a name are offered, and the one
// picked is confirmed and deleted; a no deletes nothing (exit code 0).
func TestRoute53RecordDeleteByNameOffersTheSets(t *testing.T) {
	h, r53, reset := nameHarness(t)
	h.rt.Flags.NonInteractive = false
	p := prompttest.New(t, prompttest.Label("TXT"))
	h.rt.Picker = p
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("route53", "record", "delete", "other.org", "mail"); err != nil {
		t.Fatalf("picked: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); l != "mail.other.org  A  -  198.51.100.9  ttl 300\nmail.other.org  TXT  -  v=spf1 -all  ttl 300" {
		t.Errorf("options:\n%s", l)
	}
	if left := setsOf(r53, "Z3"); strings.Contains(left, "mail.other.org. TXT") || !strings.Contains(left, "mail.other.org. A") {
		t.Errorf("left %s", left)
	}
	// One set of several values: no list, the values and the question.
	reset()
	h.stderr.Reset()
	h.rt.Picker = prompttest.New(t)
	h.rt.Stdin = strings.NewReader("n\n")
	before := setsOf(r53, "Z3")
	if err := h.run("route53", "record", "delete", "other.org", "www"); !errors.Is(err, platform.ErrNothingToDo) || setsOf(r53, "Z3") != before {
		t.Fatalf("declined = %v, sets %s", err, setsOf(r53, "Z3"))
	}
	if s := h.stderr.String(); !strings.Contains(s, "198.51.100.8") || !strings.Contains(s, "Delete the A record set of www.other.org (2 value(s))?") {
		t.Errorf("question: %q", s)
	}
}

// One type in several routing-policy sets: a terminal offers the sets, the
// non-interactive flow lists the identifiers (exit code 5).
func TestRoute53RecordDeleteByNameOfRoutedSets(t *testing.T) {
	h, r53, _ := nameHarness(t)
	r53.sets["Z3"] = []r53types.ResourceRecordSet{
		weightedSet("www.other.org.", "A", "eu", 70, "198.51.100.1"),
		weightedSet("www.other.org.", "A", "us", 30, "198.51.100.2"),
	}
	h.rt.Flags.Yes = true
	var amb *app.AmbiguousError
	if err := h.run("route53", "record", "delete", "other.org", "www"); !errors.As(err, &amb) || !strings.Contains(err.Error(), "--set-identifier") || len(r53.sets["Z3"]) != 2 {
		t.Errorf("non-interactive = %v, sets %s", err, setsOf(r53, "Z3"))
	}
	h.rt.Flags.NonInteractive = false
	p := prompttest.New(t, prompttest.Label("set us"))
	h.rt.Picker = p
	if err := h.run("route53", "record", "delete", "other.org", "www"); err != nil || len(r53.sets["Z3"]) != 1 {
		t.Errorf("picked = %v, sets %s", err, setsOf(r53, "Z3"))
	}
	p.Done()
}
