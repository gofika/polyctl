package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

func weightedSet(name, typ, id string, weight int64, values ...string) r53types.ResourceRecordSet {
	rs := valueSet(name, typ, 60, values...)
	rs.SetIdentifier = awssdk.String(id)
	rs.Weight = awssdk.Int64(weight)
	return rs
}

// route53 record delete deletes a whole record set: it lists the values and
// asks first (default no), needs --yes in the non-interactive flow before
// anything is read, and reports a missing set before asking.
func TestRoute53RecordDeleteConfirms(t *testing.T) {
	h, r53, _ := dnsPickHarness(t)
	r53.zones = []r53types.HostedZone{hostedZone("Z3", "other.org", false)}
	reset := func() {
		r53.sets["Z3"] = []r53types.ResourceRecordSet{valueSet("other.org.", "MX", 300, "10 mx1.other.org.", "20 mx2.other.org.")}
		r53.changes = nil
	}
	reset()

	// Non-interactive without --yes: a usage error naming --yes, nothing read.
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	r53.listCalls = 0
	if err := h.run("route53", "record", "delete", "other.org", "--type", "MX"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--yes") {
		t.Fatalf("no --yes = %v", err)
	}
	if r53.listCalls != 0 || len(r53.changes) != 0 {
		t.Errorf("read %d page(s), changes %v before refusing", r53.listCalls, r53.changes)
	}
	// A dry run asks nothing and needs no --yes.
	h.rt.Flags.DryRun = true
	if err := h.run("route53", "record", "delete", "other.org", "--type", "MX"); err != nil || len(r53.changes) != 0 {
		t.Errorf("dry run = %v, changes %v", err, r53.changes)
	}
	h.rt.Flags.DryRun = false
	// --yes deletes without asking.
	h.rt.Flags.Yes = true
	if err := h.run("route53", "record", "delete", "other.org", "--type", "MX"); err != nil || len(r53.sets["Z3"]) != 0 {
		t.Fatalf("--yes = %v, sets left %v", err, r53.sets["Z3"])
	}
	h.rt.Flags.Yes = false
	reset()

	// Interactive: the values are listed, a no deletes nothing (exit 0).
	h.rt.Flags.NonInteractive = false
	h.rt.Picker = prompttest.New(t)
	h.rt.Stdin = strings.NewReader("n\n")
	if err := h.run("route53", "record", "delete", "other.org", "--type", "MX"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Fatalf("declined = %v", err)
	}
	if !strings.Contains(h.stderr.String(), "mx2.other.org") || len(r53.changes) != 0 {
		t.Errorf("declined: stderr %q, changes %v", h.stderr.String(), r53.changes)
	}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("route53", "record", "delete", "other.org", "--type", "MX"); err != nil || len(r53.sets["Z3"]) != 0 {
		t.Fatalf("confirmed = %v, sets left %v", err, r53.sets["Z3"])
	}
	// A missing set is not found, before any question.
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("route53", "record", "delete", "other.org", "--type", "TXT"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing set = %v", err)
	}
	if strings.Contains(h.stderr.String(), "?") {
		t.Errorf("asked about a missing set: %q", h.stderr.String())
	}
}

// Routing-policy sets of one name and type are told apart by their set
// identifier: the picker offers each one, --set-identifier deletes or
// updates one, and without it the command is ambiguous (exit code 5)
// instead of not finding a set it just offered.
func TestRoute53RecordSetIdentifiers(t *testing.T) {
	h, r53, _ := dnsPickHarness(t)
	r53.zones = []r53types.HostedZone{hostedZone("Z3", "other.org", false)}
	reset := func() {
		r53.sets["Z3"] = []r53types.ResourceRecordSet{
			weightedSet("www.other.org.", "A", "eu", 70, "198.51.100.1"),
			weightedSet("www.other.org.", "A", "us", 30, "198.51.100.2"),
		}
	}
	reset()

	// The interactive upsert proposes the value of the set it replaces.
	up := prompttest.New(t, "A", prompttest.KeepDefault{}, "")
	h.rt.Picker = up
	if err := h.run("route53", "record", "upsert", "other.org", "--name", "www", "--set-identifier", "us"); err != nil {
		t.Fatalf("interactive upsert us: %v", err)
	}
	up.Done()
	if d := up.Asked[1].Default; d != "198.51.100.2" {
		t.Errorf("upsert of us proposed %q, want its own value", d)
	}
	reset()

	p := prompttest.New(t, prompttest.Label("set us"))
	h.rt.Picker = p
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("route53", "record", "delete", "other.org"); err != nil {
		t.Fatalf("picked delete: %v", err)
	}
	l := prompttest.Labels(p.Asked[0].Options)
	if !strings.Contains(l, "set eu") || !strings.Contains(l, "set us") {
		t.Errorf("options: %s", l)
	}
	if !strings.Contains(l, "www.other.org  A  set us  198.51.100.2  ttl 60") {
		t.Errorf("cells of a record set: %s", l)
	}
	if len(r53.sets["Z3"]) != 1 || awssdk.ToString(r53.sets["Z3"][0].SetIdentifier) != "eu" {
		t.Errorf("sets left: %+v", r53.sets["Z3"])
	}
	reset()

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive, h.rt.Flags.Yes = true, true
	var amb *app.AmbiguousError
	if err := h.run("route53", "record", "delete", "other.org", "--name", "www", "--type", "A"); !errors.As(err, &amb) || !strings.Contains(err.Error(), "--set-identifier") {
		t.Errorf("delete without identifier = %v", err)
	}
	if err := h.run("route53", "record", "upsert", "other.org", "--name", "www", "--type", "A", "--value", "203.0.113.9"); !errors.As(err, &amb) {
		t.Errorf("upsert without identifier = %v", err)
	}
	if len(r53.sets["Z3"]) != 2 {
		t.Fatalf("sets changed: %+v", r53.sets["Z3"])
	}
	// On a terminal the sets of the name and type are a list to choose from,
	// for delete and for upsert, in the positional and the former form.
	h.rt.Flags.NonInteractive = false
	for _, args := range [][]string{
		{"route53", "record", "delete", "other.org", "www", "A"},
		{"route53", "record", "delete", "other.org", "--name", "www", "--type", "A"},
		{"route53", "record", "upsert", "other.org", "www", "A", "203.0.113.9"},
	} {
		p := prompttest.New(t, prompttest.Label("set us"))
		h.rt.Picker = p
		if err := h.run(args...); err != nil {
			t.Fatalf("%v on a terminal: %v", args, err)
		}
		p.Done()
		if a := p.Asked[0]; len(a.Options) != 2 || !strings.Contains(prompttest.Labels(a.Options), "www.other.org  A  set eu  198.51.100.1  ttl 60") {
			t.Errorf("%v: options %s", args, prompttest.Labels(a.Options))
		}
		switch sets := r53.sets["Z3"]; args[2] {
		case "delete":
			if len(sets) != 1 || awssdk.ToString(sets[0].SetIdentifier) != "eu" {
				t.Errorf("%v: sets left %+v", args, sets)
			}
		default:
			for _, s := range sets {
				if id := awssdk.ToString(s.SetIdentifier); (id == "us") != (setValues(&s)[0] == "203.0.113.9") {
					t.Errorf("%v: set %s holds %v", args, id, setValues(&s))
				}
			}
		}
		reset()
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("route53", "record", "upsert", "other.org", "--name", "www", "--type", "A", "--set-identifier", "eu", "--value", "203.0.113.9"); err != nil {
		t.Fatalf("upsert eu: %v", err)
	}
	for _, s := range r53.sets["Z3"] {
		if awssdk.ToString(s.SetIdentifier) == "eu" && (awssdk.ToInt64(s.Weight) != 70 || setValues(&s)[0] != "203.0.113.9") {
			t.Errorf("eu after upsert: %+v", s)
		}
	}
	if err := h.run("route53", "record", "delete", "other.org", "--name", "www", "--type", "A", "--set-identifier", "us"); err != nil {
		t.Fatalf("delete us: %v", err)
	}
	if len(r53.sets["Z3"]) != 1 || awssdk.ToString(r53.sets["Z3"][0].SetIdentifier) != "eu" {
		t.Errorf("sets left: %+v", r53.sets["Z3"])
	}
	if err := h.run("route53", "record", "delete", "other.org", "--name", "www", "--type", "A", "--set-identifier", "nope"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("unknown identifier = %v", err)
	}
	// upsert cannot create a routing-policy set (it sets no policy): an
	// unknown identifier is not found, and nothing is sent.
	r53.changes = nil
	if err := h.run("route53", "record", "upsert", "other.org", "--name", "www", "--type", "A", "--set-identifier", "nope", "--value", "203.0.113.7"); !errors.Is(err, platform.ErrNotFound) || len(r53.changes) != 0 {
		t.Errorf("upsert unknown identifier = %v, changes %v", err, r53.changes)
	}
}
