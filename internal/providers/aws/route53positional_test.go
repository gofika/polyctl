package aws

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// setsOf lists the record sets of a zone of the fake as
// "name TYPE ttl value|value", sorted.
func setsOf(f *fakeRoute53, zone string) string {
	var out []string
	for _, s := range f.sets[zone] {
		out = append(out, fmt.Sprintf("%s %s %d %s", awssdk.ToString(s.Name), s.Type, awssdk.ToInt64(s.TTL), strings.Join(setValues(&s), "|")))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// positionalHarness is a non-interactive harness with the zone other.org
// (Z3), and a function that puts its record sets back.
func positionalHarness(t *testing.T) (*awsHarness, *fakeRoute53, func()) {
	t.Helper()
	h, r53, _ := dnsPickHarness(t)
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	r53.zones = []r53types.HostedZone{hostedZone("Z3", "other.org", false)}
	reset := func() {
		r53.sets["Z3"] = []r53types.ResourceRecordSet{
			valueSet("www.other.org.", "A", 300, "198.51.100.7"),
			valueSet("old.other.org.", "TXT", 300, `"gone"`),
		}
		r53.changes = nil
	}
	reset()
	return h, r53, reset
}

// record upsert and record delete with the record as arguments write what
// the former flags write.
func TestRoute53RecordPositionalMatchesFlagForm(t *testing.T) {
	h, r53, reset := positionalHarness(t)
	h.rt.Flags.Yes = true
	for _, c := range []struct {
		name       string
		verb       string
		positional []string
		flags      []string
	}{
		{"several values replace the set", "upsert", []string{"www", "A", "203.0.113.10", "203.0.113.11"},
			[]string{"--name", "www", "--type", "A", "--value", "203.0.113.10", "--value", "203.0.113.11"}},
		{"apex, lower-case type, priorities in the values", "upsert", []string{"@", "mx", "10 mx1.other.org", "20 mx2.other.org", "--ttl", "600"},
			[]string{"--name", "@", "--type", "mx", "--value", "10 mx1.other.org", "--value", "20 mx2.other.org", "--ttl", "600"}},
		{"full name and --priority", "upsert", []string{"mail.other.org", "MX", "mx1.other.org", "--priority", "5"},
			[]string{"--name", "mail.other.org", "--type", "MX", "--value", "mx1.other.org", "--priority", "5"}},
		{"value after --", "upsert", []string{"new", "TXT", "--", "-dash"}, []string{"--name", "new", "--type", "TXT", "--value=-dash"}},
		{"delete", "delete", []string{"www", "A"}, []string{"--name", "www", "--type", "A"}},
		{"delete, full name and lower-case type", "delete", []string{"old.other.org", "txt"}, []string{"--name", "old.other.org", "--type", "txt"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, form := range [][]string{c.positional, c.flags} {
				reset()
				before := setsOf(r53, "Z3")
				if err := h.run(append([]string{"route53", "record", c.verb, "other.org"}, form...)...); err != nil {
					t.Fatalf("%v: %v\n%s", form, err, h.stderr.String())
				}
				after := setsOf(r53, "Z3")
				if after == before {
					t.Fatalf("%v changed nothing: %s", form, after)
				}
				got = append(got, after)
			}
			if got[0] != got[1] {
				t.Errorf("positional wrote %q, flags wrote %q", got[0], got[1])
			}
		})
	}
	reset()
	if err := h.run("route53", "record", "upsert", "other.org", "www", "A", "203.0.113.10", "203.0.113.11"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(r53.values("Z3", "www.other.org.", "A"), ","); got != "203.0.113.10,203.0.113.11" {
		t.Errorf("set = %s", got)
	}
}

// Both forms at once, a wrong number of arguments and an empty argument are
// usage errors that show the positional form, and nothing is written.
func TestRoute53RecordPositionalUsage(t *testing.T) {
	h, r53, _ := positionalHarness(t)
	h.rt.Flags.Yes = true
	const upsert = "route53 record upsert <zone> <name> <type> <value>..."
	const del = "route53 record delete <zone> <name> <type>"
	before := setsOf(r53, "Z3")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"upsert"}, "usage: aws " + upsert},
		{[]string{"upsert", "other.org"}, "usage: aws " + upsert},
		{[]string{"upsert", "other.org", "www"}, upsert},
		{[]string{"upsert", "other.org", "www", "A"}, upsert},
		{[]string{"upsert", "other.org", "--type", "A"}, upsert},
		{[]string{"upsert", "other.org", "www", "A", "203.0.113.10", "--name", "www"}, "with --name; use one form: usage: aws " + upsert},
		{[]string{"upsert", "other.org", "www", "A", "203.0.113.10", "--type", "A"}, "with --type; use one form"},
		{[]string{"upsert", "other.org", "www", "A", "203.0.113.10", "--value", "203.0.113.11"}, "with --value; use one form"},
		{[]string{"upsert", "other.org", "", "A", "203.0.113.10"}, "<name> must not be empty"},
		{[]string{"upsert", "other.org", "www", "", "203.0.113.10"}, "<type> must not be empty"},
		{[]string{"upsert", "other.org", "www", "A", "203.0.113.10", ""}, "<value> must not be empty"},
		{[]string{"delete"}, "usage: aws " + del},
		{[]string{"delete", "other.org"}, "usage: aws " + del},
		{[]string{"delete", "other.org", "www"}, del},
		{[]string{"delete", "other.org", "www", "A", "198.51.100.7"}, del},
		{[]string{"delete", "other.org", "--name", "www"}, del},
		{[]string{"delete", "other.org", "www", "A", "--name", "www"}, "with --name; use one form: usage: aws " + del},
		{[]string{"delete", "other.org", "www", "A", "--type", "A"}, "with --type; use one form"},
	} {
		err := h.run(append([]string{"route53", "record"}, c.args...)...)
		if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v = %v; want a usage error with %q", c.args, err, c.want)
		}
		if len(r53.changes) != 0 || setsOf(r53, "Z3") != before {
			t.Fatalf("%v wrote: %s", c.args, setsOf(r53, "Z3"))
		}
	}
}

// With only the zone, record upsert still asks for the type and the value;
// the set is then at the zone apex.
func TestRoute53RecordUpsertWithOnlyTheZoneAsks(t *testing.T) {
	h, r53, _ := positionalHarness(t)
	h.rt.Flags.NonInteractive = false
	p := prompttest.New(t, "TXT", "hello")
	h.rt.Picker = p
	if err := h.run("route53", "record", "upsert", "other.org"); err != nil {
		t.Fatalf("upsert: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if got := r53.values("Z3", "other.org.", "TXT"); len(got) != 1 {
		t.Errorf("apex TXT = %v", got)
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position completes the record types.
func TestRoute53RecordPositionalHelp(t *testing.T) {
	h, _, _ := positionalHarness(t)
	for verb, use := range map[string]string{"upsert": "upsert <zone> <name> <type> <value>...", "delete": "delete <zone> <name> <type>"} {
		cmd, _, err := Command(h.rt).Find([]string{"route53", "record", verb})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Use != use || !strings.Contains(cmd.Example, "record "+verb+" example.com www A") || strings.Contains(cmd.Example, "--type") {
			t.Errorf("use %q, example %q", cmd.Use, cmd.Example)
		}
		for _, name := range []string{"name", "type", "value"} {
			if f := cmd.Flags().Lookup(name); f != nil && !f.Hidden {
				t.Errorf("%s: --%s should be hidden", verb, name)
			}
		}
		if f := cmd.Flags().Lookup("set-identifier"); f == nil || f.Hidden {
			t.Errorf("%s: --set-identifier should be listed", verb)
		}
		types, dir := cmd.ValidArgsFunction(cmd, []string{"example.com", "www"}, "")
		if dir != cobra.ShellCompDirectiveNoFileComp || !strings.Contains(" "+strings.Join(types, " ")+" ", " CNAME ") {
			t.Errorf("%s: type completion %v, %v", verb, types, dir)
		}
		if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example.com"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
			t.Errorf("%s: name completion %v, %v", verb, vals, dir)
		}
	}
}
