package gcp

import (
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// setsOf lists the record sets of a managed zone of the fake as
// "name TYPE ttl value|value", sorted.
func setsOf(g *fakeGoogle, zone string) string {
	g.mu.Lock()
	defer g.mu.Unlock()
	var out []string
	for _, rs := range g.rrsets[zone] {
		out = append(out, fmt.Sprintf("%s %s %d %s", rs.Name, rs.Type, rs.Ttl, strings.Join(rs.Rrdatas, "|")))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// positionalHarness is a non-interactive harness on the Cloud DNS fake.
func positionalHarness(t *testing.T) (*gcpHarness, *fakeGoogle) {
	t.Helper()
	h, g := dnsHarness(t)
	h.nonInteractive()
	return h, g
}

// record upsert and record delete with the record as arguments write what
// the former flags write.
func TestDNSRecordPositionalMatchesFlagForm(t *testing.T) {
	for _, c := range []struct {
		name       string
		verb       string
		positional []string
		flags      []string
	}{
		{"several values replace the set", "upsert", []string{"www", "A", "203.0.113.10", "203.0.113.11"},
			[]string{"--name", "www", "--type", "A", "--value", "203.0.113.10", "--value", "203.0.113.11"}},
		{"apex, priorities in the values", "upsert", []string{"@", "MX", "10 mx1.example.net", "20 mx2.example.net", "--ttl", "600"},
			[]string{"--name", "@", "--type", "MX", "--value", "10 mx1.example.net", "--value", "20 mx2.example.net", "--ttl", "600"}},
		{"full name and --priority", "upsert", []string{"mail.example.com", "MX", "mx1.example.net", "--priority", "5"},
			[]string{"--name", "mail.example.com", "--type", "MX", "--value", "mx1.example.net", "--priority", "5"}},
		{"value after --", "upsert", []string{"new", "TXT", "--", "-dash"}, []string{"--name", "new", "--type", "TXT", "--value=-dash"}},
		{"delete the set", "delete", []string{"www", "A", "--yes"}, []string{"--name", "www", "--type", "A", "--yes"}},
		{"delete one value", "delete", []string{"www.example.com", "A", "2.2.2.2"}, []string{"--name", "www.example.com", "--type", "A", "--value", "2.2.2.2"}},
		{"delete one value with its priority", "delete", []string{"@", "MX", "mail.example.com", "--priority", "10", "--yes"},
			[]string{"--name", "@", "--type", "MX", "--value", "mail.example.com", "--priority", "10", "--yes"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			var got []string
			for _, form := range [][]string{c.positional, c.flags} {
				h, g := positionalHarness(t)
				before := setsOf(g, "example-zone")
				if err := h.run(append([]string{"dns", "record", c.verb, "example-zone"}, form...)...); err != nil {
					t.Fatalf("%v: %v\n%s", form, err, h.stderr.String())
				}
				after := setsOf(g, "example-zone")
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

	// The type is case-insensitive.
	h, g := positionalHarness(t)
	if err := h.run("dns", "record", "upsert", "example-zone", "www", "a", "203.0.113.10", "203.0.113.11"); err != nil {
		t.Fatal(err)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || strings.Join(rs.Rrdatas, ",") != "203.0.113.10,203.0.113.11" {
		t.Errorf("set = %+v", rs)
	}
	if err := h.run("dns", "record", "delete", "example-zone", "www", "a", "203.0.113.11"); err != nil {
		t.Fatal(err)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || strings.Join(rs.Rrdatas, ",") != "203.0.113.10" {
		t.Errorf("after deleting one value: %+v", rs)
	}
	if err := h.run("dns", "record", "delete", "example-zone", "www", "a", "--yes"); err != nil || g.rrset("example-zone", "www.example.com.", "A") != nil {
		t.Errorf("delete the set = %v", err)
	}
}

// Both forms at once, a wrong number of arguments, an empty argument and
// --id beside a record are usage errors, and nothing is written.
func TestDNSRecordPositionalUsage(t *testing.T) {
	h, g := positionalHarness(t)
	const upsert = "dns record upsert <zone> <name> <type> <value>..."
	const del = "dns record delete <zone> <name> [<type> [<value>]]"
	const id = "example-zone|A|www.example.com|1.1.1.1"
	before := setsOf(g, "example-zone")
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"upsert"}, "usage: gcp " + upsert},
		{[]string{"upsert", "example-zone"}, "usage: gcp " + upsert},
		{[]string{"upsert", "example-zone", "www"}, upsert},
		{[]string{"upsert", "example-zone", "www", "A"}, upsert},
		{[]string{"upsert", "example-zone", "--type", "A"}, upsert},
		{[]string{"upsert", "example-zone", "www", "A", "203.0.113.10", "--name", "www"}, "with --name; use one form: usage: gcp " + upsert},
		{[]string{"upsert", "example-zone", "www", "A", "203.0.113.10", "--type", "A"}, "with --type; use one form"},
		{[]string{"upsert", "example-zone", "www", "A", "203.0.113.10", "--value", "203.0.113.11"}, "with --value; use one form"},
		{[]string{"upsert", "example-zone", "", "A", "203.0.113.10"}, "<name> must not be empty"},
		{[]string{"upsert", "example-zone", "www", "", "203.0.113.10"}, "<type> must not be empty"},
		{[]string{"upsert", "example-zone", "www", "A", "203.0.113.10", ""}, "<value> must not be empty"},
		{[]string{"delete"}, "usage: gcp " + del},
		{[]string{"delete", "example-zone"}, "a record or --id is required: usage: gcp " + del},
		{[]string{"delete", "example-zone", "www"}, "--yes"},
		{[]string{"delete", "example-zone", "www", "A", "1.1.1.1", "2.2.2.2"}, del},
		{[]string{"delete", "example-zone", "--name", "www"}, "--yes"},
		{[]string{"delete", "example-zone", "www", "A", "--yes", "--name", "www"}, "with --name; use one form: usage: gcp " + del},
		{[]string{"delete", "example-zone", "www", "A", "--yes", "--type", "A"}, "with --type; use one form"},
		{[]string{"delete", "example-zone", "www", "A", "--value", "1.1.1.1"}, "with --value; use one form"},
		{[]string{"delete", "example-zone", "www", "A", "--yes", "--id", id}, "--id selects one record value"},
		{[]string{"delete", "example-zone", "www", "A", "1.1.1.1", "--id", id}, "--id selects one record value"},
		{[]string{"delete", "example-zone", "www", "A"}, "--yes"},
	} {
		err := h.run(append([]string{"dns", "record"}, c.args...)...)
		if exitClass(err) != "usage" || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v = %v; want a usage error with %q", c.args, err, c.want)
		}
		if after := setsOf(g, "example-zone"); after != before {
			t.Fatalf("%v wrote: %s", c.args, after)
		}
	}
	if err := h.run("dns", "record", "delete", "example-zone", "nope", "A", "--yes"); exitClass(err) != "notfound" {
		t.Errorf("missing set = %v", err)
	}
}

// With only the zone, record upsert asks for the name (never taken to be
// the zone apex), the type and the values, until one is left empty; a
// record that stops after its name or type is completed. record delete
// still offers the record sets.
func TestDNSRecordWithOnlyTheZoneAsks(t *testing.T) {
	h, g := dnsHarness(t)
	p := h.answer("@", "CAA", `0 issue "letsencrypt.org"`, "")
	if err := h.run("dns", "record", "upsert", "example-zone"); err != nil {
		t.Fatalf("upsert: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if a := p.Find("Record name in example.com"); prompttest.Labels(a.Options) != "@ (apex)  MX NS SOA TXT\ngeo  A\nwww  A\nAnother name..." {
		t.Errorf("names offered:\n%s", prompttest.Labels(a.Options))
	}
	if rs := g.rrset("example-zone", "example.com.", "CAA"); rs == nil || len(rs.Rrdatas) != 1 {
		t.Errorf("apex CAA = %+v", rs)
	}
	// <zone> <name>: the type of the name is preselected, the first value
	// of the set proposed, and more values are asked.
	p = h.answer("A", prompttest.KeepDefault{}, "192.0.2.8", "")
	if err := h.run("dns", "record", "upsert", "example-zone", "www"); err != nil {
		t.Fatalf("upsert <name>: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if a := p.Find("Record type"); a.Default != "A" {
		t.Errorf("type preselected %q", a.Default)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || strings.Join(rs.Rrdatas, ",") != "1.1.1.1,192.0.2.8" {
		t.Errorf("www A = %+v", rs)
	}
	// <zone> <name> <type>, the name typed in the list of another run.
	p = h.answer(prompttest.Label("Another name"), "new", "TXT", "hello", "")
	if err := h.run("dns", "record", "upsert", "example-zone"); err != nil {
		t.Fatalf("typed name: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	p = h.answer("192.0.2.9", "")
	if err := h.run("dns", "record", "upsert", "example-zone", "new", "a"); err != nil {
		t.Fatalf("upsert <name> <type>: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if g.rrset("example-zone", "new.example.com.", "TXT") == nil || g.rrset("example-zone", "new.example.com.", "A") == nil {
		t.Errorf("new.example.com was not written")
	}
	p = h.answer(prompttest.Label("TXT"))
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("dns", "record", "delete", "example-zone"); err != nil {
		t.Fatalf("delete: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if p.Find("Record set to delete") == nil || g.rrset("example-zone", "example.com.", "TXT") != nil {
		t.Errorf("TXT set still there or not offered")
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position completes the record types.
func TestDNSRecordPositionalHelp(t *testing.T) {
	h, _ := positionalHarness(t)
	for verb, use := range map[string]string{"upsert": "upsert <zone> <name> <type> <value>...", "delete": "delete <zone> [<name> [<type> [<value>]]]"} {
		cmd, _, err := Command(h.rt).Find([]string{"dns", "record", verb})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Use != use || !strings.Contains(cmd.Example, "record "+verb+" example-zone www A") || strings.Contains(cmd.Example, "--type") {
			t.Errorf("use %q, example %q", cmd.Use, cmd.Example)
		}
		if strings.Contains(cmd.Long, "--name") || strings.Contains(cmd.Long, "--value") || strings.Contains(cmd.Short, "--name") || strings.Contains(cmd.Short, "--value") {
			t.Errorf("%s: the help still names the former flags:\n%s\n%s", verb, cmd.Short, cmd.Long)
		}
		for _, name := range []string{"name", "type", "value"} {
			if f := cmd.Flags().Lookup(name); f == nil || !f.Hidden {
				t.Errorf("%s: --%s should exist and be hidden", verb, name)
			}
		}
		if f := cmd.Flags().Lookup("priority"); f == nil || f.Hidden {
			t.Errorf("%s: --priority should be listed", verb)
		}
		types, dir := cmd.ValidArgsFunction(cmd, []string{"example-zone", "www"}, "")
		if dir != cobra.ShellCompDirectiveNoFileComp || !strings.Contains(" "+strings.Join(types, " ")+" ", " CNAME ") {
			t.Errorf("%s: type completion %v, %v", verb, types, dir)
		}
		if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example-zone"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
			t.Errorf("%s: name completion %v, %v", verb, vals, dir)
		}
	}
}
