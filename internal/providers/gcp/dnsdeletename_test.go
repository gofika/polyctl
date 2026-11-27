package gcp

import (
	"strings"
	"testing"

	"google.golang.org/api/dns/v1"

	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// A name with one record set needs no <type>, in both forms; a value
// without a type selects among the values of the name.
func TestDNSRecordDeleteByNameOfOneSet(t *testing.T) {
	for _, form := range [][]string{{"www", "--yes"}, {"--name", "www", "--yes"}} {
		h, g := positionalHarness(t)
		if err := h.run(append([]string{"dns", "record", "delete", "example-zone"}, form...)...); err != nil || g.rrset("example-zone", "www.example.com.", "A") != nil {
			t.Errorf("%v = %v, sets %s", form, err, setsOf(g, "example-zone"))
		}
	}
	h, g := positionalHarness(t)
	before := setsOf(g, "example-zone")
	// Without --yes the whole set is refused once the name is known to mean
	// one record set; a dry run reports it and asks nothing.
	if err := h.run("dns", "record", "delete", "example-zone", "www"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "pass --yes to proceed (would delete the A record set of www.example.com)") {
		t.Errorf("no --yes = %v", err)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("dns", "record", "delete", "example-zone", "www"); err != nil || !strings.Contains(h.stderr.String(), "dry run: would delete") {
		t.Errorf("dry run = %v, stderr %q", err, h.stderr.String())
	}
	h.rt.Flags.DryRun = false
	if err := h.run("dns", "record", "delete", "example-zone", "nope", "--yes"); exitClass(err) != "notfound" {
		t.Errorf("no record of the name = %v", err)
	}
	if after := setsOf(g, "example-zone"); after != before {
		t.Fatalf("wrote: %s", after)
	}
	// One value is removed without a question.
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "www", "--value", "2.2.2.2"); err != nil {
		t.Fatalf("one value = %v", err)
	}
	if rs := g.rrset("example-zone", "www.example.com.", "A"); rs == nil || strings.Join(rs.Rrdatas, ",") != "1.1.1.1" {
		t.Errorf("rrset = %+v", rs)
	}
}

// A name with record sets of several types (the apex: MX and TXT, its NS
// and SOA not counted) is exit code 5 where nothing can be asked, also with
// --yes, without it and in a dry run, and nothing is deleted.
func TestDNSRecordDeleteByNameOfSeveralTypesIsAmbiguous(t *testing.T) {
	h, g := positionalHarness(t)
	before := setsOf(g, "example-zone")
	for arg, form := range map[string][]string{"<type>": {"@"}, "--type": {"--name", "@"}} {
		for _, flag := range []string{"--yes", "--dry-run", ""} {
			yes := flag
			args := append([]string{"dns", "record", "delete", "example-zone"}, form...)
			if h.rt.Flags.DryRun = flag == "--dry-run"; flag == "--yes" {
				args = append(args, flag)
			}
			err := h.run(args...)
			if exitClass(err) != "ambiguous" || !strings.Contains(err.Error(), "example.com has records of 2 types in zone example.com (MX, TXT); give "+arg) {
				t.Errorf("%v %q = %v", form, yes, err)
			}
		}
	}
	if after := setsOf(g, "example-zone"); after != before {
		t.Fatalf("wrote: %s", after)
	}
}

// On a terminal the record sets of such a name are offered; a set of
// several values is confirmed with its ids and the way to delete one value.
func TestDNSRecordDeleteByNameOffersTheSets(t *testing.T) {
	h, g := dnsHarness(t)
	p := h.answer(prompttest.Label("TXT"))
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("dns", "record", "delete", "example-zone", "@"); err != nil {
		t.Fatalf("picked: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Find("Record set to delete").Options); strings.Count(l, "\n") != 1 || !strings.Contains(l, "example.com  MX") || !strings.Contains(l, "example.com  TXT") {
		t.Errorf("sets offered:\n%s", l)
	}
	if g.rrset("example-zone", "example.com.", "TXT") != nil || g.rrset("example-zone", "example.com.", "MX") == nil || g.rrset("example-zone", "example.com.", "NS") == nil {
		t.Errorf("sets left: %s", setsOf(g, "example-zone"))
	}

	h.stderr.Reset()
	h.answer()
	h.rt.Stdin = strings.NewReader("n\n")
	const hint = "to delete one of them only, give its <value> after the <type>, or its id with --id <id>"
	err := h.run("dns", "record", "delete", "example-zone", "www")
	if exitClass(err) != "nothing" || err.Error() != "nothing to do: no record was deleted; "+hint || g.rrset("example-zone", "www.example.com.", "A") == nil {
		t.Fatalf("declined = %v", err)
	}
	s := h.stderr.String()
	for _, want := range []string{"2 records match; " + hint, "|A|www.example.com|1.1.1.1", "|A|www.example.com|2.2.2.2", "Delete the A record set of www.example.com (2 value(s))?"} {
		if !strings.Contains(s, want) {
			t.Errorf("the question lacks %q: %s", want, s)
		}
	}
}

// What a name alone means is decided on the zone as it is, not on the
// inventory: a record set created after the records were cached counts.
func TestDNSRecordDeleteByNameReadsTheZoneLive(t *testing.T) {
	h, g := positionalHarness(t)
	if err := h.run("dns", "record", "list", "example-zone"); err != nil {
		t.Fatal(err)
	}
	add := func(name, typ, value string) {
		g.rrsets["example-zone"] = append(g.rrsets["example-zone"], &dns.ResourceRecordSet{Name: name, Type: typ, Ttl: 300, Rrdatas: []string{value}})
	}
	add("www.example.com.", "TXT", `"later"`)
	before := setsOf(g, "example-zone")
	err := h.run("dns", "record", "delete", "example-zone", "www", "--yes")
	if exitClass(err) != "ambiguous" || !strings.Contains(err.Error(), "www.example.com has records of 2 types in zone example.com (A, TXT)") || setsOf(g, "example-zone") != before {
		t.Errorf("a type added after the cache = %v, sets %s", err, setsOf(g, "example-zone"))
	}
	add("fresh.example.com.", "A", "203.0.113.9")
	if err := h.run("dns", "record", "delete", "example-zone", "fresh", "--yes"); err != nil || g.rrset("example-zone", "fresh.example.com.", "A") != nil {
		t.Errorf("a name added after the cache = %v, sets %s", err, setsOf(g, "example-zone"))
	}
}

// An empty --name ("$NAME" unset) names no record set, as leaving --name
// out does: a usage error in a script, never the apex.
func TestDNSRecordDeleteEmptyNameIsNoName(t *testing.T) {
	h, g := positionalHarness(t)
	before := setsOf(g, "example-zone")
	if err := h.run("dns", "record", "delete", "example-zone", "--name", "", "--type", "TXT", "--yes"); exitClass(err) != "usage" || !strings.Contains(err.Error(), "a record or --id <record-id> is required") {
		t.Errorf("empty --name = %v", err)
	}
	if after := setsOf(g, "example-zone"); after != before {
		t.Fatalf("wrote: %s", after)
	}
}
