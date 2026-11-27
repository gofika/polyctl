package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// mixedRecords is a zone where www has two A records, mail records of two
// types, one has a single record, and the apex its NS, SOA and one TXT.
func mixedRecords() []platform.Record {
	return []platform.Record{
		{ID: "a1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "192.0.2.1", TTL: 300},
		{ID: "a2", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "192.0.2.2", TTL: 300},
		{ID: "m1", ZoneID: "z1", Name: "mail.example.com", Type: "A", Value: "192.0.2.3", TTL: 300},
		{ID: "m2", ZoneID: "z1", Name: "mail.example.com", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
		{ID: "m3", ZoneID: "z1", Name: "mail.example.com", Type: "TXT", Value: "other", TTL: 300},
		{ID: "o1", ZoneID: "z1", Name: "one.example.com", Type: "CNAME", Value: "target.example.net", TTL: 300},
		{ID: "ns", ZoneID: "z1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
		{ID: "soa", ZoneID: "z1", Name: "example.com", Type: "SOA", Value: "x"},
		{ID: "t1", ZoneID: "z1", Name: "example.com", Type: "TXT", Value: "apex", TTL: 300},
	}
}

func recordIDs(recs []platform.Record) string {
	ids := make([]string, len(recs))
	for i, r := range recs {
		ids[i] = r.ID
	}
	return strings.Join(ids, " ")
}

// A name whose records have one type needs no <type>: the command goes on
// as if the type had been given, in both forms.
func TestDNSDeleteByNameOfOneType(t *testing.T) {
	for _, args := range [][]string{
		{"dns", "delete", "example.com", "one"},
		{"dns", "delete", "example.com", "--name", "one"},
	} {
		_, cfgPath, fc := ensureZone(t, mixedRecords()...)
		code, _, stderr := mainRun(cfgPath, args...)
		if code != ExitOK || fc.count("DeleteRecord:o1") != 1 || writes(fc) != 1 {
			t.Errorf("%v: exit %d, calls %v (%s)", args, code, fc.calls, stderr)
		}
	}
	// The apex: its SOA and NS records are never meant by the name alone.
	_, cfgPath, fc := ensureZone(t, mixedRecords()...)
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "@"); code != ExitOK || fc.count("DeleteRecord:t1") != 1 || writes(fc) != 1 {
		t.Errorf("delete @: exit %d, calls %v (%s)", code, fc.calls, stderr)
	}
	// A value without a type selects among the records of the name.
	_, cfgPath, fc = ensureZone(t, mixedRecords()...)
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "--name", "mail", "--value", "other"); code != ExitOK || fc.count("DeleteRecord:m3") != 1 || writes(fc) != 1 {
		t.Errorf("delete --name mail --value other: exit %d, calls %v (%s)", code, fc.calls, stderr)
	}
	// No record of the name is not found.
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "nope"); code != ExitNotFound || !strings.Contains(stderr, "no matching record in zone example.com") {
		t.Errorf("delete nope: exit %d (%s)", code, stderr)
	}
}

// Several records of the one type of a name are confirmed like those of a
// name and type: listed with their ids, with the way to delete one only.
func TestDNSDeleteByNameConfirmsSeveralRecords(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, mixedRecords()...)
	const hint = "to delete one of them only, give its <value> after the <type>, or its id with --id <id>"
	// Non-interactive: --yes is required, and the refusal lists the records.
	code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "www")
	if code != ExitUsage || writes(fc) != 0 || !strings.Contains(stderr, "pass --yes to proceed (would delete 2 records in zone example.com)") {
		t.Fatalf("without --yes: exit %d, calls %v (%s)", code, fc.calls, stderr)
	}
	for _, want := range []string{"a1", "a2", "192.0.2.1", "192.0.2.2", "2 records match; " + hint} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal lacks %q: %s", want, stderr)
		}
	}
	// On a terminal a no deletes nothing, is exit code 0 and repeats the hint.
	r := runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t}, strings.NewReader("n\n"), "dns", "delete", "example.com", "www")
	if r.code != ExitOK || writes(fc) != 0 || r.err == nil || r.err.Error() != "nothing to do: no record was deleted; "+hint {
		t.Errorf("answer no: exit %d, %v, calls %v", r.code, r.err, fc.calls)
	}
	if !strings.Contains(r.stderr, "2 records match; "+hint) || !strings.Contains(r.stderr, "delete 2 records in zone example.com (y/N)") {
		t.Errorf("question: %q", r.stderr)
	}
	// --dry-run reports both and asks nothing.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t}, strings.NewReader(""), "dns", "delete", "example.com", "www", "--dry-run")
	if r.err != nil || writes(fc) != 0 || strings.Contains(r.stderr, "(y/N)") || strings.Count(r.stderr, "dry run: would delete") != 2 {
		t.Errorf("dry run: %v, calls %v, stderr %q", r.err, fc.calls, r.stderr)
	}
	// A yes, and --yes, delete both.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t}, strings.NewReader("y\n"), "dns", "delete", "example.com", "www")
	if r.err != nil || fc.count("DeleteRecord:a1") != 1 || fc.count("DeleteRecord:a2") != 1 || writes(fc) != 2 {
		t.Errorf("answer yes: %v, calls %v", r.err, fc.calls)
	}
	_, cfgPath, fc = ensureZone(t, mixedRecords()...)
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "www", "--yes"); code != ExitOK || writes(fc) != 2 || strings.Contains(stderr, "records match") {
		t.Errorf("--yes: exit %d, calls %v (%s)", code, fc.calls, stderr)
	}
}

// A name with records of several types is never deleted as a whole where
// nothing can be asked: exit code 5 that names the types, also with --yes.
func TestDNSDeleteByNameOfSeveralTypesIsAmbiguous(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, mixedRecords()...)
	for _, args := range [][]string{
		{"dns", "delete", "example.com", "mail"},
		{"dns", "delete", "example.com", "mail", "--yes"},
		{"dns", "delete", "example.com", "--name", "mail", "--yes"},
		{"dns", "delete", "example.com", "mail", "--dry-run"},
	} {
		code, stdout, stderr := mainRun(cfgPath, args...)
		want := "mail.example.com has records of 2 types in zone example.com (A, TXT); give <type> to say which"
		if args[3] == "--name" {
			want = strings.Replace(want, "<type>", "--type", 1)
		}
		if code != ExitAmbiguous || writes(fc) != 0 || stdout != "" || !strings.Contains(stderr, want) {
			t.Errorf("%v: exit %d, calls %v, stdout %q, stderr %q", args, code, fc.calls, stdout, stderr)
		}
	}
	// With the type the same name is deleted.
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "mail", "A"); code != ExitOK || fc.count("DeleteRecord:m1") != 1 || writes(fc) != 1 {
		t.Errorf("delete mail A: exit %d, calls %v (%s)", code, fc.calls, stderr)
	}
}

// On a terminal the records of a name of several types are listed to tick.
func TestDNSDeleteByNameOfSeveralTypesOffersTheRecords(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, mixedRecords()...)
	const title = "Delete which records of mail.example.com?"
	p := prompttest.New(t, []string{"m2"})
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "delete", "example.com", "mail")
	if r.err != nil || fc.count("DeleteRecord:m2") != 1 || writes(fc) != 1 {
		t.Fatalf("tick one: %v, calls %v (%s)", r.err, fc.calls, r.stderr)
	}
	a := p.Find(title)
	if prompttest.Values(a.Options) != "m1 m2 m3" || len(a.Preset) != 0 {
		t.Errorf("options %+v, ticked %v", a.Options, a.Preset)
	}
	if l := a.Options[1].Label; l != "mail.example.com  TXT  v=spf1 -all  ttl 300  -  -  m2" {
		t.Errorf("label %q, want type, value, ttl and id", l)
	}
	if !strings.Contains(r.stderr, "mail.example.com has records of 2 types (A, TXT)") {
		t.Errorf("stderr %q", r.stderr)
	}
	p.Done()
	// Nothing ticked is a cancel: exit code 0, nothing deleted.
	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t, []string{}), strings.NewReader(""), "dns", "delete", "example.com", "mail")
	if r.code != ExitOK || writes(fc) != 1 {
		t.Errorf("nothing ticked: exit %d, %v, calls %v", r.code, r.err, fc.calls)
	}
	// Several ticked are confirmed; they were chosen one by one, so no hint
	// on how to choose is added.
	p = prompttest.New(t, []string{"m1", "m3"})
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader("y\n"), "dns", "delete", "example.com", "--name", "mail")
	if r.err != nil || writes(fc) != 3 || recordIDs(fc.records["z1"]) != "a1 a2 o1 ns soa t1" {
		t.Errorf("tick two: %v, records %s (%s)", r.err, recordIDs(fc.records["z1"]), r.stderr)
	}
	if !strings.Contains(r.stderr, "delete 2 records in zone example.com (y/N)") || strings.Contains(r.stderr, "records match") {
		t.Errorf("confirmation of ticked records: %q", r.stderr)
	}
	p.Done()
}

// A missing <domain> or <zone> is named as what is missing, also when --id
// or --all names the records.
func TestRecordTargetMissingZoneNamed(t *testing.T) {
	_, cfgPath, fc := ensureZone(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"dns", "delete", "--all", "--yes"}, "<domain> is required: usage: polyctl dns delete <domain> <name>"},
		{[]string{"dns", "delete", "--id", "abc", "--yes"}, "<domain> is required: usage: polyctl dns delete <domain> <name>"},
		{[]string{"cloudflare", "dns", "update", "--id", "abc", "--value", "192.0.2.1"}, "<zone> is required: usage: polyctl cloudflare dns update <zone> <name>"},
		{[]string{"dns", "delete", "example.com", "--yes"}, "a record, --id <record-id> or --all is required"},
	} {
		_, _, err := run(t, cfgPath, c.args...)
		if ExitCodeFor(err) != ExitUsage || !strings.Contains(err.Error(), c.want) || len(fc.calls) != 0 {
			t.Errorf("%v: exit %d, %v, calls %v", c.args, ExitCodeFor(err), err, fc.calls)
		}
	}
}

// An empty former --name ("$NAME" unset) is what leaving it out is: the
// records of <domain> itself, never the zone apex.
func TestDNSDeleteEmptyFormerNameIsTheDomain(t *testing.T) {
	recs := []platform.Record{
		{ID: "acme", ZoneID: "z1", Name: "_acme-challenge.www.example.com", Type: "TXT", Value: "tok", TTL: 300},
		{ID: "spf", ZoneID: "z1", Name: "example.com", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
	}
	for _, extra := range [][]string{{"--type", "TXT", "--yes"}, nil} {
		_, cfgPath, fc := ensureZone(t, recs...)
		args := append([]string{"dns", "delete", "_acme-challenge.www.example.com", "--name", ""}, extra...)
		if code, _, stderr := mainRun(cfgPath, args...); code != ExitOK || ensureCalls(fc) != "DeleteRecord:acme" {
			t.Errorf("%v: exit %d, calls %v (%s)", args, code, fc.calls, stderr)
		}
	}
}
