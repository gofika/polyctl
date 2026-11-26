package app_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

func plainRT() (*app.Runtime, *bytes.Buffer) {
	var errb bytes.Buffer
	return app.New(app.Flags{Yes: true}, strings.NewReader(""), &bytes.Buffer{}, &errb), &errb
}

// SelectRecords without a terminal: an id or a name that settles the
// records selects them, and what is open is exit code 5 or 4.
func TestSelectRecordsNonInteractive(t *testing.T) {
	recs := append(selectRecords(), platform.Record{ID: "www", Name: "id.example.com", Type: "A", Value: "192.0.2.7"},
		platform.Record{ID: "deadbeef", Name: "x.example.com", Type: "A", Value: "192.0.2.8"})
	fq := func(n string) string { return platform.FQDN(n, "example.com") }
	for _, c := range []struct {
		what string
		sel  app.RecordSelect
		ids  string
		byID bool
		is   error
		msg  string
	}{
		{"name, one type, delete", app.RecordSelect{Name: fq("x")}, "deadbeef", false, nil, ""},
		{"name and type, delete: all of them", app.RecordSelect{Name: fq("www"), Type: "a"}, "a1 a2", false, nil, ""},
		{"name, several types, delete", app.RecordSelect{Name: fq("mail")}, "", false, platform.ErrAmbiguous, "mail.example.com has records of 2 types in zone example.com (A, TXT); give <type>"},
		{"value narrows", app.RecordSelect{Name: fq("www"), Type: "A", Value: "192.0.2.2", One: true}, "a2", false, nil, ""},
		{"several, update", app.RecordSelect{Name: fq("www"), Type: "A", One: true}, "", false, platform.ErrAmbiguous,
			"2 A records of www.example.com match in zone example.com; give its <value> after the <type>, or its id with --id <id> to say which (nothing was changed)"},
		{"several types, update", app.RecordSelect{Name: fq("mail"), One: true}, "", false, platform.ErrAmbiguous,
			"mail.example.com has 2 records in zone example.com; give its <type>, or its <value> after the <type>, or its id with --id <id> to say which"},
		{"--id", app.RecordSelect{ID: "m1"}, "m1", true, nil, ""},
		{"--id wins over a name that exists", app.RecordSelect{ID: "www"}, "www", true, nil, ""},
		{"--id unknown", app.RecordSelect{ID: "nope"}, "", false, platform.ErrNotFound, "no record with the id nope in zone example.com"},
		{"former form: an id", app.RecordSelect{IDOrName: "deadbeef", Name: fq("deadbeef")}, "deadbeef", true, nil, ""},
		{"former form: a name", app.RecordSelect{IDOrName: "x", Name: fq("x")}, "deadbeef", false, nil, ""},
		{"former form: both an id and a name", app.RecordSelect{IDOrName: "www", Name: fq("www")}, "", false, platform.ErrAmbiguous,
			"www is the id of a record and the name of 2 record(s) in zone example.com; pass --id www for the record with that id, or the full name www.example.com for the records of the name"},
		{"former form: neither", app.RecordSelect{IDOrName: "nope", Name: fq("nope")}, "", false, platform.ErrNotFound, "no record with the name or the id nope in zone example.com"},
		{"no name", app.RecordSelect{Name: fq("nope")}, "", false, platform.ErrNotFound, "no matching record in zone example.com"},
		{"nothing given", app.RecordSelect{}, "", false, app.ErrUsage, "a record is required"},
	} {
		rt, errb := plainRT()
		c.sel.Zone, c.sel.Records, c.sel.Verb = "example.com", recs, "Delete"
		got, err := rt.SelectRecords(c.sel)
		if c.is == nil {
			if err != nil || ids(got.Records) != c.ids || got.ByID != c.byID || got.Listed {
				t.Errorf("%s: %s (by id %v, listed %v), %v", c.what, ids(got.Records), got.ByID, got.Listed, err)
			}
			continue
		}
		if !errors.Is(err, c.is) || !strings.Contains(err.Error(), c.msg) {
			t.Errorf("%s: %v", c.what, err)
		}
		// The candidates of an update that matches several are listed.
		if c.sel.One && c.is == platform.ErrAmbiguous && !strings.Contains(errb.String(), "192.0.2.") {
			t.Errorf("%s: candidates not listed: %q", c.what, errb.String())
		}
	}
	// An id with several spellings can name several records.
	rt, _ := plainRT()
	_, err := rt.SelectRecords(app.RecordSelect{Zone: "example.com", Records: recs, ID: "old",
		IDMatches: func(id string, r platform.Record) bool { return strings.HasPrefix(r.ID, "a") }})
	if !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), `record id "old" matches 2 records in zone example.com (a1, a2)`) {
		t.Errorf("id of several records: %v", err)
	}
}

// On a terminal what is open is a list: of the zone without a name, of the
// name with several types, one record for an update and any number for a
// delete.
func TestSelectRecordsLists(t *testing.T) {
	recs := selectRecords()
	base := app.RecordSelect{Zone: "example.com", Records: recs, Verb: "Delete"}

	// Delete without a name: the records of the zone, as Offer keeps them.
	rt, p := interactiveRT(t, []string{"a1", "t1"})
	sel := base
	sel.Offer = func(in []platform.Record) []platform.Record {
		var out []platform.Record
		for _, r := range in {
			if r.Type != "NS" && r.Type != "SOA" {
				out = append(out, r)
			}
		}
		return out
	}
	got, err := rt.SelectRecords(sel)
	if err != nil || ids(got.Records) != "a1 t1" || !got.Listed {
		t.Fatalf("zone list: %s, %v", ids(got.Records), err)
	}
	if a := p.Find("Delete which records of example.com?"); a == nil || prompttest.Values(a.Options) != "a1 a2 m1 m2 t1" {
		t.Errorf("zone list options: %+v", a)
	}
	p.Done()

	// Delete, a name with several types: its records to tick.
	rt, p = interactiveRT(t, []string{"m2"})
	sel = base
	sel.Name = "mail.example.com"
	if got, err = rt.SelectRecords(sel); err != nil || ids(got.Records) != "m2" || !got.Listed {
		t.Fatalf("name list: %s, %v", ids(got.Records), err)
	}
	if a := p.Find("Delete which records of mail.example.com?"); a == nil || prompttest.Values(a.Options) != "m1 m2" {
		t.Errorf("name list options: %+v", a)
	}
	p.Done()

	// Update: several records of one type are a list to choose one from,
	// never all of them.
	rt, p = interactiveRT(t, "a2")
	sel = app.RecordSelect{Zone: "example.com", Records: recs, Verb: "Update", One: true, Name: "www.example.com"}
	if got, err = rt.SelectRecords(sel); err != nil || ids(got.Records) != "a2" || !got.Listed {
		t.Fatalf("update list: %s, %v", ids(got.Records), err)
	}
	if a := p.Find("Update which record of www.example.com?"); a == nil || prompttest.Values(a.Options) != "a1 a2" {
		t.Errorf("update list options: %+v", a)
	}
	p.Done()

	// Update with only the zone: one record of the zone, of the type when
	// that is all that was given.
	rt, p = interactiveRT(t, "m1")
	sel = app.RecordSelect{Zone: "example.com", Records: recs, Verb: "Update", One: true, Type: "txt"}
	if got, err = rt.SelectRecords(sel); err != nil || ids(got.Records) != "m1" {
		t.Fatalf("update zone list: %s, %v", ids(got.Records), err)
	}
	if a := p.Find("Update which record of example.com?"); a == nil || prompttest.Values(a.Options) != "m1 t1" {
		t.Errorf("update zone list options: %+v", a)
	}
	p.Done()

	// List replaces the list of the command.
	rt, p = interactiveRT(t)
	sel = base
	sel.Name = "mail.example.com"
	var of string
	sel.List = func(o string, in []platform.Record) ([]platform.Record, error) { of = o; return in[:1], nil }
	if got, err = rt.SelectRecords(sel); err != nil || ids(got.Records) != "m1" || of != "mail.example.com" {
		t.Errorf("List hook: %s of %q, %v", ids(got.Records), of, err)
	}
	p.Done()
}

// A qualifier of the platform (the line of a record) narrows the selection
// when it is given, and is named as a way to say which record is meant only
// when the candidates differ in it.
func TestSelectRecordsQualifier(t *testing.T) {
	line := func(r platform.Record) string { s, _ := r.Extra["line"].(string); return s }
	on := func(id, name, value, l string) platform.Record {
		return platform.Record{ID: id, Name: name + ".example.com", Type: "A", Value: value, Extra: map[string]any{"line": l}}
	}
	recs := []platform.Record{
		on("d1", "www", "192.0.2.1", "default"), on("t1", "www", "192.0.2.1", "telecom"),
		on("s1", "same", "192.0.2.1", "default"), on("s2", "same", "192.0.2.2", "default"),
	}
	sel := func(name, given string, one bool) app.RecordSelect {
		return app.RecordSelect{Zone: "example.com", Records: recs, Name: name + ".example.com", One: one, Verb: "Update",
			Qualifiers: []app.RecordQualifier{{Flag: "--line", Noun: "line", Value: given, Of: line}}}
	}
	rt, _ := plainRT()
	if got, err := rt.SelectRecords(sel("www", "Telecom", true)); err != nil || ids(got.Records) != "t1" {
		t.Errorf("line given: %s, %v", ids(got.Records), err)
	}
	if _, err := rt.SelectRecords(sel("www", "unicom", true)); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("a line without a record = %v", err)
	}
	_, err := rt.SelectRecords(sel("www", "", true))
	if !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "give its <value> after the <type>, or its line with --line, or its id with --id <id>") {
		t.Errorf("records that differ in the line = %v", err)
	}
	if _, err := rt.SelectRecords(sel("same", "", true)); !errors.Is(err, platform.ErrAmbiguous) || strings.Contains(err.Error(), "--line") {
		t.Errorf("records of one line = %v", err)
	}
	// A delete takes every record of the name; the hint of its confirmation
	// names the line when the records differ in it.
	s := sel("www", "", false)
	got, err := rt.SelectRecords(s)
	if err != nil || ids(got.Records) != "d1 t1" || s.Exact(got) != "give its <value> after the <type>, or its line with --line, or its id with --id <id>" {
		t.Errorf("delete: %s, %q, %v", ids(got.Records), s.Exact(got), err)
	}
	s = sel("same", "", false)
	if got, _ := rt.SelectRecords(s); s.Exact(got) != "give its <value> after the <type>, or its id with --id <id>" {
		t.Errorf("delete, one line: %q", s.Exact(got))
	}
	if s.Exact(app.RecordSelection{Records: recs[:2], Listed: true}) != "" {
		t.Error("records ticked in a list need no hint")
	}
}
