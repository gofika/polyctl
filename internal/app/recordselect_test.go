package app_test

import (
	"bytes"
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

func selectRecords() []platform.Record {
	return []platform.Record{
		{ID: "a1", Name: "www.example.com", Type: "A", Value: "192.0.2.1", TTL: 300},
		{ID: "a2", Name: "www.example.com", Type: "a", Value: "192.0.2.2", TTL: 300},
		{ID: "m1", Name: "mail.example.com", Type: "TXT", Value: "x"},
		{ID: "m2", Name: "mail.example.com", Type: "A", Value: "192.0.2.3"},
		{ID: "ns", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
		{ID: "soa", Name: "example.com", Type: "SOA", Value: "x"},
		{ID: "t1", Name: "example.com", Type: "TXT", Value: "apex"},
	}
}

func ids(recs []platform.Record) string {
	out := make([]string, len(recs))
	for i, r := range recs {
		out[i] = r.ID
	}
	return strings.Join(out, " ")
}

// RecordsOfName tells one type from several, and never means the SOA and
// NS records of the apex by the name alone.
func TestRecordsOfName(t *testing.T) {
	recs := selectRecords()
	for _, c := range []struct {
		name, typ, value string
		ids, types, one  string
	}{
		{"www.example.com", "", "", "a1 a2", "A", "A"},
		{"WWW.example.com.", "", "192.0.2.2", "a2", "A", "A"},
		{"mail.example.com", "", "", "m1 m2", "A TXT", ""},
		{"mail.example.com", "txt", "", "m1", "TXT", "TXT"},
		{"example.com", "", "", "t1", "TXT", "TXT"},
		{"example.com", "NS", "", "ns", "NS", "NS"},
	} {
		n, err := app.RecordsOfName("example.com", recs, c.name, c.typ, c.value)
		if err != nil || ids(n.Records) != c.ids || strings.Join(n.Types, " ") != c.types || n.Type() != c.one {
			t.Errorf("%s %q %q: records %s, types %v, one %q, %v", c.name, c.typ, c.value, ids(n.Records), n.Types, n.Type(), err)
		}
	}
	if _, err := app.RecordsOfName("example.com", recs, "nope.example.com", "", ""); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "no matching record in zone example.com") {
		t.Errorf("no record: %v", err)
	}
}

// NeedsType: one type is settled; several are exit code 5 where nothing
// can be asked, also with --yes, and open for a list on a terminal.
func TestNeedsType(t *testing.T) {
	recs := selectRecords()
	one, _ := app.RecordsOfName("example.com", recs, "www.example.com", "", "")
	several, _ := app.RecordsOfName("example.com", recs, "mail.example.com", "", "")

	rt := app.New(app.Flags{Yes: true}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if open, err := rt.NeedsType(one, "<type>"); open || err != nil {
		t.Errorf("one type: %v, %v", open, err)
	}
	open, err := rt.NeedsType(several, "<type>")
	if open || !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "mail.example.com has records of 2 types in zone example.com (A, TXT); give <type> to say which") {
		t.Errorf("several types, non-interactive: %v, %v", open, err)
	}
	irt, _ := interactiveRT(t)
	if open, err := irt.NeedsType(several, "--type"); !open || err != nil {
		t.Errorf("several types, interactive: %v, %v", open, err)
	}
}

// PickRecords offers the records with their ids, nothing ticked; ticking
// none is nothing to do.
func TestPickRecords(t *testing.T) {
	recs := append(selectRecords()[:2], platform.Record{Name: "noid.example.com", Type: "A", Value: "192.0.2.9"})
	rt, p := interactiveRT(t, []string{"a2"})
	got, err := rt.PickRecords("Delete which?", "record", recs, func(r platform.Record) string {
		if r.ID == "a1" {
			return "bucket b"
		}
		return ""
	})
	if err != nil || ids(got) != "a2" {
		t.Fatalf("pick = %s, %v", ids(got), err)
	}
	a := p.Find("Delete which?")
	if l := prompttest.Labels(a.Options); l != "www.example.com  A  192.0.2.1  ttl 300  -  [bucket b]  a1\nwww.example.com  a  192.0.2.2  ttl 300  -  -  a2" || len(a.Preset) != 0 {
		t.Errorf("labels:\n%s\npreset %v", l, a.Preset)
	}
	p.Done()
	rt, _ = interactiveRT(t, []string{})
	if _, err := rt.PickRecords("Delete which?", "record", recs, nil); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("nothing ticked: %v", err)
	}
}

// ConfirmRecordDelete lists the records, says how many there are and how
// to delete one only, and turns a no into "nothing to do" with that hint.
func TestConfirmRecordDelete(t *testing.T) {
	grid := output.Grid{Headers: []string{"NAME", "ID"}, Rows: [][]string{{"www.example.com", "a1"}, {"www.example.com", "a2"}}}
	d := app.RecordDelete{Records: grid, Question: "delete 2 records in zone example.com", Exact: "give its <value>"}
	newRT := func(flags app.Flags, stdin string) (*app.Runtime, *bytes.Buffer) {
		var errb bytes.Buffer
		rt := app.New(flags, strings.NewReader(stdin), &bytes.Buffer{}, &errb)
		return rt, &errb
	}
	// --yes: nothing shown, nothing asked.
	rt, errb := newRT(app.Flags{Yes: true}, "")
	if err := rt.ConfirmRecordDelete(context.Background(), d); err != nil || errb.Len() != 0 {
		t.Errorf("--yes: %v, %q", err, errb.String())
	}
	// Non-interactive without --yes: the list, then the refusal.
	rt, errb = newRT(app.Flags{}, "y\n")
	err := rt.ConfirmRecordDelete(context.Background(), d)
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "pass --yes to proceed (would delete 2 records in zone example.com)") {
		t.Errorf("non-interactive: %v", err)
	}
	if s := errb.String(); !strings.Contains(s, "a1") || !strings.Contains(s, "a2") || !strings.Contains(s, "2 records match; to delete one of them only, give its <value>") {
		t.Errorf("non-interactive stderr %q", s)
	}
	// Interactive: no is nothing to do with the hint, yes goes on.
	for answer, want := range map[string]string{"n\n": "nothing to do: no record was deleted; to delete one of them only, give its <value>", "y\n": ""} {
		rt, errb = newRT(app.Flags{}, answer)
		rt.Picker = prompttest.New(t)
		t.Setenv(app.EnvNonInteractive, "")
		err := rt.ConfirmRecordDelete(context.Background(), d)
		if (want == "") != (err == nil) || (err != nil && (!errors.Is(err, platform.ErrNothingToDo) || err.Error() != want)) {
			t.Errorf("answer %q: %v", answer, err)
		}
		if !strings.Contains(errb.String(), "delete 2 records in zone example.com (y/N)") {
			t.Errorf("answer %q: stderr %q", answer, errb.String())
		}
	}
	// A command without a way to delete one record adds no hint.
	rt, errb = newRT(app.Flags{}, "n\n")
	rt.Picker = prompttest.New(t)
	d.Exact = ""
	if err := rt.ConfirmRecordDelete(context.Background(), d); err == nil || err.Error() != "nothing to do: no record was deleted" || strings.Contains(errb.String(), "records match") {
		t.Errorf("no hint: %v, %q", err, errb.String())
	}
}

// ExactRecordHint names the ways a command has to delete one record, in the
// form the command was called in.
func TestExactRecordHint(t *testing.T) {
	for _, c := range []struct {
		typeArg     string
		value, byID bool
		want        string
	}{
		{"<type>", true, true, "give its <value> after the <type>, or its id with --id <id>"},
		{"--type", true, true, "give its value with --value, or its id with --id <id>"},
		{"<type>", false, true, "give its id with --id <id>"},
		{"--type", true, false, "give its value with --value"},
		{"<type>", false, false, ""},
	} {
		if got := app.ExactRecordHint(c.typeArg, c.value, c.byID); got != c.want {
			t.Errorf("ExactRecordHint(%q, %v, %v) = %q, want %q", c.typeArg, c.value, c.byID, got, c.want)
		}
	}
}

// The refusal of the non-interactive flow names Refusal when a command
// gives one, after the list; the question stays the Question.
func TestConfirmRecordDeleteRefusal(t *testing.T) {
	var errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &errb)
	err := rt.ConfirmRecordDelete(context.Background(), app.RecordDelete{
		Records:  output.Grid{Headers: []string{"NAME", "ID"}, Rows: [][]string{{"www.example.com", "a1"}}},
		Question: "Delete the A record set of www.example.com (1 value(s))?",
		Refusal:  "delete the A record set of www.example.com",
	})
	if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "pass --yes to proceed (would delete the A record set of www.example.com)") || !strings.Contains(errb.String(), "a1") {
		t.Errorf("refusal = %v, stderr %q", err, errb.String())
	}
}
