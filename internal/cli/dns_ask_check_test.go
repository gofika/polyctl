package cli

import (
	"context"
	"strconv"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// On a terminal, a <type> given before its value is checked as soon as the
// platform is known, before the zone is read or the value asked: an unknown
// type is exit code 2, a type the platform cannot write exit code 7.
func TestDNSRecordTypeCheckedBeforeAsking(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.1"})
	fakeRecordTypes = []string{"A", "CNAME", "MX", "TXT", "SRV"}
	defer func() { fakeRecordTypes = nil }()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"dns", "add", "example.com", "www", "FOO"}, ExitUsage, "unknown record type"},
		{[]string{"dns", "add", "example.com", "www", "CAA"}, ExitNotSupported, "cannot write CAA records"},
		{[]string{"dns", "ensure", "example.com", "www", "FOO"}, ExitUsage, "unknown record type"},
		{[]string{"dns", "ensure", "example.com", "www", "CAA"}, ExitNotSupported, "cannot write CAA records"},
	} {
		fc.calls = nil
		p := &scriptedPicker{T: t}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), c.args...)
		if r.code != c.code || r.err == nil || !strings.Contains(r.err.Error(), c.want) || len(p.Asked) != 0 || fc.count("ListRecords") != 0 {
			t.Errorf("%v: exit %d, %v, prompts %v, calls %v", c.args, r.code, r.err, p.Titles(), fc.calls)
		}
	}
}

// On a terminal, a value is checked as the command checks it before it
// writes: a new MX record needs a priority, "@" is GoDaddy's form, and a
// priority is not given twice. A value the command would refuse is asked
// again instead of failing after the answers.
func TestDNSRecordValueAskedAgainWhenTheCommandWouldRefuseIt(t *testing.T) {
	for _, c := range []struct {
		args    []string
		answers []any
		want    string // the record created
	}{
		{[]string{"dns", "add", "example.com", "@", "MX"}, []any{"mail.example.com", "10 mail.example.com"}, "example.com MX mail.example.com 10"},
		{[]string{"dns", "add", "example.com", "cdn", "CNAME"}, []any{"@", "target.example.net"}, "cdn.example.com CNAME target.example.net"},
		{[]string{"dns", "add", "example.com", "@", "MX", "--priority", "20"}, []any{"10 mail.example.com", "mail.example.com"}, "example.com MX mail.example.com 20"},
		{[]string{"dns", "ensure", "example.com", "new", "MX"}, []any{"mx.example.net", "10 mx.example.net", ""}, "new.example.com MX mx.example.net 10"},
	} {
		_, cfgPath, fc := ensureZone(t)
		p := &scriptedPicker{T: t, Answers: c.answers}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), c.args...)
		var got []string
		for _, rec := range fc.records["z1"] {
			s := rec.Name + " " + rec.Type + " " + rec.Value
			if rec.Priority != nil {
				s += " " + strconv.Itoa(*rec.Priority)
			}
			got = append(got, s)
		}
		if r.err != nil || strings.Join(got, ",") != c.want {
			t.Errorf("%v: %v, records %q, prompts %v", c.args, r.err, got, p.Titles())
		}
		p.Done()
	}

	// dns ensure on a name whose MX record exists: the value alone keeps
	// its priority, and is not asked again.
	_, cfgPath, fc := ensureZone(t, wwwMX)
	p := &scriptedPicker{T: t, Answers: []any{"mx2.example.com", ""}}
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "www", "MX")
	if r.err != nil || ensureCalls(fc) != "UpdateRecord:m1" {
		t.Errorf("existing MX: %v, calls %v, prompts %v", r.err, fc.calls, p.Titles())
	}
	p.Done()

	// A priority no value can go with is the error at once, not a prompt
	// that refuses every answer.
	_, cfgPath, fc = ensureZone(t)
	p = &scriptedPicker{T: t}
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "add", "example.com", "@", "TXT", "--priority", "5")
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "MX records only") || len(p.Asked) != 0 || fc.count("ListRecords") != 0 {
		t.Errorf("priority of TXT: exit %d, %v, prompts %v, calls %v", r.code, r.err, p.Titles(), fc.calls)
	}
}

// dns ensure on a terminal checks each value of a set as the command will
// write it: one value against the one MX record of the name updates it and
// keeps its priority, but a set of several values creates every value the
// zone lacks, which then needs a priority. A value that would make the set
// fail is asked again instead of failing after the answers.
func TestDNSEnsureSetValuesCheckedAsTheSetIsWritten(t *testing.T) {
	another := "input:Another value of the MX record (empty to finish)"
	for _, c := range []struct {
		answers []any
		asked   int // the questions for another value
		calls   string
	}{
		// mx3 would make mx2 a created record without a priority: refused,
		// and finishing keeps the update of the one record.
		{[]any{"mx2.example.com", "mx3.example.com", ""}, 2, "UpdateRecord:m1"},
		{[]any{"mx2.example.com", "20 mx3.example.com", ""}, 2, "UpdateRecord:m1"},
		// Every value with its priority: both created.
		{[]any{"10 mx2.example.com", "mx3.example.com", "20 mx3.example.com", ""}, 3, "CreateRecord:www.example.com:MX,CreateRecord:www.example.com:MX"},
		// A value the zone has is kept without a priority.
		{[]any{"mail.example.com", "20 mx3.example.com", ""}, 2, "CreateRecord:www.example.com:MX"},
	} {
		_, cfgPath, fc := ensureZone(t, wwwMX)
		p := &scriptedPicker{T: t, Answers: c.answers}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "www", "MX")
		n := 0
		for _, title := range p.Titles() {
			if title == another {
				n++
			}
		}
		if r.err != nil || n != c.asked || ensureCalls(fc) != c.calls {
			t.Errorf("%v: %v, prompts %v, calls %v", c.answers, r.err, p.Titles(), fc.calls)
		}
		p.Done()
	}

	// A value repeated is asked again, as the command refuses a repeat.
	_, cfgPath, fc := ensureZone(t)
	p := &scriptedPicker{T: t, Answers: []any{"token-1", "token-1", "token-2", ""}}
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "_acme", "TXT")
	if r.err != nil || ensureCalls(fc) != "CreateRecord:_acme.example.com:TXT,CreateRecord:_acme.example.com:TXT" || len(p.Titles()) != 4 {
		t.Errorf("repeated value: %v, prompts %v, calls %v", r.err, p.Titles(), fc.calls)
	}
	p.Done()
}
