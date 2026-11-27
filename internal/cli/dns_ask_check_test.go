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
