package aliyun

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// targetZone is the alidns fake of the record update and delete tests: the
// records of example.com, and what was sent to change them.
type targetZone struct {
	recs    []map[string]any
	updated []string
}

// targetHarness is a harness whose zone example.com holds two A records of
// www on the default line (w1, w2), one A record of geo on the default and
// one on the telecom line with the same value (g1, g2), an A and a TXT
// record of mail (m1, m2) and one A record of api (p1).
func targetHarness(t *testing.T, flags app.Flags) (*harness, *targetZone) {
	t.Helper()
	t.Setenv(app.EnvNonInteractive, "")
	h := newHarness(t, flags)
	z := &targetZone{}
	add := func(id, rr, typ, value, line string) {
		z.recs = append(z.recs, map[string]any{"RecordId": id, "RR": rr, "Type": typ, "Value": value, "TTL": 600, "Line": line, "DomainName": "example.com"})
	}
	add("w1", "www", "A", "203.0.113.1", "default")
	add("w2", "www", "A", "203.0.113.2", "default")
	add("g1", "geo", "A", "203.0.113.5", "default")
	add("g2", "geo", "A", "203.0.113.5", "telecom")
	add("m1", "mail", "A", "203.0.113.3", "default")
	add("m2", "mail", "TXT", "v=spf1 -all", "default")
	add("p1", "api", "A", "203.0.113.4", "default")
	h.api.on("DescribeDomainRecords", func(q url.Values) (int, any) {
		return 200, map[string]any{"TotalCount": len(z.recs), "DomainRecords": map[string]any{"Record": z.recs}}
	})
	h.api.on("DeleteDomainRecord", func(q url.Values) (int, any) {
		for i, r := range z.recs {
			if r["RecordId"] == q.Get("RecordId") {
				z.recs = append(z.recs[:i:i], z.recs[i+1:]...)
				return 200, map[string]any{"RecordId": q.Get("RecordId")}
			}
		}
		return 400, apiErr("DomainRecordNotBelongToUser", "no such record")
	})
	h.api.on("UpdateDomainRecord", func(q url.Values) (int, any) {
		var f []string
		for _, k := range []string{"RecordId", "RR", "Type", "Value", "TTL", "Line"} {
			f = append(f, q.Get(k))
		}
		z.updated = append(z.updated, strings.Join(f, " "))
		return 200, map[string]any{"RecordId": q.Get("RecordId")}
	})
	return h, z
}

func (z *targetZone) ids() string {
	var ids []string
	for _, r := range z.recs {
		ids = append(ids, r["RecordId"].(string))
	}
	return strings.Join(ids, " ")
}

// dns record delete finds its records by name; <type>, <value>, --line and
// --id only tell records apart, and the former <domain> <record-id> still
// works.
func TestDNSRecordDeleteByName(t *testing.T) {
	const all = "w1 w2 g1 g2 m1 m2 p1"
	for _, c := range []struct {
		what string
		args []string
		is   error
		left string
		msg  string
	}{
		{"a name with one record", []string{"api"}, nil, "w1 w2 g1 g2 m1 m2", "deleted api.example.com A 203.0.113.4 via aliyun/ali"},
		{"several records need --yes", []string{"www"}, app.ErrUsage, all, "2 records match; to delete one of them only, give its <value> after the <type>, or its id with --id <id>"},
		{"several records with --yes", []string{"www", "--yes"}, nil, "g1 g2 m1 m2 p1", ""},
		{"records that differ in the line: the hint names it", []string{"geo"}, app.ErrUsage, all, "give its <value> after the <type>, or its line with --line, or its id with --id <id>"},
		{"the line tells them apart", []string{"geo", "--line", "telecom"}, nil, "w1 w2 g1 m1 m2 p1", "deleted geo.example.com A 203.0.113.5"},
		{"a line without a record", []string{"geo", "--line", "unicom"}, platform.ErrNotFound, all, "no matching record"},
		{"several types are never deleted by the name", []string{"mail", "--yes"}, platform.ErrAmbiguous, all, "mail.example.com has records of 2 types in zone example.com (A, TXT); give <type>"},
		{"the type tells them apart", []string{"mail", "txt"}, nil, "w1 w2 g1 g2 m1 p1", ""},
		{"the value tells them apart", []string{"www", "A", "203.0.113.2"}, nil, "w1 g1 g2 m1 m2 p1", ""},
		{"--id", []string{"--id", "g2"}, nil, "w1 w2 g1 m1 m2 p1", ""},
		{"the former form", []string{"m2"}, nil, "w1 w2 g1 g2 m1 p1", "deleted mail.example.com TXT"},
		{"no such name or id", []string{"nope"}, platform.ErrNotFound, all, "no record with the name or the id nope in zone example.com"},
		{"--id beside a record", []string{"www", "--id", "w1"}, app.ErrUsage, all, "--id selects one record"},
		{"--id beside --line", []string{"--id", "g2", "--line", "telecom"}, app.ErrUsage, all, "--id selects one record; it cannot be combined with --line"},
		{"only the domain", nil, app.ErrUsage, all, "a record or --id <record-id> is required: usage: aliyun dns record delete <domain> <name> [<type> [<value>]]"},
		{"the former form beside a line the record is not on", []string{"g1", "--line", "telecom"}, platform.ErrNotFound, all, "the record with the id g1 in zone example.com has the line default, not telecom (--line)"},
		{"the former form beside the line of the record", []string{"g2", "--line", "telecom"}, nil, "w1 w2 g1 m1 m2 p1", "deleted geo.example.com A 203.0.113.5"},
		{"an empty --id", []string{"--id", ""}, app.ErrUsage, all, "--id must not be empty"},
	} {
		h, z := targetHarness(t, app.Flags{NonInteractive: true})
		args := append([]string{"dns", "record", "delete", "example.com"}, c.args...)
		for i, a := range args {
			if a == "--yes" {
				h.rt.Flags.Yes, args = true, append(args[:i:i], args[i+1:]...)
				break
			}
		}
		err := h.run(args...)
		text := h.stderr.String()
		if err != nil {
			text += err.Error()
		}
		if (c.is == nil) != (err == nil) || c.is != nil && !errors.Is(err, c.is) || z.ids() != c.left || !strings.Contains(text, c.msg) {
			t.Errorf("%s: %v, records %q, %s", c.what, err, z.ids(), text)
		}
	}

	// The output names the records deleted, and the id of a single one.
	h, z := targetHarness(t, app.Flags{NonInteractive: true})
	if err := h.run("dns", "record", "delete", "example.com", "api"); err != nil {
		t.Fatal(err)
	}
	var one struct {
		Deleted, Zone string
		Records       []struct{ ID, Name string }
	}
	h.jsonOut(&one)
	if one.Deleted != "p1" || one.Zone != "example.com" || len(one.Records) != 1 || one.Records[0].Name != "api.example.com" {
		t.Errorf("output %s", h.stdout.String())
	}
	// A dry run deletes nothing and asks nothing.
	h.rt.Flags.DryRun = true
	if err := h.run("dns", "record", "delete", "example.com", "www"); err != nil || !strings.Contains(h.stdout.String(), "203.0.113.2") || z.ids() != "w1 w2 g1 g2 m1 m2" {
		t.Errorf("dry run: %v, %s, records %q", err, h.stdout.String(), z.ids())
	}
}

// On a terminal dns record delete lists what is open, with the line of a
// record that is not on the default one, and confirms several records.
func TestDNSRecordDeleteLists(t *testing.T) {
	h, z := targetHarness(t, app.Flags{})
	p := prompttest.New(t, []string{"g2", "p1"})
	h.rt.Picker = p
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("dns", "record", "delete", "example.com"); err != nil || z.ids() != "w1 w2 g1 m1 m2" {
		t.Fatalf("domain list: %v, records %q, %s", err, z.ids(), h.stderr.String())
	}
	if a := p.Find("Delete which records of example.com?"); a == nil || !strings.Contains(prompttest.Labels(a.Options), "[line telecom]") || strings.Contains(prompttest.Labels(a.Options), "[line default]") {
		t.Errorf("domain list options %+v", a)
	}
	if !strings.Contains(h.stderr.String(), "delete 2 records in zone example.com (y/N)") || strings.Contains(h.stderr.String(), "to delete one of them only") {
		t.Errorf("confirmation: %s", h.stderr.String())
	}
	p.Done()

	h, z = targetHarness(t, app.Flags{})
	p = prompttest.New(t, []string{"m1"})
	h.rt.Picker = p
	if err := h.run("dns", "record", "delete", "example.com", "mail"); err != nil || z.ids() != "w1 w2 g1 g2 m2 p1" || !strings.Contains(h.stderr.String(), "mail.example.com has records of 2 types (A, TXT)") {
		t.Errorf("name list: %v, records %q, %s", err, z.ids(), h.stderr.String())
	}
	p.Done()

	// Several records of one type: one question; a no deletes nothing and
	// says how to name one.
	for answer, left := range map[string]string{"n\n": "w1 w2 g1 g2 m1 m2 p1", "y\n": "w1 w2 m1 m2 p1"} {
		h, z = targetHarness(t, app.Flags{})
		h.rt.Picker = prompttest.New(t)
		h.rt.Stdin = strings.NewReader(answer)
		err := h.run("dns", "record", "delete", "example.com", "geo")
		text := h.stderr.String()
		if err != nil {
			text += err.Error()
		}
		if (err != nil) != (answer == "n\n") || err != nil && !errors.Is(err, platform.ErrNothingToDo) || z.ids() != left || !strings.Contains(text, "its line with --line") {
			t.Errorf("answer %q: %v, records %q, %s", answer, err, z.ids(), text)
		}
	}
}

// dns record update changes exactly one record, found by name; several
// matches are never all updated.
func TestDNSRecordUpdateByName(t *testing.T) {
	for _, c := range []struct {
		what string
		args []string
		want string
	}{
		{"a name with one record", []string{"api", "--value", "203.0.113.40"}, "p1 api A 203.0.113.40 600 default"},
		{"the type tells them apart", []string{"mail", "TXT", "--value", "v=spf1 ~all"}, "m2 mail TXT v=spf1 ~all 600 default"},
		{"the value tells them apart", []string{"www", "A", "203.0.113.2", "--ttl", "900"}, "w2 www A 203.0.113.2 900 default"},
		{"the current line tells them apart", []string{"geo", "--current-line", "telecom", "--value", "203.0.113.50"}, "g2 geo A 203.0.113.50 600 telecom"},
		{"--line is the new line", []string{"geo", "--current-line", "default", "--line", "unicom"}, "g1 geo A 203.0.113.5 600 unicom"},
		{"--id", []string{"--id", "w1", "--value", "203.0.113.11"}, "w1 www A 203.0.113.11 600 default"},
		{"the former form", []string{"w1", "--name", "web"}, "w1 web A 203.0.113.1 600 default"},
	} {
		h, z := targetHarness(t, app.Flags{NonInteractive: true})
		err := h.run(append([]string{"dns", "record", "update", "example.com"}, c.args...)...)
		if err != nil || len(z.updated) != 1 || z.updated[0] != c.want {
			t.Errorf("%s: %v, sent %q, %s", c.what, err, z.updated, h.stderr.String())
		}
	}
	for _, c := range []struct {
		what string
		args []string
		is   error
		msg  string
	}{
		{"several records", []string{"www", "--ttl", "900"}, platform.ErrAmbiguous, "www.example.com has 2 records in zone example.com; give its <value> after the <type>, or its id with --id <id> to say which (nothing was changed)"},
		{"records that differ in the line", []string{"geo", "--ttl", "900"}, platform.ErrAmbiguous, "give its <value> after the <type>, or its line with --current-line, or its id with --id <id>"},
		{"--line does not select", []string{"geo", "--line", "telecom"}, platform.ErrAmbiguous, "its line with --current-line"},
		{"several types", []string{"mail", "--ttl", "900"}, platform.ErrAmbiguous, "give its <type>, or its <value> after the <type>, or its id with --id <id>"},
		{"no such record", []string{"nope", "--ttl", "900"}, platform.ErrNotFound, "no record with the name or the id nope"},
		{"nothing to change", []string{"api"}, app.ErrUsage, "nothing to change: pass --value, --ttl, --priority, --line, --name, --type"},
		{"only the domain", []string{"--ttl", "900"}, app.ErrUsage, "a record or --id <record-id> is required: usage: aliyun dns record update <domain> <name> [<type> [<value>]]"},
		{"--id beside --current-line", []string{"--id", "g2", "--current-line", "telecom", "--ttl", "900"}, app.ErrUsage, "it cannot be combined with --current-line"},
		{"the former form beside a line the record is not on", []string{"g1", "--current-line", "telecom", "--ttl", "900"}, platform.ErrNotFound, "the record with the id g1 in zone example.com has the line default, not telecom (--current-line)"},
		{"an empty --id", []string{"--id", "", "--ttl", "900"}, app.ErrUsage, "--id must not be empty"},
	} {
		h, z := targetHarness(t, app.Flags{NonInteractive: true, Yes: true})
		err := h.run(append([]string{"dns", "record", "update", "example.com"}, c.args...)...)
		if !errors.Is(err, c.is) || !strings.Contains(err.Error(), c.msg) || len(z.updated) != 0 {
			t.Errorf("%s: %v, sent %q", c.what, err, z.updated)
		}
		// The candidates are listed with their ids and lines.
		if errors.Is(c.is, platform.ErrAmbiguous) && !strings.Contains(h.stderr.String(), "ID") {
			t.Errorf("%s: candidates not listed: %s", c.what, h.stderr.String())
		}
	}
}

// On a terminal dns record update lists the records to choose one from, and
// asks for the new value when no flag says what to change.
func TestDNSRecordUpdateLists(t *testing.T) {
	h, z := targetHarness(t, app.Flags{})
	p := prompttest.New(t, "g2")
	h.rt.Picker = p
	if err := h.run("dns", "record", "update", "example.com", "geo", "--ttl", "900"); err != nil || len(z.updated) != 1 || z.updated[0] != "g2 geo A 203.0.113.5 900 telecom" {
		t.Fatalf("several records: %v, sent %q, %s", err, z.updated, h.stderr.String())
	}
	if a := p.Find("Update which record of geo.example.com?"); a == nil || prompttest.Values(a.Options) != "g1 g2" || !strings.Contains(prompttest.Labels(a.Options), "[line telecom]") {
		t.Errorf("options %+v", a)
	}
	p.Done()

	// Only the domain: the records of the domain, then the new value.
	h, z = targetHarness(t, app.Flags{})
	p = prompttest.New(t, "p1", "203.0.113.44")
	h.rt.Picker = p
	if err := h.run("dns", "record", "update", "example.com"); err != nil || len(z.updated) != 1 || z.updated[0] != "p1 api A 203.0.113.44 600 default" {
		t.Fatalf("domain list: %v, sent %q, %s", err, z.updated, h.stderr.String())
	}
	if a := p.Find("Value of the A record"); a == nil || a.Default != "203.0.113.4" {
		t.Errorf("value question %+v", a)
	}
	p.Done()

	// The same value again changes nothing.
	h, z = targetHarness(t, app.Flags{})
	h.rt.Picker = prompttest.New(t, prompttest.KeepDefault{})
	if err := h.run("dns", "record", "update", "example.com", "api"); !errors.Is(err, platform.ErrNothingToDo) || len(z.updated) != 0 {
		t.Errorf("same value: %v, sent %q", err, z.updated)
	}
}
