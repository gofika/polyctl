package namecom_test

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// newTargetEnv is a recordEnv whose domain example.com holds two A records
// of www (ids 101, 102), an A and a TXT record of mail (103, 104) and one A
// record of api (105).
func newTargetEnv(t *testing.T) *recordEnv {
	t.Helper()
	e := newRecordEnv(t)
	e.f.Add("example.com", "www", "A", "203.0.113.1")
	e.f.Add("example.com", "www", "A", "203.0.113.2")
	e.f.Add("example.com", "mail", "A", "203.0.113.3")
	e.f.Add("example.com", "mail", "TXT", "v=spf1 -all")
	e.f.Add("example.com", "api", "A", "203.0.113.4")
	return e
}

// runTerm runs the command line on a terminal: p answers the lists, and
// answers are the lines typed at a yes/no question.
func (e *recordEnv) runTerm(p *prompttest.Picker, answers string, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(answers), &out, &errb)
	rt.Picker = p
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
	root.SetIn(strings.NewReader(answers))
	root.SetOut(&out)
	root.SetErr(&errb)
	err := root.ExecuteContext(context.Background())
	_ = rt.Close()
	text := errb.String()
	if err != nil {
		text += "error: " + err.Error() + "\n"
	}
	return cli.ExitCodeFor(err), out.String(), text
}

func (e *recordEnv) ids() string { return e.f.IDs("example.com") }

// dns delete finds its records by name; <type>, <value> and --id only tell
// records apart, and the former <domain> <record-id> still works.
func TestDNSDeleteByName(t *testing.T) {
	del := func(e *recordEnv, args ...string) (int, string, string) {
		return e.run(nil, append([]string{"namecom", "dns", "delete", "example.com"}, args...)...)
	}
	const all = "101 102 103 104 105"
	for _, c := range []struct {
		what string
		args []string
		code int
		left string
		msg  string
	}{
		{"a name with one record", []string{"api"}, cli.ExitOK, "101 102 103 104", "deleted api.example.com A 203.0.113.4 via namecom/nc"},
		{"a full name, upper case", []string{"API.example.com"}, cli.ExitOK, "101 102 103 104", ""},
		{"several records need --yes", []string{"www"}, cli.ExitUsage, all, "2 records match; to delete one of them only, give its <value> after the <type>, or its id with --id <id>"},
		{"several records with --yes", []string{"www", "--yes"}, cli.ExitOK, "103 104 105", ""},
		{"several types are never deleted by the name", []string{"mail", "--yes"}, cli.ExitAmbiguous, all, "mail.example.com has records of 2 types in zone example.com (A, TXT); give <type>"},
		{"the type tells them apart", []string{"mail", "txt"}, cli.ExitOK, "101 102 103 105", ""},
		{"the value tells them apart", []string{"www", "A", "203.0.113.2"}, cli.ExitOK, "101 103 104 105", ""},
		{"--id", []string{"--id", "101"}, cli.ExitOK, "102 103 104 105", ""},
		{"--id, another spelling of the number", []string{"--id", "0101"}, cli.ExitOK, "102 103 104 105", ""},
		{"the former form", []string{"104"}, cli.ExitOK, "101 102 103 105", "deleted mail.example.com TXT"},
		{"no such name or id", []string{"999"}, cli.ExitNotFound, all, "no record with the name or the id 999 in zone example.com"},
		{"no such value", []string{"www", "A", "203.0.113.99"}, cli.ExitNotFound, all, "no matching record"},
		{"--id beside a record", []string{"www", "--id", "101"}, cli.ExitUsage, all, "--id selects one record"},
		{"only the domain", nil, cli.ExitUsage, all, "a record or --id <record-id> is required: usage: polyctl namecom dns delete <domain> <name> [<type> [<value>]]"},
		{"too many arguments", []string{"www", "A", "203.0.113.1", "203.0.113.2"}, cli.ExitUsage, all, "usage: polyctl namecom dns delete"},
	} {
		e := newTargetEnv(t)
		code, _, stderr := del(e, c.args...)
		if code != c.code || e.ids() != c.left || !strings.Contains(stderr, c.msg) {
			t.Errorf("%s: exit %d, records %q, %s", c.what, code, e.ids(), stderr)
		}
	}

	// An argument that is the id of one record and the name of another is
	// not guessed.
	e := newTargetEnv(t)
	e.f.Add("example.com", "105", "A", "203.0.113.5")
	if code, _, stderr := del(e, "105"); code != cli.ExitAmbiguous || !strings.Contains(stderr, "pass --id 105 for the record with that id, or the full name 105.example.com") || e.ids() != all+" 106" {
		t.Errorf("id and name: exit %d, records %q, %s", code, e.ids(), stderr)
	}
	if code, _, _ := del(e, "--id", "105"); code != cli.ExitOK || e.ids() != "101 102 103 104 106" {
		t.Errorf("--id 105: exit %d, records %q", code, e.ids())
	}

	// The output names the records deleted, and the id of a single one.
	e = newTargetEnv(t)
	_, stdout, _ := del(e, "api", "-o", "json")
	var one struct {
		DeletedID string `json:"deleted_id"`
		Domain    string
		Records   []struct{ ID, Name string }
	}
	if err := json.Unmarshal([]byte(stdout), &one); err != nil || one.DeletedID != "105" || one.Domain != "example.com" || len(one.Records) != 1 || one.Records[0].Name != "api.example.com" {
		t.Errorf("output %s (%v)", stdout, err)
	}
	// A dry run deletes nothing and asks nothing.
	if code, stdout, _ := del(e, "www", "--dry-run"); code != cli.ExitOK || !strings.Contains(stdout, "203.0.113.2") || e.ids() != "101 102 103 104" {
		t.Errorf("dry run: exit %d, %s, records %q", code, stdout, e.ids())
	}
}

// On a terminal dns delete lists what is open: the records of the domain
// without a name, those of a name with several types; several records of
// one type are confirmed.
func TestDNSDeleteLists(t *testing.T) {
	e := newTargetEnv(t)
	p := prompttest.New(t, []string{"104", "105"})
	code, _, stderr := e.runTerm(p, "y\n", "namecom", "dns", "delete", "example.com")
	if code != cli.ExitOK || e.ids() != "101 102 103" {
		t.Fatalf("domain list: exit %d, records %q, %s", code, e.ids(), stderr)
	}
	if a := p.Find("Delete which records of example.com?"); a == nil || !strings.Contains(prompttest.Labels(a.Options), "www.example.com  A  203.0.113.1") {
		t.Errorf("domain list options %+v", a)
	}
	// Ticked one by one: no hint on how to delete one only.
	if !strings.Contains(stderr, "delete 2 records in zone example.com (y/N)") || strings.Contains(stderr, "to delete one of them only") {
		t.Errorf("domain list confirmation: %s", stderr)
	}
	p.Done()

	e = newTargetEnv(t)
	p = prompttest.New(t, []string{"103"})
	if code, _, stderr := e.runTerm(p, "", "namecom", "dns", "delete", "example.com", "mail"); code != cli.ExitOK || e.ids() != "101 102 104 105" || !strings.Contains(stderr, "mail.example.com has records of 2 types (A, TXT)") {
		t.Errorf("name list: exit %d, records %q, %s", code, e.ids(), stderr)
	}
	if a := p.Find("Delete which records of mail.example.com?"); a == nil || prompttest.Values(a.Options) != "103 104" {
		t.Errorf("name list options %+v", a)
	}
	p.Done()

	// Several records of one type: listed, then one question; a no deletes
	// nothing and says how to name one.
	for answer, left := range map[string]string{"n\n": "101 102 103 104 105", "y\n": "103 104 105"} {
		e = newTargetEnv(t)
		code, _, stderr := e.runTerm(prompttest.New(t), answer, "namecom", "dns", "delete", "example.com", "www")
		if code != cli.ExitOK || e.ids() != left || !strings.Contains(stderr, "2 records match; to delete one of them only, give its <value> after the <type>, or its id with --id <id>") {
			t.Errorf("answer %q: exit %d, records %q, %s", answer, code, e.ids(), stderr)
		}
	}
}

// dns update changes exactly one record, found by name; several matches
// are never all updated.
func TestDNSUpdateByName(t *testing.T) {
	upd := func(e *recordEnv, args ...string) (int, string, string) {
		return e.run(nil, append([]string{"namecom", "dns", "update", "example.com"}, args...)...)
	}
	const before = "www A 203.0.113.1 300 -,www A 203.0.113.2 300 -,mail A 203.0.113.3 300 -,mail TXT v=spf1 -all 300 -,api A 203.0.113.4 300 -"
	for _, c := range []struct {
		what      string
		args      []string
		was, want string
	}{
		{"a name with one record", []string{"api", "--value", "203.0.113.40"}, "api A 203.0.113.4 300 -", "api A 203.0.113.40 300 -"},
		{"the type tells them apart", []string{"mail", "TXT", "--value", "v=spf1 ~all"}, "mail TXT v=spf1 -all 300 -", "mail TXT v=spf1 ~all 300 -"},
		{"the value tells them apart", []string{"www", "A", "203.0.113.2", "--ttl", "600"}, "www A 203.0.113.2 300 -", "www A 203.0.113.2 600 -"},
		{"--id", []string{"--id", "101", "--value", "203.0.113.11"}, "www A 203.0.113.1 300 -", "www A 203.0.113.11 300 -"},
		{"the former form", []string{"101", "--name", "web"}, "www A 203.0.113.1 300 -", "web A 203.0.113.1 300 -"},
	} {
		e := newTargetEnv(t)
		code, _, stderr := upd(e, c.args...)
		if want := strings.Replace(before, c.was, c.want, 1); code != cli.ExitOK || e.records() != want {
			t.Errorf("%s: exit %d, records %q, %s", c.what, code, e.records(), stderr)
		}
	}
	for _, c := range []struct {
		what string
		args []string
		code int
		msg  string
	}{
		{"several records", []string{"www", "--ttl", "600"}, cli.ExitAmbiguous, "www.example.com has 2 records in zone example.com; give its <value> after the <type>, or its id with --id <id> to say which (nothing was changed)"},
		{"several records with --yes", []string{"www", "--ttl", "600", "--yes"}, cli.ExitAmbiguous, "nothing was changed"},
		{"several types", []string{"mail", "--ttl", "600"}, cli.ExitAmbiguous, "mail.example.com has 2 records in zone example.com; give its <type>, or its <value> after the <type>, or its id with --id <id>"},
		{"no such record", []string{"nope", "--ttl", "600"}, cli.ExitNotFound, "no record with the name or the id nope"},
		{"nothing to change", []string{"api"}, cli.ExitUsage, "nothing to change: pass --value, --ttl, --priority, --name, --type"},
		{"only the domain", []string{"--ttl", "600"}, cli.ExitUsage, "a record or --id <record-id> is required: usage: polyctl namecom dns update <domain> <name> [<type> [<value>]]"},
		{"--id beside a record", []string{"www", "--id", "101", "--ttl", "600"}, cli.ExitUsage, "--id selects one record"},
	} {
		e := newTargetEnv(t)
		code, _, stderr := upd(e, c.args...)
		if code != c.code || !strings.Contains(stderr, c.msg) || e.records() != before {
			t.Errorf("%s: exit %d, records %q, %s", c.what, code, e.records(), stderr)
		}
		// The candidates are listed with their ids.
		if c.code == cli.ExitAmbiguous && !strings.Contains(stderr, "101") && !strings.Contains(stderr, "103") {
			t.Errorf("%s: candidates not listed: %s", c.what, stderr)
		}
	}
}

// On a terminal dns update lists the records to choose one from, and asks
// for the new value when no flag says what to change.
func TestDNSUpdateLists(t *testing.T) {
	e := newTargetEnv(t)
	p := prompttest.New(t, "102")
	code, _, stderr := e.runTerm(p, "", "namecom", "dns", "update", "example.com", "www", "--ttl", "600")
	if code != cli.ExitOK || !strings.Contains(e.records(), "www A 203.0.113.2 600 -") || !strings.Contains(e.records(), "www A 203.0.113.1 300 -") {
		t.Fatalf("several records: exit %d, records %q, %s", code, e.records(), stderr)
	}
	if a := p.Find("Update which record of www.example.com?"); a == nil || prompttest.Values(a.Options) != "101 102" {
		t.Errorf("options %+v", a)
	}
	p.Done()

	// Only the domain: the records of the domain, then the new value.
	e = newTargetEnv(t)
	p = prompttest.New(t, "105", "203.0.113.44")
	code, _, stderr = e.runTerm(p, "", "namecom", "dns", "update", "example.com")
	if code != cli.ExitOK || !strings.Contains(e.records(), "api A 203.0.113.44 300 -") {
		t.Fatalf("domain list: exit %d, records %q, %s", code, e.records(), stderr)
	}
	if a := p.Find("Update which record of example.com?"); a == nil || prompttest.Values(a.Options) != "101 102 103 104 105" {
		t.Errorf("domain list options %+v", a)
	}
	if a := p.Find("Value of the A record"); a == nil || a.Default != "203.0.113.4" {
		t.Errorf("value question %+v", a)
	}
	p.Done()

	// The same value again changes nothing.
	e = newTargetEnv(t)
	before := e.records()
	if code, _, stderr := e.runTerm(prompttest.New(t, prompttest.KeepDefault{}), "", "namecom", "dns", "update", "example.com", "api"); code != cli.ExitOK || e.records() != before || !strings.Contains(stderr, "keeps the value") {
		t.Errorf("same value: exit %d, records %q, %s", code, e.records(), stderr)
	}
}

// dns update without a change flag proposes the current value in the form
// the record check takes: an MX value with its priority, an SRV value with
// all four fields. Keeping it is "nothing to do"; a new MX host keeps the
// priority in front.
func TestDNSUpdateProposesCheckableValue(t *testing.T) {
	e := newRecordEnv(t)
	for _, args := range [][]string{{"mx", "MX", "10 mail.example.com"}, {"_sip._tcp", "SRV", "10 5 5060 sip.example.com"}} {
		if code, _, stderr := e.run(nil, append([]string{"namecom", "dns", "create", "example.com"}, args...)...); code != cli.ExitOK {
			t.Fatalf("create %v: exit %d, %s", args, code, stderr)
		}
	}
	before := e.records()
	for _, c := range []struct{ name, typ, def string }{
		{"mx", "MX", "10 mail.example.com"},
		{"_sip._tcp", "SRV", "10 5 5060 sip.example.com"},
	} {
		p := prompttest.New(t, prompttest.KeepDefault{})
		code, _, stderr := e.runTerm(p, "", "namecom", "dns", "update", "example.com", c.name, c.typ)
		if code != cli.ExitOK || e.records() != before || !strings.Contains(stderr, "keeps the value "+c.def) {
			t.Errorf("%s keep: exit %d, records %q, %s", c.typ, code, e.records(), stderr)
		}
		if a := p.Find("Value of the " + c.typ + " record"); a == nil || a.Default != c.def {
			t.Errorf("%s default %+v, want %q", c.typ, a, c.def)
		}
	}
	p := prompttest.New(t, "10 mx2.example.com")
	if code, _, stderr := e.runTerm(p, "", "namecom", "dns", "update", "example.com", "mx", "MX"); code != cli.ExitOK || !strings.Contains(e.records(), "mx MX mx2.example.com 0 10") {
		t.Errorf("new MX host: exit %d, records %q, %s", code, e.records(), stderr)
	}
}
