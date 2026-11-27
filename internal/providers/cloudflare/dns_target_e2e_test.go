package cloudflare_test

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

// newTargetEnv is an r2Env whose zone example.com holds two A records of
// www, an A and a TXT record of mail, and one A record of api.
func newTargetEnv(t *testing.T) *r2Env {
	t.Helper()
	e := newR2Env(t)
	e.f.addRecord("zone-ex", "w1", "www.example.com", "A", "203.0.113.1")
	e.f.addRecord("zone-ex", "w2", "www.example.com", "A", "203.0.113.2")
	e.f.addRecord("zone-ex", "m1", "mail.example.com", "A", "203.0.113.3")
	e.f.addRecord("zone-ex", "m2", "mail.example.com", "TXT", "v=spf1 -all")
	e.f.addRecord("zone-ex", "p1", "api.example.com", "A", "203.0.113.4")
	return e
}

// runTerm runs the command line on a terminal: p answers the lists, and
// answers are the lines typed at a yes/no question.
func (e *r2Env) runTerm(p *prompttest.Picker, answers string, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(answers), &out, &errb)
	rt.Picker = p
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir, "--profile", "acme"}, args...))
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

func (e *r2Env) recordIDs() string {
	var ids []string
	for _, r := range e.f.records["zone-ex"] {
		ids = append(ids, r["id"].(string))
	}
	return strings.Join(ids, " ")
}

// dns delete finds its records by name; <type>, <value> and --id only tell
// records apart.
func TestDNSDeleteByName(t *testing.T) {
	del := func(e *r2Env, args ...string) (int, string, string) {
		return e.run(append([]string{"cloudflare", "dns", "delete", "example.com", "--profile", "acme"}, args...)...)
	}
	for _, c := range []struct {
		what string
		args []string
		code int
		left string
		msg  string
	}{
		{"a name with one record", []string{"api"}, cli.ExitOK, "w1 w2 m1 m2", "deleted api.example.com A 203.0.113.4 via cloudflare/acme"},
		{"a full name, upper case", []string{"API.example.com"}, cli.ExitOK, "w1 w2 m1 m2", ""},
		{"several records need --yes", []string{"www"}, cli.ExitUsage, "w1 w2 m1 m2 p1", "2 records match; to delete one of them only, give its <value> after the <type>, or its id with --id <id>"},
		{"several records with --yes", []string{"www", "--yes"}, cli.ExitOK, "m1 m2 p1", ""},
		{"several types are never deleted by the name", []string{"mail", "--yes"}, cli.ExitAmbiguous, "w1 w2 m1 m2 p1", "mail.example.com has records of 2 types in zone example.com (A, TXT); give <type>"},
		{"the type tells them apart", []string{"mail", "txt"}, cli.ExitOK, "w1 w2 m1 p1", ""},
		{"the value tells them apart", []string{"www", "A", "203.0.113.2"}, cli.ExitOK, "w1 m1 m2 p1", ""},
		{"--id", []string{"--id", "w1"}, cli.ExitOK, "w2 m1 m2 p1", ""},
		{"the former form", []string{"m2"}, cli.ExitOK, "w1 w2 m1 p1", "deleted mail.example.com TXT"},
		{"no such name or id", []string{"nope"}, cli.ExitNotFound, "w1 w2 m1 m2 p1", "no record with the name or the id nope in zone example.com"},
		{"no such value", []string{"www", "A", "203.0.113.99"}, cli.ExitNotFound, "w1 w2 m1 m2 p1", "no matching record"},
		{"--id beside a record", []string{"www", "--id", "w1"}, cli.ExitUsage, "w1 w2 m1 m2 p1", "--id selects one record"},
		{"only the zone", nil, cli.ExitUsage, "w1 w2 m1 m2 p1", "a record or --id <record-id> is required: usage: polyctl cloudflare dns delete <zone> <name> [<type> [<value>]]"},
		{"too many arguments", []string{"www", "A", "203.0.113.1", "203.0.113.2"}, cli.ExitUsage, "w1 w2 m1 m2 p1", "usage: polyctl cloudflare dns delete"},
	} {
		e := newTargetEnv(t)
		code, _, stderr := del(e, c.args...)
		if code != c.code || e.recordIDs() != c.left || !strings.Contains(stderr, c.msg) {
			t.Errorf("%s: exit %d, records %q, %s", c.what, code, e.recordIDs(), stderr)
		}
	}

	// An argument that is the id of one record and the name of another is
	// not guessed.
	e := newTargetEnv(t)
	e.f.addRecord("zone-ex", "api", "other.example.com", "A", "203.0.113.5")
	if code, _, stderr := del(e, "api"); code != cli.ExitAmbiguous || !strings.Contains(stderr, "pass --id api for the record with that id, or the full name api.example.com") || len(e.f.writes()) != 0 {
		t.Errorf("id and name: exit %d, %s", code, stderr)
	}
	if code, _, _ := del(e, "--id", "api"); code != cli.ExitOK || strings.Contains(e.recordIDs(), "api") {
		t.Errorf("--id api: exit %d, records %q", code, e.recordIDs())
	}

	// The output names the records deleted, and the id of a single one.
	e = newTargetEnv(t)
	_, stdout, _ := del(e, "api", "-o", "json")
	var one struct {
		Deleted string
		Zone    string
		Records []struct{ ID, Name string }
	}
	if err := json.Unmarshal([]byte(stdout), &one); err != nil || one.Deleted != "p1" || one.Zone != "example.com" || len(one.Records) != 1 || one.Records[0].Name != "api.example.com" {
		t.Errorf("output %s (%v)", stdout, err)
	}
	// A dry run deletes nothing and asks nothing.
	if code, stdout, _ := del(e, "www", "--dry-run"); code != cli.ExitOK || !strings.Contains(stdout, "203.0.113.2") || len(e.f.writes()) != 1 {
		t.Errorf("dry run: exit %d, %s, %v", code, stdout, e.f.writes())
	}
}

// On a terminal dns delete lists what is open: the records of the zone
// without a name, those of a name with several types; several records of
// one type are confirmed.
func TestDNSDeleteLists(t *testing.T) {
	e := newTargetEnv(t)
	e.f.accounts["acc1"].buckets = []string{"assets"}
	e.f.bind("acc1", "assets", "cdn.example.com", "zone-ex", true, "")
	p := prompttest.New(t, []string{"m2", "p1"})
	code, _, stderr := e.runTerm(p, "y\n", "cloudflare", "dns", "delete", "example.com")
	if code != cli.ExitOK || !strings.HasPrefix(e.recordIDs(), "w1 w2 m1 cname") {
		t.Fatalf("zone list: exit %d, records %q, %s", code, e.recordIDs(), stderr)
	}
	a := p.Find("Delete which records of example.com?")
	if a == nil || !strings.Contains(prompttest.Labels(a.Options), "[r2 bucket assets]") || !strings.Contains(prompttest.Labels(a.Options), "www.example.com  A  203.0.113.1") {
		t.Errorf("zone list options %+v", a)
	}
	// Ticked one by one: no hint on how to delete one only.
	if !strings.Contains(stderr, "delete 2 records in zone example.com (y/N)") || strings.Contains(stderr, "to delete one of them only") {
		t.Errorf("zone list confirmation: %s", stderr)
	}
	p.Done()

	e = newTargetEnv(t)
	p = prompttest.New(t, []string{"m1"})
	if code, _, stderr := e.runTerm(p, "", "cloudflare", "dns", "delete", "example.com", "mail"); code != cli.ExitOK || e.recordIDs() != "w1 w2 m2 p1" || !strings.Contains(stderr, "mail.example.com has records of 2 types (A, TXT)") {
		t.Errorf("name list: exit %d, records %q, %s", code, e.recordIDs(), stderr)
	}
	if a := p.Find("Delete which records of mail.example.com?"); a == nil || prompttest.Values(a.Options) != "m1 m2" {
		t.Errorf("name list options %+v", a)
	}
	p.Done()

	// Several records of one type: listed, then one question; a no deletes
	// nothing and says how to name one.
	for answer, left := range map[string]string{"n\n": "w1 w2 m1 m2 p1", "y\n": "m1 m2 p1"} {
		e = newTargetEnv(t)
		code, _, stderr := e.runTerm(prompttest.New(t), answer, "cloudflare", "dns", "delete", "example.com", "www")
		if code != cli.ExitOK || e.recordIDs() != left || !strings.Contains(stderr, "2 records match; to delete one of them only, give its <value> after the <type>, or its id with --id <id>") {
			t.Errorf("answer %q: exit %d, records %q, %s", answer, code, e.recordIDs(), stderr)
		}
	}
}

// dns update changes exactly one record, found by name; several matches
// are never all updated.
func TestDNSUpdateByName(t *testing.T) {
	upd := func(e *r2Env, args ...string) (int, string, string) {
		return e.run(append([]string{"cloudflare", "dns", "update", "example.com", "--profile", "acme"}, args...)...)
	}
	const put = "PUT /zones/zone-ex/dns_records/"
	for _, c := range []struct {
		what string
		args []string
		id   string
		want map[string]any
	}{
		{"a name with one record", []string{"api", "--value", "203.0.113.40"}, "p1", map[string]any{"name": "api.example.com", "type": "A", "content": "203.0.113.40"}},
		{"the type tells them apart", []string{"mail", "TXT", "--value", "v=spf1 ~all"}, "m2", map[string]any{"content": "v=spf1 ~all", "type": "TXT"}},
		{"the value tells them apart", []string{"www", "A", "203.0.113.2", "--ttl", "300"}, "w2", map[string]any{"content": "203.0.113.2", "ttl": float64(300)}},
		{"--id", []string{"--id", "w1", "--proxied"}, "w1", map[string]any{"content": "203.0.113.1", "proxied": true}},
		{"the former form", []string{"w1", "--name", "web"}, "w1", map[string]any{"name": "web.example.com", "content": "203.0.113.1"}},
	} {
		e := newTargetEnv(t)
		code, _, stderr := upd(e, c.args...)
		if w := e.f.writes(); code != cli.ExitOK || len(w) != 1 || w[0] != put+c.id {
			t.Errorf("%s: exit %d, writes %v, %s", c.what, code, w, stderr)
			continue
		}
		body := e.f.body(put + c.id)
		for k, v := range c.want {
			if body[k] != v {
				t.Errorf("%s: %s = %v, want %v (body %v)", c.what, k, body[k], v, body)
			}
		}
	}
	for _, c := range []struct {
		what string
		args []string
		code int
		msg  string
	}{
		{"several records", []string{"www", "--ttl", "300"}, cli.ExitAmbiguous, "www.example.com has 2 records in zone example.com; give its <value> after the <type>, or its id with --id <id> to say which (nothing was changed)"},
		{"several records of the type", []string{"www", "a", "--ttl", "300"}, cli.ExitAmbiguous, "2 A records of www.example.com match in zone example.com; give its <value> after the <type>, or its id with --id <id>"},
		{"several records with --yes", []string{"www", "--ttl", "300", "--yes"}, cli.ExitAmbiguous, "nothing was changed"},
		{"several types", []string{"mail", "--ttl", "300"}, cli.ExitAmbiguous, "mail.example.com has 2 records in zone example.com; give its <type>, or its <value> after the <type>, or its id with --id <id>"},
		{"no such record", []string{"nope", "--ttl", "300"}, cli.ExitNotFound, "no record with the name or the id nope"},
		{"nothing to change", []string{"api"}, cli.ExitUsage, "nothing to change: pass --value, --ttl, --proxied, --priority, --comment, --name, --type"},
		{"only the zone", []string{"--ttl", "300"}, cli.ExitUsage, "a record or --id <record-id> is required: usage: polyctl cloudflare dns update <zone> <name> [<type> [<value>]]"},
		{"--id beside a record", []string{"www", "--id", "w1", "--ttl", "300"}, cli.ExitUsage, "--id selects one record"},
	} {
		e := newTargetEnv(t)
		code, _, stderr := upd(e, c.args...)
		if code != c.code || !strings.Contains(stderr, c.msg) || len(e.f.writes()) != 0 {
			t.Errorf("%s: exit %d, writes %v, %s", c.what, code, e.f.writes(), stderr)
		}
		// The candidates are listed with their ids.
		if c.code == cli.ExitAmbiguous && (!strings.Contains(stderr, "w1") && !strings.Contains(stderr, "m1")) {
			t.Errorf("%s: candidates not listed: %s", c.what, stderr)
		}
	}
}

// On a terminal dns update lists the records to choose one from, and asks
// for the new value when no flag says what to change.
func TestDNSUpdateLists(t *testing.T) {
	const put = "PUT /zones/zone-ex/dns_records/"
	e := newTargetEnv(t)
	p := prompttest.New(t, "w2")
	code, _, stderr := e.runTerm(p, "", "cloudflare", "dns", "update", "example.com", "www", "--ttl", "300")
	if w := e.f.writes(); code != cli.ExitOK || len(w) != 1 || w[0] != put+"w2" {
		t.Fatalf("several records: exit %d, writes %v, %s", code, w, stderr)
	}
	if a := p.Find("Update which record of www.example.com?"); a == nil || prompttest.Values(a.Options) != "w1 w2" {
		t.Errorf("options %+v", a)
	}
	p.Done()

	// Only the zone: the records of the zone, then the new value.
	e = newTargetEnv(t)
	p = prompttest.New(t, "p1", "203.0.113.44")
	code, _, stderr = e.runTerm(p, "", "cloudflare", "dns", "update", "example.com")
	if b := e.f.body(put + "p1"); code != cli.ExitOK || b["content"] != "203.0.113.44" || b["name"] != "api.example.com" {
		t.Fatalf("zone list: exit %d, body %v, %s", code, b, stderr)
	}
	if a := p.Find("Update which record of example.com?"); a == nil || prompttest.Values(a.Options) != "w1 w2 m1 m2 p1" {
		t.Errorf("zone list options %+v", a)
	}
	if a := p.Find("Value of the A record"); a == nil || a.Default != "203.0.113.4" {
		t.Errorf("value question %+v", a)
	}
	p.Done()

	// The same value again changes nothing.
	e = newTargetEnv(t)
	if code, _, stderr := e.runTerm(prompttest.New(t, prompttest.KeepDefault{}), "", "cloudflare", "dns", "update", "example.com", "api"); code != cli.ExitOK || len(e.f.writes()) != 0 || !strings.Contains(stderr, "keeps the value") {
		t.Errorf("same value: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
}

// --proxied (true) on a type that cannot be proxied is refused
// with exit code 2 before any request where the type is known from the
// command line, and before any write where it is known once the record is
// read (--id).
func TestDNSProxiedRefusedOnATypeThatCannotBeProxied(t *testing.T) {
	const want = "proxied applies to A, AAAA and CNAME records only, not TXT"
	for _, args := range [][]string{
		{"cloudflare", "dns", "create", "example.com", "www", "TXT", "hello", "--proxied"},
		{"cloudflare", "dns", "create", "example.com", "--name", "www", "--type", "TXT", "--value", "hello", "--proxied"},
		{"cloudflare", "dns", "update", "example.com", "mail", "TXT", "--proxied"},
		{"cloudflare", "dns", "update", "example.com", "api", "--type", "TXT", "--value", "hello", "--proxied"},
	} {
		e := newTargetEnv(t)
		e.f.reset()
		code, _, stderr := e.run(append(args, "--profile", "acme")...)
		if code != cli.ExitUsage || !strings.Contains(stderr, want) || e.f.count("") != 0 {
			t.Errorf("%v: exit %d, %d requests, %s", args, code, e.f.count(""), stderr)
		}
	}
	e := newTargetEnv(t)
	code, _, stderr := e.run("cloudflare", "dns", "update", "example.com", "--id", "m2", "--proxied", "--profile", "acme")
	if code != cli.ExitUsage || !strings.Contains(stderr, want) || len(e.f.writes()) != 0 {
		t.Errorf("update --id m2 --proxied: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
}

// A proxied A record updated to a type that cannot be proxied loses the
// proxy, with --proxied=false or without it: the platform refuses
// proxied=true on a TXT record.
func TestDNSUpdateProxiedRecordToUnproxiableType(t *testing.T) {
	for _, extra := range [][]string{{"--proxied=false"}, nil} {
		e := newTargetEnv(t)
		e.f.mu.Lock()
		for _, r := range e.f.records["zone-ex"] {
			if r["id"] == "p1" {
				r["proxied"] = true
			}
		}
		e.f.mu.Unlock()
		e.f.reset()
		args := append([]string{"cloudflare", "dns", "update", "example.com", "api", "--type", "TXT", "--value", "hello", "--profile", "acme"}, extra...)
		code, _, stderr := e.run(args...)
		if code != 0 {
			t.Fatalf("%v: exit %d (%s)", extra, code, stderr)
		}
		body := e.f.bodies["PUT /zones/zone-ex/dns_records/p1"]
		if strings.Contains(body, `"proxied":true`) || !strings.Contains(body, `"type":"TXT"`) {
			t.Errorf("%v: body %s, want a TXT record without the proxy", extra, body)
		}
	}
}
