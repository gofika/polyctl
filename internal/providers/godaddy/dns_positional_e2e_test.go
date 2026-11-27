package godaddy_test

import (
	"sort"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// details lists the records of the fake with TTL and priority, sorted.
func (e *deleteEnv) details() string {
	recs := e.f.Details("example.com")
	sort.Strings(recs)
	return strings.Join(recs, ",")
}

// dns add, upsert and delete with the record as arguments write what the
// former flags write.
func TestDNSPositionalRecordMatchesFlagForm(t *testing.T) {
	e := newDeleteEnv(t)
	for _, c := range []struct {
		name       string
		verb       string
		positional []string
		flags      []string
		want       string
	}{
		{"add keeps the others", "add", []string{"www", "A", "203.0.113.3"}, []string{"--name", "www", "--type", "A", "--value", "203.0.113.3"},
			"A www 203.0.113.1 600 -,A www 203.0.113.2 600 -,A www 203.0.113.3 0 -,TXT www hello 600 -"},
		{"add, apex and lower-case type", "add", []string{"@", "txt", "v=spf1 -all", "--ttl", "3600"}, []string{"--name", "@", "--type", "txt", "--value", "v=spf1 -all", "--ttl", "3600"},
			"A www 203.0.113.1 600 -,A www 203.0.113.2 600 -,TXT @ v=spf1 -all 3600 -,TXT www hello 600 -"},
		{"add, full name and --priority", "add", []string{"mail.example.com", "MX", "mx.example.net", "--priority", "10"}, []string{"--name", "mail.example.com", "--type", "MX", "--value", "mx.example.net", "--priority", "10"},
			"A www 203.0.113.1 600 -,A www 203.0.113.2 600 -,MX mail mx.example.net 0 10,TXT www hello 600 -"},
		{"add, value after --", "add", []string{"dash", "TXT", "--", "-dash"}, []string{"--name", "dash", "--type", "TXT", "--value=-dash"},
			"A www 203.0.113.1 600 -,A www 203.0.113.2 600 -,TXT dash -dash 0 -,TXT www hello 600 -"},
		{"upsert replaces the set with several values", "upsert", []string{"www", "a", "203.0.113.8", "203.0.113.9", "--ttl", "900"}, []string{"--name", "www", "--type", "a", "--value", "203.0.113.8", "--value", "203.0.113.9", "--ttl", "900"},
			"A www 203.0.113.8 900 -,A www 203.0.113.9 900 -,TXT www hello 600 -"},
		{"upsert creates a set", "upsert", []string{"@", "MX", "mx.example.net", "--priority", "5"}, []string{"--name", "@", "--type", "MX", "--value", "mx.example.net", "--priority", "5"},
			"A www 203.0.113.1 600 -,A www 203.0.113.2 600 -,MX @ mx.example.net 0 5,TXT www hello 600 -"},
		{"delete the set", "delete", []string{"www", "A", "--yes"}, []string{"--name", "www", "--type", "A", "--yes"}, "TXT www hello 600 -"},
		{"delete, full name and lower-case type", "delete", []string{"www.example.com", "txt", "--yes"}, []string{"--name", "www.example.com", "--type", "txt", "--yes"},
			"A www 203.0.113.1 600 -,A www 203.0.113.2 600 -"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, form := range [][]string{c.positional, c.flags} {
				e.reset()
				code, _, stderr := e.run(nil, "", append([]string{"godaddy", "dns", c.verb, "example.com"}, form...)...)
				if code != cli.ExitOK {
					t.Fatalf("%v: exit %d, %s", form, code, stderr)
				}
				if got := e.details(); got != c.want {
					t.Errorf("%v wrote %q, want %q", form, got, c.want)
				}
			}
		})
	}
}

// Both forms at once, a wrong number of arguments, an empty argument and
// --id beside a positional record are usage errors, and nothing is written.
func TestDNSPositionalRecordUsage(t *testing.T) {
	e := newDeleteEnv(t)
	const (
		add    = "usage: polyctl godaddy dns add <domain> <name> <type> <value>"
		upsert = "usage: polyctl godaddy dns upsert <domain> <name> <type> <value>..."
		del    = "usage: polyctl godaddy dns delete <domain> <name> [<type> [<value>]]"
	)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"add"}, add},
		{[]string{"add", "example.com"}, add},
		{[]string{"add", "example.com", "www"}, add},
		{[]string{"add", "example.com", "www", "A"}, add},
		{[]string{"add", "example.com", "www", "A", "203.0.113.3", "203.0.113.4"}, add},
		{[]string{"add", "example.com", "--type", "A"}, add},
		{[]string{"add", "example.com", "www", "A", "203.0.113.3", "--name", "www"}, "with --name; use one form: " + add},
		{[]string{"add", "example.com", "www", "A", "203.0.113.3", "--type", "A"}, "with --type; use one form: " + add},
		{[]string{"add", "example.com", "www", "A", "203.0.113.3", "--value", "203.0.113.3"}, "with --value; use one form: " + add},
		{[]string{"add", "example.com", "", "A", "203.0.113.3"}, "<name> must not be empty"},
		{[]string{"add", "example.com", "www", "", "203.0.113.3"}, "<type> must not be empty"},
		{[]string{"add", "example.com", "www", "A", ""}, "<value> must not be empty"},
		{[]string{"upsert"}, upsert},
		{[]string{"upsert", "example.com"}, upsert},
		{[]string{"upsert", "example.com", "www"}, upsert},
		{[]string{"upsert", "example.com", "www", "A"}, upsert},
		{[]string{"upsert", "example.com", "www", "A", "203.0.113.3", "--value", "203.0.113.4"}, "with --value; use one form: " + upsert},
		{[]string{"upsert", "example.com", "www", "A", "203.0.113.3", "--name", "www", "--type", "A"}, "with --name, --type; use one form: " + upsert},
		{[]string{"delete", "--yes"}, del},
		{[]string{"delete", "example.com", "--yes"}, "a record or --id <record-id> is required: " + del},
		{[]string{"delete", "example.com", "www", "A", "203.0.113.1", "203.0.113.2", "--yes"}, del},
		{[]string{"delete", "example.com", "--id", "", "--yes"}, "--id must not be empty"},
		{[]string{"delete", "example.com", "www", "A", "--name", "www", "--yes"}, "with --name; use one form: " + del},
		{[]string{"delete", "example.com", "www", "A", "--type", "A", "--yes"}, "with --type; use one form: " + del},
		{[]string{"delete", "example.com", "www", "A", "--id", recordID, "--yes"}, "--id selects one record; it cannot be combined with <name> [<type> [<value>]]"},
	} {
		e.reset()
		code, _, stderr := e.run(nil, "", append([]string{"godaddy", "dns"}, c.args...)...)
		if code != cli.ExitUsage || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: exit %d, %s; want %q", c.args, code, stderr, c.want)
		}
		if got := e.records(); got != allRecords || len(e.f.Writes()) != 0 {
			t.Errorf("%v wrote %q (%v)", c.args, got, e.f.Writes())
		}
	}
}

// With only the domain the interactive flow asks: add and upsert for the
// name (never taken to be the apex), the type and the value (upsert for
// values until one is left empty), delete for the records to delete. A record that
// stops after its name or its type is completed.
func TestDNSRecordWithOnlyTheDomainAsks(t *testing.T) {
	e := newDeleteEnv(t)
	for _, verb := range []string{"add", "upsert"} {
		more := []any{}
		if verb == "upsert" {
			more = []any{""}
		}
		e.reset()
		p := prompttest.New(t, append([]any{"@", "TXT", "asked"}, more...)...)
		code, _, stderr := e.run(p, "", "godaddy", "dns", verb, "example.com")
		if code != cli.ExitOK {
			t.Fatalf("%s: exit %d, %s", verb, code, stderr)
		}
		p.Done()
		if a := p.Find("Record name in example.com"); prompttest.Labels(a.Options) != "@ (apex)\nwww  A TXT\nAnother name..." {
			t.Errorf("%s: names offered:\n%s", verb, prompttest.Labels(a.Options))
		}
		if got := e.records(); got != "A www 203.0.113.1,A www 203.0.113.2,TXT @ asked,TXT www hello" {
			t.Errorf("%s wrote %q", verb, got)
		}
		// <domain> <name> <type>, and a name typed in.
		e.reset()
		p = prompttest.New(t, append([]any{"203.0.113.9"}, more...)...)
		if code, _, stderr := e.run(p, "", "godaddy", "dns", verb, "example.com", "api", "a"); code != cli.ExitOK {
			t.Fatalf("%s <name> <type>: exit %d, %s", verb, code, stderr)
		}
		p.Done()
		p = prompttest.New(t, append([]any{prompttest.Label("Another name"), "new", "TXT", "typed"}, more...)...)
		if code, _, stderr := e.run(p, "", "godaddy", "dns", verb, "example.com"); code != cli.ExitOK {
			t.Fatalf("%s typed name: exit %d, %s", verb, code, stderr)
		}
		p.Done()
		if got := e.records(); got != "A api 203.0.113.9,A www 203.0.113.1,A www 203.0.113.2,TXT new typed,TXT www hello" {
			t.Errorf("%s wrote %q", verb, got)
		}
		// The non-interactive flow asks nothing.
		for _, args := range [][]string{{"example.com", "www"}, {"example.com", "www", "A"}} {
			code, _, stderr := e.run(nil, "", append([]string{"godaddy", "dns", verb}, args...)...)
			if code != cli.ExitUsage || !strings.Contains(stderr, "usage: polyctl godaddy dns "+verb+" <domain> <name> <type> <value>") {
				t.Errorf("non-interactive %s %v: exit %d, %s", verb, args, code, stderr)
			}
		}
	}
	// upsert of a name with one type: the type is preselected, the set is
	// shown and its first value proposed.
	e.reset()
	p0 := prompttest.New(t, "TXT", prompttest.KeepDefault{}, "second", "")
	if code, _, stderr := e.run(p0, "", "godaddy", "dns", "upsert", "example.com", "www"); code != cli.ExitOK || !strings.Contains(stderr, "www.example.com TXT is now: hello (the set becomes what you enter)") {
		t.Fatalf("upsert <name>: exit %d, %s", code, stderr)
	}
	p0.Done()
	if got := e.records(); got != "A www 203.0.113.1,A www 203.0.113.2,TXT www hello,TXT www second" {
		t.Errorf("upsert <name> wrote %q", got)
	}
	e.reset()
	p := prompttest.New(t, []string{"example.com|TXT|www|hello"})
	code, _, stderr := e.run(p, "", "godaddy", "dns", "delete", "example.com")
	if code != cli.ExitOK {
		t.Fatalf("delete: exit %d, %s", code, stderr)
	}
	p.Done()
	if got := e.records(); got != "A www 203.0.113.1,A www 203.0.113.2" {
		t.Errorf("delete left %q", got)
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position of a command that writes a record completes the
// record types.
func TestDNSPositionalRecordHelp(t *testing.T) {
	root := cli.NewRoot(app.New(app.Flags{}, strings.NewReader(""), new(strings.Builder), new(strings.Builder)))
	for verb, use := range map[string]string{
		"add":    "add <domain> <name> <type> <value>",
		"upsert": "upsert <domain> <name> <type> <value>...",
		"delete": "delete <domain> [<name> [<type> [<value>]]]",
	} {
		cmd, _, err := root.Find([]string{"godaddy", "dns", verb})
		if err != nil {
			t.Fatal(err)
		}
		if cmd.Use != use || !strings.Contains(cmd.Example, "dns "+verb+" example.com www A") || strings.Contains(cmd.Example, "--type") {
			t.Errorf("use %q, example %q", cmd.Use, cmd.Example)
		}
		for _, name := range []string{"name", "type", "value"} {
			if f := cmd.Flags().Lookup(name); f != nil && !f.Hidden {
				t.Errorf("%s: --%s should be hidden", verb, name)
			}
		}
		for _, name := range []string{"ttl", "priority", "id"} {
			if f := cmd.Flags().Lookup(name); f != nil && f.Hidden {
				t.Errorf("%s: --%s should be listed", verb, name)
			}
		}
		if verb == "delete" {
			continue
		}
		types, dir := cmd.ValidArgsFunction(cmd, []string{"example.com", "www"}, "")
		if dir != cobra.ShellCompDirectiveNoFileComp || !strings.Contains(" "+strings.Join(types, " ")+" ", " CNAME ") {
			t.Errorf("%s: type completion %v, %v", verb, types, dir)
		}
		if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example.com"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
			t.Errorf("%s: name completion %v, %v", verb, vals, dir)
		}
	}
}

// The <type> position completes the record types GoDaddy can write, not
// every type a record spec knows. delete completes what the domain holds in
// the inventory: the names, the types of a name and the values of a type.
func TestDNSRecordTypeCompletion(t *testing.T) {
	e := newDeleteEnv(t)
	complete := func(args ...string) string {
		t.Helper()
		code, stdout, stderr := e.run(nil, "", append([]string{"__complete", "godaddy", "dns"}, args...)...)
		if code != cli.ExitOK {
			t.Fatalf("%v: exit %d, %s", args, code, stderr)
		}
		var got []string
		for _, l := range strings.Split(stdout, "\n") {
			if l != "" && !strings.HasPrefix(l, ":") {
				got = append(got, l)
			}
		}
		return strings.Join(got, " | ")
	}
	for _, verb := range []string{"add", "upsert"} {
		if got := complete(verb, "example.com", "www", ""); got != "A | AAAA | CNAME | MX | NS | TXT | SRV | CAA" {
			t.Errorf("%s completes <type> with %q", verb, got)
		}
	}
	if got := complete("delete", "example.com", ""); got != "" {
		t.Errorf("delete without an inventory completes <name> with %q", got)
	}
	if code, _, stderr := e.run(nil, "", "godaddy", "dns", "list", "example.com"); code != cli.ExitOK {
		t.Fatalf("list: exit %d, %s", code, stderr)
	}
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"example.com", ""}, "www\tA 203.0.113.1, A 203.0.113.2, TXT hello"},
		{[]string{"example.com", "www", ""}, "A | TXT"},
		{[]string{"example.com", "www", "A", ""}, "203.0.113.1 | 203.0.113.2"},
		{[]string{"example.com", "www", "A", "203.0.113.1", ""}, ""},
	} {
		if got := complete(append([]string{"delete"}, c.args...)...); got != c.want {
			t.Errorf("delete %v completes with %q, want %q", c.args, got, c.want)
		}
	}
}

// The interactive upsert proposes the current value in the form the record
// check takes: an MX value with its priority, an SRV value with all four
// fields (GoDaddy keeps the priority, weight and port apart from the
// target). Keeping it passes the record check; the MX record is written
// again as it is.
func TestDNSUpsertProposesCheckableValue(t *testing.T) {
	e := newDeleteEnv(t)
	for _, c := range []struct{ name, typ, value string }{
		{"@", "MX", "10 mail.example.com"},
		{"_sip._tcp", "SRV", "10 5 5060 sip.example.com"},
	} {
		if code, _, stderr := e.run(nil, "", "godaddy", "dns", "add", "example.com", c.name, c.typ, c.value); code != cli.ExitOK {
			t.Fatalf("add %s: exit %d, %s", c.typ, code, stderr)
		}
		before := e.records()
		p := prompttest.New(t, prompttest.KeepDefault{}, "")
		if code, _, stderr := e.run(p, "", "godaddy", "dns", "upsert", "example.com", c.name, c.typ); code != cli.ExitOK {
			t.Fatalf("upsert %s: exit %d, %s", c.typ, code, stderr)
		}
		p.Done()
		if a := p.Find("Value of the " + c.typ + " record"); a == nil || a.Default != c.value {
			t.Errorf("%s default %+v, want %q", c.typ, a, c.value)
		}
		if got := e.records(); c.typ == "MX" && got != before {
			t.Errorf("%s upsert wrote %q, had %q", c.typ, got, before)
		}
	}
}

// A record GoDaddy lists with "@" (the zone apex) as its target, such as its
// default `www CNAME @`, is written back as it is shown.
func TestDNSWritesApexTarget(t *testing.T) {
	e := newDeleteEnv(t)
	e.f.SetRecord("example.com", "CNAME", "shop", "@")
	before := e.records()
	if code, _, stderr := e.run(nil, "", "godaddy", "dns", "upsert", "example.com", "shop", "CNAME", "@"); code != cli.ExitOK || e.records() != before {
		t.Fatalf("upsert shop CNAME @: exit %d, records %q, %s", code, e.records(), stderr)
	}
	p := prompttest.New(t, prompttest.KeepDefault{}, "")
	if code, _, stderr := e.run(p, "", "godaddy", "dns", "upsert", "example.com", "shop", "CNAME"); code != cli.ExitOK || e.records() != before {
		t.Fatalf("interactive upsert: exit %d, records %q, %s", code, e.records(), stderr)
	}
	p.Done()
	if a := p.Find("Value of the CNAME record"); a == nil || a.Default != "@" {
		t.Errorf("default %+v", a)
	}
	if code, _, stderr := e.run(nil, "", "godaddy", "dns", "add", "example.com", "@", "MX", "10 @"); code != cli.ExitOK || !strings.Contains(e.records(), "MX @ @") {
		t.Errorf("add @ MX 10 @: exit %d, records %q, %s", code, e.records(), stderr)
	}
}

// A name and type given that the platform refuses together (an SRV name
// that is not _service._proto, a CNAME at the zone apex) are refused before
// any request: on a terminal before the zone is read for the questions, and
// in a script.
func TestDNSNameAndTypeRefusedBeforeAnyRequest(t *testing.T) {
	e := newDeleteEnv(t)
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"add", "example.com", "www", "SRV"}, "_service._proto"},
		{[]string{"upsert", "example.com", "www", "SRV"}, "_service._proto"},
		{[]string{"add", "example.com", "@", "CNAME"}, "does not take a CNAME at the zone apex"},
		{[]string{"upsert", "example.com", "@", "CNAME"}, "does not take a CNAME at the zone apex"},
	} {
		value := map[string]string{"SRV": "10 5 5060 sip.example.com", "CNAME": "target.example.net"}[c.args[3]]
		for _, p := range []*prompttest.Picker{prompttest.New(t), nil} {
			args := append([]string{"godaddy", "dns"}, c.args...)
			if p == nil {
				args = append(args, value)
			}
			e.reset()
			code, _, stderr := e.run(p, "", args...)
			if code != cli.ExitUsage || !strings.Contains(stderr, c.want) || e.f.Calls() != 0 {
				t.Errorf("%v (terminal %v): exit %d, %s, %d requests", args, p != nil, code, stderr, e.f.Calls())
			}
			if p != nil {
				p.Done()
			}
		}
	}
	// The former form without --name, or with an empty one, writes to the
	// apex: an apex CNAME is refused there too, before any request.
	for _, cmd := range []string{"add", "upsert"} {
		for _, name := range [][]string{nil, {"--name", ""}} {
			args := append(append([]string{"godaddy", "dns", cmd, "example.com"}, name...), "--type", "CNAME", "--value", "target.example.net")
			e.reset()
			code, _, stderr := e.run(nil, "", args...)
			if code != cli.ExitUsage || !strings.Contains(stderr, "does not take a CNAME at the zone apex") || e.f.Calls() != 0 {
				t.Errorf("%v: exit %d, %s, %d requests", args, code, stderr, e.f.Calls())
			}
		}
	}
}
