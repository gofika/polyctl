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
		del    = "usage: polyctl godaddy dns delete <domain> <name> <type>"
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
		{[]string{"delete", "example.com", "--yes"}, "a record or --id is required: " + del},
		{[]string{"delete", "example.com", "www", "--yes"}, del},
		{[]string{"delete", "example.com", "www", "A", "203.0.113.1", "--yes"}, del},
		{[]string{"delete", "example.com", "www", "A", "--name", "www", "--yes"}, "with --name; use one form: " + del},
		{[]string{"delete", "example.com", "www", "A", "--type", "A", "--yes"}, "with --type; use one form: " + del},
		{[]string{"delete", "example.com", "www", "A", "--id", recordID, "--yes"}, "--id selects one record; it cannot be combined with <name> <type>"},
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

// With only the domain the interactive flow still asks: add and upsert for
// the type and the value (the record is then at the apex), delete for the
// record.
func TestDNSRecordWithOnlyTheDomainAsks(t *testing.T) {
	e := newDeleteEnv(t)
	for _, verb := range []string{"add", "upsert"} {
		e.reset()
		p := prompttest.New(t, "TXT", "asked")
		code, _, stderr := e.run(p, "", "godaddy", "dns", verb, "example.com")
		if code != cli.ExitOK {
			t.Fatalf("%s: exit %d, %s", verb, code, stderr)
		}
		p.Done()
		if got := e.records(); got != "A www 203.0.113.1,A www 203.0.113.2,TXT @ asked,TXT www hello" {
			t.Errorf("%s wrote %q", verb, got)
		}
	}
	e.reset()
	p := prompttest.New(t, prompttest.Label("hello"))
	code, _, stderr := e.run(p, "y\n", "godaddy", "dns", "delete", "example.com")
	if code != cli.ExitOK {
		t.Fatalf("delete: exit %d, %s", code, stderr)
	}
	p.Done()
	if got := e.records(); got != "A www 203.0.113.1,A www 203.0.113.2" {
		t.Errorf("delete left %q", got)
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position completes the record types.
func TestDNSPositionalRecordHelp(t *testing.T) {
	root := cli.NewRoot(app.New(app.Flags{}, strings.NewReader(""), new(strings.Builder), new(strings.Builder)))
	for verb, use := range map[string]string{
		"add":    "add <domain> <name> <type> <value>",
		"upsert": "upsert <domain> <name> <type> <value>...",
		"delete": "delete <domain> [<name> <type>]",
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
		types, dir := cmd.ValidArgsFunction(cmd, []string{"example.com", "www"}, "")
		if dir != cobra.ShellCompDirectiveNoFileComp || !strings.Contains(" "+strings.Join(types, " ")+" ", " CNAME ") {
			t.Errorf("%s: type completion %v, %v", verb, types, dir)
		}
		if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example.com"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
			t.Errorf("%s: name completion %v, %v", verb, vals, dir)
		}
	}
}
