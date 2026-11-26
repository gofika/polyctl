package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// recordsAfter runs one command against a fresh zone holding recs and
// returns the records of the zone afterwards, without their ids.
func recordsAfter(t *testing.T, recs []platform.Record, args ...string) string {
	t.Helper()
	_, cfgPath, fc := ensureZone(t, recs...)
	if _, stderr, err := run(t, cfgPath, args...); err != nil {
		t.Fatalf("%v: %v (stderr %q)", args, err, stderr)
	}
	var b strings.Builder
	for _, r := range fc.records["z1"] {
		prio, proxied := "-", "-"
		if r.Priority != nil {
			prio = fmt.Sprint(*r.Priority)
		}
		if r.Proxied != nil {
			proxied = fmt.Sprint(*r.Proxied)
		}
		fmt.Fprintf(&b, "%s %s %q ttl=%d prio=%s proxied=%s\n", r.Name, r.Type, r.Value, r.TTL, prio, proxied)
	}
	return b.String()
}

// The positional record <name> <type> <value>... writes and deletes what
// the flags of the former form do.
func TestDNSPositionalRecordMatchesFlagForm(t *testing.T) {
	existing := []platform.Record{
		{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.1", TTL: 300},
		{ID: "r2", ZoneID: "z1", Name: "example.com", Type: "TXT", Value: "v=spf1 -all", TTL: 300},
		{ID: "r3", ZoneID: "z1", Name: "example.com", Type: "TXT", Value: "other", TTL: 300},
	}
	for name, c := range map[string]struct {
		positional, flags []string
		want              string
	}{
		"set create": {
			[]string{"dns", "set", "example.com", "api", "a", "203.0.113.10", "--ttl", "120"},
			[]string{"dns", "set", "example.com", "--name", "api", "--type", "A", "--value", "203.0.113.10", "--ttl", "120"},
			`api.example.com A "203.0.113.10" ttl=120`,
		},
		"set update": {
			[]string{"dns", "set", "example.com", "www", "A", "203.0.113.9"},
			[]string{"dns", "set", "example.com", "--name", "www", "--type", "A", "--value", "203.0.113.9"},
			`www.example.com A "203.0.113.9" ttl=300`,
		},
		"set apex with priority": {
			[]string{"dns", "set", "example.com", "@", "MX", "mail.example.com", "--priority", "10"},
			[]string{"dns", "set", "example.com", "--name", "@", "--type", "MX", "--value", "mail.example.com", "--priority", "10"},
			`example.com MX "mail.example.com" ttl=0 prio=10`,
		},
		"set full name, proxied": {
			[]string{"dns", "set", "example.com", "cdn.example.com", "CNAME", "target.example.net", "--proxied"},
			[]string{"dns", "set", "example.com", "--name", "cdn.example.com", "--type", "CNAME", "--value", "target.example.net", "--proxied"},
			`cdn.example.com CNAME "target.example.net" ttl=0 prio=- proxied=true`,
		},
		"set value after --": {
			[]string{"dns", "set", "example.com", "dash", "TXT", "--", "-starts-with-a-dash"},
			[]string{"dns", "set", "example.com", "--name", "dash", "--type", "TXT", "--value", "-starts-with-a-dash"},
			`dash.example.com TXT "-starts-with-a-dash"`,
		},
		"add": {
			[]string{"dns", "add", "example.com", "www", "A", "203.0.113.2"},
			[]string{"dns", "add", "example.com", "--name", "www", "--type", "A", "--value", "203.0.113.2"},
			`www.example.com A "203.0.113.2"`,
		},
		"ensure one value": {
			[]string{"dns", "ensure", "example.com", "alias", "cname", "target.example.net"},
			[]string{"dns", "ensure", "example.com", "-r", "alias:CNAME:target.example.net"},
			`alias.example.com CNAME "target.example.net"`,
		},
		"ensure a set with a TTL": {
			[]string{"dns", "ensure", "example.com", "rr", "A", "203.0.113.5", "203.0.113.6", "--ttl", "60"},
			[]string{"dns", "ensure", "example.com", "-r", "rr:A:203.0.113.5:60", "-r", "rr:A:203.0.113.6:60"},
			`rr.example.com A "203.0.113.6" ttl=60`,
		},
		"ensure MX values": {
			[]string{"dns", "ensure", "example.com", "@", "MX", "10 mx1.example.com", "20 mx2.example.com"},
			[]string{"dns", "ensure", "example.com", "-r", "@:MX:10 mx1.example.com", "-r", "@:MX:20 mx2.example.com"},
			`example.com MX "mx2.example.com" ttl=0 prio=20`,
		},
		"ensure proxied, auto TTL": {
			[]string{"dns", "ensure", "example.com", "www", "A", "203.0.113.1", "--ttl", "auto", "--proxied"},
			[]string{"dns", "ensure", "example.com", "-r", "www:A:203.0.113.1:auto:true"},
			`www.example.com A "203.0.113.1" ttl=300 prio=- proxied=true`,
		},
		"ensure with a priority": {
			[]string{"dns", "ensure", "example.com", "@", "MX", "mail.example.com", "--priority", "10"},
			[]string{"dns", "ensure", "example.com", "-r", "@:MX:10 mail.example.com"},
			`example.com MX "mail.example.com" ttl=0 prio=10`,
		},
		// "true" and "false" are a name or a value like any other, also
		// beside --proxied.
		"set a name true, proxied": {
			[]string{"dns", "set", "example.com", "true", "A", "203.0.113.4", "--proxied"},
			[]string{"dns", "set", "example.com", "--name", "true", "--type", "A", "--value", "203.0.113.4", "--proxied"},
			`true.example.com A "203.0.113.4" ttl=0 prio=- proxied=true`,
		},
		"add a value true, not proxied": {
			[]string{"dns", "add", "example.com", "flag", "TXT", "true", "--proxied=false"},
			[]string{"dns", "add", "example.com", "--name", "flag", "--type", "TXT", "--value", "true", "--proxied=false"},
			`flag.example.com TXT "true" ttl=0 prio=- proxied=false`,
		},
		"ensure a value false, proxied": {
			[]string{"dns", "ensure", "example.com", "flag", "CNAME", "false", "--ttl", "auto", "--proxied"},
			[]string{"dns", "ensure", "example.com", "-r", "flag:CNAME:false:auto:true"},
			`flag.example.com CNAME "false" ttl=1 prio=- proxied=true`,
		},
		"ensure with --record": {
			[]string{"dns", "ensure", "example.com", "api", "A", "203.0.113.7", "-r", "api2:A:203.0.113.8"},
			[]string{"dns", "ensure", "example.com", "-r", "api:A:203.0.113.7", "-r", "api2:A:203.0.113.8"},
			`api2.example.com A "203.0.113.8"`,
		},
		"delete name and type": {
			[]string{"dns", "delete", "example.com", "@", "txt", "--yes"},
			[]string{"dns", "delete", "example.com", "--name", "@", "--type", "txt", "--yes"},
			"",
		},
		"delete one value": {
			[]string{"dns", "delete", "example.com", "@", "TXT", "v=spf1 -all"},
			[]string{"dns", "delete", "example.com", "--name", "@", "--type", "TXT", "--value", "v=spf1 -all"},
			`example.com TXT "other"`,
		},
	} {
		got, want := recordsAfter(t, existing, c.positional...), recordsAfter(t, existing, c.flags...)
		if got != want {
			t.Errorf("%s: positional form left\n%swant, as the flag form\n%s", name, got, want)
		}
		if !strings.Contains(got, c.want) {
			t.Errorf("%s: %q is missing in\n%s", name, c.want, got)
		}
	}
	// What was deleted is gone, not merely the same in both forms.
	if got := recordsAfter(t, existing, "dns", "delete", "example.com", "@", "TXT", "--yes"); strings.Contains(got, "TXT") {
		t.Errorf("delete @ TXT left\n%s", got)
	}
	if got := recordsAfter(t, existing, "dns", "delete", "example.com", "@", "TXT", "v=spf1 -all"); strings.Contains(got, "spf1") {
		t.Errorf("delete @ TXT <value> left\n%s", got)
	}
}

// A positional record beside the flags of the former form, a wrong number
// of arguments, and options that do not go with a positional record are
// usage errors before the zone is read.
func TestDNSPositionalRecordUsage(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, fiveRecords()...)
	const (
		setUsage    = "usage: polyctl dns set <domain> <name> <type> <value>"
		addUsage    = "usage: polyctl dns add <domain> <name> <type> <value>"
		ensureUsage = "usage: polyctl dns ensure <domain> <name> <type> <value>..."
		deleteUsage = "usage: polyctl dns delete <domain> <name> [<type> [<value>]]"
	)
	for _, c := range []struct {
		args []string
		want string
	}{
		// Both forms.
		{[]string{"dns", "set", "example.com", "www", "A", "192.0.2.9", "--name", "www"}, "use one form"},
		{[]string{"dns", "set", "example.com", "www", "A", "192.0.2.9", "--type", "A"}, "use one form"},
		{[]string{"dns", "add", "example.com", "www", "A", "192.0.2.9", "--value", "192.0.2.9"}, "use one form"},
		{[]string{"dns", "delete", "example.com", "h1", "A", "--name", "h1"}, "use one form"},
		{[]string{"dns", "delete", "example.com", "h1", "A", "--type", "A"}, "use one form"},
		{[]string{"dns", "delete", "example.com", "h1", "A", "--value", "192.0.2.1"}, "use one form"},
		// Wrong counts.
		{[]string{"dns", "set"}, setUsage},
		{[]string{"dns", "set", "example.com"}, setUsage},
		{[]string{"dns", "set", "example.com", "www"}, setUsage},
		{[]string{"dns", "set", "example.com", "www", "A"}, setUsage},
		{[]string{"dns", "set", "example.com", "www", "A", "192.0.2.9", "192.0.2.10"}, setUsage},
		{[]string{"dns", "add", "example.com", "www", "A"}, addUsage},
		{[]string{"dns", "add", "example.com", "www", "A", "192.0.2.9", "192.0.2.10"}, addUsage},
		{[]string{"dns", "ensure", "example.com"}, ensureUsage},
		{[]string{"dns", "ensure", "example.com", "www"}, ensureUsage},
		{[]string{"dns", "ensure", "example.com", "www", "A"}, ensureUsage},
		{[]string{"dns", "delete", "example.com"}, deleteUsage},
		{[]string{"dns", "delete", "example.com", "h1", "A", "192.0.2.1", "192.0.2.2"}, deleteUsage},
		// Empty arguments.
		{[]string{"dns", "set", "example.com", "", "A", "192.0.2.9"}, "<name> must not be empty"},
		{[]string{"dns", "set", "example.com", "www", "A", ""}, "<value> must not be empty"},
		// A name outside the zone is named as the argument.
		{[]string{"dns", "set", "example.com", "www.other.org", "A", "192.0.2.9"}, "<name>:"},
		{[]string{"dns", "delete", "example.com", "www.other.org.", "A"}, "<name>:"},
		// --all and --id select on their own.
		{[]string{"dns", "delete", "example.com", "h1", "A", "--all", "-y"}, "--all cannot be combined with a positional record (<name> [<type> [<value>]])"},
		{[]string{"dns", "delete", "example.com", "h1", "A", "--id", "r1"}, "--id selects one record; it cannot be combined with <name> [<type> [<value>]]"},
		{[]string{"dns", "delete", "example.com", "--id", ""}, "--id must not be empty"},
		{[]string{"dns", "delete", "example.com", "--id", "r1", "--type", "A"}, "--id selects one record; it cannot be combined with --name, --type or --value"},
		{[]string{"dns", "delete", "example.com", "--type", "A", "--type", "TXT"}, "--type takes one record type without --all"},
		{[]string{"dns", "delete", "example.com", "www", "A,TXT"}, "<type> is one record type"},
		// <type> of delete is one type; the text names the argument.
		{[]string{"dns", "delete", "example.com", "h1", "A,AAAA"}, "<type> is one record type: " + deleteUsage},
		// The record options of ensure belong to the positional record.
		{[]string{"dns", "ensure", "example.com", "-r", "www:A:192.0.2.9", "--ttl", "300"}, "--ttl applies to a positional record"},
		{[]string{"dns", "ensure", "example.com", "-r", "www:A:192.0.2.9", "--priority", "10"}, "--priority applies to a positional record"},
		{[]string{"dns", "ensure", "example.com", "-r", "www:A:192.0.2.9", "--proxied"}, "--proxied applies to a positional record"},
		{[]string{"dns", "ensure", "example.com", "www", "A", "192.0.2.9", "--ttl", "soon"}, `--ttl "soon" is not a number of seconds or auto`},
		{[]string{"dns", "ensure", "example.com", "@", "MX", "10 mail.example.com", "--priority", "20"}, "the priority is given twice (10 in the value, 20 as priority)"},
		// A stray value of --proxied is named where it cannot be part of
		// the record.
		{[]string{"dns", "set", "example.com", "www", "A", "192.0.2.9", "--proxied", "true"}, "--proxied takes no separate value"},
		{[]string{"dns", "add", "example.com", "--proxied", "false", "www", "A", "192.0.2.9"}, "--proxied takes no separate value"},
		{[]string{"dns", "ensure", "example.com", "-r", "www:A:192.0.2.9", "--proxied", "true"}, "--proxied takes no separate value"},
		// Among the values of ensure it is a value, refused as one.
		{[]string{"dns", "ensure", "example.com", "www", "A", "192.0.2.9", "--proxied", "true"}, `value "true" is not an IPv4 address`},
	} {
		code, _, stderr := mainRun(cfgPath, c.args...)
		if code != ExitUsage || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: exit %d, stderr %q; want exit %d with %q", c.args, code, stderr, ExitUsage, c.want)
		}
	}
	if writes(fc) != 0 || fc.count("ListRecords") != 0 {
		t.Errorf("a usage error reached the platform: %v", fc.calls)
	}
	// No match for a positional record is "not found", as with the flags.
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "h1", "A", "192.0.2.99"); code != ExitNotFound {
		t.Errorf("delete without a match: exit %d (%s)", code, stderr)
	}
}

// With only the domain the interactive flow asks for the record: its name
// (never taken to be the apex), its type and its value.
func TestDNSAddWithOnlyTheDomainAsks(t *testing.T) {
	_, cfgPath, fc := ensureZone(t,
		platform.Record{ID: "r1", ZoneID: "z1", Name: "example.com", Type: "A", Value: "203.0.113.10", TTL: 300},
		platform.Record{ID: "r2", ZoneID: "z1", Name: "mail.example.com", Type: "MX", Value: "mx.example.net", TTL: 300})
	p := prompttest.New(t, "@", "A", "203.0.113.20")
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "add", "example.com")
	if r.err != nil || fc.count("CreateRecord:example.com:A") != 1 || len(fc.records["z1"]) != 3 {
		t.Fatalf("add: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	p.Done()
	if a := p.Find("Record name in example.com"); prompttest.Labels(a.Options) != "@ (apex)  A\nmail  MX\nAnother name..." {
		t.Errorf("names offered:\n%s", prompttest.Labels(a.Options))
	}
	// add proposes no current value.
	if a := p.Find("Value of the A record"); a.Default != "" {
		t.Errorf("add proposed %q", a.Default)
	}
}

// A record that stops after its name or its type is completed on a
// terminal: the type the name already has is preselected, and dns set
// proposes the current value. A name can be typed in.
func TestDNSWriteCompletesAPartialRecord(t *testing.T) {
	_, cfgPath, fc := ensureZone(t,
		platform.Record{ID: "r1", ZoneID: "z1", Name: "mail.example.com", Type: "MX", Value: "mx.example.net", TTL: 300})
	p := prompttest.New(t, "MX", prompttest.KeepDefault{})
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "set", "example.com", "mail", "--dry-run")
	if r.err != nil {
		t.Fatalf("set <name>: %v, %q", r.err, r.stderr)
	}
	p.Done()
	if a := p.Find("Record type"); a.Default != "MX" {
		t.Errorf("type preselected %q", a.Default)
	}
	if a := p.Find("Value of the MX record"); a.Default != "mx.example.net" {
		t.Errorf("value proposed %q", a.Default)
	}
	p = prompttest.New(t, "192.0.2.9")
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "add", "example.com", "new", "a")
	if r.err != nil || fc.count("CreateRecord:new.example.com:A") != 1 {
		t.Fatalf("add <name> <type>: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	p.Done()
	// A name typed in, checked as it is typed: one outside the zone is
	// asked again.
	p = prompttest.New(t, prompttest.Label("Another name"), "www.example.org.", "api", "A", "192.0.2.10")
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "set", "example.com")
	if r.err != nil || fc.count("CreateRecord:api.example.com:A") != 1 {
		t.Fatalf("typed name: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	p.Done()
	// The former flag form without --name is asked for the name too.
	p = prompttest.New(t, "mail")
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "add", "example.com", "--type", "TXT", "--value", "hello")
	if r.err != nil || fc.count("CreateRecord:mail.example.com:TXT") != 1 {
		t.Fatalf("flag form: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	p.Done()
	// A <domain> below its zone names the record: nothing is asked.
	p = prompttest.New(t)
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "add", "deep.example.com", "--type", "TXT", "--value", "hello")
	if r.err != nil || fc.count("CreateRecord:deep.example.com:TXT") != 1 {
		t.Fatalf("domain below the zone: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	// The non-interactive flow asks nothing: a partial record is a usage
	// error, and the former flag form without --name still writes to the
	// apex.
	writesBefore := writes(fc)
	for _, args := range [][]string{{"example.com", "www"}, {"example.com", "www", "A"}} {
		r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append([]string{"dns", "set"}, args...)...)
		if r.code != ExitUsage || !strings.Contains(r.err.Error(), "usage: polyctl dns set <domain> <name> <type> <value>") {
			t.Errorf("non-interactive %v: exit %d, %v", args, r.code, r.err)
		}
	}
	if writes(fc) != writesBefore {
		t.Errorf("a usage error wrote: %v", fc.calls)
	}
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "add", "example.com", "--type", "TXT", "--value", "apex")
	if r.err != nil || fc.count("CreateRecord:example.com:TXT") != 1 {
		t.Fatalf("non-interactive flag form: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
}

// dns ensure without a record, --record and --file asks for one record on
// a terminal, its values until one is left empty; with --record nothing is
// asked.
func TestDNSEnsureAsksForARecord(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 300})
	p := prompttest.New(t, "www", "TXT", "one", "two", "")
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com")
	if r.err != nil || fc.count("CreateRecord:www.example.com:TXT") != 2 {
		t.Fatalf("ensure: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	p.Done()
	// A record that stops after its name: the one type is preselected and
	// the current value proposed.
	p = prompttest.New(t, "A", prompttest.KeepDefault{}, "")
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "www", "--dry-run")
	if r.err != nil {
		t.Fatalf("ensure <name>: %v, %q", r.err, r.stderr)
	}
	p.Done()
	if a := p.Find("Value of the A record"); a.Default != "203.0.113.10" {
		t.Errorf("value proposed %q", a.Default)
	}
	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t), strings.NewReader(""), "dns", "ensure", "example.com", "-r", "www:A:203.0.113.10", "--dry-run")
	if r.err != nil {
		t.Fatalf("ensure --record: %v, %q", r.err, r.stderr)
	}
	for _, args := range [][]string{{"example.com"}, {"example.com", "www"}, {"example.com", "www", "A"}} {
		r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append([]string{"dns", "ensure"}, args...)...)
		if r.code != ExitUsage || !strings.Contains(r.err.Error(), "usage: polyctl dns ensure <domain> <name> <type> <value>...") {
			t.Errorf("non-interactive %v: exit %d, %v", args, r.code, r.err)
		}
	}
}

// The help shows the positional form; the flags of the former form are
// hidden, except --type of dns delete, which --all reads.
func TestDNSPositionalRecordHelp(t *testing.T) {
	dir, cfgPath := setup(t, true)
	for cmd, use := range map[string]string{
		"set":    "polyctl dns set <domain> <name> <type> <value> [flags]",
		"add":    "polyctl dns add <domain> <name> <type> <value> [flags]",
		"ensure": "polyctl dns ensure <domain> [<name> <type> <value>...] [flags]",
		"delete": "polyctl dns delete <domain> [<name> [<type> [<value>]]] [flags]",
	} {
		code, help, stderr := mainExit(dir, "dns", cmd, "--help")
		if code != ExitOK || !strings.Contains(help, use) || !strings.Contains(help, "polyctl dns "+cmd+" example.com ") {
			t.Errorf("dns %s --help: exit %d, stderr %q, want %q and an example in\n%s", cmd, code, stderr, use, help)
		}
		for _, f := range []string{"--name ", "--value "} {
			if strings.Contains(help, "  "+f) {
				t.Errorf("dns %s --help lists %s:\n%s", cmd, f, help)
			}
		}
		if listed := strings.Contains(help, "      --type "); listed != (cmd == "delete") {
			t.Errorf("dns %s --help lists --type: %v\n%s", cmd, listed, help)
		}
	}
	// The <type> position completes record types; the name and the values
	// complete to nothing rather than to file names.
	for _, cmd := range []string{"set", "add", "ensure"} {
		out, _, err := run(t, cfgPath, cobra.ShellCompRequestCmd, "dns", cmd, "example.com", "www", "")
		if err != nil || !strings.Contains(out, "CNAME\n") || !strings.Contains(out, ":4\n") {
			t.Errorf("completion of the type of dns %s: %v\n%s", cmd, err, out)
		}
		out, _, err = run(t, cfgPath, cobra.ShellCompRequestCmd, "dns", cmd, "example.com", "")
		if err != nil || strings.Contains(out, "CNAME") || !strings.Contains(out, ":4\n") {
			t.Errorf("completion of the name of dns %s: %v\n%s", cmd, err, out)
		}
	}
}

// dns delete completes what the zone holds in the inventory, whatever the
// platform: the names, the types of a name and the values of a type.
func TestDNSDeleteCompletion(t *testing.T) {
	_, cfgPath, _ := ensureZone(t,
		platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.10"},
		platform.Record{ID: "r2", ZoneID: "z1", Name: "www.example.com", Type: "TXT", Value: "hello"},
		platform.Record{ID: "r3", ZoneID: "z1", Name: "example.com", Type: "MX", Value: "mail.example.com"})
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"example.com", ""}, "@\tMX mail.example.com\nwww\tA 203.0.113.10, TXT hello\n:4\n"},
		{[]string{"example.com", "www", ""}, "A\nTXT\n:4\n"},
		{[]string{"example.com", "www", "txt", ""}, "hello\n:4\n"},
		{[]string{"example.com", "www", "A", "203.0.113.10", ""}, ":4\n"},
		{[]string{"other.org", ""}, ":4\n"},
	} {
		code, stdout, stderr := mainRun(cfgPath, append([]string{"__complete", "dns", "delete"}, c.args...)...)
		if code != ExitOK || stdout != c.want {
			t.Errorf("%v: exit %d, completion %q, want %q (%s)", c.args, code, stdout, c.want, stderr)
		}
	}
}

// Without a platform the <type> position completes every type of a record
// spec; the name and the values complete to nothing.
func TestDNSRecordTypeCompletion(t *testing.T) {
	_, cfgPath, _ := ensureZone(t)
	for _, verb := range []string{"set", "add", "ensure"} {
		code, stdout, stderr := mainRun(cfgPath, "__complete", "dns", verb, "example.com", "www", "")
		if code != ExitOK || !strings.HasPrefix(stdout, strings.Join(platform.RecordSpecTypes, "\n")+"\n:") {
			t.Errorf("%s: exit %d, completion %q (%s)", verb, code, stdout, stderr)
		}
		code, stdout, _ = mainRun(cfgPath, "__complete", "dns", verb, "example.com", "www", "A", "")
		if code != ExitOK || !strings.HasPrefix(stdout, ":") {
			t.Errorf("%s: exit %d, a value completes to %q", verb, code, stdout)
		}
	}
}
