package namecom_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/providers/namecom"
)

type recordEnv struct {
	t   *testing.T
	dir string
	f   *namecom.Fake
}

// newRecordEnv logs a profile in to a fake name.com API that holds the
// domain example.com without records.
func newRecordEnv(t *testing.T) *recordEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	t.Setenv(app.EnvNonInteractive, "")
	e := &recordEnv{t: t, dir: dir, f: namecom.NewFake(t, "example.com")}
	if code, _, stderr := e.run(nil, "auth", "login", "namecom", "--profile", "nc", "--set", "username="+namecom.TestUser, "--set", "token="+namecom.TestToken, "--set", "env=test"); code != cli.ExitOK {
		t.Fatalf("login: exit %d, %s", code, stderr)
	}
	return e
}

// run executes the command line. A picker makes the run interactive (as a
// terminal would).
func (e *recordEnv) run(p *prompttest.Picker, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
	if p != nil {
		rt.Picker = p
	}
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
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

func (e *recordEnv) records() string { return strings.Join(e.f.Records("example.com"), ",") }

// dns create with the record as arguments writes what the former flags
// write.
func TestDNSCreatePositionalMatchesFlagForm(t *testing.T) {
	e := newRecordEnv(t)
	for _, c := range []struct {
		name       string
		positional []string
		flags      []string
		want       string
	}{
		{"relative name", []string{"www", "A", "203.0.113.10"}, []string{"--name", "www", "--type", "A", "--value", "203.0.113.10"}, "www A 203.0.113.10 0 -"},
		{"apex and lower-case type", []string{"@", "txt", "v=spf1 -all"}, []string{"--name", "@", "--type", "txt", "--value", "v=spf1 -all"}, "@ TXT v=spf1 -all 0 -"},
		{"full name with options", []string{"mail.example.com", "MX", "mx.example.net", "--priority", "10", "--ttl", "300"},
			[]string{"--name", "mail.example.com", "--type", "MX", "--value", "mx.example.net", "--priority", "10", "--ttl", "300"}, "mail MX mx.example.net 300 10"},
		{"value after --", []string{"www", "TXT", "--", "-dash"}, []string{"--name", "www", "--type", "TXT", "--value=-dash"}, "www TXT -dash 0 -"},
	} {
		t.Run(c.name, func(t *testing.T) {
			for _, form := range [][]string{c.positional, c.flags} {
				e.f.Reset()
				code, _, stderr := e.run(nil, append([]string{"namecom", "dns", "create", "example.com"}, form...)...)
				if code != cli.ExitOK {
					t.Fatalf("%v: exit %d, %s", form, code, stderr)
				}
				if got := e.records(); got != c.want {
					t.Errorf("%v wrote %q, want %q", form, got, c.want)
				}
			}
		})
	}
}

// Both forms at once, a wrong number of arguments and an empty argument are
// usage errors that show the positional form, and nothing is written.
func TestDNSCreatePositionalUsage(t *testing.T) {
	e := newRecordEnv(t)
	const usage = "usage: polyctl namecom dns create <domain> <name> <type> <value>"
	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{}, usage},
		{[]string{"example.com"}, usage},
		{[]string{"example.com", "www"}, usage},
		{[]string{"example.com", "www", "A"}, usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "203.0.113.11"}, usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "--name", "www"}, "with --name; use one form: " + usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "--type", "A"}, "with --type; use one form: " + usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "--value", "203.0.113.10"}, "with --value; use one form: " + usage},
		{[]string{"example.com", "", "A", "203.0.113.10"}, "<name> must not be empty"},
		{[]string{"example.com", "www", "", "203.0.113.10"}, "<type> must not be empty"},
		{[]string{"example.com", "www", "A", ""}, "<value> must not be empty"},
		{[]string{"example.com", "--type", "A"}, usage},
	} {
		code, _, stderr := e.run(nil, append([]string{"namecom", "dns", "create"}, c.args...)...)
		if code != cli.ExitUsage || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: exit %d, %s; want %q", c.args, code, stderr, c.want)
		}
		if got := e.records(); got != "" {
			t.Errorf("%v wrote %q", c.args, got)
		}
	}
}

// With only the domain the interactive flow still asks for the type and the
// value; the record is then at the apex.
func TestDNSCreateWithOnlyTheDomainAsks(t *testing.T) {
	e := newRecordEnv(t)
	p := prompttest.New(t, "A", "203.0.113.10")
	code, _, stderr := e.run(p, "namecom", "dns", "create", "example.com")
	if code != cli.ExitOK {
		t.Fatalf("exit %d, %s", code, stderr)
	}
	p.Done()
	if got := e.records(); got != "@ A 203.0.113.10 0 -" {
		t.Errorf("created %q", got)
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position completes the record types.
func TestDNSCreatePositionalHelp(t *testing.T) {
	root := cli.NewRoot(app.New(app.Flags{}, strings.NewReader(""), new(strings.Builder), new(strings.Builder)))
	cmd, _, err := root.Find([]string{"namecom", "dns", "create"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Use != "create <domain> <name> <type> <value>" || !strings.Contains(cmd.Example, "dns create example.com www A 203.0.113.10") || strings.Contains(cmd.Example, "--value") {
		t.Errorf("use %q, example %q", cmd.Use, cmd.Example)
	}
	for _, name := range []string{"name", "type", "value"} {
		if f := cmd.Flags().Lookup(name); f == nil || !f.Hidden {
			t.Errorf("--%s should exist and be hidden", name)
		}
	}
	for _, name := range []string{"ttl", "priority"} {
		if f := cmd.Flags().Lookup(name); f == nil || f.Hidden {
			t.Errorf("--%s should be listed", name)
		}
	}
	types, dir := cmd.ValidArgsFunction(cmd, []string{"example.com", "www"}, "")
	found := false
	for _, v := range types {
		found = found || v == "CNAME"
	}
	if dir != cobra.ShellCompDirectiveNoFileComp || !found {
		t.Errorf("type completion: %v, %v", types, dir)
	}
	if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example.com"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
		t.Errorf("name completion: %v, %v", vals, dir)
	}
}
