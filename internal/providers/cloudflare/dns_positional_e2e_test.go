package cloudflare_test

import (
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// newRecordEnv is a zoneEnv with the zone example.com in the account of the
// current profile; post is the key of the request that creates a record.
func newRecordEnv(t *testing.T) (e *zoneEnv, post string) {
	t.Helper()
	e = newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "free", "active")
	return e, "POST /zones/" + z.id + "/dns_records"
}

// dns create with the record as arguments sends what the former flags
// send.
func TestDNSCreatePositionalMatchesFlagForm(t *testing.T) {
	for _, c := range []struct {
		name       string
		positional []string
		flags      []string
		want       map[string]any
	}{
		{"relative name", []string{"www", "A", "203.0.113.10"}, []string{"--name", "www", "--type", "A", "--value", "203.0.113.10"},
			map[string]any{"name": "www.example.com", "type": "A", "content": "203.0.113.10"}},
		{"apex and lower-case type", []string{"@", "txt", "v=spf1 -all"}, []string{"--name", "@", "--type", "txt", "--value", "v=spf1 -all"},
			map[string]any{"name": "example.com", "type": "TXT", "content": "v=spf1 -all"}},
		{"full name with options", []string{"mail.example.com", "MX", "mx.example.net", "--priority", "10", "--ttl", "300", "--comment", "mail"},
			[]string{"--name", "mail.example.com", "--type", "MX", "--value", "mx.example.net", "--priority", "10", "--ttl", "300", "--comment", "mail"},
			map[string]any{"name": "mail.example.com", "type": "MX", "content": "mx.example.net", "priority": float64(10), "ttl": float64(300), "comment": "mail"}},
		{"proxied before the record", []string{"--proxied", "www", "CNAME", "target.example.net"}, []string{"--proxied", "--name", "www", "--type", "CNAME", "--value", "target.example.net"},
			map[string]any{"name": "www.example.com", "type": "CNAME", "content": "target.example.net", "proxied": true}},
		{"value after --", []string{"www", "TXT", "--", "-dash"}, []string{"--name", "www", "--type", "TXT", "--value=-dash"},
			map[string]any{"name": "www.example.com", "type": "TXT", "content": "-dash"}},
	} {
		t.Run(c.name, func(t *testing.T) {
			e, post := newRecordEnv(t)
			var sent []map[string]any
			for _, form := range [][]string{c.positional, c.flags} {
				e.f.reset()
				code, _, stderr := e.run(append([]string{"cloudflare", "dns", "create", "example.com"}, form...)...)
				if code != cli.ExitOK {
					t.Fatalf("%v: exit %d, %s", form, code, stderr)
				}
				body := e.f.body(post)
				for k, v := range c.want {
					if !reflect.DeepEqual(body[k], v) {
						t.Errorf("%v: %s = %v, want %v (body %v)", form, k, body[k], v, body)
					}
				}
				sent = append(sent, body)
			}
			if !reflect.DeepEqual(sent[0], sent[1]) {
				t.Errorf("the positional form sent %v, the flag form %v", sent[0], sent[1])
			}
		})
	}
}

// Both forms at once, a wrong number of arguments and an empty argument are
// usage errors that show the positional form, and nothing is written.
func TestDNSCreatePositionalUsage(t *testing.T) {
	e, _ := newRecordEnv(t)
	const usage = "usage: polyctl cloudflare dns create <zone> <name> <type> <value>"
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
		{[]string{"example.com", "www", "A", "203.0.113.10", "--proxied", "true"}, "--proxied takes no separate value"},
		{[]string{"example.com", "--type", "A"}, usage},
	} {
		e.f.reset()
		code, _, stderr := e.run(append([]string{"cloudflare", "dns", "create"}, c.args...)...)
		if code != cli.ExitUsage || !strings.Contains(stderr, c.want) {
			t.Errorf("%v: exit %d, %s; want %q", c.args, code, stderr, c.want)
		}
		if w := e.f.writes(); len(w) != 0 {
			t.Errorf("%v wrote %v", c.args, w)
		}
	}
}

// With only the zone the interactive flow still asks for the type and the
// value; the record is then at the zone apex.
func TestDNSCreateWithOnlyTheZoneAsks(t *testing.T) {
	e, post := newRecordEnv(t)
	p := prompttest.New(t, "A", "203.0.113.10")
	code, _, stderr := e.runPick(p, "cloudflare", "dns", "create", "example.com")
	if code != cli.ExitOK {
		t.Fatalf("exit %d, %s", code, stderr)
	}
	p.Done()
	if b := e.f.body(post); b["name"] != "example.com" || b["type"] != "A" || b["content"] != "203.0.113.10" {
		t.Errorf("created %v", b)
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position completes the record types.
func TestDNSCreatePositionalHelp(t *testing.T) {
	root := cli.NewRoot(app.New(app.Flags{}, strings.NewReader(""), new(strings.Builder), new(strings.Builder)))
	cmd, _, err := root.Find([]string{"cloudflare", "dns", "create"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Use != "create <zone> <name> <type> <value>" || !strings.Contains(cmd.Example, "dns create example.com www A 203.0.113.10") || strings.Contains(cmd.Example, "--value") {
		t.Errorf("use %q, example %q", cmd.Use, cmd.Example)
	}
	for _, name := range []string{"name", "type", "value"} {
		if f := cmd.Flags().Lookup(name); f == nil || !f.Hidden {
			t.Errorf("--%s should exist and be hidden", name)
		}
	}
	for _, name := range []string{"ttl", "priority", "proxied", "comment"} {
		if f := cmd.Flags().Lookup(name); f == nil || f.Hidden {
			t.Errorf("--%s should be listed", name)
		}
	}
	types, dir := cmd.ValidArgsFunction(cmd, []string{"example.com", "www"}, "")
	if dir != cobra.ShellCompDirectiveNoFileComp || !contains(types, "CNAME") {
		t.Errorf("type completion: %v, %v", types, dir)
	}
	if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example.com"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
		t.Errorf("name completion: %v, %v", vals, dir)
	}
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
