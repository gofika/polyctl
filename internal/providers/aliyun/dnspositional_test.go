package aliyun

import (
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// createHarness is a harness whose alidns fake records the parameters of
// every AddDomainRecord as "DomainName RR Type Value TTL Priority Line".
func createHarness(t *testing.T, flags app.Flags) (*harness, *[]string) {
	t.Helper()
	h := newHarness(t, flags)
	added := &[]string{}
	h.api.on("AddDomainRecord", func(q url.Values) (int, any) {
		var f []string
		for _, k := range []string{"DomainName", "RR", "Type", "Value", "TTL", "Priority", "Line"} {
			f = append(f, k+"="+q.Get(k))
		}
		*added = append(*added, strings.Join(f, " "))
		return 200, map[string]any{"RecordId": "9001"}
	})
	h.api.on("DescribeDomainRecordInfo", func(q url.Values) (int, any) {
		return 200, map[string]any{"RecordId": "9001", "RR": "www", "Type": "A", "Value": "203.0.113.9", "TTL": 600, "DomainName": "example.com"}
	})
	return h, added
}

// dns record create with the record as arguments sends what the former
// flags send.
func TestDNSRecordCreatePositionalMatchesFlagForm(t *testing.T) {
	h, added := createHarness(t, app.Flags{NonInteractive: true})
	for _, c := range []struct {
		name       string
		positional []string
		flags      []string
		want       string
	}{
		{"relative name", []string{"www", "A", "203.0.113.10"}, []string{"--name", "www", "--type", "A", "--value", "203.0.113.10"},
			"DomainName=example.com RR=www Type=A Value=203.0.113.10 TTL= Priority= Line=default"},
		{"apex, lower-case type, options", []string{"@", "mx", "mail.example.net", "--priority", "10", "--ttl", "900", "--line", "telecom"},
			[]string{"--name", "@", "--type", "mx", "--value", "mail.example.net", "--priority", "10", "--ttl", "900", "--line", "telecom"},
			"DomainName=example.com RR=@ Type=MX Value=mail.example.net TTL=900 Priority=10 Line=telecom"},
		{"full name, a value with spaces", []string{"a.b.example.com", "TXT", "v=spf1 -all"}, []string{"--name", "a.b.example.com", "--type", "TXT", "--value", "v=spf1 -all"},
			"DomainName=example.com RR=a.b Type=TXT Value=v=spf1 -all TTL= Priority= Line=default"},
		{"value after --", []string{"new", "TXT", "--", "-dash"}, []string{"--name", "new", "--type", "TXT", "--value=-dash"},
			"DomainName=example.com RR=new Type=TXT Value=-dash TTL= Priority= Line=default"},
	} {
		t.Run(c.name, func(t *testing.T) {
			*added = nil
			for _, form := range [][]string{c.positional, c.flags} {
				if err := h.run(append([]string{"dns", "record", "create", "example.com"}, form...)...); err != nil {
					t.Fatalf("%v: %v\n%s", form, err, h.stderr.String())
				}
			}
			if len(*added) != 2 || (*added)[0] != (*added)[1] || (*added)[0] != c.want {
				t.Errorf("positional and flags sent %q; want twice %q", *added, c.want)
			}
		})
	}
}

// Both forms at once, a wrong number of arguments and an empty argument are
// usage errors that show the positional form, and nothing is sent.
func TestDNSRecordCreatePositionalUsage(t *testing.T) {
	h, added := createHarness(t, app.Flags{NonInteractive: true})
	const usage = "usage: aliyun dns record create <domain> <name> <type> <value>"
	for _, c := range []struct {
		args []string
		want string
	}{
		{nil, usage},
		{[]string{"example.com"}, usage},
		{[]string{"example.com", "www"}, usage},
		{[]string{"example.com", "www", "A"}, usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "203.0.113.11"}, usage},
		{[]string{"example.com", "--type", "A"}, usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "--name", "www"}, "with --name; use one form: " + usage},
		{[]string{"example.com", "www", "A", "203.0.113.10", "--type", "A"}, "with --type; use one form"},
		{[]string{"example.com", "www", "A", "203.0.113.10", "--value", "203.0.113.11"}, "with --value; use one form"},
		{[]string{"example.com", "", "A", "203.0.113.10"}, "<name> must not be empty"},
		{[]string{"example.com", "www", "", "203.0.113.10"}, "<type> must not be empty"},
		{[]string{"example.com", "www", "A", ""}, "<value> must not be empty"},
	} {
		err := h.run(append([]string{"dns", "record", "create"}, c.args...)...)
		if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%v = %v; want a usage error with %q", c.args, err, c.want)
		}
		if len(*added) != 0 {
			t.Fatalf("%v sent %v", c.args, *added)
		}
	}
}

// With only the domain, dns record create still asks for the type and the
// value; the record is then at the apex.
func TestDNSRecordCreateWithOnlyTheDomainAsks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, added := createHarness(t, app.Flags{})
	seedZones(t, h, platform.ResZone, "example.com")
	p := prompttest.New(t, "TXT", "hello")
	h.rt.Picker = p
	if err := h.run("dns", "record", "create", "example.com"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if len(*added) != 1 || (*added)[0] != "DomainName=example.com RR=@ Type=TXT Value=hello TTL= Priority= Line=default" {
		t.Errorf("sent %q", *added)
	}
}

// The help shows the positional form and no longer lists the former flags,
// and the <type> position completes the record types. record update keeps
// its flags: they are the optional fields to change.
func TestDNSRecordCreatePositionalHelp(t *testing.T) {
	h, _ := createHarness(t, app.Flags{NonInteractive: true})
	cmd, _, err := Command(h.rt).Find([]string{"dns", "record", "create"})
	if err != nil {
		t.Fatal(err)
	}
	if cmd.Use != "create <domain> <name> <type> <value>" || !strings.Contains(cmd.Example, "record create example.com www A") || strings.Contains(cmd.Example, "--type") {
		t.Errorf("use %q, example %q", cmd.Use, cmd.Example)
	}
	for _, name := range []string{"name", "type", "value"} {
		if f := cmd.Flags().Lookup(name); f == nil || !f.Hidden {
			t.Errorf("--%s should exist and be hidden", name)
		}
	}
	for _, name := range []string{"ttl", "priority", "line"} {
		if f := cmd.Flags().Lookup(name); f == nil || f.Hidden {
			t.Errorf("--%s should be listed", name)
		}
	}
	types, dir := cmd.ValidArgsFunction(cmd, []string{"example.com", "www"}, "")
	if dir != cobra.ShellCompDirectiveNoFileComp || !strings.Contains(" "+strings.Join(types, " ")+" ", " CNAME ") {
		t.Errorf("type completion %v, %v", types, dir)
	}
	if vals, dir := cmd.ValidArgsFunction(cmd, []string{"example.com"}, ""); dir != cobra.ShellCompDirectiveNoFileComp || len(vals) != 0 {
		t.Errorf("name completion %v, %v", vals, dir)
	}
	update, _, err := Command(h.rt).Find([]string{"dns", "record", "update"})
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"name", "type", "value"} {
		if f := update.Flags().Lookup(name); f == nil || f.Hidden {
			t.Errorf("update: --%s should be listed", name)
		}
	}
}
