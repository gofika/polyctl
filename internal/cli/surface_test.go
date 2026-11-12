package cli

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// These tests pin the command-line surface that freezes at 1.0: the names
// of flags, variables and commands, and the rules they follow.

// Every setting is resolved flag > environment > config file > default.
// For the output format that is --output, POLYCTL_OUTPUT, then the output
// key of config.yaml, then table.
func TestOutputFormatPrecedence(t *testing.T) {
	_, cfgPath := setup(t, true)
	isJSON := func(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "[") }
	isYAML := func(s string) bool { return strings.HasPrefix(strings.TrimSpace(s), "- ") }
	isTable := func(s string) bool { return strings.HasPrefix(s, "PROFILE") || strings.Contains(s, "PLATFORM") }

	// Default.
	if out, _, err := run(t, cfgPath, "auth", "list"); err != nil || !isTable(out) {
		t.Errorf("default = %q, %v; want a table", out, err)
	}
	// Config file.
	cfg := loadConfig(t, cfgPath)
	cfg.Output = "yaml"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	if out, _, err := run(t, cfgPath, "auth", "list"); err != nil || !isYAML(out) {
		t.Errorf("config output: yaml = %q, %v", out, err)
	}
	// The environment beats the config file.
	t.Setenv(app.EnvOutput, "json")
	if out, _, err := run(t, cfgPath, "auth", "list"); err != nil || !isJSON(out) {
		t.Errorf("POLYCTL_OUTPUT=json over config yaml = %q, %v", out, err)
	}
	// The flag beats both.
	if out, _, err := run(t, cfgPath, "auth", "list", "-o", "table"); err != nil || !isTable(out) {
		t.Errorf("-o table over POLYCTL_OUTPUT=json = %q, %v", out, err)
	}
	// An invalid value in the variable is reported, not skipped.
	t.Setenv(app.EnvOutput, "xml")
	if _, _, err := run(t, cfgPath, "auth", "list"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("POLYCTL_OUTPUT=xml = %v, want a usage error", err)
	}
}

// --config-dir names the directory POLYCTL_CONFIG_DIR names, and wins over
// it: config.yaml, the file credential store and inventory.db all live
// there.
func TestConfigDirFlagBeatsEnvironment(t *testing.T) {
	envDir, _ := setup(t, true) // POLYCTL_CONFIG_DIR = envDir, with profile a
	flagDir := filepath.Join(t.TempDir(), "other")

	run := func(args ...string) (string, error) {
		t.Helper()
		var out, errb strings.Builder
		rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
		root := NewRoot(rt)
		root.SetArgs(args)
		root.SetOut(&out)
		root.SetErr(&errb)
		err := root.ExecuteContext(t.Context())
		_ = rt.Close()
		return out.String(), err
	}
	// Without the flag the variable decides.
	if out, err := run("auth", "list"); err != nil || !strings.Contains(out, "a") || strings.Contains(out, "no profiles") {
		t.Errorf("POLYCTL_CONFIG_DIR: %q, %v", out, err)
	}
	if out, err := run("inventory", "path"); err != nil || strings.TrimSpace(out) != filepath.Join(envDir, "inventory.db") {
		t.Errorf("inventory path = %q, %v", out, err)
	}
	// With the flag everything moves: the other directory has no profile,
	// and the login below writes config, credentials and (later) the
	// inventory there.
	if out, err := run("--config-dir", flagDir, "inventory", "path"); err != nil || strings.TrimSpace(out) != filepath.Join(flagDir, "inventory.db") {
		t.Errorf("--config-dir inventory path = %q, %v", out, err)
	}
	if _, err := run("--config-dir", flagDir, "auth", "login", p1, "--profile", "fresh", "--set", "token=x"); err != nil {
		t.Fatalf("login with --config-dir: %v", err)
	}
	other, err := config.Load(filepath.Join(flagDir, config.FileName))
	if err != nil || other.Profiles["fresh"] == nil {
		t.Errorf("config.yaml in --config-dir: %+v, %v", other, err)
	}
	files, _ := os.ReadDir(flagDir)
	var names []string
	for _, f := range files {
		names = append(names, f.Name())
	}
	if len(names) < 2 {
		t.Errorf("--config-dir holds %v; want config.yaml and the file credential store", names)
	}
	before, err := os.ReadFile(filepath.Join(envDir, config.FileName))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(before), "fresh") {
		t.Errorf("--config-dir wrote into the POLYCTL_CONFIG_DIR directory:\n%s", before)
	}
	// The old flag is gone.
	if _, err := run("--config", filepath.Join(flagDir, config.FileName), "auth", "list"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("--config = %v, want an unknown flag", err)
	}
}

// --no-browser belongs to the commands that can run a login flow.
func TestNoBrowserIsLocalToLoginAndManage(t *testing.T) {
	_, cfgPath := setup(t, true)
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	if f := root.PersistentFlags().Lookup("no-browser"); f != nil {
		t.Error("--no-browser is still a global flag")
	}
	var with []string
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if c.Flags().Lookup("no-browser") != nil {
			with = append(with, c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	walk(root)
	if want := []string{"polyctl auth login", "polyctl auth manage"}; !reflect.DeepEqual(with, want) {
		t.Errorf("commands with --no-browser = %v, want %v", with, want)
	}
	if _, _, err := run(t, cfgPath, "auth", "login", p1, "--profile", "a", "--no-browser", "--set", "token=x"); err != nil {
		t.Errorf("auth login --no-browser: %v", err)
	}
	if _, _, err := run(t, cfgPath, "dns", "list", "example.com", "--no-browser"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("dns list --no-browser = %v, want an unknown flag", err)
	}
}

// --proxied is a boolean with three states: given, given as false, and not
// given (keep what the record has).
func TestDNSProxiedIsABooleanFlag(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, nil)
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	find := func(name string) *platform.Record {
		t.Helper()
		for i, r := range fc.records["z1"] {
			if r.Name == name {
				return &fc.records["z1"][i]
			}
		}
		t.Fatalf("no record %s in %+v", name, fc.records["z1"])
		return nil
	}
	set := func(args ...string) {
		t.Helper()
		if _, stderr, err := run(t, cfgPath, append([]string{"dns"}, args...)...); err != nil {
			t.Fatalf("dns %v: %v (stderr %q)", args, err, stderr)
		}
	}

	set("add", "example.com", "--type", "A", "--name", "on", "--value", "192.0.2.1", "--proxied")
	if r := find("on.example.com"); r.Proxied == nil || !*r.Proxied {
		t.Errorf("--proxied: %+v", r)
	}
	set("add", "example.com", "--type", "A", "--name", "off", "--value", "192.0.2.2", "--proxied=false")
	if r := find("off.example.com"); r.Proxied == nil || *r.Proxied {
		t.Errorf("--proxied=false: %+v", r)
	}
	set("add", "example.com", "--type", "A", "--name", "unset", "--value", "192.0.2.3")
	if r := find("unset.example.com"); r.Proxied != nil {
		t.Errorf("without --proxied the record must not carry one: %+v", r)
	}
	// An update without the flag keeps the setting; with it, changes it.
	set("set", "example.com", "--type", "A", "--name", "on", "--value", "192.0.2.9")
	if r := find("on.example.com"); r.Value != "192.0.2.9" || r.Proxied == nil || !*r.Proxied {
		t.Errorf("set without --proxied: %+v", r)
	}
	set("set", "example.com", "--type", "A", "--name", "on", "--value", "192.0.2.9", "--proxied=false")
	if r := find("on.example.com"); r.Proxied == nil || *r.Proxied {
		t.Errorf("set --proxied=false: %+v", r)
	}
	// The old string form took its value from the next argument; a boolean
	// flag does not, so that argument is one too many.
	if _, _, err := run(t, cfgPath, "dns", "set", "example.com", "--type", "A", "--name", "on", "--value", "192.0.2.9", "--proxied", "false"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("--proxied false (two arguments) = %v, want a usage error", err)
	}
	if _, _, err := run(t, cfgPath, "dns", "set", "example.com", "--type", "A", "--name", "on", "--value", "192.0.2.9", "--proxied=maybe"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("--proxied=maybe = %v, want a usage error", err)
	}
}

// Nameservers are positional: one argument each, or a comma-separated
// list, or both.
func TestDomainNSSetTakesPositionalNameservers(t *testing.T) {
	dir, cfgPath := setup(t, true)
	db := openInventory(t, dir)
	if err := db.Replace(t.Context(), inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResDomain},
		app.DomainResources([]platform.Domain{{Name: "example.com"}}), 3600e9); err != nil {
		t.Fatal(err)
	}
	db.Close()
	fc := client("a")
	for _, tc := range []struct {
		args []string
		want []string
	}{
		{[]string{"ns1.example.net", "ns2.example.net"}, []string{"ns1.example.net", "ns2.example.net"}},
		{[]string{"NS1.example.net.,ns2.example.net"}, []string{"ns1.example.net", "ns2.example.net"}},
		{[]string{"ns1.example.net,ns2.example.net", "ns3.example.net"}, []string{"ns1.example.net", "ns2.example.net", "ns3.example.net"}},
		{[]string{"ns1.example.net"}, []string{"ns1.example.net"}},
	} {
		fc.domains = []platform.Domain{{Name: "example.com"}}
		args := append([]string{"domain", "ns", "set", "example.com"}, tc.args...)
		if _, stderr, err := run(t, cfgPath, args...); err != nil {
			t.Errorf("%v: %v (stderr %q)", args, err, stderr)
			continue
		}
		if got := fc.domains[0].Nameservers; !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%v set %v, want %v", args, got, tc.want)
		}
	}
	calls := fc.count("SetNameservers")
	for _, args := range [][]string{
		{"domain", "ns", "set"},
		{"domain", "ns", "set", "example.com"},
		{"domain", "ns", "set", "example.com", "ns1.example.net,,ns2.example.net"},
		{"domain", "ns", "set", "example.com", "--ns", "ns1.example.net,ns2.example.net"},
	} {
		_, _, err := run(t, cfgPath, args...)
		if ExitCodeFor(err) != ExitUsage {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
	if _, _, err := run(t, cfgPath, "domain", "ns", "set", "example.com"); err == nil || !strings.Contains(err.Error(), "at least one nameserver is required") {
		t.Errorf("missing nameservers = %v", err)
	}
	if fc.count("SetNameservers") != calls {
		t.Errorf("a refused command reached the platform: %v", fc.calls)
	}
}

// inventory list takes its --platform and --type filters as lists, in the
// syntax sync uses.
func TestInventoryListFiltersAreLists(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{
		"z1": {{ID: "r1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"}},
	})
	db := openInventory(t, dir)
	if err := db.Replace(t.Context(), inventory.Set{Platform: fakePlatform2, Profile: "b", Type: platform.ResDomain},
		app.DomainResources([]platform.Domain{{Name: "other.example"}}), 3600e9); err != nil {
		t.Fatal(err)
	}
	db.Close()

	list := func(args ...string) string {
		t.Helper()
		out, stderr, err := run(t, cfgPath, append([]string{"inventory", "list", "-o", "json"}, args...)...)
		if err != nil {
			t.Fatalf("inventory list %v: %v (stderr %q)", args, err, stderr)
		}
		var rows []inventory.Resource
		if err := json.Unmarshal([]byte(out), &rows); err != nil {
			t.Fatalf("inventory list %v: %v\n%s", args, err, out)
		}
		var got []string
		for _, r := range rows {
			got = append(got, string(r.Platform)+"/"+string(r.Type))
		}
		return strings.Join(got, " ")
	}
	zone, rec, dom := p1+"/zone", p1+"/dns_record", p2+"/domain"
	for _, tc := range []struct {
		args []string
		want string
	}{
		{nil, strings.Join([]string{rec, zone, dom}, " ")},
		{[]string{"--type", "zone"}, zone},
		{[]string{"--type", "zone,domain"}, zone + " " + dom},
		{[]string{"--type", "zone", "--type", "dns_record"}, rec + " " + zone},
		{[]string{"--platform", p1}, rec + " " + zone},
		{[]string{"--platform", p1 + "," + p2}, strings.Join([]string{rec, zone, dom}, " ")},
		{[]string{"--platform", "cf", "--platform", "gd", "--type", "domain"}, dom},
		{[]string{"--platform", p2, "--type", "zone"}, ""},
	} {
		if got := list(tc.args...); got != tc.want {
			t.Errorf("inventory list %v = %q, want %q", tc.args, got, tc.want)
		}
	}
	for _, args := range [][]string{{"--type", "zone,bogus"}, {"--platform", p1 + ",nosuch"}} {
		if _, _, err := run(t, cfgPath, append([]string{"inventory", "list"}, args...)...); ExitCodeFor(err) != ExitUsage {
			t.Errorf("inventory list %v = %v, want a usage error", args, err)
		}
	}
	// Same help wording and the same completion as on sync.
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	syncCmd, _, _ := root.Find([]string{"sync"})
	listCmd, _, _ := root.Find([]string{"inventory", "list"})
	for _, name := range []string{"platform", "type"} {
		s, l := syncCmd.Flags().Lookup(name), listCmd.Flags().Lookup(name)
		if s == nil || l == nil || s.Value.Type() != l.Value.Type() || strings.Replace(s.Usage, "only sync these", "", 1) != strings.Replace(l.Usage, "only list these", "", 1) {
			t.Errorf("--%s differs between sync and inventory list: %+v vs %+v", name, s, l)
		}
	}
}

// The routing --platform of dns and domain reads differently from the
// filters of sync and inventory list.
func TestRoutePlatformHelp(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	for _, group := range []string{"dns", "domain"} {
		c, _, _ := root.Find([]string{group})
		f := c.PersistentFlags().Lookup("platform")
		if f == nil || f.Usage != "route to the account on this platform" || f.Value.Type() != "string" {
			t.Errorf("%s --platform = %+v", group, f)
		}
	}
}

// find resolves a command path below root, or nil when the path names no
// command of its own.
func find(root *cobra.Command, path string) *cobra.Command {
	fields := strings.Fields(path)
	c, rest, err := root.Find(fields)
	if err != nil || len(rest) != 0 || c == nil || c.Name() != fields[len(fields)-1] && !c.HasAlias(fields[len(fields)-1]) {
		return nil
	}
	return c
}

// The same operation has the same verb and shape in every platform tree.
func TestPlatformTreeShapes(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)

	exists := []string{
		// One identity check, at the top of every tree.
		"aws whoami", "gcp whoami", "aliyun whoami", "cloudflare whoami", "namecom whoami", "godaddy whoami",
		// The Cloudflare tree under its platform id and its alias.
		"cloudflare dns list", "cf dns list", "cf whoami",
		// Compute trees name the resource.
		"aws ec2 instance list", "aws ec2 instance start", "aws ec2 instance stop",
		"gcp compute instance list", "gcp compute instance start", "gcp compute instance stop",
		"aliyun ecs instance list", "aliyun ecs instance start", "aliyun ecs instance stop",
		// Registrar groups: list, get, ns get|set directly below the group.
		"aws route53domains list", "aws route53domains get", "aws route53domains ns get", "aws route53domains ns set",
		"namecom domain list", "namecom domain get", "namecom domain ns get", "namecom domain ns set", "namecom domain check",
		"godaddy domain list", "godaddy domain get", "godaddy domain ns get", "godaddy domain ns set", "godaddy domain check",
		"aliyun domain list", "aliyun domain get", "aliyun domain ns get", "aliyun domain ns set",
		// Single-record platforms: create / update / delete.
		"cloudflare dns create", "namecom dns create", "aliyun dns record create",
		// Record-set platforms: upsert.
		"aws route53 record upsert", "gcp dns record upsert", "godaddy dns upsert", "godaddy dns add",
		// Core.
		"dns set", "dns add", "dns list", "dns delete", "domain ns set", "domain which",
	}
	for _, path := range exists {
		if find(root, path) == nil {
			t.Errorf("missing command %q", path)
		}
	}
	gone := []string{
		"aws sts", "aws sts whoami", "aliyun sts", "aliyun sts whoami", "namecom hello", "cloudflare token", "cloudflare token verify",
		"aws ec2 list", "aws ec2 start", "aws ec2 stop", "gcp compute list", "gcp compute start", "gcp compute stop",
		"aliyun ecs list", "aliyun ecs start", "aliyun ecs stop",
		"aws route53domains domain", "aws route53domains domain list", "aws route53domains domain get",
		"godaddy domain available", "godaddy dns replace", "aliyun dns record add", "dns update",
	}
	for _, path := range gone {
		if c := find(root, path); c != nil {
			t.Errorf("%q still exists (%s)", path, c.CommandPath())
		}
	}

	// Every `ns set` takes its nameservers as arguments and has no --ns.
	for _, path := range []string{"domain ns set", "aws route53domains ns set", "namecom domain ns set", "godaddy domain ns set", "aliyun domain ns set"} {
		c := find(root, path)
		if c == nil {
			continue
		}
		if c.Use != "set <domain> <nameserver>..." || c.Flags().Lookup("ns") != nil {
			t.Errorf("%s: use %q, --ns %v", path, c.Use, c.Flags().Lookup("ns") != nil)
		}
		for n, wantErr := range map[int]bool{0: true, 1: true, 2: false, 4: false} {
			err := c.Args(c, make([]string, n))
			if (err != nil) != wantErr || err != nil && ExitCodeFor(err) != ExitUsage {
				t.Errorf("%s with %d argument(s) = %v", path, n, err)
			}
		}
	}

	// The record id is positional where it is required, and a flag where it
	// is one of two ways to address a record.
	for _, path := range []string{"cloudflare dns update", "cloudflare dns delete", "namecom dns update", "namecom dns delete", "aliyun dns record update", "aliyun dns record delete"} {
		c := find(root, path)
		if c == nil {
			continue
		}
		if !strings.HasSuffix(c.Use, " <record-id>") || c.Flags().Lookup("id") != nil {
			t.Errorf("%s: use %q, --id %v", path, c.Use, c.Flags().Lookup("id") != nil)
		}
		if err := c.Args(c, []string{"example.com"}); ExitCodeFor(err) != ExitUsage {
			t.Errorf("%s without the record id = %v", path, err)
		}
	}
	for _, path := range []string{"dns delete", "godaddy dns delete", "gcp dns record delete"} {
		if c := find(root, path); c == nil || c.Flags().Lookup("id") == nil {
			t.Errorf("%s must keep its optional --id", path)
		}
	}

	// --proxied is a boolean wherever it exists.
	for _, path := range []string{"dns set", "dns add", "cloudflare dns create", "cloudflare dns update"} {
		c := find(root, path)
		if f := c.Flags().Lookup("proxied"); f == nil || f.Value.Type() != "bool" {
			t.Errorf("%s --proxied = %+v", path, f)
		}
	}
	// --add went away with `dns add`.
	for _, path := range []string{"dns set", "dns add"} {
		if find(root, path).Flags().Lookup("add") != nil {
			t.Errorf("%s still has --add", path)
		}
	}
}

// whoami has the same output shape in every tree.
func TestWhoamiShape(t *testing.T) {
	_, cfgPath := setupMulti(t)
	for tree, id := range map[string]platform.ID{"cloudflare": fakePlatform, "cf": fakePlatform, "godaddy": fakePlatform2} {
		out, stderr, err := run(t, cfgPath, tree, "whoami", "--profile", "a", "-o", "json")
		if err != nil {
			t.Errorf("%s whoami: %v (stderr %q)", tree, err, stderr)
			continue
		}
		var w app.Whoami
		if err := json.Unmarshal([]byte(out), &w); err != nil || w.Profile != "a" || w.Platform != id || w.Identity == nil {
			t.Errorf("%s whoami = %s (%v)", tree, out, err)
		}
		var raw map[string]any
		_ = json.Unmarshal([]byte(out), &raw)
		if len(raw) != 3 || raw["profile"] == nil || raw["platform"] == nil || raw["identity"] == nil {
			t.Errorf("%s whoami keys = %v, want profile, platform, identity", tree, raw)
		}
		table, _, err := run(t, cfgPath, tree, "whoami", "--profile", "a")
		if err != nil || !strings.HasPrefix(table, "PROFILE") || !strings.Contains(table, "PLATFORM  "+string(id)) || !strings.Contains(table, "ACCOUNT") || !strings.Contains(table, "USER") {
			t.Errorf("%s whoami table = %q, %v", tree, table, err)
		}
		if _, _, err := run(t, cfgPath, tree, "whoami", "--profile", "a", "--offline"); ExitCodeFor(err) != ExitOffline {
			t.Errorf("%s whoami --offline = %v", tree, err)
		}
	}
}
