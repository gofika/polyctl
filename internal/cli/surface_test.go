package cli

import (
	"encoding/json"
	"errors"
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
	// json and yaml output carry the path in a field, like every command.
	if out, err := run("inventory", "path", "-o", "json"); err != nil || !jsonPathIs(out, filepath.Join(envDir, "inventory.db")) {
		t.Errorf("inventory path -o json = %q, %v", out, err)
	}
	if out, err := run("inventory", "path", "-o", "yaml"); err != nil || !strings.HasPrefix(strings.TrimSpace(out), "path: ") {
		t.Errorf("inventory path -o yaml = %q, %v", out, err)
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
		// The projects of a Google Cloud account.
		"gcp project list", "gcp project current", "gcp project use", "gcp project add", "gcp project remove",
		// The accounts of a Cloudflare login.
		"cloudflare account list", "cloudflare account current", "cloudflare account use", "cloudflare account add", "cloudflare account remove",
		// One identity check, at the top of every tree.
		"aws whoami", "gcp whoami", "aliyun whoami", "cloudflare whoami", "namecom whoami", "godaddy whoami",
		// The Cloudflare tree under its platform id and its alias.
		"cloudflare dns list", "cf dns list", "cf whoami",
		// Zones: lifecycle and settings.
		"cloudflare zone create", "cloudflare zone ensure", "cloudflare zone delete",
		"cloudflare zone setting list", "cloudflare zone setting get", "cloudflare zone setting set",
		// Cache and redirect rules.
		"cloudflare cache purge", "cloudflare cache rule list", "cloudflare cache rule set",
		"cloudflare redirect rule list", "cloudflare redirect rule set",
		// R2: buckets and their custom domains.
		"cloudflare r2 bucket list", "cloudflare r2 domain list", "cloudflare r2 domain get", "cloudflare r2 domain attach",
		"cloudflare r2 domain update", "cloudflare r2 domain detach", "cloudflare r2 domain ensure",
		// Compute trees name the resource.
		"aws ec2 instance list", "aws ec2 instance start", "aws ec2 instance stop",
		"aws ec2 instance get", "aws ec2 instance create", "aws ec2 instance delete", "aws ec2 instance terminate",
		"aws ec2 instance reboot", "aws ec2 instance resize",
		"aws ec2 key-pair list", "aws ec2 key-pair import", "aws ec2 key-pair ensure",
		"aws ec2 security-group list", "aws ec2 security-group get", "aws ec2 security-group create", "aws ec2 security-group delete",
		"aws ec2 security-group ensure", "aws ec2 security-group rule add", "aws ec2 security-group rule remove",
		"aws ec2 volume list", "aws ec2 volume get", "aws ec2 volume create", "aws ec2 volume resize",
		"aws ec2 volume attach", "aws ec2 volume detach", "aws ec2 volume delete",
		"aws ec2 snapshot list", "aws ec2 snapshot create",
		"aws elbv2 load-balancer list", "aws elbv2 load-balancer get", "aws elbv2 load-balancer create", "aws elbv2 load-balancer update",
		"aws elbv2 load-balancer delete", "aws elbv2 load-balancer ensure",
		"aws elbv2 target-group list", "aws elbv2 target-group get", "aws elbv2 target-group create", "aws elbv2 target-group update",
		"aws elbv2 target-group delete",
		"aws elbv2 listener list", "aws elbv2 listener get", "aws elbv2 listener create", "aws elbv2 listener update", "aws elbv2 listener delete",
		"aws acm certificate list", "aws acm certificate get", "aws acm certificate request", "aws acm certificate import",
		"aws rds instance list", "aws rds instance get", "aws rds instance create", "aws rds instance start", "aws rds instance stop",
		"aws rds instance resize", "aws rds instance delete", "aws rds instance ensure",
		"gcp compute instance list", "gcp compute instance start", "gcp compute instance stop",
		"gcp compute instance get", "gcp compute instance create", "gcp compute instance delete",
		"gcp compute instance resize", "gcp compute instance reboot", "gcp compute instance update",
		"gcp compute instance terminate",
		"gcp compute network list", "gcp compute network get", "gcp compute subnet list",
		"gcp compute firewall list", "gcp compute firewall get", "gcp compute firewall create", "gcp compute firewall update",
		"gcp compute firewall delete", "gcp compute firewall ensure",
		"gcp compute ssl-certificate list", "gcp compute ssl-certificate create", "gcp compute ssl-certificate update",
		"gcp compute ssl-certificate delete", "gcp compute load-balancer cert set",
		"gcp compute load-balancer ensure", "gcp compute load-balancer list", "gcp compute load-balancer get", "gcp compute load-balancer delete",
		"gcp compute backend-service list", "gcp compute backend-service get", "gcp compute backend-service delete",
		"gcp compute forwarding-rule list", "gcp compute forwarding-rule get", "gcp compute forwarding-rule delete",
		"gcp compute health-check list", "gcp compute health-check get", "gcp compute health-check delete",
		"gcp compute instance-group list", "gcp compute instance-group get", "gcp compute instance-group delete",
		"aliyun ecs instance list", "aliyun ecs instance start", "aliyun ecs instance stop",
		"aliyun ecs instance get", "aliyun ecs instance create", "aliyun ecs instance delete", "aliyun ecs instance reboot",
		"aliyun ecs instance resize", "aliyun ecs instance ensure", "aliyun ecs instance terminate",
		"aliyun ecs security-group list", "aliyun ecs security-group get", "aliyun ecs security-group create",
		"aliyun ecs security-group delete", "aliyun ecs security-group ensure",
		"aliyun ecs security-group rule add", "aliyun ecs security-group rule remove",
		"aliyun ecs key-pair list", "aliyun ecs key-pair import", "aliyun ecs key-pair ensure", "aliyun ecs image latest",
		"aliyun vpc vpc list", "aliyun vpc vpc get", "aliyun vpc vpc create", "aliyun vpc vpc ensure",
		"aliyun vpc vswitch list", "aliyun vpc vswitch get", "aliyun vpc vswitch create", "aliyun vpc vswitch ensure",
		"aliyun eip address list", "aliyun eip address allocate", "aliyun eip address associate", "aliyun eip address ensure",
		"aliyun alb load-balancer list", "aliyun alb load-balancer get", "aliyun alb load-balancer create", "aliyun alb load-balancer update",
		"aliyun alb load-balancer delete", "aliyun alb load-balancer ensure",
		"aliyun alb listener list", "aliyun alb listener get", "aliyun alb listener create", "aliyun alb listener update",
		"aliyun alb listener delete", "aliyun alb listener cert set",
		"aliyun alb server-group list", "aliyun alb server-group get", "aliyun alb server-group create", "aliyun alb server-group update",
		"aliyun alb server-group delete", "aliyun alb server-group server add",
		"aliyun alb acl list", "aliyun alb acl get", "aliyun alb acl create", "aliyun alb acl delete",
		"aliyun alb acl entry add", "aliyun alb acl entry remove",
		"aliyun cas certificate list", "aliyun cas certificate upload", "aliyun cas certificate delete",
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
		"cert ensure", "cert get", "cert deploy",
	}
	for _, path := range exists {
		if find(root, path) == nil {
			t.Errorf("missing command %q", path)
		}
	}
	gone := []string{
		"aws sts", "aws sts whoami", "aliyun sts", "aliyun sts whoami", "namecom hello", "cloudflare token", "cloudflare token verify",
		"aws ec2 list", "aws ec2 start", "aws ec2 stop", "gcp compute list", "gcp compute start", "gcp compute stop",
		"aliyun ecs list", "aliyun ecs start", "aliyun ecs stop", "aws ec2 key-pair delete", "aliyun ecs key-pair delete",
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

// The instance commands of the compute trees take the same flags.
func TestInstanceCommandsAgree(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	trees := []string{"aws ec2 instance", "gcp compute instance", "aliyun ecs instance"}
	for _, tree := range trees {
		// create waits by default and takes --no-wait.
		if c := find(root, tree+" create"); c == nil {
			t.Errorf("%s create is missing", tree)
		} else if f := c.Flags().Lookup("wait"); f == nil || f.DefValue != "true" || c.Flags().Lookup("no-wait") == nil {
			t.Errorf("%s create: --wait %+v, --no-wait %v", tree, f, c.Flags().Lookup("no-wait") != nil)
		}
		// delete, start, stop and reboot take --wait, --no-wait and --timeout.
		for _, verb := range []string{"delete", "start", "stop", "reboot"} {
			c := find(root, tree+" "+verb)
			if c == nil {
				t.Errorf("%s %s is missing", tree, verb)
				continue
			}
			for _, name := range []string{"wait", "no-wait", "timeout"} {
				if c.Flags().Lookup(name) == nil {
					t.Errorf("%s %s has no --%s", tree, verb, name)
				}
			}
		}
		// resize has the same power and port controls.
		if c := find(root, tree+" resize"); c != nil {
			for _, name := range []string{"start", "wait-port", "timeout"} {
				if c.Flags().Lookup(name) == nil {
					t.Errorf("%s resize has no --%s", tree, name)
				}
			}
		}
		// --ssh-key and --ssh-key-file take one key where an instance binds
		// one key pair (AWS, Alibaba Cloud), and repeat on Compute Engine,
		// whose metadata holds any number of keys: a known difference.
		if c := find(root, tree+" create"); c != nil {
			want := "string"
			if tree == "gcp compute instance" {
				want = "stringArray"
			}
			for _, name := range []string{"ssh-key", "ssh-key-file"} {
				if f := c.Flags().Lookup(name); f == nil || f.Value.Type() != want {
					t.Errorf("%s create --%s = %+v, want a %s", tree, name, f, want)
				}
			}
		}
		// delete is also terminate.
		if c := find(root, tree+" delete"); c != nil && !c.HasAlias("terminate") {
			t.Errorf("%s delete lacks the terminate alias", tree)
		}
		// start, stop, delete, reboot and resize take a name or an id.
		for _, verb := range []string{"start", "stop", "delete", "reboot", "resize"} {
			if c := find(root, tree+" "+verb); c != nil && !strings.HasPrefix(c.Use, verb+" <name|id") {
				t.Errorf("%s %s: use %q", tree, verb, c.Use)
			}
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

// Every command that asks for a confirmation is in the one list of them (the
// Confirmations section of docs/interactive.md), and every command of that
// list exists. A command that starts to call rt.Confirm belongs in this table
// and in that list.
func TestDocsListConfirmingCommands(t *testing.T) {
	data, err := os.ReadFile(filepath.Join("..", "..", "docs", "interactive.md"))
	if err != nil {
		t.Fatal(err)
	}
	// A Windows checkout (core.autocrlf) has CRLF line endings.
	doc := strings.ReplaceAll(string(data), "\r\n", "\n")
	start := strings.Index(doc, "### Confirmations\n")
	if start < 0 {
		t.Fatal("docs/interactive.md has no Confirmations section")
	}
	section := doc[start:]
	if end := strings.Index(section[1:], "\n#"); end >= 0 {
		section = section[:end+1]
	}
	bullet := func(label string) string {
		for _, line := range strings.Split(section, "\n") {
			if strings.HasPrefix(line, "- "+label+":") {
				return line
			}
		}
		t.Errorf("Confirmations has no %q bullet", label)
		return ""
	}
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	for _, c := range []struct{ path, label, token string }{
		{"dns delete", "Core", "`dns delete`"},
		{"cert deploy", "Core", "`cert deploy --prune-expired`"},
		{"auth logout", "Accounts", "`auth logout`"},
		{"auth manage", "Accounts", "`auth manage`"},
		{"aws ec2 instance stop", "AWS", "`ec2 instance stop`"},
		{"aws ec2 instance delete", "AWS", "`ec2 instance delete`"},
		{"aws ec2 instance resize", "AWS", "`ec2 instance resize`"},
		{"aws ec2 security-group delete", "AWS", "`ec2 security-group delete`"},
		{"aws ec2 security-group rule remove", "AWS", "`rule remove`"},
		{"aws ec2 volume detach", "AWS", "`ec2 volume detach`"},
		{"aws ec2 volume delete", "AWS", "`delete`"},
		{"aws elbv2 load-balancer delete", "AWS", "`elbv2 load-balancer delete`"},
		{"aws elbv2 target-group delete", "AWS", "`target-group delete`"},
		{"aws elbv2 listener delete", "AWS", "`listener delete`"},
		{"aws rds instance delete", "AWS", "`rds instance delete`"},
		{"gcp compute instance stop", "GCP", "`compute instance stop`"},
		{"gcp compute instance delete", "GCP", "`delete`"},
		{"gcp compute instance reboot", "GCP", "`reboot`"},
		{"gcp compute instance resize", "GCP", "`resize`"},
		{"gcp compute instance password", "GCP", "`password --reset`"},
		{"gcp compute firewall delete", "GCP", "`compute firewall delete`"},
		{"gcp compute ssl-certificate delete", "GCP", "`compute ssl-certificate delete`"},
		{"gcp compute load-balancer delete", "GCP", "`compute load-balancer delete`"},
		{"gcp compute backend-service delete", "GCP", "`compute backend-service`"},
		{"gcp compute forwarding-rule delete", "GCP", "`forwarding-rule`"},
		{"gcp compute health-check delete", "GCP", "`health-check`"},
		{"gcp compute instance-group delete", "GCP", "`instance-group`"},
		{"aliyun ecs instance stop", "Alibaba Cloud", "`ecs instance stop`"},
		{"aliyun ecs instance delete", "Alibaba Cloud", "`delete`"},
		{"aliyun ecs instance reboot", "Alibaba Cloud", "`reboot --force`"},
		{"aliyun ecs instance resize", "Alibaba Cloud", "`resize`"},
		{"aliyun ecs security-group delete", "Alibaba Cloud", "`ecs security-group delete`"},
		{"aliyun ecs security-group rule remove", "Alibaba Cloud", "`rule remove`"},
		{"aliyun alb load-balancer delete", "Alibaba Cloud", "`alb load-balancer delete`"},
		{"aliyun alb listener delete", "Alibaba Cloud", "`listener delete`"},
		{"aliyun alb server-group delete", "Alibaba Cloud", "`server-group delete`"},
		{"aliyun alb acl delete", "Alibaba Cloud", "`acl delete`"},
		{"aliyun cas certificate delete", "Alibaba Cloud", "`cas certificate delete`"},
		{"cloudflare r2 domain detach", "Cloudflare", "`r2 domain detach`"},
		{"cloudflare zone delete", "Cloudflare", "`zone delete`"},
		{"cloudflare cache rule set", "Cloudflare", "`cache rule set --replace`"},
		{"cloudflare redirect rule set", "Cloudflare", "`redirect rule set --replace`"},
		{"godaddy dns delete", "GoDaddy", "`dns delete`"},
		{"aws route53 record delete", "AWS", "`route53 record delete`"},
		{"gcp dns record delete", "GCP", "`dns record delete`"},
	} {
		if find(root, c.path) == nil {
			t.Errorf("confirming command %q does not exist", c.path)
		}
		if line := bullet(c.label); line != "" && !strings.Contains(line, c.token) {
			t.Errorf("docs/interactive.md Confirmations, %s: %s is missing (%s)", c.label, c.token, c.path)
		}
	}
}

// jsonPathIs reports whether out is a JSON object whose "path" is want.
func jsonPathIs(out, want string) bool {
	var v struct {
		Path string `json:"path"`
	}
	return json.Unmarshal([]byte(out), &v) == nil && v.Path == want
}

// ns set re-indexes the zones of the registrar account it changed: a
// registrar that hosts a domain's DNS only while the domain uses its own
// nameservers must not keep routing the domain's records to itself.
func TestDomainNSSetReindexesTheRegistrarZones(t *testing.T) {
	dir, cfgPath := setup(t, true)
	fc := client("a")
	fc.ownNSSuffix = ".registrar.example"
	fc.domains = []platform.Domain{{Name: "example.com", Nameservers: []string{"ns1.registrar.example", "ns2.registrar.example"}}}
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	db := openInventory(t, dir)
	if err := db.Replace(t.Context(), inventory.Set{Platform: fakePlatform, Profile: "a", Type: platform.ResDomain},
		app.DomainResources(fc.domains), 3600e9); err != nil {
		t.Fatal(err)
	}
	db.Close()
	seed(t, dir, fc.zones, nil)

	_, stderr, err := run(t, cfgPath, "domain", "ns", "set", "example.com", "ns1.dns-host.example", "ns2.dns-host.example")
	if err != nil {
		t.Fatalf("ns set: %v (%s)", err, stderr)
	}
	if fc.count("Sync:zone") != 1 || !strings.Contains(stderr, "no longer serves the DNS of example.com") {
		t.Errorf("zone sync count %d, stderr %q", fc.count("Sync:zone"), stderr)
	}
	stdout, _, err := run(t, cfgPath, "domain", "which", "example.com", "--offline", "-o", "json")
	if err != nil || strings.Contains(stdout, `"zone"`) || !strings.Contains(stdout, `"domain"`) {
		t.Errorf("which after ns set = %q, %v", stdout, err)
	}
	if _, _, err := run(t, cfgPath, "dns", "set", "example.com", "--name", "www", "--type", "A", "--value", "203.0.113.10", "--offline"); !errors.Is(err, app.ErrDomainUnknown) {
		t.Errorf("dns set after ns set = %v, want the zone no longer routed to the registrar", err)
	}

	// Back to the registrar's own nameservers: no note.
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	_, stderr, err = run(t, cfgPath, "domain", "ns", "set", "example.com", "ns1.registrar.example", "ns2.registrar.example")
	if err != nil || strings.Contains(stderr, "no longer serves") {
		t.Errorf("ns set back: %v, %q", err, stderr)
	}
}

// --project names the Google Cloud project of one call: on the gcp dns and
// gcp compute commands, which act on resources of a project, and not on
// gcp project, which manages the selection, nor outside the gcp tree.
func TestGCPProjectFlag(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	for path, want := range map[string]bool{
		"gcp dns zone list": true, "gcp dns record upsert": true, "gcp compute instance get": true, "gcp compute firewall list": true,
		"gcp compute load-balancer get": true, "gcp compute ssl-certificate create": true,
		"gcp project list": false, "gcp project use": false, "aws ec2 instance list": false, "dns list": false,
	} {
		c, _, err := root.Find(strings.Fields(path))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := c.Flags().Lookup("project") != nil || c.InheritedFlags().Lookup("project") != nil; got != want {
			t.Errorf("%s: --project present = %v, want %v", path, got, want)
		}
	}
	// A value that cannot be a project id is refused as the flag is read.
	if code, _, stderr := mainExit(t.TempDir(), "gcp", "dns", "zone", "list", "--project", "a/b"); code != ExitUsage || !strings.Contains(stderr, "not a project id") {
		t.Errorf("--project a/b: exit %d, %s", code, stderr)
	}
	for _, sub := range []string{"use", "add", "remove"} {
		if code, _, stderr := mainExit(t.TempDir(), "gcp", "project", sub, "p1", "--dry-run"); code != ExitUsage || !strings.Contains(stderr, "does not support --dry-run") {
			t.Errorf("gcp project %s --dry-run: exit %d, %s", sub, code, stderr)
		}
	}
}

// --account is on the Cloudflare commands that work on zones, and on no
// other command.
func TestCloudflareAccountFlag(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &strings.Builder{}, &strings.Builder{})
	root := NewRoot(rt)
	for path, want := range map[string]bool{
		"cloudflare zone list": true, "cloudflare zone get": true, "cloudflare zone create": true, "cloudflare zone ensure": true,
		"cloudflare zone delete": true, "cloudflare zone setting set": true, "cloudflare dns list": true, "cloudflare dns create": true,
		"cloudflare cache purge": true, "cloudflare cache rule set": true, "cloudflare redirect rule list": true,
		"cloudflare dev-mode": true, "cloudflare ssl-mode": true, "cloudflare r2 bucket list": true, "cloudflare r2 domain ensure": true,
		"cloudflare account list": false, "cloudflare account current": false, "cloudflare account use": false, "cloudflare account add": false,
		"cloudflare account remove": false, "cloudflare whoami": false, "gcp dns zone list": false, "dns list": false, "sync": false,
	} {
		c, _, err := root.Find(strings.Fields(path))
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		if got := c.Flag("account") != nil; got != want {
			t.Errorf("%s: --account present = %v, want %v", path, got, want)
		}
	}
	// The short name of the tree takes it too, and an empty value is
	// refused as the flag is read.
	if code, _, stderr := mainExit(t.TempDir(), "cf", "zone", "list", "--account", " "); code != ExitUsage || !strings.Contains(stderr, "an account id or name is required") {
		t.Errorf("--account ' ': exit %d, %s", code, stderr)
	}
	if code, _, stderr := mainExit(t.TempDir(), "cloudflare", "account", "list", "--account", "acc1"); code != ExitUsage || !strings.Contains(stderr, "unknown flag") {
		t.Errorf("account list --account: exit %d, %s", code, stderr)
	}
	// The commands that change the selection write the local configuration
	// only: there is nothing to preview.
	for _, sub := range []string{"use", "add", "remove"} {
		if code, _, stderr := mainExit(t.TempDir(), "cloudflare", "account", sub, "acc1", "--dry-run"); code != ExitUsage || !strings.Contains(stderr, "does not support --dry-run") {
			t.Errorf("cloudflare account %s --dry-run: exit %d, %s", sub, code, stderr)
		}
	}
}

// auth list names the default project of a Google Cloud account and how
// many more are selected.
func TestMetaSummaryCountsProjects(t *testing.T) {
	for meta, want := range map[string]string{
		"p1|":         "email=a@b project=p1 method=adc",
		"p1|p1":       "email=a@b project=p1 method=adc",
		"p1|p1,p2,p3": "email=a@b project=p1 (+2 more) method=adc",
		"p1|p2":       "email=a@b project=p1 (+1 more) method=adc",
	} {
		def, list, _ := strings.Cut(meta, "|")
		m := map[string]string{"email": "a@b", "project": def, "method": "adc"}
		if list != "" {
			m["projects"] = list
		}
		if got := metaSummary(m); got != want {
			t.Errorf("metaSummary(%v) = %q, want %q", m, got, want)
		}
	}
	id := &platform.Identity{Account: "p1", User: "a@b", Extra: map[string]string{"projects": "p1,p2"}}
	if got := identitySummary(id); got != "p1 (+1 more) a@b" {
		t.Errorf("identitySummary = %q", got)
	}
	if got := identitySummary(&platform.Identity{Account: "p1", User: "a@b"}); got != "p1 a@b" {
		t.Errorf("identitySummary of one project = %q", got)
	}
	// A Cloudflare login counts its selected accounts the same way.
	cf := map[string]string{"account_id": "acc1", "accounts": "acc1,acc2,acc3", "method": "api_token"}
	if got := metaSummary(cf); got != "account_id=acc1 (+2 more) method=api_token" {
		t.Errorf("metaSummary(%v) = %q", cf, got)
	}
	if got := metaSummary(map[string]string{"account_id": "acc1", "method": "api_token"}); got != "account_id=acc1 method=api_token" {
		t.Errorf("metaSummary of one account = %q", got)
	}
	id = &platform.Identity{Account: "acc1", User: "a@b", Extra: map[string]string{"accounts": "acc1,acc2"}}
	if got := identitySummary(id); got != "acc1 (+1 more) a@b" {
		t.Errorf("identitySummary of two accounts = %q", got)
	}
}
