package cli

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// mainExit runs Main against the test's config directory.
func mainExit(dir string, args ...string) (code int, stdout, stderr string) {
	var out, errb bytes.Buffer
	code = Main(append([]string{"--config-dir", dir}, args...), strings.NewReader(""), &out, &errb)
	return code, out.String(), errb.String()
}

// A --set key the platform does not know is a usage error before the login
// starts: a removed spelling must never be dropped silently, which could
// log in with other credentials than the ones the caller named.
func TestAuthLoginRejectsUnknownSetKeys(t *testing.T) {
	dir, _ := setup(t, false)
	clearLoginEnv(t)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"aliyun", "--set", "from_cli=prod"}, `unknown login option "from_cli" for aliyun (valid: access_key_id, access_key_secret, region, site, aliyun_profile)`},
		{[]string{"aliyun", "--set", "access_key_id=LTAIone", "--set", "from_cli=-"}, `unknown login option "from_cli" for aliyun`},
		{[]string{"namecom", "--set", "user=alice"}, `unknown login option "user" for namecom (valid: username, token, env)`},
		{[]string{"aws", "--set", "profile=dev"}, `unknown login option "profile" for aws`},
		{[]string{"gcp", "--set", "keyfile=k.json"}, `unknown login option "keyfile" for gcp (valid: method, project, key_file, client_id, client_secret)`},
		{[]string{p2, "--set", "key=K", "--set", "secret=S"}, `unknown login option "key" for ` + p2},
		{[]string{p2, "--set", "secret=S"}, `unknown login option "secret" for ` + p2},
	} {
		code, _, stderr := mainExit(dir, append([]string{"auth", "login", "--profile", "x"}, tc.args...)...)
		if code != ExitUsage || !strings.Contains(stderr, tc.want) {
			t.Errorf("auth login %v: exit %d, stderr %q; want exit %d with %q", tc.args, code, stderr, ExitUsage, tc.want)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "config.yaml")); err == nil {
		t.Error("a refused login wrote config.yaml")
	}
	// Every provider declares the options its login reads.
	for _, p := range platform.Providers() {
		if len(p.LoginOptions()) == 0 {
			t.Errorf("%s declares no login options", p.ID())
		}
	}
}

// The list flags complete every element, not only the first: the values
// already typed stay in front of the candidates.
func TestListFlagCompletion(t *testing.T) {
	_, cfgPath := setup(t, false)
	for _, tc := range []struct {
		args      []string
		want, not []string
	}{
		{[]string{"inventory", "list", "--platform", ""}, []string{"cloudflare\t", "namecom\t"}, nil},
		{[]string{"inventory", "list", "--platform", "cloudflare,"}, []string{"cloudflare,namecom\t", "cloudflare,aws\t"}, []string{"cloudflare,cloudflare", "\nnamecom"}},
		{[]string{"sync", "--platform", "aws,gcp,"}, []string{"aws,gcp,aliyun\t"}, []string{"aws,gcp,aws", "aws,gcp,gcp"}},
		{[]string{"inventory", "list", "--type", "zone,d"}, []string{"zone,domain\n", "zone,dns_record\n"}, []string{"zone,zone", "\ndomain"}},
		{[]string{"sync", "--type", ""}, []string{"domain\n", "zone\n", "dns_record\n", "instance\n"}, nil},
	} {
		stdout, _, err := run(t, cfgPath, append([]string{cobra.ShellCompRequestCmd}, tc.args...)...)
		if err != nil {
			t.Fatalf("%v: %v", tc.args, err)
		}
		for _, w := range tc.want {
			if !strings.Contains("\n"+stdout, w) {
				t.Errorf("%v: missing %q in\n%s", tc.args, w, stdout)
			}
		}
		for _, n := range tc.not {
			if strings.Contains("\n"+stdout, n) {
				t.Errorf("%v: unexpected %q in\n%s", tc.args, n, stdout)
			}
		}
		// NoFileComp (4) and NoSpace (2): the list can go on after a value.
		if !strings.HasSuffix(strings.TrimSpace(stdout), ":6") {
			t.Errorf("%v: directive in\n%s", tc.args, stdout)
		}
	}
	// The routing --platform takes one platform and completes plainly.
	stdout, _, err := run(t, cfgPath, cobra.ShellCompRequestCmd, "dns", "list", "--platform", "")
	if err != nil || !strings.Contains(stdout, "cloudflare\t") || !strings.HasSuffix(strings.TrimSpace(stdout), ":4") {
		t.Errorf("dns list --platform: %v\n%s", err, stdout)
	}
}

// No positional argument of a platform tree falls back to file names, and
// record ids complete from the cached records of the zone.
func TestPlatformArgCompletion(t *testing.T) {
	dir, cfgPath := setup(t, true)
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{
		"z1": {{ID: "r1", Name: "www.example.com", Type: "A", Value: "1.2.3.4"}, {ID: "r2", Name: "example.com", Type: "MX", Value: "mail.example.com"}},
	})
	seed2 := func(args ...string) string {
		t.Helper()
		stdout, _, err := run(t, cfgPath, append([]string{cobra.ShellCompRequestCmd}, args...)...)
		if err != nil {
			t.Fatalf("%v: %v", args, err)
		}
		return stdout
	}
	for _, verb := range []string{"update", "delete"} {
		if out := seed2("cloudflare", "dns", verb, ""); !strings.Contains(out, "example.com\n") || !strings.HasSuffix(strings.TrimSpace(out), ":4") {
			t.Errorf("cloudflare dns %s <zone>:\n%s", verb, out)
		}
		out := seed2("cloudflare", "dns", verb, "example.com", "")
		if !strings.Contains(out, "r1\tA www.example.com 1.2.3.4\n") || !strings.Contains(out, "r2\tMX example.com mail.example.com\n") || !strings.HasSuffix(strings.TrimSpace(out), ":4") {
			t.Errorf("cloudflare dns %s example.com <record-id>:\n%s", verb, out)
		}
		if out := seed2("cloudflare", "dns", verb, "example.com", "r1", ""); strings.Contains(out, "r1") || !strings.HasSuffix(strings.TrimSpace(out), ":4") {
			t.Errorf("cloudflare dns %s: third argument:\n%s", verb, out)
		}
	}
	// The other trees have no account here: nothing to offer, and never
	// the files of the current directory.
	for _, args := range [][]string{
		{"namecom", "dns", "delete", "example.com", ""},
		{"namecom", "dns", "update", ""},
		{"namecom", "domain", "ns", "set", "example.com", ""},
		{"aliyun", "dns", "record", "update", ""},
		{"aliyun", "dns", "record", "delete", "example.com", ""},
		{"aliyun", "domain", "ns", "set", ""},
		{"aliyun", "ecs", "instance", "stop", ""},
		{"godaddy", "domain", "ns", "set", "example.org", ""},
		{"godaddy", "domain", "check", ""},
		{"aws", "route53domains", "ns", "set", ""},
		{"aws", "route53domains", "ns", "set", "example.com", "ns1.example.net", ""},
		{"aws", "route53", "record", "list", ""},
		{"gcp", "dns", "record", "list", ""},
	} {
		if out := seed2(args...); !strings.HasSuffix(strings.TrimSpace(out), ":4") {
			t.Errorf("%v: want ShellCompDirectiveNoFileComp, got\n%s", args, out)
		}
	}
	// Every leaf of every platform tree completes its arguments itself.
	rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	var walk func(c *cobra.Command)
	walk = func(c *cobra.Command) {
		if !c.HasSubCommands() && c.ValidArgsFunction == nil && len(c.ValidArgs) == 0 {
			t.Errorf("%s has no argument completion", c.CommandPath())
		}
		for _, sub := range c.Commands() {
			walk(sub)
		}
	}
	for _, c := range platformCommands(rt) {
		walk(c)
	}
}

// `polyctl help <words>` agrees with `polyctl <words>`: a word that names
// no command is a usage error, not the help of the group with exit 0.
func TestHelpCommandRejectsUnknownCommands(t *testing.T) {
	dir, _ := setup(t, false)
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"help", "dns", "update"}, `unknown command "update" for "polyctl dns"`},
		{[]string{"help", "aws", "sts"}, `unknown command "sts" for "polyctl aws"`},
		{[]string{"help", "aws", "sts", "whoami"}, `unknown command "sts" for "polyctl aws"`},
		{[]string{"help", "nosuchcmd"}, `unknown command "nosuchcmd" for "polyctl"`},
		{[]string{"help", "dns", "list", "example.com"}, `"polyctl dns list" has no subcommands`},
	} {
		code, stdout, stderr := mainExit(dir, tc.args...)
		if code != ExitUsage || !strings.Contains(stderr, tc.want) || stdout != "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit %d with %q", tc.args, code, stdout, stderr, ExitUsage, tc.want)
		}
	}
	for args, want := range map[string]string{
		"help":                 "Platform-specific Commands:",
		"help dns":             "polyctl dns [command]",
		"help dns set":         "polyctl dns set <domain>",
		"help aws whoami":      "polyctl aws whoami",
		"help cf dns":          "polyctl cloudflare dns [command]",
		"help help":            "polyctl help [command]",
		"help inventory list":  "--platform",
		"help completion bash": "polyctl completion bash",
	} {
		code, stdout, stderr := mainExit(dir, strings.Fields(args)...)
		if code != ExitOK || !strings.Contains(stdout, want) {
			t.Errorf("%s: exit %d, stderr %q, want %q in\n%s", args, code, stderr, want, stdout)
		}
	}
	if stdout, _, err := run(t, filepath.Join(dir, "config.yaml"), cobra.ShellCompRequestCmd, "help", "dns", ""); err != nil || !strings.Contains(stdout, "set\t") || strings.Contains("\n"+stdout, "\nupdate\t") {
		t.Errorf("completion of help dns: %v\n%s", err, stdout)
	}
}

// A bare group only prints its help, like --help and like the bare root:
// it loads no configuration, so no setting can make it fail, and it creates
// nothing.
func TestBareGroupOnlyPrintsHelp(t *testing.T) {
	dir, _ := setup(t, false)
	groups := [][]string{{"dns"}, {"aws", "ec2"}, {"domain", "ns"}, {"cloudflare"}, {"help", "dns"}}
	check := func(what, dir string) {
		t.Helper()
		for _, g := range groups {
			code, stdout, stderr := mainExit(dir, g...)
			if code != ExitOK || !strings.Contains(stdout, "Available Commands:") {
				t.Errorf("%s: %v: exit %d, stderr %q\n%s", what, g, code, stderr, stdout)
			}
		}
	}
	t.Setenv(app.EnvNonInteractive, "maybe")
	check("invalid "+app.EnvNonInteractive, dir)
	// A command that does something still refuses the value.
	if code, _, stderr := mainExit(dir, "auth", "list"); code != ExitUsage || !strings.Contains(stderr, "invalid "+app.EnvNonInteractive) {
		t.Errorf("auth list with an invalid %s: exit %d, stderr %q", app.EnvNonInteractive, code, stderr)
	}
	t.Setenv(app.EnvNonInteractive, "")

	if err := os.WriteFile(filepath.Join(dir, "config.yaml"), []byte("profiles: [not, a, map\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check("broken config.yaml", dir)
	if code, _, _ := mainExit(dir, "auth", "list"); code == ExitOK {
		t.Error("auth list accepted a broken config.yaml")
	}

	fresh := filepath.Join(t.TempDir(), "not-yet")
	check("new config directory", fresh)
	if _, err := os.Stat(fresh); err == nil {
		t.Errorf("a bare group created %s", fresh)
	}

	// An unknown subcommand is still a usage error, and the usage of a
	// group shows the subcommand form only.
	if code, _, stderr := mainExit(dir, "dns", "update"); code != ExitUsage || !strings.Contains(stderr, `unknown command "update" for "polyctl dns"`) {
		t.Errorf("dns update: exit %d, stderr %q", code, stderr)
	}
	_, stdout, _ := mainExit(fresh, "dns")
	if strings.Contains(stdout, "polyctl dns [flags]") || !strings.Contains(stdout, "polyctl dns [command]") {
		t.Errorf("usage of a group:\n%s", stdout)
	}
	if _, stdout, _ = mainExit(fresh, "dns", "list", "--help"); !strings.Contains(stdout, "polyctl dns list <domain> [flags]") {
		t.Errorf("usage of a command lost its own line:\n%s", stdout)
	}
}

// --proxied is a boolean flag: the value of the 0.1.x spelling
// (`--proxied true`) is named in the error instead of being counted as an
// argument or taken for a record id.
func TestProxiedSeparateValueIsNamed(t *testing.T) {
	dir, _ := setup(t, true)
	for _, args := range [][]string{
		{"dns", "set", "example.com", "--type", "A", "--value", "1.1.1.1", "--proxied", "true"},
		{"dns", "add", "example.com", "--type", "A", "--value", "1.1.1.1", "--proxied", "false"},
		{"cloudflare", "dns", "create", "example.com", "--type", "A", "--name", "www", "--value", "1.1.1.1", "--proxied", "true"},
		{"cloudflare", "dns", "update", "example.com", "r1", "--proxied", "false"},
		{"cloudflare", "dns", "update", "example.com", "--proxied", "true"},
	} {
		code, _, stderr := mainExit(dir, args...)
		if code != ExitUsage || !strings.Contains(stderr, "--proxied takes no separate value") || !strings.Contains(stderr, "--proxied=false") {
			t.Errorf("%v: exit %d, stderr %q", args, code, stderr)
		}
	}
	// Without --proxied a wrong count is still the plain count error.
	if code, _, stderr := mainExit(dir, "dns", "set", "example.com", "true", "--type", "A", "--value", "1.1.1.1"); code != ExitUsage || strings.Contains(stderr, "--proxied") {
		t.Errorf("extra argument without --proxied: exit %d, stderr %q", code, stderr)
	}
	_, add, _ := mainExit(dir, "dns", "add", "--help")
	_, set, _ := mainExit(dir, "dns", "set", "--help")
	if !strings.Contains(add, "--proxied=false (default: the platform default)") || strings.Contains(add, "keep the current value") {
		t.Errorf("dns add --help describes --proxied as:\n%s", add)
	}
	if !strings.Contains(set, "keep the current value") {
		t.Errorf("dns set --help describes --proxied as:\n%s", set)
	}
}

// The flag wins over the variable, as for every setting: on a terminal
// --non-interactive=false keeps the interactive flow although
// POLYCTL_NON_INTERACTIVE switches it off.
func TestNonInteractiveFlagBeatsEnv(t *testing.T) {
	_, cfgPath := setupMulti(t)
	t.Setenv(app.EnvNonInteractive, "1")
	p := &scriptedPicker{t: t, answers: []any{"b"}}
	if r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "--non-interactive=false", "auth", "use"); r.err != nil || len(p.asked) != 1 {
		t.Errorf("--non-interactive=false with the variable set: %v, prompts %v; want the profile asked for", r.err, p.titles())
	}
	for _, flag := range [][]string{nil, {"--non-interactive"}, {"--non-interactive=true"}} {
		p = &scriptedPicker{t: t}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), append(flag, "auth", "use")...)
		if r.code != ExitUsage || len(p.asked) != 0 {
			t.Errorf("%v with the variable set: exit %d (%v), prompts %v; want a usage error", flag, r.code, r.err, p.titles())
		}
	}
	t.Setenv(app.EnvNonInteractive, "0")
	p = &scriptedPicker{t: t}
	if r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "--non-interactive", "auth", "use"); r.code != ExitUsage || len(p.asked) != 0 {
		t.Errorf("--non-interactive with the variable off: exit %d (%v), prompts %v", r.code, r.err, p.titles())
	}
}
