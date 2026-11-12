package cli

import (
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/spf13/cobra"
)

// countingReader is a stdin that counts how often it is read.
type countingReader struct {
	r     io.Reader
	reads int
}

func (c *countingReader) Read(b []byte) (int, error) {
	c.reads++
	return c.r.Read(b)
}

// flowResult is the outcome of one command run.
type flowResult struct {
	code           int
	stdout, stderr string
	err            error
}

// runFlow executes the command tree the way Main does, with a picker (nil
// for none) and a stdin of the caller's choice. A picker stands in for a
// terminal on stdin and stderr.
func runFlow(t *testing.T, ctx context.Context, cfgPath string, picker *scriptedPicker, stdin io.Reader, args ...string) flowResult {
	t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, stdin, &out, &errb)
	if picker != nil {
		rt.Picker = picker
	}
	root := NewRoot(rt)
	root.SetArgs(append([]string{"--config", cfgPath}, args...))
	root.SetIn(stdin)
	root.SetOut(&out)
	root.SetErr(&errb)
	err := root.ExecuteContext(ctx)
	_ = rt.Close()
	return flowResult{code: ExitCodeFor(err), stdout: out.String(), stderr: errb.String(), err: err}
}

// diskState is everything a refused command must leave alone: the config
// and the credential file, byte for byte.
func diskState(t *testing.T, dir string) string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for _, e := range entries {
		if e.IsDir() || strings.HasPrefix(e.Name(), "inventory") || strings.HasSuffix(e.Name(), ".lock") {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			t.Fatal(err)
		}
		parts = append(parts, e.Name()+"\n"+string(data))
	}
	sort.Strings(parts)
	return strings.Join(parts, "\n---\n")
}

// flowCase is one command that can ask something, in both flows.
type flowCase struct {
	name string
	// setup prepares the config directory.
	setup func(t *testing.T) (dir, cfgPath string)
	// args is the command with the argument, the confirmation or the value
	// left out.
	args []string

	// The interactive flow: answers are the picker's, typed is what is
	// typed at line prompts. interactive checks the outcome; nil means the
	// flow needs the network and is covered in the provider's own package.
	answers     []any
	typed       string
	interactive func(t *testing.T, dir string, r flowResult, p *scriptedPicker)

	// The non-interactive flow: piped is on stdin and must not be read; the
	// command is refused with wantCode and a message holding every wantMsg.
	piped    string
	wantCode int
	wantMsg  []string
	// mutated reports what the refused command must not have done, beyond
	// the files of diskState.
	mutated func(t *testing.T, dir string) string

	// complete is the command with what the refusal named. It must finish
	// without asking; completePiped is what it reads from stdin (only
	// `--set key=-` does), completed checks the outcome. Nil: needs the
	// network.
	complete      []string
	completePiped string
	completed     func(t *testing.T, dir string, r flowResult)
}

const flowZone = "example.com"

// setupTwoRecords is setup with a zone holding two A records of one name,
// in the inventory and on the fake platform.
func setupTwoRecords(t *testing.T) (string, string) {
	t.Helper()
	dir, cfgPath := setup(t, true)
	recs := []platform.Record{
		{ID: "r1", ZoneID: "z1", Name: "www." + flowZone, Type: "A", Content: "1.2.3.4"},
		{ID: "r2", ZoneID: "z1", Name: "www." + flowZone, Type: "A", Content: "5.6.7.8"},
	}
	zones := []platform.Zone{{ID: "z1", Name: flowZone}}
	seed(t, dir, zones, map[string][]platform.Record{"z1": recs})
	fc := client("a")
	fc.zones = zones
	fc.records["z1"] = append([]platform.Record(nil), recs...)
	return dir, cfgPath
}

func setupEmpty(t *testing.T) (string, string) { return setup(t, false) }
func setupOne(t *testing.T) (string, string)   { return setup(t, true) }
func recordsDeleted(t *testing.T, _ string) string {
	if fc := client("a"); fc.count("DeleteRecord") != 0 || len(fc.records["z1"]) != 2 {
		return "records were deleted: " + strings.Join(fc.calls, " ")
	}
	return ""
}

func loggedIn(t *testing.T, _ string) string {
	if n := loginCalls(); n != 0 {
		return "a login flow ran"
	}
	return ""
}

// flowCases lists every command that can ask something.
func flowCases() []flowCase {
	dnsDelete := []string{"dns", "delete", flowZone, "--type", "A", "--name", "www"}
	bothDeleted := func(t *testing.T, _ string, r flowResult) {
		if fc := client("a"); fc.count("DeleteRecord") != 2 || len(fc.records["z1"]) != 0 {
			t.Errorf("the records were not deleted: calls %v", fc.calls)
		}
		if strings.Contains(r.stderr, "(y/N)") {
			t.Errorf("a question was printed: %q", r.stderr)
		}
	}
	profileB := func(want bool) func(t *testing.T, dir string, r flowResult) {
		return func(t *testing.T, dir string, r flowResult) {
			cfg := loadConfig(t, filepath.Join(dir, "config.yaml"))
			if _, has := cfg.Profiles["b"]; has != want {
				t.Errorf("profile b configured = %v, want %v", has, want)
			}
		}
	}
	// A login that fails before it would reach the network.
	refusedLogin := func(name string, wantMsg []string, args ...string) flowCase {
		return flowCase{name: name, setup: setupEmpty, args: append([]string{"auth", "login"}, args...),
			piped: "answer one\nanswer two\nanswer three\n", wantCode: ExitUsage, wantMsg: wantMsg}
	}
	return []flowCase{
		{
			name: "auth login: platform", setup: setupEmpty, args: []string{"auth", "login"},
			answers: []any{p1},
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				if r.err != nil || loginCalls() != 1 || token(t, dir, creds.Key(config.DefaultProfile, p1)) != "fake" || p.find("Platform").Kind != "select" {
					t.Errorf("auth login with the platform picked: %v, %d login(s), prompts %v", r.err, loginCalls(), p.titles())
				}
			},
			piped: p1 + "\n", wantCode: ExitUsage, wantMsg: []string{"auth login: <platform> is required", "one of:", p1, p2},
			mutated:  loggedIn,
			complete: []string{"auth", "login", p1},
			completed: func(t *testing.T, dir string, r flowResult) {
				if loginCalls() != 1 || token(t, dir, creds.Key(config.DefaultProfile, p1)) != "fake" {
					t.Errorf("auth login %s did not log in (stderr %q)", p1, r.stderr)
				}
			},
		},
		{
			name: "auth login: --set token=-", setup: setupEmpty, args: []string{"auth", "login", p1, "--set", "token=-"},
			typed: "typed-token\n",
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				if r.err != nil || token(t, dir, creds.Key(config.DefaultProfile, p1)) != "typed-token" || !strings.Contains(r.stderr, "token: ") {
					t.Errorf("auth login with the token typed: %v (stderr %q)", r.err, r.stderr)
				}
			},
			// Nothing piped: there is no value, and nobody to ask for one.
			piped: "", wantCode: ExitUsage, wantMsg: []string{"--set token=-", "stdin"},
			mutated:  loggedIn,
			complete: []string{"auth", "login", p1, "--set", "token=-"}, completePiped: "piped-token\n",
			completed: func(t *testing.T, dir string, r flowResult) {
				if token(t, dir, creds.Key(config.DefaultProfile, p1)) != "piped-token" || strings.Contains(r.stderr, "token: ") {
					t.Errorf("auth login with the token piped: token %q, stderr %q", token(t, dir, creds.Key(config.DefaultProfile, p1)), r.stderr)
				}
			},
		},
		{
			name: "auth use: profile", setup: setupMulti, args: []string{"auth", "use"},
			answers: []any{"b"},
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				if cfg := loadConfig(t, filepath.Join(dir, "config.yaml")); r.err != nil || cfg.CurrentProfile != "b" {
					t.Errorf("auth use with the profile picked: %v, current %q", r.err, cfg.CurrentProfile)
				}
			},
			piped: "b\n", wantCode: ExitUsage, wantMsg: []string{"auth use: <profile> is required"},
			complete: []string{"auth", "use", "b"},
			completed: func(t *testing.T, dir string, r flowResult) {
				if cfg := loadConfig(t, filepath.Join(dir, "config.yaml")); cfg.CurrentProfile != "b" {
					t.Errorf("auth use b: current %q", cfg.CurrentProfile)
				}
			},
		},
		{
			name: "auth logout: accounts and confirmations", setup: setupMulti, args: []string{"auth", "logout"},
			answers: []any{[]string{"b/" + p2}, true, false},
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				profileB(false)(t, dir, r)
				if r.err != nil || p.find(removeTitle).Kind != "multi" || p.find("Remove 1 entry?").Kind != "confirm" || p.find(keepTitle).Kind != "confirm" {
					t.Errorf("auth logout: %v, prompts %v", r.err, p.titles())
				}
			},
			piped: "y\ny\n", wantCode: ExitUsage, wantMsg: []string{"--profile <name> is required"},
			complete: []string{"auth", "logout", "--profile", "b"}, completed: profileB(false),
		},
		{
			// --yes confirms; it does not choose.
			name: "auth logout --yes: accounts", setup: setupMulti, args: []string{"auth", "logout", "--yes"},
			answers: []any{[]string{"b/" + p2}},
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				profileB(false)(t, dir, r)
				if r.err != nil || len(p.asked) != 1 || p.asked[0].Kind != "multi" {
					t.Errorf("auth logout --yes: %v, prompts %v; want the selection only", r.err, p.titles())
				}
			},
			piped: "y\n", wantCode: ExitUsage, wantMsg: []string{"--profile <name> is required"},
			complete: []string{"auth", "logout", "--yes", "--profile", "b"}, completed: profileB(false),
		},
		{
			name: "auth logout <platform>: accounts", setup: setupMulti, args: []string{"auth", "logout", p2},
			answers: []any{[]string{"b/" + p2}, true, true},
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				profileB(false)(t, dir, r)
				if r.err != nil || strings.Contains(values(p.find(removeTitle).Options), "a/"+p1) {
					t.Errorf("auth logout %s: %v, options %q", p2, r.err, values(p.find(removeTitle).Options))
				}
			},
			piped: "y\n", wantCode: ExitUsage, wantMsg: []string{"--profile <name> is required"},
			complete: []string{"auth", "logout", p2, "--profile", "b"}, completed: profileB(false),
		},
		{
			name: "auth manage: menu", setup: setupMulti, args: []string{"auth", "manage"},
			answers: []any{actQuit},
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				if r.err != nil || p.find(menuTitle).Kind != "select" {
					t.Errorf("auth manage: %v, prompts %v", r.err, p.titles())
				}
			},
			piped: "q\n", wantCode: ExitUsage, wantMsg: []string{"auth manage is interactive only", "auth list", "auth use <profile>", "auth logout [platform] --profile <name>"},
			// Its scriptable counterparts never ask.
			complete: []string{"auth", "list"},
			completed: func(t *testing.T, dir string, r flowResult) {
				if !strings.Contains(r.stdout, "PROFILE") {
					t.Errorf("auth list: stdout %q", r.stdout)
				}
			},
		},
		{
			name: "dns delete: several records", setup: setupTwoRecords, args: dnsDelete,
			typed: "y\n",
			interactive: func(t *testing.T, dir string, r flowResult, p *scriptedPicker) {
				if fc := client("a"); r.err != nil || fc.count("DeleteRecord") != 2 || !strings.Contains(r.stderr, "delete 2 records in zone "+flowZone+" (y/N)") {
					t.Errorf("dns delete confirmed: %v, calls %v, stderr %q", r.err, fc.calls, r.stderr)
				}
			},
			// A piped "y" is data, not an answer.
			piped: "y\ny\n", wantCode: ExitUsage,
			wantMsg:  []string{"confirmation required: pass --yes to proceed", "would delete 2 records in zone " + flowZone},
			mutated:  recordsDeleted,
			complete: append(append([]string{}, dnsDelete...), "--yes"), completed: bothDeleted,
		},
		{
			name: "dns delete -y: several records", setup: setupTwoRecords, args: dnsDelete,
			piped: "y\n", wantCode: ExitUsage, wantMsg: []string{"pass --yes"}, mutated: recordsDeleted,
			complete: append(append([]string{}, dnsDelete...), "-y"), completed: bothDeleted,
		},
		{
			// Refused before the account is opened: needs neither one nor
			// the network. The interactive rows are in the aliyun package.
			name: "aliyun ecs stop: confirmation", setup: setupOne, args: []string{"aliyun", "ecs", "stop", "i-1"},
			piped: "y\n", wantCode: ExitUsage, wantMsg: []string{"confirmation required: pass --yes to proceed", "would stop instance i-1"},
		},

		// Login flows of the real providers: each is refused before its
		// first request, naming the --set keys. Their interactive rows, and
		// the rows that complete, run against fakes in the provider packages.
		refusedLogin("auth login aws: method", []string{"--set method=sso", "--set method=keys", "--set method=profile"}, "aws"),
		refusedLogin("auth login aws keys: access key", []string{"--set access_key_id=<id>", "--set secret_access_key=-", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"}, "aws", "--set", "method=keys"),
		refusedLogin("auth login aws keys: secret", []string{"--set secret_access_key=-"}, "aws", "--set", "method=keys", "--set", "access_key_id=AKIAONE"),
		refusedLogin("auth login aws sso: start URL", []string{"--set start_url=<url>"}, "aws", "--set", "method=sso"),
		refusedLogin("auth login gcp service account: key file", []string{"--set key_file="}, "gcp", "--set", "method=service_account"),
		refusedLogin("auth login gcp oauth: client and project", []string{"--set client_id=<id>", "--set client_secret=-", "--set project=<id>"}, "gcp", "--set", "method=oauth"),
		refusedLogin("auth login gcp oauth: project", []string{"--set project=<id>"}, "gcp", "--set", "method=oauth", "--set", "client_id=id", "--set", "client_secret=s"),
		refusedLogin("auth login aliyun: access key", []string{"--set access_key_id=<id>", "--set access_key_secret=-", "ALIBABA_CLOUD_ACCESS_KEY_ID", "--set from_cli=<profile>"}, "aliyun"),
		refusedLogin("auth login aliyun: secret", []string{"--set access_key_secret=-"}, "aliyun", "--set", "access_key_id=LTAIone"),
		refusedLogin("auth login namecom: username and token", []string{"--set username=<user>", "--set token=-"}, "namecom"),
		refusedLogin("auth login namecom: token", []string{"--set token=-"}, "namecom", "--set", "username=alice"),
	}
}

// clearLoginEnv removes the environment variables login flows read, so that
// the developer's shell does not answer for the test.
func clearLoginEnv(t *testing.T) {
	t.Helper()
	for _, k := range []string{
		"AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY", "AWS_SESSION_TOKEN", "AWS_PROFILE",
		"ALIBABA_CLOUD_ACCESS_KEY_ID", "ALIBABA_CLOUD_ACCESS_KEY_SECRET", "CLOUDFLARE_API_TOKEN",
	} {
		t.Setenv(k, "")
	}
}

// TestFlowMatrix runs every command that can ask something in three
// situations: the interactive flow, the non-interactive flow because there
// is no terminal, and the non-interactive flow forced on a terminal with
// --no-input and with POLYCTL_NO_INPUT.
func TestFlowMatrix(t *testing.T) {
	// A non-interactive situation: how the flow is forced, and whether a
	// terminal (the picker) is present all the same.
	type situation struct {
		name     string
		terminal bool
		flag     []string
		env      string
	}
	situations := []situation{
		{name: "no terminal"},
		{name: "--no-input on a terminal", terminal: true, flag: []string{"--no-input"}},
		{name: "POLYCTL_NO_INPUT=1 on a terminal", terminal: true, env: "1"},
		{name: "POLYCTL_NO_INPUT=true without a terminal", env: "true"},
	}
	for _, tc := range flowCases() {
		t.Run(tc.name, func(t *testing.T) {
			if tc.interactive != nil {
				t.Run("interactive", func(t *testing.T) {
					clearLoginEnv(t)
					dir, cfgPath := tc.setup(t)
					p := &scriptedPicker{t: t, answers: tc.answers}
					r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(tc.typed), tc.args...)
					if len(p.answers) != 0 {
						t.Errorf("%d scripted answer(s) were never asked for (prompts: %v)", len(p.answers), p.titles())
					}
					tc.interactive(t, dir, r, p)
				})
			}
			for _, sit := range situations {
				t.Run(sit.name, func(t *testing.T) {
					clearLoginEnv(t)
					dir, cfgPath := tc.setup(t)
					t.Setenv(app.EnvNoInput, sit.env)
					// The picker has no answers: any question fails the test.
					var p *scriptedPicker
					if sit.terminal {
						p = &scriptedPicker{t: t}
					}
					asked := func() int {
						if p == nil {
							return 0
						}
						return len(p.asked)
					}
					before := diskState(t, dir)

					// Refused: exit code, message, nothing asked, read or changed.
					stdin := &countingReader{r: strings.NewReader(tc.piped)}
					r := runFlow(t, context.Background(), cfgPath, p, stdin, append(append([]string{}, tc.args...), sit.flag...)...)
					if r.code != tc.wantCode || r.err == nil {
						t.Fatalf("exit %d (%v), want %d", r.code, r.err, tc.wantCode)
					}
					for _, w := range tc.wantMsg {
						if !strings.Contains(r.err.Error(), w) {
							t.Errorf("the error does not name %q: %v", w, r.err)
						}
					}
					if asked() != 0 {
						t.Errorf("the picker was asked: %v", p.titles())
					}
					if stdin.reads != 0 && tc.piped != "" {
						t.Errorf("stdin was read %d time(s): it is data, not a conversation", stdin.reads)
					}
					if r.stdout != "" {
						t.Errorf("stdout = %q, want nothing", r.stdout)
					}
					for _, drawn := range []string{"\x1b", "cancelled", "(y/N)", "(Y/n)", "a value is required", "choose one of"} {
						if strings.Contains(r.stderr, drawn) {
							t.Errorf("stderr holds %q, which belongs to a prompt: %q", drawn, r.stderr)
						}
					}
					if after := diskState(t, dir); after != before {
						t.Errorf("the refused command changed the files:\n%s\n=== before ===\n%s", after, before)
					}
					if tc.mutated != nil {
						if what := tc.mutated(t, dir); what != "" {
							t.Errorf("the refused command acted: %s", what)
						}
					}

					// With what the refusal named: completes without asking.
					if tc.complete == nil {
						return
					}
					stdin = &countingReader{r: strings.NewReader(tc.completePiped)}
					r = runFlow(t, context.Background(), cfgPath, p, stdin, append(append([]string{}, tc.complete...), sit.flag...)...)
					if r.code != ExitOK || r.err != nil {
						t.Fatalf("%v: exit %d (%v), stderr %q", tc.complete, r.code, r.err, r.stderr)
					}
					if asked() != 0 {
						t.Errorf("%v: the picker was asked: %v", tc.complete, p.titles())
					}
					if tc.completePiped == "" && stdin.reads != 0 {
						t.Errorf("%v: stdin was read %d time(s)", tc.complete, stdin.reads)
					}
					if strings.Contains(r.stderr, "\x1b") || strings.Contains(r.stderr, "(y/N)") {
						t.Errorf("%v: stderr holds a prompt: %q", tc.complete, r.stderr)
					}
					tc.completed(t, dir, r)
				})
			}
		})
	}
}

// --no-input and --yes together: no question at all, and the destructive
// action proceeds, on a terminal too.
func TestNoInputWithYesAsksNothing(t *testing.T) {
	_, cfgPath := setupTwoRecords(t)
	p := &scriptedPicker{t: t}
	stdin := &countingReader{r: strings.NewReader("n\n")}
	r := runFlow(t, context.Background(), cfgPath, p, stdin, "dns", "delete", flowZone, "--type", "A", "--name", "www", "--no-input", "--yes")
	if r.err != nil || client("a").count("DeleteRecord") != 2 || len(p.asked) != 0 || stdin.reads != 0 || strings.Contains(r.stderr, "(y/N)") {
		t.Errorf("--no-input --yes: %v, %d deletes, prompts %v, %d stdin reads, stderr %q", r.err, client("a").count("DeleteRecord"), p.titles(), stdin.reads, r.stderr)
	}
}

// Several `--set key=-` values each read their own line of the piped stdin,
// in the order given, and no label is printed.
func TestLoginReadsSeveralStdinValues(t *testing.T) {
	dir, cfgPath := setup(t, false)
	var out, errb bytes.Buffer
	code := Main([]string{"--config", cfgPath, "auth", "login", p1, "--set", "account=-", "--set", "token=-"}, strings.NewReader("acct-piped\ntoken-piped\n"), &out, &errb)
	if code != ExitOK {
		t.Fatalf("exit %d (stderr %q)", code, errb.String())
	}
	cfg := loadConfig(t, cfgPath)
	a, err := cfg.Account(config.DefaultProfile, fakePlatform)
	if err != nil || a.Metadata["account"] != "acct-piped" || token(t, dir, creds.Key(config.DefaultProfile, p1)) != "token-piped" {
		t.Errorf("account %+v (%v), token %q", a, err, token(t, dir, creds.Key(config.DefaultProfile, p1)))
	}
	if strings.Contains(errb.String(), "token: ") || strings.Contains(errb.String(), "account: ") {
		t.Errorf("a label was printed: %q", errb.String())
	}
	// One value short: the usage error names the key that got none.
	out.Reset()
	errb.Reset()
	code = Main([]string{"--config", cfgPath, "auth", "login", p1, "--profile", "x", "--set", "account=-", "--set", "token=-"}, strings.NewReader("only-one\n"), &out, &errb)
	if code != ExitUsage || !strings.Contains(errb.String(), "--set token=-") || token(t, dir, creds.Key("x", p1)) != "" {
		t.Errorf("one value short: exit %d (stderr %q)", code, errb.String())
	}
}

// An invalid POLYCTL_NO_INPUT is a usage error, whatever the command; until
// it is fixed nothing is asked.
func TestNoInputEnvInvalid(t *testing.T) {
	_, cfgPath := setupMulti(t)
	t.Setenv(app.EnvNoInput, "maybe")
	for _, args := range [][]string{{"auth", "list"}, {"auth", "login"}, {"auth", "use"}, {"auth", "manage"}} {
		p := &scriptedPicker{t: t}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), args...)
		if r.code != ExitUsage || len(p.asked) != 0 {
			t.Errorf("%v: exit %d (%v), prompts %v; want a usage error and no question", args, r.code, r.err, p.titles())
		}
	}
	// The message names the variable and its value, also where the argument
	// check runs before Init: a person on a terminal must learn why the
	// picker did not open, not be told to pass an argument.
	for _, args := range [][]string{{"auth", "list"}, {"auth", "login"}, {"auth", "use"}} {
		for _, p := range []*scriptedPicker{nil, {t: t}} {
			r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), args...)
			if r.code != ExitUsage || r.err == nil || !strings.Contains(r.err.Error(), app.EnvNoInput) || !strings.Contains(r.err.Error(), `"maybe"`) || strings.Contains(r.err.Error(), "is required") {
				t.Errorf("%v (picker %v): exit %d, the error does not name the variable and its value: %v", args, p != nil, r.code, r.err)
			}
		}
	}
	// Help and shell completion ask nothing: the bad value does not break them.
	for _, args := range [][]string{{"help", "auth"}, {"completion", "zsh"}, {cobra.ShellCompRequestCmd, "auth", "use", ""}, {cobra.ShellCompNoDescRequestCmd, "auth", "use", ""}} {
		if r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), args...); r.err != nil || r.code != 0 {
			t.Errorf("%v with an invalid %s: exit %d (%v); want it to work", args, app.EnvNoInput, r.code, r.err)
		}
	}
	// The values that switch it off leave the interactive flow alone.
	for _, off := range []string{"0", "false", "no", ""} {
		t.Setenv(app.EnvNoInput, off)
		p := &scriptedPicker{t: t, answers: []any{"b"}}
		if r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "auth", "use"); r.err != nil || len(p.asked) != 1 {
			t.Errorf("POLYCTL_NO_INPUT=%q: %v, prompts %v; want the profile asked for", off, r.err, p.titles())
		}
	}
}

// The global flag is documented where every command shows it.
func TestNoInputFlagInHelp(t *testing.T) {
	_, cfgPath := setup(t, false)
	stdout, _, err := run(t, cfgPath, "auth", "login", "--help")
	if err != nil || !strings.Contains(stdout, "--no-input") || !strings.Contains(stdout, app.EnvNoInput) {
		t.Errorf("auth login --help does not show --no-input: %v\n%s", err, stdout)
	}
}

// Only a credential on the command line draws the argv warning. GoDaddy's
// legacy key id is not one: the documented scripted form
// `--set key=<key> --set secret=-` must not be warned against.
func TestSetWarningOnlyForSecrets(t *testing.T) {
	_, cfgPath := setup(t, false)
	r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader("s3cret\n"), "auth", "login", p1, "--set", "key=KEYID", "--set", "secret=-")
	if r.err != nil || strings.Contains(r.stderr, "warning: --set") {
		t.Errorf("--set key=<key> --set secret=-: %v, stderr %q; want no warning", r.err, r.stderr)
	}
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "auth", "login", p1, "--set", "key=KEYID", "--set", "secret=s3cret")
	if r.err != nil || !strings.Contains(r.stderr, "warning: --set secret=...") || strings.Contains(r.stderr, "warning: --set key=...") {
		t.Errorf("--set secret=<value>: %v, stderr %q; want a warning for secret only", r.err, r.stderr)
	}
}
