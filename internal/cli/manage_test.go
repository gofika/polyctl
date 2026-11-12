package cli

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// abort is a scripted answer: the user leaves the prompt with Esc or Ctrl-C.
type abort struct{}

// keepDefault is a scripted answer to Input: the user accepts the default.
type keepDefault struct{}

// asked records one prompt shown by the scripted picker.
type asked struct {
	Kind    string // select, multi, confirm or input
	Title   string
	Options []prompt.Option
	Default string
}

// scriptedPicker answers prompts from a fixed list: a string for Select and
// Input, a []string for MultiSelect, a bool for Confirm, abort{} for any of
// them. It fails the test on an unexpected prompt or a mismatched answer.
type scriptedPicker struct {
	t       *testing.T
	answers []any
	asked   []asked
}

func (p *scriptedPicker) next(a asked) (any, error) {
	p.t.Helper()
	p.asked = append(p.asked, a)
	if len(p.answers) == 0 {
		p.t.Errorf("unexpected %s prompt %q: no scripted answer left", a.Kind, a.Title)
		return nil, prompt.ErrAborted
	}
	v := p.answers[0]
	p.answers = p.answers[1:]
	if _, ok := v.(abort); ok {
		return nil, prompt.ErrAborted
	}
	return v, nil
}

func hasValue(opts []prompt.Option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}

func (p *scriptedPicker) Select(title string, opts []prompt.Option, def string) (string, error) {
	p.t.Helper()
	v, err := p.next(asked{Kind: "select", Title: title, Options: opts, Default: def})
	if err != nil {
		return "", err
	}
	s, ok := v.(string)
	if !ok || !hasValue(opts, s) {
		p.t.Errorf("select %q: scripted answer %#v is not one of the options %v", title, v, opts)
		return "", prompt.ErrAborted
	}
	return s, nil
}

func (p *scriptedPicker) MultiSelect(title string, opts []prompt.Option) ([]string, error) {
	p.t.Helper()
	v, err := p.next(asked{Kind: "multi", Title: title, Options: opts})
	if err != nil {
		return nil, err
	}
	vs, ok := v.([]string)
	if !ok {
		p.t.Errorf("multi-select %q: scripted answer %#v is not a []string", title, v)
		return nil, prompt.ErrAborted
	}
	for _, s := range vs {
		if !hasValue(opts, s) {
			p.t.Errorf("multi-select %q: %q is not one of the options %v", title, s, opts)
		}
	}
	return vs, nil
}

func (p *scriptedPicker) Confirm(title string, def bool) (bool, error) {
	p.t.Helper()
	v, err := p.next(asked{Kind: "confirm", Title: title, Default: fmt.Sprint(def)})
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		p.t.Errorf("confirm %q: scripted answer %#v is not a bool", title, v)
		return false, prompt.ErrAborted
	}
	return b, nil
}

// Input behaves like the terminal: a value the validator rejects keeps the
// prompt open, and the next scripted answer is the user's correction.
func (p *scriptedPicker) Input(title, def string, validate func(string) error) (string, error) {
	p.t.Helper()
	for {
		v, err := p.next(asked{Kind: "input", Title: title, Default: def})
		if err != nil {
			return "", err
		}
		s, ok := v.(string)
		if _, keep := v.(keepDefault); keep {
			s, ok = def, true
		}
		if !ok {
			p.t.Errorf("input %q: scripted answer %#v is not a string", title, v)
			return "", prompt.ErrAborted
		}
		if validate == nil || validate(s) == nil {
			return s, nil
		}
	}
}

// find returns the first recorded prompt with the given title.
func (p *scriptedPicker) find(title string) *asked {
	for i := range p.asked {
		if p.asked[i].Title == title {
			return &p.asked[i]
		}
	}
	p.t.Errorf("no prompt titled %q was shown; prompts: %v", title, p.titles())
	return &asked{}
}

func (p *scriptedPicker) titles() []string {
	var out []string
	for _, a := range p.asked {
		out = append(out, a.Kind+":"+a.Title)
	}
	return out
}

func values(opts []prompt.Option) string {
	var out []string
	for _, o := range opts {
		out = append(out, o.Value)
	}
	return strings.Join(out, " ")
}

// runPick executes the command tree with a scripted picker, which makes the
// runtime interactive. Every scripted answer must be used.
func runPick(t *testing.T, cfgPath string, answers []any, args ...string) (stdout, stderr string, err error, p *scriptedPicker) {
	t.Helper()
	p = &scriptedPicker{t: t, answers: answers}
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
	rt.Picker = p
	root := NewRoot(rt)
	root.SetArgs(append([]string{"--config", cfgPath}, args...))
	root.SetIn(strings.NewReader(""))
	root.SetOut(&out)
	root.SetErr(&errb)
	err = root.ExecuteContext(context.Background())
	_ = rt.Close()
	if len(p.answers) != 0 {
		t.Errorf("%d scripted answer(s) were never asked for: %#v (prompts: %v)", len(p.answers), p.answers, p.titles())
	}
	return out.String(), errb.String(), err, p
}

const (
	menuTitle   = "Profiles and accounts"
	removeTitle = "Remove which accounts?"
	keepTitle   = "Keep cached inventory?"
)

var (
	p1 = string(fakePlatform)
	p2 = string(fakePlatform2)
)

func TestRuntimeInteractive(t *testing.T) {
	rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if rt.Interactive() {
		t.Error("buffers are not a terminal")
	}
	null, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer null.Close()
	rt = app.New(app.Flags{}, null, null, null)
	if rt.Interactive() {
		t.Error("the null device is not a terminal")
	}
	if rt.Pick() == nil {
		t.Error("Pick must fall back to the terminal picker")
	}
	fake := &scriptedPicker{t: t}
	rt.Picker = fake
	if !rt.Interactive() || rt.Pick() != prompt.Picker(fake) {
		t.Error("an injected picker makes the runtime interactive and is the one returned")
	}
}

// TestNonInteractiveNeverPrompts runs the commands that prompt on a terminal
// without one: they must fail with their usage errors, as before.
func TestNonInteractiveNeverPrompts(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"auth", "manage"}, "auth manage needs an interactive terminal"},
		{[]string{"auth", "use"}, "accepts 1 arg(s), received 0"},
		{[]string{"auth", "login"}, "accepts 1 arg(s), received 0"},
		{[]string{"auth", "logout"}, "--profile <name> is required"},
		{[]string{"auth", "logout", p1}, "--profile <name> is required"},
		{[]string{"auth", "logout", "--yes"}, "--profile <name> is required"},
		{[]string{"auth", "use", "a", "b"}, "accepts 1 arg(s), received 2"},
		{[]string{"auth", "login", p1, p2}, "accepts 1 arg(s), received 2"},
		{[]string{"auth", "rename", "a"}, "accepts 2 arg(s), received 1"},
	} {
		code, stdout, stderr := mainRun(cfgPath, tc.args...)
		if code != ExitUsage || !strings.Contains(stderr, tc.want) || stdout != "" {
			t.Errorf("%v: exit %d, stdout %q, stderr %q; want exit %d and %q", tc.args, code, stdout, stderr, ExitUsage, tc.want)
		}
	}
	_, _, stderr := mainRun(cfgPath, "auth", "manage")
	for _, alt := range []string{"auth list", "auth use <profile>", "auth login <platform>", "auth status", "auth rename <old> <new>", "auth logout [platform] --profile <name>"} {
		if !strings.Contains(stderr, alt) {
			t.Errorf("the auth manage usage error does not name %q: %q", alt, stderr)
		}
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a failed command changed the config")
	}
	if token(t, dir, creds.Key("a", p1)) == "" {
		t.Error("a failed command removed a secret")
	}
}

// TestInteractiveOnlyWhenArgumentMissing checks that a picker is never
// consulted when the arguments are complete.
func TestInteractiveOnlyWhenArgumentMissing(t *testing.T) {
	_, cfgPath := setupMulti(t)
	if _, stderr, err, _ := runPick(t, cfgPath, nil, "auth", "use", "b"); err != nil || !strings.Contains(stderr, `current profile set to "b"`) {
		t.Errorf("auth use b: %v (stderr %q)", err, stderr)
	}
	if _, stderr, err, _ := runPick(t, cfgPath, nil, "auth", "login", p1, "--profile", "b"); err != nil || !strings.Contains(stderr, "logged in to") {
		t.Errorf("auth login: %v (stderr %q)", err, stderr)
	}
	if _, stderr, err, _ := runPick(t, cfgPath, nil, "auth", "logout", p1, "--profile", "b"); err != nil || !strings.Contains(stderr, "account removed") {
		t.Errorf("auth logout: %v (stderr %q)", err, stderr)
	}
	if _, _, err, _ := runPick(t, cfgPath, nil, "auth", "use", "a", "b"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("auth use with two arguments = %v, want a usage error", err)
	}
}

func TestAuthUsePicksProfile(t *testing.T) {
	_, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, err, p := runPick(t, cfgPath, []any{"b"}, "auth", "use")
	if err != nil || stdout != "" || !strings.Contains(stderr, `current profile set to "b"`) {
		t.Fatalf("auth use: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	q := p.asked[0]
	if q.Kind != "select" || values(q.Options) != "a b" || q.Default != "a" {
		t.Errorf("prompt = %+v, want a select of a and b with the current profile preselected", q)
	}
	if !strings.Contains(q.Options[0].Label, p1) || !strings.Contains(q.Options[0].Label, "[current]") {
		t.Errorf("label of the current profile = %q", q.Options[0].Label)
	}
	if got := loadConfig(t, cfgPath).CurrentProfile; got != "b" {
		t.Errorf("current_profile = %q, want b", got)
	}

	// Leaving the prompt changes nothing and is not an error.
	stdout, stderr, err, _ = runPick(t, cfgPath, []any{abort{}}, "auth", "use")
	if err != nil || stdout != "" || strings.TrimSpace(stderr) != "cancelled" {
		t.Errorf("aborted auth use: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	if got := loadConfig(t, cfgPath).CurrentProfile; got != "b" {
		t.Errorf("current_profile after an abort = %q, want b", got)
	}
}

func TestAuthUsePickWithoutProfiles(t *testing.T) {
	_, cfgPath := setup(t, false)
	_, _, err, p := runPick(t, cfgPath, nil, "auth", "use")
	if ExitCodeFor(err) != ExitNotFound || !strings.Contains(err.Error(), "no profiles configured") {
		t.Errorf("auth use without profiles = %v, want not found", err)
	}
	if len(p.asked) != 0 {
		t.Errorf("prompted with nothing to choose: %v", p.titles())
	}
}

func TestAuthLoginPicksPlatform(t *testing.T) {
	dir, cfgPath := setup(t, false)
	stdout, stderr, err, p := runPick(t, cfgPath, []any{p2}, "auth", "login", "--set", "account=acct-x")
	if err != nil || stdout != "" {
		t.Fatalf("auth login: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	q := p.asked[0]
	if q.Kind != "select" || q.Title != "Platform" || len(q.Options) != len(platform.Providers()) {
		t.Errorf("prompt = %+v, want a select of every platform", q)
	}
	var label string
	for _, o := range q.Options {
		if o.Value == p2 {
			label = o.Label
		}
	}
	if label != "Fake Registrar" {
		t.Errorf("label of %s = %q, want the provider display name", p2, label)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "default/"+p2 || cfg.CurrentProfile != "default" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if cfg.Profiles["default"].Platforms[fakePlatform2].Metadata["account"] != "acct-x" {
		t.Error("--set options were not passed to the login flow")
	}
	if token(t, dir, creds.Key("default", p2)) != "fake" {
		t.Error("the secret was not stored")
	}

	// The normal rules still apply after the choice: p2 now lives in
	// "default" only, so another profile needs --profile.
	if _, _, err := run(t, cfgPath, "auth", "login", p1, "--profile", "other"); err != nil {
		t.Fatal(err)
	}
	if _, _, err := run(t, cfgPath, "auth", "use", "other"); err != nil {
		t.Fatal(err)
	}
	_, _, err, _ = runPick(t, cfgPath, []any{p2}, "auth", "login")
	if ExitCodeFor(err) != ExitUsage || !strings.Contains(err.Error(), "already configured in profile(s) default") {
		t.Errorf("login of a platform that lives elsewhere = %v, want the usage error", err)
	}

	_, stderr, err, _ = runPick(t, cfgPath, []any{abort{}}, "auth", "login")
	if err != nil || strings.TrimSpace(stderr) != "cancelled" {
		t.Errorf("aborted auth login: %v (stderr %q)", err, stderr)
	}
}

func TestAuthLogoutPicksAccounts(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	for _, ref := range loadConfig(t, cfgPath).Accounts("") {
		seedZone(t, dir, ref, strings.ReplaceAll(ref.String(), "/", "-")+".example")
	}

	// Nothing chosen, aborted, and "No" at the confirmation leave all as is.
	for _, tc := range []struct {
		answers []any
		want    string
	}{
		{[]any{[]string{}}, "nothing selected"},
		{[]any{abort{}}, "cancelled"},
		{[]any{[]string{"a/" + p1}, false}, "cancelled"},
		{[]any{[]string{"a/" + p1}, abort{}}, "cancelled"},
		{[]any{[]string{"a/" + p1}, true, abort{}}, "cancelled"},
	} {
		stdout, stderr, err, _ := runPick(t, cfgPath, tc.answers, "auth", "logout")
		if err != nil || stdout != "" || !strings.HasSuffix(strings.TrimSpace(stderr), tc.want) {
			t.Errorf("answers %#v: %v (stdout %q, stderr %q), want %q", tc.answers, err, stdout, stderr, tc.want)
		}
		if got := accountNames(loadConfig(t, cfgPath)); got != "a/"+p1+" a/"+p2+" b/"+p2 {
			t.Fatalf("answers %#v changed the accounts: %q", tc.answers, got)
		}
		if got := inventoryOwners(t, dir); got != "a/"+p1+" a/"+p2+" b/"+p2 {
			t.Fatalf("answers %#v changed the inventory: %q", tc.answers, got)
		}
	}

	// One account of a: the profile stays, the inventory is purged.
	stdout, stderr, err, p := runPick(t, cfgPath, []any{[]string{"a/" + p2}, true, false}, "auth", "logout")
	if err != nil || stdout != "" {
		t.Fatalf("logout: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	q := p.find(removeTitle)
	if q.Kind != "multi" || values(q.Options) != "a/"+p1+" a/"+p2+" b/"+p2 {
		t.Errorf("prompt = %+v", q)
	}
	if want := "a / " + p2 + "  account=acct-a2"; q.Options[1].Label != want {
		t.Errorf("label = %q, want %q", q.Options[1].Label, want)
	}
	if c := p.asked[1]; c.Kind != "confirm" || c.Title != "Remove 1 entry?" || c.Default != "false" {
		t.Errorf("confirmation = %+v, want default No", c)
	}
	if c := p.asked[2]; c.Kind != "confirm" || c.Title != keepTitle || c.Default != "false" {
		t.Errorf("inventory question = %+v, want default No", c)
	}
	if !strings.Contains(stderr, "account  a / "+p2) || strings.Contains(stderr, "profile  a") {
		t.Errorf("the summary must name the account and no profile: %q", stderr)
	}
	if !strings.Contains(stderr, p2+` account removed from profile "a"`) || strings.Contains(stderr, `profile "a" removed`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" b/"+p2 || cfg.CurrentProfile != "a" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("a", p2)) != "" || token(t, dir, creds.Key("a", p1)) == "" {
		t.Error("exactly the secret of the removed account must be gone")
	}
	if got := inventoryOwners(t, dir); got != "a/"+p1+" b/"+p2 {
		t.Errorf("inventory = %q", got)
	}

	// A platform argument narrows the list; answering yes keeps the inventory.
	// Removing the last account removes the (current) profile too.
	_, stderr, err, p = runPick(t, cfgPath, []any{[]string{"a/" + p1}, true, true}, "auth", "logout", p1)
	if err != nil {
		t.Fatalf("logout %s: %v (stderr %q)", p1, err, stderr)
	}
	if got := values(p.find(removeTitle).Options); got != "a/"+p1 {
		t.Errorf("options with a platform argument = %q", got)
	}
	if !strings.Contains(stderr, "profile  a (the current profile)") || !strings.Contains(stderr, `profile "a" removed`) {
		t.Errorf("stderr = %q", stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "b/"+p2 || cfg.CurrentProfile != "" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if got := inventoryOwners(t, dir); got != "a/"+p1+" b/"+p2 {
		t.Errorf("inventory = %q, want the rows of a/%s kept", got, p1)
	}

	// No account on the platform: an error, without a prompt.
	_, _, err, p = runPick(t, cfgPath, nil, "auth", "logout", p1)
	if ExitCodeFor(err) != ExitNotFound || len(p.asked) != 0 {
		t.Errorf("logout of a platform without accounts = %v (prompts %v)", err, p.titles())
	}
	if _, _, err, _ = runPick(t, cfgPath, nil, "auth", "logout", "nonsense"); ExitCodeFor(err) != ExitUsage {
		t.Errorf("logout of an unknown platform = %v, want a usage error", err)
	}
}

func TestAuthLogoutPickFlags(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	for _, ref := range loadConfig(t, cfgPath).Accounts("") {
		seedZone(t, dir, ref, strings.ReplaceAll(ref.String(), "/", "-")+".example")
	}
	// --keep-inventory answers the second question.
	_, _, err, p := runPick(t, cfgPath, []any{[]string{"a/" + p1}, true}, "auth", "logout", "--keep-inventory")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.asked) != 2 {
		t.Errorf("prompts = %v, want no inventory question", p.titles())
	}
	if got := inventoryOwners(t, dir); got != "a/"+p1+" a/"+p2+" b/"+p2 {
		t.Errorf("inventory = %q, want everything kept", got)
	}
	// --yes skips both confirmations and purges the inventory.
	_, stderr, err, p := runPick(t, cfgPath, []any{[]string{"a/" + p2, "b/" + p2}}, "auth", "logout", "--yes")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.asked) != 1 {
		t.Errorf("prompts = %v, want only the selection", p.titles())
	}
	if !strings.Contains(stderr, `profile "a" removed`) || !strings.Contains(stderr, `profile "b" removed`) {
		t.Errorf("stderr = %q", stderr)
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "" {
		t.Errorf("accounts = %q, want none", got)
	}
	if got := inventoryOwners(t, dir); got != "a/"+p1 {
		t.Errorf("inventory = %q, want only the rows kept earlier", got)
	}
	if token(t, dir, creds.Key("a", p2)) != "" || token(t, dir, creds.Key("b", p2)) != "" {
		t.Error("secrets of removed accounts survived")
	}
	_, _, err, _ = runPick(t, cfgPath, nil, "auth", "logout")
	if ExitCodeFor(err) != ExitNotFound {
		t.Errorf("logout with nothing configured = %v, want not found", err)
	}
}

// TestAuthLogoutPicksEmptyProfile covers a profile without accounts, which
// only a hand-edited config can hold.
func TestAuthLogoutPicksEmptyProfile(t *testing.T) {
	_, cfgPath := setup(t, true)
	cfg := loadConfig(t, cfgPath)
	cfg.Profiles["hollow"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	cfg.CurrentProfile = "hollow"
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	_, stderr, err, p := runPick(t, cfgPath, []any{[]string{"hollow/"}, true}, "auth", "logout")
	if err != nil {
		t.Fatalf("logout: %v (stderr %q)", err, stderr)
	}
	if got := values(p.find(removeTitle).Options); got != "a/"+p1+" hollow/" {
		t.Errorf("options = %q", got)
	}
	if len(p.asked) != 2 {
		t.Errorf("prompts = %v, want no inventory question for a profile without accounts", p.titles())
	}
	cfg = loadConfig(t, cfgPath)
	if _, ok := cfg.Profiles["hollow"]; ok || cfg.CurrentProfile != "" || accountNames(cfg) != "a/"+p1 {
		t.Errorf("profiles = %v, current = %q", cfg.ProfileNames(), cfg.CurrentProfile)
	}
}

// TestAuthManageMenu walks through every action of the menu in one session.
func TestAuthManageMenu(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, "two.example")
	seedZone(t, dir, config.AccountRef{Profile: "b", Platform: fakePlatform2}, "bee.example")

	stdout, stderr, err, p := runPick(t, cfgPath, []any{
		actDetails, "a/" + p2,
		actUse, "b",
		// p1 lives in profile a only; the profile is chosen explicitly, so
		// the "configured in another profile" guard must not fire.
		actLogin, p1, "b",
		actLogin, p1, newProfileValue, "bad name", "a", "c",
		actVerify, []string{"b/" + p2},
		actVerify, []string{},
		actRename, "b", "", "a", "b2",
		actRemove, []string{"a/" + p2, "c/" + p1}, true, false,
		actQuit,
	}, "auth", "manage")
	if err != nil {
		t.Fatalf("auth manage: %v (stderr %q)", err, stderr)
	}
	if stdout != "" {
		t.Errorf("the menu wrote to stdout: %q", stdout)
	}
	if strings.Contains(stderr, "error:") {
		t.Errorf("an action failed: %q", stderr)
	}

	menu := p.find(menuTitle)
	if got := values(menu.Options); got != strings.Join([]string{actDetails, actUse, actLogin, actVerify, actRename, actRemove, actQuit}, " ") {
		t.Errorf("menu = %q", got)
	}
	if n := strings.Count(stderr, "PROFILE  PLATFORM"); n < 9 {
		t.Errorf("the account table was printed %d times, want once per menu (9) plus the status tables", n)
	}

	// Details.
	for _, want := range []string{
		"Profile              a\n",
		"Platform             Fake Registrar (" + p2 + ")",
		"Current profile      yes",
		"Credential store     file",
		"Credentials present  yes",
		"Created              unknown",
		"Metadata account     acct-a2",
		"Cached zone          1 (synced ",
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("details lack %q in:\n%s", want, stderr)
		}
	}
	if strings.Contains(stderr, "secret-a/") {
		t.Error("details printed a secret")
	}

	// Switch.
	if q := p.find("Switch to which profile?"); q.Default != "a" || values(q.Options) != "a b" {
		t.Errorf("switch prompt = %+v", q)
	}
	if !strings.Contains(stderr, `current profile set to "b"`) {
		t.Errorf("stderr lacks the switch: %q", stderr)
	}

	// Logins.
	q := p.find("Add the account to which profile?")
	if values(q.Options) != "a b "+newProfileValue || q.Default != "b" {
		t.Errorf("target profile prompt = %+v", q)
	}
	for _, want := range []string{`logged in to Fake DNS in profile "b"`, `logged in to Fake DNS in profile "c"`} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q", want)
		}
	}

	// Verification: first one account, then all of them.
	if q := p.find("Verify which accounts? (ctrl+a ticks all)"); q.Kind != "multi" || values(q.Options) != "a/"+p1+" a/"+p2+" b/"+p1+" b/"+p2+" c/"+p1 {
		t.Errorf("verify prompt = %+v", q)
	}
	if n := strings.Count(stderr, "fake-account"); n != 6 {
		t.Errorf("verified %d rows, want 1 + 5", n)
	}
	if n := clientOn("b", fakePlatform2).count("Verify"); n != 2 {
		t.Errorf("b/%s verified %d times, want 2", p2, n)
	}
	if n := clientOn("a", fakePlatform).count("Verify"); n != 1 {
		t.Errorf("a/%s verified %d times, want 1", p1, n)
	}

	// Rename: the empty name and the existing one were rejected by the prompt.
	if !strings.Contains(stderr, `profile "b" renamed to "b2"`) {
		t.Errorf("stderr lacks the rename: %q", stderr)
	}

	// Removal.
	if q := p.find(removeTitle); values(q.Options) != "a/"+p1+" a/"+p2+" b2/"+p1+" b2/"+p2+" c/"+p1 {
		t.Errorf("remove prompt = %+v", q)
	}
	if !strings.Contains(stderr, "profile  c\n") || !strings.Contains(stderr, `profile "c" removed`) {
		t.Errorf("stderr lacks the removal of profile c: %q", stderr)
	}

	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" b2/"+p1+" b2/"+p2 {
		t.Errorf("accounts = %q", got)
	}
	if cfg.CurrentProfile != "b2" {
		t.Errorf("current_profile = %q, want b2 (it followed the rename)", cfg.CurrentProfile)
	}
	for key, want := range map[string]string{
		creds.Key("a", p1):  "secret",
		creds.Key("a", p2):  "",
		creds.Key("b", p1):  "",
		creds.Key("b", p2):  "",
		creds.Key("b2", p1): "fake",
		creds.Key("b2", p2): "secret-b/" + p2,
		creds.Key("c", p1):  "",
	} {
		if got := token(t, dir, key); got != want {
			t.Errorf("secret %s = %q, want %q", key, got, want)
		}
	}
	db := openInventory(t, dir)
	defer db.Close()
	stats, err := db.Stats(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var owners []string
	for _, s := range stats {
		owners = append(owners, s.Profile+"/"+string(s.Platform))
	}
	if want := []string{"b2/" + p2}; !reflect.DeepEqual(owners, want) {
		t.Errorf("inventory owners = %v, want %v", owners, want)
	}
}

func TestAuthManageEmptyConfig(t *testing.T) {
	dir, cfgPath := setup(t, false)
	stdout, stderr, err, p := runPick(t, cfgPath, []any{actLogin, p1, keepDefault{}, actQuit}, "auth", "manage")
	if err != nil || stdout != "" {
		t.Fatalf("auth manage: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	if got := values(p.asked[0].Options); got != actLogin+" "+actQuit {
		t.Errorf("menu without profiles = %q", got)
	}
	if !strings.Contains(stderr, "no accounts configured") {
		t.Errorf("stderr lacks the empty table note: %q", stderr)
	}
	if q := p.find("Name of the new profile"); q.Kind != "input" || q.Default != config.DefaultProfile {
		t.Errorf("name prompt = %+v", q)
	}
	for _, a := range p.asked {
		if a.Title == "Add the account to which profile?" {
			t.Error("asked to choose among profiles when there is none")
		}
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "default/"+p1 || cfg.CurrentProfile != "default" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("default", p1)) != "fake" {
		t.Error("the secret was not stored")
	}
	if got := values(p.asked[len(p.asked)-1].Options); !strings.Contains(got, actDetails) || !strings.Contains(got, actRemove) {
		t.Errorf("menu after the login = %q", got)
	}
}

func TestAuthManageAbortAndErrors(t *testing.T) {
	dir, cfgPath := setupMulti(t)

	// Leaving the menu at its top level ends the command quietly.
	stdout, stderr, err, _ := runPick(t, cfgPath, []any{abort{}}, "auth", "manage")
	if err != nil || stdout != "" || strings.Contains(stderr, "error") || strings.Contains(stderr, "cancelled") {
		t.Errorf("abort at the top level: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}

	// Leaving a prompt of an action returns to the menu.
	_, stderr, err, p := runPick(t, cfgPath, []any{
		actUse, abort{},
		actRename, "a", abort{},
		actLogin, p1, abort{},
		actLogin, p1, newProfileValue, abort{},
		actVerify, abort{},
		actDetails, abort{},
		actRemove, []string{"b/" + p2}, abort{},
		actQuit,
	}, "auth", "manage")
	if err != nil || strings.Contains(stderr, "error:") {
		t.Errorf("aborted actions: %v (stderr %q)", err, stderr)
	}
	menus := 0
	for _, a := range p.asked {
		if a.Title == menuTitle {
			menus++
		}
	}
	if menus != 8 {
		t.Errorf("the menu was shown %d times, want 8", menus)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" a/"+p2+" b/"+p2 || cfg.CurrentProfile != "" {
		t.Errorf("aborted actions changed the config: accounts %q, current %q", got, cfg.CurrentProfile)
	}

	// A failing action is reported and the menu goes on. The inventory
	// cannot be opened here, which breaks the details and the removal.
	t.Setenv("POLYCTL_INVENTORY_DB", filepath.Join(dir, "missing-dir", "inventory.db"))
	_, stderr, err, _ = runPick(t, cfgPath, []any{
		actDetails, "a/" + p1,
		actRemove, []string{"a/" + p1}, true, false,
		actUse, "b",
		actQuit,
	}, "auth", "manage")
	if err != nil {
		t.Fatalf("a failing action ended the menu: %v", err)
	}
	if n := strings.Count(stderr, "\nerror: "); n != 2 {
		t.Errorf("%d errors reported, want 2: %q", n, stderr)
	}
	cfg = loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" a/"+p2+" b/"+p2 || cfg.CurrentProfile != "b" {
		t.Errorf("accounts %q, current %q; want nothing removed and b current", got, cfg.CurrentProfile)
	}
	if token(t, dir, creds.Key("a", p1)) == "" {
		t.Error("the failed removal deleted the secret")
	}
}

func TestAuthManageDetailsSingleAccount(t *testing.T) {
	dir, cfgPath := setup(t, true)
	// The only account is shown without asking which one. Its secret is
	// missing, which the details must say.
	if err := creds.NewFile(dir).Delete(creds.Key("a", p1)); err != nil {
		t.Fatal(err)
	}
	_, stderr, err, p := runPick(t, cfgPath, []any{actDetails, actQuit}, "auth", "manage")
	if err != nil {
		t.Fatal(err)
	}
	if len(p.asked) != 2 {
		t.Errorf("prompts = %v, want only the two menus", p.titles())
	}
	for _, want := range []string{"Current profile      no", "Credentials present  no", "Cached resources     none (never synced)"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("details lack %q in:\n%s", want, stderr)
		}
	}
}

// seedRename prepares setupMulti with inventory rows for every account and
// profile a as the current one.
func seedRename(t *testing.T) (dir, cfgPath string) {
	t.Helper()
	dir, cfgPath = setupMulti(t)
	if _, _, err := run(t, cfgPath, "auth", "use", "a"); err != nil {
		t.Fatal(err)
	}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, "one.example")
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, "two.example")
	seedZone(t, dir, config.AccountRef{Profile: "b", Platform: fakePlatform2}, "bee.example")
	return dir, cfgPath
}

// zoneOwners lists the cached zones as "profile/platform=zone", sorted.
func zoneOwners(t *testing.T, dir string) string {
	t.Helper()
	db := openInventory(t, dir)
	defer db.Close()
	entries, err := db.IndexEntries(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Profile+"/"+string(e.Platform)+"="+e.Domain)
	}
	return strings.Join(out, " ")
}

func TestAuthRename(t *testing.T) {
	dir, cfgPath := seedRename(t)
	// Stale rows under the new name, left by a profile removed with
	// --keep-inventory, must not survive next to the renamed ones.
	seedZone(t, dir, config.AccountRef{Profile: "acme", Platform: fakePlatform}, "stale.example")
	// An orphaned secret under a new key must not be adopted either.
	before := loadConfig(t, cfgPath).Profiles["a"].Platforms[fakePlatform2]

	stdout, stderr, err := run(t, cfgPath, "auth", "rename", "a", "acme")
	if err != nil {
		t.Fatalf("rename: %v (stderr %q)", err, stderr)
	}
	if stdout != "" || !strings.Contains(stderr, `profile "a" renamed to "acme"`) {
		t.Errorf("stdout %q, stderr %q", stdout, stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "acme/"+p1+" acme/"+p2+" b/"+p2 {
		t.Errorf("accounts = %q", got)
	}
	if cfg.CurrentProfile != "acme" {
		t.Errorf("current_profile = %q, want it to follow the rename", cfg.CurrentProfile)
	}
	after := cfg.Profiles["acme"].Platforms[fakePlatform2]
	if !reflect.DeepEqual(after.Metadata, before.Metadata) || after.CredentialBackend != "file" {
		t.Errorf("account after the rename = %+v, before = %+v", after, before)
	}
	for key, want := range map[string]string{
		creds.Key("acme", p1): "secret",
		creds.Key("acme", p2): "secret-a/" + p2,
		creds.Key("a", p1):    "",
		creds.Key("a", p2):    "",
		creds.Key("b", p2):    "secret-b/" + p2,
	} {
		if got := token(t, dir, key); got != want {
			t.Errorf("secret %s = %q, want %q", key, got, want)
		}
	}
	if got, want := zoneOwners(t, dir), "b/"+p2+"=bee.example acme/"+p1+"=one.example acme/"+p2+"=two.example"; got != want {
		t.Errorf("inventory = %q, want %q", got, want)
	}
	db := openInventory(t, dir)
	stats, err := db.Stats(context.Background())
	db.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range stats {
		if s.Profile == "a" {
			t.Errorf("sync state left under the old name: %+v", s)
		}
	}

	// The renamed profile works: its accounts open with the moved secrets.
	if _, stderr, err := run(t, cfgPath, "auth", "status", "--profile", "acme"); err != nil {
		t.Errorf("status of the renamed profile: %v (stderr %q)", err, stderr)
	}

	// A profile that is not current leaves current_profile alone.
	if _, _, err := run(t, cfgPath, "auth", "rename", "b", "bee"); err != nil {
		t.Fatal(err)
	}
	cfg = loadConfig(t, cfgPath)
	if cfg.CurrentProfile != "acme" || accountNames(cfg) != "acme/"+p1+" acme/"+p2+" bee/"+p2 {
		t.Errorf("accounts = %q, current = %q", accountNames(cfg), cfg.CurrentProfile)
	}
}

func TestAuthRenameAccountWithoutSecret(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	store := creds.NewFile(dir)
	if err := store.Delete(creds.Key("a", p2)); err != nil {
		t.Fatal(err)
	}
	// An orphaned entry under the new key is not the secret of the account.
	if err := store.Set(creds.Key("acme", p2), map[string]string{"token": "orphan"}); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := run(t, cfgPath, "auth", "rename", "a", "acme"); err != nil {
		t.Fatalf("rename: %v (stderr %q)", err, stderr)
	}
	if got := token(t, dir, creds.Key("acme", p2)); got != "" {
		t.Errorf("the account without credentials adopted %q", got)
	}
	if got := token(t, dir, creds.Key("acme", p1)); got != "secret" {
		t.Errorf("secret of the other account = %q", got)
	}
}

func TestAuthRenameErrors(t *testing.T) {
	dir, cfgPath := seedRename(t)
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"missing", "x"}, ExitNotFound, `profile "missing" not found`},
		{[]string{"a", "b"}, ExitUsage, `profile "b" already exists`},
		{[]string{"a", "a"}, ExitUsage, `profile "a" already exists`},
		{[]string{"a", "has space"}, ExitUsage, "must not contain spaces or slashes"},
		{[]string{"a", "has/slash"}, ExitUsage, "must not contain spaces or slashes"},
		{[]string{"a", "has\ttab"}, ExitUsage, "must not contain spaces or slashes"},
		{[]string{"a", ""}, ExitUsage, "must not be empty"},
		{[]string{"a"}, ExitUsage, "accepts 2 arg(s)"},
	} {
		code, stdout, stderr := mainRun(cfgPath, append([]string{"auth", "rename"}, tc.args...)...)
		if code != tc.code || !strings.Contains(stderr, tc.want) || stdout != "" {
			t.Errorf("rename %q: exit %d, stderr %q; want exit %d and %q", tc.args, code, stderr, tc.code, tc.want)
		}
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a refused rename changed the config")
	}
	if token(t, dir, creds.Key("a", p1)) != "secret" {
		t.Error("a refused rename touched the secrets")
	}
	if got := inventoryOwners(t, dir); got != "a/"+p1+" a/"+p2+" b/"+p2 {
		t.Errorf("a refused rename touched the inventory: %q", got)
	}
}

// TestAuthRenameRefusesLegacySecret covers an account converted from the
// pre-0.2 layout whose secret could not be moved: it sits in a backend this
// run cannot reach.
func TestAuthRenameRefusesLegacySecret(t *testing.T) {
	dir, cfgPath := setup(t, false)
	legacy := "current_profile: old\nprofiles:\n  old:\n    platform: " + p1 + "\n    credential_backend: keyring\n    metadata:\n      account: acct-old\n"
	if err := os.WriteFile(cfgPath, []byte(legacy), 0o600); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := mainRun(cfgPath, "auth", "rename", "old", "new")
	if code != ExitError {
		t.Fatalf("rename of a legacy-marked profile: exit %d (stderr %q)", code, stderr)
	}
	for _, want := range []string{`profile "old" cannot be renamed yet`, "pre-0.2 layout", `"keyring"`, "auth login " + p1 + " --profile old"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q: %q", want, stderr)
		}
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "old/"+p1 || cfg.CurrentProfile != "old" {
		t.Errorf("accounts = %q, current = %q", got, cfg.CurrentProfile)
	}
	if !cfg.Profiles["old"].Platforms[fakePlatform].LegacySecret {
		t.Error("the legacy mark was dropped")
	}
	if token(t, dir, creds.Key("new", p1)) != "" {
		t.Error("a secret was written under the new name")
	}
}

// TestAuthRenameRollsBack makes the inventory step fail for the second
// account, after the secrets were copied and the first account's rows were
// renamed, and checks that everything is put back.
func TestAuthRenameRollsBack(t *testing.T) {
	dir, cfgPath := seedRename(t)
	if fakePlatform >= fakePlatform2 {
		t.Fatal("this test needs fakePlatform to sort before fakePlatform2")
	}
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := sql.Open("sqlite", openInventoryPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	if _, err := raw.Exec(`CREATE TRIGGER block_rename BEFORE UPDATE ON resources WHEN OLD.platform = '` + p2 + `' BEGIN SELECT RAISE(ABORT, 'rename blocked'); END`); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := mainRun(cfgPath, "auth", "rename", "a", "acme")
	if code != ExitError || !strings.Contains(stderr, "rename blocked") {
		t.Fatalf("rename with a failing inventory: exit %d (stderr %q)", code, stderr)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the config changed:\n%s", after)
	}
	for key, want := range map[string]string{
		creds.Key("a", p1):    "secret",
		creds.Key("a", p2):    "secret-a/" + p2,
		creds.Key("acme", p1): "",
		creds.Key("acme", p2): "",
	} {
		if got := token(t, dir, key); got != want {
			t.Errorf("secret %s = %q, want %q", key, got, want)
		}
	}
	if got, want := zoneOwners(t, dir), "b/"+p2+"=bee.example a/"+p1+"=one.example a/"+p2+"=two.example"; got != want {
		t.Errorf("inventory = %q, want %q", got, want)
	}

	// Once the inventory works again the rename goes through.
	if _, err := raw.Exec(`DROP TRIGGER block_rename`); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := run(t, cfgPath, "auth", "rename", "a", "acme"); err != nil {
		t.Fatalf("second rename: %v (stderr %q)", err, stderr)
	}
	if got := accountNames(loadConfig(t, cfgPath)); got != "acme/"+p1+" acme/"+p2+" b/"+p2 {
		t.Errorf("accounts = %q", got)
	}
}

// TestAuthRenameRollsBackWhenSaveFails makes saving the config fail after
// the secrets were copied and the inventory rows renamed.
func TestAuthRenameRollsBackWhenSaveFails(t *testing.T) {
	dir, cfgPath := seedRename(t)
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{ConfigPath: cfgPath}, strings.NewReader(""), &out, &errb)
	defer rt.Close()
	if _, err := rt.Config(); err != nil {
		t.Fatal(err)
	}
	// With the config loaded, a non-empty directory takes the place of the
	// file: the save, which renames a temporary file over it, cannot
	// succeed, while the secrets and the inventory next to it stay writable.
	if err := os.Remove(cfgPath); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cfgPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cfgPath, "keep"), nil, 0o600); err != nil {
		t.Fatal(err)
	}

	err := renameProfile(context.Background(), rt, "a", "acme")
	if err == nil || !strings.Contains(err.Error(), "save config") {
		t.Fatalf("rename with a config that cannot be saved = %v", err)
	}
	cfg, _ := rt.Config()
	if got := accountNames(cfg); got != "a/"+p1+" a/"+p2+" b/"+p2 || cfg.CurrentProfile != "a" {
		t.Errorf("config in memory: accounts %q, current %q", got, cfg.CurrentProfile)
	}
	for key, want := range map[string]string{
		creds.Key("a", p1):    "secret",
		creds.Key("a", p2):    "secret-a/" + p2,
		creds.Key("acme", p1): "",
		creds.Key("acme", p2): "",
	} {
		if got := token(t, dir, key); got != want {
			t.Errorf("secret %s = %q, want %q", key, got, want)
		}
	}
	_ = rt.Close()
	if got, want := zoneOwners(t, dir), "b/"+p2+"=bee.example a/"+p1+"=one.example a/"+p2+"=two.example"; got != want {
		t.Errorf("inventory = %q, want %q", got, want)
	}
}

func TestAuthRenameCompletion(t *testing.T) {
	_, cfgPath := setupMulti(t)
	stdout, _, err := run(t, cfgPath, "__complete", "auth", "rename", "")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stdout, "a\t"+p1+", "+p2) || !strings.Contains(stdout, "b\t"+p2) {
		t.Errorf("completion of the first argument = %q", stdout)
	}
	stdout, _, err = run(t, cfgPath, "__complete", "auth", "rename", "a", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "b\t") {
		t.Errorf("the new name must not complete existing profiles: %q", stdout)
	}
	stdout, _, err = run(t, cfgPath, "__complete", "auth", "use", "a", "")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stdout, "b\t") {
		t.Errorf("auth use takes one profile: %q", stdout)
	}
	stdout, _, err = run(t, cfgPath, "__complete", "auth", "")
	if err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"manage", "rename"} {
		if !strings.Contains(stdout, sub+"\t") {
			t.Errorf("auth does not complete %q: %q", sub, stdout)
		}
	}
}

// setBackend rewrites the recorded credential backend of one account, the
// way a config written on another machine (or by hand) would have it.
func setBackend(t *testing.T, cfgPath, profile string, id platform.ID, backend string) {
	t.Helper()
	cfg := loadConfig(t, cfgPath)
	cfg.Profiles[profile].Platforms[id].CredentialBackend = backend
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
}

// TestAuthRenameRefusesUnreachableBackend covers an account whose secret is
// recorded in a backend that is not part of the opened store: the keyring,
// while this run uses the file store only.
func TestAuthRenameRefusesUnreachableBackend(t *testing.T) {
	dir, cfgPath := seedRename(t)
	setBackend(t, cfgPath, "a", fakePlatform2, "keyring")
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := mainRun(cfgPath, "auth", "rename", "a", "acme")
	if code != ExitError || stdout != "" {
		t.Fatalf("rename with an unreachable backend: exit %d (stdout %q, stderr %q), want %d", code, stdout, stderr, ExitError)
	}
	want := `profile "a" cannot be renamed now: its ` + p2 + ` credentials are stored in the keyring backend, which is not available in this session`
	if !strings.Contains(stderr, want) {
		t.Errorf("stderr lacks %q: %q", want, stderr)
	}
	after, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Errorf("the refused rename changed the config:\n%s", after)
	}
	for key, want := range map[string]string{
		creds.Key("a", p1):    "secret",
		creds.Key("a", p2):    "secret-a/" + p2,
		creds.Key("b", p2):    "secret-b/" + p2,
		creds.Key("acme", p1): "",
		creds.Key("acme", p2): "",
	} {
		if got := token(t, dir, key); got != want {
			t.Errorf("secret %s = %q, want %q", key, got, want)
		}
	}
	if got, want := zoneOwners(t, dir), "b/"+p2+"=bee.example a/"+p1+"=one.example a/"+p2+"=two.example"; got != want {
		t.Errorf("inventory = %q, want %q", got, want)
	}

	// The menu action refuses the same way and keeps the menu open.
	_, stderr, err, _ = runPick(t, cfgPath, []any{actRename, "a", "acme", actQuit}, "auth", "manage")
	if err != nil || !strings.Contains(stderr, "error: "+want) {
		t.Errorf("rename from the menu: %v (stderr %q)", err, stderr)
	}
	if after, err = os.ReadFile(cfgPath); err != nil || !bytes.Equal(before, after) {
		t.Errorf("the refused rename from the menu changed the config (%v):\n%s", err, after)
	}

	// A profile whose backends are all reachable is not affected.
	if _, stderr, err := run(t, cfgPath, "auth", "rename", "b", "bee"); err != nil {
		t.Errorf("rename of another profile: %v (stderr %q)", err, stderr)
	}
}

// removalListing returns the lines printed between the "will be removed"
// heading and the first line that is not part of the listing.
func removalListing(t *testing.T, stderr string) []string {
	t.Helper()
	_, rest, ok := strings.Cut(stderr, "The following will be removed, with the stored credentials:\n")
	if !ok {
		t.Fatalf("no removal listing in %q", stderr)
	}
	var out []string
	for _, line := range strings.Split(rest, "\n") {
		if !strings.HasPrefix(line, "  ") {
			break
		}
		out = append(out, strings.TrimSpace(line))
	}
	return out
}

// TestRemovalListingOmitsUnselectedEmptyProfile checks that a profile without
// accounts is listed as removed only when it was selected.
func TestRemovalListingOmitsUnselectedEmptyProfile(t *testing.T) {
	_, cfgPath := setupMulti(t)
	cfg := loadConfig(t, cfgPath)
	cfg.Profiles["hollow"] = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
	if err := cfg.Save(); err != nil {
		t.Fatal(err)
	}
	hasProfile := func(name string) bool {
		_, ok := loadConfig(t, cfgPath).Profiles[name]
		return ok
	}

	// With a platform argument the empty profile cannot even be selected.
	_, stderr, err, p := runPick(t, cfgPath, []any{[]string{"b/" + p2}, true, false}, "auth", "logout", p2)
	if err != nil {
		t.Fatalf("logout %s: %v (stderr %q)", p2, err, stderr)
	}
	if got := values(p.find(removeTitle).Options); got != "a/"+p2+" b/"+p2 {
		t.Errorf("options with a platform argument = %q", got)
	}
	if got, want := removalListing(t, stderr), []string{"account  b / " + p2 + "  account=acct-b", "profile  b"}; !reflect.DeepEqual(got, want) {
		t.Errorf("listing = %q, want %q", got, want)
	}
	if strings.Contains(stderr, "hollow") {
		t.Errorf("the unselected empty profile is mentioned: %q", stderr)
	}
	if hasProfile("b") || !hasProfile("hollow") {
		t.Errorf("profiles = %v, want b removed and hollow kept", loadConfig(t, cfgPath).ProfileNames())
	}

	// Without one it is offered, and left alone when it stays unticked.
	_, stderr, err, p = runPick(t, cfgPath, []any{[]string{"a/" + p1}, true, false}, "auth", "logout")
	if err != nil {
		t.Fatalf("logout: %v (stderr %q)", err, stderr)
	}
	if got := values(p.find(removeTitle).Options); got != "a/"+p1+" a/"+p2+" hollow/" {
		t.Errorf("options = %q", got)
	}
	if got, want := removalListing(t, stderr), []string{"account  a / " + p1 + "  account=acct-a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("listing = %q, want %q", got, want)
	}
	if strings.Contains(stderr, "hollow") {
		t.Errorf("the unselected empty profile is mentioned: %q", stderr)
	}
	if !hasProfile("a") || !hasProfile("hollow") {
		t.Errorf("profiles = %v, want a and hollow kept", loadConfig(t, cfgPath).ProfileNames())
	}

	// The same holds in the menu, for a profile that loses its last account.
	_, stderr, err, _ = runPick(t, cfgPath, []any{actRemove, []string{"a/" + p2}, true, false, actQuit}, "auth", "manage")
	if err != nil {
		t.Fatalf("auth manage: %v (stderr %q)", err, stderr)
	}
	if got, want := removalListing(t, stderr), []string{"account  a / " + p2 + "  account=acct-a2", "profile  a"}; !reflect.DeepEqual(got, want) {
		t.Errorf("listing = %q, want %q", got, want)
	}
	if hasProfile("a") || !hasProfile("hollow") {
		t.Errorf("profiles = %v, want only hollow kept", loadConfig(t, cfgPath).ProfileNames())
	}

	// Once ticked, it is listed and removed.
	_, stderr, err, _ = runPick(t, cfgPath, []any{[]string{"hollow/"}, true}, "auth", "logout")
	if err != nil {
		t.Fatalf("logout: %v (stderr %q)", err, stderr)
	}
	if got, want := removalListing(t, stderr), []string{"profile  hollow"}; !reflect.DeepEqual(got, want) {
		t.Errorf("listing = %q, want %q", got, want)
	}
	if hasProfile("hollow") {
		t.Error("the selected empty profile was not removed")
	}
}

// TestAuthLogoutWarnsAboutUnreachableBackend covers accounts whose secret is
// recorded in a backend that is not part of the opened store. None of them
// carries the legacy mark.
func TestAuthLogoutWarnsAboutUnreachableBackend(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	setBackend(t, cfgPath, "a", fakePlatform2, "keyring")
	setBackend(t, cfgPath, "b", fakePlatform2, "keyring")
	for _, ref := range loadConfig(t, cfgPath).Accounts("") {
		if loadConfig(t, cfgPath).Profiles[ref.Profile].Platforms[ref.Platform].LegacySecret {
			t.Fatalf("%s carries the legacy mark", ref)
		}
		seedZone(t, dir, ref, strings.ReplaceAll(ref.String(), "/", "-")+".example")
	}
	warning := func(profile string) string {
		return "warning: the " + p2 + ` credentials of profile "` + profile + `" are stored in the keyring backend, which is not available now, and were not removed`
	}

	code, stdout, stderr := mainRun(cfgPath, "auth", "logout", p2, "--profile", "a")
	if code != ExitOK || stdout != "" {
		t.Fatalf("logout: exit %d (stdout %q, stderr %q)", code, stdout, stderr)
	}
	if !strings.Contains(stderr, warning("a")) || !strings.Contains(stderr, p2+` account removed from profile "a"`) {
		t.Errorf("stderr = %q, want the warning and the removal", stderr)
	}
	cfg := loadConfig(t, cfgPath)
	if got := accountNames(cfg); got != "a/"+p1+" b/"+p2 {
		t.Errorf("accounts = %q, want the account removed from the config", got)
	}
	if got := inventoryOwners(t, dir); got != "a/"+p1+" b/"+p2 {
		t.Errorf("inventory = %q", got)
	}
	if token(t, dir, creds.Key("a", p1)) != "secret" {
		t.Error("the secret of the other account was touched")
	}

	// An account in a reachable backend is removed without the warning.
	code, _, stderr = mainRun(cfgPath, "auth", "logout", p1, "--profile", "a")
	if code != ExitOK || strings.Contains(stderr, "warning:") {
		t.Errorf("logout of a reachable account: exit %d (stderr %q)", code, stderr)
	}

	// The interactive removal warns as well and removes the profile.
	_, stderr, err, _ := runPick(t, cfgPath, []any{[]string{"b/" + p2}, true, false}, "auth", "logout")
	if err != nil {
		t.Fatalf("interactive logout: %v (stderr %q)", err, stderr)
	}
	if !strings.Contains(stderr, warning("b")) || !strings.Contains(stderr, `profile "b" removed`) {
		t.Errorf("stderr = %q, want the warning and the removal", stderr)
	}
	if cfg = loadConfig(t, cfgPath); len(cfg.Profiles) != 0 {
		t.Errorf("profiles = %v, want none", cfg.ProfileNames())
	}
}

// TestAuthLoginOffline checks that no login flow starts under --offline.
func TestAuthLoginOffline(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	before, err := os.ReadFile(cfgPath)
	if err != nil {
		t.Fatal(err)
	}
	unchanged := func(what string) {
		t.Helper()
		if n := loginCalls(); n != 0 {
			t.Errorf("%s: the provider's Login ran %d time(s)", what, n)
		}
		after, err := os.ReadFile(cfgPath)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(before, after) {
			t.Errorf("%s changed the config:\n%s", what, after)
		}
		for key, want := range map[string]string{creds.Key("a", p1): "secret", creds.Key("b", p1): "", creds.Key("new", p1): ""} {
			if got := token(t, dir, key); got != want {
				t.Errorf("%s: secret %s = %q, want %q", what, key, got, want)
			}
		}
	}

	for _, args := range [][]string{
		{"auth", "login", p1, "--profile", "a", "--offline"},   // re-authentication
		{"auth", "login", p1, "--profile", "b", "--offline"},   // new account
		{"auth", "login", p1, "--profile", "new", "--offline"}, // new profile
		{"--offline", "auth", "login", p2, "--set", "token=x"},
	} {
		code, stdout, stderr := mainRun(cfgPath, args...)
		if code != ExitOffline || stdout != "" || !strings.Contains(stderr, app.ErrOffline.Error()) {
			t.Errorf("%v: exit %d (stdout %q, stderr %q), want %d", args, code, stdout, stderr, ExitOffline)
		}
		unchanged(strings.Join(args, " "))
	}

	// With the platform picked from the list.
	_, _, err, _ = runPick(t, cfgPath, []any{p1}, "auth", "login", "--profile", "b", "--offline")
	if !errors.Is(err, app.ErrOffline) || ExitCodeFor(err) != ExitOffline {
		t.Errorf("interactive auth login --offline = %v, want app.ErrOffline", err)
	}
	unchanged("interactive auth login --offline")

	// "Add an account" of the menu: reported, and the menu stays open.
	stdout, stderr, err, _ := runPick(t, cfgPath, []any{
		actLogin, p1, "b",
		actLogin, p1, newProfileValue, "new",
		actQuit,
	}, "auth", "manage", "--offline")
	if err != nil || stdout != "" {
		t.Fatalf("auth manage --offline: %v (stdout %q, stderr %q)", err, stdout, stderr)
	}
	if n := strings.Count(stderr, "error: "+app.ErrOffline.Error()); n != 2 {
		t.Errorf("%d offline errors reported, want 2: %q", n, stderr)
	}
	if strings.Contains(stderr, "logged in to") {
		t.Errorf("a login went through: %q", stderr)
	}
	unchanged("auth manage --offline")

	// Without --offline the same login runs.
	if _, stderr, err := run(t, cfgPath, "auth", "login", p1, "--profile", "b"); err != nil || loginCalls() != 1 {
		t.Errorf("online login: %v, %d Login call(s) (stderr %q)", err, loginCalls(), stderr)
	}
}
