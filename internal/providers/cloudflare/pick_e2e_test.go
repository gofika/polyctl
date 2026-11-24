package cloudflare_test

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// runPick runs the command line with a scripted picker (the interactive
// flow).
func (e *zoneEnv) runPick(p *prompttest.Picker, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
	rt.Picker = p
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
	root.SetIn(strings.NewReader(""))
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

// zone setting set without arguments: the zones of every account, then
// the editable settings with their values, then the value (a switch
// offers on/off with the opposite of the current one preselected).
func TestZoneSettingSetPicks(t *testing.T) {
	e := newZoneEnv(t)
	z := e.f.addZone("example.com", "acc1", "free", "active")
	p := prompttest.New(t, z.id, "always_use_https", "on")
	code, _, stderr := e.runPick(p, "cloudflare", "zone", "setting", "set")
	if code != cli.ExitOK || z.settings["always_use_https"].value != "on" {
		t.Fatalf("set: exit %d, %s", code, stderr)
	}
	if a := p.Find("Zone"); len(a.Options) != 1 || !strings.Contains(a.Options[0].Label, "example.com  active  "+z.id) {
		t.Errorf("zone options %+v", a.Options)
	}
	if a := p.Find("Setting of example.com"); !strings.Contains(prompttest.Labels(a.Options), "always_use_https = off") ||
		!strings.Contains(prompttest.Values(a.Options), "argo_smart_routing foundation_dns") {
		t.Errorf("setting options %+v", a.Options)
	}
	if a := p.Find("New value of always_use_https"); a.Default != "on" || prompttest.Values(a.Options) != "on off" {
		t.Errorf("value options (default %q): %+v", a.Default, a.Options)
	}
	p.Done()

	// Leaving a question writes nothing.
	e.f.reset()
	code, _, stderr = e.runPick(prompttest.New(t, z.id, prompttest.Abort{}), "cloudflare", "zone", "setting", "set")
	if code != cli.ExitOK || len(e.f.writes()) != 0 || !strings.Contains(stderr, "cancelled") {
		t.Errorf("abort: exit %d, writes %v, %s", code, e.f.writes(), stderr)
	}
	// The non-interactive flow is unchanged.
	if code, _, _ := e.run("cloudflare", "zone", "setting", "set", "example.com"); code != cli.ExitUsage {
		t.Errorf("non-interactive: exit %d", code)
	}
}

func (e *r2Env) runPick(p *prompttest.Picker, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
	rt.Picker = p
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
	root.SetIn(strings.NewReader(""))
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

// r2 domain update without arguments: the buckets, then the custom domains
// bound to the chosen one, then what to change.
func TestR2DomainUpdatePicks(t *testing.T) {
	e := newR2Env(t)
	e.f.accounts["acc1"].buckets = []string{"assets", "other"}
	if code, _, stderr := e.run("cloudflare", "r2", "domain", "attach", "assets", "cdn.example.com"); code != cli.ExitOK {
		t.Fatalf("attach: exit %d, %s", code, stderr)
	}
	p := prompttest.New(t, "assets", "cdn.example.com", "toggle")
	code, stdout, stderr := e.runPick(p, "cloudflare", "r2", "domain", "update")
	if code != cli.ExitOK || !strings.Contains(stdout, "enabled true -> false") {
		t.Fatalf("update: exit %d, %q, %s", code, stdout, stderr)
	}
	if a := p.Find("R2 bucket"); prompttest.Values(a.Options) != "assets other" || !strings.Contains(a.Options[0].Label, "assets  cloudflare/acme") {
		t.Errorf("bucket options %+v", a.Options)
	}
	if a := p.Find("Custom domain of assets"); len(a.Options) != 1 || !strings.Contains(a.Options[0].Label, "cdn.example.com  enabled") {
		t.Errorf("domain options %+v", a.Options)
	}
	if a := p.Find("What to change on cdn.example.com"); a.Options[0].Label != "Disable the domain" {
		t.Errorf("change options %+v", a.Options)
	}
	p.Done()
	// A bucket without custom domains: nothing to do.
	code, _, stderr = e.runPick(prompttest.New(t, "other"), "cloudflare", "r2", "domain", "get")
	if code != cli.ExitOK || !strings.Contains(stderr, "nothing to do") {
		t.Errorf("empty bucket: exit %d, %s", code, stderr)
	}
}

// zone ensure without <domain> offers the registered domains without a
// Cloudflare zone and "Another domain...", whose name is checked as it is
// typed.
func TestZoneEnsureAsksTheDomain(t *testing.T) {
	e := newZoneEnv(t)
	p := prompttest.New(t, prompttest.Label("Another domain"), "not a domain", "example.org")
	code, stdout, stderr := e.runPick(p, "cloudflare", "zone", "ensure", "--dry-run", "-o", "json")
	if code != cli.ExitOK || !strings.Contains(stdout, `"zone/example.org"`) || len(e.f.writes()) != 0 {
		t.Fatalf("ensure: exit %d, %s %s", code, stdout, stderr)
	}
	p.Done()
	if code, _, _ := e.run("cloudflare", "zone", "ensure"); code != cli.ExitUsage {
		t.Errorf("non-interactive: exit %d", code)
	}
}

// Without a zone to choose from, dns create (which cannot do without one)
// is a usage error naming <zone>, while dns list has nothing to do.
func TestDNSCreateWithoutZonesIsAUsageError(t *testing.T) {
	e := newZoneEnv(t)
	code, _, stderr := e.runPick(prompttest.New(t), "cloudflare", "dns", "create", "--type", "A", "--value", "192.0.2.1")
	if code != cli.ExitUsage || !strings.Contains(stderr, "<zone> is required, and there is no zone in cloudflare/") {
		t.Errorf("create: exit %d, %s", code, stderr)
	}
	code, _, stderr = e.runPick(prompttest.New(t), "cloudflare", "dns", "list")
	if code != cli.ExitOK || !strings.Contains(stderr, "nothing to do: no zone in cloudflare/") {
		t.Errorf("list: exit %d, %s", code, stderr)
	}
}
