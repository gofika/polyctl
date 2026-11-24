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
