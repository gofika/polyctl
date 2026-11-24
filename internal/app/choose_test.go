package app_test

import (
	"bytes"
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

func interactiveRT(t *testing.T, answers ...any) (*app.Runtime, *prompttest.Picker) {
	t.Helper()
	t.Setenv(app.EnvNonInteractive, "")
	rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	p := prompttest.New(t, answers...)
	rt.Picker = p
	return rt, p
}

func TestChoose(t *testing.T) {
	opts := []prompt.Option{{Label: "web-1  i-1", Value: "i-1"}, {Label: "web-2  i-2", Value: "i-2"}}

	rt, p := interactiveRT(t, "i-2")
	got, err := rt.Choose(app.Choice{Title: "Instance", Options: opts, Default: "i-1", Arg: "<instance>"})
	if err != nil || got != "i-2" {
		t.Errorf("pick = %q, %v", got, err)
	}
	if a := p.Find("Instance"); a.Default != "i-1" || prompttest.Values(a.Options) != "i-1 i-2" {
		t.Errorf("offered %+v", a)
	}
	p.Done()

	// The create option comes last and runs Create.
	rt, p = interactiveRT(t, prompttest.Label("Create a new key pair"))
	got, err = rt.Choose(app.Choice{Title: "Key pair", Options: opts, Arg: "--key-pair", CreateLabel: "Create a new key pair...",
		Create: func() (string, error) { return "new", nil }})
	if err != nil || got != "new" {
		t.Errorf("create = %q, %v", got, err)
	}
	if a := p.Find("Key pair"); len(a.Options) != 3 || a.Options[2].Label != "Create a new key pair..." {
		t.Errorf("create option missing: %+v", a.Options)
	}

	// Nothing listed but creatable: Create runs without a question.
	rt, _ = interactiveRT(t)
	if got, err = rt.Choose(app.Choice{Title: "Key pair", Arg: "--key-pair", Create: func() (string, error) { return "new", nil }}); err != nil || got != "new" {
		t.Errorf("empty with create = %q, %v", got, err)
	}

	// Nothing to choose from: a note for a target, a usage error for a
	// required input of a create.
	if _, err = rt.Choose(app.Choice{Title: "Domain", Arg: "<domain>", What: "indexed domain"}); !errors.Is(err, platform.ErrNothingToDo) || !strings.Contains(err.Error(), "no indexed domain") {
		t.Errorf("empty target = %v", err)
	}
	if _, err = rt.Choose(app.Choice{Title: "VPC", Arg: "--vpc", Required: true}); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--vpc") {
		t.Errorf("empty required = %v", err)
	}

	// Leaving the picker is ErrAborted, which QuietAbort turns into
	// "cancelled".
	rt, _ = interactiveRT(t, prompttest.Abort{})
	if _, err = rt.Choose(app.Choice{Title: "Instance", Options: opts}); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}

	// The non-interactive flow asks nothing and names the input.
	t.Setenv(app.EnvNonInteractive, "1")
	rt = app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &bytes.Buffer{})
	if _, err = rt.Choose(app.Choice{Title: "Instance", Options: opts, Arg: "<instance>"}); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "<instance> is required") {
		t.Errorf("non-interactive = %v", err)
	}
	if _, err = rt.AskInput("--name", "Name", "", nil); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--name is required") {
		t.Errorf("non-interactive input = %v", err)
	}
}

func TestChooseMany(t *testing.T) {
	opts := []prompt.Option{{Label: "a", Value: "a"}, {Label: "b", Value: "b"}}
	rt, _ := interactiveRT(t, []string{"b"}, []string{})
	if got, err := rt.ChooseMany(app.Choice{Title: "Records", Options: opts}); err != nil || strings.Join(got, ",") != "b" {
		t.Errorf("pick = %v, %v", got, err)
	}
	if _, err := rt.ChooseMany(app.Choice{Title: "Records", Options: opts}); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("nothing ticked = %v", err)
	}
}

func TestQuietAbort(t *testing.T) {
	var errb bytes.Buffer
	t.Setenv(app.EnvNonInteractive, "")
	rt := app.New(app.Flags{}, strings.NewReader(""), &bytes.Buffer{}, &errb)
	rt.Picker = prompttest.New(t)
	run := app.QuietAbort(rt, func(*cobra.Command, []string) error { return prompt.ErrAborted })
	if err := run(nil, nil); err != nil || errb.String() != "cancelled\n" {
		t.Errorf("interactive abort = %v, stderr %q", err, errb.String())
	}
	rt.Flags.NonInteractive = true
	if err := run(nil, nil); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("non-interactive abort = %v, want the error itself", err)
	}
}

func TestArgsOrInteractive(t *testing.T) {
	rt, _ := interactiveRT(t)
	missing := func(*cobra.Command, []string) error { return app.UsageErrf("<domain> is required") }
	v := app.ArgsOrInteractive(rt, 1, missing)
	cmd := &cobra.Command{Use: "x <domain>"}
	if err := v(cmd, nil); err != nil {
		t.Errorf("interactive without the argument = %v", err)
	}
	if err := v(cmd, []string{"a", "b"}); err == nil {
		t.Error("two arguments accepted")
	}
	rt.Flags.NonInteractive = true
	if err := v(cmd, nil); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "<domain>") {
		t.Errorf("non-interactive without the argument = %v", err)
	}
	r := app.RangeArgsOrInteractive(rt, 2, 3, missing)
	if err := r(cmd, []string{"a", "b", "c"}); err != nil {
		t.Errorf("range = %v", err)
	}
}

func TestProfileForAsksInTheInteractiveFlow(t *testing.T) {
	h := newHarness(t, app.Flags{}, withProj)
	p := prompttest.New(t, "proj")
	h.rt.Picker = p
	got, err := h.rt.ProfileFor(platform.NameCom)
	if err != nil || got != "proj" {
		t.Fatalf("ProfileFor = %q, %v", got, err)
	}
	if a := p.Find("Ambiguous profile for namecom; use which one?"); prompttest.Values(a.Options) != "a b proj" {
		t.Errorf("offered %v", a.Options)
	}
	// The answer holds for the rest of the run: no second question.
	if got, err = h.rt.ProfileFor(platform.NameCom); err != nil || got != "proj" {
		t.Errorf("second ProfileFor = %q, %v", got, err)
	}
	p.Done()

	// A command that must never ask (completion) keeps the error.
	h.rt.NoPrompt = true
	if _, err := h.rt.ProfileFor(platform.GoDaddy); !errors.As(err, new(*app.AmbiguousError)) {
		t.Errorf("NoPrompt ProfileFor = %v, want *AmbiguousError", err)
	}
}

// In the interactive flow an ambiguous owner or resource is a pick, not
// exit code 5.
func TestAmbiguityIsAPickInTheInteractiveFlow(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	p := prompttest.New(t, prompttest.Label("namecom/b"), prompttest.Label("namecom/a"))
	h.rt.Picker = p
	tgt, err := h.rt.ResolveDomain(ctx, "www.shared.com", platform.ResZone)
	if err != nil || tgt.Profile != "b" || tgt.ResourceID != "z-shared-b" {
		t.Fatalf("ResolveDomain = %+v, %v", tgt, err)
	}
	r, err := h.rt.ResolveResource(ctx, platform.NameCom, platform.ResZone, "shared.com")
	if err != nil || r.ID != "z-shared-a" {
		t.Fatalf("ResolveResource = %+v, %v", r, err)
	}
	if a := p.Find(`Ambiguous owner of zone "shared.com"; use which one?`); len(a.Options) != 2 || !strings.Contains(a.Options[0].Label, "namecom/a  zone shared.com  id z-shared-a") {
		t.Errorf("owner options %+v", a.Options)
	}
	p.Done()
	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if _, err := h.rt.ResolveDomain(ctx, "www.shared.com", platform.ResZone); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
}

// PickResource offers the inventory rows of the selected accounts, filtered
// and labelled by the command; an empty selection is nothing to do.
func TestPickResource(t *testing.T) {
	h := newHarness(t, app.Flags{}, nil)
	h.seedStandard()
	p := prompttest.New(t, "z-other")
	h.rt.Picker = p
	got, err := h.rt.PickResource(ctx, app.ResourcePick{Platform: platform.NameCom, Kind: platform.ResZone, Title: "Zone", Arg: "<zone>",
		Filter: func(r inventory.Resource) bool { return r.Name != "shared.com" }})
	if err != nil || got != "z-other" {
		t.Fatalf("pick = %q, %v", got, err)
	}
	if a := p.Find("Zone"); prompttest.Values(a.Options) != "z-example z-other z-sub" || a.Options[1].Label != "other.com  z-other  namecom/b" {
		t.Errorf("options %+v", a.Options)
	}
	p.Done()
	h.rt.Flags.Profile = "a"
	if _, err := h.rt.PickResource(ctx, app.ResourcePick{Platform: platform.NameCom, Kind: platform.ResZone, Arg: "<zone>",
		Filter: func(inventory.Resource) bool { return false }}); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("empty = %v", err)
	}
}

// PickRecordID labels the records and leaves the SOA out.
func TestPickRecordID(t *testing.T) {
	rt, p := interactiveRT(t, "r2")
	on := true
	recs := []platform.Record{{ID: "soa", Name: "example.com", Type: "SOA", Value: "x"},
		{ID: "r1", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 300},
		{ID: "r2", Name: "cdn.example.com", Type: "CNAME", Value: "b.r2.dev", Proxied: &on}}
	got, err := rt.PickRecordID("Delete which record?", recs, func(r platform.Record) string {
		if r.ID == "r2" {
			return "R2 bucket b"
		}
		return ""
	})
	if err != nil || got != "r2" {
		t.Fatalf("pick = %q, %v", got, err)
	}
	if l := prompttest.Labels(p.Find("Delete which record?").Options); l != "www.example.com  A  203.0.113.10  ttl 300  r1\ncdn.example.com  CNAME  b.r2.dev  proxied  [R2 bucket b]  r2" {
		t.Errorf("labels:\n%s", l)
	}
}
