package app_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// writeCmd is a command of the shape `set <zone> <name> <type> <value>...`
// with the flags of the former form.
func writeCmd(many bool) *cobra.Command {
	cmd := &cobra.Command{Use: "set <zone> <name> <type> <value>"}
	app.FormerRecordFlags(cmd, many)
	return cmd
}

func writeRuntime(t *testing.T, p *prompttest.Picker) *app.Runtime {
	t.Helper()
	t.Setenv(app.EnvNonInteractive, "")
	var out, errb strings.Builder
	rt := app.New(app.Flags{}, strings.NewReader(""), &out, &errb)
	if p != nil {
		rt.Picker = p
	} else {
		rt.Flags.NonInteractive = true
	}
	return rt
}

var writeZone = []platform.Record{
	{ID: "1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
	{ID: "2", Name: "example.com", Type: "MX", Value: "mx.example.net"},
	{ID: "3", Name: "www.example.com", Type: "A", Value: "203.0.113.1"},
	{ID: "4", Name: "www.example.com", Type: "A", Value: "203.0.113.2"},
	{ID: "5", Name: "api.example.com", Type: "CNAME", Value: "target.example.net"},
}

// The non-interactive flow never asks: a record without its type or value
// is the usage error of the positional form, a complete one is read from
// the arguments or the former flags, and a name that was not given stays
// empty for the command to apply the default it always had.
func TestRecordInputNonInteractive(t *testing.T) {
	rt := writeRuntime(t, nil)
	form := app.RecordForm{MinValues: 1, MaxValues: 1}
	for _, args := range [][]string{{"example.com"}, {"example.com", "www"}, {"example.com", "www", "A"}} {
		_, err := rt.RecordInput(writeCmd(false), args, form)
		if !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "usage: set <zone> <name> <type> <value>") {
			t.Errorf("%v = %v", args, err)
		}
	}
	in, err := rt.RecordInput(writeCmd(false), []string{"example.com", "www", "a", "203.0.113.9"}, form)
	if err != nil || in.Name != "www" || in.Type != "A" || in.Value() != "203.0.113.9" || in.NameArg != "<name>" {
		t.Fatalf("positional = %+v, %v", in, err)
	}
	cmd := writeCmd(true)
	if err := cmd.ParseFlags([]string{"--type", "txt", "--value", "a", "--value", "b"}); err != nil {
		t.Fatal(err)
	}
	in, err = rt.RecordInput(cmd, []string{"example.com"}, app.RecordForm{MinValues: 1, MaxValues: -1})
	if err != nil || in.Name != "" || in.Type != "TXT" || strings.Join(in.Values, ",") != "a,b" || in.NameArg != "--name" {
		t.Fatalf("former flags = %+v, %v", in, err)
	}
	// CompleteRecord asks nothing and does not read the zone.
	if err := rt.CompleteRecord(in, app.RecordPrompt{Zone: "example.com", Existing: func() ([]platform.Record, error) {
		t.Error("the zone was read")
		return nil, nil
	}}); err != nil || in.Name != "" {
		t.Errorf("complete = %+v, %v", in, err)
	}
	// Optional: no record at all is left to the command, a begun one is
	// refused.
	opt := app.RecordForm{MinValues: 1, MaxValues: -1, Optional: true}
	if in, err := rt.RecordInput(writeCmd(true), []string{"example.com"}, opt); err != nil || in.Given() {
		t.Errorf("optional, nothing given = %+v, %v", in, err)
	}
	cmd = writeCmd(true)
	_ = cmd.ParseFlags([]string{"--type", "A"})
	if _, err := rt.RecordInput(cmd, []string{"example.com"}, opt); !errors.Is(err, app.ErrUsage) {
		t.Errorf("optional, begun = %v", err)
	}
}

// On a terminal the missing parts are asked in the order name, type,
// value; what was given is not asked again, and a complete record reads
// nothing.
func TestCompleteRecordAsksWhatIsMissing(t *testing.T) {
	existing := func() ([]platform.Record, error) { return writeZone, nil }
	for _, c := range []struct {
		name    string
		args    []string
		prompt  app.RecordPrompt
		many    bool
		answers []any
		titles  string
		want    string
		check   func(t *testing.T, p *prompttest.Picker)
	}{
		{name: "zone alone", args: []string{"example.com"}, answers: []any{"www", "A", "203.0.113.9"},
			titles: "select:Record name in example.com,select:Record type,input:Value of the A record", want: "www A 203.0.113.9",
			check: func(t *testing.T, p *prompttest.Picker) {
				if l := prompttest.Labels(p.Asked[0].Options); l != "@ (apex)  NS MX\napi  CNAME\nwww  A\nAnother name..." {
					t.Errorf("names:\n%s", l)
				}
				if p.Asked[1].Default != "A" || p.Asked[2].Default != "" {
					t.Errorf("defaults %q %q", p.Asked[1].Default, p.Asked[2].Default)
				}
			}},
		{name: "name given: its one type preselected", args: []string{"example.com", "api"}, prompt: app.RecordPrompt{Replaces: true},
			answers: []any{"CNAME", prompttest.KeepDefault{}}, titles: "select:Record type,input:Value of the CNAME record", want: "api CNAME target.example.net",
			check: func(t *testing.T, p *prompttest.Picker) {
				if p.Asked[0].Default != "CNAME" {
					t.Errorf("type preselected %q", p.Asked[0].Default)
				}
			}},
		{name: "apex: NS is not what the name has", args: []string{"example.com", "@"}, answers: []any{"MX", "mx2.example.net"},
			titles: "select:Record type,input:Value of the MX record", want: "@ MX mx2.example.net",
			check: func(t *testing.T, p *prompttest.Picker) {
				if p.Asked[0].Default != "MX" {
					t.Errorf("type preselected %q", p.Asked[0].Default)
				}
			}},
		{name: "name and type given: several records propose nothing", args: []string{"example.com", "www", "a"}, prompt: app.RecordPrompt{Replaces: true},
			answers: []any{"203.0.113.9"}, titles: "input:Value of the A record", want: "www A 203.0.113.9",
			check: func(t *testing.T, p *prompttest.Picker) {
				if p.Asked[0].Default != "" {
					t.Errorf("value proposed %q", p.Asked[0].Default)
				}
			}},
		{name: "whole set: first value proposed, more values asked", args: []string{"example.com", "www", "A"}, prompt: app.RecordPrompt{WholeSet: true}, many: true,
			answers: []any{prompttest.KeepDefault{}, "not-an-ip", "203.0.113.9", ""},
			titles:  "input:Value of the A record,input:Another value of the A record (empty to finish),input:Another value of the A record (empty to finish),input:Another value of the A record (empty to finish)",
			want:    "www A 203.0.113.1,203.0.113.9"},
		{name: "a name typed in", args: []string{"example.com"}, answers: []any{prompttest.Label("Another name"), "", "a.b.example.org.", "new.example.com", "TXT", "x"},
			titles: "select:Record name in example.com,input:Record name (relative to example.com, or a full name inside it),input:Record name (relative to example.com, or a full name inside it),input:Record name (relative to example.com, or a full name inside it),select:Record type,input:Value of the TXT record",
			want:   "new.example.com TXT x"},
		{name: "complete", args: []string{"example.com", "www", "A", "203.0.113.9"}, want: "www A 203.0.113.9"},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := prompttest.New(t, c.answers...)
			rt := writeRuntime(t, p)
			form := app.RecordForm{MinValues: 1, MaxValues: 1}
			if c.many {
				form.MaxValues = -1
			}
			in, err := rt.RecordInput(writeCmd(c.many), c.args, form)
			if err != nil {
				t.Fatal(err)
			}
			pr := c.prompt
			pr.Platform, pr.Zone, pr.Existing = "", "example.com", existing
			if len(c.answers) == 0 {
				pr.Existing = func() ([]platform.Record, error) {
					t.Error("the zone was read")
					return nil, nil
				}
			}
			if err := rt.CompleteRecord(in, pr); err != nil {
				t.Fatal(err)
			}
			p.Done()
			if got := strings.Join(p.Titles(), ","); got != c.titles {
				t.Errorf("prompts %s\nwant    %s", got, c.titles)
			}
			if got := in.Name + " " + in.Type + " " + strings.Join(in.Values, ","); got != c.want {
				t.Errorf("record %q, want %q", got, c.want)
			}
			if c.check != nil {
				c.check(t, p)
			}
		})
	}
}

// Leaving a question changes nothing: the error is the abort.
func TestCompleteRecordAbort(t *testing.T) {
	p := prompttest.New(t, prompttest.Abort{})
	rt := writeRuntime(t, p)
	in, err := rt.RecordInput(writeCmd(false), []string{"example.com"}, app.RecordForm{MinValues: 1, MaxValues: 1})
	if err != nil {
		t.Fatal(err)
	}
	if err := rt.CompleteRecord(in, app.RecordPrompt{Zone: "example.com"}); err == nil || in.Given() {
		t.Errorf("abort = %v, %+v", err, in)
	}
}
