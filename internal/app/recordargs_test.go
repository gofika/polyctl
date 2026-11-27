package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func recordCmd(use string, flags ...string) *cobra.Command {
	root := &cobra.Command{Use: "polyctl"}
	cmd := &cobra.Command{Use: use, Run: func(*cobra.Command, []string) {}}
	for _, f := range flags {
		cmd.Flags().String(f, "", "")
	}
	root.AddCommand(cmd)
	return cmd
}

func parseShape(min, max int, cmd *cobra.Command, args, former []string) (*RecordArgs, error) {
	return recordShape{minValues: min, maxValues: max}.parse(cmd, args, former)
}

func TestRecordShapeParse(t *testing.T) {
	cmd := recordCmd("upsert <zone> <name> <type> <value>...", "name", "type", "value", "content")
	if rec, err := parseShape(1, -1, cmd, nil, nil); rec != nil || err != nil {
		t.Errorf("no arguments = %+v, %v", rec, err)
	}
	rec, err := parseShape(1, -1, cmd, []string{" www ", "cname", "a.example.net", "b.example.net"}, nil)
	if err != nil || rec.Name != "www" || rec.Type != "CNAME" || len(rec.Values) != 2 || rec.Value() != "a.example.net" {
		t.Errorf("record = %+v, %v", rec, err)
	}
	if rec, err := parseShape(0, 1, cmd, []string{"@", "TXT"}, nil); err != nil || rec.Value() != "" {
		t.Errorf("record without a value = %+v, %v", rec, err)
	}
	for name, c := range map[string]struct {
		args     []string
		min, max int
		want     string
	}{
		"name only":       {[]string{"www"}, 1, 1, "usage: polyctl upsert <zone> <name> <type> <value>"},
		"no value":        {[]string{"www", "A"}, 1, -1, "usage: polyctl upsert <zone> <name> <type> <value>..."},
		"too many":        {[]string{"www", "A", "x", "y"}, 0, 1, "usage: polyctl upsert <zone> <name> <type> [<value>]"},
		"value not taken": {[]string{"www", "A", "x"}, 0, 0, "usage: polyctl upsert <zone> <name> <type>"},
		"empty type":      {[]string{"www", " ", "x"}, 1, 1, "<type> must not be empty"},
	} {
		_, err := parseShape(c.min, c.max, cmd, c.args, nil)
		if !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a usage error with %q", name, err, c.want)
		}
	}
	// The flags of the former form: the default ones, or those named.
	_ = cmd.Flags().Set("content", "x")
	if _, err := parseShape(1, 1, cmd, []string{"www", "A", "x"}, nil); err != nil {
		t.Errorf("a flag that is not of the former form: %v", err)
	}
	if _, err := parseShape(1, 1, cmd, []string{"www", "A", "x"}, []string{"name", "type", "content"}); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "with --content; use one form") {
		t.Errorf("named former flag: %v", err)
	}
	_ = cmd.Flags().Set("type", "A")
	if _, err := parseShape(1, 1, cmd, []string{"www", "A", "x"}, nil); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "with --type; use one form") {
		t.Errorf("default former flag: %v", err)
	}
}

// The record of an update or delete command is a selector: only the name
// is required, and the form says what else stands for a record.
func TestRecordTargetFormParse(t *testing.T) {
	const use = "delete <zone> [<name> [<type> [<value>]]]"
	parse := func(f RecordTargetForm, args []string, flags ...string) (*RecordArgs, error) {
		cmd := recordCmd(use, "name", "value", "id")
		cmd.Flags().StringArray("type", nil, "")
		cmd.Flags().Bool("all", false, "")
		for i := 0; i < len(flags); i += 2 {
			if err := cmd.Flags().Set(flags[i], flags[i+1]); err != nil {
				t.Fatal(err)
			}
		}
		return f.Parse(cmd, args)
	}
	all := RecordTargetForm{FormerFlags: []string{"name", "type", "value"}, Instead: []string{"all"}}
	apex := RecordTargetForm{FormerFlags: []string{"name", "type"}, FormerApex: true}
	for _, c := range []struct {
		what  string
		form  RecordTargetForm
		args  []string
		flags []string
		want  string // "name type value typeArg", "" for no record
	}{
		{"the zone alone", all, []string{"z"}, nil, ""},
		{"no argument", all, nil, nil, ""},
		{"--id", all, []string{"z"}, []string{"id", "r1"}, ""},
		{"a name", all, []string{"z", " www "}, nil, "www   <type>"},
		{"a name, a type and a value", all, []string{"z", "www", "a", "x"}, nil, "www A x <type>"},
		{"the former flags", all, []string{"z"}, []string{"name", "www", "type", "txt", "value", "v"}, "www TXT v --type"},
		{"the former --name alone", all, []string{"z"}, []string{"name", "www"}, "www   --type"},
		{"an empty former --name is the apex", all, []string{"z"}, []string{"name", ""}, "@   --type"},
		{"the former --type alone names no record", all, []string{"z"}, []string{"type", "A"}, " A  --type"},
		{"the former --value alone names no record", all, []string{"z"}, []string{"value", "v"}, "  v --type"},
		{"the former --type alone of a form with an apex default", apex, []string{"z"}, []string{"type", "A"}, "@ A  --type"},
		{"an Instead flag beside --type", all, []string{"z"}, []string{"all", "true", "type", "A", "type", "TXT"}, ""},
	} {
		rec, err := parse(c.form, c.args, c.flags...)
		got := ""
		if rec != nil {
			got = rec.Name + " " + rec.Type + " " + rec.Value() + " " + rec.TypeArg
		}
		if err != nil || got != c.want {
			t.Errorf("%s: %q, %v; want %q", c.what, got, err, c.want)
		}
	}
	const usage = "usage: polyctl delete <zone> <name> [<type> [<value>]]"
	for _, c := range []struct {
		what  string
		form  RecordTargetForm
		args  []string
		flags []string
		want  string
	}{
		{"too many values", all, []string{"z", "www", "A", "x", "y"}, nil, usage},
		{"an empty name", all, []string{"z", ""}, nil, usage},
		{"an empty type", all, []string{"z", "www", ""}, nil, usage},
		{"an empty value", all, []string{"z", "www", "A", " "}, nil, usage},
		{"a value where none is taken", RecordTargetForm{NoValue: true}, []string{"z", "www", "A", "x"}, nil, "usage: polyctl delete <zone> <name> [<type>]"},
		{"several types", all, []string{"z", "www", "A,TXT"}, nil, "<type> is one record type: " + usage},
		{"both forms", all, []string{"z", "www"}, []string{"name", "www"}, "with --name; use one form"},
		{"--id beside a record", all, []string{"z", "www"}, []string{"id", "r1"}, "--id selects one record; it cannot be combined with <name> [<type> [<value>]]"},
		{"--id beside a former flag", all, []string{"z"}, []string{"id", "r1", "value", "v"}, "--id selects one record; it cannot be combined with --name, --type or --value"},
		{"an empty --id", all, []string{"z"}, []string{"id", " "}, "--id must not be empty"},
		{"an empty --id beside a record", all, []string{"z", "www"}, []string{"id", ""}, "--id must not be empty"},
		{"an Instead flag beside a record", all, []string{"z", "www"}, []string{"all", "true"}, "--all cannot be combined with a positional record (<name> [<type> [<value>]])"},
		{"several former types", all, []string{"z"}, []string{"type", "A", "type", "TXT"}, "--type takes one record type without --all"},
		{"a list of former types", all, []string{"z"}, []string{"type", "A,TXT"}, "--type takes one record type without --all"},
	} {
		if _, err := parse(c.form, c.args, c.flags...); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a usage error with %q", c.what, err, c.want)
		}
	}
}

// The non-interactive flow needs the zone and a record, --id or a flag that
// stands for a record, before anything is read; a terminal may leave them
// out.
func TestRecordTargetFormArgs(t *testing.T) {
	t.Setenv(EnvNonInteractive, "")
	form := RecordTargetForm{FormerFlags: []string{"name", "type", "value"}, Instead: []string{"all"}}
	check := func(rt *Runtime, f RecordTargetForm, args []string, flags ...string) error {
		cmd := recordCmd("delete <zone> [<name> [<type> [<value>]]]", "name", "type", "value")
		if len(f.FormerFlags) > 0 || len(flags) > 0 {
			cmd.Flags().String("id", "", "")
			cmd.Flags().Bool("all", false, "")
		}
		for i := 0; i < len(flags); i += 2 {
			_ = cmd.Flags().Set(flags[i], flags[i+1])
		}
		return f.ArgsOrInteractive(rt)(cmd, args)
	}
	script := New(Flags{NonInteractive: true}, strings.NewReader(""), new(strings.Builder), new(strings.Builder))
	for _, c := range []struct {
		args  []string
		flags []string
	}{
		{[]string{"z", "www"}, nil},
		{[]string{"z"}, []string{"id", "r1"}},
		{[]string{"z"}, []string{"all", "true"}},
		{[]string{"z"}, []string{"name", "www"}},
	} {
		if err := check(script, form, c.args, c.flags...); err != nil {
			t.Errorf("%v %v: %v", c.args, c.flags, err)
		}
	}
	const need = "a record, --id <record-id> or --all is required: usage: polyctl delete <zone> <name> [<type> [<value>]]"
	for _, c := range []struct {
		args  []string
		flags []string
	}{
		{[]string{"z"}, nil},
		{[]string{"z"}, []string{"value", "v"}},
		{[]string{"z"}, []string{"type", "A"}},
	} {
		if err := check(script, form, c.args, c.flags...); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), need) {
			t.Errorf("%v %v: %v, want %q", c.args, c.flags, err, need)
		}
	}
	// Without the zone, the zone is what is missing.
	const needZone = "<zone> is required: usage: polyctl delete <zone> <name> [<type> [<value>]]"
	for _, flags := range [][]string{nil, {"id", "r1"}, {"all", "true"}} {
		if err := check(script, form, nil, flags...); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), needZone) {
			t.Errorf("no zone %v: %v, want %q", flags, err, needZone)
		}
	}
	// A command without --id or an Instead flag names neither.
	if err := check(script, RecordTargetForm{NoValue: true}, []string{"z"}); err == nil || !strings.Contains(err.Error(), "usage error: a record is required: usage: polyctl delete <zone> <name> [<type>]") {
		t.Errorf("without --id: %v", err)
	}
}
