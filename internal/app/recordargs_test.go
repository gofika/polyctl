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

func TestParseRecordArgs(t *testing.T) {
	cmd := recordCmd("upsert <zone> <name> <type> <value>...", "name", "type", "value", "content")
	if rec, err := ParseRecordArgs(cmd, nil, 1, -1); rec != nil || err != nil {
		t.Errorf("no arguments = %+v, %v", rec, err)
	}
	rec, err := ParseRecordArgs(cmd, []string{" www ", "cname", "a.example.net", "b.example.net"}, 1, -1)
	if err != nil || rec.Name != "www" || rec.Type != "CNAME" || len(rec.Values) != 2 || rec.Value() != "a.example.net" {
		t.Errorf("record = %+v, %v", rec, err)
	}
	if rec, err := ParseRecordArgs(cmd, []string{"@", "TXT"}, 0, 1); err != nil || rec.Value() != "" {
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
		_, err := ParseRecordArgs(cmd, c.args, c.min, c.max)
		if !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s: %v, want a usage error with %q", name, err, c.want)
		}
	}
	// The flags of the former form: the default ones, or those named.
	_ = cmd.Flags().Set("content", "x")
	if _, err := ParseRecordArgs(cmd, []string{"www", "A", "x"}, 1, 1); err != nil {
		t.Errorf("a flag that is not of the former form: %v", err)
	}
	if _, err := ParseRecordArgs(cmd, []string{"www", "A", "x"}, 1, 1, "name", "type", "content"); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "with --content; use one form") {
		t.Errorf("named former flag: %v", err)
	}
	_ = cmd.Flags().Set("type", "A")
	if _, err := ParseRecordArgs(cmd, []string{"www", "A", "x"}, 1, 1); !errors.Is(err, ErrUsage) || !strings.Contains(err.Error(), "with --type; use one form") {
		t.Errorf("default former flag: %v", err)
	}
}
