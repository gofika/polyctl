package godaddy_test

import (
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// A name whose records have one type needs no <type>, in both forms: every
// record of it is deleted, confirmed with the ids and the way to delete one.
func TestDNSDeleteByNameOfOneType(t *testing.T) {
	e := newDeleteEnv(t)
	oneType := func() {
		e.f.Reset()
		e.f.SetRecord("example.com", "A", "www", "203.0.113.1")
		e.f.SetRecord("example.com", "A", "www", "203.0.113.2")
		e.f.SetRecord("example.com", "TXT", "other", "hello")
	}
	for _, form := range [][]string{{"www"}, {"--name", "www"}} {
		oneType()
		// The former form has no --value: the hint names the id only.
		hint := "to delete one of them only, give its <value> after the <type>, or its id with --id <id>"
		if form[0] == "--name" {
			hint = "to delete one of them only, give its id with --id <id>"
		}
		args := append([]string{"godaddy", "dns", "delete", "example.com"}, form...)
		// Non-interactive without --yes: refused, nothing written.
		if code, _, stderr := e.run(nil, "", args...); code != cli.ExitUsage || !strings.Contains(stderr, "pass --yes to proceed (would delete 2 records in zone example.com)") || len(e.f.Writes()) != 0 {
			t.Errorf("%v without --yes: exit %d, %s", form, code, stderr)
		}
		// A dry run reports and asks nothing.
		if code, _, stderr := e.run(nil, "", append(args, "--dry-run")...); code != cli.ExitOK || !strings.Contains(stderr, "dry run: would delete") || len(e.f.Writes()) != 0 {
			t.Errorf("%v --dry-run: exit %d, %s", form, code, stderr)
		}
		// A no deletes nothing and says how to delete one record.
		code, _, stderr := e.run(prompttest.New(t), "n\n", args...)
		if code != cli.ExitOK || len(e.f.Writes()) != 0 || !strings.Contains(stderr, "nothing to do: no record was deleted; "+hint) {
			t.Errorf("%v, no: exit %d, writes %v, %s", form, code, e.f.Writes(), stderr)
		}
		for _, want := range []string{"example.com|A|www|203.0.113.1", "example.com|A|www|203.0.113.2", "2 records match; " + hint, "delete 2 records in zone example.com (y/N)"} {
			if !strings.Contains(stderr, want) {
				t.Errorf("%v: the question lacks %q: %s", form, want, stderr)
			}
		}
		if code, _, stderr := e.run(nil, "", append(args, "--yes")...); code != cli.ExitOK || e.records() != "TXT other hello" {
			t.Errorf("%v --yes: exit %d, records %s, %s", form, code, e.records(), stderr)
		}
	}
	oneType()
	if code, _, stderr := e.run(nil, "", "godaddy", "dns", "delete", "example.com", "nope", "--yes"); code != cli.ExitNotFound || len(e.f.Writes()) != 0 {
		t.Errorf("no record of the name: exit %d, %s", code, stderr)
	}
}

// A name with records of several types is exit code 5 where nothing can be
// asked, with --yes, without it and in a dry run; a terminal lists its
// records to tick, after a line that names the types.
func TestDNSDeleteByNameOfSeveralTypes(t *testing.T) {
	e := newDeleteEnv(t)
	for arg, form := range map[string][]string{"<type>": {"www"}, "--type": {"--name", "www"}} {
		for _, flag := range []string{"--yes", "--dry-run", ""} {
			args := append([]string{"godaddy", "dns", "delete", "example.com"}, form...)
			if flag != "" {
				args = append(args, flag)
			}
			code, _, stderr := e.run(nil, "", args...)
			if code != cli.ExitAmbiguous || e.records() != allRecords || len(e.f.Writes()) != 0 ||
				!strings.Contains(stderr, "www.example.com has records of 2 types in zone example.com (A, TXT); give "+arg) {
				t.Errorf("%v %s: exit %d, %s", form, flag, code, stderr)
			}
		}
	}
	p := prompttest.New(t, []string{"example.com|TXT|www|hello"})
	code, _, stderr := e.run(p, "", "godaddy", "dns", "delete", "example.com", "www")
	if code != cli.ExitOK || e.records() != "A www 203.0.113.1,A www 203.0.113.2" {
		t.Fatalf("picked: exit %d, records %s, %s", code, e.records(), stderr)
	}
	p.Done()
	if !strings.Contains(stderr, "www.example.com has records of 2 types (A, TXT)") {
		t.Errorf("the types are not announced: %s", stderr)
	}
	if a := p.Find("Delete which records of www.example.com?"); len(a.Options) != 3 || !strings.Contains(a.Options[0].Label, "example.com|A|www|203.0.113.1") {
		t.Errorf("options %+v", a.Options)
	}
}
