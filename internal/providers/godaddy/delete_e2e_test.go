package godaddy_test

import (
	"bytes"
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
	"github.com/gofika/polyctl/internal/providers/godaddy"
)

type deleteEnv struct {
	t   *testing.T
	dir string
	f   *godaddy.Fake
}

// newDeleteEnv logs a profile in to a fake GoDaddy API that holds two A
// records and one TXT record for www.example.com.
func newDeleteEnv(t *testing.T) *deleteEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv(config.EnvConfigDir, dir)
	t.Setenv("POLYCTL_CREDENTIAL_STORE", "file")
	t.Setenv("POLYCTL_INVENTORY_DB", "")
	t.Setenv("POLYCTL_OUTPUT", "")
	t.Setenv(app.EnvNonInteractive, "")
	e := &deleteEnv{t: t, dir: dir, f: godaddy.NewFake(t, "example.com")}
	if code, _, stderr := e.run(nil, "", "auth", "login", "godaddy", "--profile", "gd", "--set", "token="+godaddy.TestToken, "--set", "env=ote", "--set", "base_url="+e.f.URL); code != cli.ExitOK {
		t.Fatalf("login: exit %d, %s", code, stderr)
	}
	e.reset()
	return e
}

func (e *deleteEnv) reset() {
	e.f.Reset()
	e.f.SetRecord("example.com", "A", "www", "203.0.113.1")
	e.f.SetRecord("example.com", "A", "www", "203.0.113.2")
	e.f.SetRecord("example.com", "TXT", "www", "hello")
}

// run executes the command line. A picker makes the run interactive (as a
// terminal would); the confirmation reads its answer from stdin.
func (e *deleteEnv) run(p *prompttest.Picker, stdin string, args ...string) (int, string, string) {
	e.t.Helper()
	var out, errb bytes.Buffer
	rt := app.New(app.Flags{}, strings.NewReader(stdin), &out, &errb)
	if p != nil {
		rt.Picker = p
	}
	root := cli.NewRoot(rt)
	root.SetArgs(append([]string{"--config-dir", e.dir}, args...))
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

// records lists the records of the fake, sorted.
func (e *deleteEnv) records() string {
	recs := e.f.Records("example.com")
	sort.Strings(recs)
	return strings.Join(recs, ",")
}

const (
	recordID   = "example.com|A|www|203.0.113.1"
	allRecords = "A www 203.0.113.1,A www 203.0.113.2,TXT www hello"
)

// setForms name the two A records of www; idForms name one of them.
var (
	setForms = [][]string{
		{"godaddy", "dns", "delete", "example.com", "www", "A"},
		// The former form.
		{"godaddy", "dns", "delete", "example.com", "--type", "A", "--name", "www"},
	}
	idForms = [][]string{
		{"godaddy", "dns", "delete", "example.com", "--id", recordID},
		// The id older versions printed, without the zone, still works.
		{"godaddy", "dns", "delete", "example.com", "--id", "A|www|203.0.113.1"},
		{"godaddy", "dns", "delete", "example.com", "www", "A", "203.0.113.1"},
	}
)

const (
	question = "delete 2 records in zone example.com (y/N)"
	oneLeft  = "A www 203.0.113.2,TXT www hello"
)

// godaddy dns delete lists several records and asks one question (default
// no); a yes deletes, a no or leaving the question (Ctrl-D) deletes nothing.
func TestDNSDeleteConfirms(t *testing.T) {
	e := newDeleteEnv(t)
	for _, form := range setForms {
		code, _, stderr := e.run(prompttest.New(t), "y\n", form...)
		if code != cli.ExitOK || e.records() != "TXT www hello" {
			t.Errorf("%v, yes: exit %d, records %s, %s", form, code, e.records(), stderr)
		}
		list := strings.Index(stderr, "203.0.113.1")
		if q := strings.Index(stderr, question); q < 0 || list < 0 || list > q {
			t.Errorf("%v: the records are not listed before the question: %s", form, stderr)
		}
		for _, answer := range []string{"\n", "n\n", ""} {
			e.reset()
			code, _, stderr := e.run(prompttest.New(t), answer, form...)
			if code != cli.ExitOK || e.records() != allRecords || len(e.f.Writes()) != 0 || !strings.Contains(stderr, "no record was deleted") {
				t.Errorf("%v, answer %q: exit %d, records %s, writes %v, %s", form, answer, code, e.records(), e.f.Writes(), stderr)
			}
		}
		e.reset()
	}
}

// One record (--id, or a name, type and value that match one) is deleted
// at once in both flows, as by every record delete command.
func TestDNSDeleteOneRecord(t *testing.T) {
	e := newDeleteEnv(t)
	for _, form := range idForms {
		for _, p := range []*prompttest.Picker{nil, prompttest.New(t)} {
			code, stdout, stderr := e.run(p, "", append(form, "-o", "json")...)
			if code != cli.ExitOK || e.records() != oneLeft || strings.Contains(stderr, "(y/N)") || !strings.Contains(stdout, `"deleted": [`) || !strings.Contains(stdout, recordID) {
				t.Errorf("%v: exit %d, records %s, %s%s", form, code, e.records(), stdout, stderr)
			}
			e.reset()
		}
	}
}

// A set or a record that does not exist is not found, and nothing is asked.
func TestDNSDeleteMissing(t *testing.T) {
	e := newDeleteEnv(t)
	for _, args := range [][]string{
		{"godaddy", "dns", "delete", "example.com", "--type", "MX", "--name", "www"},
		{"godaddy", "dns", "delete", "example.com", "www", "A", "198.51.100.9"},
		{"godaddy", "dns", "delete", "example.com", "--id", "example.com|A|www|198.51.100.9"},
		// An id of another domain names no record of this one.
		{"godaddy", "dns", "delete", "example.com", "--id", "other.com|A|www|203.0.113.1"},
	} {
		code, _, stderr := e.run(prompttest.New(t), "y\n", args...)
		if code != cli.ExitNotFound || strings.Contains(stderr, "(y/N)") || len(e.f.Writes()) != 0 {
			t.Errorf("%v: exit %d, writes %v, %s", args, code, e.f.Writes(), stderr)
		}
	}
	// So does the neutral dns delete.
	code, _, stderr := e.run(nil, "", "dns", "delete", "example.com", "--id", "other.com|A|www|203.0.113.1", "--yes")
	if code != cli.ExitNotFound || len(e.f.Writes()) != 0 {
		t.Errorf("neutral: exit %d, writes %v, %s", code, e.f.Writes(), stderr)
	}
}

// With only the domain a terminal lists the records to tick; several are
// confirmed, one is deleted at once.
func TestDNSDeleteLists(t *testing.T) {
	e := newDeleteEnv(t)
	both := []string{recordID, "example.com|A|www|203.0.113.2"}
	p := prompttest.New(t, both)
	if code, _, stderr := e.run(p, "n\n", "godaddy", "dns", "delete", "example.com"); code != cli.ExitOK || e.records() != allRecords || !strings.Contains(stderr, question) {
		t.Errorf("no: exit %d, records %s, %s", code, e.records(), stderr)
	}
	p.Done()
	if a := p.Find("Delete which records of example.com?"); a == nil || len(a.Options) != 3 {
		t.Errorf("options %+v", a)
	}
	p = prompttest.New(t, both)
	if code, _, stderr := e.run(p, "y\n", "godaddy", "dns", "delete", "example.com"); code != cli.ExitOK || e.records() != "TXT www hello" {
		t.Errorf("yes: exit %d, records %s, %s", code, e.records(), stderr)
	}
	p.Done()
	e.reset()
	p = prompttest.New(t, []string{recordID})
	if code, _, stderr := e.run(p, "", "godaddy", "dns", "delete", "example.com"); code != cli.ExitOK || e.records() != oneLeft || strings.Contains(stderr, "(y/N)") {
		t.Errorf("one ticked: exit %d, records %s, %s", code, e.records(), stderr)
	}
	p.Done()
	// Where nothing can be asked the domain alone is a usage error before
	// anything is read.
	e.reset()
	if code, _, stderr := e.run(nil, "", "godaddy", "dns", "delete", "example.com"); code != cli.ExitUsage || !strings.Contains(stderr, "a record or --id <record-id> is required: usage: polyctl godaddy dns delete <domain> <name> [<type> [<value>]]") {
		t.Errorf("only the domain: exit %d, %s", code, stderr)
	}
}

// --yes deletes several records without a question in both flows; the
// non-interactive flow without it is a usage error naming --yes.
func TestDNSDeleteYes(t *testing.T) {
	e := newDeleteEnv(t)
	for _, form := range setForms {
		code, _, stderr := e.run(nil, "y\n", form...)
		if code != cli.ExitUsage || !strings.Contains(stderr, "pass --yes to proceed (would delete 2 records in zone example.com)") || e.records() != allRecords || len(e.f.Writes()) != 0 {
			t.Errorf("%v, non-interactive without --yes: exit %d, records %s, %s", form, code, e.records(), stderr)
		}
		if code, _, stderr := e.run(nil, "", append(form, "--yes")...); code != cli.ExitOK || e.records() != "TXT www hello" {
			t.Errorf("%v, non-interactive --yes: exit %d, records %s, %s", form, code, e.records(), stderr)
		}
		e.reset()
		if code, _, stderr := e.run(prompttest.New(t), "", append(form, "--yes")...); code != cli.ExitOK || e.records() != "TXT www hello" || strings.Contains(stderr, "(y/N)") {
			t.Errorf("%v, interactive --yes: exit %d, records %s, %s", form, code, e.records(), stderr)
		}
		e.reset()
	}
}

// A dry run asks nothing and needs no --yes, in both flows.
func TestDNSDeleteDryRun(t *testing.T) {
	e := newDeleteEnv(t)
	for _, form := range append(append([][]string{}, setForms...), idForms...) {
		code, stdout, stderr := e.run(nil, "", append(form, "--dry-run")...)
		if code != cli.ExitOK || !strings.Contains(stdout, "would delete") || len(e.f.Writes()) != 0 {
			t.Errorf("%v, non-interactive dry run: exit %d, %q, writes %v, %s", form, code, stdout, e.f.Writes(), stderr)
		}
		code, _, stderr = e.run(prompttest.New(t), "", append(form, "--dry-run")...)
		if code != cli.ExitOK || strings.Contains(stderr, "(y/N)") || len(e.f.Writes()) != 0 {
			t.Errorf("%v, interactive dry run: exit %d, writes %v, %s", form, code, e.f.Writes(), stderr)
		}
	}
}

// upsert replaces a record set without a question.
func TestDNSUpsertAsksNothing(t *testing.T) {
	e := newDeleteEnv(t)
	code, _, stderr := e.run(prompttest.New(t), "", "godaddy", "dns", "upsert", "example.com", "--type", "A", "--name", "www", "--value", "198.51.100.7")
	if code != cli.ExitOK || strings.Contains(stderr, "(y/N)") || e.records() != "A www 198.51.100.7,TXT www hello" {
		t.Errorf("upsert: exit %d, records %s, %s", code, e.records(), stderr)
	}
}

// The neutral dns delete takes the id older versions printed, without the
// zone, as long as it names one record.
func TestNeutralDNSDeleteOldID(t *testing.T) {
	e := newDeleteEnv(t)
	code, _, stderr := e.run(nil, "", "dns", "delete", "example.com", "--id", "A|www|203.0.113.1", "--yes")
	if code != cli.ExitOK || e.records() != "A www 203.0.113.2,TXT www hello" {
		t.Fatalf("exit %d, records %s, %s", code, e.records(), stderr)
	}

	// An older SRV id names both records that differ only in protocol.
	e.f.Reset()
	e.f.SetSRV("example.com", "_sip", "_tcp", "sip.example.com", 5060)
	e.f.SetSRV("example.com", "_sip", "_udp", "sip.example.com", 5060)
	code, _, stderr = e.run(nil, "", "dns", "delete", "example.com", "--id", "SRV|@|sip.example.com", "--yes", "--refresh")
	if code != cli.ExitAmbiguous || len(e.f.Writes()) != 0 || !strings.Contains(stderr, "example.com|SRV|@|sip.example.com|_sip|_udp|5060|0|0") {
		t.Fatalf("ambiguous old id: exit %d, writes %v, %s", code, e.f.Writes(), stderr)
	}
	code, _, stderr = e.run(nil, "", "dns", "delete", "example.com", "--id", "example.com|SRV|@|sip.example.com|_sip|_udp|5060|0|0", "--yes")
	if code != cli.ExitOK || len(e.f.Records("example.com")) != 1 || !strings.Contains(e.f.Records("example.com")[0], "SRV @ sip.example.com") {
		t.Fatalf("current id: exit %d, records %v, %s", code, e.f.Records("example.com"), stderr)
	}
}

// --id selects one record: --type or --name beside it would be ignored, so
// the combination is a usage error and nothing is asked or deleted.
func TestDNSDeleteIDWithFilters(t *testing.T) {
	e := newDeleteEnv(t)
	for _, extra := range [][]string{
		{"--type", "TXT", "--name", "www"},
		{"--type", "TXT"},
		{"--name", "mail"},
		{"www"},
		{"--id", ""},
	} {
		args := append([]string{"godaddy", "dns", "delete", "example.com", "--id", recordID, "--yes"}, extra...)
		if code, _, stderr := e.run(nil, "", args...); code != cli.ExitUsage || !strings.Contains(stderr, "--id") || e.records() != allRecords {
			t.Errorf("%v: exit %d, records %s, %s", extra, code, e.records(), stderr)
		}
	}
}
