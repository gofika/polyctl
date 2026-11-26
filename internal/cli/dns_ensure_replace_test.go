package cli

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// The records of the zone the tests of what dns ensure changes start from.
var (
	wwwA   = platform.Record{ID: "a1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.1", TTL: 300}
	wwwTXT = platform.Record{ID: "t1", ZoneID: "z1", Name: "www.example.com", Type: "TXT", Value: "hello", TTL: 300}
	wwwMX  = platform.Record{ID: "m1", ZoneID: "z1", Name: "www.example.com", Type: "MX", Value: "mail.example.com", Priority: intp(10), TTL: 300}
	apexNS = []platform.Record{
		{ID: "soa", ZoneID: "z1", Name: "example.com", Type: "SOA", Value: "ns1.example.net. admin.example.com. 1 7200 3600 86400 300"},
		{ID: "ns1", ZoneID: "z1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
	}
)

// ensureCalls are the calls of fc after the zone was read: its writes.
func ensureCalls(fc *fakeClient) string {
	var w []string
	for _, c := range fc.calls {
		if strings.HasPrefix(c, "CreateRecord") || strings.HasPrefix(c, "UpdateRecord") || strings.HasPrefix(c, "DeleteRecord") {
			w = append(w, c)
		}
	}
	return strings.Join(w, ",")
}

// a and c: one record of another type is replaced: the record is deleted,
// then the desired one created, after a confirmation on a terminal and with
// --yes in a script.
func TestDNSEnsureReplacesTheOneRecordOfAName(t *testing.T) {
	args := []string{"dns", "ensure", "example.com", "www", "CNAME", "target.example.net"}

	// The non-interactive flow without --yes: exit 2, nothing written.
	_, cfgPath, fc := ensureZone(t, wwwA)
	r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader("y\n"), args...)
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "confirmation required: pass --yes to proceed (would replace the A record of www.example.com with the CNAME record in zone example.com)") || writes(fc) != 0 {
		t.Fatalf("without --yes: exit %d, %v, calls %v", r.code, r.err, fc.calls)
	}

	// --dry-run: both steps reported, nothing asked or written, no --yes.
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append(args, "--dry-run", "-o", "json")...)
	if r.err != nil || writes(fc) != 0 {
		t.Fatalf("dry run: %v, calls %v", r.err, fc.calls)
	}
	if rep := decodeReport(t, r.stdout); dnsReportActions(rep) != "dns-record/www/A=would_delete dns-record/www/CNAME=would_create" || rep.Changes[0].ID != "a1" {
		t.Errorf("dry run report = %+v", rep)
	}
	p := &scriptedPicker{T: t}
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), append(args, "--dry-run")...)
	if r.err != nil || len(p.Asked) != 0 || strings.Contains(r.stderr, "(y/N)") || writes(fc) != 0 {
		t.Errorf("dry run on a terminal: %v, prompts %v, stderr %q", r.err, p.Titles(), r.stderr)
	}

	// On a terminal: the record that goes is shown, and a no (the default)
	// writes nothing and is exit code 0.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t}, strings.NewReader("\n"), args...)
	if r.code != ExitOK || !errors.Is(r.err, errNothingToDo) || !strings.Contains(r.err.Error(), "nothing was written") || writes(fc) != 0 {
		t.Fatalf("declined: exit %d, %v, calls %v", r.code, r.err, fc.calls)
	}
	for _, want := range []string{"www.example.com: its record of another type is deleted, then the CNAME record written", "203.0.113.1", "a1",
		"replace the A record of www.example.com with the CNAME record in zone example.com (y/N)"} {
		if !strings.Contains(r.stderr, want) {
			t.Errorf("confirmation lacks %q:\n%s", want, r.stderr)
		}
	}

	// A yes: the delete comes before the create, and the inventory follows.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t}, strings.NewReader("y\n"), args...)
	if r.err != nil || ensureCalls(fc) != "DeleteRecord:a1,CreateRecord:www.example.com:CNAME" {
		t.Fatalf("confirmed: %v, calls %v", r.err, fc.calls)
	}
	out, _, err := run(t, cfgPath, "dns", "list", "example.com", "--offline")
	if err != nil || !strings.Contains(out, "target.example.net") || strings.Contains(out, "203.0.113.1") {
		t.Errorf("inventory after the replace = %q, %v", out, err)
	}

	// --yes in a script; -o json reports the deleted record in full.
	_, cfgPath, fc = ensureZone(t, wwwA)
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append(args, "--yes", "-o", "json")...)
	if r.err != nil || ensureCalls(fc) != "DeleteRecord:a1,CreateRecord:www.example.com:CNAME" {
		t.Fatalf("--yes: %v, calls %v", r.err, fc.calls)
	}
	rep := decodeReport(t, r.stdout)
	if dnsReportActions(rep) != "dns-record/www/A=deleted dns-record/www/CNAME=created" {
		t.Fatalf("report = %+v", rep)
	}
	if c := rep.Changes[0]; c.ID != "a1" || c.Attrs["value"] != "203.0.113.1" || c.Attrs["ttl"] != "300" || c.Attrs["replaced_by"] != "CNAME" || !strings.Contains(c.Detail, "replaced by the CNAME record") {
		t.Errorf("deleted change = %+v", c)
	}
	if c := rep.Changes[1]; c.ID == "" || c.ID == "a1" {
		t.Errorf("created change = %+v", c)
	}
}

func dnsReportActions(rep platform.Report) string {
	var s []string
	for _, c := range rep.Changes {
		s = append(s, c.Resource+"="+string(c.Action))
	}
	return strings.Join(s, " ")
}

// a, b and d: the zone's own records at the apex never count, and records
// of other types beside a record of the type are left alone; nothing is
// asked and no --yes is needed.
func TestDNSEnsureLeavesOtherTypesBesideTheTarget(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, append(append([]platform.Record(nil), apexNS...), wwwA, wwwTXT)...)
	out, stderr, err := run(t, cfgPath, "dns", "ensure", "example.com", "-r", "@:A:203.0.113.9", "-r", "www:A:203.0.113.2", "-o", "json")
	if err != nil {
		t.Fatalf("ensure: %v (%s)", err, stderr)
	}
	if rep := decodeReport(t, out); dnsReportActions(rep) != "dns-record/@/A=created dns-record/www/A=updated" {
		t.Errorf("report = %+v", rep)
	}
	if ensureCalls(fc) != "CreateRecord:example.com:A,UpdateRecord:a1" {
		t.Errorf("calls = %v", fc.calls)
	}
	for _, id := range []string{"soa", "ns1", "t1"} {
		if !hasRecord(fc, id) {
			t.Errorf("record %s is gone: %+v", id, fc.records["z1"])
		}
	}
}

func hasRecord(fc *fakeClient, id string) bool {
	for _, r := range fc.records["z1"] {
		if r.ID == id {
			return true
		}
	}
	return false
}

// e: several records of other types are never deleted by a script (exit
// code 5, --yes or not); a terminal chooses to replace them, keep them or
// cancel.
func TestDNSEnsureSeveralRecordsOfOtherTypes(t *testing.T) {
	args := []string{"dns", "ensure", "example.com", "www", "A", "203.0.113.8"}
	_, cfgPath, fc := ensureZone(t, wwwTXT, wwwMX)
	for _, extra := range [][]string{nil, {"--yes"}, {"--dry-run"}} {
		r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader("y\n"), append(append([]string{}, args...), extra...)...)
		if r.code != ExitAmbiguous || writes(fc) != 0 {
			t.Fatalf("%v: exit %d, %v, calls %v", extra, r.code, r.err, fc.calls)
		}
		for _, want := range []string{"www.example.com holds 2 records of other types", `TXT "hello" ttl=300`, "MX 10 mail.example.com ttl=300", "`polyctl dns add`", "`polyctl dns delete`", "nothing was written"} {
			if !strings.Contains(r.err.Error(), want) {
				t.Errorf("%v: error %q lacks %q", extra, r.err, want)
			}
		}
	}

	const title = "What should dns ensure do with the records of www.example.com?"
	// Cancel: nothing written, exit code 0.
	p := &scriptedPicker{T: t, Answers: []any{cancelRun}}
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), args...)
	if r.code != ExitOK || writes(fc) != 0 || !strings.Contains(r.stderr, "www.example.com holds 2 records of other types than A") || !strings.Contains(r.stderr, "mail.example.com") {
		t.Fatalf("cancel: exit %d, %v, stderr %q, calls %v", r.code, r.err, r.stderr, fc.calls)
	}
	if a := p.Find(title); a.Kind != "select" || a.Default != cancelRun || len(a.Options) != 3 || a.Options[1].Value != keepThem {
		t.Errorf("choice = %+v", a)
	}
	// Replace, then a no: nothing written.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t, Answers: []any{replaceThem}}, strings.NewReader("n\n"), args...)
	if r.code != ExitOK || writes(fc) != 0 || !strings.Contains(r.stderr, "replace the 2 records of www.example.com with the A record in zone example.com (y/N)") {
		t.Fatalf("replace declined: exit %d, %v, stderr %q", r.code, r.err, r.stderr)
	}
	// Keep: the record is added beside them, as dns add does.
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t, Answers: []any{keepThem}}, strings.NewReader(""), args...)
	if r.err != nil || ensureCalls(fc) != "CreateRecord:www.example.com:A" || strings.Contains(r.stderr, "(y/N)") {
		t.Fatalf("keep: %v, calls %v", r.err, fc.calls)
	}
	// Replace and a yes: both deleted first.
	_, cfgPath, fc = ensureZone(t, wwwTXT, wwwMX)
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t, Answers: []any{replaceThem}}, strings.NewReader("y\n"), args...)
	if r.err != nil || ensureCalls(fc) != "DeleteRecord:t1,DeleteRecord:m1,CreateRecord:www.example.com:A" {
		t.Fatalf("replace: %v, calls %v", r.err, fc.calls)
	}
	// A dry run asks the choice, not the confirmation.
	_, cfgPath, fc = ensureZone(t, wwwTXT, wwwMX)
	r = runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t, Answers: []any{replaceThem}}, strings.NewReader(""), append(args, "--dry-run", "-o", "json")...)
	if rep := decodeReport(t, r.stdout); r.err != nil || writes(fc) != 0 || dnsReportActions(rep) != "dns-record/www/TXT=would_delete dns-record/www/MX=would_delete dns-record/www/A=would_create" {
		t.Errorf("dry run: %v, %+v, calls %v", r.err, rep, fc.calls)
	}

	// Types that cannot share the name: keeping them is not offered.
	_, cfgPath, fc = ensureZone(t, wwwA, platform.Record{ID: "q1", ZoneID: "z1", Name: "www.example.com", Type: "AAAA", Value: "2001:db8::1"})
	p = &scriptedPicker{T: t, Answers: []any{cancelRun}}
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "www", "CNAME", "target.example.net")
	if r.code != ExitOK || writes(fc) != 0 {
		t.Fatalf("conflict cancel: exit %d, %v", r.code, r.err)
	}
	if a := p.Find(title); len(a.Options) != 2 || a.Options[0].Value != replaceThem || a.Options[1].Value != cancelRun {
		t.Errorf("conflict choice = %+v", a)
	}
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "ensure", "example.com", "www", "CNAME", "target.example.net", "--yes")
	if r.code != ExitAmbiguous || !strings.Contains(r.err.Error(), "cannot stay beside them") || writes(fc) != 0 {
		t.Errorf("conflict script: exit %d, %v", r.code, r.err)
	}
}

// f and g: several records of the type are duplicates as before, and a set
// of one name and type replaces the one record of another type.
func TestDNSEnsureSetReplacesARecordOfAnotherType(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, wwwTXT)
	_, stderr, err := run(t, cfgPath, "dns", "ensure", "example.com", "www", "MX", "10 mx1.example.com", "20 mx2.example.com", "--yes")
	if err != nil || ensureCalls(fc) != "DeleteRecord:t1,CreateRecord:www.example.com:MX,CreateRecord:www.example.com:MX" {
		t.Fatalf("set: %v (%s), calls %v", err, stderr, fc.calls)
	}
	// Duplicates of the type, the other types beside them left alone.
	_, cfgPath, fc = ensureZone(t, wwwTXT, wwwA, platform.Record{ID: "a2", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.2"})
	if _, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "www", "A", "203.0.113.9"); ExitCodeFor(err) != ExitAmbiguous || !strings.Contains(err.Error(), "--prune-duplicates") || writes(fc) != 0 {
		t.Errorf("duplicates = %v, calls %v", err, fc.calls)
	}
	if _, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "www", "A", "203.0.113.2"); err != nil || writes(fc) != 0 {
		t.Errorf("duplicate as desired = %v, calls %v", err, fc.calls)
	}
}

// h: every name of a run is decided before the first write.
func TestDNSEnsureDecidesEveryNameBeforeWriting(t *testing.T) {
	file := filepath.Join(t.TempDir(), "records.yaml")
	if err := os.WriteFile(file, []byte("records:\n  - name: api\n    type: A\n    value: 203.0.113.1\n  - name: www\n    type: A\n    value: 203.0.113.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, cfgPath, fc := ensureZone(t, wwwTXT, wwwMX)
	for _, extra := range [][]string{nil, {"--yes"}} {
		r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append([]string{"dns", "ensure", "example.com", "-f", file}, extra...)...)
		if r.code != ExitAmbiguous || writes(fc) != 0 {
			t.Errorf("%v: exit %d, %v, calls %v", extra, r.code, r.err, fc.calls)
		}
	}
	_, cfgPath, fc = ensureZone(t, wwwTXT)
	r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "ensure", "example.com", "-f", file)
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "pass --yes") || writes(fc) != 0 {
		t.Errorf("needs --yes: exit %d, %v, calls %v", r.code, r.err, fc.calls)
	}
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "ensure", "example.com", "-f", file, "--yes")
	if r.err != nil || ensureCalls(fc) != "CreateRecord:api.example.com:A,DeleteRecord:t1,CreateRecord:www.example.com:A" {
		t.Errorf("with --yes: %v, calls %v", r.err, fc.calls)
	}
}

// A create that fails after the record it replaces was deleted says so and
// prints the command that restores the record: exit code 1.
func TestDNSEnsureFailedCreateAfterReplace(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, wwwA)
	fc.failCreate = "www.example.com"
	r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "ensure", "example.com", "www", "TXT", "hello world", "--yes", "-o", "json")
	if r.code != ExitError || ensureCalls(fc) != "DeleteRecord:a1,CreateRecord:www.example.com:TXT" {
		t.Fatalf("failure: exit %d, %v, calls %v", r.code, r.err, fc.calls)
	}
	for _, want := range []string{"the record it replaces was deleted before and is gone", "www.example.com A 203.0.113.1 ttl=300",
		"restore it with: polyctl dns add example.com www A 203.0.113.1 --ttl 300 --platform cloudflare --profile a"} {
		if !strings.Contains(r.err.Error(), want) {
			t.Errorf("error %q lacks %q", r.err, want)
		}
	}
	if rep := decodeReport(t, r.stdout); dnsReportActions(rep) != "dns-record/www/A=deleted dns-record/www/TXT=failed" {
		t.Errorf("report = %+v", rep)
	}
	// The command it prints restores the record.
	fc.failCreate = ""
	if _, stderr, err := run(t, cfgPath, "dns", "add", "example.com", "www", "A", "203.0.113.1", "--ttl", "300", "--platform", "cloudflare", "--profile", "a"); err != nil {
		t.Fatalf("restore: %v (%s)", err, stderr)
	}
	if rs := fc.records["z1"]; len(rs) != 1 || rs[0].Value != "203.0.113.1" || rs[0].TTL != 300 {
		t.Errorf("restored = %+v", rs)
	}
}
