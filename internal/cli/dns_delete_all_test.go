package cli

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func fiveRecords() []platform.Record {
	var recs []platform.Record
	for i := 1; i <= 5; i++ {
		recs = append(recs, platform.Record{ID: fmt.Sprintf("r%d", i), ZoneID: "z1", Name: fmt.Sprintf("h%d.example.com", i), Type: "A", Value: fmt.Sprintf("192.0.2.%d", i), TTL: 300})
	}
	return recs
}

func TestDNSDeleteAllDeletesEveryRecord(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, fiveRecords()...)
	out, stderr, err := run(t, cfgPath, "dns", "delete", "example.com", "--all", "--yes", "-o", "json")
	if err != nil {
		t.Fatalf("delete --all: %v (%s)", err, stderr)
	}
	rep := decodeReport(t, out)
	if rep.DryRun || len(rep.Changes) != 5 || rep.Summary == nil || *rep.Summary != (platform.Summary{Deleted: 5}) || rep.Target.Domain != "example.com" {
		t.Fatalf("report = %+v", rep)
	}
	if c := rep.Changes[0]; c.Resource != "dns-record/h1/A" || c.Action != platform.Deleted || c.ID != "r1" || c.Attrs["value"] != "192.0.2.1" {
		t.Errorf("change = %+v", c)
	}
	if fc.count("DeleteRecord") != 5 || len(fc.records["z1"]) != 0 || !strings.Contains(stderr, "deleted 5, kept 0, failed 0") {
		t.Errorf("calls %v, stderr %q", fc.calls, stderr)
	}
	// The inventory forgot them.
	if out, _, err := run(t, cfgPath, "dns", "list", "example.com", "--offline"); err != nil || strings.Contains(out, "h1.example.com") {
		t.Errorf("dns list after delete --all = %q, %v", out, err)
	}
}

func TestDNSDeleteAllNothingToDo(t *testing.T) {
	// An empty zone.
	_, cfgPath, fc := ensureZone(t)
	out, stderr, err := run(t, cfgPath, "dns", "delete", "example.com", "--all", "--yes", "-o", "json")
	if err != nil || !strings.Contains(stderr, "no records to clean up") || writes(fc) != 0 {
		t.Fatalf("empty zone: %v, %q, %v", err, stderr, fc.calls)
	}
	if rep := decodeReport(t, out); rep.Changes == nil || len(rep.Changes) != 0 || !strings.Contains(out, `"changes": []`) {
		t.Errorf("empty report = %q", out)
	}

	// Only system records: all skipped, no question even without --yes on
	// a terminal, nothing written.
	_, cfgPath, fc = ensureZone(t,
		platform.Record{ID: "ns1", ZoneID: "z1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
		platform.Record{ID: "soa", ZoneID: "z1", Name: "example.com", Type: "SOA", Value: "ns1.example.net hostmaster.example.com 1 2 3 4 5"})
	p := &scriptedPicker{T: t}
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "delete", "example.com", "--all")
	if r.err != nil || writes(fc) != 0 || strings.Count(r.stdout, "skipped") != 2 || strings.Contains(r.stderr, "(y/N)") || !strings.Contains(r.stdout, "system record") {
		t.Errorf("system records only: %v, %q, %q, %v", r.err, r.stdout, r.stderr, fc.calls)
	}
}

func TestDNSDeleteAllDryRun(t *testing.T) {
	recs := append(fiveRecords()[:2], platform.Record{ID: "soa", ZoneID: "z1", Name: "example.com", Type: "SOA", Value: "x"})
	for _, extra := range [][]string{nil, {"--yes"}} {
		_, cfgPath, fc := ensureZone(t, recs...)
		args := append([]string{"dns", "delete", "example.com", "--all", "--dry-run", "-o", "json"}, extra...)
		// No terminal and no --yes: a dry run needs no confirmation.
		out, stderr, err := run(t, cfgPath, args...)
		if err != nil || writes(fc) != 0 || strings.Contains(stderr, "(y/N)") {
			t.Fatalf("%v: %v, %q, %v", args, err, stderr, fc.calls)
		}
		rep := decodeReport(t, out)
		if !rep.DryRun || len(rep.Changes) != 3 || rep.Changes[0].Action != platform.WouldDelete || rep.Changes[2].Action != platform.Skipped ||
			*rep.Summary != (platform.Summary{Deleted: 2, Skipped: 1}) {
			t.Errorf("%v: report = %+v", args, rep)
		}
	}
}

func TestDNSDeleteAllInteractive(t *testing.T) {
	recs := append(fiveRecords()[:2],
		platform.Record{ID: "t1", ZoneID: "z1", Name: "example.com", Type: "TXT", Value: "v=spf1 -all"},
		platform.Record{ID: "ns1", ZoneID: "z1", Name: "example.com", Type: "NS", Value: "ns1.example.net"})
	for _, typed := range []string{"n\n", "\n", ""} {
		_, cfgPath, fc := ensureZone(t, recs...)
		p := &scriptedPicker{T: t}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(typed), "dns", "delete", "example.com", "--all")
		if r.code != ExitOK || writes(fc) != 0 || !strings.Contains(fmt.Sprint(r.err), "cancelled") {
			t.Errorf("answer %q: exit %d, %v, stderr %q, calls %v", typed, r.code, r.err, r.stderr, fc.calls)
		}
		for _, want := range []string{"about to delete 3 DNS records of example.com", "cannot be undone", "A 2, TXT 1", "kept (system records): NS 1", "delete 3 records in zone example.com (y/N)"} {
			if !strings.Contains(r.stderr, want) {
				t.Errorf("answer %q: stderr lacks %q: %q", typed, want, r.stderr)
			}
		}
	}
	_, cfgPath, fc := ensureZone(t, recs...)
	r := runFlow(t, context.Background(), cfgPath, &scriptedPicker{T: t}, strings.NewReader("yes\n"), "dns", "delete", "example.com", "--all")
	if r.err != nil || fc.count("DeleteRecord") != 3 || len(fc.records["z1"]) != 1 {
		t.Errorf("confirmed: %v, %v", r.err, fc.calls)
	}
}

func TestDNSDeleteAllTypes(t *testing.T) {
	recs := []platform.Record{
		{ID: "t1", ZoneID: "z1", Name: "example.com", Type: "TXT", Value: "v=spf1 -all"},
		{ID: "a1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"},
		{ID: "t2", ZoneID: "z1", Name: "_acme-challenge.example.com", Type: "TXT", Value: "token"},
		{ID: "m1", ZoneID: "z1", Name: "example.com", Type: "MX", Value: "mail.example.com", Priority: intp(10)},
	}
	_, cfgPath, fc := ensureZone(t, recs...)
	if _, stderr, err := run(t, cfgPath, "dns", "delete", "example.com", "--all", "--type", "txt", "-y"); err != nil || fc.count("DeleteRecord:t") != 2 || writes(fc) != 2 {
		t.Errorf("--type txt: %v, %q, %v", err, stderr, fc.calls)
	}
	// Repeatable and comma-separated.
	_, cfgPath, fc = ensureZone(t, recs...)
	if _, _, err := run(t, cfgPath, "dns", "delete", "example.com", "--all", "--type", "TXT,a", "--type", "MX", "-y"); err != nil || writes(fc) != 4 {
		t.Errorf("--type TXT,a --type MX: %v, %v", err, fc.calls)
	}
}

func TestDNSDeleteAllUsage(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, fiveRecords()...)
	for _, args := range [][]string{
		{"--all", "--name", "www", "-y"},
		{"--all", "--id", "r1", "-y"},
		{"--all", "--value", "1.2.3.4", "-y"},
		{"--all", "--type", "A-B", "-y"},
		{"--all", "--type", "", "-y"},
		{"--keep-bound", "--type", "A", "--name", "h1"},
		{"--type", "A,TXT", "--name", "h1"},
		{"--type", "A", "--type", "TXT", "--name", "h1"},
		{"--all"}, // non-interactive without --yes
		// --id with a filter: the filter would be ignored.
		{"--id", "r1", "--name", "mail", "--type", "MX", "--value", "9.9.9.9", "-y"},
		{"--id", "r1", "--name", "www"},
		{"--id", "r1", "--type", "A"},
		{"--id", "r1", "--value", "1.2.3.4"},
	} {
		code, _, stderr := mainRun(cfgPath, append([]string{"dns", "delete", "example.com"}, args...)...)
		if code != ExitUsage {
			t.Errorf("%v: exit %d (%s)", args, code, stderr)
		}
	}
	if writes(fc) != 0 || fc.count("ListRecords") != 0 {
		t.Errorf("a usage error reached the platform: %v", fc.calls)
	}
	if code, _, _ := mainRun(cfgPath, "dns", "delete", "example.com", "--all", "-y", "--offline"); code != ExitOffline || writes(fc) != 0 {
		t.Errorf("--offline: exit %d", code)
	}
	if code, _, _ := mainRun(cfgPath, "dns", "delete", "nosuch.test", "--all", "-y"); code != ExitNotFound {
		t.Errorf("unknown zone: exit %d", code)
	}
}

func TestDNSDeleteAllFailuresGoOn(t *testing.T) {
	recs := append(fiveRecords()[:3], platform.Record{ZoneID: "z1", Name: "noid.example.com", Type: "A", Value: "192.0.2.9"})
	_, cfgPath, fc := ensureZone(t, recs...)
	fc.failDelete = "r2"
	code, out, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "--all", "-y", "-o", "json")
	if code != ExitError || fc.count("DeleteRecord") != 3 {
		t.Fatalf("exit %d, %q, %v", code, stderr, fc.calls)
	}
	rep := decodeReport(t, out)
	if *rep.Summary != (platform.Summary{Deleted: 2, Failed: 2}) || rep.Changes[1].Action != platform.Failed || !strings.Contains(rep.Changes[1].Detail, "fake delete failure") ||
		rep.Changes[3].Detail != "the record has no id" {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(stderr, "2 of 4 step(s) failed") {
		t.Errorf("stderr = %q", stderr)
	}
	// The failed record stays in the inventory, the deleted ones are gone.
	out, _, _ = run(t, cfgPath, "dns", "list", "example.com", "--offline")
	if !strings.Contains(out, "h2.example.com") || strings.Contains(out, "h1.example.com") || strings.Contains(out, "h3.example.com") {
		t.Errorf("inventory = %q", out)
	}
}

// A zone whose only deletable-looking records have no id is no "nothing
// to do": the records are reported failed and the exit code is 1.
func TestDNSDeleteAllOnlyRecordsWithoutID(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ZoneID: "z1", Name: "noid.example.com", Type: "A", Value: "192.0.2.9"})
	code, _, stderr := mainRun(cfgPath, "dns", "delete", "example.com", "--all", "-y")
	if code != ExitError || writes(fc) != 0 || strings.Contains(stderr, "no records to clean up") || !strings.Contains(stderr, "1 record(s) have no id") {
		t.Errorf("exit %d, %q, %v", code, stderr, fc.calls)
	}
}

// A zone held by two accounts is ambiguous: nothing is deleted anywhere.
func TestDNSDeleteAllAmbiguous(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	const zoneName = "both.example"
	zones := []platform.Zone{{ID: "z-" + zoneName, Name: zoneName}}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, zoneName)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, zoneName)
	cf, gd := client("a"), clientOn("a", fakePlatform2)
	cf.zones, gd.zones = zones, zones
	if code, _, stderr := mainRun(cfgPath, "dns", "delete", zoneName, "--all", "-y"); code != ExitAmbiguous || writes(cf) != 0 || writes(gd) != 0 {
		t.Errorf("exit %d (%s)", code, stderr)
	}
}

// The zone is read in full once, then every record is deleted.
func TestDNSDeleteAllReadsFirst(t *testing.T) {
	var recs []platform.Record
	for i := 0; i < 101; i++ {
		recs = append(recs, platform.Record{ID: fmt.Sprintf("r%d", i), ZoneID: "z1", Name: fmt.Sprintf("h%d.example.com", i), Type: "A", Value: "192.0.2.1"})
	}
	_, cfgPath, fc := ensureZone(t, recs...)
	if _, stderr, err := run(t, cfgPath, "dns", "delete", "example.com", "--all", "-y"); err != nil || fc.count("ListRecords") != 1 || fc.count("DeleteRecord") != 101 {
		t.Errorf("%v, %q: %d lists, %d deletes", err, stderr, fc.count("ListRecords"), fc.count("DeleteRecord"))
	}
}

// A dns list filter that matches nothing prints "records": [] with -o
// json, not null.
func TestDNSListEmptyFilterPrintsEmptyArray(t *testing.T) {
	_, cfgPath, _ := ensureZone(t, fiveRecords()...)
	out, stderr, err := run(t, cfgPath, "dns", "list", "example.com", "--type", "CAA", "-o", "json")
	if err != nil || !strings.Contains(out, `"records": []`) || strings.Contains(out, "null") {
		t.Errorf("dns list = %q, %q, %v", out, stderr, err)
	}
}
