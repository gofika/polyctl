package cli

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func decodeReport(t *testing.T, out string) platform.Report {
	t.Helper()
	var rep platform.Report
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("decode report %q: %v", out, err)
	}
	return rep
}

func writes(fc *fakeClient) int {
	return fc.count("CreateRecord") + fc.count("UpdateRecord") + fc.count("DeleteRecord") + fc.count("SetNameservers")
}

// --dry-run reports what a write command would change and writes nothing.
func TestDryRunWritesNothing(t *testing.T) {
	dir, cfgPath := setup(t, true)
	recs := []platform.Record{
		{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "1.2.3.4"},
		{ID: "r2", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "5.6.7.8"},
		{ID: "r3", ZoneID: "z1", Name: "api.example.com", Type: "A", Value: "9.9.9.9"},
	}
	seed(t, dir, []platform.Zone{{ID: "z1", Name: "example.com"}}, map[string][]platform.Record{"z1": recs})
	fc := client("a")
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
	fc.records["z1"] = append([]platform.Record(nil), recs...)

	// A new record: would_create, in json.
	out, stderr, err := run(t, cfgPath, "dns", "set", "example.com", "--type", "A", "--name", "new", "--value", "1.1.1.1", "--dry-run", "-o", "json")
	if err != nil {
		t.Fatalf("dns set --dry-run: %v (%s)", err, stderr)
	}
	rep := decodeReport(t, out)
	if !rep.DryRun || len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].Resource != "record/new.example.com/A" ||
		rep.Target.Platform != fakePlatform || rep.Target.Profile != "a" || rep.Target.Domain != "example.com" {
		t.Errorf("report = %+v", rep)
	}
	if !strings.Contains(stderr, "dry run: would create record/new.example.com/A") {
		t.Errorf("stderr = %q", stderr)
	}
	// An existing record: would_update, as a table.
	out, _, err = run(t, cfgPath, "dns", "set", "example.com", "--type", "A", "--name", "api", "--value", "2.2.2.2", "--dry-run")
	if err != nil || !strings.HasPrefix(out, "RESOURCE") || !strings.Contains(out, "would update") || !strings.Contains(out, "9.9.9.9 -> 2.2.2.2") {
		t.Errorf("dns set (update) --dry-run = %q, %v", out, err)
	}
	if _, _, err := run(t, cfgPath, "dns", "add", "example.com", "--type", "A", "--name", "www", "--value", "3.3.3.3", "--dry-run"); err != nil {
		t.Errorf("dns add --dry-run: %v", err)
	}
	// Several records: no question, no --yes needed, in the non-interactive flow.
	out, _, err = run(t, cfgPath, "dns", "delete", "example.com", "--type", "A", "--name", "www", "--dry-run", "-o", "json")
	if err != nil {
		t.Fatalf("dns delete --dry-run: %v", err)
	}
	if rep := decodeReport(t, out); len(rep.Changes) != 2 || rep.Changes[0].Action != platform.WouldDelete || rep.Changes[1].ID != "r2" {
		t.Errorf("delete report = %+v", rep)
	}
	// --dry-run with --yes: still nothing.
	if _, _, err := run(t, cfgPath, "dns", "delete", "example.com", "--type", "A", "--name", "www", "--dry-run", "--yes"); err != nil {
		t.Errorf("dns delete --dry-run --yes: %v", err)
	}
	if n := writes(fc); n != 0 || len(fc.records["z1"]) != 3 {
		t.Errorf("dry runs wrote: %v", fc.calls)
	}
	// Read-only commands ignore the flag.
	if out, _, err := run(t, cfgPath, "dns", "list", "example.com", "--dry-run"); err != nil || !strings.Contains(out, "api.example.com") {
		t.Errorf("dns list --dry-run = %q, %v", out, err)
	}
	// Without --dry-run the same command writes.
	if _, _, err := run(t, cfgPath, "dns", "set", "example.com", "--type", "A", "--name", "new", "--value", "1.1.1.1"); err != nil || fc.count("CreateRecord") != 1 {
		t.Errorf("real write: %v, %v", err, fc.calls)
	}
}

func TestDryRunNameservers(t *testing.T) {
	dir, cfgPath := setup(t, true)
	fc := client("a")
	fc.domains = []platform.Domain{{Name: "example.com", Nameservers: []string{"a.ns"}}}
	_ = dir
	out, _, err := run(t, cfgPath, "domain", "ns", "set", "example.com", "ns1.example.net", "ns2.example.net", "--dry-run", "-o", "json")
	if err != nil {
		t.Fatalf("ns set --dry-run: %v", err)
	}
	rep := decodeReport(t, out)
	if len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[0].Detail != "ns1.example.net,ns2.example.net" {
		t.Errorf("report = %+v", rep)
	}
	if fc.count("SetNameservers") != 0 {
		t.Errorf("dry run set nameservers: %v", fc.calls)
	}
}

// Commands that change local configuration refuse --dry-run rather than
// ignore it.
func TestDryRunRefusedByAuthWrites(t *testing.T) {
	_, cfgPath := setup(t, true)
	for _, args := range [][]string{
		{"auth", "login", string(fakePlatform), "--set", "token=x"},
		{"auth", "use", "a"},
		{"auth", "logout", "--profile", "a"},
		{"auth", "rename", "a", "b"},
	} {
		r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append(args, "--dry-run")...)
		if r.code != ExitUsage || !strings.Contains(r.err.Error(), "does not support --dry-run") {
			t.Errorf("%v --dry-run = %v (exit %d)", args, r.err, r.code)
		}
	}
	if loginCalls() != 0 {
		t.Error("a login ran")
	}
	// auth list and auth status read only: they ignore it.
	if _, _, err := run(t, cfgPath, "auth", "list", "--dry-run"); err != nil {
		t.Errorf("auth list --dry-run: %v", err)
	}
}
