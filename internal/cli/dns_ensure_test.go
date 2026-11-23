package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

func ensureZone(t *testing.T, recs ...platform.Record) (dir, cfgPath string, fc *fakeClient) {
	t.Helper()
	dir, cfgPath = setup(t, true)
	zones := []platform.Zone{{ID: "z1", Name: "example.com"}}
	seed(t, dir, zones, map[string][]platform.Record{"z1": recs})
	fc = client("a")
	fc.zones = zones
	fc.records["z1"] = append([]platform.Record(nil), recs...)
	return dir, cfgPath, fc
}

func TestDNSEnsureCreatesThenIsIdempotent(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 300})
	out, stderr, err := run(t, cfgPath, "dns", "ensure", "example.com", "-r", "www:A:203.0.113.10:300", "--record", "_dmarc:TXT:v=DMARC1; p=none", "-o", "json")
	if err != nil {
		t.Fatalf("ensure: %v (%s)", err, stderr)
	}
	rep := decodeReport(t, out)
	if rep.DryRun || rep.Target.Platform != fakePlatform || rep.Target.Profile != "a" || rep.Target.Domain != "example.com" || len(rep.Changes) != 2 {
		t.Fatalf("report = %+v", rep)
	}
	if c := rep.Changes[0]; c.Resource != "dns-record/www/A" || c.Action != platform.Unchanged || c.ID != "r1" || c.Detail != "203.0.113.10 ttl=300 proxied=false" {
		t.Errorf("change 0 = %+v", c)
	}
	if c := rep.Changes[1]; c.Resource != "dns-record/_dmarc/TXT" || c.Action != platform.Created || c.ID == "" {
		t.Errorf("change 1 = %+v", c)
	}
	if n := writes(fc); n != 1 || fc.count("CreateRecord:_dmarc.example.com:TXT") != 1 {
		t.Errorf("writes = %v", fc.calls)
	}
	// The inventory has the new record without a refresh.
	if out, _, err := run(t, cfgPath, "dns", "list", "example.com", "--offline"); err != nil || !strings.Contains(out, "_dmarc.example.com") {
		t.Errorf("dns list after ensure = %q, %v", out, err)
	}
	// Second run: nothing written; a table report.
	out, _, err = run(t, cfgPath, "dns", "ensure", "example.com", "-r", "www:A:203.0.113.10:300", "-r", "_dmarc:TXT:v=DMARC1; p=none")
	if err != nil || writes(fc) != 1 || !strings.HasPrefix(out, "RESOURCE") || strings.Count(out, "unchanged") != 2 {
		t.Errorf("second run = %q, %v, %v", out, err, fc.calls)
	}
}

func TestDNSEnsureUpdateAndDryRun(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "example.com", Type: "CNAME", Value: "example.org", TTL: 1, Proxied: boolp(true)})
	out, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "-r", "@:CNAME:example.net", "-r", "new:A:203.0.113.20", "--dry-run", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	rep := decodeReport(t, out)
	if !rep.DryRun || len(rep.Changes) != 2 || rep.Changes[0].Action != platform.WouldUpdate || rep.Changes[1].Action != platform.WouldCreate || rep.Changes[1].ID != platform.Pending {
		t.Fatalf("dry run = %+v", rep)
	}
	if a := rep.Changes[0].Attrs; a["changed"] != "value" || a["old_value"] != "example.org" || a["new_value"] != "example.net" {
		t.Errorf("attrs = %v", a)
	}
	if writes(fc) != 0 {
		t.Fatalf("dry run wrote: %v", fc.calls)
	}
	// For real: the update keeps the id and the proxy setting.
	out, _, err = run(t, cfgPath, "dns", "ensure", "example.com", "-r", "@:CNAME:example.net", "-o", "json")
	if err != nil {
		t.Fatal(err)
	}
	if rep := decodeReport(t, out); rep.Changes[0].Action != platform.Updated || rep.Changes[0].ID != "r1" {
		t.Errorf("update = %+v", rep)
	}
	if r := fc.records["z1"][0]; fc.count("UpdateRecord:r1") != 1 || r.Value != "example.net" || r.Proxied == nil || !*r.Proxied {
		t.Errorf("record = %+v, calls %v", r, fc.calls)
	}
}

func boolp(b bool) *bool { return &b }

func TestDNSEnsureFileAndRecords(t *testing.T) {
	_, cfgPath, fc := ensureZone(t)
	file := filepath.Join(t.TempDir(), "records.yaml")
	if err := os.WriteFile(file, []byte("records:\n  - name: \"@\"\n    type: MX\n    value: mail.example.com\n    priority: 10\n  - name: \"@\"\n    type: MX\n    value: 20 mx2.example.com\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, stderr, err := run(t, cfgPath, "dns", "ensure", "example.com", "-f", file, "-r", "www:A:203.0.113.1"); err != nil {
		t.Fatalf("ensure: %v (%s)", err, stderr)
	}
	if n := fc.count("CreateRecord"); n != 3 {
		t.Errorf("creates = %v", fc.calls)
	}
	for _, r := range fc.records["z1"] {
		if r.Type == "MX" && (r.Priority == nil || (r.Value == "mx2.example.com") != (*r.Priority == 20)) {
			t.Errorf("MX record = %+v", r)
		}
	}
	// A missing file is a usage error.
	if _, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "-f", filepath.Join(t.TempDir(), "none.yaml")); ExitCodeFor(err) != ExitUsage {
		t.Errorf("missing file = %v", err)
	}
}

func TestDNSEnsureErrors(t *testing.T) {
	dir, cfgPath, fc := ensureZone(t,
		platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.1"},
		platform.Record{ID: "r2", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.2"},
	)
	for name, c := range map[string]struct {
		args []string
		code int
	}{
		"no records":        {nil, ExitUsage},
		"bad record":        {[]string{"-r", "www:A:nope"}, ExitUsage},
		"proxied TXT":       {[]string{"-r", "@:TXT:hello:300:true"}, ExitUsage},
		"outside zone":      {[]string{"-r", "foo.other-zone.com:A:203.0.113.1"}, ExitUsage},
		"two CNAMEs":        {[]string{"-r", "x:CNAME:a.example.net", "-r", "x:CNAME:b.example.net"}, ExitUsage},
		"MX no priority":    {[]string{"-r", "@:MX:mail.example.com"}, ExitUsage},
		"offline":           {[]string{"-r", "api:A:203.0.113.1", "--offline"}, ExitOffline},
		"duplicates":        {[]string{"-r", "www:A:203.0.113.9"}, ExitAmbiguous},
		"unknown domain":    {[]string{"-r", "api:A:203.0.113.1", "--platform", "cloudflare", "--profile", "a", "nothere.org"}, ExitNotFound},
		"positional twice?": {[]string{"-r", "api:A:203.0.113.1", "extra.example.com"}, ExitUsage},
	} {
		args := append([]string{"dns", "ensure"}, c.args...)
		if name != "unknown domain" {
			args = append([]string{"dns", "ensure", "example.com"}, c.args...)
		}
		_, _, err := run(t, cfgPath, args...)
		if got := ExitCodeFor(err); got != c.code {
			t.Errorf("%s: exit %d (%v), want %d", name, got, err, c.code)
		}
	}
	if n := writes(fc); n != 0 {
		t.Fatalf("errors wrote: %v", fc.calls)
	}
	// A type the platform cannot write: exit 7, nothing read or written.
	fakeRecordTypes = []string{"A", "TXT"}
	before := fc.count("ListRecords")
	if _, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "-r", "@:SPF:v=spf1 -all"); ExitCodeFor(err) != ExitNotSupported || fc.count("ListRecords") != before {
		t.Errorf("SPF = %v, calls %v", err, fc.calls)
	}
	fakeRecordTypes = nil
	// --prune-duplicates: no confirmation needed (non-interactive, no --yes);
	// the oldest is updated, then the other deleted.
	out, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "-r", "www:A:203.0.113.9", "--prune-duplicates", "-o", "json")
	if err != nil {
		t.Fatalf("prune: %v", err)
	}
	if rep := decodeReport(t, out); len(rep.Changes) != 2 || rep.Changes[0].Action != platform.Updated || rep.Changes[0].ID != "r1" || rep.Changes[1].Action != platform.Deleted || rep.Changes[1].ID != "r2" {
		t.Errorf("prune report = %+v", rep)
	}
	if strings.Join(fc.calls[len(fc.calls)-2:], ",") != "UpdateRecord:r1,DeleteRecord:r2" {
		t.Errorf("calls = %v", fc.calls)
	}
	// The deleted record left the inventory.
	if out, _, err := run(t, cfgPath, "dns", "list", "example.com", "--offline"); err != nil || strings.Contains(out, "203.0.113.2") {
		t.Errorf("dns list after prune = %q, %v", out, err)
	}
	_ = dir
}

// A zone held by two accounts is ambiguous (exit 5) until --platform
// picks one; proxied=true on a platform without a proxy is skipped.
func TestDNSEnsureRoutingAndProxiedElsewhere(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	const zoneName = "both.example"
	zones := []platform.Zone{{ID: "z-" + zoneName, Name: zoneName}}
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform}, zoneName)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, zoneName)
	cf, gd := client("a"), clientOn("a", fakePlatform2)
	cf.zones, gd.zones = zones, zones
	_, _, err := run(t, cfgPath, "dns", "ensure", zoneName, "-r", "www:A:203.0.113.1")
	if ExitCodeFor(err) != ExitAmbiguous {
		t.Fatalf("ambiguous = %v", err)
	}
	out, stderr, err := run(t, cfgPath, "dns", "ensure", zoneName, "-r", "www:A:203.0.113.1:300:true", "-r", "api:A:203.0.113.2", "--platform", string(fakePlatform2), "-o", "json")
	if err != nil {
		t.Fatalf("ensure: %v (%s)", err, stderr)
	}
	rep := decodeReport(t, out)
	if len(rep.Changes) != 2 || rep.Changes[0].Action != platform.Skipped || !strings.Contains(rep.Changes[0].Detail, "Cloudflare only") || rep.Changes[1].Action != platform.Created {
		t.Errorf("report = %+v", rep)
	}
	if writes(cf) != 0 || gd.count("CreateRecord") != 1 {
		t.Errorf("writes: cf %v, gd %v", cf.calls, gd.calls)
	}
}

// A failed write stops the plan: the report shows what was done and the
// failed step, and the command fails.
func TestDNSEnsureReportsAFailure(t *testing.T) {
	_, cfgPath, fc := ensureZone(t)
	fc.failCreate = "b.example.com"
	out, _, err := run(t, cfgPath, "dns", "ensure", "example.com", "-r", "a:A:203.0.113.1", "-r", "b:A:203.0.113.2", "-r", "c:A:203.0.113.3", "-o", "json")
	if err == nil || ExitCodeFor(err) != ExitError {
		t.Fatalf("failure = %v", err)
	}
	rep := decodeReport(t, out)
	if len(rep.Changes) != 2 || rep.Changes[0].Action != platform.Created || rep.Changes[1].Action != platform.Failed || !errors.Is(err, errFakeCreate) {
		t.Errorf("report = %+v", rep)
	}
	if fc.count("CreateRecord:c.") != 0 {
		t.Errorf("went on after the failure: %v", fc.calls)
	}
}
