package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// dns list without <domain>: the indexed zones are offered; the
// non-interactive flow keeps the usage error.
func TestDNSListPicksTheZone(t *testing.T) {
	_, cfgPath, _ := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 300})
	p := prompttest.New(t, "example.com")
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "list", "--offline")
	if r.err != nil || !strings.Contains(r.stdout, "www.example.com") {
		t.Fatalf("pick: %v, %q, %q", r.err, r.stdout, r.stderr)
	}
	if a := p.Find("Zone"); prompttest.Values(a.Options) != "example.com" || !strings.Contains(a.Options[0].Label, "zone cloudflare/a") {
		t.Errorf("zone options %+v", a.Options)
	}
	p.Done()

	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t, prompttest.Abort{}), strings.NewReader(""), "dns", "list", "--offline")
	if r.code != ExitOK || r.stderr != "cancelled\n" {
		t.Errorf("abort: exit %d, %v, %q", r.code, r.err, r.stderr)
	}
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "list", "--offline")
	if r.code != ExitUsage || !strings.Contains(r.stderr+r.err.Error(), "accepts 1 arg(s), received 0") {
		t.Errorf("non-interactive: exit %d, %v", r.code, r.err)
	}
}

// An empty index: nothing to do for a command acting on an existing zone
// or domain, a usage error for one creating a record in it.
func TestDNSPickWithEmptyIndex(t *testing.T) {
	_, cfgPath := setup(t, true)
	r := runFlow(t, context.Background(), cfgPath, prompttest.New(t), strings.NewReader(""), "dns", "list", "--offline")
	if r.code != ExitOK || !strings.Contains(r.err.Error(), "nothing to do: no indexed zone") {
		t.Errorf("list: exit %d, %v", r.code, r.err)
	}
	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t), strings.NewReader(""), "dns", "set", "--offline")
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "<domain> is required") {
		t.Errorf("set: exit %d, %v", r.code, r.err)
	}
	// dns delete and domain ns set act on an existing zone or domain:
	// nothing to do.
	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t), strings.NewReader(""), "dns", "delete")
	if r.code != ExitOK || !strings.Contains(r.err.Error(), "nothing to do: no indexed zone") {
		t.Errorf("delete: exit %d, %v", r.code, r.err)
	}
	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t), strings.NewReader(""), "domain", "ns", "set")
	if r.code != ExitOK || !strings.Contains(r.err.Error(), "nothing to do: no indexed domain") {
		t.Errorf("ns set: exit %d, %v", r.code, r.err)
	}
}

// dns set without a record asks for the name, the type and the value, the
// value checked as it is typed and prefilled with the current one.
func TestDNSSetAsksTypeAndValue(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "example.com", Type: "A", Value: "203.0.113.10", TTL: 300})
	p := prompttest.New(t, "@", "A", "not-an-ip", "203.0.113.20")
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "set", "example.com")
	if r.err != nil || fc.count("UpdateRecord") != 1 || fc.records["z1"][0].Value != "203.0.113.20" {
		t.Fatalf("set: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	if a := p.Find("Value of the A record"); a.Default != "203.0.113.10" {
		t.Errorf("value default %q", a.Default)
	}
	p.Done()
	// Non-interactive: unchanged.
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "set", "example.com", "--type", "A")
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "usage: polyctl dns set <domain> <name> <type> <value>") {
		t.Errorf("non-interactive: exit %d, %v", r.code, r.err)
	}
}

// dns delete without a selection lists the records to tick, never the
// zone's own SOA and apex NS.
func TestDNSDeletePicksRecords(t *testing.T) {
	recs := append(fiveRecords()[:2],
		platform.Record{ID: "ns1", ZoneID: "z1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
		platform.Record{ID: "soa", ZoneID: "z1", Name: "example.com", Type: "SOA", Value: "x"})
	_, cfgPath, fc := ensureZone(t, recs...)
	p := prompttest.New(t, []string{"r2"})
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "delete", "example.com")
	if r.err != nil || fc.count("DeleteRecord") != 1 || len(fc.records["z1"]) != 3 {
		t.Fatalf("delete: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	if a := p.Find("Delete which records of example.com?"); prompttest.Values(a.Options) != "r1 r2" || !strings.Contains(a.Options[1].Label, "h2.example.com  A  192.0.2.2  ttl 300") {
		t.Errorf("record options %+v", a.Options)
	}
	p.Done()
	// --value alone narrows the records offered; a dry run still asks and
	// deletes nothing.
	p = prompttest.New(t, []string{"r1"})
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "delete", "example.com", "--value", "192.0.2.1", "--dry-run")
	if r.err != nil || fc.count("DeleteRecord") != 1 {
		t.Fatalf("narrowed dry run: %v, %q, calls %v", r.err, r.stderr, fc.calls)
	}
	if a := p.Find("Delete which records of example.com?"); prompttest.Values(a.Options) != "r1" {
		t.Errorf("narrowed options %+v", a.Options)
	}
	p.Done()
	// Nothing ticked: nothing to do.
	r = runFlow(t, context.Background(), cfgPath, prompttest.New(t, []string{}), strings.NewReader(""), "dns", "delete", "example.com")
	if r.code != ExitOK || fc.count("DeleteRecord") != 1 {
		t.Errorf("nothing ticked: exit %d, %v", r.code, r.err)
	}
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "delete", "example.com")
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "a record, --id <record-id> or --all is required: usage: polyctl dns delete <domain> <name> [<type> [<value>]]") {
		t.Errorf("non-interactive: exit %d, %v", r.code, r.err)
	}
}
