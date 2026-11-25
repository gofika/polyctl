package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// domain ns set without arguments: the registered domains, then the
// nameserver sets of the zones of that domain, or a typed list.
func TestDomainNSSetPicks(t *testing.T) {
	_, cfgPath := setup(t, true)
	fc := client("a")
	fc.domains = []platform.Domain{{Name: "example.com", Nameservers: []string{"a.ns"}}}
	fc.zones = []platform.Zone{{ID: "z1", Name: "example.com", Nameservers: []string{"alice.ns.example.net", "bob.ns.example.net"}}}
	if _, stderr, err := run(t, cfgPath, "domain", "index"); err != nil {
		t.Fatalf("index: %v (%s)", err, stderr)
	}
	p := prompttest.New(t, "example.com", prompttest.Label("zone example.com  cloudflare/a  alice.ns.example.net, bob.ns.example.net"))
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "domain", "ns", "set", "--dry-run", "-o", "json")
	if r.err != nil {
		t.Fatalf("ns set: %v (%s)", r.err, r.stderr)
	}
	if rep := decodeReport(t, r.stdout); len(rep.Changes) != 1 || rep.Changes[0].Detail != "alice.ns.example.net,bob.ns.example.net" {
		t.Errorf("report = %+v", rep)
	}
	if a := p.Find("Registered domain"); prompttest.Values(a.Options) != "example.com" || !strings.Contains(a.Options[0].Label, "domain cloudflare/a") {
		t.Errorf("domain options %+v", a.Options)
	}
	p.Done()

	// Typed nameservers, an empty list re-asked.
	p = prompttest.New(t, "example.com", prompttest.Label("Enter nameservers"), " , ", "ns1.example.org, ns2.example.org")
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "domain", "ns", "set", "--dry-run", "-o", "json")
	if rep := decodeReport(t, r.stdout); r.err != nil || len(rep.Changes) != 1 || rep.Changes[0].Detail != "ns1.example.org,ns2.example.org" {
		t.Errorf("typed: %v, %+v", r.err, rep)
	}
	p.Done()
	if fc.count("SetNameservers") != 0 {
		t.Errorf("a dry run wrote: %v", fc.calls)
	}
	// Non-interactive: unchanged.
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "domain", "ns", "set", "example.com")
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "at least one nameserver is required") {
		t.Errorf("non-interactive: exit %d, %v", r.code, r.err)
	}
}
