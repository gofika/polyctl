package app

import (
	"errors"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func avail(p platform.ID, profile string, ns ...string) NSView {
	return NSView{Platform: p, Profile: profile, NS: platform.NormalizeNS(ns), Available: true}
}

func liveNS(ns ...string) NSView {
	return NSView{NS: platform.NormalizeNS(ns), Resolver: "1.1.1.1", Result: platform.NSOK, Available: true}
}

func TestNSEvaluateStatuses(t *testing.T) {
	cf := []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	old := []string{"ns1.old-dns.example", "ns2.old-dns.example"}
	cases := []struct {
		name      string
		reg, live NSView
		zones     []NSView
		noZone    bool
		zoneErrs  []error
		status    string
		message   string
	}{
		{"ok", avail("godaddy", "acme", cf...), liveNS(cf...), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusOK, "points to the hosted zone"},
		{"ok in any case and order", avail("godaddy", "acme", "BOB.ns.cloudflare.com.", "alice.ns.cloudflare.com"), liveNS("bob.ns.cloudflare.com", "ALICE.NS.CLOUDFLARE.COM."), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusOK, ""},
		{"ok without registrar", NSView{NS: []string{}}, liveNS(cf...), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusOK, ""},
		{"partial overlap", avail("godaddy", "acme", cf...), liveNS(cf[0], old[0]), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusPartial, "partly"},
		{"live equals zone, registrar differs", avail("godaddy", "acme", old...), liveNS(cf...), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusPartial, "registrar lists others"},
		{"mismatch registrar not changed", avail("godaddy", "acme", old...), liveNS(old...), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusMismatch, "set the nameservers at the registrar"},
		{"mismatch cached", avail("godaddy", "acme", cf...), liveNS(old...), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusMismatch, "cached"},
		{"mismatch no registrar", NSView{NS: []string{}}, liveNS(old...), []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusMismatch, "set the nameservers"},
		{"no zone", avail("godaddy", "acme", old...), liveNS(old...), nil, false, nil, NSStatusNoZone, "no hosted zone"},
		{"zone side failed", avail("godaddy", "acme", old...), liveNS(old...), nil, false, []error{errors.New("boom")}, NSStatusUnknown, "could not be read"},
		{"no live", avail("godaddy", "acme", cf...), NSView{NS: []string{}, Result: platform.NSNXDomain, Available: true, Reason: "NXDOMAIN: x"}, []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusNoLive, "NXDOMAIN"},
		{"no zone beats no live", avail("godaddy", "acme", cf...), NSView{NS: []string{}, Result: platform.NSServFail, Available: true, Reason: "SERVFAIL"}, nil, false, nil, NSStatusNoZone, ""},
		{"live timed out", avail("godaddy", "acme", cf...), NSView{NS: []string{}, Result: platform.NSTimeout, Reason: "resolution timed out"}, []NSView{avail("cloudflare", "acme", cf...)}, false, nil, NSStatusUnknown, "timed out"},
		{"no zone flag", avail("godaddy", "acme", cf...), liveNS(cf...), nil, true, nil, NSStatusUnknown, "--no-zone"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &NSCheckResult{CheckedDomain: "example.com", Registrar: c.reg, Live: c.live, Zones: append([]NSView{}, c.zones...)}
			if c.noZone {
				r.Zone = NSView{NS: []string{}, Skipped: true}
			}
			r.evaluate(c.noZone, c.zoneErrs)
			if r.Status != c.status || !strings.Contains(r.Message, c.message) {
				t.Errorf("status %q message %q; want %q containing %q", r.Status, r.Message, c.status, c.message)
			}
		})
	}
}

func TestNSEvaluateMatchAndGuess(t *testing.T) {
	cf := []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	old := []string{"ns1.old-dns.example", "ns2.old-dns.example"}
	z := avail("cloudflare", "acme", cf...)
	z.Status = "pending"
	r := &NSCheckResult{Registrar: avail("godaddy", "acme", old...), Live: liveNS(old...), Zones: []NSView{z}}
	r.evaluate(false, nil)
	m := r.Match
	if m.RegistrarVsZone == nil || *m.RegistrarVsZone || m.LiveVsZone == nil || *m.LiveVsZone || m.RegistrarVsLive == nil || !*m.RegistrarVsLive {
		t.Errorf("match = %+v", m)
	}
	if r.Status != NSStatusMismatch || r.Zone.Status != "pending" || !strings.Contains(r.Message, "pending") || r.ProviderGuess != "unknown" {
		t.Errorf("result = %+v", r)
	}
	// Without live NS the guess comes from the zone; a missing side is null.
	r = &NSCheckResult{Registrar: NSView{NS: []string{}}, Live: NSView{NS: []string{}, Result: platform.NSNXDomain, Available: true}, Zones: []NSView{avail("aliyun", "acme", "ns1.alidns.com", "ns2.alidns.com")}}
	r.evaluate(false, nil)
	if r.ProviderGuess != "aliyun" || r.Match.RegistrarVsZone != nil || r.Match.RegistrarVsLive != nil || r.Match.LiveVsZone == nil {
		t.Errorf("guess/match = %q %+v", r.ProviderGuess, r.Match)
	}
	r = &NSCheckResult{Live: liveNS("alice.ns.cloudflare.com", "ns1.alidns.com"), Zones: []NSView{}}
	r.evaluate(false, nil)
	if r.ProviderGuess != "mixed" || strings.Join(r.Providers, ",") != "aliyun,cloudflare" {
		t.Errorf("mixed = %q %v", r.ProviderGuess, r.Providers)
	}
}

// With several zones, the one the live nameservers point to is compared;
// a zone that only mirrors the registration counts last.
func TestNSBestZone(t *testing.T) {
	cf := []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}
	ali := []string{"ns1.alidns.com", "ns2.alidns.com"}
	old := []string{"ns1.old-dns.example", "ns2.old-dns.example"}
	r := &NSCheckResult{Registrar: avail("godaddy", "acme", ali...), Live: liveNS(ali...), Zones: []NSView{avail("cloudflare", "acme", cf...), avail("aliyun", "acme", ali...)}}
	r.evaluate(false, nil)
	if r.Zone.Platform != "aliyun" || r.Status != NSStatusOK || r.Zones[0].LiveMatch != NSLiveNone || r.Zones[1].LiveMatch != NSLiveEqual {
		t.Errorf("best = %+v, zones %+v, status %s", r.Zone, r.Zones, r.Status)
	}
	// The registrar account's own zone mirrors the registration (old NS):
	// the Cloudflare zone is the one compared, so the delegation is not
	// reported as fine.
	r = &NSCheckResult{Registrar: avail("godaddy", "acme", old...), Live: liveNS(old...), Zones: []NSView{avail("godaddy", "acme", old...), avail("cloudflare", "acme", cf...)}}
	r.evaluate(false, nil)
	if r.Zone.Platform != "cloudflare" || r.Status != NSStatusMismatch || !r.Zones[0].MirrorsRegistrar {
		t.Errorf("mirror = %+v, zones %+v, status %s", r.Zone, r.Zones, r.Status)
	}
	// Alone, a mirroring zone is still compared.
	r = &NSCheckResult{Registrar: avail("godaddy", "acme", old...), Live: liveNS(old...), Zones: []NSView{avail("godaddy", "acme", old...)}}
	r.evaluate(false, nil)
	if r.Zone.Platform != "godaddy" || r.Status != NSStatusOK {
		t.Errorf("single mirror = %+v %s", r.Zone, r.Status)
	}
}

func TestNSLiveView(t *testing.T) {
	v := liveView("example.com", platform.LiveNSResult{Kind: platform.NSNoData, Resolver: "8.8.8.8:53", ZoneApex: "example.co"})
	if !v.Available || v.Resolver != "8.8.8.8" || !strings.Contains(v.Reason, "not a zone apex") || !strings.Contains(v.Reason, "example.co") {
		t.Errorf("nodata = %+v", v)
	}
	if v := liveView("example.com", platform.LiveNSResult{Kind: platform.NSServFail}); !strings.Contains(v.Reason, "DS record") {
		t.Errorf("servfail = %+v", v)
	}
	if v := liveView("example.com", platform.LiveNSResult{Kind: platform.NSTimeout}); v.Available || !strings.Contains(v.Reason, "timed out") {
		t.Errorf("timeout = %+v", v)
	}
	if v := liveView("example.com", platform.LiveNSResult{Kind: platform.NSOK, Resolver: "[::1]:53", Nameservers: []string{"a.example"}}); v.Resolver != "::1" || len(v.NS) != 1 {
		t.Errorf("ok = %+v", v)
	}
}
