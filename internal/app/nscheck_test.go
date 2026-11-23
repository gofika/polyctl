package app_test

import (
	"errors"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

// A DNS client without GetZone is read through its zone list; the index
// is built on the first check, and nothing is written.
func TestNSCheckReadsZonesThroughTheList(t *testing.T) {
	h := newHarness(t, app.Flags{Profile: "c"}, nil)
	fc := clientFor("c", platform.GoDaddy)
	ns := []string{"ns1.dns.example.net", "ns2.dns.example.net"}
	fc.zones = []platform.Zone{{ID: "example.com", Name: "example.com", Nameservers: ns}}
	fc.domains = []platform.Domain{{Name: "example.com", Nameservers: ns}}
	srv := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: ns}})

	res, err := h.rt.NSCheck(ctx, app.NSCheckOptions{Domain: "www.example.com", Resolvers: []string{srv.Addr}, Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if res.CheckedDomain != "example.com" || res.Status != app.NSStatusOK || res.Zone.Platform != platform.GoDaddy || !res.Registrar.Available || res.Failed != nil {
		t.Fatalf("result = %+v", res)
	}
	if fc.count("ListZones") != 1 || fc.count("GetDomain:example.com") != 1 || fc.count("Sync:zone") != 1 || fc.count("Sync:domain") != 1 {
		t.Errorf("calls = %v", fc.calls)
	}
	for _, c := range fc.calls {
		switch {
		case len(c) >= 6 && (c[:6] == "Create" || c[:6] == "Update" || c[:6] == "Delete"), len(c) >= 14 && c[:14] == "SetNameservers":
			t.Errorf("write call %q", c)
		}
	}
}

// --offline is refused before anything is asked.
func TestNSCheckOffline(t *testing.T) {
	h := newHarness(t, app.Flags{Offline: true}, nil)
	if _, err := h.rt.NSCheck(ctx, app.NSCheckOptions{Domain: "example.com", Resolvers: []string{"127.0.0.1:1"}}); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline = %v", err)
	}
}
