package aliyun

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// Every type Alidns writes reaches AddDomainRecord as its Type, Value and
// Priority (an MX priority apart, a TXT value unquoted, a CAA value
// quoted); every other known type, and an invalid value, is refused before
// any request.
func TestDNSRecordCreateEveryType(t *testing.T) {
	h, added := createHarness(t, app.Flags{NonInteractive: true})
	want := map[string]string{
		"A":     "Type=A Value=203.0.113.10 TTL= Priority=",
		"AAAA":  "Type=AAAA Value=2001:db8::10 TTL= Priority=",
		"CNAME": "Type=CNAME Value=target.example.net TTL= Priority=",
		"ALIAS": "Type=ALIAS Value=target.example.net TTL= Priority=",
		"MX":    "Type=MX Value=mail.example.com TTL= Priority=10",
		"NS":    "Type=NS Value=ns1.example.net TTL= Priority=",
		"TXT":   "Type=TXT Value=v=spf1 include:_spf.example.net ~all TTL= Priority=",
		"SRV":   "Type=SRV Value=10 5 5060 sip.example.com TTL= Priority=",
		"CAA":   `Type=CAA Value=0 issue "letsencrypt.org" TTL= Priority=`,
		"HTTPS": "Type=HTTPS Value=1 . alpn=h3,h2 TTL= Priority=",
		"SVCB":  "Type=SVCB Value=1 svc.example.net port=8443 TTL= Priority=",
		"TLSA":  "Type=TLSA Value=3 1 1 " + strings.Repeat("ab", 32) + " TTL= Priority=",
	}
	types := platform.WritableRecordTypes(platform.Aliyun)
	if len(types) != len(want) {
		t.Fatalf("types = %v", types)
	}
	for _, typ := range types {
		info, _ := platform.RecordType(typ)
		*added = nil
		if err := h.run("dns", "record", "create", "example.com", "x", typ, info.Example); err != nil {
			t.Errorf("%s %q: %v", typ, info.Example, err)
			continue
		}
		if want := "DomainName=example.com RR=x " + want[typ] + " Line=default"; len(*added) != 1 || (*added)[0] != want {
			t.Errorf("%s: sent %q, want %q", typ, *added, want)
		}
	}
	for _, typ := range platform.KnownRecordTypes {
		if slices.Contains(types, typ) {
			continue
		}
		info, _ := platform.RecordType(typ)
		h.api.calls = nil
		err := h.run("dns", "record", "create", "example.com", "x", typ, info.Example)
		if !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "aliyun cannot write "+typ+" records") || len(h.api.calls) != 0 {
			t.Errorf("%s: %v, %d requests", typ, err, len(h.api.calls))
		}
	}
	for _, args := range [][]string{
		{"create", "example.com", "x", "SRV", "5 5060 sip.example.com"},
		{"create", "example.com", "x", "MX", "mail.example.com"},
		{"create", "example.com", "x", "TLSA", "3 1 1 abcd"},
		{"create", "example.com", "x", "REDIRECT_URL", "https://example.net"},
		{"update", "example.com", "x", "A", "--value", "nope"},
		{"update", "example.com", "x", "--type", "PTR", "--value", "host.example.com"},
	} {
		h.api.calls = nil
		err := h.run(append([]string{"dns", "record"}, args...)...)
		if !errors.Is(err, platform.ErrInvalidInput) && !errors.Is(err, app.ErrUsage) && !errors.Is(err, platform.ErrNotSupported) || len(h.api.calls) != 0 {
			t.Errorf("%v: %v, %d requests", args, err, len(h.api.calls))
		}
	}
	// A TXT value given as quoted strings is sent as its text.
	*added = nil
	if err := h.run("dns", "record", "create", "example.com", "x", "TXT", `"v=spf1 " "-all"`); err != nil || len(*added) != 1 || !strings.Contains((*added)[0], "Value=v=spf1 -all TTL") {
		t.Errorf("quoted TXT: %v, %q", err, *added)
	}
}
