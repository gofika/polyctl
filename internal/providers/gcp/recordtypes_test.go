package gcp

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// Every type Cloud DNS writes reaches it as an rrdata in zone-file form,
// the host names in it fully qualified; every other known type, and an
// invalid value, is refused before any request.
func TestDNSRecordUpsertEveryType(t *testing.T) {
	want := map[string]string{
		"A":        "203.0.113.10",
		"AAAA":     "2001:db8::10",
		"CNAME":    "target.example.net.",
		"ALIAS":    "target.example.net.",
		"MX":       "10 mail.example.com.",
		"NS":       "ns1.example.net.",
		"TXT":      `"v=spf1 include:_spf.example.net ~all"`,
		"SPF":      `"v=spf1 -all"`,
		"SRV":      "10 5 5060 sip.example.com.",
		"CAA":      `0 issue "letsencrypt.org"`,
		"PTR":      "host.example.com.",
		"NAPTR":    `100 10 "S" "SIP+D2U" "" _sip._udp.example.com.`,
		"HTTPS":    "1 . alpn=h3,h2",
		"SVCB":     "1 svc.example.net. port=8443",
		"TLSA":     "3 1 1 " + strings.Repeat("ab", 32),
		"SSHFP":    "4 2 " + strings.Repeat("cd", 32),
		"DS":       "12345 13 2 " + strings.Repeat("ef", 32),
		"DNSKEY":   "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==",
		"IPSECKEY": "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==",
	}
	types := platform.WritableRecordTypes(platform.GCP)
	if len(types) != len(want) {
		t.Fatalf("types = %v", types)
	}
	for _, typ := range types {
		info, _ := platform.RecordType(typ)
		h, g := positionalHarness(t)
		if err := h.run("dns", "record", "upsert", "example-zone", "x", typ, info.Example); err != nil {
			t.Errorf("%s %q: %v", typ, info.Example, err)
			continue
		}
		if rs := g.rrset("example-zone", "x.example.com.", typ); rs == nil || !slices.Equal(rs.Rrdatas, []string{want[typ]}) {
			t.Errorf("%s: set %+v, want %q", typ, rs, want[typ])
		}
	}
	h, g := positionalHarness(t)
	for _, typ := range platform.KnownRecordTypes {
		if slices.Contains(types, typ) {
			continue
		}
		info, _ := platform.RecordType(typ)
		g.requests = nil
		err := h.run("dns", "record", "upsert", "example-zone", "x", typ, info.Example)
		if !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "gcp cannot write "+typ+" records") || len(g.requests) != 0 {
			t.Errorf("%s: %v, requests %v", typ, err, g.requests)
		}
	}
	for _, args := range [][]string{
		{"x", "SRV", "5 5060 sip.example.com"},
		{"x", "SRV", "5 5060 sip.example.com", "--priority", "10"},
		{"x", "MX", "mail.example.com"},
		{"x", "NAPTR", `100 10 "S" "SIP" "!x!y!" host.example.com`},
		{"x", "CAA", "0 issue"},
	} {
		g.requests = nil
		err := h.run(append([]string{"dns", "record", "upsert", "example-zone"}, args...)...)
		if !errors.Is(err, platform.ErrInvalidInput) && !errors.Is(err, app.ErrUsage) || len(g.requests) != 0 {
			t.Errorf("%v: %v, requests %v", args, err, g.requests)
		}
	}
}
