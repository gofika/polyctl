package aws

import (
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// Every type Route 53 writes reaches it as the value of a record set in
// zone-file form; every other known type, and an invalid value, is refused
// before any request.
func TestRoute53RecordUpsertEveryType(t *testing.T) {
	h, r53, reset := positionalHarness(t)
	want := map[string]string{
		"A":     "203.0.113.10",
		"AAAA":  "2001:db8::10",
		"CNAME": "target.example.net",
		"MX":    "10 mail.example.com",
		"NS":    "ns1.example.net",
		"TXT":   `"v=spf1 include:_spf.example.net ~all"`,
		"SPF":   `"v=spf1 -all"`,
		"SRV":   "10 5 5060 sip.example.com",
		"CAA":   `0 issue "letsencrypt.org"`,
		"PTR":   "host.example.com",
		"NAPTR": `100 10 "S" "SIP+D2U" "" _sip._udp.example.com`,
		"HTTPS": "1 . alpn=h3,h2",
		"SVCB":  "1 svc.example.net port=8443",
		"TLSA":  "3 1 1 " + strings.Repeat("ab", 32),
		"SSHFP": "4 2 " + strings.Repeat("cd", 32),
		"DS":    "12345 13 2 " + strings.Repeat("ef", 32),
	}
	types := platform.WritableRecordTypes(platform.AWS)
	if len(types) != len(want) {
		t.Fatalf("types = %v", types)
	}
	for _, typ := range types {
		info, _ := platform.RecordType(typ)
		reset()
		if err := h.run("route53", "record", "upsert", "other.org", "x", typ, info.Example); err != nil {
			t.Errorf("%s %q: %v", typ, info.Example, err)
			continue
		}
		if got := r53.values("Z3", "x.other.org.", typ); !slices.Equal(got, []string{want[typ]}) {
			t.Errorf("%s: values %q, want %q", typ, got, want[typ])
		}
	}
	for _, typ := range platform.KnownRecordTypes {
		if slices.Contains(types, typ) {
			continue
		}
		info, _ := platform.RecordType(typ)
		reset()
		r53.calls = 0
		err := h.run("route53", "record", "upsert", "other.org", "x", typ, info.Example)
		if !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "aws cannot write "+typ+" records") || r53.calls != 0 {
			t.Errorf("%s: %v, %d requests", typ, err, r53.calls)
		}
	}
	for _, args := range [][]string{
		{"x", "SRV", "5 5060 sip.example.com"},
		{"x", "SRV", "5 5060 sip.example.com", "--priority", "10"},
		{"x", "MX", "mail.example.com"},
		{"x", "MX", "10 mx1.example.net", "--priority", "20"},
		{"x", "TXT", `"a" b`},
		{"x", "HTTPS", "0 . alpn=h2"},
	} {
		reset()
		r53.calls = 0
		err := h.run(append([]string{"route53", "record", "upsert", "other.org"}, args...)...)
		if !errors.Is(err, platform.ErrInvalidInput) && !errors.Is(err, app.ErrUsage) || r53.calls != 0 {
			t.Errorf("%v: %v, %d requests", args, err, r53.calls)
		}
	}
	// TXT bytes outside printable ASCII are written as octal escapes.
	if got := quoteTXT("TXT", "a\tbé"); got != `"a\011b\303\251"` {
		t.Errorf("escaped TXT = %s", got)
	}
}
