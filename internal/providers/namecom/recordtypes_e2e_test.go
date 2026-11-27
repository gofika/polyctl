package namecom_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/platform"
)

// Every type name.com writes reaches its API as host, type, answer and
// priority; every other known type, and an invalid value, is refused
// before any request.
func TestDNSCreateEveryType(t *testing.T) {
	e := newRecordEnv(t)
	want := map[string]string{
		"A":     "www A 203.0.113.10 0 -",
		"AAAA":  "www AAAA 2001:db8::10 0 -",
		"CNAME": "www CNAME target.example.net 0 -",
		"ANAME": "www ANAME target.example.net 0 -",
		"MX":    "www MX mail.example.com 0 10",
		"NS":    "www NS ns1.example.net 0 -",
		"TXT":   "www TXT v=spf1 include:_spf.example.net ~all 0 -", // the text, unquoted
		"SRV":   "www SRV 5 5060 sip.example.com 0 10",
	}
	types := platform.WritableRecordTypes(platform.NameCom)
	if len(types) != len(want) {
		t.Fatalf("types = %v", types)
	}
	for _, typ := range types {
		info, _ := platform.RecordType(typ)
		e.f.Reset()
		code, _, stderr := e.run(nil, "namecom", "dns", "create", "example.com", "www", typ, info.Example)
		if code != cli.ExitOK || e.records() != want[typ] {
			t.Errorf("%s %q: exit %d, %s, records %q, want %q", typ, info.Example, code, stderr, e.records(), want[typ])
		}
	}
	for _, typ := range platform.KnownRecordTypes {
		if slices.Contains(types, typ) {
			continue
		}
		info, _ := platform.RecordType(typ)
		n := e.f.Requests()
		code, _, stderr := e.run(nil, "namecom", "dns", "create", "example.com", "www", typ, info.Example)
		if code != cli.ExitNotSupported || !strings.Contains(stderr, "namecom cannot write "+typ+" records (it writes A AAAA CNAME ANAME MX NS TXT SRV)") || e.f.Requests() != n {
			t.Errorf("%s: exit %d, %s, %d requests", typ, code, stderr, e.f.Requests()-n)
		}
	}
	for _, args := range [][]string{
		{"namecom", "dns", "create", "example.com", "www", "SRV", "5 5060 sip.example.com"},
		{"namecom", "dns", "create", "example.com", "www", "SRV", "5 5060 sip.example.com", "--priority", "10"},
		{"namecom", "dns", "create", "example.com", "www", "MX", "mail.example.com"},
		{"namecom", "dns", "create", "example.com", "www", "CNAME", "a..example.net"},
		{"namecom", "dns", "update", "example.com", "www", "A", "--value", "nope"},
		{"namecom", "dns", "update", "example.com", "www", "--type", "CAA", "--value", "0 issue x"},
	} {
		n := e.f.Requests()
		code, _, stderr := e.run(nil, args...)
		if (code != cli.ExitUsage && code != cli.ExitNotSupported) || e.f.Requests() != n {
			t.Errorf("%v: exit %d, %s, %d requests", args, code, stderr, e.f.Requests()-n)
		}
	}
}
