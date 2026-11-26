package godaddy_test

import (
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/platform"
)

// Every type GoDaddy writes reaches its API in its fields (the numbers of
// an SRV value in fields of their own, the target in data); every other
// known type, and an invalid value, is refused before any request.
func TestDNSAddEveryType(t *testing.T) {
	e := newDeleteEnv(t)
	want := map[string]string{
		"A":     "A www 203.0.113.10 0 -",
		"AAAA":  "AAAA www 2001:db8::10 0 -",
		"CNAME": "CNAME www target.example.net 0 -",
		"MX":    "MX www mail.example.com 0 10",
		"NS":    "NS www ns1.example.net 0 -",
		"TXT":   `TXT www "v=spf1 include:_spf.example.net ~all" 0 -`,
		"SRV":   "SRV www sip.example.com 0 10",
		"CAA":   `CAA www 0 issue "letsencrypt.org" 0 -`,
	}
	types := platform.WritableRecordTypes(platform.GoDaddy)
	if len(types) != len(want) {
		t.Fatalf("types = %v", types)
	}
	for _, typ := range types {
		info, _ := platform.RecordType(typ)
		e.f.Reset()
		name := "www"
		if typ == "SRV" {
			name = "_sip._tcp.www"
		}
		code, _, stderr := e.run(nil, "", "godaddy", "dns", "add", "example.com", name, typ, info.Example)
		if code != cli.ExitOK || e.details() != want[typ] {
			t.Errorf("%s %q: exit %d, %s, records %q, want %q", typ, info.Example, code, stderr, e.details(), want[typ])
		}
		if typ == "SRV" {
			if got := strings.Join(e.f.SRVs("example.com"), ","); got != "_sip _tcp www 5060 5 10 sip.example.com" {
				t.Errorf("SRV fields = %q", got)
			}
		}
	}
	for _, typ := range platform.KnownRecordTypes {
		if slices.Contains(types, typ) {
			continue
		}
		info, _ := platform.RecordType(typ)
		e.f.Reset()
		code, _, stderr := e.run(nil, "", "godaddy", "dns", "add", "example.com", "www", typ, info.Example)
		if code != cli.ExitNotSupported || !strings.Contains(stderr, "godaddy cannot write "+typ+" records (it writes A AAAA CNAME MX NS TXT SRV CAA)") || e.f.Calls() != 0 {
			t.Errorf("%s: exit %d, %s, %d requests", typ, code, stderr, e.f.Calls())
		}
	}
	for _, args := range [][]string{
		{"add", "example.com", "_sip._tcp", "SRV", "5 5060 sip.example.com"},
		{"add", "example.com", "www", "MX", "mail.example.com"},
		{"add", "example.com", "www", "MX", "mail.example.com", "--priority", "x"},
		{"add", "example.com", "www", "TXT", "x", "--priority", "1"},
		{"upsert", "example.com", "www", "A", "203.0.113.1", "nope"},
		{"upsert", "example.com", "@", "MX", "10 mx1.example.net", "mx2.example.net"},
	} {
		e.f.Reset()
		code, _, stderr := e.run(nil, "", append([]string{"godaddy", "dns"}, args...)...)
		if code != cli.ExitUsage || e.f.Calls() != 0 {
			t.Errorf("%v: exit %d, %s, %d requests", args, code, stderr, e.f.Calls())
		}
	}
	// An SRV record without its _service._proto labels cannot be written.
	e.f.Reset()
	if code, _, stderr := e.run(nil, "", "godaddy", "dns", "add", "example.com", "www", "SRV", "10 5 5060 sip.example.com"); code != cli.ExitUsage || len(e.f.Writes()) != 0 {
		t.Errorf("SRV without labels: exit %d, %s", code, stderr)
	}
}
