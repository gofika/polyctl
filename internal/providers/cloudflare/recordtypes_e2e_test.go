package cloudflare_test

import (
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/platform"
)

// cloudflareTypes are the types of Cloudflare's create-record request.
var cloudflareTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR", "NAPTR", "HTTPS", "SVCB", "TLSA", "SMIMEA", "SSHFP", "DS", "DNSKEY", "CERT", "URI", "LOC", "OPENPGPKEY"}

// Every type Cloudflare writes reaches the API in its fields (the
// components of data for the types that have them), from the example value
// of the type; every other known type, and an invalid value, is refused
// before any request.
func TestDNSCreateEveryType(t *testing.T) {
	if got := platform.WritableRecordTypes(platform.Cloudflare); !slices.Equal(got, cloudflareTypes) {
		t.Fatalf("types = %v", got)
	}
	hex64 := strings.Repeat("ab", 32)
	want := map[string]map[string]any{
		"A":          {"content": "203.0.113.10"},
		"AAAA":       {"content": "2001:db8::10"},
		"CNAME":      {"content": "target.example.net"},
		"MX":         {"content": "mail.example.com", "priority": float64(10)},
		"NS":         {"content": "ns1.example.net"},
		"TXT":        {"content": `"v=spf1 include:_spf.example.net ~all"`},
		"SRV":        {"data": map[string]any{"priority": float64(10), "weight": float64(5), "port": float64(5060), "target": "sip.example.com"}},
		"CAA":        {"data": map[string]any{"flags": float64(0), "tag": "issue", "value": "letsencrypt.org"}},
		"PTR":        {"content": "host.example.com"},
		"NAPTR":      {"data": map[string]any{"order": float64(100), "preference": float64(10), "flags": "S", "service": "SIP+D2U", "regex": "", "replacement": "_sip._udp.example.com"}},
		"HTTPS":      {"data": map[string]any{"priority": float64(1), "target": ".", "value": "alpn=h3,h2"}},
		"SVCB":       {"data": map[string]any{"priority": float64(1), "target": "svc.example.net", "value": "port=8443"}},
		"TLSA":       {"data": map[string]any{"usage": float64(3), "selector": float64(1), "matching_type": float64(1), "certificate": hex64}},
		"SMIMEA":     {"data": map[string]any{"usage": float64(3), "selector": float64(1), "matching_type": float64(1), "certificate": hex64}},
		"SSHFP":      {"data": map[string]any{"algorithm": float64(4), "type": float64(2), "fingerprint": strings.Repeat("cd", 32)}},
		"DS":         {"data": map[string]any{"key_tag": float64(12345), "algorithm": float64(13), "digest_type": float64(2), "digest": strings.Repeat("ef", 32)}},
		"DNSKEY":     {"data": map[string]any{"flags": float64(257), "protocol": float64(3), "algorithm": float64(13)}},
		"CERT":       {"data": map[string]any{"type": float64(1), "key_tag": float64(0), "algorithm": float64(0), "certificate": "MIIBszCCAVmgAwIBAgIU"}},
		"URI":        {"priority": float64(10), "data": map[string]any{"weight": float64(1), "target": "https://www.example.com/"}},
		"LOC":        {"data": map[string]any{"lat_degrees": float64(52), "lat_minutes": float64(22), "lat_seconds": float64(23), "lat_direction": "N", "long_degrees": float64(4), "long_minutes": float64(53), "long_seconds": float64(32), "long_direction": "E", "altitude": float64(-2), "size": float64(1), "precision_horz": float64(10000), "precision_vert": float64(10)}},
		"OPENPGPKEY": {"content": "mDMEXEcE6RYJKwYBBAHaRw8BAQdA"},
	}
	e, post := newRecordEnv(t)
	for _, typ := range cloudflareTypes {
		info, _ := platform.RecordType(typ)
		e.f.reset()
		code, _, stderr := e.run("cloudflare", "dns", "create", "example.com", "_x._tcp", typ, info.Example)
		if code != cli.ExitOK {
			t.Errorf("%s %q: exit %d, %s", typ, info.Example, code, stderr)
			continue
		}
		body := e.f.body(post)
		if body["type"] != typ {
			t.Errorf("%s: type = %v", typ, body["type"])
		}
		for k, v := range want[typ] {
			got := body[k]
			if m, ok := v.(map[string]any); ok && k == "data" {
				d, _ := got.(map[string]any)
				for dk, dv := range m {
					if !reflect.DeepEqual(d[dk], dv) {
						t.Errorf("%s: data.%s = %#v, want %#v (body %v)", typ, dk, d[dk], dv, body)
					}
				}
				if _, ok := body["content"]; ok {
					t.Errorf("%s: content sent beside data: %v", typ, body)
				}
				continue
			}
			if !reflect.DeepEqual(got, v) {
				t.Errorf("%s: %s = %#v, want %#v (body %v)", typ, k, got, v, body)
			}
		}
	}
	for _, typ := range platform.KnownRecordTypes {
		if slices.Contains(cloudflareTypes, typ) {
			continue
		}
		info, _ := platform.RecordType(typ)
		e.f.reset()
		code, _, stderr := e.run("cloudflare", "dns", "create", "example.com", "www", typ, info.Example)
		if code != cli.ExitNotSupported || !strings.Contains(stderr, "cloudflare cannot write "+typ+" records (it writes A AAAA CNAME") || len(e.f.reqs()) != 0 {
			t.Errorf("%s: exit %d, %s, requests %v", typ, code, stderr, e.f.reqs())
		}
	}
	for _, args := range [][]string{
		{"www", "SRV", "5 5060 sip.example.com"},
		{"www", "MX", "mail.example.com"},
		{"_sip._tcp", "SRV", "5 5060 sip.example.com", "--priority", "10"},
		{"www", "CAA", "0 is-sue x"},
		{"www", "TXT", `"unterminated`},
		{"www", "XYZ", "x"},
		{"www", "FORWARD_URL", "https://example.net"},
	} {
		e.f.reset()
		code, _, stderr := e.run(append([]string{"cloudflare", "dns", "create", "example.com"}, args...)...)
		if code != cli.ExitUsage || len(e.f.reqs()) != 0 {
			t.Errorf("%v: exit %d, %s, requests %v", args, code, stderr, e.f.reqs())
		}
	}
	// update checks the new type and value before it reads anything.
	for _, args := range [][]string{
		{"www", "A", "--value", "nope"},
		{"www", "--type", "SPF", "--value", "v=spf1 -all"},
		{"www", "TXT", "--priority", "10"},
		{"_sip._tcp", "SRV", "--priority", "10"},
	} {
		e.f.reset()
		code, _, stderr := e.run(append([]string{"cloudflare", "dns", "update", "example.com"}, args...)...)
		if (code != cli.ExitUsage && code != cli.ExitNotSupported) || len(e.f.reqs()) != 0 {
			t.Errorf("update %v: exit %d, %s, requests %v", args, code, stderr, e.f.reqs())
		}
	}
}
