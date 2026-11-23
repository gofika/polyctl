package platform

import (
	"strings"
	"testing"
)

func TestParseRecordSpec(t *testing.T) {
	type want struct {
		name, typ, value string
		ttl              int // -1 = not given
		proxied          string
	}
	for in, w := range map[string]want{
		"www:A:1.2.3.4":                        {"www", "A", "1.2.3.4", -1, ""},
		"www:a:1.2.3.4:300":                    {"www", "A", "1.2.3.4", 300, ""},
		"www:A:1.2.3.4:300:true":               {"www", "A", "1.2.3.4", 300, "true"},
		"www:A:1.2.3.4::false":                 {"www", "A", "1.2.3.4", -1, "false"},
		"www:A:1.2.3.4:auto:TRUE":              {"www", "A", "1.2.3.4", -1, "true"},
		"v6:AAAA:2001:db8::1":                  {"v6", "AAAA", "2001:db8::1", -1, ""},
		"lo:AAAA:::1":                          {"lo", "AAAA", "::1", -1, ""},
		"v6:AAAA:2001:db8::1:300:true":         {"v6", "AAAA", "2001:db8::1", 300, "true"},
		"@:TXT:v=spf1 ip6:2001:db8::/32 -all":  {"@", "TXT", "v=spf1 ip6:2001:db8::/32 -all", -1, ""},
		"@:TXT:hello:600":                      {"@", "TXT", "hello", 600, ""},
		"@:CNAME:example.com":                  {"@", "CNAME", "example.com", -1, ""},
		"mail:MX:10 mail.example.com:3600":     {"mail", "MX", "10 mail.example.com", 3600, ""},
		"www.example.com.:CNAME:a.example.net": {"www.example.com.", "CNAME", "a.example.net", -1, ""},
	} {
		s, err := ParseRecordSpec(in)
		if err != nil {
			t.Errorf("ParseRecordSpec(%q): %v", in, err)
			continue
		}
		ttl := -1
		if s.TTL != nil {
			ttl = *s.TTL
		}
		px := ""
		if s.Proxied != nil {
			px = map[bool]string{true: "true", false: "false"}[*s.Proxied]
		}
		if s.Name != w.name || s.Type != w.typ || s.Value != w.value || ttl != w.ttl || px != w.proxied {
			t.Errorf("ParseRecordSpec(%q) = %+v (ttl %d, proxied %q), want %+v", in, s, ttl, px, w)
		}
	}
	for in, want := range map[string]string{
		"www:A":                     "at least name, type and value",
		"www:A:":                    "not an IPv4",
		"www:A:example.com":         "not an IPv4",
		"x:AAAA:::1:300":            "more than one way",
		"x:AAAA:2001:db8::1:300":    "more than one way",
		"@:SOA:x":                   "SOA",
		"@:XYZ:x":                   "unknown record type",
		"@:TXT:hello:300:true":      "proxied applies",
		"www:A:1.2.3.4:-5":          "",
		":A:1.2.3.4":                "name is empty",
		"www:CNAME:host:with:colon": "not valid",
	} {
		_, err := ParseRecordSpec(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseRecordSpec(%q) = %v, want %q", in, err, want)
		}
	}
}

func TestRecordSpecFQDN(t *testing.T) {
	for name, want := range map[string]string{"@": "example.com", "www": "www.example.com", "www.example.com": "www.example.com", "www.example.com.": "www.example.com", "a.b": "a.b.example.com"} {
		if got, err := (RecordSpec{Name: name}).FQDN("example.com"); err != nil || got != want {
			t.Errorf("FQDN(%q) = %q, %v", name, got, err)
		}
	}
	if _, err := (RecordSpec{Name: "foo.other.com."}).FQDN("example.com"); err == nil {
		t.Error("an absolute name outside the zone is accepted")
	}
}

func TestParseRecordFile(t *testing.T) {
	specs, err := ParseRecordFile(strings.NewReader(`records:
  - name: www
    type: a
    value: 1.2.3.4
    ttl: 300
    proxied: true
  - name: "@"
    type: MX
    value: mail.example.com
    priority: 10
  - name: v6
    type: AAAA
    value: "::1"
    ttl: auto
`))
	if err != nil || len(specs) != 3 || specs[0].Type != "A" || *specs[0].TTL != 300 || !*specs[0].Proxied || *specs[1].Priority != 10 || specs[2].TTL != nil || specs[2].Value != "::1" {
		t.Fatalf("specs = %+v, %v", specs, err)
	}
	for body, want := range map[string]string{
		"records:\n  - name: w\n    type: A\n    value: 1.2.3.4\n    tll: 3\n":    "tll",
		"records:\n  - name: w\n    type: A\n    value: nope\n":                   "record 1",
		"records:\n  - name: w\n    type: TXT\n    value: x\n    priority: 1\n":   "priority applies",
		"records:\n  - name: w\n    type: A\n    value: 1.2.3.4\n    ttl: soon\n": "ttl",
		"": "empty",
	} {
		if _, err := ParseRecordFile(strings.NewReader(body)); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: %v, want %q", body, err, want)
		}
	}
}
