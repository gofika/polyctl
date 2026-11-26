package platform

import (
	"errors"
	"slices"
	"strings"
	"testing"
)

// Every known type: valid values and their normal form, and invalid values
// with what the error says.
func TestCheckRecordValues(t *testing.T) {
	hex64 := strings.Repeat("ab", 32)
	valid := []struct{ typ, in, want string }{
		{"A", "203.0.113.10", "203.0.113.10"},
		{"AAAA", "2001:DB8:0:0::10", "2001:db8::10"},
		{"CNAME", "Target.Example.NET.", "target.example.net"},
		{"CNAME", "_dkim.example.net", "_dkim.example.net"},
		{"CNAME", "bücher.example", "xn--bcher-kva.example"},
		{"ALIAS", "lb.example.net.", "lb.example.net"},
		{"ANAME", "lb.example.net", "lb.example.net"},
		{"NS", "ns1.example.net", "ns1.example.net"},
		{"PTR", "host.example.com.", "host.example.com"},
		{"MX", "mail.example.com", "mail.example.com"},
		{"MX", "10 Mail.Example.com.", "mail.example.com"},
		{"MX", "0 .", "."},
		{"TXT", "v=spf1 include:_spf.example.net ~all", "v=spf1 include:_spf.example.net ~all"},
		{"TXT", `say "hi"`, `say "hi"`},
		{"TXT", `"a b" "c"`, `"a b" "c"`},
		{"TXT", strings.Repeat("x", 600), strings.Repeat("x", 600)},
		{"SPF", `"v=spf1 -all"`, `"v=spf1 -all"`},
		{"SRV", "10 5 5060 SIP.example.com.", "10 5 5060 sip.example.com"},
		{"SRV", "0 0 0 .", "0 0 0 ."},
		{"CAA", "0 issue letsencrypt.org", `0 issue "letsencrypt.org"`},
		{"CAA", `128 ISSUEWILD "ca.example.net; account=1"`, `128 issuewild "ca.example.net; account=1"`},
		{"CAA", "0 issue letsencrypt.org; validationmethods=dns-01", `0 issue "letsencrypt.org; validationmethods=dns-01"`},
		{"CAA", `0 issue ";"`, `0 issue ";"`},
		{"NAPTR", `100 10 "S" "SIP+D2U" "" _sip._udp.example.com.`, `100 10 "S" "SIP+D2U" "" _sip._udp.example.com`},
		{"NAPTR", `100 50 u E2U+sip "!^(\\+44)$!sip:\\1@example.com!" .`, `100 50 "u" "E2U+sip" "!^(\\+44)$!sip:\\1@example.com!" .`},
		{"HTTPS", `1 . alpn="h3,h2"`, `1 . alpn=h3,h2`},
		{"HTTPS", "0 cdn.example.net.", "0 cdn.example.net"},
		{"SVCB", "16 svc.example.net port=8443 ipv4hint=192.0.2.1,192.0.2.2 no-default-alpn alpn=h2 mandatory=alpn,port", "16 svc.example.net port=8443 ipv4hint=192.0.2.1,192.0.2.2 no-default-alpn alpn=h2 mandatory=alpn,port"},
		{"SVCB", "1 . key65000=x", "1 . key65000=x"},
		{"TLSA", "3 1 1 " + strings.ToUpper(hex64), "3 1 1 " + hex64},
		{"TLSA", "3 1 0 ab cd", "3 1 0 abcd"},
		{"SMIMEA", "3 1 1 " + hex64, "3 1 1 " + hex64},
		{"SSHFP", "4 2 " + hex64, "4 2 " + hex64},
		{"SSHFP", "1 1 09F6A01D2175742B257C6B98B7C72C44C4040683", "1 1 09f6a01d2175742b257c6b98b7c72c44c4040683"},
		{"DS", "12345 13 2 " + hex64, "12345 13 2 " + hex64},
		{"DNSKEY", "257 3 13 AbCd EfGh", "257 3 13 AbCdEfGh"},
		{"CERT", "PKIX 0 0 AbCd", "1 0 0 AbCd"},
		{"URI", "10 1 https://www.example.com/", `10 1 "https://www.example.com/"`},
		{"LOC", "52 22 23.000 N 4 53 32.000 E -2.00m", "52 22 23.000 N 4 53 32.000 E -2.00m 1m 10000m 10m"},
		{"LOC", "42 S 71 W 10 2m 1000 5", "42 0 0.000 S 71 0 0.000 W 10.00m 2m 1000m 5m"},
		{"OPENPGPKEY", "mQIN BFit", "mQINBFit"},
		{"IPSECKEY", "10 1 2 192.0.2.38 AQNR", "10 1 2 192.0.2.38 AQNR"},
		{"IPSECKEY", "10 3 2 GW.example.com. AQNR", "10 3 2 gw.example.com AQNR"},
		{"IPSECKEY", "10 0 0 .", "10 0 0 ."},
	}
	for _, c := range valid {
		v, err := CheckRecord(RecordCheck{Type: c.typ, Value: c.in})
		if err != nil || v.Value != c.want {
			t.Errorf("%s %q = %q, %v; want %q", c.typ, c.in, v.Value, err, c.want)
		}
	}
	invalidValues := []struct{ typ, in, want string }{
		{"A", "2001:db8::1", "not an IPv4 address"},
		{"A", "example.com", "not an IPv4 address"},
		{"AAAA", "192.0.2.1", "not an IPv6 address"},
		{"AAAA", "::ffff:192.0.2.1", "not an IPv6 address"},
		{"CNAME", "a..example.net", "empty label"},
		{"CNAME", ".", "root"},
		{"CNAME", "a b", "one host name"},
		{"NS", "ns1:example", "not a host name"},
		{"MX", "70000 mail.example.com", "over 65535"},
		{"MX", "x mail.example.com", "not a number"},
		{"MX", "10 20 mail.example.com", "<priority> <host>"},
		{"TXT", `"unterminated`, "quote is not closed"},
		{"TXT", `"a" b`, "not a list of quoted strings"},
		{"TXT", `"` + strings.Repeat("x", 256) + `"`, "256 bytes long"},
		{"SRV", "5 5060 sip.example.com", "3 fields, not 4"},
		{"SRV", "10 5 70000 sip.example.com", "port 70000 is over 65535"},
		{"SRV", "10 5 5060 sip..example.com", "target"},
		{"CAA", "0 issue", "2 fields"},
		{"CAA", "256 issue x", "over 255"},
		{"CAA", "0 is-sue x", "tag"},
		{"CAA", `0 issue "a" "b"`, "more than one quoted string"},
		{"NAPTR", `100 10 "S" "SIP+D2U" ""`, "5 fields, not 6"},
		{"NAPTR", `100 10 "S" "SIP" "!x!y!" host.example.com`, "exclude each other"},
		{"NAPTR", `100 10 "S+" "SIP" "" host.example.com`, "flags"},
		{"HTTPS", "1", "no target"},
		{"HTTPS", "0 . alpn=h2", "alias mode"},
		{"HTTPS", "1 . alpn", "needs a value"},
		{"HTTPS", "1 . port=x", "not a number"},
		{"HTTPS", "1 . alpn=h2 alpn=h3", "given twice"},
		{"HTTPS", "1 . colour=red", "not a parameter key"},
		{"HTTPS", "1 . no-default-alpn=1", "takes no value"},
		{"HTTPS", "1 . ipv4hint=2001:db8::1", "not an IPv4"},
		{"HTTPS", "1 . mandatory=mandatory", "mandatory"},
		{"HTTPS", "1 . ech=!!", "base64"},
		{"TLSA", "3 1 1 abcd", "4 hex digits, not 64"},
		{"TLSA", "3 1 1 " + strings.Repeat("zz", 32), "not hex"},
		{"TLSA", "256 1 1 " + hex64, "over 255"},
		{"TLSA", "3 1 1", "3 fields, not 4"},
		{"SSHFP", "4 2 abc", "odd number"},
		{"SSHFP", "4 1 " + hex64, "64 hex digits, not 40"},
		{"DS", "70000 13 2 " + hex64, "over 65535"},
		{"DS", "12345 13 2 abcd", "not 64"},
		{"DNSKEY", "257 4 13 AbCd", "always 3"},
		{"DNSKEY", "257 3 13 !!!!", "not base64"},
		{"CERT", "FOO 0 0 AbCd", "not a number"},
		{"URI", "10 1", "2 fields"},
		{"URI", `10 1 "not a uri"`, "not a URI"},
		{"LOC", "91 N 4 E 0", "between 0 and 90"},
		{"LOC", "52 22 23 X 4 53 32 E 0", "does not end in N or S"},
		{"LOC", "52 N 4 E", "altitude is missing"},
		{"LOC", "52.5 N 4 E 0", "whole number"},
		{"OPENPGPKEY", "!!", "not base64"},
		{"IPSECKEY", "10 1 2 example.com AQNR", "not an IPv4"},
		{"IPSECKEY", "10 4 2 . AQNR", "over 3"},
		{"IPSECKEY", "10 1 2 192.0.2.38", "key is missing"},
	}
	for _, c := range invalidValues {
		_, err := CheckRecord(RecordCheck{Type: c.typ, Value: c.in})
		if !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%s %q = %v, want a usage error with %q", c.typ, c.in, err, c.want)
			continue
		}
		// The error shows a valid value of the type.
		info, _ := RecordType(c.typ)
		if !strings.Contains(err.Error(), "e.g. "+info.Example) {
			t.Errorf("%s %q: %v does not show the example %q", c.typ, c.in, err, info.Example)
		}
		// The example itself is valid.
		if _, err := CheckRecord(RecordCheck{Type: c.typ, Value: info.Example}); err != nil {
			t.Errorf("the example of %s is invalid: %v", c.typ, err)
		}
	}
}

// The types, the platform's list and the priority are checked before the
// value, each with its own exit code.
func TestCheckRecordTypesAndPriority(t *testing.T) {
	ten := 10
	for _, c := range []struct {
		check RecordCheck
		is    error
		want  string
	}{
		{RecordCheck{Type: "XYZ", Value: "x"}, ErrInvalidInput, "unknown record type \"XYZ\" (known types: A AAAA"},
		{RecordCheck{Type: "", Value: "x"}, ErrInvalidInput, "type is empty"},
		{RecordCheck{Type: "SOA", Value: "x"}, ErrInvalidInput, "managed by the platform"},
		{RecordCheck{Type: "FORWARD_URL", Value: "https://example.net"}, ErrInvalidInput, "not a DNS record type"},
		{RecordCheck{Type: "URL", Value: "https://example.net"}, ErrInvalidInput, "redirect rule set"},
		{RecordCheck{Platform: Cloudflare, Types: []string{"A", "TXT"}, Type: "SPF", Value: "x"}, ErrNotSupported, "cloudflare cannot write SPF records (it writes A TXT); write the SPF policy as a TXT record"},
		{RecordCheck{Platform: NameCom, Types: []string{"ANAME"}, Type: "ALIAS", Value: "x.example"}, ErrNotSupported, "name.com calls this type ANAME"},
		{RecordCheck{Platform: GCP, Types: []string{"ALIAS"}, Type: "ANAME", Value: "x.example"}, ErrNotSupported, "gcp calls this type ALIAS"},
		{RecordCheck{Platform: Cloudflare, Types: []string{"CNAME"}, Type: "ALIAS", Value: "x.example"}, ErrNotSupported, "write a CNAME"},
		{RecordCheck{Platform: AWS, Types: []string{"A"}, Type: "ALIAS", Value: "x.example"}, ErrNotSupported, "alias target"},
		// An unwritable type is reported before its value is looked at.
		{RecordCheck{Platform: GoDaddy, Types: []string{"A"}, Type: "TLSA", Value: "nonsense"}, ErrNotSupported, "godaddy cannot write TLSA"},
		{RecordCheck{Type: "SRV", Value: "5 5060 sip.example.com", Priority: &ten}, ErrInvalidInput, "the priority is the first field of the value, <priority> <weight> <port> <target> (e.g. 10 5 5060 sip.example.com)"},
		{RecordCheck{Type: "HTTPS", Value: "1 .", Priority: &ten}, ErrInvalidInput, "the priority is the first field of the value (0 is alias mode)"},
		{RecordCheck{Type: "URI", Value: `1 "https://x.example/"`, Priority: &ten}, ErrInvalidInput, "first field of the value"},
		{RecordCheck{Type: "NAPTR", Value: `100 10 "S" "SIP" "" x.example`, Priority: &ten}, ErrInvalidInput, "order and preference"},
		{RecordCheck{Type: "TXT", Value: "x", Priority: &ten}, ErrInvalidInput, "applies to MX records only, not to TXT"},
		{RecordCheck{Type: "MX", Value: "20 mail.example.com", Priority: &ten}, ErrInvalidInput, "given twice"},
		{RecordCheck{Type: "MX", Value: "mail.example.com", New: true}, ErrInvalidInput, "needs a priority"},
	} {
		_, err := CheckRecord(c.check)
		if !errors.Is(err, c.is) || !strings.Contains(err.Error(), c.want) {
			t.Errorf("%+v = %v, want %v with %q", c.check, err, c.is, c.want)
		}
	}
	// The MX priority, in the value or apart.
	for _, c := range []RecordCheck{{Type: "mx", Value: "10 mail.example.com", New: true}, {Type: "MX", Value: "mail.example.com", Priority: &ten, New: true}, {Type: "MX", Value: "10 mail.example.com", Priority: &ten}} {
		v, err := CheckRecord(c)
		if err != nil || v.Type != "MX" || v.Value != "mail.example.com" || v.Priority == nil || *v.Priority != 10 || v.ZoneValue() != "10 mail.example.com" {
			t.Errorf("%+v = %+v, %v", c, v, err)
		}
	}
	// An MX without a priority is fine for a record that is not new (an
	// update keeps the priority it has).
	if v, err := CheckRecord(RecordCheck{Type: "MX", Value: "mail.example.com"}); err != nil || v.Priority != nil {
		t.Errorf("MX update = %+v, %v", v, err)
	}
}

// Every known type has a form and an example, and the example passes.
func TestKnownRecordTypes(t *testing.T) {
	for _, typ := range KnownRecordTypes {
		info, ok := RecordType(strings.ToLower(typ))
		if !ok || info.Form == "" || info.Example == "" {
			t.Errorf("%s: %+v", typ, info)
			continue
		}
		if _, err := CheckRecord(RecordCheck{Type: typ, Value: info.Example}); err != nil {
			t.Errorf("example of %s: %v", typ, err)
		}
	}
	if slices.Contains(KnownRecordTypes, "SOA") {
		t.Error("SOA is a known type")
	}
}

func TestRecordFields(t *testing.T) {
	for _, c := range []struct {
		typ, in string
		want    []string
	}{
		{"SRV", "10 5 5060 sip.example.com.", []string{"10", "5", "5060", "sip.example.com"}},
		{"MX", "10 mail.example.com", []string{"10", "mail.example.com"}},
		{"CAA", "0 issue letsencrypt.org", []string{"0", "issue", "letsencrypt.org"}},
		{"NAPTR", `100 10 "S" "SIP+D2U" "" _sip._udp.example.com`, []string{"100", "10", "S", "SIP+D2U", "", "_sip._udp.example.com"}},
		{"URI", `10 1 "https://x.example/"`, []string{"10", "1", "https://x.example/"}},
		{"TXT", `"a" "b"`, []string{"ab"}},
	} {
		got, err := RecordFields(c.typ, c.in)
		if err != nil || !slices.Equal(got, c.want) {
			t.Errorf("RecordFields(%s, %q) = %q, %v", c.typ, c.in, got, err)
		}
	}
	if _, err := RecordFields("SRV", "nope"); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("invalid SRV = %v", err)
	}
}

func TestRecordTypesConflict(t *testing.T) {
	for _, c := range []struct {
		p        ID
		a, b     string
		conflict bool
	}{
		{Cloudflare, "CNAME", "A", true},
		{Cloudflare, "CNAME", "TXT", false},
		{Cloudflare, "NS", "TXT", true},
		{Cloudflare, "NS", "DS", false},
		{AWS, "CNAME", "TXT", true},
		{AWS, "TXT", "CNAME", true},
		{AWS, "NS", "TXT", false},
		{Aliyun, "NS", "MX", true},
		{GCP, "ALIAS", "A", true},
		{GCP, "ALIAS", "TXT", false},
		{AWS, "CNAME", "CNAME", false},
		{AWS, "A", "TXT", false},
	} {
		if got := RecordTypesConflict(c.p, false, c.a, c.b); got != c.conflict {
			t.Errorf("%s %s/%s = %v", c.p, c.a, c.b, got)
		}
	}
	// The NS records of the apex are the zone's own: other records sit
	// beside them, but a CNAME does not.
	if RecordTypesConflict(Aliyun, true, "NS", "TXT") || !RecordTypesConflict(Aliyun, true, "NS", "CNAME") || RecordTypesConflict(Cloudflare, true, "TXT", "NS") {
		t.Error("apex NS conflicts")
	}
	// dns ensure refuses records of its input that cannot share a name.
	if _, err := NormalizeRecordSpecs("example.com", AWS, []RecordSpec{{Name: "www", Type: "CNAME", Value: "a.example.net"}, {Name: "www", Type: "TXT", Value: "x"}}, nil, nil); !errors.Is(err, ErrInvalidInput) || !strings.Contains(err.Error(), "cannot coexist with any other record") {
		t.Errorf("CNAME and TXT on aws = %v", err)
	}
	if _, err := NormalizeRecordSpecs("example.com", Cloudflare, []RecordSpec{{Name: "www", Type: "CNAME", Value: "a.example.net"}, {Name: "www", Type: "TXT", Value: "x"}}, nil, nil); err != nil {
		t.Errorf("CNAME and TXT on cloudflare = %v", err)
	}
}
