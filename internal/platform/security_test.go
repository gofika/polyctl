package platform

import (
	"strings"
	"testing"
)

func TestParseIngressRule(t *testing.T) {
	for in, want := range map[string]string{
		"tcp:443:0.0.0.0/0":         "tcp 443 0.0.0.0/0",
		"TCP:https:0.0.0.0/0":       "tcp 443 0.0.0.0/0",
		"tcp:ssh:10.0.0.0/8":        "tcp 22 10.0.0.0/8",
		"udp:8000-8999:10.5.6.7/8":  "udp 8000-8999 10.0.0.0/8",
		"tcp:http-8080:10.0.0.0/8":  "tcp 80-8080 10.0.0.0/8",
		"tcp:22:203.0.113.7":        "tcp 22 203.0.113.7/32",
		"tcp:all:203.0.113.7/32":    "tcp 1-65535 203.0.113.7/32",
		"icmp:all:::/0":             "icmp all ::/0",
		"tcp:443:2001:db8::1":       "tcp 443 2001:db8::1/128",
		"tcp:443:2001:db8::/32":     "tcp 443 2001:db8::/32",
		"all:all:sg-0123456789abc":  "all all sg-0123456789abc",
		"tcp:postgres:192.0.2.0/24": "tcp 5432 192.0.2.0/24",
	} {
		r, err := ParseIngressRule(in)
		if err != nil || r.String() != want {
			t.Errorf("ParseIngressRule(%q) = %q, %v; want %q", in, r.String(), err, want)
		}
	}
	r, _ := ParseIngressRule("tcp:443:::/0")
	if r.SourceKind != SourceIPv6 {
		t.Errorf("::/0 kind = %s", r.SourceKind)
	}
	r, _ = ParseIngressRule("icmp:all:sg-1")
	if r.SourceKind != SourceGroup || r.FromPort != -1 {
		t.Errorf("sg rule = %+v", r)
	}
	for in, want := range map[string]string{
		"tcp:443":           "three parts",
		"tcp:443:":          "a source is required",
		"sctp:1:0.0.0.0/0":  "unknown protocol",
		"tcp:0:0.0.0.0/0":   "out of range",
		"tcp:70000:1.2.3.4": "out of range",
		"tcp:9-1:1.2.3.4":   "reversed",
		"tcp:foo:1.2.3.4":   "unknown port or alias",
		"icmp:80:1.2.3.4":   "icmp takes no port",
		"all:80:1.2.3.4":    "every port",
		"tcp:80:example":    "not a CIDR",
		"tcp:80:sg-":        "incomplete",
	} {
		if _, err := ParseIngressRule(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseIngressRule(%q) = %v, want %q", in, err, want)
		}
	}
}

func TestRuleSetHelpers(t *testing.T) {
	rules, err := ParseIngressRules([]string{"tcp:443:1.2.3.4", "tcp:https:1.2.3.4/32", "tcp:80:0.0.0.0/0"})
	if err != nil || len(rules) != 2 {
		t.Fatalf("dedup = %+v, %v", rules, err)
	}
	have := []IngressRule{{Protocol: "tcp", FromPort: 443, ToPort: 443, Source: "1.2.3.4/32", Description: "something else"}}
	missing := MissingRules(have, rules)
	if len(missing) != 1 || missing[0].String() != "tcp 80 0.0.0.0/0" {
		t.Errorf("missing = %+v (the description must not count)", missing)
	}
	if _, err := ParseIngressRules([]string{"bad"}); err == nil {
		t.Error("bad rule accepted")
	}
}

func TestParseListener(t *testing.T) {
	for in, want := range map[string]string{"tcp:80": "tcp:80", "HTTPS:443": "https:443", "tls:https": "tls:443", "tcp_udp:53": "tcp_udp:53"} {
		l, err := ParseListener(in)
		if err != nil || l.String() != want {
			t.Errorf("ParseListener(%q) = %v, %v", in, l, err)
		}
	}
	for _, in := range []string{"tcp", "tcp:", ":80", "sctp:80", "tcp:0", "tcp:x"} {
		if _, err := ParseListener(in); err == nil {
			t.Errorf("ParseListener(%q) accepted", in)
		}
	}
}
