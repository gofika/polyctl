package platform_test

import (
	"context"
	"reflect"
	"testing"
	"time"

	"github.com/miekg/dns"

	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

func TestRegisteredDomain(t *testing.T) {
	ok := map[string]string{
		"www.example.com":     "example.com",
		"example.com":         "example.com",
		"Example.COM.":        "example.com",
		"example.co.uk":       "example.co.uk",
		"a.b.example.com.cn":  "example.com.cn",
		"foo.github.io":       "foo.github.io",
		"deep.www.example.co": "example.co",
	}
	for in, want := range ok {
		if got, err := platform.RegisteredDomain(in); err != nil || got != want {
			t.Errorf("RegisteredDomain(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "1.2.3.4", "::1", "com", "co.uk"} {
		if got, err := platform.RegisteredDomain(in); err == nil {
			t.Errorf("RegisteredDomain(%q) = %q, want an error", in, got)
		}
	}
}

func TestParseResolver(t *testing.T) {
	ok := map[string]string{
		"1.1.1.1":              "1.1.1.1:53",
		" 8.8.8.8 ":            "8.8.8.8:53",
		"127.0.0.1:5353":       "127.0.0.1:5353",
		"2606:4700:4700::1111": "[2606:4700:4700::1111]:53",
		"[::1]:5353":           "[::1]:5353",
	}
	for in, want := range ok {
		if got, err := platform.ParseResolver(in); err != nil || got != want {
			t.Errorf("ParseResolver(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "dns.google", "dns.google:53", "1.1.1.1:0", "1.1.1.1:99999", "1.1.1.1:x"} {
		if got, err := platform.ParseResolver(in); err == nil {
			t.Errorf("ParseResolver(%q) = %q, want an error", in, got)
		}
	}
}

func TestNormalizeNS(t *testing.T) {
	a := platform.NormalizeNS([]string{"BOB.ns.cloudflare.com.", "ALICE.ns.cloudflare.com.", "alice.ns.cloudflare.com", ""})
	b := platform.NormalizeNS([]string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"})
	if !platform.SameNS(a, b) || !reflect.DeepEqual(a, []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}) {
		t.Errorf("normalized = %v / %v", a, b)
	}
	if !platform.OverlapNS(a, []string{"bob.ns.cloudflare.com", "x.example.net"}) || platform.OverlapNS(a, []string{"x.example.net"}) {
		t.Error("OverlapNS")
	}
}

func TestGuessProvider(t *testing.T) {
	cases := []struct {
		ns      []string
		want    string
		vendors []string
	}{
		{[]string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}, "cloudflare", nil},
		{[]string{"a.foundationdns.com", "b.foundationdns.net", "c.foundationdns.org"}, "cloudflare", nil},
		{[]string{"ns3.cloudflare.com"}, "cloudflare", nil},
		{[]string{"ns1.alidns.com", "ns2.alidns.com"}, "aliyun", nil},
		{[]string{"dns1.hichina.com"}, "aliyun", nil},
		{[]string{"ns-1.awsdns-01.org", "ns-2.awsdns-02.co.uk"}, "aws", nil},
		{[]string{"ns-cloud-a1.googledomains.com."}, "gcp", nil},
		{[]string{"alice.ns.cloudflare.com", "ns1.alidns.com"}, "mixed", []string{"aliyun", "cloudflare"}},
		{[]string{"alice.ns.cloudflare.com", "ns1.example.net"}, "cloudflare", nil},
		{[]string{"ns1.example.net"}, "unknown", nil},
		{nil, "unknown", nil},
	}
	for _, c := range cases {
		got, vendors := platform.GuessProvider(c.ns)
		if got != c.want || !reflect.DeepEqual(vendors, c.vendors) {
			t.Errorf("GuessProvider(%v) = %q %v, want %q %v", c.ns, got, vendors, c.want, c.vendors)
		}
	}
}

func TestLiveNSAnswers(t *testing.T) {
	srv := dnstest.Start(t, map[string]dnstest.Answer{
		"example.com":     {NS: []string{"BOB.ns.cloudflare.com", "alice.ns.cloudflare.com"}},
		"www.example.com": {SOA: "example.com"},
		"broken.com":      {Rcode: dns.RcodeServerFailure},
		"refused.com":     {Rcode: dns.RcodeRefused},
	})
	ctx := context.Background()
	res := []string{srv.Addr}

	r := platform.LiveNS(ctx, "example.com", res, time.Second)
	if r.Kind != platform.NSOK || r.Resolver != srv.Addr || !reflect.DeepEqual(r.Nameservers, []string{"alice.ns.cloudflare.com", "bob.ns.cloudflare.com"}) || !r.Available() {
		t.Errorf("ok = %+v", r)
	}
	if r := platform.LiveNS(ctx, "missing.com", res, time.Second); r.Kind != platform.NSNXDomain || !r.Available() || len(r.Nameservers) != 0 {
		t.Errorf("nxdomain = %+v", r)
	}
	if r := platform.LiveNS(ctx, "www.example.com", res, time.Second); r.Kind != platform.NSNoData || r.ZoneApex != "example.com" {
		t.Errorf("nodata = %+v", r)
	}
	if r := platform.LiveNS(ctx, "broken.com", res, time.Second); r.Kind != platform.NSServFail || !r.Available() {
		t.Errorf("servfail = %+v", r)
	}
	// A resolver that refuses says nothing about the name.
	if r := platform.LiveNS(ctx, "refused.com", res, time.Second); r.Kind != "REFUSED" || r.Available() {
		t.Errorf("refused = %+v", r)
	}
	// A refusal is passed over for a definite answer of another resolver.
	other := dnstest.Start(t, map[string]dnstest.Answer{"refused.com": {SOA: "com"}})
	if r := platform.LiveNS(ctx, "refused.com", []string{srv.Addr, other.Addr}, time.Second); r.Kind != platform.NSNoData || r.Resolver != other.Addr || r.ZoneApex != "com" {
		t.Errorf("refused then nodata = %+v", r)
	}
}

func TestLiveNSResolverOrder(t *testing.T) {
	first := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: []string{"ns1.first.example"}}})
	second := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: []string{"ns1.second.example"}}})
	silent := dnstest.Silent(t)
	ctx := context.Background()

	// A resolver that times out is followed by the next one.
	r := platform.LiveNS(ctx, "example.com", []string{silent, second.Addr}, 200*time.Millisecond)
	if r.Kind != platform.NSOK || r.Resolver != second.Addr || r.Nameservers[0] != "ns1.second.example" {
		t.Errorf("after timeout = %+v", r)
	}
	// Both answer, differently: the first one is used.
	r = platform.LiveNS(ctx, "example.com", []string{first.Addr, second.Addr}, time.Second)
	if r.Resolver != first.Addr || r.Nameservers[0] != "ns1.first.example" {
		t.Errorf("first wins = %+v", r)
	}
	if u, _ := second.Queries(); u != 1 {
		t.Errorf("second resolver asked %d times after the first answered", u)
	}
	// A resolver without NS records is followed by one that has them.
	empty := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {Rcode: dns.RcodeServerFailure}})
	r = platform.LiveNS(ctx, "example.com", []string{empty.Addr, first.Addr}, time.Second)
	if r.Kind != platform.NSOK || r.Resolver != first.Addr {
		t.Errorf("after servfail = %+v", r)
	}
	// Every resolver times out: not available, which is not "no NS".
	r = platform.LiveNS(ctx, "example.com", []string{silent, dnstest.Silent(t)}, 100*time.Millisecond)
	if r.Kind != platform.NSTimeout || r.Available() || r.Err == nil {
		t.Errorf("all timeouts = %+v", r)
	}
	// A timeout next to a definite answer: the answer counts.
	r = platform.LiveNS(ctx, "nosuch.com", []string{silent, first.Addr}, 100*time.Millisecond)
	if r.Kind != platform.NSNXDomain || r.Resolver != first.Addr {
		t.Errorf("timeout and nxdomain = %+v", r)
	}
	if r := platform.LiveNS(ctx, "example.com", nil, time.Second); r.Kind != platform.NSUnavailable || r.Available() {
		t.Errorf("no resolvers = %+v", r)
	}
}

func TestLiveNSRetriesTruncatedOverTCP(t *testing.T) {
	srv := dnstest.Start(t, map[string]dnstest.Answer{"example.com": {NS: []string{"ns1.example.net", "ns2.example.net"}, Truncate: true}})
	r := platform.LiveNS(context.Background(), "example.com", []string{srv.Addr}, time.Second)
	if r.Kind != platform.NSOK || len(r.Nameservers) != 2 {
		t.Fatalf("truncated = %+v", r)
	}
	if u, tcp := srv.Queries(); u != 1 || tcp != 1 {
		t.Errorf("queries udp=%d tcp=%d, want 1 and 1", u, tcp)
	}
	// Without a TCP listener the retry is refused: the resolver is
	// unavailable, and that is not "no NS" either.
	udpOnly := dnstest.StartUDPOnly(t, map[string]dnstest.Answer{"example.com": {NS: []string{"ns1.example.net"}, Truncate: true}})
	r = platform.LiveNS(context.Background(), "example.com", []string{udpOnly.Addr}, time.Second)
	if r.Kind != platform.NSUnavailable || r.Available() || r.Err == nil {
		t.Errorf("tcp refused = %+v", r)
	}
}
