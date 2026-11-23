package platform

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/miekg/dns"
	"golang.org/x/net/publicsuffix"
)

// DefaultNSResolvers are the recursive resolvers the live nameserver check
// asks (Cloudflare and Google public DNS). The system resolver is never
// used: a local resolver may be hijacked, filtered or cache a delegation
// for a long time.
var DefaultNSResolvers = []string{"1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4"}

// DefaultNSTimeout is the timeout of one DNS query of the live check.
const DefaultNSTimeout = 5 * time.Second

// Outcomes of a live NS query (LiveNSResult.Kind).
const (
	// NSOK means a resolver answered with NS records.
	NSOK = "OK"
	// NSNXDomain means the name does not exist.
	NSNXDomain = "NXDOMAIN"
	// NSNoData means the name exists but has no NS records (it is not a
	// zone apex).
	NSNoData = "NODATA"
	// NSServFail means the resolvers failed to resolve the name, usually a
	// broken delegation or DNSSEC.
	NSServFail = "SERVFAIL"
	// NSTimeout means no resolver answered in time.
	NSTimeout = "TIMEOUT"
	// NSUnavailable means no resolver could be reached (connection
	// refused, network unreachable, ...).
	NSUnavailable = "UNAVAILABLE"
)

// RegisteredDomain returns the registered domain (eTLD+1 by the Public
// Suffix List) of name: www.example.com -> example.com, example.co.uk ->
// example.co.uk. Private suffixes of the list count (foo.github.io stays
// foo.github.io). A name that has no registered domain (localhost, an IP
// address, a bare public suffix, an empty string) is an error.
func RegisteredDomain(name string) (string, error) {
	d := NormalizeDomain(name)
	if d == "" {
		return "", errors.New("empty domain")
	}
	if net.ParseIP(strings.Trim(d, "[]")) != nil {
		return "", fmt.Errorf("%q is an IP address, not a domain", name)
	}
	reg, err := publicsuffix.EffectiveTLDPlusOne(d)
	if err != nil {
		return "", fmt.Errorf("%q has no registered domain: %v", name, err)
	}
	return reg, nil
}

// ParseResolver validates a resolver address: an IP address (port 53) or
// IP:port ([IPv6]:port). It returns the host:port to send queries to.
func ParseResolver(s string) (string, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", errors.New("empty resolver address")
	}
	if ip := net.ParseIP(s); ip != nil {
		return net.JoinHostPort(ip.String(), "53"), nil
	}
	host, port, err := net.SplitHostPort(s)
	if err != nil || net.ParseIP(host) == nil {
		return "", fmt.Errorf("invalid resolver %q: expected an IP address or IP:port", s)
	}
	if p, err := net.LookupPort("udp", port); err != nil || p <= 0 || p > 65535 {
		return "", fmt.Errorf("invalid resolver %q: bad port %q", s, port)
	}
	return net.JoinHostPort(host, port), nil
}

// NormalizeNS lowercases the nameservers, strips their trailing dots,
// drops empty entries and duplicates, and sorts them, so that two lists
// compare equal whatever their order and spelling.
func NormalizeNS(ns []string) []string {
	out := make([]string, 0, len(ns))
	seen := map[string]bool{}
	for _, n := range ns {
		n = NormalizeDomain(n)
		if n == "" || seen[n] {
			continue
		}
		seen[n] = true
		out = append(out, n)
	}
	sort.Strings(out)
	return out
}

// SameNS reports whether two normalized lists hold the same nameservers.
func SameNS(a, b []string) bool { return slices.Equal(a, b) }

// OverlapNS reports whether two normalized lists share a nameserver.
func OverlapNS(a, b []string) bool {
	for _, x := range a {
		if slices.Contains(b, x) {
			return true
		}
	}
	return false
}

// Provider guesses of GuessProvider.
const (
	GuessCloudflare = "cloudflare"
	GuessAliyun     = "aliyun"
	GuessAWS        = "aws"
	GuessGCP        = "gcp"
	GuessUnknown    = "unknown"
	GuessMixed      = "mixed"
)

// nsVendor recognizes the DNS host of one nameserver: by suffix first, then
// by substring (cloudflare.com's own nameservers are ns3.cloudflare.com,
// without ".ns.").
func nsVendor(ns string) string {
	n := NormalizeDomain(ns)
	suffixes := []struct{ suffix, vendor string }{
		{".ns.cloudflare.com", GuessCloudflare},
		{".foundationdns.com", GuessCloudflare},
		{".foundationdns.net", GuessCloudflare},
		{".foundationdns.org", GuessCloudflare},
		{".alidns.com", GuessAliyun},
		{".hichina.com", GuessAliyun},
		{".googledomains.com", GuessGCP},
	}
	for _, s := range suffixes {
		if strings.HasSuffix(n, s.suffix) {
			return s.vendor
		}
	}
	switch {
	case strings.Contains(n, "cloudflare"), strings.Contains(n, "foundationdns"):
		return GuessCloudflare
	case strings.Contains(n, "alicloud"), strings.Contains(n, "aliyun"), strings.Contains(n, "alidns"):
		return GuessAliyun
	case strings.Contains(n, "awsdns"):
		return GuessAWS
	}
	return ""
}

// GuessProvider names the DNS host the nameservers belong to: cloudflare,
// aliyun, aws or gcp; mixed when they belong to several (the vendors are
// returned as the second value, sorted); unknown when none is recognized.
// It is a hint only: whether a delegation is in place is decided by
// comparing nameserver sets.
func GuessProvider(ns []string) (string, []string) {
	set := map[string]bool{}
	for _, n := range ns {
		if v := nsVendor(n); v != "" {
			set[v] = true
		}
	}
	vendors := make([]string, 0, len(set))
	for v := range set {
		vendors = append(vendors, v)
	}
	sort.Strings(vendors)
	switch len(vendors) {
	case 0:
		return GuessUnknown, nil
	case 1:
		return vendors[0], nil
	}
	return GuessMixed, vendors
}

// LiveNSResult is the answer of LiveNS.
type LiveNSResult struct {
	// Kind is one of NSOK, NSNXDomain, NSNoData, NSServFail, NSTimeout,
	// NSUnavailable, or another RCODE name (REFUSED, ...).
	Kind string
	// Nameservers are the normalized NS of the name (Kind NSOK only).
	Nameservers []string
	// Resolver is the resolver whose answer was used: the one that
	// answered with NS records, else the first one that gave a definite
	// answer.
	Resolver string
	// ZoneApex is the owner of the SOA record of a NODATA answer: the apex
	// of the zone the name lives in.
	ZoneApex string
	// Err is the last transport error when no resolver could be reached.
	Err error
}

// Available reports whether the resolvers told something about the name:
// NS records, or NXDOMAIN, NODATA or SERVFAIL (the name has no usable NS).
// A timeout, an unreachable resolver or another response code (a resolver
// that refuses to answer) says nothing about the name.
func (r LiveNSResult) Available() bool {
	switch r.Kind {
	case NSOK, NSNXDomain, NSNoData, NSServFail:
		return true
	}
	return false
}

// nsAnswer is the outcome of one query to one resolver.
type nsAnswer struct {
	kind string
	ns   []string
	apex string
	err  error
}

// queryNS asks one resolver for the NS records of domain over UDP, and
// again over TCP when the answer is truncated (Exchange does not fall back
// by itself).
func queryNS(ctx context.Context, domain, addr string, timeout time.Duration) nsAnswer {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(domain), dns.TypeNS)
	m.RecursionDesired = true
	c := &dns.Client{Net: "udp", Timeout: timeout}
	exchange := func() (*dns.Msg, error) {
		qctx, cancel := context.WithTimeout(ctx, timeout)
		defer cancel()
		r, _, err := c.ExchangeContext(qctx, m, addr)
		return r, err
	}
	r, err := exchange()
	if err == nil && r.Truncated {
		c.Net = "tcp"
		r, err = exchange()
	}
	if err != nil {
		var ne net.Error
		if (errors.As(err, &ne) && ne.Timeout()) || errors.Is(err, context.DeadlineExceeded) {
			return nsAnswer{kind: NSTimeout, err: err}
		}
		return nsAnswer{kind: NSUnavailable, err: err}
	}
	switch r.Rcode {
	case dns.RcodeNameError:
		return nsAnswer{kind: NSNXDomain}
	case dns.RcodeServerFailure:
		return nsAnswer{kind: NSServFail}
	case dns.RcodeSuccess:
		var ns []string
		for _, rr := range r.Answer {
			if n, ok := rr.(*dns.NS); ok {
				ns = append(ns, n.Ns)
			}
		}
		if len(ns) > 0 {
			return nsAnswer{kind: NSOK, ns: NormalizeNS(ns)}
		}
		a := nsAnswer{kind: NSNoData}
		for _, rr := range r.Ns {
			if soa, ok := rr.(*dns.SOA); ok {
				a.apex = NormalizeDomain(soa.Hdr.Name)
				break
			}
		}
		return a
	}
	if s, ok := dns.RcodeToString[r.Rcode]; ok {
		return nsAnswer{kind: s}
	}
	return nsAnswer{kind: fmt.Sprintf("RCODE%d", r.Rcode)}
}

// LiveNS asks the resolvers, one after the other, for the NS records of
// domain and returns the first answer that has NS records. A resolver that
// times out, fails or answers without NS records is followed by the next.
// When none has NS records, the first NXDOMAIN, NODATA or SERVFAIL answer is
// returned, else the first answer with another response code; when no
// resolver answered at all, Kind is NSTimeout (every failure was a timeout)
// or NSUnavailable. The resolvers must be host:port addresses (see
// ParseResolver).
func LiveNS(ctx context.Context, domain string, resolvers []string, timeout time.Duration) LiveNSResult {
	if timeout <= 0 {
		timeout = DefaultNSTimeout
	}
	var definite, other *LiveNSResult
	allTimeouts := true
	var lastErr error
	for _, addr := range resolvers {
		if err := ctx.Err(); err != nil {
			lastErr = err
			break
		}
		a := queryNS(ctx, domain, addr, timeout)
		switch a.kind {
		case NSOK:
			return LiveNSResult{Kind: NSOK, Nameservers: a.ns, Resolver: addr}
		case NSTimeout, NSUnavailable:
			if a.kind == NSUnavailable {
				allTimeouts = false
			}
			lastErr = a.err
		case NSNXDomain, NSNoData, NSServFail:
			if definite == nil {
				definite = &LiveNSResult{Kind: a.kind, Resolver: addr, ZoneApex: a.apex}
			}
		default:
			if other == nil {
				other = &LiveNSResult{Kind: a.kind, Resolver: addr}
			}
		}
	}
	if definite != nil {
		return *definite
	}
	if other != nil {
		return *other
	}
	kind := NSTimeout
	if !allTimeouts || len(resolvers) == 0 {
		kind = NSUnavailable
	}
	if lastErr == nil && len(resolvers) == 0 {
		lastErr = errors.New("no resolver configured")
	}
	return LiveNSResult{Kind: kind, Err: lastErr}
}
