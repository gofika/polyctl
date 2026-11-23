package cert

import (
	"context"
	"errors"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-acme/lego/v4/challenge/dns01"
	"github.com/miekg/dns"

	"github.com/gofika/polyctl/internal/platform"
)

// txtAnswer is what one resolver said about the TXT records of a name.
type txtAnswer struct {
	// Kind is OK, NXDOMAIN, SERVFAIL, TIMEOUT, UNAVAILABLE or another
	// response code.
	Kind   string
	Values []string
}

func (a txtAnswer) String() string {
	if a.Kind == platform.NSOK {
		if len(a.Values) == 0 {
			return "no TXT record"
		}
		return "[" + strings.Join(a.Values, " ") + "]"
	}
	return a.Kind
}

// TXTLookup asks one resolver for the TXT values of a name.
type TXTLookup func(ctx context.Context, resolver, fqdn string) txtAnswer

// Propagation decides when the challenge records are visible: each of the
// resolvers is asked for the TXT records of the challenge name (never the
// system resolver, whose cache and split horizon mislead), and the record
// counts as propagated when at least Min of them return the expected value
// among the values they return. NXDOMAIN, SERVFAIL and timeouts only mean
// "not yet". Once propagated, SettleDelay is waited before the CA is told
// to validate, for the caches of the CA's own resolvers.
type Propagation struct {
	Ctx          context.Context
	Resolvers    []string // host:port
	Min          int
	QueryTimeout time.Duration
	SettleDelay  time.Duration
	// Sleep waits (tests replace it); nil sleeps for real.
	Sleep func(ctx context.Context, d time.Duration) error
	// Lookup asks one resolver (tests replace it); nil uses DNS.
	Lookup   TXTLookup
	Verbosef func(format string, args ...any)

	mu   sync.Mutex
	last map[string]txtAnswer
	fqdn string
}

// Check is the propagation check given to lego (dns01.WrapPreCheck). The
// default check lego passes in is not used: it would query the zone's
// authoritative servers through the system resolver.
func (p *Propagation) Check(domain, fqdn, value string, _ dns01.PreCheckFunc) (bool, error) {
	ctx := p.Ctx
	if ctx == nil {
		ctx = context.Background()
	}
	// A context that ended stops the wait: lego keeps polling a check that
	// only reports an error until its own propagation timeout, so the check
	// says "done" together with the error.
	if err := ctx.Err(); err != nil {
		return true, err
	}
	answers := p.query(ctx, fqdn)
	seen := 0
	for _, r := range p.Resolvers {
		if a := answers[r]; a.Kind == platform.NSOK && slices.Contains(a.Values, value) {
			seen++
		}
	}
	if p.Verbosef != nil {
		p.Verbosef("propagation of %s TXT %q: %d of %d resolvers see it (%d needed): %s", strings.TrimSuffix(fqdn, "."), value, seen, len(p.Resolvers), p.Min, p.Summary())
	}
	if seen < p.Min {
		return false, nil
	}
	if p.SettleDelay > 0 {
		if p.Verbosef != nil {
			p.Verbosef("waiting %s before the CA validates %s", p.SettleDelay, domain)
		}
		sleep := p.Sleep
		if sleep == nil {
			sleep = sleepCtx
		}
		if err := sleep(ctx, p.SettleDelay); err != nil {
			return true, err
		}
	}
	return true, nil
}

// query asks every resolver at once.
func (p *Propagation) query(ctx context.Context, fqdn string) map[string]txtAnswer {
	lookup := p.Lookup
	if lookup == nil {
		timeout := p.QueryTimeout
		if timeout <= 0 {
			timeout = platform.DefaultNSTimeout
		}
		lookup = func(ctx context.Context, resolver, fqdn string) txtAnswer {
			return queryTXT(ctx, resolver, fqdn, timeout)
		}
	}
	out := make(map[string]txtAnswer, len(p.Resolvers))
	var mu sync.Mutex
	var wg sync.WaitGroup
	for _, r := range p.Resolvers {
		wg.Add(1)
		go func(r string) {
			defer wg.Done()
			a := lookup(ctx, r, fqdn)
			mu.Lock()
			out[r] = a
			mu.Unlock()
		}(r)
	}
	wg.Wait()
	p.mu.Lock()
	p.last, p.fqdn = out, fqdn
	p.mu.Unlock()
	return out
}

// Summary lists what each resolver returned in the last check
// ("1.1.1.1:53=[v1 v2], 8.8.8.8:53=NXDOMAIN"), "" before any check.
func (p *Propagation) Summary() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.last == nil {
		return ""
	}
	var parts []string
	for _, r := range p.Resolvers {
		parts = append(parts, r+"="+p.last[r].String())
	}
	return strings.Join(parts, ", ")
}

// queryTXT asks one resolver for the TXT records of fqdn over UDP, and
// over TCP when the answer is truncated.
func queryTXT(ctx context.Context, addr, fqdn string, timeout time.Duration) txtAnswer {
	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(fqdn), dns.TypeTXT)
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
			return txtAnswer{Kind: platform.NSTimeout}
		}
		return txtAnswer{Kind: platform.NSUnavailable}
	}
	switch r.Rcode {
	case dns.RcodeSuccess:
		var vals []string
		for _, rr := range r.Answer {
			if t, ok := rr.(*dns.TXT); ok {
				vals = append(vals, strings.Join(t.Txt, ""))
			}
		}
		sort.Strings(vals)
		return txtAnswer{Kind: platform.NSOK, Values: vals}
	case dns.RcodeNameError:
		return txtAnswer{Kind: platform.NSNXDomain}
	case dns.RcodeServerFailure:
		return txtAnswer{Kind: platform.NSServFail}
	}
	if s, ok := dns.RcodeToString[r.Rcode]; ok {
		return txtAnswer{Kind: s}
	}
	return txtAnswer{Kind: fmt.Sprintf("RCODE%d", r.Rcode)}
}

// nsWarning compares the nameservers of the hosted zone with the ones
// public resolvers return for root. When both are known and share none,
// it returns the warning that DNS-01 will most likely fail: the TXT
// records would be written to a zone nobody queries. It only warns: right
// after a nameserver change the resolvers may still cache the old ones.
func nsWarning(root string, zoneNS, liveNS []string) string {
	z, l := platform.NormalizeNS(zoneNS), platform.NormalizeNS(liveNS)
	if len(z) == 0 || len(l) == 0 || platform.OverlapNS(z, l) {
		return ""
	}
	return fmt.Sprintf("warning: the nameservers of %s are [%s], not the ones of the hosting account's zone [%s]; DNS-01 validation will most likely fail (see `polyctl domain ns check %s`)",
		root, strings.Join(l, " "), strings.Join(z, " "), root)
}
