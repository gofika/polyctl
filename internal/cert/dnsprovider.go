package cert

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// ChallengeLabel is the name of the DNS-01 challenge record, relative to
// the domain being validated.
const ChallengeLabel = "_acme-challenge"

// ChallengeValue is the TXT value of a DNS-01 challenge: the base64url
// (unpadded) SHA-256 of the key authorization. It is computed here rather
// than by the ACME library, which would look the record name up in DNS
// first.
func ChallengeValue(keyAuth string) string {
	sum := sha256.Sum256([]byte(keyAuth))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ChallengeTTL is the TTL of challenge records on a platform: the lowest
// the platform accepts, 60 seconds where that is allowed.
func ChallengeTTL(id platform.ID) int {
	switch id {
	case platform.Aliyun, platform.GoDaddy:
		// Alibaba Cloud DNS (free edition) and GoDaddy refuse TXT TTLs
		// below 600 seconds.
		return 600
	case platform.NameCom:
		return 300
	}
	return 60
}

// DNSProvider writes the TXT records of DNS-01 challenges through the DNS
// account that hosts the zone. It implements the challenge.Provider and
// challenge.ProviderTimeout interfaces of lego.
//
// The certificate of a root domain covers the root and its wildcard: two
// authorizations whose challenge records share one name,
// _acme-challenge.<root>, with different values. The ACME client presents
// both before validating either, so both records must exist at the same
// time: Present creates a record (it never replaces one of the same name),
// and CleanUp deletes exactly the record of its value.
type DNSProvider struct {
	// Ctx bounds every call to the platform.
	Ctx    context.Context
	DNS    platform.DNSService
	ZoneID string
	// Zone is the name of the zone.
	Zone string
	TTL  int
	// PropagationTimeout and PollInterval are what Timeout reports to the
	// ACME client: how long it waits for the records to be seen.
	PropagationTimeout, PollInterval time.Duration
	// SettleDelay is waited after stale challenge records were deleted, so
	// that resolvers drop the old values before the new ones are checked.
	SettleDelay time.Duration
	// Ledger keeps the records written and not deleted yet; the first
	// Present deletes the stale records it lists, and only those (nil:
	// none is deleted).
	Ledger ChallengeLedger
	// Sleep waits (tests replace it); nil sleeps for real.
	Sleep func(ctx context.Context, d time.Duration) error
	// Warnf and Verbosef report progress (nil: silent).
	Warnf, Verbosef func(format string, args ...any)
	// Written and Removed are told about every record written or deleted
	// (to keep the inventory in step); nil: nobody.
	Written func(ctx context.Context, r platform.Record)
	Removed func(ctx context.Context, id string)

	mu      sync.Mutex
	cleaned bool
	added   map[string]string // value -> record id
	// Presented counts the records created.
	Presented int
}

// Present creates the challenge record of one authorization. The first
// call first deletes the _acme-challenge TXT records of the domain an
// earlier run wrote and did not clean up (those of the Ledger), and waits
// SettleDelay when there was any. Other records of the name (another ACME
// client validating the same domain) are kept: the CA needs one matching
// value only. A record that already exists with this value counts as
// created.
func (p *DNSProvider) Present(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx := p.ctx()
	fqdn := challengeFQDN(domain)
	value := ChallengeValue(keyAuth)
	if p.added == nil {
		p.added = map[string]string{}
	}
	if !p.cleaned {
		recs, err := p.DNS.ListRecords(ctx, p.ZoneID)
		if err != nil {
			return fmt.Errorf("list the records of zone %s: %w", p.Zone, err)
		}
		owned := map[string]bool{}
		if p.Ledger != nil {
			mine, err := p.Ledger.Records()
			if err != nil {
				p.warnf("warning: the challenge records of earlier runs are unknown (%v); none is deleted", err)
			}
			for _, r := range mine {
				if r.ZoneID == p.ZoneID {
					owned[r.ID] = true
				}
			}
		}
		deleted, foreign := 0, 0
		for _, r := range recs {
			if !p.isChallenge(r, fqdn) || r.ID == "" {
				continue
			}
			if !owned[r.ID] {
				foreign++
				continue
			}
			delete(owned, r.ID)
			p.verbosef("deleting a stale challenge record %s TXT %q", fqdn, r.Value)
			if err := p.DNS.DeleteRecord(ctx, p.ZoneID, r.ID); err != nil && !isNotFound(err) {
				return fmt.Errorf("delete the stale challenge record %s (%s): %w", fqdn, r.ID, err)
			}
			p.forget(ctx, r.ID)
			deleted++
		}
		// What the ledger lists and the zone no longer holds was deleted
		// by someone else.
		for id := range owned {
			p.forget(ctx, id)
		}
		if foreign > 0 {
			p.warnf("note: kept %d %s TXT record(s) polyctl has no record of writing (another ACME client may be validating the domain)", foreign, fqdn)
		}
		p.cleaned = true
		if deleted > 0 && p.SettleDelay > 0 {
			p.verbosef("deleted %d stale challenge record(s); waiting %s for resolvers to forget them", deleted, p.SettleDelay)
			if err := p.sleep(ctx, p.SettleDelay); err != nil {
				return err
			}
		}
	}
	p.verbosef("creating %s TXT %q (ttl %d)", fqdn, value, p.TTL)
	rec, err := p.DNS.CreateRecord(ctx, p.ZoneID, platform.Record{Name: fqdn, Type: "TXT", Value: value, TTL: p.TTL})
	switch {
	case err == nil:
	case isDuplicate(err):
		p.verbosef("%s TXT %q exists already", fqdn, value)
		rec = nil
		if found, ferr := p.find(ctx, fqdn, value); ferr == nil && found != nil {
			rec = found
		}
	default:
		return fmt.Errorf("create the challenge record %s TXT in zone %s: %w", fqdn, p.Zone, err)
	}
	if rec != nil {
		p.added[value] = rec.ID
		if rec.ID != "" {
			if p.Ledger != nil {
				if err := p.Ledger.Add(ChallengeRecord{ZoneID: p.ZoneID, ID: rec.ID, Value: value}); err != nil {
					p.warnf("warning: the challenge record %s TXT %q is not in the ledger (%v); delete it by hand if this run does not", fqdn, value, err)
				}
			}
			if p.Written != nil {
				p.Written(ctx, *rec)
			}
		}
	} else {
		p.added[value] = ""
	}
	p.Presented++
	return nil
}

// CleanUp deletes the challenge record of one authorization. A record that
// is gone already is fine; any other failure is only a warning (the next
// run's Present deletes what is left).
func (p *DNSProvider) CleanUp(domain, token, keyAuth string) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	ctx := p.ctx()
	fqdn := challengeFQDN(domain)
	value := ChallengeValue(keyAuth)
	id := p.added[value]
	if id == "" {
		r, err := p.find(ctx, fqdn, value)
		if err != nil {
			p.warnf("warning: could not clean up the challenge record %s TXT %q: %v", fqdn, value, err)
			return nil
		}
		if r == nil {
			return nil
		}
		id = r.ID
	}
	p.verbosef("deleting %s TXT %q", fqdn, value)
	if err := p.DNS.DeleteRecord(ctx, p.ZoneID, id); err != nil && !isNotFound(err) {
		p.warnf("warning: could not clean up the challenge record %s TXT %q: %v", fqdn, value, err)
		return nil
	}
	p.forget(ctx, id)
	delete(p.added, value)
	return nil
}

// forget drops a deleted record from the ledger and the inventory.
func (p *DNSProvider) forget(ctx context.Context, id string) {
	if p.Ledger != nil {
		if err := p.Ledger.Remove(p.ZoneID, id); err != nil {
			p.warnf("warning: challenge ledger: %v", err)
		}
	}
	if p.Removed != nil {
		p.Removed(ctx, id)
	}
}

// Timeout tells the ACME client how long to wait for propagation.
func (p *DNSProvider) Timeout() (timeout, interval time.Duration) {
	return p.PropagationTimeout, p.PollInterval
}

func (p *DNSProvider) find(ctx context.Context, fqdn, value string) (*platform.Record, error) {
	recs, err := p.DNS.ListRecords(ctx, p.ZoneID)
	if err != nil {
		return nil, err
	}
	for _, r := range recs {
		if p.isChallenge(r, fqdn) && unquote(r.Value) == value {
			out := r
			return &out, nil
		}
	}
	return nil, nil
}

// isChallenge reports whether r is a TXT record of fqdn. Platforms return
// FQDNs (with or without a trailing dot) or names relative to the zone.
func (p *DNSProvider) isChallenge(r platform.Record, fqdn string) bool {
	if !strings.EqualFold(r.Type, "TXT") {
		return false
	}
	n := platform.NormalizeDomain(r.Name)
	return n == fqdn || platform.FQDN(n, p.Zone) == fqdn
}

func (p *DNSProvider) ctx() context.Context {
	if p.Ctx != nil {
		return p.Ctx
	}
	return context.Background()
}

func (p *DNSProvider) sleep(ctx context.Context, d time.Duration) error {
	if p.Sleep != nil {
		return p.Sleep(ctx, d)
	}
	return sleepCtx(ctx, d)
}

func (p *DNSProvider) warnf(format string, args ...any) {
	if p.Warnf != nil {
		p.Warnf(format, args...)
	}
}

func (p *DNSProvider) verbosef(format string, args ...any) {
	if p.Verbosef != nil {
		p.Verbosef(format, args...)
	}
}

// challengeFQDN is _acme-challenge.<domain> without the trailing dot.
func challengeFQDN(domain string) string {
	return ChallengeLabel + "." + platform.NormalizeDomain(strings.TrimPrefix(domain, "*."))
}

// unquote strips the double quotes some platforms keep around TXT values.
func unquote(v string) string {
	if len(v) >= 2 && v[0] == '"' && v[len(v)-1] == '"' {
		return v[1 : len(v)-1]
	}
	return v
}

// isNotFound reports a record that does not exist (any more).
func isNotFound(err error) bool {
	if errors.Is(err, platform.ErrNotFound) || platform.HasErrorCode(err, "81044", "DomainRecordNotBelongToUser", "InvalidRecordId.NotFound") {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "does not exist") || strings.Contains(msg, "not found")
}

// isDuplicate reports a create refused because the same record exists
// (Cloudflare 81058 "An identical record already exists.", Alibaba Cloud
// DomainRecordDuplicate).
func isDuplicate(err error) bool {
	if platform.HasErrorCode(err, "81058", "DomainRecordDuplicate") {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "already exists") || strings.Contains(msg, "81058") || strings.Contains(msg, "domainrecordduplicate")
}

// sleepCtx waits for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
