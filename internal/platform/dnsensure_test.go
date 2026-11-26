package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// memDNS is an in-memory DNSService recording its writes.
type memDNS struct {
	recs   []Record
	calls  []string
	nextID int
	// patch makes it a RecordPatcher.
	patches []RecordPatch
}

func (m *memDNS) ListZones(ctx context.Context) ([]Zone, error) { return nil, nil }
func (m *memDNS) ListRecords(ctx context.Context, zoneID string) ([]Record, error) {
	return append([]Record(nil), m.recs...), nil
}
func (m *memDNS) CreateRecord(ctx context.Context, zoneID string, r Record) (*Record, error) {
	m.nextID++
	r.ID = fmt.Sprintf("new%d", m.nextID)
	m.calls = append(m.calls, "create:"+r.Name+":"+r.Type+":"+r.Value)
	m.recs = append(m.recs, r)
	return &r, nil
}
func (m *memDNS) UpdateRecord(ctx context.Context, zoneID string, r Record) (*Record, error) {
	m.calls = append(m.calls, "update:"+r.ID+":"+r.Value)
	for i := range m.recs {
		if m.recs[i].ID == r.ID {
			m.recs[i] = r
			return &r, nil
		}
	}
	return nil, ErrNotFound
}
func (m *memDNS) DeleteRecord(ctx context.Context, zoneID, id string) error {
	m.calls = append(m.calls, "delete:"+id)
	for i := range m.recs {
		if m.recs[i].ID == id {
			m.recs = append(m.recs[:i], m.recs[i+1:]...)
			return nil
		}
	}
	return ErrNotFound
}

func (m *memDNS) writes() int { return len(m.calls) }

// patchDNS is memDNS with PATCH semantics.
type patchDNS struct{ memDNS }

func (m *patchDNS) PatchRecord(ctx context.Context, zoneID string, cur Record, p RecordPatch) (*Record, error) {
	m.calls = append(m.calls, "patch:"+cur.ID)
	m.patches = append(m.patches, p)
	for i := range m.recs {
		if m.recs[i].ID == cur.ID {
			if p.Value != nil {
				m.recs[i].Value = *p.Value
			}
			if p.TTL != nil {
				m.recs[i].TTL = *p.TTL
			}
			if p.Proxied != nil {
				m.recs[i].Proxied = p.Proxied
			}
			out := m.recs[i]
			return &out, nil
		}
	}
	return nil, ErrNotFound
}

func specs(t *testing.T, in ...string) []RecordSpec {
	t.Helper()
	var out []RecordSpec
	for _, s := range in {
		r, err := ParseRecordSpec(s)
		if err != nil {
			t.Fatalf("ParseRecordSpec(%q): %v", s, err)
		}
		out = append(out, r)
	}
	return out
}

func bp(b bool) *bool { return &b }
func ip(n int) *int   { return &n }

type ensureRun struct {
	changes []Change
	err     error
}

func ensure(t *testing.T, dns DNSService, p ID, prune, dryRun bool, records ...string) ensureRun {
	t.Helper()
	desired, err := NormalizeRecordSpecs("example.com", p, specs(t, records...), nil, nil)
	if err != nil {
		return ensureRun{err: err}
	}
	existing, _ := dns.ListRecords(context.Background(), "z1")
	plan, err := PlanDNSEnsure(DNSEnsure{Platform: p, ZoneID: "z1", Existing: existing, Desired: desired, PruneDuplicates: prune, DNS: dns})
	if err != nil {
		return ensureRun{err: err}
	}
	ch, err := plan.Run(context.Background(), dryRun)
	return ensureRun{ch, err}
}

func dnsActions(ch []Change) string {
	var s []string
	for _, c := range ch {
		s = append(s, c.Resource+"="+string(c.Action))
	}
	return strings.Join(s, " ")
}

func TestDNSEnsureFourCases(t *testing.T) {
	m := &memDNS{}
	// Fresh: two creates.
	r := ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10", "_dmarc:TXT:v=DMARC1; p=none")
	if r.err != nil || dnsActions(r.changes) != "dns-record/www/A=created dns-record/_dmarc/TXT=created" || m.writes() != 2 {
		t.Fatalf("fresh = %s, %v, calls %v", dnsActions(r.changes), r.err, m.calls)
	}
	if r.changes[1].Detail != `"v=DMARC1; p=none" ttl=auto proxied=false` || r.changes[0].ID != "new1" {
		t.Errorf("created change = %+v", r.changes)
	}
	// Satisfied: nothing written (idempotent second run).
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10", "_dmarc:TXT:v=DMARC1; p=none")
	if r.err != nil || dnsActions(r.changes) != "dns-record/www/A=unchanged dns-record/_dmarc/TXT=unchanged" || m.writes() != 2 {
		t.Fatalf("second run = %s, %v, calls %v", dnsActions(r.changes), r.err, m.calls)
	}
	// Partly missing.
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10", "api:A:203.0.113.11")
	if r.err != nil || dnsActions(r.changes) != "dns-record/www/A=unchanged dns-record/api/A=created" || m.writes() != 3 {
		t.Fatalf("partial = %s, %v", dnsActions(r.changes), r.err)
	}
	// Dry run: nothing written, would_*, pending id.
	r = ensure(t, m, Cloudflare, false, true, "www:A:203.0.113.99", "new:A:203.0.113.12")
	if r.err != nil || dnsActions(r.changes) != "dns-record/www/A=would_update dns-record/new/A=would_create" || m.writes() != 3 {
		t.Fatalf("dry run = %s, %v, calls %v", dnsActions(r.changes), r.err, m.calls)
	}
	if r.changes[1].ID != Pending || r.changes[0].Attrs["changed"] != "value" {
		t.Errorf("dry run changes = %+v", r.changes)
	}
}

func TestDNSEnsureUpdateKeepsID(t *testing.T) {
	m := &memDNS{recs: []Record{{ID: "rec-2", Name: "example.com", Type: "CNAME", Value: "example.org", TTL: 300}}}
	r := ensure(t, m, AWS, false, false, "@:CNAME:example.net.")
	if r.err != nil || dnsActions(r.changes) != "dns-record/@/CNAME=updated" || m.calls[0] != "update:rec-2:example.net" {
		t.Fatalf("update = %s, %v, %v", dnsActions(r.changes), r.err, m.calls)
	}
	c := r.changes[0]
	if c.Attrs["changed"] != "value" || c.Attrs["old_value"] != "example.org" || c.Attrs["new_value"] != "example.net" || c.Detail != "value example.org -> example.net" {
		t.Errorf("change = %+v", c)
	}
	if m.recs[0].TTL != 300 {
		t.Errorf("TTL not kept: %+v", m.recs[0])
	}
}

func TestDNSEnsureNormalizedCompare(t *testing.T) {
	m := &memDNS{recs: []Record{
		{ID: "a", Name: "www.example.com", Type: "CNAME", Value: "example.com"},
		{ID: "b", Name: "v6.example.com", Type: "AAAA", Value: "2001:0db8:0000:0000:0000:0000:0000:0001"},
		{ID: "c", Name: "example.com", Type: "TXT", Value: `"v=spf1 " "-all"`},
		{ID: "d", Name: "example.com", Type: "MX", Value: "mail.example.com.", Priority: ip(10)},
		{ID: "e", Name: "_sip._tcp.example.com", Type: "SRV", Value: "5 5060 sip.example.com.", Priority: ip(10)},
	}}
	r := ensure(t, m, AWS, false, false,
		"www:CNAME:example.com.", "v6:AAAA:2001:db8::1", "@:TXT:v=spf1 -all", "@:MX:10 MAIL.example.com", "_sip._tcp:SRV:10 5 5060 sip.example.com")
	if r.err != nil || m.writes() != 0 {
		t.Fatalf("normalized = %s, %v, %v", dnsActions(r.changes), r.err, m.calls)
	}
	r = ensure(t, m, AWS, false, false, "www:CNAME:Example.COM")
	if r.err != nil || m.writes() != 0 {
		t.Fatalf("case = %s, %v", dnsActions(r.changes), r.err)
	}
}

func TestDNSEnsureTriStateProxiedAndTTL(t *testing.T) {
	m := &patchDNS{memDNS{recs: []Record{
		{ID: "a", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 1, Proxied: bp(true), Extra: map[string]any{"comment": "keep"}},
		{ID: "b", Name: "api.example.com", Type: "A", Value: "203.0.113.11", TTL: 300, Proxied: bp(false)},
	}}}
	// Unspecified proxied and TTL: kept.
	r := ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10", "api:A:203.0.113.11")
	if r.err != nil || m.writes() != 0 {
		t.Fatalf("unspecified = %s, %v", dnsActions(r.changes), r.err)
	}
	// A TTL on a proxied record is not compared.
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10:300")
	if r.err != nil || m.writes() != 0 {
		t.Fatalf("proxied ttl = %s, %v", dnsActions(r.changes), r.err)
	}
	// proxied=false on a proxied record: one PATCH with only that field.
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10::false", "api:A:203.0.113.11:600")
	if r.err != nil || dnsActions(r.changes) != "dns-record/www/A=updated dns-record/api/A=updated" || len(m.patches) != 2 {
		t.Fatalf("updates = %s, %v, %v", dnsActions(r.changes), r.err, m.calls)
	}
	p := m.patches[0]
	if p.Proxied == nil || *p.Proxied || p.Value != nil || p.TTL != nil {
		t.Errorf("patch = %+v", p)
	}
	if p := m.patches[1]; p.TTL == nil || *p.TTL != 600 || p.Value != nil || p.Proxied != nil {
		t.Errorf("patch = %+v", p)
	}
	if r.changes[0].Attrs["changed"] != "proxied" || r.changes[0].Detail != "proxied true -> false" || r.changes[1].Detail != "ttl 300 -> 600" {
		t.Errorf("changes = %+v", r.changes)
	}
	if m.recs[0].Extra["comment"] != "keep" {
		t.Error("comment lost")
	}
}

// ttl=auto is Cloudflare's automatic TTL (1) there and "not given"
// elsewhere; ttl=0 outside Cloudflare would never be found as desired.
func TestDNSEnsureAutoAndZeroTTL(t *testing.T) {
	m := &patchDNS{memDNS{recs: []Record{{ID: "a", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 300, Proxied: bp(false)}}}}
	r := ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10:auto")
	if r.err != nil || len(m.patches) != 1 || m.patches[0].TTL == nil || *m.patches[0].TTL != 1 || r.changes[0].Detail != "ttl 300 -> auto" {
		t.Fatalf("cloudflare auto = %+v, %v, %v", r.changes, r.err, m.calls)
	}
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10:auto")
	if r.err != nil || len(m.patches) != 1 {
		t.Fatalf("cloudflare auto again = %+v, %v", r.changes, r.err)
	}
	fileSpecs, err := ParseRecordFile(strings.NewReader("records:\n  - {name: www, type: A, value: 203.0.113.10, ttl: auto}\n"))
	if err != nil || !fileSpecs[0].TTLAuto || fileSpecs[0].TTL != nil {
		t.Fatalf("file auto = %+v, %v", fileSpecs, err)
	}
	a := &memDNS{recs: []Record{{ID: "a", Name: "www.example.com", Type: "A", Value: "203.0.113.10", TTL: 300}}}
	if r := ensure(t, a, AWS, false, false, "www:A:203.0.113.10:auto"); r.err != nil || a.writes() != 0 {
		t.Fatalf("aws auto = %+v, %v", r.changes, r.err)
	}
	if r := ensure(t, a, AWS, false, false, "www:A:203.0.113.10:0"); !errors.Is(r.err, ErrInvalidInput) || a.writes() != 0 {
		t.Fatalf("aws ttl 0 = %v", r.err)
	}
	if r := ensure(t, &memDNS{}, Cloudflare, false, false, "www:A:203.0.113.10:0"); r.err != nil {
		t.Fatalf("cloudflare ttl 0 = %v", r.err)
	}
}

func TestDNSEnsureURIAndZonedAddress(t *testing.T) {
	m := &memDNS{recs: []Record{{ID: "u", Name: "_http._tcp.example.com", Type: "URI", Value: `1 "https://Example.com/Path"`, Priority: ip(10)}}}
	if r := ensure(t, m, Cloudflare, false, false, "_http._tcp:URI:10 1 https://Example.com/Path"); r.err != nil || m.writes() != 0 {
		t.Fatalf("URI = %+v, %v, %v", r.changes, r.err, m.calls)
	}
	if _, err := NormalizeRecordSpecs("example.com", Cloudflare, []RecordSpec{{Name: "v6", Type: "AAAA", Value: "fe80::1%eth0"}}, nil, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("zoned address = %v", err)
	}
}

func TestDNSEnsureProxiedOnOtherPlatforms(t *testing.T) {
	m := &memDNS{}
	r := ensure(t, m, AWS, false, false, "www:A:203.0.113.10:300:true", "api:A:203.0.113.11::false")
	if r.err != nil || dnsActions(r.changes) != "dns-record/www/A=skipped dns-record/api/A=created" || m.writes() != 1 {
		t.Fatalf("aws proxied = %s, %v, %v", dnsActions(r.changes), r.err, m.calls)
	}
	if !strings.Contains(r.changes[0].Detail, "Cloudflare only") || m.recs[0].Proxied != nil {
		t.Errorf("changes = %+v, recs %+v", r.changes, m.recs)
	}
	// proxied on a type that cannot be proxied is a usage error.
	if _, err := NormalizeRecordSpecs("example.com", Cloudflare, []RecordSpec{{Name: "@", Type: "TXT", Value: "x", Proxied: bp(true)}}, nil, nil); !errors.Is(err, ErrInvalidInput) {
		t.Errorf("TXT proxied = %v", err)
	}
}

func TestDNSEnsureDuplicates(t *testing.T) {
	dup := func() *memDNS {
		return &memDNS{recs: []Record{
			{ID: "r2", Name: "www.example.com", Type: "A", Value: "203.0.113.2", Extra: map[string]any{"created_on": "2024-02-01T00:00:00Z"}},
			{ID: "r9", Name: "www.example.com", Type: "A", Value: "203.0.113.9", Extra: map[string]any{"created_on": "2024-01-01T00:00:00Z"}},
		}}
	}
	// None as desired: ambiguous, nothing written.
	m := dup()
	r := ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.10", "api:A:203.0.113.11")
	if !errors.Is(r.err, ErrAmbiguous) || m.writes() != 0 || !strings.Contains(r.err.Error(), "--prune-duplicates") {
		t.Fatalf("ambiguous = %v, %v", r.err, m.calls)
	}
	// --prune-duplicates: the oldest (r9 by created_on) updated first, then the other deleted.
	m = dup()
	r = ensure(t, m, Cloudflare, true, false, "www:A:203.0.113.10")
	if r.err != nil || strings.Join(m.calls, ",") != "update:r9:203.0.113.10,delete:r2" || dnsActions(r.changes) != "dns-record/www/A=updated dns-record/www/A=deleted" {
		t.Fatalf("prune = %s, %v, %v", dnsActions(r.changes), r.err, m.calls)
	}
	// One of them as desired: unchanged, the other left alone.
	m = dup()
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.2")
	if r.err != nil || m.writes() != 0 || r.changes[0].Action != Unchanged || !strings.Contains(r.changes[0].Detail, "1 other record(s)") || r.changes[0].ID != "r2" {
		t.Fatalf("one satisfied = %+v, %v", r.changes, r.err)
	}
	// ... deleted with --prune-duplicates; in a dry run only reported.
	r = ensure(t, m, Cloudflare, true, true, "www:A:203.0.113.2")
	if r.err != nil || m.writes() != 0 || dnsActions(r.changes) != "dns-record/www/A=unchanged dns-record/www/A=would_delete" || r.changes[1].ID != "r9" {
		t.Fatalf("prune dry run = %+v, %v", r.changes, r.err)
	}

	// One has the desired value but another TTL: that one is updated, not
	// reported as ambiguous, and --prune-duplicates deletes the other.
	ttl := func() *memDNS {
		m := dup()
		for i := range m.recs {
			m.recs[i].TTL = 3600
		}
		return m
	}
	m = ttl()
	r = ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.2:300")
	if r.err != nil || strings.Join(m.calls, ",") != "update:r2:203.0.113.2" || dnsActions(r.changes) != "dns-record/www/A=updated" || !strings.Contains(r.changes[0].Detail, "1 other record(s)") {
		t.Fatalf("value match, other ttl = %+v, %v, %v", r.changes, r.err, m.calls)
	}
	m = ttl()
	r = ensure(t, m, Cloudflare, true, false, "www:A:203.0.113.2:300")
	if r.err != nil || strings.Join(m.calls, ",") != "update:r2:203.0.113.2,delete:r9" {
		t.Fatalf("value match, other ttl, prune = %+v, %v, %v", r.changes, r.err, m.calls)
	}
}

func TestDNSEnsureSetSemantics(t *testing.T) {
	m := &memDNS{recs: []Record{{ID: "mx1", Name: "example.com", Type: "MX", Value: "mx1.example.com", Priority: ip(10)}}}
	r := ensure(t, m, Cloudflare, false, false, "@:MX:10 mx1.example.com", "@:MX:20 mx2.example.com")
	if r.err != nil || dnsActions(r.changes) != "dns-record/@/MX=unchanged dns-record/@/MX=created" || len(m.calls) != 1 || m.calls[0] != "create:example.com:MX:mx2.example.com" {
		t.Fatalf("set = %s, %v, %v", dnsActions(r.changes), r.err, m.calls)
	}
	if p := m.recs[1].Priority; p == nil || *p != 20 {
		t.Errorf("priority = %v", p)
	}
}

func TestDNSEnsureUsageErrors(t *testing.T) {
	for name, in := range map[string][]RecordSpec{
		"two CNAMEs":        {{Name: "www", Type: "CNAME", Value: "a.example.net"}, {Name: "www", Type: "CNAME", Value: "b.example.net"}},
		"CNAME and A":       {{Name: "www", Type: "CNAME", Value: "a.example.net"}, {Name: "www", Type: "A", Value: "203.0.113.1"}},
		"repeated":          {{Name: "www", Type: "A", Value: "203.0.113.1"}, {Name: "www.example.com", Type: "A", Value: "203.0.113.1"}},
		"outside zone":      {{Name: "foo.other-zone.com", Type: "A", Value: "203.0.113.1"}},
		"outside zone dot":  {{Name: "foo.other-zone.com.", Type: "A", Value: "203.0.113.1"}},
		"empty label":       {{Name: "a..b", Type: "A", Value: "203.0.113.1"}},
		"bad host":          {{Name: "www", Type: "CNAME", Value: "a..example.net"}},
		"MX twice priority": {{Name: "@", Type: "MX", Value: "10 mail.example.com", Priority: ip(20)}},
		"SRV short":         {{Name: "_sip._tcp", Type: "SRV", Value: "5 5060 sip.example.com"}},
		"SOA":               {{Name: "@", Type: "SOA", Value: "x"}},
	} {
		if _, err := NormalizeRecordSpecs("example.com", Cloudflare, in, nil, nil); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v, want a usage error", name, err)
		}
	}
	// Relative names with dots stay relative; an unknown last label is not a TLD.
	d, err := NormalizeRecordSpecs("example.com", Cloudflare, []RecordSpec{{Name: "a.b", Type: "A", Value: "203.0.113.1"}, {Name: "*.dev.internal", Type: "A", Value: "203.0.113.2"}, {Name: "WWW.Example.com.", Type: "A", Value: "203.0.113.3"}}, nil, nil)
	if err != nil || d[0].FQDN != "a.b.example.com" || d[0].Name != "a.b" || d[1].Name != "*.dev.internal" || d[2].Name != "www" {
		t.Errorf("names = %+v, %v", d, err)
	}
	// A type the platform cannot write: not supported, checked before any read.
	if _, err := NormalizeRecordSpecs("example.com", Cloudflare, []RecordSpec{{Name: "@", Type: "SPF", Value: "v=spf1 -all"}}, []string{"A", "TXT"}, nil); !errors.Is(err, ErrNotSupported) {
		t.Errorf("SPF = %v", err)
	}
	// An MX record created without a priority is a usage error before any write.
	m := &memDNS{}
	r := ensure(t, m, Cloudflare, false, false, "www:A:203.0.113.1", "@:MX:mail.example.com")
	if !errors.Is(r.err, ErrInvalidInput) || m.writes() != 0 {
		t.Errorf("MX without priority = %v, %v", r.err, m.calls)
	}
	// An existing MX keeps its priority when none is given.
	m = &memDNS{recs: []Record{{ID: "mx", Name: "example.com", Type: "MX", Value: "old.example.com", Priority: ip(5)}}}
	r = ensure(t, m, AWS, false, false, "@:MX:mail.example.com")
	if r.err != nil || m.recs[0].Priority == nil || *m.recs[0].Priority != 5 || m.recs[0].Value != "mail.example.com" {
		t.Errorf("MX update = %v, %+v", r.err, m.recs)
	}
}

func TestDNSEnsureWarnings(t *testing.T) {
	var notes []string
	warn := func(f string, a ...any) { notes = append(notes, fmt.Sprintf(f, a...)) }
	_, err := NormalizeRecordSpecs("example.com", Cloudflare, specs(t, "www:CNAME:lb", "api:A:203.0.113.1:300:true"), nil, warn)
	if err != nil || len(notes) != 2 || !strings.Contains(notes[0], "single label") || !strings.Contains(notes[1], "always auto") {
		t.Errorf("notes = %q, %v", notes, err)
	}
}

// ensureDecided is ensure with a Decide that records the names it is asked
// about and answers replace (or err), and a Restore that names the record.
func ensureDecided(t *testing.T, dns DNSService, p ID, dryRun, replace bool, err error, records ...string) (ensureRun, []OccupiedName) {
	t.Helper()
	desired, nerr := NormalizeRecordSpecs("example.com", p, specs(t, records...), nil, nil)
	if nerr != nil {
		t.Fatalf("normalize: %v", nerr)
	}
	existing, _ := dns.ListRecords(context.Background(), "z1")
	var asked []OccupiedName
	plan, perr := PlanDNSEnsure(DNSEnsure{Platform: p, ZoneID: "z1", Existing: existing, Desired: desired, DNS: dns,
		Decide: func(o OccupiedName) (bool, error) {
			asked = append(asked, o)
			return replace, err
		},
		Restore: func(r Record) string { return "restore " + r.Type + " " + RecordAddValue(r) },
	})
	if perr != nil {
		return ensureRun{err: perr}, asked
	}
	ch, rerr := plan.Run(context.Background(), dryRun)
	return ensureRun{ch, rerr}, asked
}

// The records of other types on a name: the rules of what ensure changes.
func TestDNSEnsureOccupiedNames(t *testing.T) {
	apex := []Record{
		{ID: "soa", Name: "example.com", Type: "SOA", Value: "ns1.example.net. admin.example.com. 1 7200 3600 86400 300"},
		{ID: "ns1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
	}
	txt := Record{ID: "t1", Name: "www.example.com", Type: "TXT", Value: "hello", TTL: 300}
	a := Record{ID: "a1", Name: "www.example.com", Type: "A", Value: "203.0.113.1", TTL: 300}
	mx := Record{ID: "m1", Name: "www.example.com", Type: "MX", Value: "mail.example.com", Priority: ip(10), TTL: 300}

	// a. Only the zone's own records at the apex: created, nothing asked.
	m := &memDNS{recs: append([]Record(nil), apex...)}
	r, asked := ensureDecided(t, m, AWS, false, true, nil, "@:A:203.0.113.9")
	if r.err != nil || len(asked) != 0 || strings.Join(m.calls, ",") != "create:example.com:A:203.0.113.9" {
		t.Errorf("apex beside SOA and NS = %v, asked %d, calls %v", r.err, len(asked), m.calls)
	}

	// c. One record of another type: replaced, the delete before the create.
	m = &memDNS{recs: []Record{a}}
	r, asked = ensureDecided(t, m, AWS, false, true, nil, "www:CNAME:target.example.net")
	if r.err != nil || len(asked) != 1 || !asked[0].Single() || asked[0].CanKeep() || asked[0].What() != "the CNAME record" {
		t.Fatalf("replace = %v, asked %+v", r.err, asked)
	}
	if strings.Join(m.calls, ",") != "delete:a1,create:www.example.com:CNAME:target.example.net" || dnsActions(r.changes) != "dns-record/www/A=deleted dns-record/www/CNAME=created" {
		t.Errorf("replace = %s, calls %v", dnsActions(r.changes), m.calls)
	}
	if c := r.changes[0]; c.ID != "a1" || c.Attrs["value"] != "203.0.113.1" || c.Attrs["ttl"] != "300" || c.Attrs["replaced_by"] != "CNAME" || !strings.Contains(c.Detail, "replaced by the CNAME record") {
		t.Errorf("deleted change = %+v", c)
	}
	// ... a dry run reports both steps and writes nothing.
	m = &memDNS{recs: []Record{txt}}
	r, _ = ensureDecided(t, m, AWS, true, true, nil, "www:A:203.0.113.5")
	if r.err != nil || m.writes() != 0 || dnsActions(r.changes) != "dns-record/www/TXT=would_delete dns-record/www/A=would_create" {
		t.Errorf("replace dry run = %s, %v, calls %v", dnsActions(r.changes), r.err, m.calls)
	}
	// ... a refused decision stops the plan before anything is written.
	stop := errors.New("declined")
	r, _ = ensureDecided(t, m, AWS, false, true, stop, "www:A:203.0.113.5")
	if !errors.Is(r.err, stop) || m.writes() != 0 {
		t.Errorf("declined = %v, calls %v", r.err, m.calls)
	}
	// ... and nobody to decide is a refusal.
	if r := ensure(t, m, AWS, false, false, "www:A:203.0.113.5"); r.err == nil || !strings.Contains(r.err.Error(), "needs a confirmation") || m.writes() != 0 {
		t.Errorf("undecided = %v, calls %v", r.err, m.calls)
	}

	// d. One record of the type among others: that one is updated, the
	// others left alone, nothing asked.
	m = &memDNS{recs: []Record{txt, a}}
	r, asked = ensureDecided(t, m, AWS, false, true, nil, "www:A:203.0.113.7")
	if r.err != nil || len(asked) != 0 || strings.Join(m.calls, ",") != "update:a1:203.0.113.7" {
		t.Errorf("target among others = %v, asked %d, calls %v", r.err, len(asked), m.calls)
	}
	// ... unless the type cannot share the name with them: a choice.
	m = &memDNS{recs: []Record{{ID: "c1", Name: "www.example.com", Type: "CNAME", Value: "old.example.net"}, txt}}
	r, asked = ensureDecided(t, m, AWS, false, true, nil, "www:CNAME:new.example.net")
	if r.err != nil || len(asked) != 1 || asked[0].Single() || asked[0].CanKeep() || strings.Join(m.calls, ",") != "delete:t1,update:c1:new.example.net" {
		t.Errorf("conflicting others = %v, asked %+v, calls %v", r.err, asked, m.calls)
	}

	// e. Several records of other types: a choice. Keeping them writes the
	// desired record beside them.
	m = &memDNS{recs: []Record{txt, mx}}
	r, asked = ensureDecided(t, m, AWS, false, false, nil, "www:A:203.0.113.8")
	if r.err != nil || len(asked) != 1 || asked[0].Single() || !asked[0].CanKeep() || len(asked[0].Others) != 2 || strings.Join(m.calls, ",") != "create:www.example.com:A:203.0.113.8" {
		t.Errorf("keep = %v, asked %+v, calls %v", r.err, asked, m.calls)
	}
	err := asked[0].Ambiguous()
	for _, want := range []string{"www.example.com holds 2 records of other types", `TXT "hello" ttl=300`, "MX 10 mail.example.com ttl=300", "`polyctl dns add`", "`polyctl dns delete`", "nothing was written"} {
		if !errors.Is(err, ErrAmbiguous) || !strings.Contains(err.Error(), want) {
			t.Errorf("ambiguous error %q lacks %q", err, want)
		}
	}
	if r := ensure(t, &memDNS{recs: []Record{txt, mx}}, AWS, false, false, "www:A:203.0.113.8"); !errors.Is(r.err, ErrAmbiguous) {
		t.Errorf("undecided choice = %v", r.err)
	}
	// ... replacing deletes them all first.
	m = &memDNS{recs: []Record{txt, mx}}
	r, _ = ensureDecided(t, m, AWS, false, true, nil, "www:A:203.0.113.8")
	if r.err != nil || strings.Join(m.calls, ",") != "delete:t1,delete:m1,create:www.example.com:A:203.0.113.8" {
		t.Errorf("replace several = %v, calls %v", r.err, m.calls)
	}

	// g. A set of one name and type replaces the record of another type.
	m = &memDNS{recs: []Record{txt}}
	r, asked = ensureDecided(t, m, AWS, false, true, nil, "www:MX:10 mx1.example.com", "www:MX:20 mx2.example.com")
	if r.err != nil || len(asked) != 1 || asked[0].What() != "the MX records" ||
		strings.Join(m.calls, ",") != "delete:t1,create:www.example.com:MX:mx1.example.com,create:www.example.com:MX:mx2.example.com" {
		t.Errorf("set = %v, asked %+v, calls %v", r.err, asked, m.calls)
	}

	// h. Every name is decided before the first write; a duplicates error
	// comes before any question.
	m = &memDNS{recs: []Record{txt, {ID: "o1", Name: "other.example.com", Type: "TXT", Value: "x"}}}
	r, asked = ensureDecided(t, m, AWS, false, true, stop, "api:A:203.0.113.1", "www:A:203.0.113.2", "other:A:203.0.113.3")
	if !errors.Is(r.err, stop) || len(asked) != 1 || m.writes() != 0 {
		t.Errorf("stopped run = %v, asked %d, calls %v", r.err, len(asked), m.calls)
	}
	m = &memDNS{recs: []Record{txt, {ID: "d1", Name: "dup.example.com", Type: "A", Value: "203.0.113.1"}, {ID: "d2", Name: "dup.example.com", Type: "A", Value: "203.0.113.2"}}}
	r, asked = ensureDecided(t, m, AWS, false, true, nil, "www:A:203.0.113.2", "dup:A:203.0.113.3")
	if !errors.Is(r.err, ErrAmbiguous) || len(asked) != 0 || m.writes() != 0 {
		t.Errorf("duplicates first = %v, asked %d", r.err, len(asked))
	}
}

// A write that fails after the records it replaces were deleted says so,
// names them and the command that restores them, and is a general error.
func TestDNSEnsureFailedCreateAfterReplace(t *testing.T) {
	m := &failDNS{memDNS{recs: []Record{{ID: "t1", Name: "b.example.com", Type: "TXT", Value: "hello world", TTL: 300}}}}
	r, _ := ensureDecided(t, m, AWS, false, true, nil, "b:A:203.0.113.2")
	if r.err == nil || dnsActions(r.changes) != "dns-record/b/TXT=deleted dns-record/b/A=failed" {
		t.Fatalf("failure = %s, %v", dnsActions(r.changes), r.err)
	}
	for _, want := range []string{"boom", "the record it replaces was deleted before and is gone", `b.example.com TXT "hello world" ttl=300`, "restore it with: restore TXT hello world"} {
		if !strings.Contains(r.err.Error(), want) {
			t.Errorf("error %q lacks %q", r.err, want)
		}
	}
	if errors.Is(r.err, ErrInvalidInput) || errors.Is(r.err, ErrAmbiguous) {
		t.Errorf("error %v wraps a sentinel", r.err)
	}
}

func TestRecordAddValue(t *testing.T) {
	for _, c := range []struct {
		r    Record
		want string
	}{
		{Record{Type: "MX", Value: "mail.example.com", Priority: ip(10)}, "10 mail.example.com"},
		{Record{Type: "MX", Value: "10 mail.example.com"}, "10 mail.example.com"},
		{Record{Type: "SRV", Value: "5 5060 sip.example.com", Priority: ip(10)}, "10 5 5060 sip.example.com"},
		{Record{Type: "SRV", Value: "sip.example.com", Priority: ip(10), Extra: map[string]any{"weight": 5, "port": 5060}}, "10 5 5060 sip.example.com"},
		{Record{Type: "SRV", Value: "x", Extra: map[string]any{"data": map[string]any{"priority": 1, "weight": 2, "port": 3, "target": "t.example.com"}}}, "1 2 3 t.example.com"},
		{Record{Type: "URI", Value: `1 "https://example.com/"`, Priority: ip(10)}, `10 1 "https://example.com/"`},
		{Record{Type: "TXT", Value: "hello"}, "hello"},
	} {
		if got := RecordAddValue(c.r); got != c.want {
			t.Errorf("RecordAddValue(%+v) = %q, want %q", c.r, got, c.want)
		}
	}
}

func TestDNSEnsureStopsAtFirstFailure(t *testing.T) {
	m := &failDNS{}
	r := ensure(t, m, Cloudflare, false, false, "a:A:203.0.113.1", "b:A:203.0.113.2", "c:A:203.0.113.3")
	if r.err == nil || dnsActions(r.changes) != "dns-record/a/A=created dns-record/b/A=failed" {
		t.Errorf("failure = %s, %v", dnsActions(r.changes), r.err)
	}
}

type failDNS struct{ memDNS }

func (f *failDNS) CreateRecord(ctx context.Context, zoneID string, r Record) (*Record, error) {
	if strings.HasPrefix(r.Name, "b.") {
		return nil, errors.New("boom")
	}
	return f.memDNS.CreateRecord(ctx, zoneID, r)
}

func TestJoinTXT(t *testing.T) {
	for in, want := range map[string]string{
		`hello world`:          "hello world",
		`"hello world"`:        "hello world",
		`"a" "b"`:              "ab",
		`"say \"hi\""`:         `say "hi"`,
		`"\065"`:               "A",
		`"unterminated`:        `"unterminated`,
		`"a" junk`:             `"a" junk`,
		`v=DMARC1; p="reject"`: `v=DMARC1; p="reject"`,
	} {
		if got := JoinTXT(in); got != want {
			t.Errorf("JoinTXT(%q) = %q, want %q", in, got, want)
		}
	}
}
