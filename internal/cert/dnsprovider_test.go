package cert

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/dnstest"
	"github.com/gofika/polyctl/internal/platform"
)

// fakeDNS is an in-memory DNSService that records the writes.
type fakeDNS struct {
	mu      sync.Mutex
	zones   []platform.Zone
	records []platform.Record
	nextID  int
	writes  []string
	// dupErr makes a create of an identical record fail like Cloudflare.
	dupErr bool
	// createErr and deleteErr fail every create / delete.
	createErr, deleteErr error
	// relativeNames returns record names relative to the zone.
	relativeNames bool
}

func (f *fakeDNS) ListZones(ctx context.Context) ([]platform.Zone, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return slices.Clone(f.zones), nil
}

func (f *fakeDNS) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := slices.Clone(f.records)
	if f.relativeNames {
		for i := range out {
			out[i].Name = platform.RelativeName(out[i].Name, "example.com")
		}
	}
	return out, nil
}

func (f *fakeDNS) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.createErr != nil {
		return nil, f.createErr
	}
	for _, x := range f.records {
		if f.dupErr && x.Name == r.Name && x.Type == r.Type && x.Value == r.Value {
			return nil, errors.New("cloudflare: An identical record already exists. (81058)")
		}
	}
	f.nextID++
	r.ID = fmt.Sprintf("r%d", f.nextID)
	r.ZoneID = zoneID
	f.records = append(f.records, r)
	f.writes = append(f.writes, "create:"+r.Value)
	out := r
	return &out, nil
}

func (f *fakeDNS) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	return nil, errors.New("not used")
}

func (f *fakeDNS) DeleteRecord(ctx context.Context, zoneID, id string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.writes = append(f.writes, "delete:"+id)
	if f.deleteErr != nil {
		return f.deleteErr
	}
	for i, x := range f.records {
		if x.ID == id {
			f.records = append(f.records[:i:i], f.records[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("%w: record %s", platform.ErrNotFound, id)
}

func (f *fakeDNS) values(name string) []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []string
	for _, r := range f.records {
		if r.Name == name && r.Type == "TXT" {
			out = append(out, r.Value)
		}
	}
	return out
}

type sleeps struct {
	mu  sync.Mutex
	got []time.Duration
}

func (s *sleeps) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.got = append(s.got, d)
	s.mu.Unlock()
	return nil
}

func newProvider(f *fakeDNS, sl *sleeps) *DNSProvider {
	return &DNSProvider{DNS: f, ZoneID: "z1", Zone: "example.com", TTL: 60, SettleDelay: 20 * time.Second, Sleep: sl.sleep}
}

const challengeName = "_acme-challenge.example.com"

func TestPresentKeepsBothValuesAndCleansUpOne(t *testing.T) {
	f := &fakeDNS{}
	sl := &sleeps{}
	p := newProvider(f, sl)
	if err := p.Present("example.com", "t1", "ka1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Present("example.com", "t2", "ka2"); err != nil {
		t.Fatal(err)
	}
	v1, v2 := ChallengeValue("ka1"), ChallengeValue("ka2")
	if got := f.values(challengeName); !slices.Equal(got, []string{v1, v2}) {
		t.Fatalf("records = %v", got)
	}
	if len(sl.got) != 0 {
		t.Errorf("slept without stale records: %v", sl.got)
	}
	if f.records[0].TTL != 60 {
		t.Errorf("ttl = %d", f.records[0].TTL)
	}
	if err := p.CleanUp("example.com", "t1", "ka1"); err != nil {
		t.Fatal(err)
	}
	if got := f.values(challengeName); !slices.Equal(got, []string{v2}) {
		t.Fatalf("after cleanup = %v", got)
	}
	if err := p.CleanUp("example.com", "t2", "ka2"); err != nil || len(f.values(challengeName)) != 0 {
		t.Fatalf("second cleanup: %v %v", err, f.records)
	}
	// Cleaning up a record that is gone is fine.
	if err := p.CleanUp("example.com", "t2", "ka2"); err != nil {
		t.Fatal(err)
	}
}

func TestPresentDeletesStaleRecordsFirst(t *testing.T) {
	f := &fakeDNS{relativeNames: true}
	// More stale records than one page of most APIs, and records of other
	// names that must stay.
	for i := range 150 {
		f.records = append(f.records, platform.Record{ID: fmt.Sprintf("old%d", i), Name: challengeName, Type: "TXT", Value: fmt.Sprintf("stale-%d", i)})
	}
	f.records = append(f.records,
		platform.Record{ID: "keep1", Name: "_acme-challenge.www.example.com", Type: "TXT", Value: "other"},
		platform.Record{ID: "keep2", Name: "example.com", Type: "TXT", Value: "v=spf1 -all"})
	sl := &sleeps{}
	p := newProvider(f, sl)
	if err := p.Present("example.com", "t1", "ka1"); err != nil {
		t.Fatal(err)
	}
	if err := p.Present("example.com", "t2", "ka2"); err != nil {
		t.Fatal(err)
	}
	if got := f.values(challengeName); len(got) != 2 {
		t.Fatalf("records = %v", got)
	}
	if len(f.records) != 4 {
		t.Errorf("other records touched: %v", f.records)
	}
	if !slices.Equal(sl.got, []time.Duration{20 * time.Second}) {
		t.Errorf("sleeps = %v", sl.got)
	}
}

func TestPresentDuplicateIsIdempotent(t *testing.T) {
	f := &fakeDNS{dupErr: true}
	p := newProvider(f, &sleeps{})
	p.cleaned = true // the record of this run exists already
	v := ChallengeValue("ka1")
	f.records = []platform.Record{{ID: "r9", Name: challengeName, Type: "TXT", Value: v}}
	if err := p.Present("example.com", "t1", "ka1"); err != nil {
		t.Fatalf("duplicate create: %v", err)
	}
	if p.added[v] != "r9" {
		t.Errorf("id of the existing record not found: %v", p.added)
	}
	if err := p.CleanUp("example.com", "t1", "ka1"); err != nil || len(f.records) != 0 {
		t.Fatalf("cleanup: %v %v", err, f.records)
	}
}

func TestPresentErrorsAndCleanUpWarnings(t *testing.T) {
	f := &fakeDNS{createErr: fmt.Errorf("%w: bad token", platform.ErrUnauthorized)}
	p := newProvider(f, &sleeps{})
	if err := p.Present("example.com", "t", "ka"); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("err = %v", err)
	}
	f2 := &fakeDNS{}
	var warns []string
	p2 := newProvider(f2, &sleeps{})
	p2.Warnf = func(format string, a ...any) { warns = append(warns, fmt.Sprintf(format, a...)) }
	if err := p2.Present("example.com", "t", "ka"); err != nil {
		t.Fatal(err)
	}
	f2.deleteErr = errors.New("platform down")
	if err := p2.CleanUp("example.com", "t", "ka"); err != nil || len(warns) != 1 {
		t.Fatalf("cleanup failure must warn only: %v %v", err, warns)
	}
}

func TestPropagation(t *testing.T) {
	want := "expected"
	answers := map[string]txtAnswer{
		"r1": {Kind: platform.NSOK, Values: []string{"other", want}},
		"r2": {Kind: platform.NSNXDomain},
		"r3": {Kind: platform.NSTimeout},
		"r4": {Kind: platform.NSOK, Values: []string{"other"}},
	}
	sl := &sleeps{}
	p := &Propagation{Resolvers: []string{"r1", "r2", "r3", "r4"}, Min: 2, SettleDelay: 20 * time.Second, Sleep: sl.sleep,
		Lookup: func(ctx context.Context, r, fqdn string) txtAnswer { return answers[r] }}
	ok, err := p.Check("example.com", challengeName+".", want, nil)
	if err != nil || ok {
		t.Fatalf("one resolver must not be enough: %v %v", ok, err)
	}
	if s := p.Summary(); s != "r1=[other expected], r2=NXDOMAIN, r3=TIMEOUT, r4=[other]" {
		t.Errorf("summary = %q", s)
	}
	if len(sl.got) != 0 {
		t.Error("settled before propagation")
	}
	answers["r4"] = txtAnswer{Kind: platform.NSOK, Values: []string{want}}
	ok, err = p.Check("example.com", challengeName+".", want, nil)
	if err != nil || !ok || !slices.Equal(sl.got, []time.Duration{20 * time.Second}) {
		t.Fatalf("two resolvers: %v %v %v", ok, err, sl.got)
	}
}

func TestPropagationOverDNS(t *testing.T) {
	a := dnstest.Start(t, map[string]dnstest.Answer{challengeName: {TXT: []string{"v1", "v2"}}})
	b := dnstest.Start(t, nil) // NXDOMAIN
	p := &Propagation{Resolvers: []string{a.Addr, b.Addr}, Min: 1, QueryTimeout: time.Second}
	ok, err := p.Check("example.com", challengeName+".", "v2", nil)
	if err != nil || !ok {
		t.Fatalf("check = %v %v (%s)", ok, err, p.Summary())
	}
	if s := p.Summary(); !strings.Contains(s, a.Addr+"=[v1 v2]") || !strings.Contains(s, b.Addr+"=NXDOMAIN") {
		t.Errorf("summary = %q", s)
	}
	silent := dnstest.Silent(t)
	p = &Propagation{Resolvers: []string{silent}, Min: 1, QueryTimeout: 50 * time.Millisecond}
	if ok, err := p.Check("example.com", challengeName+".", "v2", nil); ok || err != nil || !strings.Contains(p.Summary(), "TIMEOUT") {
		t.Fatalf("timeout = %v %v %s", ok, err, p.Summary())
	}
}

func TestNSWarning(t *testing.T) {
	if w := nsWarning("example.com", []string{"a.ns.cloudflare.com"}, []string{"ns1.alidns.com."}); !strings.Contains(w, "most likely fail") {
		t.Errorf("warning = %q", w)
	}
	for _, c := range [][2][]string{
		{{"a.ns.cloudflare.com"}, {"A.NS.CLOUDFLARE.COM.", "b.ns.cloudflare.com"}},
		{nil, {"x"}},
		{{"x"}, nil},
	} {
		if w := nsWarning("example.com", c[0], c[1]); w != "" {
			t.Errorf("%v: %q", c, w)
		}
	}
}

func TestChallengeTTL(t *testing.T) {
	if ChallengeTTL(platform.Cloudflare) != 60 || ChallengeTTL(platform.Aliyun) != 600 {
		t.Error("ttl")
	}
}
