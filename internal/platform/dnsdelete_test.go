package platform

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
)

// unbindDNS is memDNS with a RecordUnbinder: proxied CNAMEs to r2.dev are
// owned; Unbind removes the record like the platform does.
type unbindDNS struct {
	memDNS
	unbindErr error
	handled   bool
	unbinds   []string
}

func (m *unbindDNS) Match(_ Zone, r Record) (string, bool) {
	if r.Type == "CNAME" && strings.Contains(r.Value, "r2.dev") && r.Proxied != nil && *r.Proxied {
		b, _ := r.Meta["r2_bucket"].(string)
		return "r2 bucket " + b, true
	}
	return "", false
}

func (m *unbindDNS) Unbind(_ context.Context, _ Zone, r Record) (bool, error) {
	m.unbinds = append(m.unbinds, r.ID)
	if m.unbindErr != nil || !m.handled {
		return false, m.unbindErr
	}
	for i := range m.recs {
		if m.recs[i].ID == r.ID {
			m.recs = append(m.recs[:i], m.recs[i+1:]...)
			break
		}
	}
	return true, nil
}

// refuseDNS fails DeleteRecord for one id.
type refuseDNS struct {
	memDNS
	fail string
}

func (m *refuseDNS) DeleteRecord(ctx context.Context, zoneID, id string) error {
	if id == m.fail {
		m.calls = append(m.calls, "delete:"+id)
		return errors.New("refused")
	}
	return m.memDNS.DeleteRecord(ctx, zoneID, id)
}

var testZone = Zone{ID: "z1", Name: "example.com"}

func deleteAll(t *testing.T, dns DNSService, in DNSDeleteAll, dryRun bool) ([]Change, error, []string) {
	t.Helper()
	recs, _ := dns.ListRecords(context.Background(), "z1")
	in.Zone, in.Records, in.DNS = testZone, recs, dns
	if in.Platform == "" {
		in.Platform = Cloudflare
	}
	var removed []string
	in.Removed = func(_ context.Context, id string) { removed = append(removed, id) }
	plan := PlanDNSDeleteAll(in)
	ch, err := plan.Run(context.Background(), dryRun)
	return ch, err, removed
}

func TestDeleteAllNormalRecords(t *testing.T) {
	m := &memDNS{}
	for i := 1; i <= 5; i++ {
		m.recs = append(m.recs, Record{ID: fmt.Sprintf("r%d", i), Name: fmt.Sprintf("h%d.example.com", i), Type: "A", Value: "192.0.2.1", TTL: 300})
	}
	ch, err, removed := deleteAll(t, m, DNSDeleteAll{}, false)
	if err != nil || m.writes() != 5 || len(m.recs) != 0 || len(removed) != 5 {
		t.Fatalf("err=%v writes=%d left=%d removed=%v", err, m.writes(), len(m.recs), removed)
	}
	if ch[0].Resource != "dns-record/h1/A" || ch[0].Action != Deleted || ch[0].ID != "r1" || ch[0].Attrs["value"] != "192.0.2.1" || ch[0].Attrs["ttl"] != "300" {
		t.Errorf("change = %+v", ch[0])
	}
	if s := Summarize(ch); s != (Summary{Deleted: 5}) {
		t.Errorf("summary = %+v", s)
	}
}

func TestDeleteAllSystemRecords(t *testing.T) {
	m := &memDNS{recs: []Record{
		{ID: "ns1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
		{ID: "soa", Name: "example.com", Type: "SOA", Value: "ns1 hostmaster 1 2 3 4 5"},
		{ID: "soa2", Name: "sub.example.com", Type: "soa", Value: "x"},
		{ID: "ns2", Name: "sub.example.com", Type: "NS", Value: "ns.other.net"},
		{ID: "a1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"},
	}}
	ch, err, _ := deleteAll(t, m, DNSDeleteAll{}, false)
	if err != nil || dnsActions(ch) != "dns-record/@/NS=skipped dns-record/@/SOA=skipped dns-record/sub/SOA=skipped dns-record/sub/NS=deleted dns-record/www/A=deleted" {
		t.Fatalf("err=%v %s", err, dnsActions(ch))
	}
	if ch[0].Detail != "system record" || strings.Join(m.calls, ",") != "delete:ns2,delete:a1" {
		t.Errorf("detail %q calls %v", ch[0].Detail, m.calls)
	}

	// --type NS still keeps the apex NS.
	m = &memDNS{recs: []Record{
		{ID: "ns1", Name: "example.com", Type: "NS", Value: "ns1.example.net"},
		{ID: "ns2", Name: "sub.example.com", Type: "NS", Value: "ns.other.net"},
		{ID: "a1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"},
	}}
	ch, err, _ = deleteAll(t, m, DNSDeleteAll{Types: []string{"ns"}}, false)
	if err != nil || dnsActions(ch) != "dns-record/@/NS=skipped dns-record/sub/NS=deleted" || m.writes() != 1 {
		t.Errorf("--type NS: err=%v %s %v", err, dnsActions(ch), m.calls)
	}

	// Only system records: nothing written.
	m = &memDNS{recs: []Record{{ID: "ns1", Name: "example.com", Type: "NS", Value: "x"}, {ID: "s", Name: "example.com", Type: "SOA", Value: "y"}}}
	plan := PlanDNSDeleteAll(DNSDeleteAll{Zone: testZone, Records: m.recs, DNS: m})
	if plan.Deletes() != 0 {
		t.Errorf("deletes = %d", plan.Deletes())
	}
}

func TestDeleteAllTypeFilter(t *testing.T) {
	m := &memDNS{recs: []Record{
		{ID: "t1", Name: "example.com", Type: "TXT", Value: "v=spf1 -all"},
		{ID: "a1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"},
		{ID: "t2", Name: "_acme-challenge.example.com", Type: "txt", Value: "token"},
	}}
	types, err := ParseRecordTypes([]string{"txt"})
	if err != nil {
		t.Fatal(err)
	}
	ch, err, _ := deleteAll(t, m, DNSDeleteAll{Types: types}, false)
	if err != nil || dnsActions(ch) != "dns-record/@/TXT=deleted dns-record/_acme-challenge/TXT=deleted" || len(m.recs) != 1 {
		t.Errorf("err=%v %s", err, dnsActions(ch))
	}
}

func TestParseRecordTypes(t *testing.T) {
	got, err := ParseRecordTypes([]string{"txt,A", " cname ", "TXT"})
	if err != nil || strings.Join(got, ",") != "TXT,A,CNAME" {
		t.Errorf("got %v, %v", got, err)
	}
	for _, bad := range []string{"", "A,", "T-X", "1A", "A B"} {
		if _, err := ParseRecordTypes([]string{bad}); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%q: err = %v", bad, err)
		}
	}
}

func TestDeleteAllDryRun(t *testing.T) {
	m := &unbindDNS{handled: true}
	m.recs = []Record{
		{ID: "a1", Name: "www.example.com", Type: "A", Value: "192.0.2.1"},
		{ID: "c1", Name: "cdn.example.com", Type: "CNAME", Value: "public.r2.dev", Proxied: bp(true), Meta: map[string]any{"r2_bucket": "assets"}},
		{ID: "s", Name: "example.com", Type: "SOA", Value: "x"},
	}
	ch, err, removed := deleteAll(t, m, DNSDeleteAll{}, true)
	if err != nil || dnsActions(ch) != "dns-record/www/A=would_delete dns-record/cdn/CNAME=would_delete dns-record/@/SOA=skipped" || m.writes() != 0 || len(m.unbinds) != 0 || len(removed) != 0 {
		t.Fatalf("err=%v %s calls=%v unbinds=%v", err, dnsActions(ch), m.calls, m.unbinds)
	}
	if ch[1].Detail != "unbind r2 bucket assets then record auto-removed" || ch[1].Attrs["via"] != "unbind:cloudflare" {
		t.Errorf("bound = %+v", ch[1])
	}
	if s := Summarize(ch); s != (Summary{Deleted: 2, Skipped: 1}) {
		t.Errorf("summary = %+v", s)
	}
}

func TestDeleteAllUnbind(t *testing.T) {
	r2 := Record{ID: "c1", Name: "cdn.example.com", Type: "CNAME", Value: "public.r2.dev", Proxied: bp(true), Meta: map[string]any{"r2_bucket": "assets"}}
	plain := Record{ID: "c2", Name: "files.example.com", Type: "CNAME", Value: "public.r2.dev", Proxied: bp(false)}

	// Owned: unbound, never deleted through the DNS API.
	m := &unbindDNS{handled: true}
	m.recs = []Record{r2, plain}
	ch, err, removed := deleteAll(t, m, DNSDeleteAll{}, false)
	if err != nil || strings.Join(m.unbinds, ",") != "c1" || strings.Join(m.calls, ",") != "delete:c2" || len(removed) != 2 {
		t.Fatalf("err=%v unbinds=%v calls=%v removed=%v", err, m.unbinds, m.calls, removed)
	}
	if ch[0].Action != Deleted || !strings.Contains(ch[0].Detail, "unbound r2 bucket assets") {
		t.Errorf("change = %+v", ch[0])
	}

	// Unbinding fails: the record is left in place and reported failed,
	// the others go on; no DeleteRecord for it.
	for _, tc := range []struct {
		name string
		m    *unbindDNS
	}{
		{"error", &unbindDNS{unbindErr: fmt.Errorf("%w: no R2 permission", ErrForbidden)}},
		{"not handled", &unbindDNS{}},
	} {
		tc.m.recs = []Record{r2, plain}
		ch, err, removed = deleteAll(t, tc.m, DNSDeleteAll{}, false)
		var pe *PartialError
		if !errors.As(err, &pe) || pe.Failed != 1 || dnsActions(ch) != "dns-record/cdn/CNAME=failed dns-record/files/CNAME=deleted" ||
			strings.Join(tc.m.calls, ",") != "delete:c2" || len(tc.m.unbinds) != 1 || strings.Join(removed, ",") != "c2" {
			t.Errorf("%s: err=%v %s calls=%v", tc.name, err, dnsActions(ch), tc.m.calls)
		}
		if s := Summarize(ch); s != (Summary{Deleted: 1, Failed: 1}) {
			t.Errorf("%s: summary = %+v", tc.name, s)
		}
	}

	// --keep-bound: skipped, the rest deleted.
	m = &unbindDNS{handled: true}
	m.recs = []Record{r2, plain}
	ch, err, _ = deleteAll(t, m, DNSDeleteAll{KeepBound: true}, false)
	if err != nil || dnsActions(ch) != "dns-record/cdn/CNAME=skipped dns-record/files/CNAME=deleted" || len(m.unbinds) != 0 || ch[0].Detail != "--keep-bound: owned by r2 bucket assets" {
		t.Errorf("keep-bound: err=%v %s %+v", err, dnsActions(ch), ch[0])
	}
}

func TestDeleteAllFailuresGoOn(t *testing.T) {
	m := &refuseDNS{fail: "a2"}
	m.recs = []Record{
		{ID: "a1", Name: "a.example.com", Type: "A", Value: "192.0.2.1"},
		{ID: "a2", Name: "b.example.com", Type: "A", Value: "192.0.2.2"},
		{ID: "", Name: "c.example.com", Type: "A", Value: "192.0.2.3"},
		{ID: "a4", Name: "d.example.com", Type: "A", Value: "192.0.2.4"},
	}
	ch, err, removed := deleteAll(t, m, DNSDeleteAll{}, false)
	var pe *PartialError
	if !errors.As(err, &pe) || pe.Failed != 1 || dnsActions(ch) != "dns-record/a/A=deleted dns-record/b/A=failed dns-record/c/A=failed dns-record/d/A=deleted" {
		t.Fatalf("err=%v %s", err, dnsActions(ch))
	}
	if ch[2].Detail != "the record has no id" || strings.Join(removed, ",") != "a1,a4" || len(m.recs) != 2 {
		t.Errorf("no-id %+v removed %v left %v", ch[2], removed, m.recs)
	}
	if s := Summarize(ch); s != (Summary{Deleted: 2, Failed: 2}) {
		t.Errorf("summary = %+v", s)
	}
	if fe := FailedChanges(ch); fe == nil || !strings.Contains(fe.Error(), "2 of 4") {
		t.Errorf("FailedChanges = %v", fe)
	}
	if FailedChanges(ch[:1]) != nil {
		t.Error("FailedChanges of a clean report")
	}
}

type sysDNS struct{ memDNS }

func (sysDNS) SystemRecord(_ Zone, r Record) (string, bool) {
	if r.Extra["locked"] == true {
		return "locked by the platform", true
	}
	return "", false
}

func TestDeleteAllProviderSystemRecords(t *testing.T) {
	m := &sysDNS{}
	m.recs = []Record{{ID: "l", Name: "x.example.com", Type: "A", Value: "1.2.3.4", Extra: map[string]any{"locked": true}}, {ID: "a", Name: "y.example.com", Type: "A", Value: "1.2.3.5"}}
	ch, err, _ := deleteAll(t, m, DNSDeleteAll{}, false)
	if err != nil || dnsActions(ch) != "dns-record/x/A=skipped dns-record/y/A=deleted" || ch[0].Detail != "locked by the platform" {
		t.Errorf("err=%v %s %+v", err, dnsActions(ch), ch[0])
	}
}

func TestTypeCounts(t *testing.T) {
	items := []DeleteAllItem{{Record: Record{Type: "TXT"}}, {Record: Record{Type: "A"}}, {Record: Record{Type: "cname"}}, {Record: Record{Type: "A"}}}
	got := TypeCounts(items, func(typ string) string {
		if typ == "CNAME" {
			return "1 unbound first"
		}
		return ""
	})
	if got != "A 2, CNAME 1 (1 unbound first), TXT 1" {
		t.Errorf("got %q", got)
	}
}
