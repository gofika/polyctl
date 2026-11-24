package godaddy

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestRecordIDRoundTrip(t *testing.T) {
	cases := []struct{ typ, name, data string }{
		{"A", "@", "1.2.3.4"},
		{"a", "www", "1.2.3.4"},
		{"TXT", "@", "v=spf1 include:_spf.example.com ~all"},
		{"TXT", "_dmarc", `v=DMARC1; p=none; rua=mailto:a@b.c`},
		{"CNAME", "*", "target.example.net"},
		{"TXT", "weird", "pipe|inside|data"},
		{"TXT", "pct", "100% sure"},
	}
	for _, c := range cases {
		id := recordID("Example.com", apiRecord{Type: c.typ, Name: c.name, Data: c.data})
		if strings.Count(id, "|") != 3 {
			t.Errorf("%q: id %q must contain exactly three separators", c.data, id)
		}
		if strings.ContainsAny(id, " \t\n\"'") {
			t.Errorf("id %q contains unsafe characters", id)
		}
		k, err := decodeRecordID(id, "example.com")
		if err != nil {
			t.Fatalf("decode %q: %v", id, err)
		}
		if k.Zone != "example.com" || k.Type != strings.ToUpper(c.typ) || k.Name != c.name || k.Data != c.data || k.Ext != nil {
			t.Errorf("round trip of %+v gave %+v (id %q)", c, k, id)
		}
	}
	if got := recordID("example.com", apiRecord{Type: "A", Data: "1.1.1.1"}); got != "example.com|A|@|1.1.1.1" {
		t.Errorf("empty name should become @, got %q", got)
	}
	mx := recordID("example.com", apiRecord{Type: "MX", Name: "@", Data: "mail.example.com", Priority: intp(10)})
	if mx != "example.com|MX|@|mail.example.com|10" {
		t.Errorf("MX id: %q", mx)
	}
	srv := apiRecord{Type: "SRV", Name: "@", Data: "sip.example.com", Service: "_sip", Protocol: "_udp", Port: intp(5060), Weight: intp(20), Priority: intp(5)}
	id := recordID("example.com", srv)
	if id != "example.com|SRV|@|sip.example.com|_sip|_udp|5060|20|5" {
		t.Errorf("SRV id: %q", id)
	}
	k, err := decodeRecordID(id, "")
	if err != nil || !slices.Equal(k.Ext, []string{"_sip", "_udp", "5060", "20", "5"}) || !k.matches(srv) {
		t.Errorf("SRV decode: %+v %v", k, err)
	}
}

func TestDecodeRecordIDZone(t *testing.T) {
	if _, err := decodeRecordID("b.com|A|@|1.1.1.1", "a.com"); !errors.Is(err, platform.ErrInvalidInput) || !strings.Contains(err.Error(), "belongs to zone b.com") {
		t.Errorf("id of another zone: %v", err)
	}
	// An older id carries no zone and fits any.
	if k, err := decodeRecordID("A|@|1.1.1.1", "a.com"); err != nil || k.Zone != "" || k.Data != "1.1.1.1" {
		t.Errorf("older id: %+v %v", k, err)
	}
	r := platform.Record{ID: "a.com|SRV|@|sip|_sip|_udp|5060|0|0", ZoneID: "a.com"}
	for id, want := range map[string]bool{
		r.ID:                                 true,
		"SRV|@|sip":                          true,
		"a.com|SRV|@|sip":                    true,
		"a.com|SRV|@|sip|_sip|_tcp|5060|0|0": false,
		"b.com|SRV|@|sip|_sip|_udp|5060|0|0": false,
		"A|@|sip":                            false,
	} {
		if got := sameRecord(id, r); got != want {
			t.Errorf("sameRecord(%q) = %v, want %v", id, got, want)
		}
	}
}

func TestDecodeRecordIDErrors(t *testing.T) {
	for _, bad := range []string{"", "A", "A|www", "|www|data", "A||data", "A|%zz|data", "|A|www|data",
		"x.com|A|www|data|extra", "x.com|MX|@|mail|1|2", "x.com|MX|@|mail|ten", "x.com|SRV|@|sip|_sip|_tcp|5060", "x.com|SRV|@|sip|_sip|_tcp|port|0|0"} {
		if _, err := decodeRecordID(bad, ""); !errors.Is(err, ErrBadRecordID) {
			t.Errorf("%q: expected ErrBadRecordID, got %v", bad, err)
		}
	}
}

// sipRecords are two SRV records of the apex that differ only in their
// protocol; GoDaddy keeps both in the SRV/@ set.
func sipRecords() []apiRecord {
	return []apiRecord{
		{Type: "SRV", Name: "@", Data: "sip.example.com", TTL: 600, Service: "_sip", Protocol: "_tcp", Port: intp(5060), Weight: intp(0), Priority: intp(0)},
		{Type: "SRV", Name: "@", Data: "sip.example.com", TTL: 600, Service: "_sip", Protocol: "_udp", Port: intp(5060), Weight: intp(0), Priority: intp(0)},
	}
}

func TestSRVRecordsWithTheSameTargetGetTheirOwnIDs(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com")
	f.setRecords("example.com", sipRecords()...)
	ctx := context.Background()
	recs, err := c.ListRecords(ctx, "example.com")
	if err != nil || len(recs) != 2 {
		t.Fatalf("list: %v %+v", err, recs)
	}
	if recs[0].ID == recs[1].ID {
		t.Fatalf("both SRV records got id %q", recs[0].ID)
	}
	var udp platform.Record
	for _, r := range recs {
		if r.Name == "_sip._udp.example.com" {
			udp = r
		}
	}
	if err := c.DeleteRecord(ctx, "example.com", udp.ID); err != nil {
		t.Fatal(err)
	}
	got := f.getRecords("example.com")
	if len(got) != 1 || got[0].Protocol != "_tcp" {
		t.Fatalf("deleting _sip._udp must keep _sip._tcp: %+v", got)
	}

	// Update: change the port of _sip._udp, _sip._tcp stays as it was.
	f.setRecords("example.com", sipRecords()...)
	udp.Extra = map[string]any{"service": "_sip", "protocol": "_udp", "port": 5061, "weight": 0}
	if _, err := c.UpdateRecord(ctx, "example.com", udp); err != nil {
		t.Fatal(err)
	}
	got = f.getRecords("example.com")
	ports := map[string]int{}
	for _, r := range got {
		ports[r.Protocol] = *r.Port
	}
	if len(got) != 2 || ports["_tcp"] != 5060 || ports["_udp"] != 5061 {
		t.Fatalf("updating _sip._udp must leave _sip._tcp alone: %+v", got)
	}
}

func TestOldRecordIDMatchingSeveralRecordsIsAmbiguous(t *testing.T) {
	f, c := newTestClient(t)
	f.addDomain("example.com")
	f.setRecords("example.com", sipRecords()...)
	ctx := context.Background()
	err := c.DeleteRecord(ctx, "example.com", "SRV|@|sip.example.com")
	if !errors.Is(err, platform.ErrAmbiguous) || !strings.Contains(err.Error(), "example.com|SRV|@|sip.example.com|_sip|_udp|5060|0|0") {
		t.Fatalf("old SRV id: %v", err)
	}
	if _, err := c.UpdateRecord(ctx, "example.com", platform.Record{ID: "SRV|@|sip.example.com", Name: "_sip._udp.example.com", Type: "SRV", Value: "x.example.com", Extra: map[string]any{"port": 1}}); !errors.Is(err, platform.ErrAmbiguous) {
		t.Fatalf("old SRV id on update: %v", err)
	}
	if got := f.getRecords("example.com"); len(got) != 2 || got[0].Data != "sip.example.com" || got[1].Data != "sip.example.com" {
		t.Fatalf("an ambiguous id must not change anything: %+v", got)
	}
	// An old id that names one record still works.
	f.setRecords("example.com", apiRecord{Type: "MX", Name: "@", Data: "mail.example.com", Priority: intp(10)})
	if err := c.DeleteRecord(ctx, "example.com", "MX|@|mail.example.com"); err != nil || len(f.getRecords("example.com")) != 0 {
		t.Fatalf("old MX id: %v %+v", err, f.getRecords("example.com"))
	}
}
