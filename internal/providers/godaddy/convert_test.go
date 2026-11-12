package godaddy

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func intp(i int) *int { return &i }

func TestRecordFromAPI(t *testing.T) {
	zone := "Example.COM"
	a := recordFromAPI(zone, apiRecord{Type: "A", Name: "@", Data: "1.2.3.4", TTL: 600})
	if a.Name != "example.com" || a.ZoneID != "example.com" || a.ID != "A|@|1.2.3.4" || a.Priority != nil {
		t.Errorf("apex A: %+v", a)
	}
	c := recordFromAPI(zone, apiRecord{Type: "cname", Name: "www", Data: "example.com", TTL: 3600})
	if c.Name != "www.example.com" || c.Type != "CNAME" || c.Value != "example.com" || c.ID != "CNAME|www|example.com" {
		t.Errorf("www CNAME: %+v", c)
	}
	mx := recordFromAPI(zone, apiRecord{Type: "MX", Name: "@", Data: "mail.example.com", TTL: 3600, Priority: intp(10)})
	if mx.Priority == nil || *mx.Priority != 10 || mx.Value != "mail.example.com" {
		t.Errorf("MX priority must move to Priority: %+v", mx)
	}
	// A records can carry priority:0 in GoDaddy's output; it must not leak.
	a2 := recordFromAPI(zone, apiRecord{Type: "A", Name: "x", Data: "1.1.1.1", Priority: intp(0)})
	if a2.Priority != nil {
		t.Errorf("A record must not expose a priority: %+v", a2)
	}
	srv := recordFromAPI(zone, apiRecord{Type: "SRV", Name: "@", Data: "sip.example.com", TTL: 600, Priority: intp(5), Port: intp(5060), Weight: intp(20), Service: "_sip", Protocol: "_tcp"})
	if srv.Name != "_sip._tcp.example.com" || srv.Value != "sip.example.com" || srv.ID != "SRV|@|sip.example.com" {
		t.Errorf("SRV: %+v", srv)
	}
	if srv.Extra["port"] != 5060 || srv.Extra["weight"] != 20 || srv.Extra["service"] != "_sip" {
		t.Errorf("SRV extra: %+v", srv.Extra)
	}
	srv2 := recordFromAPI(zone, apiRecord{Type: "SRV", Name: "host", Data: "x", Service: "_xmpp", Protocol: "_udp"})
	if srv2.Name != "_xmpp._udp.host.example.com" {
		t.Errorf("SRV owner: %q", srv2.Name)
	}
}

func TestRecordToAPI(t *testing.T) {
	zone := "example.com"
	r, err := recordToAPI(zone, platform.Record{Name: "www.example.com", Type: "a", Value: "1.2.3.4", TTL: 600})
	if err != nil || r.Type != "A" || r.Name != "www" || r.Data != "1.2.3.4" || r.TTL != 600 || r.Priority != nil {
		t.Errorf("www A: %+v %v", r, err)
	}
	r, err = recordToAPI(zone, platform.Record{Name: "example.com", Type: "TXT", Value: "hello world"})
	if err != nil || r.Name != "@" {
		t.Errorf("apex: %+v %v", r, err)
	}
	r, err = recordToAPI(zone, platform.Record{Name: "example.com.", Type: "MX", Value: "mail.example.com", Priority: intp(20)})
	if err != nil || r.Name != "@" || r.Priority == nil || *r.Priority != 20 {
		t.Errorf("MX: %+v %v", r, err)
	}
	r, err = recordToAPI(zone, platform.Record{Name: "example.com", Type: "MX", Value: "mail.example.com"})
	if err != nil || r.Priority == nil || *r.Priority != 0 {
		t.Errorf("MX default priority: %+v %v", r, err)
	}
	if _, err := recordToAPI(zone, platform.Record{Name: "x.example.com", Type: "", Value: "1"}); err == nil {
		t.Error("missing type must fail")
	}
	if _, err := recordToAPI(zone, platform.Record{Name: "x.example.com", Type: "A", Value: ""}); err == nil {
		t.Error("missing content must fail")
	}
	// SRV with extras that went through JSON (numbers become float64).
	var extra map[string]any
	_ = json.Unmarshal([]byte(`{"port":5060,"weight":10,"service":"_sip","protocol":"_tcp"}`), &extra)
	r, err = recordToAPI(zone, platform.Record{Name: "_sip._tcp.example.com", Type: "SRV", Value: "sip.example.com", Priority: intp(1), Extra: extra})
	if err != nil || r.Name != "@" || r.Service != "_sip" || r.Protocol != "_tcp" || r.Port == nil || *r.Port != 5060 || r.Weight == nil || *r.Weight != 10 {
		t.Errorf("SRV from extra: %+v %v", r, err)
	}
	// SRV with the service/protocol only in the name.
	r, err = recordToAPI(zone, platform.Record{Name: "_sip._tcp.host.example.com", Type: "SRV", Value: "sip.example.com", Extra: map[string]any{"port": 5060}})
	if err != nil || r.Name != "host" || r.Service != "_sip" || r.Protocol != "_tcp" {
		t.Errorf("SRV from name: %+v %v", r, err)
	}
	if _, err := recordToAPI(zone, platform.Record{Name: "_sip._tcp.example.com", Type: "SRV", Value: "x"}); err == nil {
		t.Error("SRV without port must fail")
	}
}

func TestDomainConversion(t *testing.T) {
	yes := true
	d := domainFromAPI(apiDomain{Domain: "Example.com", DomainID: 42, Status: "ACTIVE", Expires: "2030-01-01T00:00:00Z", NameServers: []string{"ns1.x", "ns2.x"}, RenewAuto: &yes, Locked: &yes, TransferProtected: &yes})
	if d.Name != "example.com" || d.Status != "ACTIVE" || d.ExpiresAt != "2030-01-01T00:00:00Z" || d.AutoRenew == nil || !*d.AutoRenew || d.Locked == nil || d.Privacy != nil {
		t.Errorf("domain: %+v", d)
	}
	if d.Extra["domain_id"] != int64(42) || d.Extra["transfer_protected"] != true {
		t.Errorf("extra: %+v", d.Extra)
	}
	z := zoneFromDomain(d)
	if z.ID != "example.com" || z.Name != "example.com" || len(z.Nameservers) != 2 || z.Status != "ACTIVE" {
		t.Errorf("zone: %+v", z)
	}
}

func TestKeyPrefix(t *testing.T) {
	if keyPrefix("abcdefghij") != "abcdef" || keyPrefix("abc") != "abc" || keyPrefix("") != "" {
		t.Error("keyPrefix")
	}
	if fp := fingerprint("abcdefghij"); len(fp) != 8 || fp == fingerprint("abcdefghik") || strings.Contains("abcdefghij", fp) {
		t.Errorf("fingerprint = %q", fp)
	}
}
