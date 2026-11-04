package gcp

import (
	"reflect"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"

	"github.com/gofika/polyctl/internal/platform"
)

func TestRecordIDRoundTrip(t *testing.T) {
	cases := []struct{ typ, fqdn, raw string }{
		{"A", "www.example.com", "1.2.3.4"},
		{"mx", "Example.COM.", "10 mail.example.com."},
		{"TXT", "example.com", `"v=spf1 include:_spf.google.com ~all"`},
		{"TXT", "example.com", `"pipe|inside" "and spaces"`},
		{"SRV", "_sip._tcp.example.com", "10 5 5060 sip.example.com."},
	}
	for _, c := range cases {
		id := encodeRecordID("my-zone", c.typ, c.fqdn, c.raw)
		zone, typ, fqdn, raw, err := decodeRecordID(id)
		if err != nil {
			t.Fatalf("decode %q: %v", id, err)
		}
		if zone != "my-zone" || typ != strings.ToUpper(c.typ) || fqdn != platform.NormalizeDomain(c.fqdn) || raw != c.raw {
			t.Errorf("round trip %q -> %q %q %q %q", id, zone, typ, fqdn, raw)
		}
	}
	if id := encodeRecordID("z", "TXT", "example.com", "a|b"); id != "z|TXT|example.com|a%7Cb" {
		t.Errorf("pipe not escaped: %q", id)
	}
	// Same name/type/value in two zones (split-horizon) must not collide.
	if encodeRecordID("public", "A", "www.example.com", "10.0.0.1") == encodeRecordID("private", "A", "www.example.com", "10.0.0.1") {
		t.Error("record ids of different zones collide")
	}
	for _, bad := range []string{"", "A|www", "A|www|1.1.1.1", "|A|x|y", "z||x|y", "z|A||1.1.1.1", "z|A|www|%zz"} {
		if _, _, _, _, err := decodeRecordID(bad); err == nil {
			t.Errorf("expected error for %q", bad)
		}
	}
}

func intp(i int) *int { return &i }

func TestRecordsFromRRSet(t *testing.T) {
	rs := &dns.ResourceRecordSet{Name: "example.com.", Type: "MX", Ttl: 3600, Rrdatas: []string{"10 mail.example.com.", "20 mail2.example.com."}}
	recs := recordsFromRRSet("zone-1", rs)
	if len(recs) != 2 {
		t.Fatalf("got %d records", len(recs))
	}
	r := recs[0]
	if r.ID != "zone-1|MX|example.com|10+mail.example.com." || r.ZoneID != "zone-1" || r.Name != "example.com" || r.Type != "MX" || r.TTL != 3600 {
		t.Errorf("unexpected record %+v", r)
	}
	if r.Content != "mail.example.com" || r.Priority == nil || *r.Priority != 10 {
		t.Errorf("MX content/priority: %q %v", r.Content, r.Priority)
	}
	if recs[1].Content != "mail2.example.com" || *recs[1].Priority != 20 {
		t.Errorf("second MX: %+v", recs[1])
	}

	cases := []struct {
		typ, raw, content string
		prio              *int
	}{
		{"CNAME", "target.example.net.", "target.example.net", nil},
		{"NS", "ns1.example.net.", "ns1.example.net", nil},
		{"A", "1.2.3.4", "1.2.3.4", nil},
		{"TXT", `"v=spf1 -all"`, `v=spf1 -all`, nil},
		{"TXT", `"say \"hi\""`, `say "hi"`, nil},
		{"TXT", `"a" "b"`, `"a" "b"`, nil},
		{"TXT", `unquoted`, `unquoted`, nil},
		{"SRV", "10 5 5060 sip.example.com.", "5 5060 sip.example.com", intp(10)},
		{"MX", "garbage", "garbage", nil},
	}
	for _, c := range cases {
		got := recordsFromRRSet("z", &dns.ResourceRecordSet{Name: "x.example.com.", Type: c.typ, Rrdatas: []string{c.raw}})[0]
		if got.Content != c.content || !reflect.DeepEqual(got.Priority, c.prio) {
			t.Errorf("%s %q: content %q prio %v", c.typ, c.raw, got.Content, got.Priority)
		}
		if got.Extra["rrdata"] != c.raw {
			t.Errorf("%s: extra rrdata %v", c.typ, got.Extra["rrdata"])
		}
	}
	if recordsFromRRSet("z", nil) != nil {
		t.Error("nil rrset should yield nil")
	}

	// A routing-policy set has no rrdatas; it is surfaced as one read-only record.
	policy := &dns.RRSetRoutingPolicy{Geo: &dns.RRSetRoutingPolicyGeoPolicy{}}
	geo := recordsFromRRSet("z", &dns.ResourceRecordSet{Name: "geo.example.com.", Type: "A", Ttl: 60, RoutingPolicy: policy})
	if len(geo) != 1 {
		t.Fatalf("routing policy set yielded %d records", len(geo))
	}
	if geo[0].ID != "z|A|geo.example.com|routing-policy" || geo[0].Content != routingPolicyContent || geo[0].TTL != 60 || geo[0].Extra["routing_policy"] != policy {
		t.Errorf("routing policy record: %+v", geo[0])
	}
}

func TestUnquoteTXT(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`"v=spf1 -all"`, `v=spf1 -all`, true},
		{`""`, ``, true},
		{`"a \"b\" c"`, `a "b" c`, true},
		{`"back\\slash"`, `back\\slash`, true},
		{`"a" "b"`, `"a" "b"`, false},
		{`"unterminated`, `"unterminated`, false},
		{`plain`, `plain`, false},
		{`"`, `"`, false},
		{`"ends with escape\"`, `"ends with escape\"`, false},
	}
	for _, c := range cases {
		got, ok := unquoteTXT(c.in)
		if got != c.want || ok != c.ok {
			t.Errorf("unquoteTXT(%q) = %q, %v; want %q, %v", c.in, got, ok, c.want, c.ok)
		}
		if ok && quoteTXT(got) != c.in {
			t.Errorf("quoteTXT(%q) = %q, want %q", got, quoteTXT(got), c.in)
		}
	}
}

func TestRRDataFromRecord(t *testing.T) {
	cases := []struct {
		name string
		rec  platform.Record
		want string
		err  bool
	}{
		{"A", platform.Record{Type: "A", Content: "1.2.3.4"}, "1.2.3.4", false},
		{"CNAME adds dot", platform.Record{Type: "cname", Content: "target.example.net"}, "target.example.net.", false},
		{"CNAME keeps dot", platform.Record{Type: "CNAME", Content: "target.example.net."}, "target.example.net.", false},
		{"NS", platform.Record{Type: "NS", Content: "ns1.example.net"}, "ns1.example.net.", false},
		{"MX with priority", platform.Record{Type: "MX", Content: "mail.example.com", Priority: intp(10)}, "10 mail.example.com.", false},
		{"MX inline priority", platform.Record{Type: "MX", Content: "20 mail.example.com."}, "20 mail.example.com.", false},
		{"MX missing priority", platform.Record{Type: "MX", Content: "mail.example.com"}, "", true},
		{"MX too many fields", platform.Record{Type: "MX", Content: "a b", Priority: intp(1)}, "", true},
		{"SRV", platform.Record{Type: "SRV", Content: "5 5060 sip.example.com", Priority: intp(10)}, "10 5 5060 sip.example.com.", false},
		{"SRV bad", platform.Record{Type: "SRV", Content: "5060 sip.example.com", Priority: intp(10)}, "", true},
		{"TXT quotes", platform.Record{Type: "TXT", Content: `v=spf1 "x" ~all`}, `"v=spf1 \"x\" ~all"`, false},
		{"TXT already quoted", platform.Record{Type: "TXT", Content: `"a" "b"`}, `"a" "b"`, false},
		{"empty", platform.Record{Type: "A", Content: "  "}, "", true},
	}
	for _, c := range cases {
		got, err := rrdataFromRecord(c.rec)
		if (err != nil) != c.err {
			t.Errorf("%s: err=%v", c.name, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}

func TestRRDataRoundTrip(t *testing.T) {
	for _, rs := range []*dns.ResourceRecordSet{
		{Name: "example.com.", Type: "MX", Rrdatas: []string{"10 mail.example.com."}},
		{Name: "_sip._tcp.example.com.", Type: "SRV", Rrdatas: []string{"10 5 5060 sip.example.com."}},
		{Name: "www.example.com.", Type: "CNAME", Rrdatas: []string{"example.com."}},
		{Name: "example.com.", Type: "TXT", Rrdatas: []string{`"v=spf1 -all"`}},
		{Name: "example.com.", Type: "TXT", Rrdatas: []string{`"a" "b"`}},
		{Name: "example.com.", Type: "AAAA", Rrdatas: []string{"2001:db8::1"}},
	} {
		rec := recordsFromRRSet("z", rs)[0]
		if rs.Type == "TXT" && rs.Rrdatas[0] == `"v=spf1 -all"` && rec.Content != `v=spf1 -all` {
			t.Errorf("TXT content should be unquoted for users: %q", rec.Content)
		}
		// Content is what a user would pass on the command line; it must
		// produce the same rrdata as the listing came from.
		raw, err := rrdataFromRecord(platform.Record{Type: rec.Type, Content: rec.Content, Priority: rec.Priority})
		if err != nil {
			t.Fatalf("%s: %v", rs.Type, err)
		}
		if raw != rs.Rrdatas[0] {
			t.Errorf("%s: round trip %q -> %q", rs.Type, rs.Rrdatas[0], raw)
		}
	}
}

func TestZoneFromManaged(t *testing.T) {
	z := zoneFromManaged(&dns.ManagedZone{Name: "example-zone", DnsName: "example.com.", Id: 12345, Visibility: "public",
		Description: "d", NameServers: []string{"ns-1.googledomains.com."}, Labels: map[string]string{"env": "prod"}})
	if z.ID != "example-zone" || z.Name != "example.com" || z.Status != "public" || z.Extra["id"] != "12345" || z.Extra["description"] != "d" {
		t.Errorf("zone: %+v", z)
	}
	if lbl, ok := z.Extra["labels"].(map[string]string); !ok || lbl["env"] != "prod" {
		t.Errorf("labels: %v", z.Extra["labels"])
	}
}

func TestInstanceFromAPI(t *testing.T) {
	in := &compute.Instance{
		Id: 42, Name: "web-1", Status: "RUNNING", CreationTimestamp: "2026-01-01T00:00:00Z",
		Zone:        "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a",
		MachineType: "https://www.googleapis.com/compute/v1/projects/p/zones/us-central1-a/machineTypes/e2-small",
		Labels:      map[string]string{"role": "web"},
		NetworkInterfaces: []*compute.NetworkInterface{{
			NetworkIP:     "10.0.0.2",
			AccessConfigs: []*compute.AccessConfig{{NatIP: "34.1.2.3"}},
		}},
	}
	got := instanceFromAPI(in)
	want := Instance{Name: "web-1", ID: "42", Zone: "us-central1-a", MachineType: "e2-small", Status: "RUNNING",
		InternalIP: "10.0.0.2", ExternalIP: "34.1.2.3", CreationTimestamp: "2026-01-01T00:00:00Z", Labels: map[string]string{"role": "web"}}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("got %+v\nwant %+v", got, want)
	}
	res := instanceResource(got)
	if res.Type != platform.ResInstance || res.ID != "42" || res.Name != "web-1" || res.Domain != "" {
		t.Errorf("resource: %+v", res)
	}
}

func TestParseServiceAccountKey(t *testing.T) {
	key, err := parseServiceAccountKey([]byte(`{"type":"service_account","project_id":"p","client_email":"sa@p.iam.gserviceaccount.com"}`))
	if err != nil || key.ProjectID != "p" || key.ClientEmail != "sa@p.iam.gserviceaccount.com" {
		t.Fatalf("parse: %v %+v", err, key)
	}
	for _, bad := range []string{`{`, `{"type":"authorized_user"}`, `{"type":"service_account"}`} {
		if _, err := parseServiceAccountKey([]byte(bad)); err == nil {
			t.Errorf("expected error for %s", bad)
		}
	}
}

func TestLocateInstance(t *testing.T) {
	list := []Instance{
		{Name: "web", ID: "111", Zone: "us-central1-a"},
		{Name: "web", ID: "222", Zone: "europe-west1-b"},
		{Name: "db", ID: "333", Zone: "us-central1-a"},
	}
	// A numeric id is unique even when the name exists in several zones.
	if zone, name, cands := locateInstance(list, "222"); zone != "europe-west1-b" || name != "web" || cands != nil {
		t.Errorf("by id: %q %q %v", zone, name, cands)
	}
	if zone, name, cands := locateInstance(list, "db"); zone != "us-central1-a" || name != "db" || cands != nil {
		t.Errorf("unique name: %q %q %v", zone, name, cands)
	}
	if zone, name, cands := locateInstance(list, "web"); zone != "" || name != "web" || !reflect.DeepEqual(cands, []string{"us-central1-a", "europe-west1-b"}) {
		t.Errorf("ambiguous name: %q %q %v", zone, name, cands)
	}
	if zone, _, cands := locateInstance(list, "nope"); zone != "" || cands != nil {
		t.Errorf("missing: %q %v", zone, cands)
	}
}

func TestLabelAndHelpers(t *testing.T) {
	if label("", "p") != "project p" || label("a@b", "p") != "a@b (project p)" {
		t.Error("label")
	}
	if lastSegment("a/b/c") != "c" || lastSegment("plain") != "plain" {
		t.Error("lastSegment")
	}
	if ensureDot("x") != "x." || ensureDot("x.") != "x." || ensureDot("") != "" {
		t.Error("ensureDot")
	}
	vals, ok := removeValue([]string{"a", "b"}, "a")
	if !ok || !reflect.DeepEqual(vals, []string{"b"}) {
		t.Error("removeValue")
	}
	if _, ok := removeValue([]string{"a"}, "z"); ok {
		t.Error("removeValue missing")
	}
}
