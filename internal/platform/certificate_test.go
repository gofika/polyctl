package platform

import (
	"strings"
	"testing"
)

func TestACMValidationRecords(t *testing.T) {
	recs := []ValidationRecord{
		{Domain: "*.example.com", Name: "_abc123.Example.com.", Type: "CNAME", Value: "_def456.acm-validations.aws."},
		// The bare name shares the record of the wildcard.
		{Domain: "example.com", Name: "_abc123.example.com.", Type: "CNAME", Value: "_DEF456.acm-validations.aws."},
		{Domain: "api.example.com", Name: "_x1.api.example.com.", Type: "CNAME", Value: "_y1.acm-validations.aws."},
		// Not published yet.
		{Domain: "www.example.com"},
		// Outside the zone: kept as a FQDN.
		{Domain: "example.net", Name: "_n.example.net.", Type: "CNAME", Value: "_v.acm-validations.aws."},
	}
	specs := ACMValidationRecords("example.com", recs)
	var got []string
	for _, s := range specs {
		if s.TTL == nil || *s.TTL != 300 || s.Proxied == nil || *s.Proxied {
			t.Errorf("spec %+v: want ttl 300 and proxied false", s)
		}
		got = append(got, s.Inline())
	}
	want := "_abc123:CNAME:_def456.acm-validations.aws:300:false,_x1.api:CNAME:_y1.acm-validations.aws:300:false,_n.example.net:CNAME:_v.acm-validations.aws:300:false"
	if strings.Join(got, ",") != want {
		t.Errorf("specs = %s\nwant    %s", strings.Join(got, ","), want)
	}
	// The case AWS used is kept.
	if specs[0].Name != "_abc123" {
		t.Errorf("name = %q", specs[0].Name)
	}
	// Without a zone every name stays a FQDN without the trailing dot.
	if s := ACMValidationRecords("", recs[:1]); len(s) != 1 || s[0].Name != "_abc123.Example.com" {
		t.Errorf("no zone = %+v", s)
	}
	for _, s := range specs {
		if err := s.Validate(); err != nil {
			t.Errorf("%s: %v", s.Inline(), err)
		}
		if p, err := ParseRecordSpec(s.Inline()); err != nil || p.Value != s.Value || p.Name != s.Name {
			t.Errorf("round trip %s = %+v, %v", s.Inline(), p, err)
		}
	}
}

func TestRecordSpecInline(t *testing.T) {
	yes := true
	ttl := 60
	cases := map[string]RecordSpec{
		"www:A:203.0.113.10":         {Name: "www", Type: "A", Value: "203.0.113.10"},
		"www:A:203.0.113.10:60":      {Name: "www", Type: "A", Value: "203.0.113.10", TTL: &ttl},
		"www:A:203.0.113.10::true":   {Name: "www", Type: "A", Value: "203.0.113.10", Proxied: &yes},
		"www:A:203.0.113.10:60:true": {Name: "www", Type: "A", Value: "203.0.113.10", TTL: &ttl, Proxied: &yes},
	}
	for want, r := range cases {
		if got := r.Inline(); got != want {
			t.Errorf("Inline = %q, want %q", got, want)
		}
	}
}
