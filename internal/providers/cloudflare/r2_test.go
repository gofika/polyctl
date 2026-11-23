package cloudflare

import (
	"encoding/json"
	"errors"
	"reflect"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestNormalizeR2Domain(t *testing.T) {
	for in, want := range map[string]string{"CDN.Example.com.": "cdn.example.com", "a.b.example.co.uk": "a.b.example.co.uk"} {
		if got, err := NormalizeR2Domain(in); err != nil || got != want {
			t.Errorf("%q = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "*.example.com", "a.*.example.com", "cdn example.com", "localhost", "a..example.com", "a/b.example.com"} {
		if got, err := NormalizeR2Domain(in); err == nil {
			t.Errorf("%q = %q, want an error", in, got)
		}
	}
}

func TestZoneCandidates(t *testing.T) {
	if got := zoneCandidates("cdn.a.example.com"); !reflect.DeepEqual(got, []string{"cdn.a.example.com", "a.example.com", "example.com"}) {
		t.Errorf("got %v", got)
	}
	if got := zoneCandidates("x.example.co.uk"); !reflect.DeepEqual(got, []string{"x.example.co.uk", "example.co.uk", "co.uk"}) {
		t.Errorf("got %v", got)
	}
	if !underZone("example.com", "example.com") || !underZone("a.example.com", "example.com") || underZone("aexample.com", "example.com") {
		t.Error("underZone")
	}
}

func TestValidMinTLS(t *testing.T) {
	for _, v := range []string{"1.0", "1.1", "1.2", "1.3"} {
		if !ValidMinTLS(v) {
			t.Errorf("%s refused", v)
		}
	}
	for _, v := range []string{"", "2.0", "9.9", "1"} {
		if ValidMinTLS(v) {
			t.Errorf("%s accepted", v)
		}
	}
}

// The custom domain endpoints speak camelCase; an unset minTLS is absent.
func TestR2DomainJSON(t *testing.T) {
	var d r2CustomDomain
	in := `{"domain":"cdn.example.com","enabled":true,"zoneId":"z1","zoneName":"example.com","status":{"ownership":"active","ssl":"pending"}}`
	if err := json.Unmarshal([]byte(in), &d); err != nil || d.ZoneID != "z1" || d.ZoneName != "example.com" || d.MinTLS != "" || d.Status.SSL != "pending" {
		t.Fatalf("decoded %+v, %v", d, err)
	}
	if v := viewOf(d, nil); v.MinTLS != nil || v.minTLSLabel() != "-" {
		t.Errorf("view = %+v", v)
	}
	b, _ := json.Marshal(r2AttachBody{Domain: "cdn.example.com", Enabled: true, ZoneID: "z1", MinTLS: "1.2"})
	if string(b) != `{"domain":"cdn.example.com","enabled":true,"zoneId":"z1","minTLS":"1.2"}` {
		t.Errorf("attach body = %s", b)
	}
	f := false
	b, _ = json.Marshal(r2UpdateBody{Enabled: &f})
	if string(b) != `{"enabled":false}` {
		t.Errorf("update body = %s", b)
	}
}

func TestDomainUpdate(t *testing.T) {
	on, off := true, false
	cur := r2CustomDomain{Enabled: false, MinTLS: "1.0"}
	if _, desc := domainUpdate(cur, &off, ""); desc != "" {
		t.Errorf("unchanged = %q", desc)
	}
	body, desc := domainUpdate(cur, &on, "1.2")
	if body.Enabled == nil || !*body.Enabled || body.MinTLS != "1.2" || desc != "enabled false -> true; min_tls 1.0 -> 1.2" {
		t.Errorf("body %+v, %q", body, desc)
	}
	// An unset minimum TLS version differs from every given one.
	if _, desc := domainUpdate(r2CustomDomain{Enabled: true}, nil, "1.0"); desc != "min_tls - -> 1.0" {
		t.Errorf("unset = %q", desc)
	}
}

// R2 not enabled on an account is "not supported", not a credentials
// problem, although the API answers 403.
func TestClassifyR2NotEnabled(t *testing.T) {
	err := newError(403, "GET", "/accounts/a/r2/buckets", []message{{Code: 10042, Message: "Please enable R2 through the Cloudflare Dashboard."}})
	if !errors.Is(err, platform.ErrNotSupported) || errors.Is(err, platform.ErrUnauthorized) {
		t.Errorf("10042 = %v", err)
	}
	if !hasCode(err, 10042) || hasCode(err, 10006) {
		t.Error("hasCode")
	}
}

func TestR2RecordMatch(t *testing.T) {
	yes, no := true, false
	c := &Client{}
	r2 := platform.Record{Name: "cdn.example.com", Type: "CNAME", Value: "public.r2.dev", Proxied: &yes, Meta: map[string]any{"r2_bucket": "assets", "read_only": true}}
	if owner, ok := c.Match(platform.Zone{}, r2); !ok || owner != "r2 bucket assets" {
		t.Errorf("r2 record = %q, %v", owner, ok)
	}
	plain := r2
	plain.Proxied = &no
	if _, ok := c.Match(platform.Zone{}, plain); ok {
		t.Error("an unproxied CNAME to r2.dev is a record of its own")
	}
	bare := r2
	bare.Meta = nil
	if owner, ok := c.Match(platform.Zone{}, bare); !ok || owner != "r2 custom domain" {
		t.Errorf("without meta = %q, %v", owner, ok)
	}
	if handled, err := c.Unbind(t.Context(), platform.Zone{}, bare); handled || err == nil {
		t.Errorf("unbind without a bucket = %v, %v", handled, err)
	}
	// The meta of a record comes from the API.
	rec := toRecord(apiRecord{ID: "r", Name: "cdn.example.com", Type: "CNAME", Content: "public.r2.dev", Proxied: &yes, Meta: map[string]any{"r2_bucket": "assets"}})
	if R2Bucket(rec) != "assets" {
		t.Errorf("meta = %v", rec.Meta)
	}
	if rec := toRecord(apiRecord{ID: "r", Name: "a.example.com", Type: "A", Meta: map[string]any{}}); rec.Meta != nil {
		t.Errorf("empty meta kept: %v", rec.Meta)
	}
}
