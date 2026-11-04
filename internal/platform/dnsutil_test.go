package platform_test

import (
	"reflect"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestNormalizeDomain(t *testing.T) {
	cases := map[string]string{
		"":                    "",
		"example.com":         "example.com",
		"Example.COM.":        "example.com",
		"  WWW.Example.com. ": "www.example.com",
		".":                   "",
	}
	for in, want := range cases {
		if got := platform.NormalizeDomain(in); got != want {
			t.Errorf("NormalizeDomain(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestFQDN(t *testing.T) {
	cases := []struct{ name, zone, want string }{
		{"www", "example.com", "www.example.com"},
		{"@", "example.com", "example.com"},
		{"", "example.com", "example.com"},
		{"example.com", "example.com", "example.com"},
		{"www.example.com", "example.com", "www.example.com"},
		{"WWW", "Example.COM.", "www.example.com"},
		{"a.b", "example.com", "a.b.example.com"},
		{"www.example.com.", "example.com.", "www.example.com"},
		// A name that merely ends with the zone text but is not under it is
		// treated as relative.
		{"notexample.com", "example.com", "notexample.com.example.com"},
	}
	for _, c := range cases {
		if got := platform.FQDN(c.name, c.zone); got != c.want {
			t.Errorf("FQDN(%q, %q) = %q, want %q", c.name, c.zone, got, c.want)
		}
	}
}

func TestRelativeName(t *testing.T) {
	cases := []struct{ fqdn, zone, want string }{
		{"www.example.com", "example.com", "www"},
		{"example.com", "example.com", "@"},
		{"", "example.com", "@"},
		{"Example.COM.", "example.com", "@"},
		{"a.b.example.com", "example.com", "a.b"},
		{"other.org", "example.com", "other.org"},
		{"WWW.Example.com.", "EXAMPLE.com", "www"},
	}
	for _, c := range cases {
		if got := platform.RelativeName(c.fqdn, c.zone); got != c.want {
			t.Errorf("RelativeName(%q, %q) = %q, want %q", c.fqdn, c.zone, got, c.want)
		}
	}
}

func TestCandidates(t *testing.T) {
	cases := []struct {
		in   string
		want []string
	}{
		{"www.a.example.com", []string{"www.a.example.com", "a.example.com", "example.com"}},
		{"example.com", []string{"example.com"}},
		{"Example.COM.", []string{"example.com"}},
		{"com", nil},
		{"", nil},
		{"  ", nil},
	}
	for _, c := range cases {
		got := platform.Candidates(c.in)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("Candidates(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestParse(t *testing.T) {
	ok := map[string]platform.ID{
		"aws": platform.AWS, "amazon": platform.AWS,
		"gcp": platform.GCP, "google": platform.GCP, "gcloud": platform.GCP,
		"aliyun": platform.Aliyun, "alibaba": platform.Aliyun, "alicloud": platform.Aliyun,
		"cloudflare": platform.Cloudflare, "cf": platform.Cloudflare,
		"namecom": platform.NameCom, "name.com": platform.NameCom, "name": platform.NameCom,
		"godaddy": platform.GoDaddy, "gd": platform.GoDaddy,
	}
	for in, want := range ok {
		got, err := platform.Parse(in)
		if err != nil || got != want {
			t.Errorf("Parse(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "AWS", "azure", "name com"} {
		if got, err := platform.Parse(in); err == nil {
			t.Errorf("Parse(%q) = %q, want error", in, got)
		}
	}
}

func TestParseResourceType(t *testing.T) {
	for _, rt := range []platform.ResourceType{platform.ResDomain, platform.ResZone, platform.ResDNSRecord, platform.ResInstance} {
		got, err := platform.ParseResourceType(string(rt))
		if err != nil || got != rt {
			t.Errorf("ParseResourceType(%q) = %q, %v", rt, got, err)
		}
	}
	for _, in := range []string{"", "Zone", "record", "dns-record", "instances"} {
		if got, err := platform.ParseResourceType(in); err == nil {
			t.Errorf("ParseResourceType(%q) = %q, want error", in, got)
		}
	}
}

func TestAllHaveDisplayOrder(t *testing.T) {
	seen := map[platform.ID]bool{}
	for _, id := range platform.All {
		if seen[id] {
			t.Errorf("platform %q listed twice in All", id)
		}
		seen[id] = true
		if _, err := platform.Parse(string(id)); err != nil {
			t.Errorf("Parse(%q) failed for an ID in All: %v", id, err)
		}
	}
}
