package app

import (
	"encoding/json"
	"testing"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// The labels of selection lists keep every fact in its cell: a fact a row
// does not have is "-" when a later cell follows, so the later cells do not
// slide left.
func TestOptionLabelsKeepTheirCells(t *testing.T) {
	on, off := true, false
	domain := func(d platform.Domain) inventory.Resource {
		data, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		return inventory.Resource{Platform: platform.NameCom, Profile: "acme", Type: platform.ResDomain, Name: d.Name, ID: d.Name, Data: data}
	}
	for _, tc := range []struct{ name, got, want string }{
		{"resource", resourceLabel(inventory.Resource{Platform: platform.NameCom, Profile: "a", Name: "web", ID: "i-1"}), "web  i-1  namecom/a"},
		{"resource named by its id", resourceLabel(inventory.Resource{Platform: platform.NameCom, Profile: "a", Name: "i-1", ID: "i-1"}), "-  i-1  namecom/a"},
		{"resource without a name", resourceLabel(inventory.Resource{Platform: platform.NameCom, Profile: "a", ID: "i-1"}, "in vpc-1"), "-  i-1  namecom/a  in vpc-1"},
		{"resource without a parent", resourceLabel(inventory.Resource{Platform: platform.NameCom, Profile: "a", Name: "web", ID: "i-1"}, ""), "web  i-1  namecom/a"},

		{"domain", domainLabel(domain(platform.Domain{Name: "example.com", Status: "ACTIVE", ExpiresAt: "2027-03-01T00:00:00Z", Locked: &on, AutoRenew: &on})),
			"example.com  ACTIVE  expires 2027-03-01  locked  autorenew  namecom/acme"},
		{"domain without expiry", domainLabel(domain(platform.Domain{Name: "example.com", Status: "ACTIVE", Locked: &off, AutoRenew: &on})),
			"example.com  ACTIVE  -  -  autorenew  namecom/acme"},
		{"zone", domainLabel(inventory.Resource{Platform: platform.NameCom, Profile: "acme", Type: platform.ResZone, Name: "example.com", ID: "z1"}),
			"example.com  -  -  -  -  namecom/acme"},

		{"stored", storedLabel("win-1", "i-1", "cn-shanghai", "Administrator"), "win-1  i-1  cn-shanghai  user Administrator"},
		{"stored without a name", storedLabel("i-1", "i-1", "", "root", "project p1"), "-  i-1  -  user root  project p1"},
		{"stored with the id only", storedLabel("", "i-1", "", "", ""), "-  i-1"},

		{"record", RecordLabel(platform.Record{Name: "www", Type: "A", Value: "203.0.113.10", TTL: 300, Proxied: &on}, "[R2 bucket b]", "r1"),
			"www  A  203.0.113.10  ttl 300  proxied  [R2 bucket b]  r1"},
		{"record without TTL", RecordLabel(platform.Record{Name: "www", Type: "TXT", Value: "v=spf1  -all", Proxied: &off}, "", "r1"),
			"www  TXT  v=spf1 -all  -  -  -  r1"},
		{"record alone", RecordLabel(platform.Record{Name: "www", Type: "A", Value: "203.0.113.10"}, ""), "www  A  203.0.113.10"},
	} {
		if tc.got != tc.want {
			t.Errorf("%s: label = %q, want %q", tc.name, tc.got, tc.want)
		}
	}
}

// One resource reached through two profiles gives two candidates that
// differ in their profile only: it has to be in the part of the label an
// 80-column terminal shows (a label is cut at its end, after 75 columns),
// however long the name is.
func TestCandidateLabelShowsTheProfile(t *testing.T) {
	shown := func(label string) string {
		if r := []rune(label); len(r) > 75 {
			return string(r[:75])
		}
		return label
	}
	r := inventory.Resource{Platform: platform.Aliyun, Profile: "prod-ro", ParentID: "vpc-1",
		Name: "billing-export-worker-production-eu-central-1-blue-green-canary-2026", ID: "i-0123456789abcdef0"}
	other := r
	other.Profile = "prod-rw"
	if a, b := shown(candidateLabel(r)), shown(candidateLabel(other)); a == b {
		t.Errorf("one resource of two profiles is shown as the same row: %q", a)
	}
	if got, want := candidateLabel(r), "aliyun/prod-ro  i-0123456789abcdef0  "+r.Name+"  in vpc-1"; got != want {
		t.Errorf("candidate:\n got %q\nwant %q", got, want)
	}
	if got, want := candidateLabel(inventory.Resource{Platform: platform.Aliyun, Profile: "a", Name: "i-1", ID: "i-1", ParentID: "vpc-1"}), "aliyun/a  i-1  -  in vpc-1"; got != want {
		t.Errorf("candidate named by its id:\n got %q\nwant %q", got, want)
	}
}
