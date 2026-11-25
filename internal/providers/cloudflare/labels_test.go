package cloudflare

import (
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// TestOptionLabelsKeepTheirCells pins the cells of the selection lists: a
// fact keeps its position, and a fact a row does not have is "-" unless
// nothing follows it.
func TestOptionLabelsKeepTheirCells(t *testing.T) {
	for _, c := range []struct{ name, got, want string }{
		{"zone", zoneLabel(platform.Zone{Name: "example.com", Status: "active", ID: "z1"}, "Acme", "work"),
			"example.com  active  z1  account Acme  cloudflare/work"},
		{"zone without a status or an account", zoneLabel(platform.Zone{Name: "example.com", ID: "z1"}, "", "work"),
			"example.com  -  z1  -  cloudflare/work"},
		{"account", accountOption("acc1", "Acme", "default").Label, "Acme  acc1  default"},
		{"account without a mark", accountOption("acc1", "Acme", "").Label, "Acme  acc1"},
		{"account without a name", accountOption("acc1", "", "selected").Label, "-  acc1  selected"},
		{"ambiguous zone", zoneCand{profile: "work", account: "acc1", accountName: "Acme", id: "z1", status: "active"}.cells(),
			"cloudflare/work  z1  active  account acc1  Acme"},
		{"ambiguous zone without a status or an account name", zoneCand{profile: "work", account: "acc1", id: "z1"}.cells(),
			"cloudflare/work  z1  -  account acc1"},
		{"owner of a domain without a status or an account name",
			prompt.Cells(append([]string{"cloudflare/work"}, (&provider{}).OwnerCells(platform.ResZone, "z1", "acc1", []byte(`{}`))...)...),
			"cloudflare/work  z1  -  account acc1"},
		{"ambiguous bucket", (&r2Acct{profile: "work", account: "acc1"}).candCells(), "cloudflare/work  account acc1"},
		{"custom domain", bucketDomainLabel(r2CustomDomain{Domain: "cdn.example.com", Enabled: true, MinTLS: "1.2", ZoneName: "example.com"}),
			"cdn.example.com  enabled  tls 1.2  zone example.com"},
		{"custom domain without a minimum TLS version", bucketDomainLabel(r2CustomDomain{Domain: "cdn.example.com", ZoneName: "example.com"}),
			"cdn.example.com  disabled  -  zone example.com"},
		{"custom domain of no zone", bucketDomainLabel(r2CustomDomain{Domain: "cdn.example.com", Enabled: true}),
			"cdn.example.com  enabled"},
	} {
		if c.got != c.want {
			t.Errorf("%s: label %q, want %q", c.name, c.got, c.want)
		}
	}
}

// shown is what an 80-column terminal shows of a label of a select list: a
// label is cut at its end, after 75 columns.
func shown(label string) string {
	if r := []rune(label); len(r) > 75 {
		return string(r[:75])
	}
	return label
}

// One zone seen through two logins gives two candidates that differ in
// their profile only: it has to be in the part of the label a terminal
// shows.
func TestAmbiguousZoneLabelShowsTheProfile(t *testing.T) {
	c := zoneCand{account: "a1b2c3d4e5f60718293a4b5c6d7e8f90", accountName: "Acme Production", id: "0123456789abcdef0123456789abcdef", status: "active"}
	work, personal := c, c
	work.profile, personal.profile = "work", "personal"
	if a, b := shown(work.cells()), shown(personal.cells()); a == b {
		t.Errorf("one zone of two profiles is shown as the same row: %q", a)
	}
}
