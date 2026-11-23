package aws

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

func newACMHarness(t *testing.T, flags app.Flags, defaults map[string]any) (*awsHarness, *fakeClock) {
	t.Helper()
	h := newAWSHarness(t, flags, defaults)
	return h, useFakeACMClock(t)
}

func expires(y int) *time.Time {
	t := time.Date(y, 5, 1, 0, 0, 0, 0, time.UTC)
	return &t
}

func (h *awsHarness) listRows() []acmRow {
	h.t.Helper()
	var rows []acmRow
	h.jsonOut(&rows)
	return rows
}

func rowDomains(rows []acmRow) string {
	var out []string
	for _, r := range rows {
		out = append(out, r.Domain+"/"+r.KeyAlgorithm)
	}
	return strings.Join(out, ",")
}

func TestACMList(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", names: []string{"*.example.com", "example.com"}, status: acmIssued, notAfter: expires(2027)})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "example.com", status: acmPendingValidation, keyAlg: "RSA_2048"})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "big.example.org", status: acmIssued, keyAlg: "RSA_4096"})
	h.addCert(&fakeCert{region: "us-east-1", domain: "cdn.example.net", status: acmIssued})

	if err := h.run("acm", "certificate", "list"); err != nil {
		t.Fatalf("list: %v\n%s", err, h.stderr.String())
	}
	// The inventory sync names every key type of the SDK.
	if l := h.acm().lists; len(l) != 1 || l[0].Includes == nil || len(l[0].Includes.KeyTypes) != 7 {
		t.Errorf("sync list input = %+v", l)
	}
	rows := h.listRows()
	// Default key types: EC_prime256v1 and RSA_2048; the profile's region only.
	if got := rowDomains(rows); got != "*.example.com/EC_prime256v1,example.com/RSA_2048" {
		t.Errorf("rows = %s", got)
	}
	if r := rows[0]; r.Profile != "lab" || r.Region != "ap-east-1" || r.NotAfter == nil || r.Type != acmAmazonIssued || r.Status != acmIssued {
		t.Errorf("row = %+v", r)
	}
	if rows[1].NotAfter != nil {
		t.Errorf("pending row has an expiry: %+v", rows[1])
	}
	// A second run reads the inventory.
	h.resetACM()
	if err := h.run("acm", "certificate", "list", "--key-type", "RSA_4096", "--key-type", "ec_prime256v1"); err != nil {
		t.Fatal(err)
	}
	if got := rowDomains(h.listRows()); got != "*.example.com/EC_prime256v1,big.example.org/RSA_4096" {
		t.Errorf("--key-type rows = %s", got)
	}
	if len(h.acmCalls()) != 0 || !strings.Contains(h.stderr.String(), "local inventory") {
		t.Errorf("calls = %v, stderr = %s", h.acmCalls(), h.stderr.String())
	}
	if err := h.run("acm", "certificate", "list", "--status", "pending_validation"); err != nil || rowDomains(h.listRows()) != "example.com/RSA_2048" {
		t.Errorf("--status = %v, %s", err, h.stdout.String())
	}
	if err := h.run("acm", "certificate", "list", "--domain", "example.com"); err != nil || len(h.listRows()) != 2 {
		t.Errorf("--domain = %v, %s", err, h.stdout.String())
	}
	// No match: [], a note, exit code 0.
	if err := h.run("acm", "certificate", "list", "--domain", "nothing.example"); err != nil || strings.TrimSpace(h.stdout.String()) != "[]" ||
		!strings.Contains(h.stderr.String(), "no certificates") {
		t.Errorf("empty = %v, %q, %q", err, h.stdout.String(), h.stderr.String())
	}
	// Bad values are usage errors.
	for _, args := range [][]string{{"--key-type", "RSA_512"}, {"--status", "GONE"}, {"--region", "Bad Region"}, {"--domain", "http://x"}} {
		if err := h.run(append([]string{"acm", "certificate", "list"}, args...)...); !ExitUsageErr(err) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
}

func TestACMListRegionAndRefresh(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	h.ec2.find.regions = []string{"ap-east-1", "us-east-1"}
	h.addCert(&fakeCert{region: "ap-east-1", domain: "a.example.com", status: acmIssued})
	h.addCert(&fakeCert{region: "us-east-1", domain: "cdn.example.com", status: acmIssued})
	h.addCert(&fakeCert{region: "us-east-1", domain: "cdn2.example.com", status: acmIssued, keyAlg: "RSA_2048"})

	// --region asks AWS, with the default key types, page by page.
	h.acm().pageSize = 1
	if err := h.run("acm", "certificate", "list", "--region", "us-east-1"); err != nil {
		t.Fatal(err)
	}
	if got := rowDomains(h.listRows()); got != "cdn.example.com/EC_prime256v1,cdn2.example.com/RSA_2048" {
		t.Errorf("rows = %s", got)
	}
	l := h.acm().lists
	if len(l) != 2 || len(l[0].Includes.KeyTypes) != 2 || l[0].Includes.KeyTypes[0] != "EC_prime256v1" || l[0].Includes.KeyTypes[1] != "RSA_2048" {
		t.Errorf("list inputs = %+v", l)
	}
	h.acm().pageSize = 0

	// --region all: every region of the inventory.
	if err := h.run("acm", "certificate", "list", "--region", "all"); err != nil {
		t.Fatal(err)
	}
	if got := rowDomains(h.listRows()); got != "a.example.com/EC_prime256v1,cdn.example.com/EC_prime256v1,cdn2.example.com/RSA_2048" {
		t.Errorf("all rows = %s", got)
	}
	// A certificate deleted on the platform goes with --refresh.
	h.ec2.acm.certs = h.ec2.acm.certs[1:]
	h.rt.Flags.Refresh = true
	if err := h.run("acm", "certificate", "list", "--region", "all"); err != nil {
		t.Fatal(err)
	}
	if got := rowDomains(h.listRows()); got != "cdn.example.com/EC_prime256v1,cdn2.example.com/RSA_2048" {
		t.Errorf("refreshed rows = %s", got)
	}
	h.rt.Flags.Refresh = false
	// --offline reads the inventory.
	h.rt.Flags.Offline = true
	h.resetACM()
	if err := h.run("acm", "certificate", "list", "--region", "all"); err != nil || len(h.listRows()) != 2 || len(h.acmCalls()) != 0 {
		t.Errorf("offline = %v, calls %v", err, h.acmCalls())
	}
	if err := h.run("acm", "certificate", "list", "--region", "us-east-1"); !errors.Is(err, app.ErrOffline) {
		t.Errorf("offline --region = %v", err)
	}
}

func TestACMListOfflineNeverSynced(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{Offline: true}, nil)
	if err := h.run("acm", "certificate", "list"); !errors.Is(err, inventory.ErrNeverSynced) {
		t.Errorf("offline never synced = %v", err)
	}
}

func TestACMGet(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	old := h.addCert(&fakeCert{region: "ap-east-1", domain: "example.com", status: acmExpired, notAfter: expires(2025)})
	late := h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", names: []string{"*.example.com", "example.com"}, status: acmIssued, notAfter: expires(2027)})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", status: acmIssued, notAfter: expires(2026)})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "example.com", status: acmPendingValidation})

	// By domain: the inventory is synced once, the best one is read live.
	if err := h.run("acm", "certificate", "get", "example.com"); err != nil {
		t.Fatalf("get: %v\n%s", err, h.stderr.String())
	}
	var d acmDetail
	h.jsonOut(&d)
	if d.ARN != late.arn || d.Status != acmIssued || d.KeyAlgorithm != "EC_prime256v1" || d.Issuer != "Amazon" || strings.Join(d.SANs, ",") != "*.example.com,example.com" ||
		d.Profile != "lab" || d.Region != "ap-east-1" || d.ValidationRecords != nil {
		t.Errorf("detail = %+v", d)
	}
	// --validation-records adds the records, one per distinct record.
	if err := h.run("acm", "certificate", "get", "*.example.com", "--validation-records"); err != nil {
		t.Fatal(err)
	}
	d = acmDetail{}
	h.jsonOut(&d)
	if d.ValidationRecords == nil || len(*d.ValidationRecords) != 1 || !strings.HasSuffix((*d.ValidationRecords)[0].Name, ".example.com.") {
		t.Errorf("records = %+v", d.ValidationRecords)
	}
	// By ARN.
	if err := h.run("acm", "certificate", "get", old.arn); err != nil {
		t.Fatal(err)
	}
	d = acmDetail{}
	h.jsonOut(&d)
	if d.ARN != old.arn || d.Status != acmExpired {
		t.Errorf("by arn = %+v", d)
	}
	// The table shows the validation block of a pending certificate.
	h.rt.Flags.Output = "table"
	if err := h.rt.Init(); err != nil {
		t.Fatal(err)
	}
	pending := h.addCert(&fakeCert{region: "ap-east-1", domain: "new.example.org", status: acmPendingValidation})
	if err := h.run("acm", "certificate", "get", pending.arn); err != nil {
		t.Fatal(err)
	}
	if s := h.stdout.String(); !strings.Contains(s, "PENDING_VALIDATION") || !strings.Contains(s, "# validation records") || !strings.Contains(s, "acm-validations.aws.") {
		t.Errorf("table = %s", s)
	}
	if s := h.stderr.String(); !strings.Contains(s, "72 hours") || !strings.Contains(s, "polyctl dns ensure new.example.org --record _") || !strings.Contains(s, ":CNAME:") {
		t.Errorf("stderr = %s", s)
	}
}

func TestACMGetErrors(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	h.ec2.find.regions = []string{"ap-east-1", "us-east-1"}
	gone := h.addCert(&fakeCert{region: "ap-east-1", domain: "gone.example.com", status: acmIssued})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "two.example.com", status: acmIssued})
	h.addCert(&fakeCert{region: "us-east-1", domain: "two.example.com", status: acmIssued})

	if err := h.run("acm", "certificate", "get", "nothing.example.com"); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "--region") {
		t.Errorf("missing = %v", err)
	}
	var amb *app.AmbiguousError
	if err := h.run("acm", "certificate", "get", "two.example.com"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Errorf("two regions = %v", err)
	}
	// --region picks one.
	if err := h.run("acm", "certificate", "get", "two.example.com", "--region", "us-east-1"); err != nil {
		t.Errorf("--region = %v", err)
	}
	// A certificate deleted on the platform: exit code 4, and it leaves the inventory.
	h.ec2.acm.certs = slices.DeleteFunc(h.ec2.acm.certs, func(c *fakeCert) bool { return c.arn == gone.arn })
	if err := h.run("acm", "certificate", "get", "gone.example.com"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("deleted = %v", err)
	}
	db, _ := h.rt.DB()
	if _, err := db.Get(context.Background(), inventory.Set{Platform: platform.AWS, Profile: "lab"}, platform.ResCertificate, gone.arn); err == nil {
		t.Error("deleted certificate still in the inventory")
	}
	for _, bad := range []string{"arn:aws:acm:ap-east-1:1:certificate/x", "not a domain"} {
		if err := h.run("acm", "certificate", "get", bad); !ExitUsageErr(err) {
			t.Errorf("%q = %v, want a usage error", bad, err)
		}
	}
	if err := h.run("acm", "certificate", "get", gone.arn, "--region", "us-east-1"); !ExitUsageErr(err) {
		t.Errorf("--region conflict = %v", err)
	}
	h.acm().errs = map[string]error{"DescribeCertificate": &fakeAPIError{"AccessDeniedException", "no"}}
	if err := h.run("acm", "certificate", "get", "arn:aws:acm:ap-east-1:123456789012:certificate/abc"); !errors.Is(err, platform.ErrUnauthorized) ||
		!strings.Contains(err.Error(), "acm:DescribeCertificate") {
		t.Errorf("denied = %v", err)
	}
}

func TestCheckCertName(t *testing.T) {
	for _, ok := range []string{"example.com", "*.example.com", "a-b.example.co", "xn--bcher-kva.example"} {
		if err := checkCertName("domain", ok); err != nil {
			t.Errorf("%q: %v", ok, err)
		}
	}
	for _, bad := range []string{"", "example", "https://example.com", "example.com/x", "exa mple.com", "*.*.example.com", "*.", "-a.example.com",
		"a_b.example.com", "example.c", strings.Repeat("a", 64) + ".com"} {
		if err := checkCertName("domain", bad); !errors.Is(err, app.ErrUsage) {
			t.Errorf("%q = %v, want a usage error", bad, err)
		}
	}
}
