package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

type requestOut struct {
	platform.Report
	ARN               string              `json:"arn"`
	ValidationRecords []acmValidationView `json:"validation_records"`
}

func (h *awsHarness) requestOut() requestOut {
	h.t.Helper()
	var out requestOut
	h.jsonOut(&out)
	return out
}

func TestACMRequest(t *testing.T) {
	h, clk := newACMHarness(t, app.Flags{}, map[string]any{"tags": map[string]any{"team": "ops"}})
	h.acm().dvoAfter, h.acm().recordsAfter = 1, 3

	if err := h.run("acm", "certificate", "request", "example.com", "--tag", "env=prod"); err != nil {
		t.Fatalf("request: %v\n%s", err, h.stderr.String())
	}
	if w := h.acmWrites(); len(w) != 1 {
		t.Fatalf("writes = %v", w)
	}
	in := h.acm().requests[0]
	tags := map[string]string{}
	for _, tg := range in.Tags {
		tags[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
	}
	if awssdk.ToString(in.DomainName) != "*.example.com" || strings.Join(in.SubjectAlternativeNames, ",") != "example.com" ||
		in.ValidationMethod != acmtypes.ValidationMethodDns || in.KeyAlgorithm != "EC_prime256v1" || len(awssdk.ToString(in.IdempotencyToken)) != 32 ||
		tags["team"] != "ops" || tags["env"] != "prod" {
		t.Errorf("request input = %+v, tags %v", in, tags)
	}
	// The records showed up after a few polls 2 seconds apart.
	if len(clk.slept) != 3 || clk.slept[0] != 2*time.Second {
		t.Errorf("slept = %v", clk.slept)
	}
	out := h.requestOut()
	a := actions(out.Report)
	if a["certificate/example.com created"] != 1 || a["certificate/example.com/validation created"] != 1 {
		t.Errorf("changes = %v", a)
	}
	// The wildcard and the bare name share one record.
	if len(out.ValidationRecords) != 1 || out.ARN == "" || !strings.HasPrefix(out.ValidationRecords[0].Name, "_") ||
		!strings.HasSuffix(out.ValidationRecords[0].Value, ".acm-validations.aws.") || out.ValidationRecords[0].Type != "CNAME" {
		t.Errorf("out = %+v", out)
	}
	if out.Target.Region != "ap-east-1" || out.Target.Profile != "lab" || out.DryRun {
		t.Errorf("target = %+v", out.Target)
	}
	if s := h.stderr.String(); !strings.Contains(s, "polyctl dns ensure example.com --record _") || !strings.Contains(s, ":300:false") || !strings.Contains(s, "renews") {
		t.Errorf("stderr = %s", s)
	}
	token := awssdk.ToString(in.IdempotencyToken)

	// A second run finds the certificate: no write, unchanged, the records again.
	h.resetACM()
	if err := h.run("acm", "certificate", "request", "*.example.com"); err != nil {
		t.Fatal(err)
	}
	if w := h.acmWrites(); len(w) != 0 {
		t.Errorf("second run writes = %v", w)
	}
	out = h.requestOut()
	if a := actions(out.Report); a["certificate/example.com unchanged"] != 1 || a["certificate/example.com/validation unchanged"] != 1 || len(out.ValidationRecords) != 1 {
		t.Errorf("second run = %+v", out)
	}
	if l := h.acm().lists[0]; len(l.Includes.KeyTypes) != 1 || l.Includes.KeyTypes[0] != "EC_prime256v1" {
		t.Errorf("lookup input = %+v", l)
	}

	// Other names: a new certificate, and a note about the existing one.
	h.resetACM()
	if err := h.run("acm", "certificate", "request", "example.com", "--san", "www.example.net", "--san", "WWW.example.net"); err != nil {
		t.Fatal(err)
	}
	if w := h.acmWrites(); len(w) != 1 || !strings.Contains(h.stderr.String(), "other names") {
		t.Errorf("writes = %v, stderr %s", w, h.stderr.String())
	}
	in = h.acm().requests[0]
	if strings.Join(in.SubjectAlternativeNames, ",") != "example.com,www.example.net" || awssdk.ToString(in.IdempotencyToken) == token {
		t.Errorf("san request = %+v", in)
	}
	// Different names have different records.
	if out := h.requestOut(); len(out.ValidationRecords) != 2 {
		t.Errorf("records = %+v", out.ValidationRecords)
	}
	// dns ensure reads names relative to the zone, which may be a parent of
	// the domain: full names, and a command per domain outside it.
	if s := h.stderr.String(); !strings.Contains(s, "polyctl dns ensure example.com --record _") ||
		!strings.Contains(s, "polyctl dns ensure www.example.net --record _") || !strings.Contains(s, ".www.example.net:CNAME:") {
		t.Errorf("stderr = %s", s)
	}

	// A subdomain: the record names stay full, so a zone of the parent
	// domain gets them at the right place.
	h.resetACM()
	if err := h.run("acm", "certificate", "request", "app.example.com", "--wildcard=false"); err != nil {
		t.Fatal(err)
	}
	if s := h.stderr.String(); !strings.Contains(s, "polyctl dns ensure app.example.com --record _") || !strings.Contains(s, ".app.example.com:CNAME:") {
		t.Errorf("subdomain stderr = %s", s)
	}

	// --wildcard=false and another key algorithm.
	h.resetACM()
	if err := h.run("acm", "certificate", "request", "example.com", "--wildcard=false", "--key-algorithm", "RSA_2048", "--no-wait"); err != nil {
		t.Fatal(err)
	}
	in = h.acm().requests[0]
	if awssdk.ToString(in.DomainName) != "example.com" || in.SubjectAlternativeNames != nil || in.KeyAlgorithm != "RSA_2048" {
		t.Errorf("--wildcard=false input = %+v", in)
	}
	// --no-wait reads the certificate once.
	n := 0
	for _, c := range h.acmCalls() {
		if c == "DescribeCertificate" {
			n++
		}
	}
	if n != 1 || !strings.Contains(h.stderr.String(), "not published yet") {
		t.Errorf("describes = %d, stderr %s", n, h.stderr.String())
	}
}

func TestACMRequestTruncatedNamesAndIssued(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	c := h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", names: []string{"*.example.com", "example.com", "a.example.org"}, status: acmIssued, truncated: true})
	if err := h.run("acm", "certificate", "request", "example.com", "--san", "a.example.org"); err != nil {
		t.Fatal(err)
	}
	out := h.requestOut()
	if len(h.acmWrites()) != 0 || out.ARN != c.arn || actions(out.Report)["certificate/example.com unchanged"] != 1 {
		t.Errorf("out = %+v, writes %v", out, h.acmWrites())
	}
}

func TestACMRequestDryRun(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{DryRun: true}, nil)
	if err := h.run("acm", "certificate", "request", "example.com"); err != nil {
		t.Fatal(err)
	}
	out := h.requestOut()
	if len(h.acmWrites()) != 0 || !out.DryRun || out.ARN != platform.Pending || len(out.ValidationRecords) != 0 || len(out.Changes) != 2 ||
		out.Changes[0].Action != platform.WouldCreate || out.Changes[1].Action != platform.Skipped || !strings.Contains(out.Changes[1].Detail, "after request") {
		t.Errorf("dry run = %+v", out)
	}
	// An existing certificate is unchanged in a dry run too.
	h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", names: []string{"*.example.com", "example.com"}, status: acmIssued})
	if err := h.run("acm", "certificate", "request", "example.com"); err != nil {
		t.Fatal(err)
	}
	if out := h.requestOut(); out.Changes[0].Action != platform.Unchanged || len(h.acmWrites()) != 0 {
		t.Errorf("dry run existing = %+v", out)
	}
}

func TestACMRequestFailures(t *testing.T) {
	h, clk := newACMHarness(t, app.Flags{}, nil)
	// Records that never come: the wait times out, the certificate stays.
	h.acm().dvoAfter, h.acm().recordsAfter = 0, 1_000_000
	err := h.run("acm", "certificate", "request", "slow.example.org", "--timeout", "10s")
	var te *platform.WaitTimeoutError
	if !errors.As(err, &te) || !strings.Contains(err.Error(), "--validation-records") {
		t.Fatalf("timeout = %v", err)
	}
	out := h.requestOut()
	if a := actions(out.Report); a["certificate/slow.example.org created"] != 1 || a["certificate/slow.example.org/validation failed"] != 1 || out.ARN == "" {
		t.Errorf("timeout report = %+v", out)
	}
	if len(clk.slept) == 0 {
		t.Error("no poll")
	}

	// A certificate that fails (ACM refuses the name) ends the wait at once.
	h.acm().dvoAfter, h.acm().recordsAfter, h.acm().fail = 1, 1, true
	clk.slept = nil
	err = h.run("acm", "certificate", "request", "sub.example.com")
	if err == nil || !strings.Contains(err.Error(), "FAILED (ADDITIONAL_VERIFICATION_REQUIRED)") || errors.As(err, &te) || len(clk.slept) != 1 {
		t.Errorf("failed certificate = %v (slept %v)", err, clk.slept)
	}
	h.acm().fail = false

	// Errors of the request.
	h.acm().errs = map[string]error{"RequestCertificate": &acmtypes.LimitExceededException{Message: awssdk.String("Certificate has too many domains.")}}
	err = h.run("acm", "certificate", "request", "other.example.com")
	if err == nil || !strings.Contains(err.Error(), "Service Quotas") || errors.Is(err, platform.ErrInvalidInput) || errors.Is(err, app.ErrUsage) {
		t.Errorf("limit = %v", err)
	}
	h.acm().errs = map[string]error{"ListCertificates": &fakeAPIError{"AccessDeniedException", "no"}}
	if err := h.run("acm", "certificate", "request", "other.example.com"); !errors.Is(err, platform.ErrUnauthorized) || !strings.Contains(err.Error(), "acm:ListCertificates") {
		t.Errorf("denied = %v", err)
	}
	h.acm().errs = nil

	// Usage errors: nothing is sent.
	h.resetACM()
	for _, args := range [][]string{
		{"exa mple.com"}, {"https://example.com"}, {"*.*.example.com"}, {"example.com", "--key-algorithm", "RSA_512"},
		{"example.com", "--san", "example.com"}, {"example.com", "--san", "*.example.com"}, {"example.com", "--wildcard=false", "--san", "example.com"},
		{"*.example.com", "--wildcard=false"}, {"example.com", "--tag", "novalue"}, {"example.com", "--timeout", "0s"},
	} {
		if err := h.run(append([]string{"acm", "certificate", "request"}, args...)...); !ExitUsageErr(err) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
	if c := h.acmCalls(); len(c) != 0 {
		t.Errorf("usage errors called %v", c)
	}
}

func TestValidationProblem(t *testing.T) {
	cert := &platform.Certificate{ID: "a", Validation: []platform.ValidationRecord{{Domain: "x.example.com", Status: "FAILED", Method: "DNS"}}}
	if err := validationProblem(cert); err == nil || !strings.Contains(err.Error(), "x.example.com FAILED") {
		t.Errorf("failed validation = %v", err)
	}
	cert.Validation[0] = platform.ValidationRecord{Domain: "x.example.com", Method: "EMAIL"}
	if err := validationProblem(cert); err == nil || !strings.Contains(err.Error(), "EMAIL") {
		t.Errorf("email validation = %v", err)
	}
}

// A run after the certificate of an earlier run failed or was deleted
// requests a new certificate: the token of each run is fresh, so ACM does
// not hand back the old ARN.
func TestACMRequestRerunAfterFailedOrDeleted(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	h.acm().dvoAfter, h.acm().recordsAfter = 0, 0
	if err := h.run("acm", "certificate", "request", "example.com"); err != nil {
		t.Fatal(err)
	}
	first := h.requestOut().ARN
	// CAA blocked it after its records were published.
	h.ec2.mu.Lock()
	h.acm().certs[0].status = "FAILED"
	h.ec2.mu.Unlock()
	h.resetACM()
	if err := h.run("acm", "certificate", "request", "example.com"); err != nil {
		t.Fatalf("rerun after FAILED: %v", err)
	}
	second := h.requestOut().ARN
	if second == first || len(h.acm().certs) != 2 {
		t.Errorf("rerun after FAILED = %s (first %s), %d certificates", second, first, len(h.acm().certs))
	}
	// Deleted.
	h.ec2.mu.Lock()
	h.acm().certs = h.acm().certs[:1]
	h.ec2.mu.Unlock()
	h.resetACM()
	if err := h.run("acm", "certificate", "request", "example.com"); err != nil {
		t.Fatalf("rerun after delete: %v", err)
	}
	if third := h.requestOut().ARN; third == second || third == first {
		t.Errorf("rerun after delete = %s", third)
	}
}

// A FAILED certificate whose records were published does not count as a
// finished wait.
func TestWaitValidationRecordsFailedWithRecords(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	c := h.addCert(&fakeCert{region: "ap-east-1", domain: "example.com", status: "FAILED", failure: "CAA_ERROR"})
	cl := &client{region: "ap-east-1", acmFor: func(r string) acmAPI { return newACM(awssdk.Config{Region: r}) }}
	if _, err := cl.waitValidationRecords(context.Background(), "ap-east-1", c.arn, true, time.Minute); err == nil || !strings.Contains(err.Error(), "FAILED") {
		t.Errorf("failed certificate with records = %v", err)
	}
}
