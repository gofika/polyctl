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

// useFakeACMClock makes the certificate waits use a fake clock.
func useFakeACMClock(t *testing.T) *fakeClock {
	t.Helper()
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	old := acmClock
	acmClock = clk
	t.Cleanup(func() { acmClock = old })
	return clk
}

func TestKeyAlgorithmSpellings(t *testing.T) {
	if got := normalizeKeyAlgorithm("EC-prime256v1"); got != "EC_prime256v1" {
		t.Errorf("normalize = %q", got)
	}
	// The response spelling never equals the SDK constant: that is why
	// polyctl normalizes.
	if string(acmtypes.KeyAlgorithmEcPrime256v1) == "EC-prime256v1" {
		t.Error("SDK constant uses hyphens")
	}
	for in, want := range map[string]string{"ec_prime256v1": "EC_prime256v1", "RSA-2048": "RSA_2048", "ml_dsa_65": "ML_DSA_65"} {
		if got, ok := canonicalKeyAlgorithm(in); !ok || got != want {
			t.Errorf("canonical(%q) = %q, %v", in, got, ok)
		}
	}
	if _, ok := canonicalKeyAlgorithm("RSA_512"); ok {
		t.Error("RSA_512 accepted")
	}
	if len(acmSyncKeyTypes) != 7 {
		t.Errorf("sync key types = %v", acmSyncKeyTypes)
	}
}

func TestNormalizeSerial(t *testing.T) {
	if normalizeSerial("0a:1B:2c") != normalizeSerial("0a1b2c") || normalizeSerial("0a:1b") != "a1b" {
		t.Errorf("serials differ: %q %q", normalizeSerial("0a:1B:2c"), normalizeSerial("0a1b2c"))
	}
}

func TestParseACMARN(t *testing.T) {
	a, ok := parseACMARN("arn:aws:acm:ap-east-1:123456789012:certificate/0f1e2d3c-aaaa-bbbb-cccc-0123456789ab")
	if !ok || a.Region != "ap-east-1" || a.Account != "123456789012" || a.ID != "0f1e2d3c-aaaa-bbbb-cccc-0123456789ab" {
		t.Errorf("parse = %+v, %v", a, ok)
	}
	if _, ok := parseACMARN("arn:aws-cn:acm:cn-north-1:123456789012:certificate/abc"); !ok {
		t.Error("aws-cn partition refused")
	}
	for _, bad := range []string{"arn:aws:acm:ap-east-1:1234:certificate/x", "arn:aws:acm:ap-east-1:123456789012:cert/x",
		"arn:aws:elasticloadbalancing:ap-east-1:123456789012:certificate/x", "arn:aws:acm::123456789012:certificate/x",
		"arn:aws:acm:ap-east-1:123456789012:certificate/", "arn:aws:acm:ap-east-1:123456789012:certificate/a b", "example.com"} {
		if _, ok := parseACMARN(bad); ok {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestPickCertificate(t *testing.T) {
	at := func(d int) *time.Time { t := time.Date(2027, 1, d, 0, 0, 0, 0, time.UTC); return &t }
	certs := []platform.Certificate{
		{ID: "expired", Status: acmExpired, NotAfter: at(30)},
		{ID: "pending", Status: acmPendingValidation, CreatedAt: at(20)},
		{ID: "issued-early", Status: acmIssued, NotAfter: at(1)},
		{ID: "issued-late", Status: acmIssued, NotAfter: at(9)},
		{ID: "failed", Status: "FAILED"},
	}
	if got := pickCertificate(certs).ID; got != "issued-late" {
		t.Errorf("pick = %s", got)
	}
	if got := pickCertificate([]platform.Certificate{certs[0], certs[1], certs[4]}).ID; got != "pending" {
		t.Errorf("pick without issued = %s", got)
	}
	// Same state and expiry: the newer one.
	older := platform.Certificate{ID: "a", Status: acmPendingValidation, CreatedAt: at(1)}
	newer := platform.Certificate{ID: "b", Status: acmPendingValidation, CreatedAt: at(2)}
	if got := pickCertificate([]platform.Certificate{older, newer}).ID; got != "b" {
		t.Errorf("pick newer = %s", got)
	}
}

func TestACMErr(t *testing.T) {
	denied := acmErr("RequestCertificate", "ap-east-1", &fakeAPIError{"AccessDeniedException", "nope"})
	if !errors.Is(denied, platform.ErrUnauthorized) || !strings.Contains(denied.Error(), "acm:RequestCertificate") {
		t.Errorf("denied = %v", denied)
	}
	nf := acmErr("DescribeCertificate", "ap-east-1", &acmtypes.ResourceNotFoundException{Message: awssdk.String("x")})
	if !errors.Is(nf, platform.ErrNotFound) || !strings.Contains(nf.Error(), "--region") {
		t.Errorf("not found = %v", nf)
	}
	if nf := acmErr("DescribeCertificate", "ap-east-1", &fakeAPIError{"ResourceNotFoundException", "x"}); !errors.Is(nf, platform.ErrNotFound) {
		t.Errorf("not found by code = %v", nf)
	}
	le := acmErr("RequestCertificate", "ap-east-1", &acmtypes.LimitExceededException{Message: awssdk.String("Certificate has too many domains.")})
	if errors.Is(le, platform.ErrNotFound) || errors.Is(le, platform.ErrUnauthorized) || errors.Is(le, platform.ErrInvalidInput) ||
		!strings.Contains(le.Error(), "Service Quotas") || !strings.Contains(le.Error(), "too many domains") {
		t.Errorf("limit = %v", le)
	}
	ve := acmErr("ImportCertificate", "ap-east-1", &acmtypes.ValidationException{Message: awssdk.String("Key provided does not match the certificate.")})
	if errors.Is(ve, platform.ErrInvalidInput) || !strings.Contains(ve.Error(), "does not match") {
		t.Errorf("validation = %v", ve)
	}
}

func TestListCertificatesPagesAndIncludes(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	h.addCert(&fakeCert{region: "ap-east-1", domain: "*.a.example", status: acmIssued})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "b.example", status: acmIssued, keyAlg: "RSA_2048"})
	h.addCert(&fakeCert{region: "ap-east-1", domain: "c.example", status: acmIssued, keyAlg: "RSA_4096"})
	h.addCert(&fakeCert{region: "eu-west-1", domain: "d.example", status: acmIssued})
	h.acm().pageSize = 1
	c, err := openProfile(context.Background(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	certs, err := c.ListCertificates(context.Background(), platform.CertificateFilter{})
	if err != nil {
		t.Fatal(err)
	}
	if len(certs) != 2 || certs[0].KeyAlgorithm != "EC_prime256v1" || certs[1].KeyAlgorithm != "RSA_2048" || certs[0].Region != "ap-east-1" {
		t.Errorf("certs = %+v", certs)
	}
	lists := h.acm().lists
	if len(lists) != 2 || lists[0].Includes == nil || len(lists[0].Includes.KeyTypes) != 2 || awssdk.ToInt32(lists[0].MaxItems) != 1000 {
		t.Errorf("list inputs = %+v", lists)
	}
}
