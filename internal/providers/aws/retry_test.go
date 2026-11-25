package aws

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/platform"
)

// serverFailure is a 503 with the code EC2 and ACM answer an overloaded
// request with: the request may have been carried out.
type serverFailure struct{}

func (serverFailure) Error() string        { return "api error ServiceUnavailable: try again" }
func (serverFailure) ErrorCode() string    { return "ServiceUnavailable" }
func (serverFailure) ErrorMessage() string { return "try again" }
func (serverFailure) HTTPStatusCode() int  { return 503 }

// throttled is a request AWS refused because of its rate.
var throttled = &fakeAPIError{"RequestLimitExceeded", "Request limit exceeded."}

// ec2CallRetryer and acmCallRetryer return the retryer the SDK client
// would use for a call made with opts: the client's, then the per-call
// options.
func ec2CallRetryer(opts []func(*ec2.Options)) awssdk.Retryer {
	o := ec2.Options{Retryer: retry.NewStandard()}
	for _, fn := range opts {
		fn(&o)
	}
	return o.Retryer
}

func acmCallRetryer(opts []func(*acm.Options)) awssdk.Retryer {
	o := acm.Options{Retryer: retry.AddWithMaxAttempts(retry.NewStandard(), acmMaxAttempts)}
	for _, fn := range opts {
		fn(&o)
	}
	return o.Retryer
}

// noteUnsafeRetry records call when the retryer it was made with would
// repeat it after a failure of unknown outcome.
func (s *fakeEC2s) noteUnsafeRetry(call string, r awssdk.Retryer) {
	if !r.IsErrorRetryable(serverFailure{}) {
		return
	}
	s.retryMu.Lock()
	defer s.retryMu.Unlock()
	s.unsafeRetries = append(s.unsafeRetries, call)
}

func TestRefusedOnlyRetryer(t *testing.T) {
	plain := ec2CallRetryer(nil)
	if !plain.IsErrorRetryable(serverFailure{}) {
		t.Fatal("the standard retryer does not retry a 503: the test error does not exercise it")
	}
	r := ec2CallRetryer([]func(*ec2.Options){ec2NoUnsafeRetry})
	if r.IsErrorRetryable(serverFailure{}) {
		t.Error("a 503 is retried")
	}
	if r.IsErrorRetryable(errors.New("read tcp: connection reset by peer")) {
		t.Error("a broken connection is retried")
	}
	if !r.IsErrorRetryable(throttled) {
		t.Error("a throttled request is not retried")
	}
	if r.MaxAttempts() != retry.DefaultMaxAttempts {
		t.Errorf("MaxAttempts = %d", r.MaxAttempts())
	}
	a := acmCallRetryer([]func(*acm.Options){acmNoUnsafeRetry})
	if a.IsErrorRetryable(serverFailure{}) || !a.IsErrorRetryable(throttled) || a.MaxAttempts() != acmMaxAttempts {
		t.Errorf("ACM retryer: 503 %v, throttled %v, attempts %d", a.IsErrorRetryable(serverFailure{}), a.IsErrorRetryable(throttled), a.MaxAttempts())
	}
	if !platform.OutcomeUnknown(serverFailure{}) {
		t.Error("a 503 is not of unknown outcome")
	}
}

// The creates without an idempotency token are made without the SDK's
// retry of a failure of unknown outcome; a re-import into an ARN keeps it.
func TestNonIdempotentCreatesAreNotRetried(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ctx := context.Background()
	c, err := openProfile(ctx, h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := c.createKeyPairRSA(ctx, "ap-east-1", "kp-a", nil); err != nil {
		t.Fatal(err)
	}
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0aaa", size: 8})
	if _, err := c.createSnapshot(ctx, "ap-east-1", "vol-0aaa", "", nil); err != nil {
		t.Fatal(err)
	}
	b, _, _ := issue(t, certtest.New("Test Issuer"), "example.com", nil, time.Now().Add(90*24*time.Hour))
	arn, err := c.ImportCertificate(ctx, platform.CertificateImport{Region: "ap-east-1", Cert: b.CertPEM, Chain: b.ChainPEM, Key: b.PrivKeyPEM})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.ImportCertificate(ctx, platform.CertificateImport{Region: "ap-east-1", ARN: arn, Cert: b.CertPEM, Chain: b.ChainPEM, Key: b.PrivKeyPEM}); err != nil {
		t.Fatal(err)
	}
	h.ec2.retryMu.Lock()
	got := strings.Join(h.ec2.unsafeRetries, ",")
	h.ec2.retryMu.Unlock()
	if got != "" {
		t.Errorf("retried after an unknown outcome: %s", got)
	}
	if h.ec2.reimportRetried != 1 {
		t.Errorf("re-imports made with the client's retryer = %d, want 1", h.ec2.reimportRetried)
	}
}

// A create whose outcome is unknown says what may have been left behind.
func TestNonIdempotentCreateUnknownOutcome(t *testing.T) {
	h := newAWSHarness(t, app.Flags{}, nil)
	ctx := context.Background()
	c, err := openProfile(ctx, h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	h.ec2.inst.errs = map[string]error{"CreateKeyPair": serverFailure{}}
	_, _, err = c.createKeyPairRSA(ctx, "ap-east-1", "kp-a", nil)
	if err == nil || !strings.Contains(err.Error(), "may have been created") || !strings.Contains(err.Error(), "delete-key-pair --region ap-east-1 --key-name kp-a") {
		t.Errorf("CreateKeyPair: %v", err)
	}
	h.ec2.inst.errs = map[string]error{"CreateKeyPair": throttled}
	if _, _, err := c.createKeyPairRSA(ctx, "ap-east-1", "kp-a", nil); err == nil || strings.Contains(err.Error(), "may have been") {
		t.Errorf("a refused CreateKeyPair: %v", err)
	}
	h.addVolume("ap-east-1", &fakeVol{id: "vol-0aaa", size: 8})
	h.ebsSetErr("CreateSnapshot", serverFailure{})
	if _, err := c.createSnapshot(ctx, "ap-east-1", "vol-0aaa", "", nil); err == nil || !strings.Contains(err.Error(), "may have been created") {
		t.Errorf("CreateSnapshot: %v", err)
	}
	h.acm().errs = map[string]error{"ImportCertificate": serverFailure{}}
	b, _, _ := issue(t, certtest.New("Test Issuer"), "example.com", nil, time.Now().Add(90*24*time.Hour))
	if _, err := c.ImportCertificate(ctx, platform.CertificateImport{Region: "ap-east-1", Cert: b.CertPEM, Chain: b.ChainPEM, Key: b.PrivKeyPEM}); err == nil || !strings.Contains(err.Error(), "may have been imported") {
		t.Errorf("ImportCertificate: %v", err)
	}
}
