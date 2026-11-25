package aws

import (
	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/aws/retry"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
)

// The SDK's standard retryer repeats a call after a 5xx response or a
// broken connection, whether or not the call is idempotent. For a create
// without an idempotency token (CreateKeyPair, ImportCertificate of a new
// certificate, CreateSnapshot) the first attempt may have been carried
// out, and repeating it either fails with a misleading error (the key pair
// "already exists", its private key is lost; a snapshot "is in progress")
// or creates a second resource (a duplicate imported certificate). Those
// calls use refusedOnlyRetryables instead: only the errors that mean AWS
// did not process the request (throttling, 429) are retried; any other
// failure is returned with its outcome unknown (platform.OutcomeUnknown),
// as internal/httpx does for POST and PATCH.
var refusedOnlyRetryables = []retry.IsErrorRetryable{
	retry.NoRetryCanceledError{},
	retry.RetryableHTTPStatusCode{Codes: map[int]struct{}{429: {}}},
	retry.RetryableErrorCode{Codes: retry.DefaultThrottleErrorCodes},
}

// refusedOnlyRetryer returns a standard retryer with the attempt count of
// cur that retries only refused requests (refusedOnlyRetryables).
func refusedOnlyRetryer(cur awssdk.Retryer) awssdk.Retryer {
	attempts := retry.DefaultMaxAttempts
	if cur != nil {
		attempts = cur.MaxAttempts()
	}
	return retry.NewStandard(func(o *retry.StandardOptions) {
		o.MaxAttempts = attempts
		o.Retryables = refusedOnlyRetryables
	})
}

// ec2NoUnsafeRetry is the per-call option of an EC2 create that is not
// idempotent.
func ec2NoUnsafeRetry(o *ec2.Options) { o.Retryer = refusedOnlyRetryer(o.Retryer) }

// acmNoUnsafeRetry is the per-call option of an ACM import of a new
// certificate (a re-import into an ARN is idempotent and keeps the
// client's retryer).
func acmNoUnsafeRetry(o *acm.Options) { o.Retryer = refusedOnlyRetryer(o.Retryer) }
