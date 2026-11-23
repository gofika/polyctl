package gcp

import (
	"errors"
	"fmt"
	"net/http"
	"strings"

	"google.golang.org/api/compute/v1"
	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/platform"
)

// Compute Engine errors come in two layers, and every write checks both:
//
//   - at submission, the call itself fails with a *googleapi.Error whose
//     reason is googleapi.Error.Errors[0].Reason ("notFound",
//     "alreadyExists", "resourceNotReady", "invalid", ...);
//   - the call is accepted but the Operation finishes with an error, whose
//     codes are in Operation.Error.Errors[i].Code
//     ("UNSUPPORTED_OPERATION", "IP_IN_USE_BY_ANOTHER_RESOURCE", ...).
//
// Quota and capacity errors are general failures (exit code 1) whatever
// HTTP status carries them: the cause is the resource, not a permission.
// Their exact statuses and reasons, and those of a disabled API, could not
// be observed, so they are recognised by several spellings.

// capacityMarkers name quota and capacity problems in reasons, codes and
// messages.
var capacityMarkers = []string{"QUOTA_EXCEEDED", "quotaExceeded", "ZONE_RESOURCE_POOL_EXHAUSTED", "RESOURCE_POOL_EXHAUSTED",
	"rateLimitExceeded", "userRateLimitExceeded"}

func isCapacity(s string) bool { return containsAny(s, capacityMarkers...) }

// isCapacityMessage reports a quota or capacity problem told by an error
// message only. A bare "quota" is not enough: a 403 about a missing quota
// project (Application Default Credentials without one) is a credentials
// problem and must stay exit code 3.
func isCapacityMessage(msg string) bool {
	if isCapacity(msg) {
		return true
	}
	m := strings.ToLower(msg)
	return strings.Contains(m, "quota") && containsAny(m, "exceeded", "exhausted") ||
		strings.Contains(m, "does not have enough resources")
}

// capacityHint is appended to quota and capacity failures.
const capacityHint = "quota or capacity, not a permission problem: try another zone or machine type, or ask for a higher quota"

// computeErr maps a Compute Engine error at submission to the platform
// sentinels: 401 and 403 are authentication errors (with a hint telling a
// disabled Compute Engine API from a missing permission), except quota and
// capacity errors, which stay general failures; 404, and 400 for a machine
// type that does not exist in the zone, are "not found".
func computeErr(err error) error {
	if err == nil {
		return nil
	}
	var ge *googleapi.Error
	if !errors.As(err, &ge) {
		return mapErr(err)
	}
	reason := googleReason(err)
	if isCapacity(reason) || isCapacityMessage(ge.Message) {
		return fmt.Errorf("%w (%s)", err, capacityHint)
	}
	switch ge.Code {
	case http.StatusUnauthorized:
		return fmt.Errorf("%w: %w", platform.ErrUnauthorized, err)
	case http.StatusForbidden:
		if reason == "accessNotConfigured" || strings.Contains(ge.Message, "has not been used") || strings.Contains(ge.Message, "is disabled") {
			return fmt.Errorf("%w: the Compute Engine API is not enabled for the project: %w", platform.ErrUnauthorized, err)
		}
		return fmt.Errorf("%w: the credentials lack a Compute Engine permission (compute.instances.*, compute.addresses.*, compute.firewalls.*, compute.sslCertificates.*, compute.targetHttpsProxies.setSslCertificates, ...): %w", platform.ErrUnauthorized, err)
	case http.StatusNotFound:
		return fmt.Errorf("%w: %w", platform.ErrNotFound, err)
	case http.StatusBadRequest:
		msg := strings.ToLower(ge.Message)
		if strings.Contains(msg, "machine type") && strings.Contains(msg, "does not exist") {
			return fmt.Errorf("%w: %w", platform.ErrNotFound, err)
		}
	}
	return err
}

// isReason reports whether err is a submission error with that reason.
func isReason(err error, reason string) bool { return googleReason(err) == reason }

// isFingerprintMismatch reports the error of a write with a stale
// fingerprint: 400 "invalid" with "Fingerprint mismatch" for an instance
// Update, 412 "conditionNotMet" for SetTags.
func isFingerprintMismatch(err error) bool {
	var ge *googleapi.Error
	if !errors.As(err, &ge) {
		return false
	}
	return ge.Code == http.StatusPreconditionFailed || strings.Contains(strings.ToLower(ge.Message), "fingerprint")
}

// OperationError is the error of an Operation that finished with errors.
// It carries the first error code as the platform error code.
type OperationError struct {
	Operation string
	Type      string
	Codes     []string
	Messages  []string
}

func (e *OperationError) Error() string {
	var parts []string
	for i, c := range e.Codes {
		parts = append(parts, c+": "+e.Messages[i])
	}
	msg := fmt.Sprintf("operation %s", e.Operation)
	if e.Type != "" {
		msg += " (" + e.Type + ")"
	}
	msg += " failed: " + strings.Join(parts, "; ")
	if isCapacity(strings.Join(e.Codes, " ")) || isCapacityMessage(strings.Join(e.Messages, " ")) {
		msg += " (" + capacityHint + ")"
	}
	return msg
}

// ErrorCode is the first error code of the operation.
func (e *OperationError) ErrorCode() string {
	if len(e.Codes) == 0 {
		return ""
	}
	return e.Codes[0]
}

var _ platform.CodedError = (*OperationError)(nil)

// opError returns the error of a finished operation, or nil.
func opError(op *compute.Operation) error {
	if op == nil || op.Error == nil || len(op.Error.Errors) == 0 {
		return nil
	}
	e := &OperationError{Operation: op.Name, Type: op.OperationType}
	for _, x := range op.Error.Errors {
		e.Codes = append(e.Codes, x.Code)
		e.Messages = append(e.Messages, x.Message)
	}
	return e
}
