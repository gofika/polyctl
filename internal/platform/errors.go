package platform

import (
	"context"
	"errors"
	"slices"
	"strings"
)

// ErrForbidden marks a request that valid credentials were not allowed to
// make: a RAM / IAM policy denial, or an account that the platform refuses
// to serve until something is done in its console (basic information not
// completed, real-name verification missing). It maps to the
// authentication exit code like ErrUnauthorized, but it is not a reason to
// log in again, and a sync goes on with the other resource types after it.
var ErrForbidden = errors.New("forbidden")

// ErrInvalidInput marks input the caller has to correct: a malformed flag
// value, a missing value the non-interactive flow cannot ask for. It maps
// to the usage exit code (2), like app.ErrUsage, for code below the app
// package.
var ErrInvalidInput = errors.New("invalid input")

// ErrAmbiguous marks a choice polyctl cannot make on its own (several
// resources match). It maps to the ambiguity exit code (5).
var ErrAmbiguous = errors.New("ambiguous")

// ErrNothingToDo marks a command that found nothing to act on, or a
// question the user left: not a failure. It maps to exit code 0, and the
// message is printed as a note.
var ErrNothingToDo = errors.New("nothing to do")

// CodedError is an API error that carries the platform's own error code
// (smithy.APIError for AWS, the Alibaba Cloud error of the aliyun provider,
// ...). Codes are compared as whole strings: a code is never trimmed (no
// "Fault" suffix stripping) before it is matched.
type CodedError interface {
	error
	ErrorCode() string
}

// ErrorCode returns the platform error code carried by err (anywhere in its
// chain), or "" when it carries none.
func ErrorCode(err error) string {
	var ce CodedError
	if errors.As(err, &ce) {
		return ce.ErrorCode()
	}
	return ""
}

// HasErrorCode reports whether err carries one of codes, compared exactly.
func HasErrorCode(err error, codes ...string) bool {
	code := ErrorCode(err)
	return code != "" && slices.Contains(codes, code)
}

// serverFailureCodes are the codes of a server-side failure, after which a
// write may or may not have been carried out.
var serverFailureCodes = []string{"InternalError", "InternalFailure", "ServiceUnavailable", "Unavailable", "UnknownError"}

// OutcomeUnknown reports whether a failed write may still have been carried
// out: the error carries no platform error code (a transport failure, a
// request cancelled or timed out after it was sent), a client-side SDK code
// (Alibaba Cloud "SDK.*": timeouts, an unreachable server) or a server-side
// failure code. An error with any other code is a definite refusal.
func OutcomeUnknown(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	code := ErrorCode(err)
	return code == "" || strings.HasPrefix(code, "SDK.") || slices.Contains(serverFailureCodes, code)
}
