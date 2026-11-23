package platform

import (
	"errors"
	"slices"
)

// ErrForbidden marks a request that valid credentials were not allowed to
// make: a RAM / IAM policy denial, or an account that the platform refuses
// to serve until something is done in its console (basic information not
// completed, real-name verification missing). It maps to the
// authentication exit code like ErrUnauthorized, but it is not a reason to
// log in again, and a sync goes on with the other resource types after it.
var ErrForbidden = errors.New("forbidden")

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
