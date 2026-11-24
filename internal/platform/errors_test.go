package platform

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

type codedErr struct{ code string }

func (e codedErr) Error() string     { return "api: " + e.code }
func (e codedErr) ErrorCode() string { return e.code }

func TestErrorCodeMatchesWholeCodes(t *testing.T) {
	err := fmt.Errorf("wrapped: %w", codedErr{"DBSubnetGroupNotFoundFault"})
	if got := ErrorCode(err); got != "DBSubnetGroupNotFoundFault" {
		t.Fatalf("ErrorCode = %q", got)
	}
	if HasErrorCode(err, "DBSubnetGroupNotFound") {
		t.Error("a code must not match with its Fault suffix trimmed")
	}
	if !HasErrorCode(err, "Other", "DBSubnetGroupNotFoundFault") {
		t.Error("exact code not matched")
	}
	if ErrorCode(errors.New("plain")) != "" || HasErrorCode(nil, "") {
		t.Error("an error without a code has none")
	}
}

func TestOutcomeUnknown(t *testing.T) {
	for _, err := range []error{errors.New("connection reset"), context.DeadlineExceeded, codedErr{"SDK.TimeoutError"}, codedErr{"InternalError"}} {
		if !OutcomeUnknown(fmt.Errorf("run: %w", err)) {
			t.Errorf("%v: want unknown", err)
		}
	}
	for _, err := range []error{nil, codedErr{"InsufficientInstanceCapacity"}, codedErr{"InvalidParameter"}} {
		if OutcomeUnknown(err) {
			t.Errorf("%v: want a definite outcome", err)
		}
	}
}
