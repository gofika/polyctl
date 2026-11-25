package gcp

import (
	"errors"
	"fmt"
	"testing"

	"google.golang.org/api/googleapi"

	"github.com/gofika/polyctl/internal/platform"
)

// A project whose API is off or whose billing is off is told apart from
// every other failure: only a 403 that names one of those causes, and
// never a quota or capacity answer.
func TestIsAPIDisabled(t *testing.T) {
	reason := func(r string) []googleapi.ErrorItem { return []googleapi.ErrorItem{{Reason: r}} }
	info := func(r string) []any {
		return []any{map[string]any{"@type": "type.googleapis.com/google.rpc.ErrorInfo", "reason": r, "domain": "googleapis.com"}}
	}
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"accessNotConfigured", &googleapi.Error{Code: 403, Errors: reason("accessNotConfigured")}, true},
		{"SERVICE_DISABLED reason", &googleapi.Error{Code: 403, Errors: reason("SERVICE_DISABLED")}, true},
		{"billingNotEnabled", &googleapi.Error{Code: 403, Errors: reason("billingNotEnabled")}, true},
		{"BILLING_DISABLED reason", &googleapi.Error{Code: 403, Errors: reason("BILLING_DISABLED")}, true},
		{"SERVICE_DISABLED in the details", &googleapi.Error{Code: 403, Errors: reason("forbidden"), Details: info("SERVICE_DISABLED")}, true},
		{"BILLING_DISABLED in the details", &googleapi.Error{Code: 403, Details: info("BILLING_DISABLED")}, true},
		{"message: has not been used", &googleapi.Error{Code: 403, Message: "Compute Engine API has not been used in project 12 before or it is disabled."}, true},
		{"message: is disabled", &googleapi.Error{Code: 403, Message: "Cloud DNS API is disabled for the project"}, true},
		{"message: requires billing", &googleapi.Error{Code: 403, Message: "This API method requires billing to be enabled. Please enable billing on project #12."}, true},
		{"message: billing is disabled", &googleapi.Error{Code: 403, Message: "Billing is disabled for project p2"}, true},
		{"wrapped by the error mappers", computeErr(&googleapi.Error{Code: 403, Errors: reason("accessNotConfigured")}), true},
		{"wrapped twice", fmt.Errorf("project p2: %w", mapErr(&googleapi.Error{Code: 403, Details: info("SERVICE_DISABLED")})), true},

		{"missing permission", &googleapi.Error{Code: 403, Errors: reason("forbidden"), Message: "Required 'compute.instances.list' permission for 'projects/p2'"}, false},
		{"IAM denial in the details", &googleapi.Error{Code: 403, Details: info("IAM_PERMISSION_DENIED")}, false},
		{"quota reason", &googleapi.Error{Code: 403, Errors: reason("quotaExceeded"), Message: "Quota exceeded; the API is disabled until it resets"}, false},
		{"rate limit reason", &googleapi.Error{Code: 403, Errors: reason("rateLimitExceeded")}, false},
		{"quota in the details", &googleapi.Error{Code: 403, Errors: reason("accessNotConfigured"), Details: info("RATE_LIMIT_EXCEEDED")}, false},
		{"quota message", &googleapi.Error{Code: 403, Message: "Quota exceeded for quota metric 'Queries'; billing is disabled"}, false},
		{"401", &googleapi.Error{Code: 401, Errors: reason("accessNotConfigured")}, false},
		{"404", &googleapi.Error{Code: 404, Message: "The resource is disabled"}, false},
		{"500", &googleapi.Error{Code: 500, Errors: reason("SERVICE_DISABLED")}, false},
		{"details of another shape", &googleapi.Error{Code: 403, Details: []any{"SERVICE_DISABLED", map[string]any{"reason": 7}}}, false},
		{"not an API error", errors.New("dial tcp: connection refused, the network is disabled"), false},
		{"a sentinel alone", platform.ErrUnauthorized, false},
		{"nil", nil, false},
	}
	for _, tc := range cases {
		if got := isAPIDisabled(tc.err); got != tc.want {
			t.Errorf("%s: isAPIDisabled = %v, want %v (%v)", tc.name, got, tc.want, tc.err)
		}
	}
}
