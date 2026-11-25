package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// When routing indexes the accounts and every one fails to sync, a domain
// it cannot find is not "unknown" (exit code 4): the failure is reported,
// exit code 3 for credentials, 1 otherwise.
func TestRoutingIndexFailureIsNotUnknown(t *testing.T) {
	for _, tc := range []struct {
		name string
		err  error
		code int
	}{
		{"credentials", fmt.Errorf("%w: token rejected", platform.ErrUnauthorized), ExitAuth},
		{"network", errors.New("dial tcp: connection refused"), ExitError},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, cfgPath := setup(t, true)
			fc := client("a")
			fc.zones = []platform.Zone{{ID: "z1", Name: "example.com"}}
			fc.syncErrs = map[platform.ResourceType]error{platform.ResZone: tc.err, platform.ResDomain: tc.err}
			for _, args := range [][]string{
				{"dns", "list", "example.com", "-o", "json"},
				{"dns", "list", "example.com", "--refresh", "-o", "json"},
				{"domain", "which", "example.com"},
				{"domain", "which", "example.com", "--refresh"},
			} {
				_, stderr, err := run(t, cfgPath, args...)
				if ExitCodeFor(err) != tc.code || !strings.Contains(err.Error(), "could not index") {
					t.Errorf("%v = %v (exit %d), want exit %d (%s)", args, err, ExitCodeFor(err), tc.code, stderr)
				}
			}
			// domain list --refresh prints the index as it stands and
			// fails as domain index does.
			out, _, err := run(t, cfgPath, "domain", "list", "--refresh", "-o", "json")
			if ExitCodeFor(err) != tc.code || strings.TrimSpace(out) != "[]" {
				t.Errorf("domain list --refresh = %q, %v (exit %d)", out, err, ExitCodeFor(err))
			}
			// Once the sync works, an unknown domain is exit code 4 again.
			fc.syncErrs = nil
			if _, _, err := run(t, cfgPath, "dns", "list", "nosuch.org", "--refresh"); ExitCodeFor(err) != ExitNotFound {
				t.Errorf("unknown domain = %v", err)
			}
			if _, _, err := run(t, cfgPath, "domain", "list", "--refresh"); err != nil {
				t.Errorf("domain list --refresh = %v", err)
			}
		})
	}
}

// domain which only reports: indexing for it never asks which owner,
// even when several accounts hold the domain.
func TestDomainWhichNeverAsks(t *testing.T) {
	_, cfgPath := setupMulti(t)
	zones := []platform.Zone{{ID: "z1", Name: "example.com"}}
	client("a").zones, clientOn("a", fakePlatform2).zones, clientOn("b", fakePlatform2).zones = zones, zones, zones
	p := prompttest.New(t)
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "domain", "which", "example.com", "-o", "json")
	if r.err != nil || strings.Count(r.stdout, `"resource_id": "z1"`) != 3 {
		t.Fatalf("which = %v, %q (%s)", r.err, r.stdout, r.stderr)
	}
	p.Done()
}
