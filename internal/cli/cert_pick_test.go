package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// cert get and cert deploy without a domain offer the store; an empty
// store is nothing to do.
func TestCertPicksFromTheStore(t *testing.T) {
	_, cfgPath := setup(t, true)
	for _, args := range [][]string{{"cert", "get"}, {"cert", "deploy"}} {
		r := runFlow(t, context.Background(), cfgPath, prompttest.New(t), strings.NewReader(""), args...)
		if r.code != ExitOK || !strings.Contains(r.err.Error(), "holds no certificate") {
			t.Errorf("%v with an empty store: exit %d, %v", args, r.code, r.err)
		}
	}
	r := runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "cert", "deploy")
	if r.code != ExitUsage || !strings.Contains(r.err.Error(), "name a domain or pass --all") {
		t.Errorf("non-interactive deploy: exit %d, %v", r.code, r.err)
	}
}
