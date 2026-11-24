package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// find without the query asks for it, checked as it is typed.
func TestFindAsksTheQuery(t *testing.T) {
	_, cfgPath := setup(t, true)
	p := prompttest.New(t, "not an address!", "203.0.113.10")
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "find", "--offline")
	if r.code == ExitUsage || len(p.Asked) != 2 {
		t.Errorf("find: exit %d, %v, asked %v", r.code, r.err, p.Titles())
	}
	p.Done()
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "find")
	if r.code != ExitUsage {
		t.Errorf("non-interactive: exit %d, %v", r.code, r.err)
	}
}
