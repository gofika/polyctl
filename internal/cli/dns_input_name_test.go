package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// A record name whose relative form ends in a top-level domain (foo.dev in
// zone example.com) is offered by its full name wherever an existing name
// is handed back as <name>: the name list of dns add and dns ensure on a
// terminal, and the completion of dns delete (neutral and platform), so
// that the name picked is not refused.
func TestExistingNameEndingInTLDOfferedInFull(t *testing.T) {
	foo := platform.Record{ID: "t9", ZoneID: "z1", Name: "foo.dev.example.com", Type: "TXT", Value: "hello", TTL: 300}
	www := platform.Record{ID: "w1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "192.0.2.1", TTL: 300}
	for _, verb := range []string{"add", "ensure"} {
		_, cfgPath, fc := ensureZone(t, foo, www)
		p := prompttest.New(t, "foo.dev.example.com", "TXT", "world", "")
		if verb == "add" {
			p.Answers = p.Answers[:3]
		}
		r := runFlow(t, context.Background(), cfgPath, (*scriptedPicker)(p), strings.NewReader(""), "dns", verb, "example.com")
		if got := prompttest.Values(p.Find("Record name in example.com").Options); !strings.HasPrefix(got, "@ foo.dev.example.com www ") {
			t.Errorf("dns %s: names %q", verb, got)
		}
		want := map[string]string{"add": "CreateRecord:foo.dev.example.com:TXT", "ensure": "UpdateRecord:t9"}[verb]
		if r.err != nil || fc.count(want) != 1 {
			t.Errorf("dns %s: %v, calls %v, prompts %v", verb, r.err, fc.calls, p.Titles())
		}
	}
	_, cfgPath, _ := ensureZone(t, foo, www)
	for _, args := range [][]string{{"dns", "delete", "example.com", ""}, {"cloudflare", "dns", "delete", "example.com", ""}} {
		_, stdout, _ := mainRun(cfgPath, append([]string{"__complete"}, args...)...)
		if !strings.Contains(stdout, "foo.dev.example.com\tTXT hello") || strings.Contains(stdout, "foo.dev\t") || !strings.Contains(stdout, "www\tA 192.0.2.1") {
			t.Errorf("%v: completion %q", args, stdout)
		}
	}
}
