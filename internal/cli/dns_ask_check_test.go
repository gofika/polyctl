package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// On a terminal, a <type> given before its value is checked as soon as the
// platform is known, before the zone is read or the value asked: an unknown
// type is exit code 2, a type the platform cannot write exit code 7.
func TestDNSRecordTypeCheckedBeforeAsking(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.1"})
	fakeRecordTypes = []string{"A", "CNAME", "MX", "TXT", "SRV"}
	defer func() { fakeRecordTypes = nil }()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"dns", "add", "example.com", "www", "FOO"}, ExitUsage, "unknown record type"},
		{[]string{"dns", "add", "example.com", "www", "CAA"}, ExitNotSupported, "cannot write CAA records"},
		{[]string{"dns", "ensure", "example.com", "www", "FOO"}, ExitUsage, "unknown record type"},
		{[]string{"dns", "ensure", "example.com", "www", "CAA"}, ExitNotSupported, "cannot write CAA records"},
	} {
		fc.calls = nil
		p := &scriptedPicker{T: t}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), c.args...)
		if r.code != c.code || r.err == nil || !strings.Contains(r.err.Error(), c.want) || len(p.Asked) != 0 || fc.count("ListRecords") != 0 {
			t.Errorf("%v: exit %d, %v, prompts %v, calls %v", c.args, r.code, r.err, p.Titles(), fc.calls)
		}
	}
}
