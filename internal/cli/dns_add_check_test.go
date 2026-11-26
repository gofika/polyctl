package cli

import (
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// dns add checks its record before any request: an invalid value or a
// priority that does not belong is exit code 2, a type the platform of the
// zone cannot write exit code 7, and nothing is read or written. A valid
// record is written in its normal form.
func TestDNSAddChecksTheRecordFirst(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "r1", ZoneID: "z1", Name: "www.example.com", Type: "A", Value: "203.0.113.1"})
	fakeRecordTypes = []string{"A", "CNAME", "MX", "TXT", "SRV"}
	defer func() { fakeRecordTypes = nil }()
	for _, c := range []struct {
		args []string
		code int
		want string
	}{
		{[]string{"www", "A", "nope"}, ExitUsage, "not an IPv4 address"},
		{[]string{"_sip._tcp", "SRV", "5 5060 sip.example.com", "--priority", "10"}, ExitUsage, "the priority is the first field of the value"},
		{[]string{"_sip._tcp", "SRV", "5 5060 sip.example.com"}, ExitUsage, "e.g. 10 5 5060 sip.example.com"},
		{[]string{"@", "MX", "mail.example.com"}, ExitUsage, "needs a priority"},
		{[]string{"@", "TXT", "x", "--priority", "1"}, ExitUsage, "MX records only"},
		{[]string{"@", "XYZ", "x"}, ExitUsage, "unknown record type"},
		{[]string{"@", "CAA", `0 issue "letsencrypt.org"`}, ExitNotSupported, "cannot write CAA records (it writes A CNAME MX TXT SRV)"},
	} {
		fc.calls = nil
		_, _, err := run(t, cfgPath, append([]string{"dns", "add", "example.com"}, c.args...)...)
		if ExitCodeFor(err) != c.code || err == nil || !strings.Contains(err.Error(), c.want) || len(fc.calls) != 0 {
			t.Errorf("%v: exit %d, %v, calls %v", c.args, ExitCodeFor(err), err, fc.calls)
		}
	}
	// A CNAME beside the A record of its name is refused before the write.
	fc.calls = nil
	if _, _, err := run(t, cfgPath, "dns", "add", "example.com", "www", "CNAME", "target.example.net"); err == nil || !strings.Contains(err.Error(), "already has an A record") || fc.count("CreateRecord") != 0 {
		t.Errorf("CNAME beside A = %v, calls %v", err, fc.calls)
	}
	// Valid records are written in their normal form, the priority of an
	// MX value apart.
	if _, stderr, err := run(t, cfgPath, "dns", "add", "example.com", "_sip._tcp", "srv", "10 5 5060 SIP.Example.com."); err != nil {
		t.Fatalf("SRV: %v (%s)", err, stderr)
	}
	if _, stderr, err := run(t, cfgPath, "dns", "add", "example.com", "@", "MX", "20 Mail.Example.com"); err != nil {
		t.Fatalf("MX: %v (%s)", err, stderr)
	}
	var got []string
	for _, r := range fc.records["z1"] {
		v := r.Type + " " + r.Value
		if r.Priority != nil {
			v += " prio"
		}
		got = append(got, v)
	}
	if strings.Join(got, ",") != "A 203.0.113.1,SRV 10 5 5060 sip.example.com,MX mail.example.com prio" {
		t.Errorf("records = %q", got)
	}
}
