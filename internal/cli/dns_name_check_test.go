package cli

import (
	"context"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// gdZone is a GoDaddy zone gd.example holding recs, on the fake platform
// that stands in for GoDaddy.
func gdZone(t *testing.T, recs ...platform.Record) (cfgPath string, gd *fakeClient) {
	t.Helper()
	dir, cfgPath := setupMulti(t)
	seedZone(t, dir, config.AccountRef{Profile: "a", Platform: fakePlatform2}, "gd.example")
	gd = clientOn("a", fakePlatform2)
	gd.zones = []platform.Zone{{ID: "z-gd.example", Name: "gd.example"}}
	gd.records["z-gd.example"] = append([]platform.Record(nil), recs...)
	return cfgPath, gd
}

// A name and type that dns ensure refuses together (@ NS, an apex CNAME
// where the platform refuses one, a GoDaddy SRV name that is not
// _service._proto) are refused on a terminal as soon as both are known,
// before the zone is read or a value asked, as in a script; so are the ones
// dns add refuses (all of them but @ NS).
func TestDNSEnsureNameAndTypeRefusedBeforeAsking(t *testing.T) {
	_, cfgPath, fc := ensureZone(t, platform.Record{ID: "n1", ZoneID: "z1", Name: "example.com", Type: "NS", Value: "ns1.cf.example"})
	p := &scriptedPicker{T: t}
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "@", "NS")
	if r.code != ExitUsage || !strings.Contains(r.stderr+errString(r.err), "zone's own nameservers") || len(p.Asked) != 0 || len(fc.calls) != 0 {
		t.Errorf("@ NS: exit %d, %v, prompts %v, calls %v", r.code, r.err, p.Titles(), fc.calls)
	}

	for _, c := range []struct {
		args []string
		want string
	}{
		{[]string{"dns", "ensure", "gd.example", "@", "CNAME"}, "does not take a CNAME at the zone apex"},
		{[]string{"dns", "ensure", "gd.example", "sip", "SRV"}, "_service._proto"},
		{[]string{"dns", "add", "gd.example", "sip", "SRV"}, "_service._proto"},
		{[]string{"dns", "add", "gd.example", "@", "CNAME"}, "does not take a CNAME at the zone apex"},
		{[]string{"dns", "add", "gd.example", "sip", "SRV", "10 5 5060 sip.example.com"}, "_service._proto"},
	} {
		cfgPath, gd := gdZone(t, platform.Record{ID: "a1", ZoneID: "z-gd.example", Name: "gd.example", Type: "A", Value: "192.0.2.1"})
		p := &scriptedPicker{T: t}
		r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), c.args...)
		if r.code != ExitUsage || !strings.Contains(errString(r.err), c.want) || len(p.Asked) != 0 || len(gd.calls) != 0 {
			t.Errorf("%v: exit %d, %v, prompts %v, calls %v", c.args, r.code, r.err, p.Titles(), gd.calls)
		}
		// In a script, the complete record is refused before any request too.
		if len(c.args) == 5 {
			gd.calls = nil
			value := map[string]string{"CNAME": "target.example.net", "SRV": "10 5 5060 sip.example.com"}[c.args[4]]
			r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), append(c.args, value)...)
			if r.code != ExitUsage || !strings.Contains(errString(r.err), c.want) || len(gd.calls) != 0 {
				t.Errorf("%v in a script: exit %d, %v, calls %v", c.args, r.code, r.err, gd.calls)
			}
		}
	}

	// An apex CNAME asking for proxied=true off Cloudflare is only reported
	// as skipped: it is not refused.
	cfgPath, gd := gdZone(t)
	r = runFlow(t, context.Background(), cfgPath, nil, strings.NewReader(""), "dns", "ensure", "gd.example", "@", "CNAME", "target.example.net", "--proxied")
	if r.code != 0 || writes(gd) != 0 || !strings.Contains(r.stdout+r.stderr, "skipped") {
		t.Errorf("proxied apex CNAME on GoDaddy: exit %d, %v, %q, calls %v", r.code, r.err, r.stdout+r.stderr, gd.calls)
	}
}

// The type list of a name picked on a terminal leaves out the types the
// command refuses for it: NS at the apex for dns ensure, CNAME at the apex
// where the platform refuses one (dns add too), SRV on GoDaddy at a name that
// is not _service._proto (the apex among them).
func TestDNSTypeListLeavesOutTypesRefusedForTheName(t *testing.T) {
	types := []string{"A", "CNAME", "MX", "NS", "TXT", "SRV"}
	defer func() { fakeRecordTypes = nil }()
	for _, c := range []struct {
		args    []string
		name    string
		offered string
	}{
		{[]string{"dns", "ensure", "gd.example"}, "@", "A MX TXT"},
		{[]string{"dns", "ensure", "gd.example"}, "sip", "A CNAME MX NS TXT"},
		{[]string{"dns", "ensure", "gd.example"}, "_sip._tcp", "A CNAME MX NS TXT SRV"},
		{[]string{"dns", "add", "gd.example"}, "@", "A MX NS TXT"},
		{[]string{"dns", "add", "gd.example"}, "sip", "A CNAME MX NS TXT"},
	} {
		cfgPath, _ := gdZone(t)
		fakeRecordTypes = types
		answers := []any{c.name}
		if c.name != "@" {
			answers = []any{prompttest.Label("Another name"), c.name}
		}
		p := prompttest.New(t, append(answers, "TXT", "hello", "")...)
		r := runFlow(t, context.Background(), cfgPath, (*scriptedPicker)(p), strings.NewReader(""), c.args...)
		if a := p.Find("Record type"); prompttest.Values(a.Options) != c.offered {
			t.Errorf("%v name %s: types %q, want %q", c.args, c.name, prompttest.Values(a.Options), c.offered)
		}
		if r.err != nil {
			t.Errorf("%v name %s: %v, prompts %v", c.args, c.name, r.err, p.Titles())
		}
	}
	// Cloudflare flattens an apex CNAME: only NS is left out for dns ensure.
	_, cfgPath, _ := ensureZone(t)
	fakeRecordTypes = types
	p := prompttest.New(t, "@", "TXT", "hello", "")
	if r := runFlow(t, context.Background(), cfgPath, (*scriptedPicker)(p), strings.NewReader(""), "dns", "ensure", "example.com"); r.err != nil || prompttest.Values(p.Find("Record type").Options) != "A CNAME MX TXT SRV" {
		t.Errorf("cloudflare apex: %v, types %q", r.err, prompttest.Values(p.Find("Record type").Options))
	}
}

func errString(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

// proxied applies to A, AAAA and CNAME only: dns ensure on a terminal
// refuses it on another type as soon as the type is known, before the zone
// is read or a value asked, as a script does, and off Cloudflare too (where
// proxied=true on a type it applies to is only reported as skipped). The
// type list under --proxied offers only those types.
func TestDNSEnsureProxiedTypeRefusedBeforeAsking(t *testing.T) {
	_, cfgPath, fc := ensureZone(t)
	p := &scriptedPicker{T: t}
	r := runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "example.com", "www", "TXT", "--proxied")
	if r.code != ExitUsage || !strings.Contains(errString(r.err), "proxied applies to A, AAAA and CNAME records only, not TXT") || len(p.Asked) != 0 || len(fc.calls) != 0 {
		t.Errorf("cloudflare www TXT --proxied: exit %d, %v, prompts %v, calls %v", r.code, r.err, p.Titles(), fc.calls)
	}

	cfgPath, gd := gdZone(t)
	p = &scriptedPicker{T: t}
	r = runFlow(t, context.Background(), cfgPath, p, strings.NewReader(""), "dns", "ensure", "gd.example", "@", "NS", "--proxied")
	if r.code != ExitUsage || !strings.Contains(errString(r.err), "proxied applies") || len(p.Asked) != 0 || len(gd.calls) != 0 {
		t.Errorf("godaddy @ NS --proxied: exit %d, %v, prompts %v, calls %v", r.code, r.err, p.Titles(), gd.calls)
	}

	defer func() { fakeRecordTypes = nil }()
	cfgPath, _ = gdZone(t)
	fakeRecordTypes = []string{"A", "CNAME", "MX", "NS", "TXT", "SRV"}
	pp := prompttest.New(t, "@", "A", "192.0.2.1", "")
	r = runFlow(t, context.Background(), cfgPath, (*scriptedPicker)(pp), strings.NewReader(""), "dns", "ensure", "gd.example", "--proxied")
	if got := prompttest.Values(pp.Find("Record type").Options); got != "A CNAME" || r.err != nil {
		t.Errorf("godaddy @ --proxied: types %q, %v", got, r.err)
	}
}
