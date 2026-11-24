package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// casHarness is the aliyun harness with a CAS store and ALB listeners.
func casHarness(t *testing.T, flags app.Flags) (*harness, *casFake, *albFake) {
	t.Helper()
	h := newHarness(t, flags)
	f := newCASFake(t, h.api)
	a := &albFake{lbs: map[string][]map[string]any{}, listeners: map[string][]map[string]any{}, certs: map[string][]string{}, extra: map[string][]string{}}
	a.install(h.api)
	return h, f, a
}

// fixedCASClock pins the clock of the expiry computations.
func fixedCASClock(t *testing.T, now time.Time) {
	t.Helper()
	old := casNow
	casNow = func() time.Time { return now }
	t.Cleanup(func() { casNow = old })
}

// writePEM writes a chain for example.com valid for days and its key (or
// another key when mismatched) and returns the two paths.
func writePEM(t *testing.T, days int, mismatched bool) (certPath, keyPath string, notAfter time.Time) {
	t.Helper()
	ca := certtest.New("Test Issuer")
	key := certtest.Key()
	now := time.Now()
	notAfter = now.Add(time.Duration(days) * 24 * time.Hour)
	chain := ca.Issue(key.Public(), []string{"example.com", "www.example.com"}, now.Add(-time.Hour), notAfter)
	keyPEM := certtest.KeyPEM(key)
	if mismatched {
		keyPEM = certtest.KeyPEM(certtest.Key())
	}
	dir := t.TempDir()
	certPath, keyPath = filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	return certPath, keyPath, notAfter
}

func TestCASUploadCreatesThenReuses(t *testing.T) {
	h, f, _ := casHarness(t, app.Flags{})
	certPath, keyPath, notAfter := writePEM(t, 76, false)
	end := notAfter.UTC().Format("2006-01-02")
	if err := h.run("cas", "certificate", "upload", "upload_example.com_"+end, "--cert", certPath, "--key", keyPath); err != nil {
		t.Fatalf("%v\n%s", err, h.stderr.String())
	}
	if len(f.uploads) != 1 {
		t.Fatalf("uploads = %d", len(f.uploads))
	}
	q := f.uploads[0]
	chain, _ := os.ReadFile(certPath)
	key, _ := os.ReadFile(keyPath)
	if q.Get("Name") != "upload_example.com_"+end || q.Get("Cert") != string(chain) || q.Get("Key") != string(key) {
		t.Errorf("upload = name %q, cert %d bytes, key %d bytes", q.Get("Name"), len(q.Get("Cert")), len(q.Get("Key")))
	}
	rep := reportOf(t, h)
	if rep.Target != (platform.Target{Platform: platform.Aliyun, Profile: "ali", Region: "cn-shanghai"}) || rep.DryRun ||
		len(rep.Changes) != 1 || rep.Changes[0].Resource != "cas/certificate/upload_example.com_"+end || rep.Changes[0].Action != platform.Created ||
		rep.Changes[0].ID != "9000001" || rep.Changes[0].Detail != "end "+end {
		t.Errorf("report = %+v", rep)
	}
	rows, err := h.db().List(context.Background(), inventory.Query{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResCertificate})
	if err != nil || len(rows) != 1 || rows[0].ID != "9000001" {
		t.Fatalf("inventory = %+v, %v", rows, err)
	}
	var stored casCertificate
	if err := rows[0].Decode(&stored); err != nil || stored.EndDate != end || stored.Source != "cas" || len(stored.Fingerprint) != 40 || stored.Endpoint != "cas.aliyuncs.com" {
		t.Errorf("stored = %+v, %v", stored, err)
	}

	// The second run finds the name: nothing is written.
	if err := h.run("cas", "certificate", "upload", "upload_example.com_"+end, "--cert", certPath, "--key", keyPath); err != nil {
		t.Fatal(err)
	}
	if len(f.uploads) != 1 {
		t.Errorf("uploads after the second run = %d", len(f.uploads))
	}
	rep = reportOf(t, h)
	if len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Unchanged || rep.Changes[0].ID != "9000001" {
		t.Errorf("second report = %+v", rep.Changes)
	}
}

func TestCASUploadDryRunAndFailures(t *testing.T) {
	certPath, keyPath, _ := writePEM(t, 76, false)

	h, f, _ := casHarness(t, app.Flags{DryRun: true})
	if err := h.run("cas", "certificate", "upload", "n1", "--cert", certPath, "--key", keyPath); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if len(f.uploads) != 0 || !rep.DryRun || len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldCreate || rep.Changes[0].ID != platform.Pending ||
		!strings.HasPrefix(rep.Changes[0].Detail, "end ") {
		t.Errorf("dry run: uploads %d, report %+v", len(f.uploads), rep)
	}

	// A key of another certificate: exit code 2, nothing sent.
	h, _, _ = casHarness(t, app.Flags{})
	badCert, badKey, _ := writePEM(t, 76, true)
	err := h.run("cas", "certificate", "upload", "n1", "--cert", badCert, "--key", badKey)
	if !errors.Is(err, platform.ErrInvalidInput) || len(h.api.calls) != 0 {
		t.Errorf("mismatched key = %v, %d calls", err, len(h.api.calls))
	}
	for _, args := range [][]string{
		{"--cert", certPath},
		{"--cert", "-", "--key", "-"},
		{"--cert", filepath.Join(t.TempDir(), "missing.pem"), "--key", keyPath},
	} {
		err := h.run(append([]string{"cas", "certificate", "upload", "n1"}, args...)...)
		if !errors.Is(err, app.ErrUsage) || len(h.api.calls) != 0 {
			t.Errorf("%v = %v, %d calls", args, err, len(h.api.calls))
		}
	}

	// CertId 0 is a failure, not a usage error.
	h, f, _ = casHarness(t, app.Flags{})
	f.zeroID = true
	err = h.run("cas", "certificate", "upload", "n1", "--cert", certPath, "--key", keyPath)
	if err == nil || errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrInvalidInput) || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("CertId 0 = %v", err)
	}

	// A name taken meanwhile (NameRepeat) that is listed then is reused.
	h, f, _ = casHarness(t, app.Flags{})
	lists := 0
	h.api.on("ListUserCertificateOrder", func(q url.Values) (int, any) {
		lists++
		if lists == 1 {
			return 200, map[string]any{"TotalCount": 0}
		}
		return f.list(q)
	})
	f.add(4242, "n1", "2027-02-01")
	if err := h.run("cas", "certificate", "upload", "n1", "--cert", certPath, "--key", keyPath); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Unchanged || rep.Changes[0].ID != "4242" {
		t.Errorf("NameRepeat race = %+v", rep.Changes)
	}
}

func TestCASUploadReadsStdin(t *testing.T) {
	certPath, keyPath, _ := writePEM(t, 30, false)
	h, f, _ := casHarness(t, app.Flags{})
	chain, _ := os.ReadFile(certPath)
	h.rt.Stdin = strings.NewReader(string(chain))
	if err := h.run("cas", "certificate", "upload", "n1", "--cert", "-", "--key", keyPath); err != nil {
		t.Fatal(err)
	}
	if len(f.uploads) != 1 || f.uploads[0].Get("Cert") != string(chain) {
		t.Errorf("uploads = %v", f.uploads)
	}
}

func TestCASListFiltersAndPages(t *testing.T) {
	fixedCASClock(t, time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC))
	h, f, _ := casHarness(t, app.Flags{Refresh: true})
	for i := range 250 {
		f.add(int64(5000+i), fmt.Sprintf("bulk-%03d", i), "2027-06-01")
	}
	f.add(1, "upload_old.example_2026-11-01", "2026-11-01")
	f.add(2, "upload_today.example_2026-11-17", "2026-11-17")
	f.add(3, "upload_soon.example_2026-12-01", "2026-12-01")
	f.add(4, "no-end", "")
	if err := h.run("cas", "certificate", "list"); err != nil {
		t.Fatal(err)
	}
	var all []casCertView
	h.jsonOut(&all)
	if len(all) != 254 || len(h.api.callsFor("ListUserCertificateOrder")) != 3 {
		t.Fatalf("%d rows in %d pages", len(all), len(h.api.callsFor("ListUserCertificateOrder")))
	}
	// Ordered by end date: the one without a date first.
	if all[0].Name != "no-end" || !all[0].Expired || all[0].DaysToExpire != 0 {
		t.Errorf("first = %+v", all[0])
	}
	if all[1] != (casCertView{ID: "1", Name: "upload_old.example_2026-11-01", CommonName: "example.com", StartDate: "2026-11-03", EndDate: "2026-11-01",
		DaysToExpire: -16, Expired: true, Fingerprint: "FEFD0123456789ABCDEF0123456789ABCDEF0123", Sans: "example.com,www.example.com"}) {
		t.Errorf("old = %+v", all[1])
	}

	names := func(args ...string) []string {
		t.Helper()
		if err := h.run(append([]string{"cas", "certificate", "list"}, args...)...); err != nil {
			t.Fatal(err)
		}
		var rows []casCertView
		h.jsonOut(&rows)
		var out []string
		for _, r := range rows {
			out = append(out, r.Name)
		}
		return out
	}
	if got := names("--expired"); strings.Join(got, ",") != "no-end,upload_old.example_2026-11-01,upload_today.example_2026-11-17" {
		t.Errorf("--expired = %v", got)
	}
	if got := names("--expires-within", "14"); strings.Join(got, ",") != "no-end,upload_old.example_2026-11-01,upload_today.example_2026-11-17,upload_soon.example_2026-12-01" {
		t.Errorf("--expires-within 14 = %v", got)
	}
	if got := names("--name", "soon"); len(got) != 1 {
		t.Errorf("--name = %v", got)
	}
	if got := names("--name", "nothing-like-this"); len(got) != 0 || strings.TrimSpace(h.stdout.String()) != "[]" || !strings.Contains(h.stderr.String(), "note: no uploaded certificates") {
		t.Errorf("empty = %v, stdout %q, stderr %q", got, h.stdout.String(), h.stderr.String())
	}
	if err := h.run("cas", "certificate", "list", "--expires-within", "-1"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("negative = %v", err)
	}
}

func TestCASListCacheAndDenial(t *testing.T) {
	h, f, _ := casHarness(t, app.Flags{})
	f.add(1, "one", "2027-01-01")
	if err := h.run("cas", "certificate", "list"); err != nil {
		t.Fatal(err)
	}
	// Served from the inventory the second time.
	if err := h.run("cas", "certificate", "list"); err != nil {
		t.Fatal(err)
	}
	if n := len(h.api.callsFor("ListUserCertificateOrder")); n != 1 || !strings.Contains(h.stderr.String(), "local inventory") {
		t.Errorf("list calls = %d, stderr %q", n, h.stderr.String())
	}

	h, f, _ = casHarness(t, app.Flags{})
	f.failList, f.failStatus = "NoPermission", 403
	if err := h.run("cas", "certificate", "list"); !errors.Is(err, platform.ErrForbidden) {
		t.Errorf("denied list = %v", err)
	}
}

// The sync of the account stores the certificates; a denial is the error
// of the type, and the endpoint of config.yaml is the one used.
func TestCASSyncAndEndpointSetting(t *testing.T) {
	h, f, _ := casHarness(t, app.Flags{})
	f.add(77, "one", "2027-01-01")
	cfg, _ := h.rt.Config()
	cfg.Profiles["ali"].Platforms[platform.Aliyun].Metadata[metaAccountID] = "1234567890"
	cfg.Defaults = config.Defaults{"aliyun": {"cas_endpoint": "cas.example.test"}}
	reports, err := h.rt.SyncAccount(context.Background(), aliAccount, []platform.ResourceType{platform.ResCertificate})
	if err != nil || len(reports) != 1 || reports[0].Count != 1 || reports[0].Error != "" {
		t.Fatalf("sync = %+v, %v", reports, err)
	}
	rows, _ := h.db().List(context.Background(), inventory.Query{Platform: platform.Aliyun, Profile: "ali", Type: platform.ResCertificate})
	var ct casCertificate
	if len(rows) != 1 || rows[0].Decode(&ct) != nil || ct.Endpoint != "cas.example.test" || ct.Account != "1234567890" || ct.ID != "77" {
		t.Errorf("rows = %+v (%+v)", rows, ct)
	}
	f.failList, f.failStatus = "NoPermission", 403
	reports, _ = h.rt.SyncAccount(context.Background(), aliAccount, []platform.ResourceType{platform.ResCertificate})
	if len(reports) != 1 || !errors.Is(reports[0].Err, platform.ErrForbidden) {
		t.Errorf("denied sync = %+v", reports)
	}
}

// useListener makes an HTTPS listener of a load balancer in cn-shanghai
// hold the certificate ids.
func useListener(a *albFake, lb, lbName, listener string, ids ...string) {
	region := "cn-shanghai"
	found := false
	for _, l := range a.lbs[region] {
		if l["LoadBalancerId"] == lb {
			found = true
		}
	}
	if !found {
		a.lbs[region] = append(a.lbs[region], map[string]any{"LoadBalancerId": lb, "LoadBalancerName": lbName})
	}
	a.listeners[lb] = append(a.listeners[lb], map[string]any{"ListenerId": listener, "LoadBalancerId": lb, "ListenerProtocol": "HTTPS", "ListenerPort": 443})
	a.certs[listener] = ids
}

func TestCASDeleteChecksListeners(t *testing.T) {
	h, f, a := casHarness(t, app.Flags{Yes: true})
	f.add(1234567, "used", "2027-01-01")
	f.add(7654321, "free", "2027-01-01")
	useListener(a, "alb-1", "lb-example-com", "lsn-1", "1234567")
	useListener(a, "alb-2", "lb-other", "lsn-2", "1234567-ap-southeast-1")

	err := h.run("cas", "certificate", "delete", "1234567")
	if err == nil || errors.Is(err, app.ErrUsage) || errors.Is(err, platform.ErrForbidden) || !strings.Contains(err.Error(), "--force") {
		t.Fatalf("delete of a used certificate = %v", err)
	}
	stderr := h.stderr.String()
	for _, want := range []string{
		"cannot delete certificate 1234567: used by listener lsn-1 of load balancer lb-example-com (cn-shanghai)",
		"cannot delete certificate 1234567: used by listener lsn-2 of load balancer lb-other (cn-shanghai)",
		casOnlyALBNote,
	} {
		if !strings.Contains(stderr, want) {
			t.Errorf("stderr lacks %q:\n%s", want, stderr)
		}
	}
	if len(f.deletes) != 0 || len(h.api.callsFor("DeleteUserCertificate")) != 0 {
		t.Fatalf("deleted %v", f.deletes)
	}

	// An unused certificate is deleted.
	if err := h.run("cas", "certificate", "delete", "7654321"); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if len(f.deletes) != 1 || f.deletes[0] != "7654321" || len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Deleted || rep.Changes[0].Resource != "cas/certificate/7654321" {
		t.Errorf("deletes %v, report %+v", f.deletes, rep)
	}

	// --force skips the check.
	before := len(h.api.callsFor("ListLoadBalancers"))
	if err := h.run("cas", "certificate", "delete", "1234567", "--force"); err != nil {
		t.Fatal(err)
	}
	if len(f.deletes) != 2 || len(h.api.callsFor("ListLoadBalancers")) != before || strings.Contains(h.stderr.String(), casOnlyALBNote) {
		t.Errorf("--force: deletes %v, ListLoadBalancers %d -> %d", f.deletes, before, len(h.api.callsFor("ListLoadBalancers")))
	}

	// A missing id is exit code 4.
	if err := h.run("cas", "certificate", "delete", "999"); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("missing = %v", err)
	}
}

func TestCASDeleteRefusesAnAdditionalCertificate(t *testing.T) {
	h, f, a := casHarness(t, app.Flags{Yes: true})
	f.add(5555555, "extra", "2027-01-01")
	useListener(a, "alb-1", "lb-example-com", "lsn-1", "1234567")
	a.extra["lsn-1"] = []string{"5555555"}
	err := h.run("cas", "certificate", "delete", "5555555")
	if err == nil || !strings.Contains(h.stderr.String(), "cannot delete certificate 5555555: used by listener lsn-1") || len(f.deletes) != 0 {
		t.Errorf("delete of an additional certificate = %v, deletes %v:\n%s", err, f.deletes, h.stderr.String())
	}
}

func TestCASDeleteRefusesWhenTheCheckFails(t *testing.T) {
	h, f, a := casHarness(t, app.Flags{Yes: true})
	f.add(1, "one", "2027-01-01")
	a.fail = map[string]string{"cn-shanghai": "Forbidden.LoadBalancer"}
	err := h.run("cas", "certificate", "delete", "1")
	if !errors.Is(err, platform.ErrForbidden) || !strings.Contains(err.Error(), "cn-shanghai") || len(f.deletes) != 0 {
		t.Errorf("forbidden check = %v, deletes %v", err, f.deletes)
	}
	a.fail = map[string]string{"cn-shanghai": "ServiceUnavailable"}
	err = h.run("cas", "certificate", "delete", "1")
	if err == nil || errors.Is(err, platform.ErrForbidden) || len(f.deletes) != 0 {
		t.Errorf("failed check = %v, deletes %v", err, f.deletes)
	}
	// --region limits the check: an unreadable region left out is not read.
	a.fail = map[string]string{"cn-shanghai": "ServiceUnavailable"}
	if err := h.run("cas", "certificate", "delete", "1", "--region", "cn-hongkong"); err != nil {
		t.Fatal(err)
	}
	if q := h.api.callsFor("ListLoadBalancers"); q[len(q)-1].Get("RegionId") != "cn-hongkong" || len(f.deletes) != 1 {
		t.Errorf("--region: last region %q, deletes %v", q[len(q)-1].Get("RegionId"), f.deletes)
	}
}

func TestCASDeleteUsageAndFlows(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, f, _ := casHarness(t, app.Flags{})
	f.add(1, "one", "2027-01-01")
	for _, args := range [][]string{
		{"1"},              // no --yes in the non-interactive flow
		{"1", "--force"},   // --force needs --yes too
		{"--expired"},      // as does the batch
		{},                 // no id
		{"1", "--expired"}, // both
		{"abc"},            // not an integer
	} {
		err := h.run(append([]string{"cas", "certificate", "delete"}, args...)...)
		if !errors.Is(err, app.ErrUsage) || len(h.api.calls) != 0 {
			t.Errorf("%v = %v, %d calls", args, err, len(h.api.calls))
		}
	}

	// The interactive flow asks (default no): a yes deletes.
	h, f, _ = casHarness(t, app.Flags{})
	f.add(1, "one", "2027-01-01")
	h.rt.Picker = terminalStub{t}
	h.rt.Stdin = strings.NewReader("y\n")
	if err := h.run("cas", "certificate", "delete", "1"); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(h.stderr.String(), "Delete certificate 1 (one, end 2027-01-01) from cas.aliyuncs.com? (y/N)") || len(f.deletes) != 1 {
		t.Errorf("stderr %q, deletes %v", h.stderr.String(), f.deletes)
	}
	// A declined question deletes nothing and is not an error.
	f.add(2, "two", "2027-01-01")
	h.rt.Stdin = strings.NewReader("\n")
	if err := h.run("cas", "certificate", "delete", "2", "--force"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("declined = %v", err)
	}
	if !strings.Contains(h.stderr.String(), "without checking ALB listeners") || len(f.deletes) != 1 {
		t.Errorf("stderr %q, deletes %v", h.stderr.String(), f.deletes)
	}
}

func TestCASDeleteDryRun(t *testing.T) {
	h, f, a := casHarness(t, app.Flags{DryRun: true})
	h.rt.Stdin = unreadStdin{t}
	f.add(1, "used", "2027-01-01")
	f.add(2, "free", "2027-01-01")
	useListener(a, "alb-1", "lb-example-com", "lsn-1", "1")
	if err := h.run("cas", "certificate", "delete", "2"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(rep.Changes) != 1 || rep.Changes[0].Action != platform.WouldDelete {
		t.Errorf("dry run = %+v", rep)
	}
	if err := h.run("cas", "certificate", "delete", "1"); err != nil {
		t.Fatal(err)
	}
	rep := reportOf(t, h)
	if len(rep.Changes) != 1 || rep.Changes[0].Action != platform.Skipped || !strings.Contains(rep.Changes[0].Detail, "would refuse: used by listener lsn-1 of load balancer lb-example-com") {
		t.Errorf("dry run of a used certificate = %+v", rep)
	}
	if len(f.deletes) != 0 || len(h.api.callsFor("GetListenerAttribute")) != 2 {
		t.Errorf("deletes %v, GetListenerAttribute %d: the check runs in a dry run", f.deletes, len(h.api.callsFor("GetListenerAttribute")))
	}
}

func TestCASDeleteExpired(t *testing.T) {
	fixedCASClock(t, time.Date(2026, 11, 17, 10, 0, 0, 0, time.UTC))
	h, f, a := casHarness(t, app.Flags{Yes: true})
	f.add(1, "old-free", "2026-10-01")
	f.add(2, "old-used", "2026-10-02")
	f.add(3, "old-broken", "2026-10-03")
	f.add(4, "today", "2026-11-17")
	f.add(5, "valid", "2027-01-01")
	f.failDelete["3"] = "ServiceUnavailable"
	useListener(a, "alb-1", "lb-example-com", "lsn-1", "2-ap-southeast-1")
	useListener(a, "alb-1", "lb-example-com", "lsn-2", "5")
	// Two regions: each is enumerated once for every certificate.
	h.api.on("DescribeRegions", func(url.Values) (int, any) {
		return 200, map[string]any{"Regions": map[string]any{"Region": []map[string]any{{"RegionId": "cn-shanghai"}, {"RegionId": "cn-beijing"}}}}
	})
	err := h.run("cas", "certificate", "delete", "--expired")
	if err == nil || !strings.Contains(err.Error(), "1 of 3 expired certificate deletion(s) failed") || errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("delete --expired = %v", err)
	}
	if strings.Join(f.deletes, ",") != "1,4" {
		t.Errorf("deleted %v", f.deletes)
	}
	rep := reportOf(t, h)
	actions := map[string]platform.Action{}
	for _, c := range rep.Changes {
		actions[c.ID] = c.Action
	}
	if len(rep.Changes) != 4 || actions["1"] != platform.Deleted || actions["2"] != platform.Skipped || actions["3"] != platform.Failed || actions["4"] != platform.Deleted {
		t.Errorf("changes = %+v", rep.Changes)
	}
	if rep.Summary == nil || rep.Summary.Deleted != 2 || rep.Summary.Skipped != 1 || rep.Summary.Failed != 1 {
		t.Errorf("summary = %+v", rep.Summary)
	}
	if n := len(h.api.callsFor("ListLoadBalancers")); n != 2 {
		t.Errorf("ListLoadBalancers called %d times, want once per region", n)
	}
	if n := len(h.api.callsFor("GetListenerAttribute")); n != 2 {
		t.Errorf("GetListenerAttribute called %d times, want once per listener", n)
	}

	// Nothing expired: exit code 0, an empty report and a note.
	h, f, _ = casHarness(t, app.Flags{Yes: true})
	f.add(5, "valid", "2027-01-01")
	if err := h.run("cas", "certificate", "delete", "--expired"); err != nil {
		t.Fatal(err)
	}
	if rep := reportOf(t, h); len(rep.Changes) != 0 || !strings.Contains(h.stderr.String(), "note: no expired uploaded certificates") {
		t.Errorf("nothing expired = %+v, %q", rep, h.stderr.String())
	}
}

// upload without <name>, --cert and --key asks for the two files (each
// checked as typed: a missing file and a key of another certificate are
// asked again) and the name, upload_<root>_<date> proposed.
func TestCASUploadAsks(t *testing.T) {
	t.Setenv(app.EnvNonInteractive, "")
	h, _, _ := casHarness(t, app.Flags{DryRun: true})
	certPath, keyPath, notAfter := writePEM(t, 90, false)
	_, otherKey, _ := writePEM(t, 90, true)
	p := prompttest.New(t, "/nonexistent/fullchain.pem", certPath, otherKey, keyPath, prompttest.KeepDefault{})
	h.rt.Picker = p
	if err := h.run("cas", "certificate", "upload"); err != nil {
		t.Fatalf("upload: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	want := "upload_example.com_" + notAfter.UTC().Format("2006-01-02")
	if a := p.Asked[len(p.Asked)-1]; a.Default != want {
		t.Errorf("name proposed %q, want %q", a.Default, want)
	}
	if !strings.Contains(h.stdout.String(), want) {
		t.Errorf("stdout = %s", h.stdout.String())
	}
	if len(h.api.callsFor("UploadUserCertificate")) != 0 {
		t.Error("the dry run uploaded")
	}

	h.rt.Picker = prompttest.New(t, prompttest.Abort{})
	if err := h.run("cas", "certificate", "upload", "x"); !errors.Is(err, prompt.ErrAborted) {
		t.Errorf("abort = %v", err)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("cas", "certificate", "upload", "x"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive without --cert / --key = %v", err)
	}
}
