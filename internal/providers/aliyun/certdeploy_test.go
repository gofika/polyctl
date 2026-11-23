package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/platform"
)

var deployNow = time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)

// albDeploy is the fake ALB and CAS of the deployer tests, with a bundle
// of example.com valid for 90 days in the "store".
type albDeploy struct {
	t      *testing.T
	api    *fakeAPI
	alb    *fakeALB
	cas    *casFake
	c      *client
	bundle *cert.Bundle
	// updateRefusals answers that many UpdateListenerAttribute calls
	// with IncorrectStatus.Listener first.
	updateRefusals int
	// ensured counts the calls of Ensure.
	ensured int
}

func newALBDeploy(t *testing.T) *albDeploy {
	t.Helper()
	h, _, alb, cas, _ := albHarness(t, app.Flags{})
	d := &albDeploy{t: t, api: h.api, alb: alb, cas: cas, c: h.api.client()}
	ca := certtest.New("Fake R1")
	key := certtest.Key()
	chain := ca.Issue(key.Public(), []string{"example.com", "*.example.com"}, deployNow.Add(-time.Hour), deployNow.Add(90*24*time.Hour))
	b, err := cert.NewBundle("example.com", chain, certtest.KeyPEM(key))
	if err != nil {
		t.Fatal(err)
	}
	d.bundle = b
	// Every listener certificate, the additional ones included.
	h.api.on("ListListenerCertificates", func(q url.Values) (int, any) {
		var certs []map[string]any
		if l := alb.listener(q.Get("ListenerId")); l != nil {
			for _, c := range l["certs"].([]string) {
				certs = append(certs, map[string]any{"CertificateId": c, "IsDefault": len(certs) == 0})
			}
		}
		return 200, map[string]any{"Certificates": certs, "NextToken": ""}
	})
	// The upload keeps the serial number and the expiry of what it got,
	// as CAS does.
	h.api.on("UploadUserCertificate", func(q url.Values) (int, any) {
		status, body := cas.upload(q)
		if status == 200 {
			if leaf, _, err := platform.LeafOf(q.Get("Cert")); err == nil {
				m := cas.certs[len(cas.certs)-1]
				m["SerialNo"] = cert.SerialHex(leaf)
				m["CertEndTime"] = leaf.NotAfter.UnixMilli()
				m["EndDate"] = leaf.NotAfter.UTC().Format("2006-01-02")
			}
		}
		return status, body
	})
	h.api.on("UpdateListenerAttribute", func(q url.Values) (int, any) {
		if d.updateRefusals > 0 {
			d.updateRefusals--
			return 400, apiErr("IncorrectStatus.Listener", "The status of the listener is incorrect.")
		}
		return alb.updateListener(q)
	})
	return d
}

// casCert stores a CAS certificate expiring at end with a serial number.
func (d *albDeploy) casCert(id int64, name string, end time.Time, serial string) {
	m := d.cas.add(id, name, end.Format("2006-01-02"))
	m["CertEndTime"] = end.UnixMilli()
	m["SerialNo"] = serial
	m["Expired"] = !deployNow.Before(end)
}

func (d *albDeploy) run(o cert.DeployOptions, regions ...string) (*cert.DeployReport, error) {
	d.t.Helper()
	dep, _ := platform.GetDeployer(albDeployerID)
	o.Deployers = []platform.CertDeployer{dep}
	if o.Days == 0 {
		o.Days = 30
	}
	if !o.All && o.Domain == "" {
		o.All = true
	}
	env := &cert.DeployEnv{
		Accounts: []config.AccountRef{{Profile: "acme", Platform: platform.Aliyun}},
		Open:     func(context.Context, config.AccountRef) (platform.Client, error) { return d.c, nil },
		Regions:  func(config.AccountRef) []string { return regions },
		Ensure: func(_ context.Context, root string, days int) (*cert.Result, error) {
			d.ensured++
			if root != "example.com" {
				return nil, fmt.Errorf("%w: %s", app.ErrDomainUnknown, root)
			}
			return &cert.Result{Bundle: d.bundle, Changes: []platform.Change{{Resource: "cert/" + root, Action: platform.Unchanged}}}, nil
		},
		Now: func() time.Time { return deployNow },
	}
	return cert.Deploy(context.Background(), env, o)
}

func deployRowsOf(rep *cert.DeployReport) []string {
	var out []string
	for _, c := range rep.Changes {
		out = append(out, c.Resource+" "+string(c.Action)+" "+c.Detail)
	}
	return out
}

func (d *albDeploy) listenerCert(id string) string { return d.alb.listener(id)["certs"].([]string)[0] }

func TestALBDeployerUploadsOnceAndBindsEveryDueListener(t *testing.T) {
	d := newALBDeploy(t)
	d.casCert(1111, "upload_example.com_2026-11-30", deployNow.Add(10*24*time.Hour), "01")
	d.casCert(2222, "upload_example.com_2027-03-01", deployNow.Add(100*24*time.Hour), "02")
	d.alb.addLB("alb-1", "lb-example", "vpc-site", "Active")
	d.alb.addLB("alb-2", "lb-other", "vpc-site", "Active")
	d.alb.addListener("lsn-1", "alb-1", "HTTPS", 443, "sgp-1", "1111-ap-southeast-1", "7777-ap-southeast-1")
	d.alb.addListener("lsn-2", "alb-1", "HTTPS", 8443, "sgp-1", "1111-ap-southeast-1")
	d.alb.addListener("lsn-3", "alb-1", "HTTPS", 9443, "sgp-1", "1111-ap-southeast-1")["ListenerStatus"] = "Stopped"
	d.alb.addListener("lsn-4", "alb-2", "HTTPS", 443, "sgp-1", "2222-ap-southeast-1")
	d.alb.addListener("lsn-5", "alb-2", "HTTP", 80, "sgp-1")

	rep, err := d.run(cert.DeployOptions{}, "cn-hongkong")
	if err != nil {
		t.Fatalf("deploy: %v\n%s", err, strings.Join(deployRowsOf(rep), "\n"))
	}
	if n := len(d.api.callsFor("UploadUserCertificate")); n != 1 {
		t.Errorf("%d uploads, want one shared by both listeners", n)
	}
	up := d.api.callsFor("UploadUserCertificate")[0]
	if up.Get("Name") != "upload_example.com_2027-02-18" || !strings.Contains(up.Get("Cert"), "BEGIN CERTIFICATE") {
		t.Errorf("upload = %v", up.Get("Name"))
	}
	newID := fmt.Sprint(d.cas.nextID - 1)
	want := newID + "-ap-southeast-1"
	if d.listenerCert("lsn-1") != want || d.listenerCert("lsn-2") != want || d.listenerCert("lsn-4") != "2222-ap-southeast-1" || d.listenerCert("lsn-3") != "1111-ap-southeast-1" {
		t.Errorf("listener certificates %s %s %s %s", d.listenerCert("lsn-1"), d.listenerCert("lsn-2"), d.listenerCert("lsn-3"), d.listenerCert("lsn-4"))
	}
	rows := deployRowsOf(rep)
	for _, w := range []string{
		"aliyun-alb/acme/lb-example(HTTPS:9443) skipped listener lsn-3 is stopped",
		"aliyun-alb/acme/cert created upload_example.com_2027-02-18 -> cert_id=" + newID,
		"aliyun-alb/acme/lb-example(HTTPS:443) updated cert_id=" + want + " (was 1111-ap-southeast-1); 1 additional certificate(s) left alone",
		"aliyun-alb/acme/lb-example(HTTPS:8443) updated cert_id=" + want + " (was 1111-ap-southeast-1)",
		"aliyun-alb/acme/lb-other(HTTPS:443) unchanged days_left=100",
	} {
		if !slices.Contains(rows, w) {
			t.Errorf("missing row %q in\n%s", w, strings.Join(rows, "\n"))
		}
	}
	for _, c := range rep.Changes {
		if c.Resource == "aliyun-alb/acme/lb-example(HTTPS:443)" && (c.Attrs["old_cert_id"] != "1111" || c.Attrs["region"] != "cn-hongkong" || c.Attrs["cert_name"] != "upload_example.com_2027-02-18") {
			t.Errorf("attrs = %v", c.Attrs)
		}
	}
	// The second run finds every listener fresh: nothing is written.
	updates := len(d.api.callsFor("UpdateListenerAttribute"))
	if _, err := d.run(cert.DeployOptions{}, "cn-hongkong"); err != nil {
		t.Fatal(err)
	}
	if len(d.api.callsFor("UploadUserCertificate")) != 1 || len(d.api.callsFor("UpdateListenerAttribute")) != updates {
		t.Errorf("second run wrote")
	}
}

func TestALBDeployerReusesNamesAndRetries(t *testing.T) {
	d := newALBDeploy(t)
	name := "upload_example.com_" + d.bundle.NotAfter.Format("2006-01-02")
	d.casCert(1111, "upload_example.com_2026-11-30", deployNow.Add(10*24*time.Hour), "01")
	// A certificate of the same day under the name: another serial.
	d.casCert(3333, name, d.bundle.NotAfter, "0dead")
	d.alb.addLB("alb-1", "lb-example", "vpc-site", "Active")
	d.alb.addListener("lsn-1", "alb-1", "HTTPS", 443, "sgp-1", "1111")
	d.updateRefusals = 2
	rep, err := d.run(cert.DeployOptions{})
	if err != nil {
		t.Fatalf("deploy: %v %v", err, deployRowsOf(rep))
	}
	ups := d.api.callsFor("UploadUserCertificate")
	if len(ups) != 1 || ups[0].Get("Name") != name+"-"+serialPrefix(d.bundle.Serial) {
		t.Errorf("uploads = %v", ups)
	}
	// The central store: the bare id, after two refused attempts.
	if got := d.listenerCert("lsn-1"); got != fmt.Sprint(d.cas.nextID-1) || len(d.api.callsFor("UpdateListenerAttribute")) != 3 {
		t.Errorf("listener cert %s after %d updates", got, len(d.api.callsFor("UpdateListenerAttribute")))
	}
	// The certificate uploaded before under the expected name is reused,
	// and a listener holding it already is not written (--force).
	d2 := newALBDeploy(t)
	d2.bundle = d.bundle
	d2.casCert(4444, name, d.bundle.NotAfter, d.bundle.Serial)
	d2.alb.addLB("alb-1", "lb-example", "vpc-site", "Active")
	d2.alb.addListener("lsn-1", "alb-1", "HTTPS", 443, "sgp-1", "1111")
	d2.alb.addListener("lsn-2", "alb-1", "HTTPS", 8443, "sgp-1", "4444")
	d2.casCert(1111, "old", deployNow.Add(5*24*time.Hour), "01")
	rep, err = d2.run(cert.DeployOptions{Domain: "example.com", Force: true})
	if err != nil {
		t.Fatal(err)
	}
	rows := deployRowsOf(rep)
	if len(d2.api.callsFor("UploadUserCertificate")) != 0 || len(d2.api.callsFor("UpdateListenerAttribute")) != 1 || d2.listenerCert("lsn-1") != "4444" ||
		!slices.Contains(rows, "aliyun-alb/acme/cert unchanged "+name+" cert_id=4444") ||
		!slices.Contains(rows, "aliyun-alb/acme/lb-example(HTTPS:8443) unchanged cert_id=4444") {
		t.Errorf("reuse: %v", rows)
	}
}

func TestALBDeployerDryRunAndSkips(t *testing.T) {
	d := newALBDeploy(t)
	d.casCert(1111, "upload_example.com_2026-11-30", deployNow.Add(10*24*time.Hour), "01")
	d.alb.addLB("alb-1", "lb-example", "vpc-site", "Active")
	d.alb.addListener("lsn-1", "alb-1", "HTTPS", 443, "sgp-1", "1111")
	d.alb.addListener("lsn-2", "alb-1", "HTTPS", 444, "sgp-1", "5555")
	d.alb.addListener("lsn-3", "alb-1", "HTTPS", 445, "sgp-1", "6666")
	d.alb.addListener("lsn-4", "alb-1", "HTTPS", 446, "sgp-1")
	d.alb.addListener("lsn-5", "alb-1", "HTTPS", 447, "sgp-1", "1111")["ListenerStatus"] = "Configuring"
	// 5555 is not an uploaded certificate: its detail tells the expiry.
	pair := certtest.New("Other CA")
	k := certtest.Key()
	other := pair.Issue(k.Public(), []string{"example.com"}, deployNow.Add(-time.Hour), deployNow.Add(3*24*time.Hour))
	d.api.on("GetUserCertificateDetail", func(q url.Values) (int, any) {
		if q.Get("CertId") == "5555" {
			return 200, map[string]any{"Id": 5555, "Name": "bought", "Cert": string(other), "Key": "secret", "EndDate": "2026-11-23"}
		}
		return 400, apiErr("NotFound", "not found")
	})
	rep, err := d.run(cert.DeployOptions{DryRun: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, w := range []string{"UploadUserCertificate", "UpdateListenerAttribute", "DeleteUserCertificate"} {
		if len(d.api.callsFor(w)) != 0 {
			t.Errorf("dry run called %s", w)
		}
	}
	rows := deployRowsOf(rep)
	for _, w := range []string{
		"aliyun-alb/acme/cert would_create upload_example.com_2027-02-18",
		"aliyun-alb/acme/lb-example(HTTPS:443) would_update cert_id=(pending)",
		"aliyun-alb/acme/lb-example(HTTPS:444) would_update cert_id=(pending)",
		"aliyun-alb/acme/lb-example(HTTPS:445) skipped certificate 6666 is not in the CAS certificate list (deleted when it expired?); expiry unknown",
		"aliyun-alb/acme/lb-example(HTTPS:446) skipped listener lsn-4 has no default certificate",
		"aliyun-alb/acme/lb-example(HTTPS:447) skipped listener lsn-5 is Configuring (not waited for in a dry run)",
	} {
		if !slices.Contains(rows, w) {
			t.Errorf("missing row %q in\n%s", w, strings.Join(rows, "\n"))
		}
	}
}

func TestALBDeployerPermissionAndPrune(t *testing.T) {
	d := newALBDeploy(t)
	d.alb.lbFail, d.alb.lbFailStatus = "Forbidden.RAM", 403
	_, err := d.run(cert.DeployOptions{})
	if !errors.Is(err, platform.ErrForbidden) {
		t.Fatalf("denied = %v", err)
	}
	d.alb.lbFail = ""
	d.casCert(3333, "upload_example.com_2026-10-01", deployNow.Add(-50*24*time.Hour), "03")
	d.casCert(4444, "upload_example.com_2026-11-01", deployNow.Add(-19*24*time.Hour), "04")
	d.casCert(5555, "upload_example.com_2027-02-18", deployNow.Add(90*24*time.Hour), "05")
	// No dates at all: never taken as expired.
	d.cas.add(6666, "upload_nodate.com", "")
	d.alb.addLB("alb-1", "lb-example", "vpc-site", "Active")
	d.alb.addListener("lsn-1", "alb-1", "HTTPS", 443, "sgp-1", "5555", "4444")
	rep, err := d.run(cert.DeployOptions{Prune: true, DryRun: true})
	if err != nil || len(d.cas.deletes) != 0 {
		t.Fatalf("dry run prune: %v %v", err, d.cas.deletes)
	}
	rows := deployRowsOf(rep)
	if !slices.Contains(rows, "aliyun-alb/acme/cert/3333 would_delete cert=3333 expired (2026-10-01) upload_example.com_2026-10-01") ||
		!slices.ContainsFunc(rows, func(r string) bool {
			return strings.HasPrefix(r, "aliyun-alb/acme/cert/4444 skipped") && strings.Contains(r, "still used by listener lsn-1")
		}) {
		t.Errorf("rows = %v", rows)
	}
	if _, err := d.run(cert.DeployOptions{Prune: true}); err != nil || !slices.Equal(d.cas.deletes, []string{"3333"}) {
		t.Errorf("prune: %v %v", err, d.cas.deletes)
	}
}

func TestDeployCASName(t *testing.T) {
	for tmpl, want := range map[string]string{
		"":                           "upload_example.com_2027-02-18",
		"upload_{name}_{not_after}":  "upload_example.com_2027-02-18",
		"polyctl-{name}-{not_after}": "polyctl-example.com-2027-02-18",
	} {
		if got, err := deployCASName(platform.DeployOptions{NameTemplate: tmpl}, "example.com", "2027-02-18"); err != nil || got != want {
			t.Errorf("%q = %q, %v", tmpl, got, err)
		}
	}
	if _, err := deployCASName(platform.DeployOptions{NameTemplate: "x-{region}"}, "example.com", "2027-02-18"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("unknown variable = %v", err)
	}
}
