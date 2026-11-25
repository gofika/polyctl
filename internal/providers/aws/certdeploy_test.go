package aws

import (
	"context"
	"fmt"
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

type acmDeploy struct {
	t      *testing.T
	h      *awsHarness
	c      *client
	bundle *cert.Bundle
}

func newACMDeploy(t *testing.T) *acmDeploy {
	h := newAWSHarness(t, app.Flags{}, nil)
	c, err := openProfile(t.Context(), h.rt, "lab")
	if err != nil {
		t.Fatal(err)
	}
	ca := certtest.New("Fake R1")
	key := certtest.Key()
	chain := ca.Issue(key.Public(), []string{"example.com", "*.example.com"}, deployNow.Add(-time.Hour), deployNow.Add(90*24*time.Hour))
	b, err := cert.NewBundle("example.com", chain, certtest.KeyPEM(key))
	if err != nil {
		t.Fatal(err)
	}
	return &acmDeploy{t: t, h: h, c: c, bundle: b}
}

// colons writes a serial number the way ACM does: 0a:1b:...
func colons(hexs string) string {
	var parts []string
	for i := 0; i+1 < len(hexs); i += 2 {
		parts = append(parts, hexs[i:i+2])
	}
	return strings.Join(parts, ":")
}

func (d *acmDeploy) run(o cert.DeployOptions, regions ...string) (*cert.DeployReport, error) {
	d.t.Helper()
	dep, _ := platform.GetDeployer(acmDeployerID)
	o.Deployers = []platform.CertDeployer{dep}
	if o.Days == 0 {
		o.Days = 30
	}
	if o.Domain == "" {
		o.All = true
	}
	d.h.resetACM()
	env := &cert.DeployEnv{
		Accounts: []config.AccountRef{{Profile: "lab", Platform: platform.AWS}},
		Open:     func(context.Context, config.AccountRef) (platform.Client, error) { return d.c, nil },
		Regions:  func(config.AccountRef) []string { return regions },
		Ensure: func(_ context.Context, root string, days int) (*cert.Result, error) {
			if root != "example.com" {
				return nil, fmt.Errorf("%w: %s", app.ErrDomainUnknown, root)
			}
			return &cert.Result{Bundle: d.bundle}, nil
		},
		Now: func() time.Time { return deployNow },
	}
	return cert.Deploy(context.Background(), env, o)
}

func acmRows(rep *cert.DeployReport) []string {
	var out []string
	for _, c := range rep.Changes {
		out = append(out, c.Resource+" "+string(c.Action)+" "+c.Detail)
	}
	return out
}

func at(days int) *time.Time {
	t := deployNow.Add(time.Duration(days) * 24 * time.Hour)
	return &t
}

func TestACMDeployerReimportsInPlace(t *testing.T) {
	d := newACMDeploy(t)
	imported := d.h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", names: []string{"*.example.com", "example.com"}, typ: acmImported,
		status: acmIssued, notAfter: at(10), serial: "0f:99", inUseBy: []string{"arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/app/web/1"}})
	d.h.addCert(&fakeCert{region: "ap-east-1", domain: "amazon.example.com", status: acmIssued, notAfter: at(5)})
	d.h.addCert(&fakeCert{region: "ap-east-1", domain: "pending.example.com", status: acmPendingValidation})
	rep, err := d.run(cert.DeployOptions{})
	if err != nil {
		t.Fatalf("deploy: %v %v", err, acmRows(rep))
	}
	s := d.h.acm()
	if len(s.lists) == 0 || len(s.lists[0].Includes.KeyTypes) != len(acmSyncKeyTypes) {
		t.Errorf("ListCertificates must ask for every key type: %+v", s.lists)
	}
	if len(s.imports) != 1 {
		t.Fatalf("imports = %d", len(s.imports))
	}
	in := s.imports[0]
	if *in.CertificateArn != imported.arn || len(in.Tags) != 0 || strings.Count(string(in.Certificate), "BEGIN CERTIFICATE") != 1 || len(in.CertificateChain) == 0 {
		t.Errorf("import = arn %v tags %v", *in.CertificateArn, in.Tags)
	}
	if platform.SerialKey(imported.serial) != platform.SerialKey(d.bundle.Serial) {
		t.Errorf("serial after import = %s", imported.serial)
	}
	rows := acmRows(rep)
	for _, w := range []string{
		"aws-acm/lab/ap-east-1/" + imported.arn + " updated re-imported serial " + d.bundle.Serial + ", EC_prime256v1, expires 2027-02-18 (the ARN stays)",
		"aws-acm/lab/ap-east-1/" + s.certs[1].arn + " skipped Type=AMAZON_ISSUED, renewed by ACM",
	} {
		if !slices.Contains(rows, w) {
			t.Errorf("missing row %q in\n%s", w, strings.Join(rows, "\n"))
		}
	}
	if !slices.ContainsFunc(rows, func(r string) bool {
		return strings.Contains(r, "status PENDING_VALIDATION: complete its DNS validation")
	}) {
		t.Errorf("rows = %v", rows)
	}
	// Second run: fresh, nothing written; a domain run finds the serial.
	if _, err := d.run(cert.DeployOptions{}); err != nil || len(d.h.acmWrites()) != 0 {
		t.Errorf("second run: %v %v", err, d.h.acmWrites())
	}
	if _, err := d.run(cert.DeployOptions{Domain: "example.com"}); err != nil || len(d.h.acmWrites()) != 0 {
		t.Errorf("domain run: %v %v", err, d.h.acmWrites())
	}
}

func TestACMDeployerKeyAlgorithmChangeAndDryRun(t *testing.T) {
	d := newACMDeploy(t)
	rsa := d.h.addCert(&fakeCert{region: "us-east-1", domain: "example.com", typ: acmImported, status: acmIssued, keyAlg: "RSA_2048",
		notAfter: at(3), serial: "0b:02"})
	rep, err := d.run(cert.DeployOptions{DryRun: true}, "us-east-1")
	if err != nil || len(d.h.acmWrites()) != 0 {
		t.Fatalf("dry run: %v %v", err, d.h.acmWrites())
	}
	if !slices.Contains(acmRows(rep), "aws-acm/lab/us-east-1/"+rsa.arn+" would_update import as a new certificate (serial "+d.bundle.Serial+", EC_prime256v1, expires 2027-02-18): the ARN changes") {
		t.Errorf("rows = %v", acmRows(rep))
	}
	rep, err = d.run(cert.DeployOptions{}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	s := d.h.acm()
	if len(s.imports) != 1 || s.imports[0].CertificateArn != nil || len(s.imports[0].Tags) != 1 || *s.imports[0].Tags[0].Key != "polyctl:domain" {
		t.Fatalf("imports = %+v", s.imports)
	}
	if rsa.serial != "0b:02" || !slices.ContainsFunc(acmRows(rep), func(r string) bool { return strings.Contains(r, "the ARN changed, update where "+rsa.arn+" is used") }) {
		t.Errorf("rows = %v", acmRows(rep))
	}
	newARN := s.certs[len(s.certs)-1].arn
	// The next runs find the certificate imported already: nothing is
	// imported again, in --all and in domain mode.
	for _, o := range []cert.DeployOptions{{}, {Domain: "example.com"}} {
		rep, err = d.run(o, "us-east-1")
		if err != nil || len(d.h.acmWrites()) != 0 {
			t.Fatalf("run %+v: %v %v", o, err, d.h.acmWrites())
		}
		if !slices.ContainsFunc(acmRows(rep), func(r string) bool {
			return strings.HasPrefix(r, "aws-acm/lab/us-east-1/"+rsa.arn+" skipped") && strings.Contains(r, "imported as "+newARN+" already")
		}) {
			t.Errorf("run %+v rows = %v", o, acmRows(rep))
		}
	}
}

// After a renewal, the certificate an earlier run imported with the new
// key type still holds the old serial. Whichever of the old certificate
// and its replacement is handled first, the replacement is re-imported in
// place and no further certificate is imported.
func TestACMDeployerReplacementIndependentOfOrder(t *testing.T) {
	for _, oldFirst := range []bool{true, false} {
		t.Run(fmt.Sprint("oldFirst=", oldFirst), func(t *testing.T) {
			d := newACMDeploy(t)
			addOld := func() *fakeCert {
				return d.h.addCert(&fakeCert{region: "us-east-1", domain: "example.com", typ: acmImported, status: acmIssued, keyAlg: "RSA_2048",
					notAfter: at(3), serial: "0b:02", inUseBy: []string{"arn:aws:elasticloadbalancing:us-east-1:123456789012:loadbalancer/app/web/1"}})
			}
			addNew := func() *fakeCert {
				return d.h.addCert(&fakeCert{region: "us-east-1", domain: "example.com", names: []string{"example.com", "*.example.com"}, typ: acmImported,
					status: acmIssued, notAfter: at(4), serial: "0c:01", tags: map[string]string{"polyctl:domain": "example.com"}})
			}
			var old, repl *fakeCert
			if oldFirst {
				old, repl = addOld(), addNew()
			} else {
				repl, old = addNew(), addOld()
			}
			rep, err := d.run(cert.DeployOptions{}, "us-east-1")
			if err != nil {
				t.Fatalf("deploy: %v %v", err, acmRows(rep))
			}
			s := d.h.acm()
			if len(s.certs) != 2 || len(s.imports) != 1 || s.imports[0].CertificateArn == nil || *s.imports[0].CertificateArn != repl.arn {
				t.Fatalf("certs=%d imports=%+v", len(s.certs), s.imports)
			}
			if platform.SerialKey(repl.serial) != platform.SerialKey(d.bundle.Serial) || old.serial != "0b:02" {
				t.Errorf("serials: replacement %s, old %s", repl.serial, old.serial)
			}
			if !slices.ContainsFunc(acmRows(rep), func(r string) bool {
				return strings.HasPrefix(r, "aws-acm/lab/us-east-1/"+old.arn+" skipped") && strings.Contains(r, repl.arn)
			}) {
				t.Errorf("rows = %v", acmRows(rep))
			}
		})
	}
}

// An imported certificate of the new key type that serves fewer names
// than the old certificate (another certificate of a subdomain) does not
// replace it: the old certificate is imported as a new certificate.
func TestACMDeployerReplacementServesTheOldNames(t *testing.T) {
	d := newACMDeploy(t)
	old := d.h.addCert(&fakeCert{region: "us-east-1", domain: "example.com", names: []string{"example.com", "*.example.com"}, typ: acmImported,
		status: acmIssued, keyAlg: "RSA_2048", notAfter: at(3), serial: "0b:02"})
	www := d.h.addCert(&fakeCert{region: "us-east-1", domain: "www.example.com", typ: acmImported, status: acmIssued, notAfter: at(4), serial: "0c:01"})
	rep, err := d.run(cert.DeployOptions{}, "us-east-1")
	if err != nil {
		t.Fatalf("deploy: %v %v", err, acmRows(rep))
	}
	if slices.ContainsFunc(acmRows(rep), func(r string) bool {
		return strings.HasPrefix(r, "aws-acm/lab/us-east-1/"+old.arn+" skipped") && strings.Contains(r, www.arn)
	}) {
		t.Errorf("the certificate of www.example.com replaces %s: %v", old.arn, acmRows(rep))
	}
	news := 0
	for _, in := range d.h.acm().imports {
		if in.CertificateArn == nil {
			news++
		}
	}
	if news != 1 {
		t.Errorf("new imports = %d, rows %v", news, acmRows(rep))
	}
}

func TestACMDeployerRefusedReimportImportsOnce(t *testing.T) {
	d := newACMDeploy(t)
	old := d.h.addCert(&fakeCert{region: "us-east-1", domain: "example.com", typ: acmImported, status: acmIssued, notAfter: at(3), serial: "0b:02"})
	d.h.acm().refuseReimport = true
	if _, err := d.run(cert.DeployOptions{}, "us-east-1"); err != nil {
		t.Fatal(err)
	}
	if n := len(d.h.acm().certs); n != 2 {
		t.Fatalf("certificates after the first run = %d", n)
	}
	rep, err := d.run(cert.DeployOptions{}, "us-east-1")
	if err != nil {
		t.Fatal(err)
	}
	s := d.h.acm()
	if len(s.certs) != 2 || len(s.imports) != 1 || s.imports[0].CertificateArn == nil || *s.imports[0].CertificateArn != old.arn {
		t.Fatalf("second run: certs=%d imports=%+v", len(s.certs), s.imports)
	}
	if !slices.ContainsFunc(acmRows(rep), func(r string) bool {
		return strings.HasPrefix(r, "aws-acm/lab/us-east-1/"+old.arn+" skipped") && strings.Contains(r, "ACM refused the re-import")
	}) {
		t.Errorf("rows = %v", acmRows(rep))
	}
}

func TestACMDeployerPrune(t *testing.T) {
	d := newACMDeploy(t)
	gone := d.h.addCert(&fakeCert{region: "ap-east-1", domain: "gone.example.org", typ: acmImported, status: acmExpired, notAfter: at(-4), serial: "01"})
	used := d.h.addCert(&fakeCert{region: "ap-east-1", domain: "used.example.org", typ: acmImported, status: acmExpired, notAfter: at(-4), serial: "02",
		inUseBy: []string{"arn:aws:elasticloadbalancing:ap-east-1:123456789012:loadbalancer/app/web/1"}})
	amazon := d.h.addCert(&fakeCert{region: "ap-east-1", domain: "amazon.example.org", status: acmExpired, notAfter: at(-4)})
	rep, err := d.run(cert.DeployOptions{Prune: true})
	if err != nil {
		t.Fatal(err)
	}
	var arns []string
	for _, c := range d.h.acm().certs {
		arns = append(arns, c.arn)
	}
	if slices.Contains(arns, gone.arn) || !slices.Contains(arns, used.arn) || !slices.Contains(arns, amazon.arn) {
		t.Errorf("left = %v", arns)
	}
	if !slices.ContainsFunc(acmRows(rep), func(r string) bool {
		return strings.HasPrefix(r, "aws-acm/lab/ap-east-1/"+used.arn+" skipped") && strings.Contains(r, "still used by")
	}) {
		t.Errorf("rows = %v", acmRows(rep))
	}
}
