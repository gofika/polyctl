package aws

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/cert/certtest"
	"github.com/gofika/polyctl/internal/platform"
)

// issue returns a chain and key of root valid until notAfter (an ECDSA
// P-256 key unless key is given).
func issue(t *testing.T, ca *certtest.CA, root string, key crypto.Signer, notAfter time.Time) (*cert.Bundle, []byte, []byte) {
	t.Helper()
	if key == nil {
		key = certtest.Key()
	}
	chain := ca.Issue(key.Public(), cert.Names(root), time.Now().Add(-time.Hour), notAfter)
	keyPEM := certtest.KeyPEM(key)
	b, err := cert.NewBundle(root, chain, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	return b, chain, keyPEM
}

// storeBundle saves b as the live certificate of its domain in the
// harness's local store.
func storeBundle(t *testing.T, h *awsHarness, b *cert.Bundle) {
	t.Helper()
	st, err := cert.OpenRuntimeStore(h.rt, false)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(b); err != nil {
		t.Fatal(err)
	}
}

type importOut struct {
	platform.Report
	ARN string `json:"arn"`
}

func (h *awsHarness) importOut() importOut {
	h.t.Helper()
	var out importOut
	h.jsonOut(&out)
	return out
}

func TestACMImportFromStore(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, map[string]any{"tags": map[string]any{"team": "ops"}})
	ca := certtest.New("Test Issuer")
	b, _, _ := issue(t, ca, "example.com", nil, time.Now().Add(90*24*time.Hour))
	storeBundle(t, h, b)

	// No imported certificate of the domain: a new one, tagged.
	if err := h.run("acm", "certificate", "import", "www.example.com", "--tag", "env=prod"); err != nil {
		t.Fatalf("import: %v\n%s", err, h.stderr.String())
	}
	out := h.importOut()
	if a := actions(out.Report); a["certificate/example.com created"] != 1 || out.ARN == "" || out.ARN == platform.Pending {
		t.Errorf("out = %+v", out)
	}
	in := h.acm().imports[0]
	tags := map[string]string{}
	for _, tg := range in.Tags {
		tags[awssdk.ToString(tg.Key)] = awssdk.ToString(tg.Value)
	}
	if strings.Count(string(in.Certificate), "BEGIN CERTIFICATE") != 1 || strings.Count(string(in.CertificateChain), "BEGIN CERTIFICATE") != 2 ||
		!strings.Contains(string(in.PrivateKey), "PRIVATE KEY") || in.CertificateArn != nil ||
		tags["polyctl:domain"] != "example.com" || tags["team"] != "ops" || tags["env"] != "prod" {
		t.Errorf("import input: arn %v, tags %v", in.CertificateArn, tags)
	}
	arn := out.ARN

	// The same certificate again: unchanged, nothing written.
	h.resetACM()
	if err := h.run("acm", "certificate", "import", "example.com"); err != nil {
		t.Fatal(err)
	}
	if out := h.importOut(); len(h.acmWrites()) != 0 || actions(out.Report)["certificate/example.com unchanged"] != 1 || out.ARN != arn {
		t.Errorf("second run = %+v, writes %v", out, h.acmWrites())
	}

	// A renewed certificate: re-imported into the same ARN, without tags.
	renewed, _, _ := issue(t, ca, "example.com", nil, time.Now().Add(120*24*time.Hour))
	storeBundle(t, h, renewed)
	h.resetACM()
	if err := h.run("acm", "certificate", "import", "example.com"); err != nil {
		t.Fatal(err)
	}
	out = h.importOut()
	if a := actions(out.Report); a["certificate/example.com updated"] != 1 || out.ARN != arn {
		t.Errorf("renewed = %+v", out)
	}
	if in := h.acm().imports[0]; awssdk.ToString(in.CertificateArn) != arn || len(in.Tags) != 0 {
		t.Errorf("re-import input: arn %v, tags %v", awssdk.ToString(in.CertificateArn), in.Tags)
	}
	if !strings.Contains(out.Changes[0].Detail, "the ARN stays") {
		t.Errorf("detail = %q", out.Changes[0].Detail)
	}

	// Another key algorithm: refused before anything is sent.
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaBundle, _, _ := issue(t, ca, "example.com", rsaKey, time.Now().Add(150*24*time.Hour))
	storeBundle(t, h, rsaBundle)
	h.resetACM()
	err = h.run("acm", "certificate", "import", "example.com")
	if err == nil || !strings.Contains(err.Error(), "--new") || len(h.acmWrites()) != 0 || errors.Is(err, app.ErrUsage) {
		t.Errorf("key change = %v, writes %v", err, h.acmWrites())
	}
	// --new imports it as a new certificate.
	if err := h.run("acm", "certificate", "import", "example.com", "--new"); err != nil {
		t.Fatal(err)
	}
	if out := h.importOut(); out.ARN == arn || actions(out.Report)["certificate/example.com created"] != 1 {
		t.Errorf("--new = %+v", out)
	}
	// Two imported certificates of the domain, one of them holding the
	// certificate of the store: that one is the target, nothing changes.
	if err := h.run("acm", "certificate", "import", "example.com"); err != nil {
		t.Fatal(err)
	}
	if out := h.importOut(); out.ARN == arn || actions(out.Report)["certificate/example.com unchanged"] != 1 {
		t.Errorf("holding the serial = %+v", out)
	}
	// Neither holds it: ambiguous without --arn.
	renewed, _, _ = issue(t, ca, "example.com", rsaKey, time.Now().Add(160*24*time.Hour))
	storeBundle(t, h, renewed)
	var amb *app.AmbiguousError
	if err := h.run("acm", "certificate", "import", "example.com"); !errors.As(err, &amb) || len(amb.Candidates) != 2 {
		t.Errorf("two imported = %v", err)
	}
	h.rt.Flags.DryRun = true
	defer func() { h.rt.Flags.DryRun = false }()
	if err := h.run("acm", "certificate", "import", "example.com", "--arn", arn); err == nil || !strings.Contains(err.Error(), "key algorithm") {
		t.Errorf("--arn with the other key = %v", err)
	}
}

func TestACMImportDryRunAndFiles(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	ca := certtest.New("Test Issuer")
	b, chain, keyPEM := issue(t, ca, "example.com", nil, time.Now().Add(90*24*time.Hour))
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "fullchain.pem"), filepath.Join(dir, "privkey.pem")
	if err := os.WriteFile(certPath, chain, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("acm", "certificate", "import", "example.com", "--cert-file", certPath, "--key-file", keyPath); err != nil {
		t.Fatal(err)
	}
	out := h.importOut()
	if len(h.acmWrites()) != 0 || !out.DryRun || out.ARN != platform.Pending || out.Changes[0].Action != platform.WouldCreate {
		t.Errorf("dry run = %+v", out)
	}
	h.rt.Flags.DryRun = false
	if err := h.run("acm", "certificate", "import", "example.com", "--cert-file", certPath, "--key-file", keyPath); err != nil {
		t.Fatal(err)
	}
	if in := h.acm().imports; len(in) != 1 || strings.Count(string(in[0].Certificate), "BEGIN CERTIFICATE") != 1 {
		t.Errorf("imports = %d", len(in))
	}
	arn := h.importOut().ARN
	c := h.ec2.acm.certs[0]
	if normalizeSerial(c.serial) != normalizeSerial(b.Serial) {
		t.Errorf("serial %s != %s", c.serial, b.Serial)
	}
	// A dry run of a renewal: would update, the ARN stays.
	renewed, chain2, key2 := issue(t, ca, "example.com", nil, time.Now().Add(100*24*time.Hour))
	_ = renewed
	if err := os.WriteFile(certPath, chain2, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, key2, 0o600); err != nil {
		t.Fatal(err)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("acm", "certificate", "import", "example.com", "--cert-file", certPath, "--key-file", keyPath); err != nil {
		t.Fatal(err)
	}
	if out := h.importOut(); out.ARN != arn || out.Changes[0].Action != platform.WouldUpdate || len(h.acmWrites()) != 1 {
		t.Errorf("dry run renewal = %+v", out)
	}
	h.rt.Flags.DryRun = false

	// Usage errors.
	otherKey := certtest.KeyPEM(certtest.Key())
	other := filepath.Join(dir, "other.pem")
	if err := os.WriteFile(other, otherKey, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"example.com", "--cert-file", certPath},
		{"example.com", "--chain-file", certPath},
		{"example.com", "--cert-file", certPath, "--key-file", other},
		{"example.org", "--cert-file", certPath, "--key-file", keyPath},
		{"example.com", "--cert-file", filepath.Join(dir, "missing.pem"), "--key-file", keyPath},
		{"example.com", "--new", "--arn", arn},
		{"example.com", "--arn", "arn:aws:acm:bad"},
		{"example.com", "--arn", arn, "--region", "us-east-1"},
	} {
		if err := h.run(append([]string{"acm", "certificate", "import"}, args...)...); !ExitUsageErr(err) {
			t.Errorf("%v = %v, want a usage error", args, err)
		}
	}
	// No certificate in the store: exit code 4.
	if err := h.run("acm", "certificate", "import", "example.net"); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "cert ensure") {
		t.Errorf("empty store = %v", err)
	}
}

func TestACMImportExpired(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	ca := certtest.New("Test Issuer")
	key := certtest.Key()
	chain := ca.Issue(key.Public(), cert.Names("example.com"), time.Now().Add(-48*time.Hour), time.Now().Add(-time.Hour))
	b, err := cert.NewBundle("example.com", chain, certtest.KeyPEM(key))
	if err != nil {
		t.Fatal(err)
	}
	storeBundle(t, h, b)
	err = h.run("acm", "certificate", "import", "example.com")
	if err == nil || !strings.Contains(err.Error(), "validity period") || len(h.acmCalls()) != 0 {
		t.Errorf("expired = %v, calls %v", err, h.acmCalls())
	}
}

func TestACMImportRefusesAmazonIssued(t *testing.T) {
	h, _ := newACMHarness(t, app.Flags{}, nil)
	ca := certtest.New("Test Issuer")
	b, _, _ := issue(t, ca, "example.com", nil, time.Now().Add(90*24*time.Hour))
	storeBundle(t, h, b)
	c := h.addCert(&fakeCert{region: "ap-east-1", domain: "*.example.com", status: acmIssued})
	err := h.run("acm", "certificate", "import", "example.com", "--arn", c.arn)
	if err == nil || !strings.Contains(err.Error(), "AMAZON_ISSUED") || len(h.acmWrites()) != 0 {
		t.Errorf("amazon issued = %v", err)
	}
}
