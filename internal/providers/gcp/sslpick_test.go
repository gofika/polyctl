package gcp

import (
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/cert"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// storeCert saves a certificate of the names into polyctl's certificate
// store of the harness, under root.
func storeCert(t *testing.T, h *gcpHarness, root string, p pemPair) {
	t.Helper()
	st, err := cert.OpenRuntimeStore(h.rt, false)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cert.NewBundle(root, p.chain, p.key)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Save(b); err != nil {
		t.Fatal(err)
	}
}

// create without files, scope and name: the store's certificate, the
// scope (Global and the regions that are UP) and the templated name.
func TestSSLCertificateCreateAsks(t *testing.T) {
	h, _ := interactiveGCP(t, map[string]any{"zone": "europe-west1-b"})
	storeCert(t, h, "example.com", newPair(t, []string{"example.com", "*.example.com"}, 90))
	p := h.answer("example.com", "us-central1", prompttest.KeepDefault{})
	if err := h.run("compute", "ssl-certificate", "create"); err != nil {
		t.Fatalf("create: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "example.com  example.com,*.example.com  expires 2026-04-01 (90 days)") || !strings.Contains(l, "Other files...") {
		t.Errorf("store offered:\n%s", l)
	}
	scope := p.Find("Scope of the certificate")
	if v := prompttest.Values(scope.Options); v != globalScope+" europe-west1 us-central1" || scope.Default != "europe-west1" {
		t.Errorf("scopes offered %q, default %q", v, scope.Default)
	}
	if h.gce.cert("us-central1", "example-com-cert-20260101") == nil {
		t.Errorf("certificate not created: %v", h.gce.lbWrites())
	}

	// Other files: the key is checked against the certificate as typed.
	pair, wrong := newPair(t, []string{"other.com"}, 30), newPair(t, []string{"x.com"}, 30)
	p = h.answer(otherValue, pair.certFile, wrong.keyFile, pair.keyFile, globalScope, "other-cert")
	if err := h.run("compute", "ssl-certificate", "create"); err != nil {
		t.Fatalf("create from files: %v", err)
	}
	p.Done()
	if h.gce.cert("global", "other-cert") == nil {
		t.Errorf("global certificate not created")
	}

	h.nonInteractive()
	if err := h.run("compute", "ssl-certificate", "create", "x-cert", "--cert-file", pair.certFile, "--key-file", pair.keyFile); exitClass(err) != "usage" || !strings.Contains(err.Error(), "--global") {
		t.Errorf("non-interactive = %v", err)
	}
}

// update without <name> offers the self-managed certificates of every
// scope (Google-managed ones left out); delete offers those no proxy uses.
func TestSSLCertificateUpdateDeletePick(t *testing.T) {
	h, _ := interactiveGCP(t, nil)
	old := newPair(t, []string{"example.com"}, 10)
	h.gce.addCert("us-central1", "example-com-cert-old", old.chain)
	h.gce.addCert("global", "free", old.chain)
	h.gce.addManagedCert("global", "managed", []string{"m.example.com"}, "2026-06-01T00:00:00Z")
	h.gce.addHTTPSProxy("us-central1", "proxy-https-web-1", "lb-web-1", "example-com-cert-old")
	storeCert(t, h, "example.com", newPair(t, []string{"example.com"}, 90))

	p := h.answer(prompttest.Label("example-com-cert-old"), "example.com")
	if err := h.run("compute", "ssl-certificate", "update"); err != nil {
		t.Fatalf("update: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); strings.Contains(l, "managed  global  MANAGED") || !strings.Contains(l, "example-com-cert-old  us-central1  SELF_MANAGED  example.com  expires 2026-01-11 (10 days)  used by proxy-https-web-1") {
		t.Errorf("certificates offered:\n%s", l)
	}
	if p.Asked[1].Default != "example.com" {
		t.Errorf("store default %q", p.Asked[1].Default)
	}
	if got := h.gce.proxyCerts("us-central1", "proxy-https-web-1"); len(got) != 1 || !strings.Contains(got[0], "example-com-cert-20260101") {
		t.Errorf("proxy certs = %v", got)
	}

	p = h.answer(prompttest.Label("free"))
	if err := h.run("compute", "ssl-certificate", "delete", "--yes"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	p.Done()
	if l := prompttest.Labels(p.Asked[0].Options); strings.Contains(l, "proxy-https-web-1") {
		t.Errorf("delete offered a certificate in use:\n%s", l)
	}
	if h.gce.cert("global", "free") != nil {
		t.Errorf("free not deleted")
	}
}
