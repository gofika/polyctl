package platform

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	"testing"
	"time"
)

func selfSigned(t *testing.T, key crypto.Signer, signer crypto.Signer, names []string, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(7), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: notAfter.Add(-90 * 24 * time.Hour), NotAfter: notAfter}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), signer)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

func TestParseCertMaterial(t *testing.T) {
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	ec, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rk, _ := rsa.GenerateKey(rand.Reader, 2048)
	certPEM := selfSigned(t, ec, ec, []string{"example.com", "*.example.com"}, now.Add(60*24*time.Hour))
	pkcs8, _ := x509.MarshalPKCS8PrivateKey(ec)
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: pkcs8})
	sec1, _ := x509.MarshalECPrivateKey(ec)
	ecPEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})

	m, err := ParseCertMaterial(certPEM, keyPEM, now)
	if err != nil || m.Fingerprint == "" || !m.Covers("www.example.com") || !m.Covers("example.com") || m.Covers("a.b.example.com") {
		t.Fatalf("material = %+v, %v", m, err)
	}
	// One text holding both, and a SEC 1 key.
	both := append(append([]byte{}, certPEM...), ecPEM...)
	if m2, err := ParseCertMaterial(both, both, now); err != nil || m2.Fingerprint != m.Fingerprint || string(m2.Fullchain) != string(certPEM) {
		t.Fatalf("combined = %v", err)
	}
	// RSA PKCS#1.
	rsaCert := selfSigned(t, rk, rk, []string{"rsa.example.com"}, now.Add(time.Hour))
	if _, err := ParseCertMaterial(rsaCert, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(rk)}), now); err != nil {
		t.Fatalf("rsa = %v", err)
	}
	otherDER, _ := x509.MarshalPKCS8PrivateKey(other)
	expired := selfSigned(t, ec, ec, []string{"example.com"}, now.Add(-time.Hour))
	for name, c := range map[string][2][]byte{
		"not pem":     {[]byte("not a pem"), keyPEM},
		"no key":      {certPEM, []byte("nothing")},
		"encrypted":   {certPEM, pem.EncodeToMemory(&pem.Block{Type: "ENCRYPTED PRIVATE KEY", Bytes: []byte{1}})},
		"legacy enc":  {certPEM, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Headers: map[string]string{"Proc-Type": "4,ENCRYPTED"}, Bytes: []byte{1}})},
		"mismatch":    {certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER})},
		"expired":     {expired, keyPEM},
		"bad key der": {certPEM, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: []byte{1, 2}})},
	} {
		if _, err := ParseCertMaterial(c[0], c[1], now); !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: err = %v, want invalid input", name, err)
		}
	}
}

func TestCertDomainAndCovers(t *testing.T) {
	for _, c := range []struct {
		names []string
		cn    string
		want  string
	}{
		{[]string{"*.example.com", "Example.com"}, "", "example.com"},
		{[]string{"*.example.com"}, "", "example.com"},
		{nil, "*.Example.org", "example.org"},
		{nil, "", ""},
	} {
		if got := CertDomain(c.names, c.cn); got != c.want {
			t.Errorf("CertDomain(%v, %q) = %q, want %q", c.names, c.cn, got, c.want)
		}
	}
	if !CertCovers([]string{"*.example.com"}, "WWW.example.com.") || CertCovers([]string{"*.example.com"}, "example.com") ||
		!CertCovers([]string{"*.example.com"}, "*.example.com") {
		t.Error("CertCovers")
	}
	if _, fp, err := LeafOf("junk"); err == nil || fp != "" {
		t.Error("LeafOf junk")
	}
}
