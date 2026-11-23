// Package certtest builds certificate chains for tests: a throwaway root
// and intermediate that sign leaf certificates of any names and validity,
// so that certificate code is tested without a CA.
package certtest

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"sync"
	"time"
)

// CA is a root and an intermediate certificate authority.
type CA struct {
	rootKey, interKey *ecdsa.PrivateKey
	root, inter       *x509.Certificate
	// IssuerName is the common name of the intermediate, which leaf
	// certificates name as their issuer.
	IssuerName string

	mu     sync.Mutex
	serial int64
}

// New creates a CA whose intermediate is called issuerName ("(STAGING)
// Fake Issuer" makes a staging-looking chain).
func New(issuerName string) *CA {
	ca := &CA{IssuerName: issuerName, serial: 0x0a00}
	ca.rootKey = mustKey()
	ca.interKey = mustKey()
	now := time.Now()
	rootTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test Root", Organization: []string{"polyctl test"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(10 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca.root = mustCert(rootTmpl, rootTmpl, ca.rootKey.Public(), ca.rootKey)
	interTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: issuerName, Organization: []string{"polyctl test"}, Country: []string{"US"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(5 * 365 * 24 * time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	ca.inter = mustCert(interTmpl, ca.root, ca.interKey.Public(), ca.rootKey)
	return ca
}

// Issue signs a leaf certificate for pub with the given DNS names (the
// first one is the subject CN) valid from notBefore to notAfter, and
// returns the chain as PEM: leaf, intermediate, root.
func (ca *CA) Issue(pub crypto.PublicKey, names []string, notBefore, notAfter time.Time) []byte {
	ca.mu.Lock()
	ca.serial++
	serial := ca.serial
	ca.mu.Unlock()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(serial),
		Subject:      pkix.Name{CommonName: names[0]},
		DNSNames:     names,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leaf := mustCert(tmpl, ca.inter, pub, ca.interKey)
	out := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leaf.Raw})
	out = append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.inter.Raw})...)
	return append(out, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ca.root.Raw})...)
}

// Key returns a new ECDSA P-256 key.
func Key() *ecdsa.PrivateKey { return mustKey() }

// KeyPEM encodes key as PKCS#8 PEM.
func KeyPEM(key crypto.Signer) []byte {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		panic(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func mustKey() *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	return k
}

func mustCert(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) *x509.Certificate {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		panic(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}
	return c
}
