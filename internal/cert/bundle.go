package cert

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"time"
)

// Key types of certificates (the values of --key-type and cert.key_type).
const (
	KeyEC256   = "ec256"
	KeyEC384   = "ec384"
	KeyRSA2048 = "rsa2048"
	KeyRSA4096 = "rsa4096"
)

// KeyTypes lists the key types polyctl issues certificates with.
var KeyTypes = []string{KeyEC256, KeyEC384, KeyRSA2048, KeyRSA4096}

// ErrCorrupt marks a certificate store entry that cannot be used: files
// that do not parse, or a private key that does not belong to the
// certificate. It is never silently replaced or ignored.
var ErrCorrupt = errors.New("certificate store is corrupt")

// Bundle is a certificate of the store with its chain and private key.
type Bundle struct {
	// Domain is the root domain the certificate is stored under.
	Domain string
	// Names are the DNS names of the certificate: the root first, then its
	// wildcard, then any other name.
	Names []string
	// FullchainPEM is the leaf followed by the intermediates; CertPEM the
	// leaf alone; ChainPEM the intermediates; PrivKeyPEM the PKCS#8 key.
	FullchainPEM, CertPEM, ChainPEM, PrivKeyPEM []byte
	Leaf                                        *x509.Certificate
	Key                                         crypto.Signer
	// Serial is the serial number in lowercase hex, byte-aligned (a leading
	// zero of the first byte is kept), without colons.
	Serial string
	// Fingerprint is the SHA-256 of the leaf's DER, lowercase hex.
	Fingerprint string
	NotBefore   time.Time
	NotAfter    time.Time
	// KeyType is one of KeyTypes, or "other".
	KeyType string
	Subject string
	Issuer  string
	// Path is the directory of the bundle in the store.
	Path string
	// IssuedAt and ACMEDirectory come from meta.json, when known.
	IssuedAt      time.Time
	ACMEDirectory string
}

// NewBundle parses a full chain (leaf first) and a private key and checks
// that the key belongs to the leaf.
func NewBundle(domain string, fullchain, privkey []byte) (*Bundle, error) {
	certs, blocks, err := parseCerts(fullchain)
	if err != nil {
		return nil, err
	}
	key, err := ParsePrivateKey(privkey)
	if err != nil {
		return nil, err
	}
	leaf := certs[0]
	if !samePublicKey(leaf.PublicKey, key.Public()) {
		return nil, fmt.Errorf("%w: the private key does not belong to the certificate", ErrCorrupt)
	}
	keyPEM, err := MarshalPrivateKey(key)
	if err != nil {
		return nil, err
	}
	var chain bytes.Buffer
	for _, b := range blocks[1:] {
		_ = pem.Encode(&chain, b)
	}
	sum := sha256.Sum256(leaf.Raw)
	b := &Bundle{
		Domain:       domain,
		Names:        orderNames(domain, leaf.DNSNames),
		FullchainPEM: pemJoin(blocks),
		CertPEM:      pem.EncodeToMemory(blocks[0]),
		ChainPEM:     chain.Bytes(),
		PrivKeyPEM:   keyPEM,
		Leaf:         leaf,
		Key:          key,
		Serial:       SerialHex(leaf),
		Fingerprint:  hex.EncodeToString(sum[:]),
		NotBefore:    leaf.NotBefore.UTC(),
		NotAfter:     leaf.NotAfter.UTC(),
		KeyType:      KeyTypeOf(leaf.PublicKey),
		Subject:      leaf.Subject.String(),
		Issuer:       leaf.Issuer.String(),
	}
	return b, nil
}

// DaysLeft is the number of whole days until the certificate expires,
// rounded down (negative once it has expired).
func (b *Bundle) DaysLeft(now time.Time) int {
	return int(math.Floor(b.NotAfter.Sub(now).Hours() / 24))
}

// CoversRoot reports whether the certificate holds both the root domain
// and its wildcard, in any order.
func (b *Bundle) CoversRoot() bool {
	return slices.Contains(b.Names, b.Domain) && slices.Contains(b.Names, "*."+b.Domain)
}

// Covers reports whether the certificate is valid for host: an exact name,
// or a wildcard name that matches exactly one label in front of its base
// (*.example.com covers www.example.com, not example.com nor a.b.example.com).
func (b *Bundle) Covers(host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, n := range b.Names {
		n = strings.ToLower(n)
		if n == host {
			return true
		}
		if base, ok := strings.CutPrefix(n, "*."); ok {
			if label, rest, found := strings.Cut(host, "."); found && label != "" && label != "*" && rest == base {
				return true
			}
		}
	}
	return false
}

// Staging reports whether the certificate was issued by a staging CA,
// whose certificates no browser trusts (Let's Encrypt names its staging
// issuers "(STAGING) ...").
func (b *Bundle) Staging() bool { return strings.Contains(b.Issuer, "(STAGING)") }

// orderNames puts root first, then *.root, then the other names sorted.
func orderNames(root string, names []string) []string {
	out := make([]string, 0, len(names))
	var rest []string
	seen := map[string]bool{}
	for _, n := range names {
		n = strings.ToLower(n)
		if seen[n] {
			continue
		}
		seen[n] = true
		if n != root && n != "*."+root {
			rest = append(rest, n)
		}
	}
	if seen[root] {
		out = append(out, root)
	}
	if seen["*."+root] {
		out = append(out, "*."+root)
	}
	slices.Sort(rest)
	return append(out, rest...)
}

// SerialHex returns the serial number of c in lowercase hex without
// colons, one byte per two digits (big.Int.Text(16) would drop the leading
// zero of a first byte below 0x10).
func SerialHex(c *x509.Certificate) string { return hex.EncodeToString(c.SerialNumber.Bytes()) }

// KeyTypeOf names the key type of a public key (KeyTypes), or "other".
func KeyTypeOf(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return KeyEC256
		case elliptic.P384():
			return KeyEC384
		}
	case *rsa.PublicKey:
		switch k.N.BitLen() {
		case 2048:
			return KeyRSA2048
		case 4096:
			return KeyRSA4096
		}
	}
	return "other"
}

// KeyLabel is the key type as `cert get` shows it: ecdsa-p256, rsa-2048...
func KeyLabel(keyType string) string {
	switch keyType {
	case KeyEC256:
		return "ecdsa-p256"
	case KeyEC384:
		return "ecdsa-p384"
	case KeyRSA2048:
		return "rsa-2048"
	case KeyRSA4096:
		return "rsa-4096"
	}
	return keyType
}

// GenerateKey creates a private key of a key type.
func GenerateKey(keyType string) (crypto.Signer, error) {
	switch keyType {
	case KeyEC256:
		return ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	case KeyEC384:
		return ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	case KeyRSA2048:
		return rsa.GenerateKey(rand.Reader, 2048)
	case KeyRSA4096:
		return rsa.GenerateKey(rand.Reader, 4096)
	}
	return nil, fmt.Errorf("unknown key type %q (expected one of: %s)", keyType, strings.Join(KeyTypes, ", "))
}

// MarshalPrivateKey encodes a private key as a PKCS#8 "PRIVATE KEY" PEM.
func MarshalPrivateKey(key crypto.Signer) ([]byte, error) {
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), nil
}

// ParsePrivateKey reads a PEM private key: PKCS#8 ("PRIVATE KEY"), SEC 1
// ("EC PRIVATE KEY") or PKCS#1 ("RSA PRIVATE KEY"), so that keys copied
// from another ACME client are read too.
func ParsePrivateKey(data []byte) (crypto.Signer, error) {
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, fmt.Errorf("%w: no private key found", ErrCorrupt)
		}
		var key any
		var err error
		switch b.Type {
		case "PRIVATE KEY":
			key, err = x509.ParsePKCS8PrivateKey(b.Bytes)
		case "EC PRIVATE KEY":
			key, err = x509.ParseECPrivateKey(b.Bytes)
		case "RSA PRIVATE KEY":
			key, err = x509.ParsePKCS1PrivateKey(b.Bytes)
		default:
			continue
		}
		if err != nil {
			return nil, fmt.Errorf("%w: private key: %v", ErrCorrupt, err)
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("%w: unsupported private key type %T", ErrCorrupt, key)
		}
		return s, nil
	}
}

// parseCerts reads the certificates of a PEM chain, in order.
func parseCerts(data []byte) ([]*x509.Certificate, []*pem.Block, error) {
	var certs []*x509.Certificate
	var blocks []*pem.Block
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, nil, fmt.Errorf("%w: certificate: %v", ErrCorrupt, err)
		}
		certs = append(certs, c)
		blocks = append(blocks, &pem.Block{Type: "CERTIFICATE", Bytes: b.Bytes})
	}
	if len(certs) == 0 {
		return nil, nil, fmt.Errorf("%w: no certificate found", ErrCorrupt)
	}
	return certs, blocks, nil
}

func pemJoin(blocks []*pem.Block) []byte {
	var buf bytes.Buffer
	for _, b := range blocks {
		_ = pem.Encode(&buf, b)
	}
	return buf.Bytes()
}

// samePublicKey compares two public keys.
func samePublicKey(a, b crypto.PublicKey) bool {
	type equaler interface{ Equal(crypto.PublicKey) bool }
	if e, ok := a.(equaler); ok {
		return e.Equal(b)
	}
	return false
}
