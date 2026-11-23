package platform

import (
	"bytes"
	"context"
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"
)

// Certificate is a certificate a platform holds (an AWS Certificate Manager
// certificate). Empty fields are unknown: a listing reports less than a
// detailed read.
type Certificate struct {
	// ID is the platform id (an ACM ARN).
	ID     string
	Region string
	// Domain is the primary name of the certificate.
	Domain string
	// Names are the names of the certificate (the primary name included),
	// as the platform reports them. NamesTruncated is set when a listing
	// returned only some of them.
	Names          []string
	NamesTruncated bool
	Status         string
	Type           string
	// KeyAlgorithm is in the spelling of requests (EC_prime256v1, RSA_2048).
	KeyAlgorithm string
	InUse        bool
	InUseBy      []string
	Issuer       string
	Serial       string
	CreatedAt    *time.Time
	IssuedAt     *time.Time
	ImportedAt   *time.Time
	NotBefore    *time.Time
	NotAfter     *time.Time
	// RenewalEligibility and FailureReason are empty when the platform
	// did not report them (a listing, a certificate that did not fail).
	RenewalEligibility string
	FailureReason      string
	// Validation lists the domain validations of the certificate, one per
	// name, with the DNS record that proves control when the platform has
	// published it.
	Validation []ValidationRecord
}

// ValidationRecord is the domain validation of one name of a certificate.
// Name and Value are kept as the platform reports them (an ACM name ends in
// a dot); Name is empty while the record is not published yet.
type ValidationRecord struct {
	Domain string
	Status string
	Method string
	Name   string
	Type   string
	Value  string
}

// Ready reports whether the DNS record of the validation is known.
func (v ValidationRecord) Ready() bool { return v.Name != "" && v.Value != "" }

// CertificateFilter selects the certificates of a listing.
type CertificateFilter struct {
	Region string
	// KeyTypes are the key algorithms to include (request spelling).
	KeyTypes []string
	// Statuses keep the certificates in these states; empty keeps all.
	Statuses []string
}

// CertificateRequest asks a platform to issue a certificate validated
// through DNS.
type CertificateRequest struct {
	Region       string
	Domain       string
	SANs         []string
	KeyAlgorithm string
	// Token makes a repeated identical request return the first
	// certificate instead of a second one.
	Token string
	Tags  map[string]string
}

// CertificateImport is the material of a certificate imported into a
// platform. ARN, when set, names the certificate whose content is
// replaced (the id stays); Tags are only sent with a new certificate.
type CertificateImport struct {
	Region string
	ARN    string
	// Cert is the leaf certificate (PEM), Chain the intermediates (PEM,
	// may be empty) and Key the unencrypted private key (PEM).
	Cert, Chain, Key []byte
	Tags             map[string]string
}

// CertificateService is implemented by clients of a platform that holds
// certificates.
type CertificateService interface {
	ListCertificates(ctx context.Context, f CertificateFilter) ([]Certificate, error)
	// DescribeCertificate returns one certificate with its validation
	// records; a missing one is ErrNotFound.
	DescribeCertificate(ctx context.Context, region, id string) (*Certificate, error)
	// RequestCertificate returns the id of the new certificate.
	RequestCertificate(ctx context.Context, req CertificateRequest) (string, error)
	// ImportCertificate returns the id of the imported certificate.
	ImportCertificate(ctx context.Context, imp CertificateImport) (string, error)
}

// ValidationTTL is the TTL of the DNS records that validate a certificate.
const ValidationTTL = 300

// ACMValidationRecords turns the validation records of a certificate into
// the records `dns ensure` writes: one CNAME per distinct record (the
// wildcard and the bare name share theirs), without the trailing dot, with
// the name relative to zone when it lies below it (a FQDN otherwise), the
// case AWS used kept, a TTL of ValidationTTL and proxied false (a proxied
// CNAME would hide the target from the validation). Records that are not
// published yet are left out.
func ACMValidationRecords(zone string, recs []ValidationRecord) []RecordSpec {
	zone = NormalizeDomain(zone)
	seen := map[string]bool{}
	var out []RecordSpec
	for _, v := range recs {
		if !v.Ready() {
			continue
		}
		typ := strings.ToUpper(strings.TrimSpace(v.Type))
		if typ == "" {
			typ = "CNAME"
		}
		name := strings.TrimSuffix(strings.TrimSpace(v.Name), ".")
		value := strings.TrimSuffix(strings.TrimSpace(v.Value), ".")
		key := strings.ToLower(name) + "|" + typ + "|" + strings.ToLower(value)
		if seen[key] {
			continue
		}
		seen[key] = true
		if zone != "" {
			lower := strings.ToLower(name)
			switch {
			case lower == zone:
				name = "@"
			case strings.HasSuffix(lower, "."+zone):
				name = name[:len(name)-len(zone)-1]
			}
		}
		ttl, proxied := ValidationTTL, false
		out = append(out, RecordSpec{Name: name, Type: typ, Value: value, TTL: &ttl, Proxied: &proxied})
	}
	return out
}

// Inline writes the record in the command-line syntax
// name:type:value[:ttl[:proxied]].
func (r RecordSpec) Inline() string {
	s := r.Name + ":" + r.Type + ":" + r.Value
	switch {
	case r.TTL != nil:
		s += ":" + strconv.Itoa(*r.TTL)
	case r.Proxied != nil:
		s += ":"
	}
	if r.Proxied != nil {
		if *r.Proxied {
			s += ":true"
		} else {
			s += ":false"
		}
	}
	return s
}

// CertMaterial is a certificate chain and its private key, checked
// locally before anything is uploaded: platforms accept a key that does
// not belong to the certificate, and an expired certificate, without a
// word.
type CertMaterial struct {
	// Fullchain holds the certificates (leaf first) and PrivKey the
	// private key, both as PEM, without any other block.
	Fullchain, PrivKey []byte
	Leaf               *x509.Certificate
	// Fingerprint is the SHA-256 of the leaf's DER, lowercase hex.
	Fingerprint string
}

// ParseCertMaterial reads a PEM chain (leaf first) and an unencrypted PEM
// private key (PKCS#8, SEC 1 or PKCS#1) and checks that the key belongs to
// the leaf and that the leaf has not expired at now. Every problem is
// ErrInvalidInput. The two inputs may be the same text holding both.
func ParseCertMaterial(fullchain, privkey []byte, now time.Time) (*CertMaterial, error) {
	var certs []*pem.Block
	for rest := fullchain; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type == "CERTIFICATE" {
			certs = append(certs, &pem.Block{Type: b.Type, Bytes: b.Bytes})
		}
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("%w: no PEM CERTIFICATE block found in the certificate file", ErrInvalidInput)
	}
	leaf, err := x509.ParseCertificate(certs[0].Bytes)
	if err != nil {
		return nil, fmt.Errorf("%w: the first certificate cannot be parsed: %v", ErrInvalidInput, err)
	}
	for i, b := range certs[1:] {
		if _, err := x509.ParseCertificate(b.Bytes); err != nil {
			return nil, fmt.Errorf("%w: certificate %d of the chain cannot be parsed: %v", ErrInvalidInput, i+2, err)
		}
	}
	keyBlock, key, err := parsePrivateKeyPEM(privkey)
	if err != nil {
		return nil, err
	}
	type equaler interface{ Equal(crypto.PublicKey) bool }
	pub, ok := key.Public().(equaler)
	if !ok || !pub.Equal(leaf.PublicKey) {
		return nil, fmt.Errorf("%w: the private key does not belong to the certificate (the first certificate of the chain must be the leaf)", ErrInvalidInput)
	}
	if !now.Before(leaf.NotAfter) {
		return nil, fmt.Errorf("%w: the certificate expired on %s", ErrInvalidInput, leaf.NotAfter.UTC().Format(time.RFC3339))
	}
	var chain bytes.Buffer
	for _, b := range certs {
		_ = pem.Encode(&chain, b)
	}
	sum := sha256.Sum256(leaf.Raw)
	return &CertMaterial{Fullchain: chain.Bytes(), PrivKey: pem.EncodeToMemory(keyBlock), Leaf: leaf, Fingerprint: hex.EncodeToString(sum[:])}, nil
}

// parsePrivateKeyPEM finds the private key of a PEM text. An encrypted key
// is refused: platforms take unencrypted keys only.
func parsePrivateKeyPEM(data []byte) (*pem.Block, crypto.Signer, error) {
	for rest := data; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, nil, fmt.Errorf("%w: no PEM private key found in the key file", ErrInvalidInput)
		}
		if b.Type == "ENCRYPTED PRIVATE KEY" || strings.Contains(b.Headers["Proc-Type"], "ENCRYPTED") {
			return nil, nil, fmt.Errorf("%w: the private key is encrypted; decrypt it first (for example with openssl pkey -in key.pem -out plain.pem)", ErrInvalidInput)
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
			return nil, nil, fmt.Errorf("%w: the private key cannot be parsed: %v", ErrInvalidInput, err)
		}
		s, ok := key.(crypto.Signer)
		if !ok {
			return nil, nil, fmt.Errorf("%w: unsupported private key type %T", ErrInvalidInput, key)
		}
		return &pem.Block{Type: b.Type, Bytes: b.Bytes}, s, nil
	}
}

// Names are the DNS names of the leaf, or its common name when it has
// none.
func (m *CertMaterial) Names() []string {
	if len(m.Leaf.DNSNames) > 0 {
		return m.Leaf.DNSNames
	}
	if m.Leaf.Subject.CommonName != "" {
		return []string{m.Leaf.Subject.CommonName}
	}
	return nil
}

// Covers reports whether the leaf is valid for host (see CertCovers).
func (m *CertMaterial) Covers(host string) bool { return CertCovers(m.Names(), host) }

// CertCovers reports whether a certificate of names is valid for host: an
// exact name, or a wildcard that matches exactly one label in front of its
// base (*.example.com covers www.example.com, not example.com nor
// a.b.example.com). A wildcard host is covered by the same wildcard only.
func CertCovers(names []string, host string) bool {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	for _, n := range names {
		n = strings.ToLower(strings.TrimSpace(n))
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

// LeafOf parses the first certificate of a PEM text and returns it with
// the SHA-256 of its DER (lowercase hex).
func LeafOf(pemText string) (*x509.Certificate, string, error) {
	for rest := []byte(pemText); ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			return nil, "", errors.New("no PEM certificate found")
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(b.Bytes)
		if err != nil {
			return nil, "", err
		}
		sum := sha256.Sum256(c.Raw)
		return c, hex.EncodeToString(sum[:]), nil
	}
}

// CertDomain is the domain a certificate is for: its first DNS name that
// is not a wildcard; with wildcards only, the first one without "*."; with
// no DNS name, the common name without "*.". Lowercase; "" when unknown.
func CertDomain(names []string, commonName string) string {
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" && !strings.HasPrefix(n, "*.") {
			return n
		}
	}
	for _, n := range names {
		if n = strings.ToLower(strings.TrimSpace(n)); n != "" {
			return strings.TrimPrefix(n, "*.")
		}
	}
	return strings.TrimPrefix(strings.ToLower(strings.TrimSpace(commonName)), "*.")
}
