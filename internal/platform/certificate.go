package platform

import (
	"context"
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
