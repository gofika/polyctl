package aws

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/gofika/polyctl/internal/platform"
)

// acmAPI is the part of the AWS Certificate Manager API polyctl uses.
type acmAPI interface {
	ListCertificates(ctx context.Context, in *acm.ListCertificatesInput, optFns ...func(*acm.Options)) (*acm.ListCertificatesOutput, error)
	DescribeCertificate(ctx context.Context, in *acm.DescribeCertificateInput, optFns ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error)
	RequestCertificate(ctx context.Context, in *acm.RequestCertificateInput, optFns ...func(*acm.Options)) (*acm.RequestCertificateOutput, error)
	ImportCertificate(ctx context.Context, in *acm.ImportCertificateInput, optFns ...func(*acm.Options)) (*acm.ImportCertificateOutput, error)
}

// newACM creates the ACM client of a region; tests replace it with a fake.
var newACM = func(cfg awssdk.Config) acmAPI { return acm.NewFromConfig(cfg) }

var _ platform.CertificateService = (*client)(nil)

// acmClock is the clock of the certificate waits; tests replace it.
var acmClock platform.Clock = platform.RealClock

const (
	// acmValidationPoll is the pause between two reads of a requested
	// certificate whose validation records are not published yet (they
	// showed up after 7 to 13 seconds).
	acmValidationPoll = 2 * time.Second
	// acmValidationTimeout is the default bound of that wait.
	acmValidationTimeout = 5 * time.Minute
	// acmImportPoll and acmImportTimeout bound the read-back of an import.
	acmImportPoll    = 3 * time.Second
	acmImportTimeout = 30 * time.Second
	// acmPageSize is the largest page ListCertificates accepts (1-1000).
	acmPageSize = 1000
)

// Certificate states and types of ACM.
const (
	acmIssued            = "ISSUED"
	acmPendingValidation = "PENDING_VALIDATION"
	acmExpired           = "EXPIRED"
	acmAmazonIssued      = "AMAZON_ISSUED"
	acmImported          = "IMPORTED"
	acmValidationFailed  = "FAILED"
	acmDNS               = "DNS"
)

// acmKeyAlgorithms are the key algorithms ACM accepts in requests and
// filters (the list its validation error names; the SDK constants lack the
// ML_DSA ones).
var acmKeyAlgorithms = []string{"RSA_1024", "RSA_2048", "RSA_3072", "RSA_4096", "EC_prime256v1", "EC_secp384r1", "EC_secp521r1",
	"ML_DSA_44", "ML_DSA_65", "ML_DSA_87"}

// acmSyncKeyTypes are the key algorithms the inventory sync includes: every
// algorithm of the SDK, so that no certificate is missing from the
// inventory (without Includes ACM lists RSA_1024 and RSA_2048 only).
var acmSyncKeyTypes = func() []string {
	var out []string
	for _, k := range acmtypes.KeyAlgorithm("").Values() {
		out = append(out, string(k))
	}
	return out
}()

// acmDefaultKeyTypes are the key types list and get include by default.
var acmDefaultKeyTypes = []string{"EC_prime256v1", "RSA_2048"}

// acmDefaultKeyAlgorithm is the key algorithm of a request by default. It
// is always sent: ACM falls back to RSA_2048 without it.
const acmDefaultKeyAlgorithm = "EC_prime256v1"

// acmStatuses are the certificate states ACM reports.
var acmStatuses = func() []string {
	var out []string
	for _, s := range acmtypes.CertificateStatus("").Values() {
		out = append(out, string(s))
	}
	return out
}()

// normalizeKeyAlgorithm turns the spelling of ACM responses (EC-prime256v1,
// RSA-2048) into the spelling of requests and filters (EC_prime256v1).
func normalizeKeyAlgorithm(s string) string {
	return strings.ReplaceAll(strings.TrimSpace(s), "-", "_")
}

// canonicalKeyAlgorithm returns the ACM spelling of a key algorithm given in
// any case, with hyphens or underscores; ok is false for an unknown one.
func canonicalKeyAlgorithm(s string) (string, bool) {
	n := normalizeKeyAlgorithm(s)
	for _, k := range acmKeyAlgorithms {
		if strings.EqualFold(k, n) {
			return k, true
		}
	}
	return "", false
}

// normalizeSerial makes two spellings of a serial number comparable: ACM
// reports "0a:1b:..." and the local store "0a1b...". Colons go, letters
// become lowercase and leading zeros are trimmed.
func normalizeSerial(s string) string {
	return strings.TrimLeft(strings.ToLower(strings.ReplaceAll(strings.TrimSpace(s), ":", "")), "0")
}

// acmNotFound reports whether err says the certificate does not exist (also
// for an ARN of another account).
func acmNotFound(err error) bool {
	var nf *acmtypes.ResourceNotFoundException
	return errors.As(err, &nf) || platform.HasErrorCode(err, "ResourceNotFoundException")
}

// acmLimitExceeded reports whether err is a quota of ACM.
func acmLimitExceeded(err error) bool {
	var le *acmtypes.LimitExceededException
	return errors.As(err, &le) || platform.HasErrorCode(err, "LimitExceededException")
}

// acmErr wraps an error of the ACM call action in region: a missing
// certificate is ErrNotFound, a quota names Service Quotas, a denial names
// the IAM action, and the rest (ValidationException,
// InvalidDomainValidationOptionsException, ...: the input was checked
// before it was sent) keeps the general exit code with the AWS message.
func acmErr(action, region string, err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	where := fmt.Sprintf("acm:%s in %s", action, region)
	switch {
	case acmNotFound(err):
		return fmt.Errorf("%w: %s: %w (ACM certificates belong to one region: check --region)", platform.ErrNotFound, where, err)
	case acmLimitExceeded(err):
		return fmt.Errorf("%s: %w (an ACM quota; an increase can be requested through Service Quotas)", where, err)
	}
	m := mapErr(err)
	if errors.Is(m, platform.ErrUnauthorized) {
		return fmt.Errorf("%s (the credentials need the IAM action acm:%s): %w", where, action, m)
	}
	return fmt.Errorf("%s: %w", where, m)
}

// ------------------------------------------------------------ ARNs

// acmARN is the parsed form of an ACM certificate ARN:
// arn:<partition>:acm:<region>:<account>:certificate/<id>.
type acmARN struct {
	Region, Account, ID string
}

// parseACMARN parses an ACM certificate ARN; ok is false for anything else,
// including a malformed one (which ACM would refuse with a
// ValidationException).
func parseACMARN(s string) (acmARN, bool) {
	parts := strings.SplitN(strings.TrimSpace(s), ":", 6)
	if len(parts) != 6 || parts[0] != "arn" || !strings.HasPrefix(parts[1], "aws") || parts[2] != "acm" {
		return acmARN{}, false
	}
	region, account, res := parts[3], parts[4], parts[5]
	if !validRegionName(region) || len(account) != 12 || strings.Trim(account, "0123456789") != "" {
		return acmARN{}, false
	}
	id, ok := strings.CutPrefix(res, "certificate/")
	if !ok || id == "" {
		return acmARN{}, false
	}
	for _, r := range id {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-') {
			return acmARN{}, false
		}
	}
	return acmARN{Region: region, Account: account, ID: id}, true
}

// validRegionName reports whether s looks like an AWS region name
// (ap-east-1, us-gov-west-1).
func validRegionName(s string) bool {
	if len(s) < 4 || strings.HasPrefix(s, "-") || strings.HasSuffix(s, "-") || !strings.Contains(s, "-") {
		return false
	}
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-') {
			return false
		}
	}
	return true
}

// ------------------------------------------------------------ conversion

func timePtr(t *time.Time) *time.Time {
	if t == nil || t.IsZero() {
		return nil
	}
	u := t.UTC()
	return &u
}

func certFromSummary(region string, s acmtypes.CertificateSummary) platform.Certificate {
	return platform.Certificate{
		ID: awssdk.ToString(s.CertificateArn), Region: region, Domain: awssdk.ToString(s.DomainName),
		Names: s.SubjectAlternativeNameSummaries, NamesTruncated: awssdk.ToBool(s.HasAdditionalSubjectAlternativeNames),
		Status: string(s.Status), Type: string(s.Type), KeyAlgorithm: normalizeKeyAlgorithm(string(s.KeyAlgorithm)),
		InUse: awssdk.ToBool(s.InUse), CreatedAt: timePtr(s.CreatedAt), IssuedAt: timePtr(s.IssuedAt), ImportedAt: timePtr(s.ImportedAt),
		NotBefore: timePtr(s.NotBefore), NotAfter: timePtr(s.NotAfter), RenewalEligibility: string(s.RenewalEligibility),
	}
}

func certFromDetail(region string, d acmtypes.CertificateDetail) platform.Certificate {
	c := platform.Certificate{
		ID: awssdk.ToString(d.CertificateArn), Region: region, Domain: awssdk.ToString(d.DomainName), Names: d.SubjectAlternativeNames,
		Status: string(d.Status), Type: string(d.Type), KeyAlgorithm: normalizeKeyAlgorithm(string(d.KeyAlgorithm)),
		InUse: len(d.InUseBy) > 0, InUseBy: d.InUseBy, Issuer: awssdk.ToString(d.Issuer), Serial: awssdk.ToString(d.Serial),
		CreatedAt: timePtr(d.CreatedAt), IssuedAt: timePtr(d.IssuedAt), ImportedAt: timePtr(d.ImportedAt),
		NotBefore: timePtr(d.NotBefore), NotAfter: timePtr(d.NotAfter),
		RenewalEligibility: string(d.RenewalEligibility), FailureReason: string(d.FailureReason),
	}
	for _, v := range d.DomainValidationOptions {
		r := platform.ValidationRecord{Domain: awssdk.ToString(v.DomainName), Status: string(v.ValidationStatus), Method: string(v.ValidationMethod)}
		if rr := v.ResourceRecord; rr != nil {
			r.Name, r.Type, r.Value = awssdk.ToString(rr.Name), string(rr.Type), awssdk.ToString(rr.Value)
		}
		c.Validation = append(c.Validation, r)
	}
	return c
}

func acmTags(tags map[string]string) []acmtypes.Tag {
	keys := make([]string, 0, len(tags))
	for k := range tags {
		keys = append(keys, k)
	}
	slices.Sort(keys)
	var out []acmtypes.Tag
	for _, k := range keys {
		out = append(out, acmtypes.Tag{Key: awssdk.String(k), Value: awssdk.String(tags[k])})
	}
	return out
}

// ------------------------------------------------------------ calls

// ListCertificates lists the certificates of a region, every page, with
// the key types of the filter (ACM leaves out every other key type).
func (c *client) ListCertificates(ctx context.Context, f platform.CertificateFilter) ([]platform.Certificate, error) {
	region := c.regionOr(f.Region)
	in := &acm.ListCertificatesInput{MaxItems: awssdk.Int32(acmPageSize)}
	keyTypes := f.KeyTypes
	if len(keyTypes) == 0 {
		keyTypes = acmDefaultKeyTypes
	}
	in.Includes = &acmtypes.Filters{}
	for _, k := range keyTypes {
		in.Includes.KeyTypes = append(in.Includes.KeyTypes, acmtypes.KeyAlgorithm(k))
	}
	for _, s := range f.Statuses {
		in.CertificateStatuses = append(in.CertificateStatuses, acmtypes.CertificateStatus(s))
	}
	var out []platform.Certificate
	pg := acm.NewListCertificatesPaginator(c.acmFor(region), in)
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, acmErr("ListCertificates", region, err)
		}
		for _, s := range page.CertificateSummaryList {
			out = append(out, certFromSummary(region, s))
		}
	}
	return out, nil
}

// DescribeCertificate reads one certificate with its validation records.
func (c *client) DescribeCertificate(ctx context.Context, region, arn string) (*platform.Certificate, error) {
	region = c.regionOr(region)
	out, err := c.acmFor(region).DescribeCertificate(ctx, &acm.DescribeCertificateInput{CertificateArn: awssdk.String(arn)})
	if err != nil {
		return nil, acmErr("DescribeCertificate", region, err)
	}
	if out.Certificate == nil {
		return nil, fmt.Errorf("%w: acm:DescribeCertificate in %s: certificate %s", platform.ErrNotFound, region, arn)
	}
	cert := certFromDetail(region, *out.Certificate)
	if cert.ID == "" {
		cert.ID = arn
	}
	return &cert, nil
}

// RequestCertificate requests a public certificate validated through DNS.
func (c *client) RequestCertificate(ctx context.Context, req platform.CertificateRequest) (string, error) {
	region := c.regionOr(req.Region)
	in := &acm.RequestCertificateInput{
		DomainName:       awssdk.String(req.Domain),
		ValidationMethod: acmtypes.ValidationMethodDns,
		KeyAlgorithm:     acmtypes.KeyAlgorithm(req.KeyAlgorithm),
		Tags:             acmTags(req.Tags),
	}
	if len(req.SANs) > 0 {
		in.SubjectAlternativeNames = req.SANs
	}
	if req.Token != "" {
		in.IdempotencyToken = awssdk.String(req.Token)
	}
	out, err := c.acmFor(region).RequestCertificate(ctx, in)
	if err != nil {
		return "", acmErr("RequestCertificate", region, err)
	}
	return awssdk.ToString(out.CertificateArn), nil
}

// ImportCertificate imports a certificate, into the certificate imp.ARN
// names when it is set (the ARN stays; tags are not allowed then).
func (c *client) ImportCertificate(ctx context.Context, imp platform.CertificateImport) (string, error) {
	region := c.regionOr(imp.Region)
	in := &acm.ImportCertificateInput{Certificate: imp.Cert, PrivateKey: imp.Key}
	if len(imp.Chain) > 0 {
		in.CertificateChain = imp.Chain
	}
	if imp.ARN != "" {
		in.CertificateArn = awssdk.String(imp.ARN)
	} else {
		in.Tags = acmTags(imp.Tags)
	}
	out, err := c.acmFor(region).ImportCertificate(ctx, in)
	if err != nil {
		return "", acmErr("ImportCertificate", region, err)
	}
	arn := awssdk.ToString(out.CertificateArn)
	if arn == "" {
		arn = imp.ARN
	}
	return arn, nil
}

// ------------------------------------------------------------ inventory

// acmCertificate is the inventory form of an ACM certificate.
type acmCertificate struct {
	ARN          string     `json:"arn" yaml:"arn"`
	Domain       string     `json:"domain" yaml:"domain"`
	Names        []string   `json:"names,omitempty" yaml:"names,omitempty"`
	Status       string     `json:"status" yaml:"status"`
	Type         string     `json:"type" yaml:"type"`
	KeyAlgorithm string     `json:"key_algorithm" yaml:"key_algorithm"`
	InUse        bool       `json:"in_use" yaml:"in_use"`
	NotAfter     *time.Time `json:"not_after,omitempty" yaml:"not_after,omitempty"`
	CreatedAt    *time.Time `json:"created_at,omitempty" yaml:"created_at,omitempty"`
	Region       string     `json:"region" yaml:"region"`
}

func acmRecord(c platform.Certificate) acmCertificate {
	return acmCertificate{ARN: c.ID, Domain: c.Domain, Names: c.Names, Status: c.Status, Type: c.Type, KeyAlgorithm: normalizeKeyAlgorithm(c.KeyAlgorithm),
		InUse: c.InUse, NotAfter: c.NotAfter, CreatedAt: c.CreatedAt, Region: c.Region}
}

func (a acmCertificate) certificate() platform.Certificate {
	return platform.Certificate{ID: a.ARN, Region: a.Region, Domain: a.Domain, Names: a.Names, Status: a.Status, Type: a.Type,
		KeyAlgorithm: a.KeyAlgorithm, InUse: a.InUse, NotAfter: a.NotAfter, CreatedAt: a.CreatedAt}
}

// resource is the inventory row: keyed by the ARN, the region as parent
// (so that a region that cannot be listed keeps its rows).
func (a acmCertificate) resource() platform.Resource {
	return platform.Resource{Type: platform.ResCertificate, ID: a.ARN, Name: a.Domain, ParentID: a.Region, Data: a}
}

// certificateResources lists the certificates of a region, of every key
// type, for the inventory.
func (c *client) certificateResources(ctx context.Context, region string) ([]platform.Resource, error) {
	certs, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: acmSyncKeyTypes})
	if err != nil {
		return nil, err
	}
	var out []platform.Resource
	for _, cert := range certs {
		out = append(out, acmRecord(cert).resource())
	}
	return out, nil
}

// ------------------------------------------------------------ selection

// certMatchesDomain reports whether the primary name of a certificate is
// domain or its wildcard (names are compared without case; the other
// names of the certificate are not looked at).
func certMatchesDomain(c platform.Certificate, domain string) bool {
	d := strings.TrimSuffix(strings.ToLower(c.Domain), ".")
	return d == domain || d == "*."+domain
}

// statusRank orders certificate states for the choice among several
// certificates of a domain: issued first, then pending, then the rest,
// with the ones that can never be used last.
func statusRank(status string) int {
	switch status {
	case acmIssued:
		return 0
	case acmPendingValidation:
		return 1
	case acmExpired, "FAILED", "VALIDATION_TIMED_OUT", "REVOKED":
		return 3
	}
	return 2
}

// compareCertificates orders the better certificate first: by state, then
// the later expiry, then the newer one.
func compareCertificates(a, b platform.Certificate) int {
	if ra, rb := statusRank(a.Status), statusRank(b.Status); ra != rb {
		return ra - rb
	}
	if c := laterFirst(a.NotAfter, b.NotAfter); c != 0 {
		return c
	}
	if c := laterFirst(a.CreatedAt, b.CreatedAt); c != 0 {
		return c
	}
	return strings.Compare(a.ID, b.ID)
}

func laterFirst(a, b *time.Time) int {
	switch {
	case a == nil && b == nil:
		return 0
	case a == nil:
		return 1
	case b == nil:
		return -1
	case a.After(*b):
		return -1
	case b.After(*a):
		return 1
	}
	return 0
}

// pickCertificate returns the best of several certificates of a domain.
func pickCertificate(certs []platform.Certificate) platform.Certificate {
	return slices.MinFunc(certs, compareCertificates)
}

// nameSet returns names lowercased, without trailing dots, deduplicated
// and sorted: ACM folds the names of a request the same way.
func nameSet(names ...string) []string {
	var out []string
	for _, n := range names {
		n = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(n)), ".")
		if n != "" {
			out = append(out, n)
		}
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// acmToken derives the IdempotencyToken of a request from what it asks
// for: the same request in the same account and region gets the same
// token (ACM then returns the first certificate), and any difference
// another one. ACM takes at most 32 word characters.
func acmToken(profile, region, domain, keyAlgorithm string, sans []string) string {
	sum := sha256.Sum256([]byte(strings.Join([]string{profile, region, strings.ToLower(domain), keyAlgorithm, strings.Join(nameSet(sans...), ",")}, "|")))
	return hex.EncodeToString(sum[:])[:32]
}

// validationComplete reports whether every name of the certificate has its
// DNS validation record published.
func validationComplete(c *platform.Certificate) bool {
	if len(c.Validation) == 0 {
		return false
	}
	for _, v := range c.Validation {
		if !v.Ready() {
			return false
		}
	}
	return true
}

// validationProblem returns why the validation of a certificate cannot
// complete: a validation method other than DNS, or a failed validation.
func validationProblem(c *platform.Certificate) error {
	var failed []string
	for _, v := range c.Validation {
		if v.Method != "" && v.Method != acmDNS {
			return fmt.Errorf("certificate %s validates %s through %s, not DNS", c.ID, v.Domain, v.Method)
		}
		if v.Status == acmValidationFailed {
			failed = append(failed, v.Domain+" "+v.Status)
		}
	}
	if len(failed) > 0 {
		return fmt.Errorf("the validation of certificate %s failed (%s)", c.ID, strings.Join(failed, ", "))
	}
	return nil
}

// statusWithReason is the status of a certificate with its failure reason.
func statusWithReason(c *platform.Certificate) string {
	if c.FailureReason != "" {
		return c.Status + " (" + c.FailureReason + ")"
	}
	return c.Status
}

// waitValidationRecords reads a certificate until its DNS validation
// records are all published (every acmValidationPoll, at most timeout).
// Without wait it reads it once. A certificate that leaves
// PENDING_VALIDATION without its records (FAILED, for a name ACM will not
// issue for), or a validation that failed, ends the wait with an error at
// once.
func (c *client) waitValidationRecords(ctx context.Context, region, arn string, wait bool, timeout time.Duration) (*platform.Certificate, error) {
	if !wait {
		return c.DescribeCertificate(ctx, region, arn)
	}
	var last *platform.Certificate
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "certificate " + arn, Want: "published validation records", Timeout: timeout,
		Interval: acmValidationPoll, Clock: acmClock}, func(ctx context.Context) (platform.WaitState, string, error) {
		cert, err := c.DescribeCertificate(ctx, region, arn)
		if err != nil {
			return 0, "", err
		}
		last = cert
		if validationComplete(cert) {
			return platform.WaitDone, cert.Status, nil
		}
		if cert.Status != acmPendingValidation {
			return 0, cert.Status, fmt.Errorf("certificate %s is %s: ACM will not publish its validation records", arn, statusWithReason(cert))
		}
		if err := validationProblem(cert); err != nil {
			return 0, cert.Status, err
		}
		return platform.KeepWaiting, cert.Status, nil
	})
	return last, err
}

// waitImported reads an imported certificate until it reports the serial
// number of what was imported and is ISSUED (an import is synchronous, so
// this normally holds at the first read).
func (c *client) waitImported(ctx context.Context, region, arn, serial string) (*platform.Certificate, error) {
	var last *platform.Certificate
	err := platform.WaitUntil(ctx, platform.WaitOptions{Resource: "certificate " + arn, Want: "the imported certificate", Timeout: acmImportTimeout,
		Interval: acmImportPoll, Clock: acmClock}, func(ctx context.Context) (platform.WaitState, string, error) {
		cert, err := c.DescribeCertificate(ctx, region, arn)
		if err != nil {
			return 0, "", err
		}
		last = cert
		if normalizeSerial(cert.Serial) == normalizeSerial(serial) && cert.Status == acmIssued {
			return platform.WaitDone, cert.Status, nil
		}
		return platform.KeepWaiting, cert.Status + " serial " + cert.Serial, nil
	})
	return last, err
}

// acmKeyAlgorithmOf returns the ACM key algorithm of a public key.
func acmKeyAlgorithmOf(pub any) (string, error) {
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		switch k.Curve {
		case elliptic.P256():
			return "EC_prime256v1", nil
		case elliptic.P384():
			return "EC_secp384r1", nil
		case elliptic.P521():
			return "EC_secp521r1", nil
		}
	case *rsa.PublicKey:
		alg := fmt.Sprintf("RSA_%d", k.N.BitLen())
		if slices.Contains(acmKeyAlgorithms, alg) {
			return alg, nil
		}
	}
	return "", fmt.Errorf("%w: ACM does not import a certificate with a %T key of this size", platform.ErrInvalidInput, pub)
}
