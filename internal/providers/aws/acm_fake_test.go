package aws

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"
)

const fakeAccountID = "123456789012"

// fakeCert is a certificate of the fake ACM.
type fakeCert struct {
	arn, region, domain string
	names               []string
	status, typ         string
	// keyAlg is in the request spelling; responses use hyphens.
	keyAlg   string
	inUseBy  []string
	notAfter *time.Time
	created  time.Time
	serial   string
	failure  string
	token    string
	tags     map[string]string
	// dvoAfter and recordsAfter are the number of reads before the
	// validation list, then the records, show up; fail makes the
	// certificate FAILED once its validations appear, without records.
	dvoAfter, recordsAfter int
	fail                   bool
	reads                  int
	// truncated reports only the first name in listings.
	truncated bool
}

// fakeACMs is the state of the fake ACM of every region.
type fakeACMs struct {
	certs    []*fakeCert
	calls    []string
	lists    []*acm.ListCertificatesInput
	requests []*acm.RequestCertificateInput
	imports  []*acm.ImportCertificateInput
	errs     map[string]error
	pageSize int
	seq      int
	// dvoAfter, recordsAfter and fail are the defaults of new
	// certificates.
	dvoAfter, recordsAfter int
	fail                   bool
}

type fakeACM struct {
	shared *fakeEC2s
	region string
}

func (h *awsHarness) acm() *fakeACMs { return &h.ec2.acm }

func (f *fakeACM) state() *fakeACMs { return &f.shared.acm }

func (f *fakeACM) call(action string) error {
	s := f.state()
	s.calls = append(s.calls, f.region+":"+action)
	return s.errs[action]
}

func respAlg(k string) acmtypes.KeyAlgorithm {
	return acmtypes.KeyAlgorithm(strings.ReplaceAll(k, "_", "-"))
}

func validationName(name string) (string, string) {
	base := strings.TrimPrefix(strings.ToLower(name), "*.")
	sum := sha256.Sum256([]byte(base))
	h := hex.EncodeToString(sum[:])
	return "_" + h[:16] + "." + base + ".", "_" + h[16:32] + ".xyz.acm-validations.aws."
}

func (c *fakeCert) summary() acmtypes.CertificateSummary {
	s := acmtypes.CertificateSummary{CertificateArn: awssdk.String(c.arn), DomainName: awssdk.String(c.domain), Status: acmtypes.CertificateStatus(c.status),
		Type: acmtypes.CertificateType(c.typ), KeyAlgorithm: respAlg(c.keyAlg), InUse: awssdk.Bool(len(c.inUseBy) > 0), NotAfter: c.notAfter,
		CreatedAt: awssdk.Time(c.created), SubjectAlternativeNameSummaries: c.names}
	if c.truncated && len(c.names) > 1 {
		s.SubjectAlternativeNameSummaries = c.names[:1]
		s.HasAdditionalSubjectAlternativeNames = awssdk.Bool(true)
	}
	return s
}

func (f *fakeACM) ListCertificates(_ context.Context, in *acm.ListCertificatesInput, _ ...func(*acm.Options)) (*acm.ListCertificatesOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("ListCertificates"); err != nil {
		return nil, err
	}
	s := f.state()
	s.lists = append(s.lists, in)
	keyTypes := []string{"RSA_1024", "RSA_2048"}
	if in.Includes != nil && len(in.Includes.KeyTypes) > 0 {
		keyTypes = nil
		for _, k := range in.Includes.KeyTypes {
			keyTypes = append(keyTypes, string(k))
		}
	}
	var match []*fakeCert
	for _, c := range s.certs {
		if c.region != f.region || !slices.Contains(keyTypes, c.keyAlg) {
			continue
		}
		if len(in.CertificateStatuses) > 0 && !slices.Contains(in.CertificateStatuses, acmtypes.CertificateStatus(c.status)) {
			continue
		}
		match = append(match, c)
	}
	size := int(awssdk.ToInt32(in.MaxItems))
	if s.pageSize > 0 {
		size = s.pageSize
	}
	start := 0
	if in.NextToken != nil {
		start, _ = strconv.Atoi(*in.NextToken)
	}
	end := min(start+size, len(match))
	out := &acm.ListCertificatesOutput{}
	for _, c := range match[start:end] {
		out.CertificateSummaryList = append(out.CertificateSummaryList, c.summary())
	}
	if end < len(match) {
		out.NextToken = awssdk.String(strconv.Itoa(end))
	}
	return out, nil
}

func (f *fakeACM) find(arn string) *fakeCert {
	for _, c := range f.state().certs {
		if c.arn == arn && c.region == f.region {
			return c
		}
	}
	return nil
}

func notFoundErr(arn string) error {
	return &acmtypes.ResourceNotFoundException{Message: awssdk.String("Could not find certificate " + arn + ".")}
}

func (f *fakeACM) DescribeCertificate(_ context.Context, in *acm.DescribeCertificateInput, _ ...func(*acm.Options)) (*acm.DescribeCertificateOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("DescribeCertificate"); err != nil {
		return nil, err
	}
	c := f.find(awssdk.ToString(in.CertificateArn))
	if c == nil {
		return nil, notFoundErr(awssdk.ToString(in.CertificateArn))
	}
	c.reads++
	d := &acmtypes.CertificateDetail{CertificateArn: awssdk.String(c.arn), DomainName: awssdk.String(c.domain), SubjectAlternativeNames: c.names,
		Status: acmtypes.CertificateStatus(c.status), Type: acmtypes.CertificateType(c.typ), KeyAlgorithm: respAlg(c.keyAlg), InUseBy: c.inUseBy,
		NotAfter: c.notAfter, CreatedAt: awssdk.Time(c.created), Serial: awssdk.String(c.serial)}
	switch c.typ {
	case acmAmazonIssued:
		d.Issuer = awssdk.String("Amazon")
		if c.reads > c.dvoAfter {
			if c.fail {
				c.status, c.failure = "FAILED", "ADDITIONAL_VERIFICATION_REQUIRED"
				d.Status, d.FailureReason = "FAILED", "ADDITIONAL_VERIFICATION_REQUIRED"
			}
			for _, n := range c.names {
				v := acmtypes.DomainValidation{DomainName: awssdk.String(n), ValidationMethod: acmtypes.ValidationMethodDns,
					ValidationStatus: acmtypes.DomainStatus(c.status)}
				if c.status == acmIssued {
					v.ValidationStatus = acmtypes.DomainStatusSuccess
				}
				if !c.fail && c.reads > c.recordsAfter {
					name, value := validationName(n)
					v.ResourceRecord = &acmtypes.ResourceRecord{Name: awssdk.String(name), Type: acmtypes.RecordTypeCname, Value: awssdk.String(value)}
				}
				d.DomainValidationOptions = append(d.DomainValidationOptions, v)
			}
		}
	case acmImported:
		d.Issuer = awssdk.String("Test CA")
		d.RenewalEligibility = acmtypes.RenewalEligibilityIneligible
		d.DomainValidationOptions = []acmtypes.DomainValidation{{DomainName: awssdk.String(c.domain)}}
	}
	return &acm.DescribeCertificateOutput{Certificate: d}, nil
}

func (f *fakeACM) newARN() string {
	s := f.state()
	s.seq++
	return fmt.Sprintf("arn:aws:acm:%s:%s:certificate/00000000-0000-0000-0000-%012d", f.region, fakeAccountID, s.seq)
}

func (f *fakeACM) RequestCertificate(_ context.Context, in *acm.RequestCertificateInput, _ ...func(*acm.Options)) (*acm.RequestCertificateOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("RequestCertificate"); err != nil {
		return nil, err
	}
	s := f.state()
	s.requests = append(s.requests, in)
	alg := string(in.KeyAlgorithm)
	if alg == "" {
		alg = "RSA_2048"
	}
	names := nameSet(append([]string{awssdk.ToString(in.DomainName)}, in.SubjectAlternativeNames...)...)
	// The primary name first, as ACM lists it.
	primary := strings.ToLower(awssdk.ToString(in.DomainName))
	ordered := []string{primary}
	for _, n := range names {
		if n != primary {
			ordered = append(ordered, n)
		}
	}
	token := awssdk.ToString(in.IdempotencyToken)
	for _, c := range s.certs {
		if token != "" && c.token == token && c.region == f.region && c.keyAlg == alg && c.domain == primary && slices.Equal(nameSet(c.names...), names) {
			return &acm.RequestCertificateOutput{CertificateArn: awssdk.String(c.arn)}, nil
		}
	}
	if len(names) > 10 {
		return nil, &acmtypes.LimitExceededException{Message: awssdk.String("Certificate has too many domains.")}
	}
	tags := map[string]string{}
	for _, t := range in.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	c := &fakeCert{arn: f.newARN(), region: f.region, domain: primary, names: ordered, status: acmPendingValidation, typ: acmAmazonIssued,
		keyAlg: alg, created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), token: token, tags: tags, dvoAfter: s.dvoAfter, recordsAfter: s.recordsAfter, fail: s.fail}
	s.certs = append(s.certs, c)
	return &acm.RequestCertificateOutput{CertificateArn: awssdk.String(c.arn)}, nil
}

// leafInfo reads what the fake needs from a PEM certificate.
func leafInfo(data []byte) (domain, serial, alg string, notAfter time.Time, err error) {
	b, _ := pem.Decode(data)
	if b == nil {
		return "", "", "", time.Time{}, fmt.Errorf("no PEM")
	}
	leaf, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	alg, err = acmKeyAlgorithmOf(leaf.PublicKey)
	if err != nil {
		return "", "", "", time.Time{}, err
	}
	hexs := hex.EncodeToString(leaf.SerialNumber.Bytes())
	var parts []string
	for i := 0; i < len(hexs); i += 2 {
		parts = append(parts, hexs[i:i+2])
	}
	return leaf.Subject.CommonName, strings.Join(parts, ":"), alg, leaf.NotAfter, nil
}

func (f *fakeACM) ImportCertificate(_ context.Context, in *acm.ImportCertificateInput, _ ...func(*acm.Options)) (*acm.ImportCertificateOutput, error) {
	f.shared.mu.Lock()
	defer f.shared.mu.Unlock()
	if err := f.call("ImportCertificate"); err != nil {
		return nil, err
	}
	s := f.state()
	s.imports = append(s.imports, in)
	if n := strings.Count(string(in.Certificate), "BEGIN CERTIFICATE"); n != 1 {
		return nil, &acmtypes.ValidationException{Message: awssdk.String("The certificate field contains more than one certificate.")}
	}
	domain, serial, alg, notAfter, err := leafInfo(in.Certificate)
	if err != nil {
		return nil, &acmtypes.ValidationException{Message: awssdk.String(err.Error())}
	}
	if arn := awssdk.ToString(in.CertificateArn); arn != "" {
		if len(in.Tags) > 0 {
			return nil, &acmtypes.ValidationException{Message: awssdk.String("Tagging is not permitted on re-import.")}
		}
		c := f.find(arn)
		if c == nil {
			return nil, notFoundErr(arn)
		}
		if c.keyAlg != alg {
			return nil, &acmtypes.ValidationException{Message: awssdk.String(fmt.Sprintf("New certificate has a key of %s which is different from %s in the current certificate.", alg, c.keyAlg))}
		}
		c.domain, c.names, c.serial, c.notAfter, c.status = domain, []string{domain}, serial, &notAfter, acmIssued
		return &acm.ImportCertificateOutput{CertificateArn: awssdk.String(arn)}, nil
	}
	tags := map[string]string{}
	for _, t := range in.Tags {
		tags[awssdk.ToString(t.Key)] = awssdk.ToString(t.Value)
	}
	c := &fakeCert{arn: f.newARN(), region: f.region, domain: domain, names: []string{domain}, status: acmIssued, typ: acmImported, keyAlg: alg,
		created: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC), serial: serial, notAfter: &notAfter, tags: tags}
	s.certs = append(s.certs, c)
	return &acm.ImportCertificateOutput{CertificateArn: awssdk.String(c.arn)}, nil
}

// addCert puts a certificate into the fake ACM and returns it.
func (h *awsHarness) addCert(c *fakeCert) *fakeCert {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	s := &h.ec2.acm
	if c.arn == "" {
		s.seq++
		c.arn = fmt.Sprintf("arn:aws:acm:%s:%s:certificate/11111111-0000-0000-0000-%012d", c.region, fakeAccountID, s.seq)
	}
	if c.typ == "" {
		c.typ = acmAmazonIssued
	}
	if c.keyAlg == "" {
		c.keyAlg = "EC_prime256v1"
	}
	if len(c.names) == 0 {
		c.names = []string{c.domain}
	}
	if c.created.IsZero() {
		c.created = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)
	}
	s.certs = append(s.certs, c)
	return c
}

// acmCalls lists the ACM calls (without region) since the last reset.
func (h *awsHarness) acmCalls() []string {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	var out []string
	for _, c := range h.ec2.acm.calls {
		_, call, _ := strings.Cut(c, ":")
		out = append(out, call)
	}
	return out
}

// acmWrites counts the ACM write calls since the last reset.
func (h *awsHarness) acmWrites() []string {
	var out []string
	for _, c := range h.acmCalls() {
		if c == "RequestCertificate" || c == "ImportCertificate" {
			out = append(out, c)
		}
	}
	return out
}

func (h *awsHarness) resetACM() {
	h.ec2.mu.Lock()
	defer h.ec2.mu.Unlock()
	h.ec2.acm.calls, h.ec2.acm.lists, h.ec2.acm.requests, h.ec2.acm.imports = nil, nil, nil, nil
}
