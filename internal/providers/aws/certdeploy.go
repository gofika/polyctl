package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/acm"
	acmtypes "github.com/aws/aws-sdk-go-v2/service/acm/types"

	"github.com/gofika/polyctl/internal/platform"
)

// The aws-acm deployer of cert deploy. Load balancers and CloudFront
// distributions reference an ACM certificate by its ARN, and an imported
// certificate can be re-imported under the same ARN, so a due imported
// certificate is re-imported in place and nothing else changes.
// Amazon-issued certificates are renewed by ACM and left alone. A
// certificate is only ever updated, never imported for the first time
// (that is `aws acm certificate import`).

const acmDeployerID = "aws-acm"

func init() { platform.RegisterDeployer(acmDeployer{}) }

// acmDeployer implements platform.CertDeployer for imported ACM
// certificates.
type acmDeployer struct{}

func (acmDeployer) ID() string            { return acmDeployerID }
func (acmDeployer) Platform() platform.ID { return platform.AWS }

// deployClient is the AWS client of a deploy account.
func deployClient(acct *platform.DeployAccount) (*client, error) {
	c, ok := acct.Client.(*client)
	if !ok {
		return nil, fmt.Errorf("%w: the client of %s is not an AWS client", platform.ErrNotSupported, acct.Profile)
	}
	return c, nil
}

// acmDeployRegions are the regions the deployer scans: --region or
// cert.aws.regions, else the profile's region (CloudFront certificates
// live in us-east-1, which has to be named).
func acmDeployRegions(acct *platform.DeployAccount, c *client) []string {
	if len(acct.Regions) > 0 {
		return acct.Regions
	}
	return []string{c.regionOr("")}
}

// deleteACMCertificate deletes a certificate.
func (c *client) deleteACMCertificate(ctx context.Context, region, arn string) error {
	region = c.regionOr(region)
	_, err := c.acmFor(region).DeleteCertificate(ctx, &acm.DeleteCertificateInput{CertificateArn: awssdk.String(arn)})
	return acmErr("DeleteCertificate", region, err)
}

// acmInUse reports the error of deleting a certificate something uses.
func acmInUse(err error) bool {
	var iu *acmtypes.ResourceInUseException
	return errors.As(err, &iu) || platform.HasErrorCode(err, "ResourceInUseException")
}

// Discover lists the certificates of every key type in the regions (a
// listing without key types leaves out ECDSA). Imported ones are targets;
// Amazon-issued ones are skipped.
func (d acmDeployer) Discover(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.DeployTarget, []platform.Change, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, nil, err
	}
	var targets []platform.DeployTarget
	var skipped []platform.Change
	for _, region := range acmDeployRegions(acct, c) {
		certs, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: acmSyncKeyTypes})
		if err != nil {
			return nil, nil, err
		}
		for _, s := range certs {
			name := region + "/" + s.ID
			res := platform.DeployResource(acmDeployerID, acct.Profile, name)
			attrs := map[string]string{"deployer": acmDeployerID, "platform": string(platform.AWS), "profile": acct.Profile, "region": region}
			if root, err := platform.RegisteredDomain(platform.CertDomain(append([]string{s.Domain}, s.Names...), "")); err == nil {
				attrs["domain"] = root
			}
			switch s.Type {
			case acmImported:
			case acmAmazonIssued:
				detail := "Type=AMAZON_ISSUED, renewed by ACM"
				if s.Status == acmPendingValidation || s.Status == acmValidationFailed {
					detail += fmt.Sprintf("; status %s: complete its DNS validation (polyctl aws acm certificate get %s --region %s)", s.Status, s.ID, region)
				}
				skipped = append(skipped, platform.Change{Resource: res, Action: platform.Skipped, ID: s.ID, Detail: detail, Attrs: attrs})
				continue
			default:
				skipped = append(skipped, platform.Change{Resource: res, Action: platform.Skipped, ID: s.ID, Detail: "Type=" + s.Type + ", not an imported certificate", Attrs: attrs})
				continue
			}
			full, err := c.DescribeCertificate(ctx, region, s.ID)
			if errors.Is(err, platform.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, nil, err
			}
			var notAfter time.Time
			if full.NotAfter != nil {
				notAfter = full.NotAfter.UTC()
			}
			targets = append(targets, platform.DeployTarget{Deployer: acmDeployerID, Platform: platform.AWS, Profile: acct.Profile, Region: region,
				Kind: "acm-certificate", ID: s.ID, Name: name, CurrentCertID: s.ID, CurrentDomains: nameSet(append([]string{full.Domain}, full.Names...)...),
				CurrentNotAfter: notAfter, CurrentSerial: full.Serial,
				Attrs: map[string]string{"key_algorithm": normalizeKeyAlgorithm(full.KeyAlgorithm), "in_use_by": strings.Join(full.InUseBy, ",")}})
		}
	}
	return targets, skipped, nil
}

// Plan re-imports the certificate into the ARN of the target: the leaf and
// the chain apart, without tags (ACM refuses them on a re-import and keeps
// the ones the certificate has), then reads it back until it shows the new
// serial number. ACM cannot change the key algorithm of a certificate: a
// certificate of another key type is imported as a new certificate, whose
// new ARN has to be set where the old one is used (a warning says so).
func (d acmDeployer) Plan(ctx context.Context, acct *platform.DeployAccount, t platform.DeployTarget, cert *platform.DeployCert, o platform.DeployOptions) ([]platform.Step, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, err
	}
	res := t.Resource()
	if cert.Pending {
		return []platform.Step{{Resource: res, Action: platform.Updated, ID: t.ID, Desc: "re-import " + t.ID + " (the ARN stays)",
			Apply: func(context.Context) (platform.Change, error) {
				return platform.Change{}, errors.New("the certificate was not issued")
			}}}, nil
	}
	if platform.SerialKey(t.CurrentSerial) == platform.SerialKey(cert.Serial) {
		return []platform.Step{{Resource: res, Action: platform.Unchanged, ID: t.ID, Desc: "holds serial " + cert.Serial}}, nil
	}
	alg, err := acmKeyAlgorithmOf(cert.Leaf.PublicKey)
	if err != nil {
		return nil, err
	}
	desc := fmt.Sprintf("serial %s, %s, expires %s", cert.Serial, alg, cert.NotAfter.UTC().Format("2006-01-02"))
	importNew := func(ctx context.Context, why string) (platform.Change, error) {
		arn, err := c.ImportCertificate(ctx, platform.CertificateImport{Region: t.Region, Cert: cert.Cert, Chain: cert.Chain, Key: cert.Key,
			Tags: map[string]string{"polyctl:domain": cert.Root}})
		if err != nil {
			return platform.Change{}, err
		}
		if _, err := c.waitImported(ctx, t.Region, arn, cert.Serial); err != nil {
			return platform.Change{ID: arn}, fmt.Errorf("certificate %s was imported, but reading it back failed: %w", arn, err)
		}
		o.Warnf("%s: %s; imported as the new certificate %s: the ARN changed, update the load balancers and CloudFront distributions that use %s", acct.Profile, why, arn, t.ID)
		return platform.Change{ID: arn, Detail: fmt.Sprintf("new certificate %s (%s): the ARN changed, update where %s is used", arn, desc, t.ID)}, nil
	}
	// replaced is the change of a target whose certificate an earlier run
	// imported as a new certificate already: it is not imported again.
	replaced := func(arn, why string) platform.Change {
		detail := fmt.Sprintf("%s; the certificate (serial %s) is imported as %s already: update the load balancers and CloudFront distributions that use %s, then delete it",
			why, cert.Serial, arn, t.ID)
		if t.Attrs["in_use_by"] != "" {
			o.Warnf("%s: %s", acct.Profile, detail)
		}
		return platform.Change{Action: platform.Skipped, Detail: detail}
	}
	if have := t.Attrs["key_algorithm"]; have != "" && have != alg {
		why := fmt.Sprintf("ACM cannot change the key algorithm of %s (%s, the new certificate has %s)", t.ID, have, alg)
		arn, err := c.importedWithSerial(ctx, t.Region, cert, t.ID)
		if err != nil {
			return nil, err
		}
		if arn != "" {
			ch := replaced(arn, why)
			return []platform.Step{{Resource: res, Action: platform.Skipped, ID: t.ID, Desc: ch.Detail}}, nil
		}
		return []platform.Step{{Resource: res, Action: platform.Updated, ID: t.ID, Desc: "import as a new certificate (" + desc + "): the ARN changes",
			Apply: func(ctx context.Context) (platform.Change, error) { return importNew(ctx, why) }}}, nil
	}
	return []platform.Step{{Resource: res, Action: platform.Updated, ID: t.ID, Desc: "re-import " + desc + " (the ARN stays)",
		Apply: func(ctx context.Context) (platform.Change, error) {
			_, err := c.ImportCertificate(ctx, platform.CertificateImport{Region: t.Region, ARN: t.ID, Cert: cert.Cert, Chain: cert.Chain, Key: cert.Key})
			var ve *acmtypes.ValidationException
			if err != nil && errors.As(err, &ve) && strings.Contains(ve.ErrorMessage(), "different from") {
				why := "ACM refused the re-import: " + ve.ErrorMessage()
				arn, err := c.importedWithSerial(ctx, t.Region, cert, t.ID)
				if err != nil {
					return platform.Change{}, err
				}
				if arn != "" {
					return replaced(arn, why), nil
				}
				return importNew(ctx, why)
			}
			if err != nil {
				return platform.Change{}, err
			}
			if _, err := c.waitImported(ctx, t.Region, t.ID, cert.Serial); err != nil {
				return platform.Change{}, fmt.Errorf("certificate %s was re-imported, but reading it back failed: %w", t.ID, err)
			}
			return platform.Change{Detail: "re-imported " + desc + " (the ARN stays)"}, nil
		}}}, nil
}

// importedWithSerial returns the ARN of another imported certificate of
// the region that holds the serial number of cert (an earlier run imported
// it as a new certificate), or "". Only certificates whose domain cert
// covers are read.
func (c *client) importedWithSerial(ctx context.Context, region string, cert *platform.DeployCert, except string) (string, error) {
	certs, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: acmSyncKeyTypes})
	if err != nil {
		return "", err
	}
	want := platform.SerialKey(cert.Serial)
	for _, s := range certs {
		if s.Type != acmImported || s.ID == except {
			continue
		}
		if len(cert.Names) > 0 && !platform.CertCovers(cert.Names, s.Domain) {
			continue
		}
		full, err := c.DescribeCertificate(ctx, region, s.ID)
		if errors.Is(err, platform.ErrNotFound) {
			continue
		}
		if err != nil {
			return "", err
		}
		if platform.SerialKey(full.Serial) == want {
			return s.ID, nil
		}
	}
	return "", nil
}

// Prune deletes the expired imported certificates of the regions that
// nothing uses (DescribeCertificate's InUseBy); Amazon-issued ones are
// left to ACM.
func (d acmDeployer) Prune(ctx context.Context, acct *platform.DeployAccount, o platform.DeployOptions) ([]platform.Step, error) {
	c, err := deployClient(acct)
	if err != nil {
		return nil, err
	}
	var steps []platform.Step
	for _, region := range acmDeployRegions(acct, c) {
		certs, err := c.ListCertificates(ctx, platform.CertificateFilter{Region: region, KeyTypes: acmSyncKeyTypes, Statuses: []string{acmExpired}})
		if err != nil {
			return nil, err
		}
		for _, s := range certs {
			if s.Type != acmImported {
				continue
			}
			full, err := c.DescribeCertificate(ctx, region, s.ID)
			if errors.Is(err, platform.ErrNotFound) {
				continue
			}
			if err != nil {
				return nil, err
			}
			res := platform.DeployResource(acmDeployerID, acct.Profile, region+"/"+s.ID)
			desc := "cert=" + s.ID + " expired"
			if full.NotAfter != nil {
				desc += " (" + full.NotAfter.UTC().Format("2006-01-02") + ")"
			}
			if len(full.InUseBy) > 0 {
				steps = append(steps, platform.Step{Resource: res, Action: platform.Skipped, ID: s.ID, Desc: desc + "; still used by " + strings.Join(full.InUseBy, ", ")})
				continue
			}
			arn, r := s.ID, region
			steps = append(steps, platform.Step{Resource: res, Action: platform.Deleted, ID: s.ID, Desc: desc,
				Apply: func(ctx context.Context) (platform.Change, error) {
					err := c.deleteACMCertificate(ctx, r, arn)
					if err != nil && acmInUse(err) {
						return platform.Change{Action: platform.Skipped, Detail: desc + "; still in use"}, nil
					}
					return platform.Change{}, err
				}})
		}
	}
	return steps, nil
}
