package aws

import (
	"context"
	"errors"
	"fmt"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// route53domainsRegion is the only region that serves the Route 53 Domains API.
const route53domainsRegion = "us-east-1"

// The small API surfaces used by the client, so tests can substitute fakes.
type stsAPI interface {
	GetCallerIdentity(ctx context.Context, in *sts.GetCallerIdentityInput, optFns ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error)
}

type route53API interface {
	ListHostedZones(ctx context.Context, in *route53.ListHostedZonesInput, optFns ...func(*route53.Options)) (*route53.ListHostedZonesOutput, error)
	GetHostedZone(ctx context.Context, in *route53.GetHostedZoneInput, optFns ...func(*route53.Options)) (*route53.GetHostedZoneOutput, error)
	ListResourceRecordSets(ctx context.Context, in *route53.ListResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ListResourceRecordSetsOutput, error)
	ChangeResourceRecordSets(ctx context.Context, in *route53.ChangeResourceRecordSetsInput, optFns ...func(*route53.Options)) (*route53.ChangeResourceRecordSetsOutput, error)
}

type route53domainsAPI interface {
	ListDomains(ctx context.Context, in *route53domains.ListDomainsInput, optFns ...func(*route53domains.Options)) (*route53domains.ListDomainsOutput, error)
	GetDomainDetail(ctx context.Context, in *route53domains.GetDomainDetailInput, optFns ...func(*route53domains.Options)) (*route53domains.GetDomainDetailOutput, error)
	UpdateDomainNameservers(ctx context.Context, in *route53domains.UpdateDomainNameserversInput, optFns ...func(*route53domains.Options)) (*route53domains.UpdateDomainNameserversOutput, error)
}

type ec2API interface {
	DescribeInstances(ctx context.Context, in *ec2.DescribeInstancesInput, optFns ...func(*ec2.Options)) (*ec2.DescribeInstancesOutput, error)
	StartInstances(ctx context.Context, in *ec2.StartInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StartInstancesOutput, error)
	StopInstances(ctx context.Context, in *ec2.StopInstancesInput, optFns ...func(*ec2.Options)) (*ec2.StopInstancesOutput, error)
}

// client is an authenticated AWS session.
type client struct {
	region string
	sts    stsAPI
	r53    route53API
	r53d   route53domainsAPI
	ec2For func(region string) ec2API
}

var (
	_ platform.Client           = (*client)(nil)
	_ platform.DNSService       = (*client)(nil)
	_ platform.RegistrarService = (*client)(nil)
)

func newClient(cfg awssdk.Config, region string) *client {
	regional := func(r string) awssdk.Config {
		c := cfg
		c.Region = r
		return c
	}
	return &client{
		region: region,
		sts:    sts.NewFromConfig(regional(region)),
		r53:    route53.NewFromConfig(regional(region)),
		r53d:   route53domains.NewFromConfig(regional(route53domainsRegion)),
		ec2For: func(r string) ec2API { return ec2.NewFromConfig(regional(r)) },
	}
}

// Verify calls sts GetCallerIdentity.
func (c *client) Verify(ctx context.Context) (*platform.Identity, error) {
	out, err := c.sts.GetCallerIdentity(ctx, &sts.GetCallerIdentityInput{})
	if err != nil {
		return nil, mapErr(err)
	}
	id := identityFromCaller(awssdk.ToString(out.Account), awssdk.ToString(out.Arn), awssdk.ToString(out.UserId))
	if c.region != "" {
		if id.Extra == nil {
			id.Extra = map[string]string{}
		}
		id.Extra["region"] = c.region
	}
	return id, nil
}

// Sync fetches every resource of the given type.
func (c *client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	switch rt {
	case platform.ResZone:
		zones, err := c.listZonesWithNameservers(ctx)
		if err != nil {
			return nil, err
		}
		return zoneResources(zones), nil
	case platform.ResDNSRecord:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		var out []platform.Resource
		for _, z := range zones {
			recs, err := c.ListRecords(ctx, z.ID)
			if err != nil {
				return nil, fmt.Errorf("zone %s: %w", z.Name, err)
			}
			out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
		}
		return out, nil
	case platform.ResDomain:
		domains, err := c.ListDomains(ctx)
		if err != nil {
			if registrarUnavailable(err) {
				// Not an ErrUnauthorized: the sync reports the reason and
				// keeps the cached domains instead of replacing them with
				// an empty set.
				return nil, fmt.Errorf("route 53 domains unavailable (%s); keeping cached domains", apiErrorCode(err))
			}
			return nil, err
		}
		return app.DomainResources(domains), nil
	case platform.ResInstance:
		return c.listInstances(ctx, c.region)
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}

// zoneResources converts zones to inventory resources. Private zones stay
// in the inventory but are not indexed by domain, so the generic dns
// commands never route a public change to a private zone of the same name.
func zoneResources(zones []platform.Zone) []platform.Resource {
	out := app.ZoneResources(zones)
	for i := range out {
		if z, ok := out[i].Data.(platform.Zone); ok && z.Status == "private" {
			out[i].Domain = ""
		}
	}
	return out
}

// apiError is the subset of smithy.APIError the error mapping needs; using
// a local interface avoids a direct dependency on smithy-go.
type apiError interface {
	error
	ErrorCode() string
	ErrorMessage() string
}

type httpStatusError interface {
	error
	HTTPStatusCode() int
}

var unauthorizedCodes = map[string]bool{
	"AccessDenied":                true,
	"AccessDeniedException":       true,
	"UnauthorizedException":       true,
	"UnauthorizedClientException": true,
	"UnauthorizedOperation":       true,
	"AuthFailure":                 true,
	"InvalidClientTokenId":        true,
	"UnrecognizedClientException": true,
	"InvalidSignatureException":   true,
	"SignatureDoesNotMatch":       true,
	"ExpiredToken":                true,
	"ExpiredTokenException":       true,
	"InvalidGrantException":       true,
	"RequestExpired":              true,
	"InvalidIdentityToken":        true,
}

var notFoundCodes = map[string]bool{
	"NoSuchHostedZone":    true,
	"NoSuchDomain":        true,
	"NoSuchChange":        true,
	"NotFoundException":   true,
	"ResourceNotFound":    true,
	"InvalidZoneIdFormat": true,
}

// mapErr translates AWS errors to the platform sentinels where applicable.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	if errors.Is(err, platform.ErrUnauthorized) || errors.Is(err, platform.ErrNotFound) {
		return err
	}
	var ae apiError
	if errors.As(err, &ae) {
		code, msg := ae.ErrorCode(), strings.TrimSpace(ae.ErrorMessage())
		switch {
		case unauthorizedCodes[code]:
			return fmt.Errorf("%w: %s: %s: %w", platform.ErrUnauthorized, code, msg, err)
		case notFoundCodes[code], strings.HasSuffix(code, ".NotFound"),
			code == "InvalidInput" && strings.Contains(strings.ToLower(msg), "not found"):
			return fmt.Errorf("%w: %s: %s: %w", platform.ErrNotFound, code, msg, err)
		}
	}
	var he httpStatusError
	if errors.As(err, &he) {
		switch he.HTTPStatusCode() {
		case 401, 403:
			return fmt.Errorf("%w: %w", platform.ErrUnauthorized, err)
		case 404:
			return fmt.Errorf("%w: %w", platform.ErrNotFound, err)
		}
	}
	return err
}

// apiErrorCode returns the AWS error code of err, or its message when it
// is not an API error.
func apiErrorCode(err error) string {
	var ae apiError
	if errors.As(err, &ae) {
		return ae.ErrorCode()
	}
	if err == nil {
		return ""
	}
	return err.Error()
}

// registrarUnavailable reports whether err means the account cannot use
// Route 53 Domains at all (not enabled / not permitted).
func registrarUnavailable(err error) bool {
	var ae apiError
	if !errors.As(err, &ae) {
		return false
	}
	switch ae.ErrorCode() {
	case "AccessDenied", "AccessDeniedException", "UnsupportedOperation", "OptInRequired", "SubscriptionRequiredException":
		return true
	}
	return false
}
