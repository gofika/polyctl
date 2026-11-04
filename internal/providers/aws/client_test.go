package aws

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	r53dtypes "github.com/aws/aws-sdk-go-v2/service/route53domains/types"
	"github.com/aws/aws-sdk-go-v2/service/sts"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// fakeAPIError mimics a smithy API error.
type fakeAPIError struct{ code, msg string }

func (e *fakeAPIError) Error() string        { return e.code + ": " + e.msg }
func (e *fakeAPIError) ErrorCode() string    { return e.code }
func (e *fakeAPIError) ErrorMessage() string { return e.msg }

type fakeHTTPError struct{ status int }

func (e *fakeHTTPError) Error() string       { return fmt.Sprintf("http %d", e.status) }
func (e *fakeHTTPError) HTTPStatusCode() int { return e.status }

func TestMapErr(t *testing.T) {
	cases := []struct {
		err  error
		want error
	}{
		{&fakeAPIError{"AccessDeniedException", "nope"}, platform.ErrUnauthorized},
		{&fakeAPIError{"UnauthorizedException", "token expired"}, platform.ErrUnauthorized},
		{&fakeAPIError{"InvalidClientTokenId", "bad key"}, platform.ErrUnauthorized},
		{fmt.Errorf("wrapped: %w", &fakeAPIError{"ExpiredTokenException", "x"}), platform.ErrUnauthorized},
		{&fakeAPIError{"NoSuchHostedZone", "x"}, platform.ErrNotFound},
		{&fakeAPIError{"InvalidInstanceID.NotFound", "x"}, platform.ErrNotFound},
		{&fakeAPIError{"InvalidInput", "Domain example.com not found in account"}, platform.ErrNotFound},
		{&fakeHTTPError{403}, platform.ErrUnauthorized},
		{&fakeHTTPError{404}, platform.ErrNotFound},
	}
	for _, c := range cases {
		if got := mapErr(c.err); !errors.Is(got, c.want) {
			t.Errorf("mapErr(%v) = %v, want %v", c.err, got, c.want)
		}
	}
	other := &fakeAPIError{"Throttling", "slow down"}
	if got := mapErr(other); !errors.Is(got, other) || errors.Is(got, platform.ErrUnauthorized) || errors.Is(got, platform.ErrNotFound) {
		t.Errorf("unrelated errors must pass through, got %v", got)
	}
	if got := mapErr(context.Canceled); !errors.Is(got, context.Canceled) {
		t.Errorf("context errors must pass through, got %v", got)
	}
	if mapErr(nil) != nil {
		t.Error("nil must stay nil")
	}
	if !registrarUnavailable(&fakeAPIError{"AccessDeniedException", ""}) || registrarUnavailable(&fakeAPIError{"InvalidInput", ""}) {
		t.Error("registrarUnavailable mismatch")
	}
}

type fakeSTS struct {
	out *sts.GetCallerIdentityOutput
	err error
}

func (f *fakeSTS) GetCallerIdentity(context.Context, *sts.GetCallerIdentityInput, ...func(*sts.Options)) (*sts.GetCallerIdentityOutput, error) {
	return f.out, f.err
}

func TestVerify(t *testing.T) {
	c := &client{sts: &fakeSTS{out: &sts.GetCallerIdentityOutput{Account: awssdk.String("123456789012"), Arn: awssdk.String("arn:aws:iam::123456789012:user/me"), UserId: awssdk.String("AIDA")}}}
	id, err := c.Verify(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if id.Account != "123456789012" || id.User != "arn:aws:iam::123456789012:user/me" || id.Extra["user_id"] != "AIDA" {
		t.Fatalf("unexpected identity %+v", id)
	}
	c = &client{sts: &fakeSTS{err: &fakeAPIError{"InvalidClientTokenId", "x"}}}
	if _, err := c.Verify(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized, got %v", err)
	}
}

type fakeDomains struct {
	summaries []r53dtypes.DomainSummary
	details   map[string]*route53domains.GetDomainDetailOutput
	listErr   error
	detailErr error
	updated   map[string][]string
	pageSize  int
}

func (f *fakeDomains) ListDomains(ctx context.Context, in *route53domains.ListDomainsInput, _ ...func(*route53domains.Options)) (*route53domains.ListDomainsOutput, error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	start := 0
	if in.Marker != nil {
		for i, s := range f.summaries {
			if awssdk.ToString(s.DomainName) == *in.Marker {
				start = i
			}
		}
	}
	end := start + f.pageSize
	out := &route53domains.ListDomainsOutput{}
	if end >= len(f.summaries) {
		end = len(f.summaries)
	} else {
		out.NextPageMarker = f.summaries[end].DomainName
	}
	out.Domains = f.summaries[start:end]
	return out, nil
}

func (f *fakeDomains) GetDomainDetail(ctx context.Context, in *route53domains.GetDomainDetailInput, _ ...func(*route53domains.Options)) (*route53domains.GetDomainDetailOutput, error) {
	if f.detailErr != nil {
		return nil, f.detailErr
	}
	d, ok := f.details[awssdk.ToString(in.DomainName)]
	if !ok {
		return nil, &fakeAPIError{"InvalidInput", "Domain " + awssdk.ToString(in.DomainName) + " not found in account"}
	}
	return d, nil
}

func (f *fakeDomains) UpdateDomainNameservers(ctx context.Context, in *route53domains.UpdateDomainNameserversInput, _ ...func(*route53domains.Options)) (*route53domains.UpdateDomainNameserversOutput, error) {
	if f.updated == nil {
		f.updated = map[string][]string{}
	}
	var ns []string
	for _, n := range in.Nameservers {
		ns = append(ns, awssdk.ToString(n.Name))
	}
	f.updated[awssdk.ToString(in.DomainName)] = ns
	return &route53domains.UpdateDomainNameserversOutput{OperationId: awssdk.String("op-1")}, nil
}

func TestDomains(t *testing.T) {
	exp := time.Date(2027, 1, 2, 3, 4, 5, 0, time.UTC)
	f := &fakeDomains{
		pageSize: 1,
		summaries: []r53dtypes.DomainSummary{
			{DomainName: awssdk.String("a.com"), AutoRenew: awssdk.Bool(true), TransferLock: awssdk.Bool(true), Expiry: &exp},
			{DomainName: awssdk.String("b.com"), AutoRenew: awssdk.Bool(false)},
		},
		details: map[string]*route53domains.GetDomainDetailOutput{
			"a.com": {
				DomainName: awssdk.String("A.com"), AdminPrivacy: awssdk.Bool(true), ExpirationDate: &exp,
				Nameservers: []r53dtypes.Nameserver{{Name: awssdk.String("NS1.example.net.")}, {Name: awssdk.String("ns2.example.net")}},
				StatusList:  []string{"clientTransferProhibited", "ok"}, RegistrarName: awssdk.String("Amazon Registrar, Inc."),
			},
		},
	}
	c := &client{r53d: f}
	domains, err := c.ListDomains(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(domains) != 2 {
		t.Fatalf("expected 2 domains, got %d", len(domains))
	}
	a := domains[0]
	if a.Name != "a.com" || a.ExpiresAt != "2027-01-02T03:04:05Z" || a.Privacy == nil || !*a.Privacy || a.Locked == nil || !*a.Locked {
		t.Fatalf("unexpected domain %+v", a)
	}
	if len(a.Nameservers) != 2 || a.Nameservers[0] != "ns1.example.net" || a.Status != "clientTransferProhibited,ok" || a.Extra["registrar_name"] != "Amazon Registrar, Inc." {
		t.Fatalf("unexpected detail mapping %+v", a)
	}
	if domains[1].Name != "b.com" || domains[1].AutoRenew == nil || *domains[1].AutoRenew || domains[1].Extra["detail_error"] != "InvalidInput" {
		t.Fatalf("summary fallback failed %+v", domains[1])
	}

	// Detail not permitted: the summary is kept and the reason recorded.
	f.detailErr = &fakeAPIError{"AccessDeniedException", "no GetDomainDetail"}
	domains, err = c.ListDomains(context.Background())
	if err != nil || len(domains) != 2 || domains[0].Nameservers != nil || domains[0].Extra["detail_error"] != "AccessDeniedException" {
		t.Fatalf("denied detail must keep the summary: %v %+v", err, domains)
	}
	// Any other detail failure (throttling, network) is an error, not a
	// silently degraded domain.
	f.detailErr = &fakeAPIError{"ThrottlingException", "slow down"}
	if _, err := c.ListDomains(context.Background()); err == nil || !strings.Contains(err.Error(), "ThrottlingException") {
		t.Fatalf("throttled detail must fail the listing, got %v", err)
	}
	f.detailErr = nil

	if _, err := c.GetDomain(context.Background(), "missing.com"); !errors.Is(err, platform.ErrNotFound) {
		t.Fatalf("expected ErrNotFound, got %v", err)
	}
	if err := c.SetNameservers(context.Background(), "A.com.", []string{"ns1.x.net.", "NS2.x.net"}); err != nil {
		t.Fatal(err)
	}
	if got := f.updated["a.com"]; len(got) != 2 || got[0] != "ns1.x.net" || got[1] != "ns2.x.net" {
		t.Fatalf("nameservers not normalized: %v", got)
	}

	// Route 53 Domains not enabled or not permitted: sync reports a plain
	// (non-Unauthorized) error so the cached domains are kept, explicit
	// calls fail with ErrUnauthorized.
	f.listErr = &fakeAPIError{"AccessDeniedException", "not subscribed"}
	res, err := c.Sync(context.Background(), platform.ResDomain)
	if err == nil || errors.Is(err, platform.ErrUnauthorized) || len(res) != 0 || !strings.Contains(err.Error(), "AccessDeniedException") {
		t.Fatalf("sync must report an unavailable registrar without ErrUnauthorized: %v %v", err, res)
	}
	if _, err := c.ListDomains(context.Background()); !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("explicit list must fail with ErrUnauthorized, got %v", err)
	}
}

func TestInstanceFrom(t *testing.T) {
	lt := time.Date(2026, 5, 6, 7, 8, 9, 0, time.UTC)
	info := instanceFrom("eu-west-1", ec2types.Instance{
		InstanceId: awssdk.String("i-0123"), InstanceType: ec2types.InstanceTypeT3Micro, LaunchTime: &lt,
		State:            &ec2types.InstanceState{Name: ec2types.InstanceStateNameRunning},
		Placement:        &ec2types.Placement{AvailabilityZone: awssdk.String("eu-west-1a")},
		PrivateIpAddress: awssdk.String("10.0.0.1"), PublicIpAddress: awssdk.String("3.3.3.3"),
		Tags: []ec2types.Tag{{Key: awssdk.String("Name"), Value: awssdk.String("web")}, {Key: awssdk.String("env"), Value: awssdk.String("prod")}},
	})
	if info.ID != "i-0123" || info.Name != "web" || info.State != "running" || info.Type != "t3.micro" || info.AZ != "eu-west-1a" || info.Region != "eu-west-1" {
		t.Fatalf("unexpected instance %+v", info)
	}
	if info.LaunchTime != "2026-05-06T07:08:09Z" || info.Tags["env"] != "prod" || info.PrivateIP != "10.0.0.1" || info.PublicIP != "3.3.3.3" {
		t.Fatalf("unexpected instance details %+v", info)
	}
	r := info.resource()
	if r.Type != platform.ResInstance || r.ID != "i-0123" || r.Name != "web" || r.Domain != "" {
		t.Fatalf("unexpected resource %+v", r)
	}
}

func TestSyncUnsupported(t *testing.T) {
	c := &client{}
	if _, err := c.Sync(context.Background(), platform.ResourceType("bucket")); !errors.Is(err, platform.ErrNotSupported) {
		t.Fatalf("expected ErrNotSupported, got %v", err)
	}
}

func TestSyncRecordsAndZones(t *testing.T) {
	f := newFakeRoute53()
	f.zones = []r53types.HostedZone{
		{Id: awssdk.String("/hostedzone/Z1"), Name: awssdk.String("example.com.")},
		// Split horizon: a private zone of the same name.
		{Id: awssdk.String("/hostedzone/Z2"), Name: awssdk.String("example.com."), Config: &r53types.HostedZoneConfig{PrivateZone: true}},
	}
	f.sets["Z1"] = []r53types.ResourceRecordSet{valueSet("www.example.com.", "A", 300, "1.1.1.1", "2.2.2.2")}
	f.sets["Z2"] = []r53types.ResourceRecordSet{valueSet("www.example.com.", "A", 300, "1.1.1.1")}
	c := testClient(f)
	ctx := context.Background()
	zones, err := c.Sync(ctx, platform.ResZone)
	if err != nil || len(zones) != 2 || zones[0].ID != "Z1" || zones[1].ID != "Z2" {
		t.Fatalf("zone sync: %v %+v", err, zones)
	}
	if zones[0].Domain != "example.com" || len(zones[0].Data.(platform.Zone).Nameservers) != 2 {
		t.Fatalf("public zone must be indexed with its nameservers: %+v", zones[0])
	}
	if zones[1].Domain != "" || zones[1].Data.(platform.Zone).Status != "private" {
		t.Fatalf("private zone must not be indexed by domain: %+v", zones[1])
	}
	recs, err := c.Sync(ctx, platform.ResDNSRecord)
	if err != nil || len(recs) != 3 {
		t.Fatalf("record sync: %v %+v", err, recs)
	}
	ids := map[string]bool{}
	for _, r := range recs {
		if (r.ParentID != "Z1" && r.ParentID != "Z2") || r.Domain != "example.com" || r.Type != platform.ResDNSRecord {
			t.Fatalf("bad record resource %+v", r)
		}
		if ids[r.ID] {
			t.Fatalf("duplicate record id across zones: %s", r.ID)
		}
		ids[r.ID] = true
	}

	// Only the public zone reaches the domain index.
	db, err := inventory.Open(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	set := inventory.Set{Platform: platform.AWS, Profile: "p", Type: platform.ResZone}
	if err := db.Replace(ctx, set, zones, time.Hour); err != nil {
		t.Fatal(err)
	}
	entries, err := db.LookupDomain(ctx, []string{"example.com"}, platform.ResZone)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].ResourceID != "Z1" {
		t.Fatalf("domain index must only hold the public zone: %+v", entries)
	}
	rows, err := db.List(ctx, inventory.Query{Platform: platform.AWS, Profile: "p", Type: platform.ResZone})
	if err != nil || len(rows) != 2 {
		t.Fatalf("both zones must stay in the inventory: %v %+v", err, rows)
	}
}

func TestOpenProfileUsesSharedConfigRegion(t *testing.T) {
	dir := t.TempDir()
	cfgFile := filepath.Join(dir, "config")
	if err := os.WriteFile(cfgFile, []byte("[profile eu]\nregion = eu-west-1\n\n[profile noregion]\noutput = json\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	credFile := filepath.Join(dir, "credentials")
	if err := os.WriteFile(credFile, []byte("[eu]\naws_access_key_id = AKIATEST\naws_secret_access_key = secret\n\n[noregion]\naws_access_key_id = AKIATEST\naws_secret_access_key = secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AWS_CONFIG_FILE", cfgFile)
	t.Setenv("AWS_SHARED_CREDENTIALS_FILE", credFile)
	for _, k := range []string{"AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AWS_DEFAULT_PROFILE"} {
		t.Setenv(k, "")
	}
	p := &provider{}
	open := func(meta map[string]string) string {
		t.Helper()
		meta[metaMethod] = methodProfile
		c, err := p.Open(context.Background(), platform.Profile{Name: "x", Platform: platform.AWS, Metadata: meta})
		if err != nil {
			t.Fatalf("open %v: %v", meta, err)
		}
		return c.(*client).region
	}
	if got := open(map[string]string{metaAWSProfile: "eu"}); got != "eu-west-1" {
		t.Fatalf("region must come from ~/.aws/config, got %q", got)
	}
	if got := open(map[string]string{metaAWSProfile: "eu", metaRegion: "ap-northeast-1"}); got != "ap-northeast-1" {
		t.Fatalf("explicit metadata region must win, got %q", got)
	}
	if got := open(map[string]string{metaAWSProfile: "noregion"}); got != defaultRegion {
		t.Fatalf("profile without region must fall back to %s, got %q", defaultRegion, got)
	}
}

func TestOpenRejectsIncompleteProfiles(t *testing.T) {
	p := &provider{}
	_, err := p.Open(context.Background(), platform.Profile{Name: "x", Platform: platform.AWS, Metadata: map[string]string{metaMethod: methodKeys}, Secret: map[string]string{}})
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for missing keys, got %v", err)
	}
	_, err = p.Open(context.Background(), platform.Profile{Name: "x", Platform: platform.AWS, Metadata: map[string]string{metaMethod: methodSSO, metaAccountID: "1", metaRoleName: "r"}, Secret: map[string]string{
		secretAccessToken: "t", secretTokenExpiresAt: time.Now().Add(-time.Hour).UTC().Format(time.RFC3339),
	}})
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for an expired SSO token without refresh token, got %v", err)
	}
	_, err = p.Open(context.Background(), platform.Profile{Name: "x", Platform: platform.AWS, Metadata: map[string]string{}})
	if !errors.Is(err, platform.ErrUnauthorized) {
		t.Fatalf("expected ErrUnauthorized for an unknown method, got %v", err)
	}
	c, err := p.Open(context.Background(), platform.Profile{Name: "x", Platform: platform.AWS,
		Metadata: map[string]string{metaMethod: methodKeys, metaRegion: "ap-northeast-1"},
		Secret:   map[string]string{secretAccessKeyID: "AKIA", secretSecretAccessKey: "s"}})
	if err != nil {
		t.Fatal(err)
	}
	if ac := c.(*client); ac.region != "ap-northeast-1" {
		t.Fatalf("region not taken from metadata: %q", ac.region)
	}
	if _, ok := c.(platform.DNSService); !ok {
		t.Fatal("client must implement DNSService")
	}
	if _, ok := c.(platform.RegistrarService); !ok {
		t.Fatal("client must implement RegistrarService")
	}
}
