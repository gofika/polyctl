package aws

import (
	"strings"
	"testing"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/platform"
)

// The labels of the selection lists are rows of cells: a fact keeps its
// position in every row, "-" stands for a fact a row does not have when a
// later cell follows, and trailing empty cells are dropped.
func TestOptionLabelsKeepTheirCells(t *testing.T) {
	exp := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	for name, c := range map[string]struct{ got, want string }{
		"instance without a public address": {
			instanceOptionLabel(instanceInfo{ID: "i-0abc", Name: "web-01", State: "stopped", Type: "t3.nano", AZ: "ap-east-1a", PrivateIP: "10.0.1.5"}, "lab"),
			"web-01  i-0abc  stopped  t3.nano  ap-east-1a  10.0.1.5  -  aws/lab"},
		"instance without a name": {
			instanceOptionLabel(instanceInfo{ID: "i-0abc", State: "running", Type: "t3.nano", AZ: "ap-east-1a", PrivateIP: "10.0.1.5", PublicIP: "198.51.100.7"}, "lab"),
			"i-0abc  i-0abc  running  t3.nano  ap-east-1a  10.0.1.5  198.51.100.7  aws/lab"},
		"attached volume": {
			volumeOptionLabel("lab", volumeInfo{ID: "vol-0222", Name: "site-data", Size: 400, Type: "gp3", State: "in-use", AZ: "ap-east-1a",
				Attachments: []volumeAttachment{{InstanceID: "i-0abc", Device: "/dev/sdb"}}}),
			"site-data  vol-0222  400 GB  gp3  in-use  ap-east-1a  i-0abc as /dev/sdb  aws/lab"},
		"unattached volume": {
			volumeOptionLabel("lab", volumeInfo{ID: "vol-0333", Name: "orphan", Size: 8, Type: "gp2", State: "available", AZ: "ap-east-1a"}),
			"orphan  vol-0333  8 GB  gp2  available  ap-east-1a  -  aws/lab"},
		"subnet without a count of free addresses": {
			subnetLabel(ec2types.Subnet{SubnetId: awssdk.String("subnet-0def"), AvailabilityZone: awssdk.String("ap-east-1a"),
				CidrBlock: awssdk.String("10.0.1.0/24"), VpcId: awssdk.String("vpc-0abc"), DefaultForAz: awssdk.Bool(true)}),
			"subnet-0def  subnet-0def  ap-east-1a  10.0.1.0/24  vpc-0abc  -  [default for zone]"},
		"subnet that is no default": {
			subnetLabel(ec2types.Subnet{SubnetId: awssdk.String("subnet-0def"), AvailabilityZone: awssdk.String("ap-east-1a"),
				CidrBlock: awssdk.String("10.0.1.0/24"), VpcId: awssdk.String("vpc-0abc"), AvailableIpAddressCount: awssdk.Int32(250)}),
			"subnet-0def  subnet-0def  ap-east-1a  10.0.1.0/24  vpc-0abc  250 free IPs"},
		"vpc": {
			vpcLabel(ec2types.Vpc{VpcId: awssdk.String("vpc-0abc"), CidrBlock: awssdk.String("10.0.0.0/16")}),
			"vpc-0abc  vpc-0abc  10.0.0.0/16"},
		"snapshot without a start time": {
			snapshotOptionLabel(ec2types.Snapshot{SnapshotId: awssdk.String("snap-0aaa"), VolumeSize: awssdk.Int32(400), Description: awssdk.String("before  upgrade")}),
			"snap-0aaa  snap-0aaa  400 GB  -  before upgrade"},
		"load balancer without a VPC": {
			lbOptionLabel("lab", loadBalancer{Name: "site-lb", Type: "network", Scheme: "internal", State: "active", DNSName: "site-lb.elb.amazonaws.com", Region: "ap-east-1"}),
			"site-lb  network  internal  active  -  site-lb.elb.amazonaws.com  aws/lab/ap-east-1"},
		"target group without a target type": {
			tgOptionLabel(platform.LBTargetGroup{Name: "web-80", Protocol: "TCP", Port: 80, VPC: "vpc-0abc"}),
			"web-80  TCP:80  -  vpc-0abc"},
		"security group without a VPC": {
			sgOptionLabel(platform.SecurityGroup{ID: "sg-0abc", Name: "web", Description: "test group"}),
			"web  sg-0abc  -  0 rules  test group"},
		"database without a zone": {
			dbOptionLabel("lab", dbInstance{ID: "db-b", Engine: "mysql", EngineVersion: "8.0.36", Class: "db.t3.micro", Status: "creating", Region: "ap-east-1"}),
			"db-b  mysql 8.0.36  db.t3.micro  creating  -  aws/lab/ap-east-1"},
		"certificate of one name that is in use": {
			certOptionLabel(platform.Certificate{ID: "arn:1", Domain: "example.com", Names: []string{"example.com"}, Status: "ISSUED", NotAfter: &exp, InUse: true}),
			"example.com  -  ISSUED  expires 2027-03-01  in use  arn:1"},
		"pending certificate of an account": {
			certOptionLabel(platform.Certificate{ID: "arn:2", Domain: "example.org", Names: []string{"example.org", "a.example.org", "b.example.org"}, Status: "PENDING_VALIDATION"}, "aws/lab/ap-east-1"),
			"example.org  +2 names  PENDING_VALIDATION  -  -  arn:2  aws/lab/ap-east-1"},
		"Identity Center account": {
			ssoAccount{ID: "123456789012", Name: "Production", Email: "ops@example.com"}.cells(),
			"Production  123456789012  ops@example.com"},
		"Identity Center account without a name": {
			ssoAccount{ID: "123456789012", Email: "ops@example.com"}.cells(),
			"123456789012  123456789012  ops@example.com"},
	} {
		if c.got != c.want {
			t.Errorf("%s:\n got %q\nwant %q", name, c.got, c.want)
		}
	}
}

// shown is what an 80-column terminal shows of a label of a select list: a
// label is cut at its end, after 75 columns.
func shown(label string) string {
	if r := []rune(label); len(r) > 75 {
		return string(r[:75])
	}
	return label
}

// The routed record sets of one name and type differ in their set identifier
// only: it has to be in the part of the label a terminal shows, however long
// the values are.
func TestRecordSetLabelShowsTheSetIdentifier(t *testing.T) {
	dkim := []string{`"v=DKIM1; k=rsa; p=MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1234567890abcdefghijklmnopqrstuvwxyz"`}
	us := recordSetLabel("mail.example.com.", "TXT", "us", dkim, 300)
	eu := recordSetLabel("mail.example.com.", "TXT", "eu", dkim, 300)
	if shown(us) == shown(eu) {
		t.Errorf("two sets are shown as the same row: %q", shown(us))
	}
	if got, want := recordSetLabel("www.example.com.", "A", "", []string{"198.51.100.2", "198.51.100.3"}, 60), "www.example.com.  A  -  198.51.100.2, 198.51.100.3  ttl 60"; got != want {
		t.Errorf("set without an identifier:\n got %q\nwant %q", got, want)
	}
}

// An ACM ARN takes 83 columns. What a terminal shows of a certificate row
// must still say whether the certificate is in use, and in the list of the
// certificates to re-import into, which are of one domain, which one it is.
func TestCertificateLabelsShowWhatTellsThemApart(t *testing.T) {
	exp := time.Date(2027, 3, 1, 0, 0, 0, 0, time.UTC)
	cert := func(id string, inUse bool) platform.Certificate {
		return platform.Certificate{ID: "arn:aws:acm:ap-east-1:123456789012:certificate/" + id, Domain: "example.com",
			Names: []string{"example.com", "a.example.com", "b.example.com"}, Status: "ISSUED", NotAfter: &exp, InUse: inUse}
	}
	used, free := cert("11111111-2222-3333-4444-555555555555", true), cert("aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", false)
	for name, where := range map[string][]string{"one region": nil, "several accounts": {"aws/lab/ap-east-1"}} {
		a, b := shown(certOptionLabel(used, where...)), shown(certOptionLabel(free, where...))
		if !strings.Contains(a, "  in use") || a == b {
			t.Errorf("%s: the mark of a certificate in use is not shown:\n%q\n%q", name, a, b)
		}
	}
	if a, b := shown(reimportOptionLabel(used)), shown(reimportOptionLabel(free)); a == b {
		t.Errorf("two certificates to re-import into are shown as the same row: %q", a)
	}
	if got, want := reimportOptionLabel(used), "arn:aws:acm:ap-east-1:123456789012:certificate/11111111-2222-3333-4444-555555555555  example.com  expires "+timeStr(&exp)+"  in use"; got != want {
		t.Errorf("re-import label:\n got %q\nwant %q", got, want)
	}
}
