package aws

import (
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"
	r53dtypes "github.com/aws/aws-sdk-go-v2/service/route53domains/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// dnsPickHarness is an AWS harness in the interactive flow whose Route 53
// and Route 53 Domains clients are the fakes it returns.
func dnsPickHarness(t *testing.T) (*awsHarness, *fakeRoute53, *fakeDomains) {
	t.Helper()
	r53, r53d := newFakeRoute53(), &fakeDomains{pageSize: 10}
	oldR, oldD := newRoute53, newRoute53Domains
	newRoute53 = func(awssdk.Config) route53API { return r53 }
	newRoute53Domains = func(awssdk.Config) route53domainsAPI { return r53d }
	t.Cleanup(func() { newRoute53, newRoute53Domains = oldR, oldD })
	h := newAWSHarness(t, app.Flags{NonInteractiveSet: true}, nil)
	h.rt.Picker = prompttest.New(t)
	return h, r53, r53d
}

func hostedZone(id, name string, private bool) r53types.HostedZone {
	return r53types.HostedZone{Id: awssdk.String("/hostedzone/" + id), Name: awssdk.String(name + "."), Config: &r53types.HostedZoneConfig{PrivateZone: private}}
}

// zone get without <zone> offers the hosted zones of the profile; a name
// held by a public and a private zone is a pick.
func TestRoute53ZonePicks(t *testing.T) {
	h, r53, _ := dnsPickHarness(t)
	r53.zones = []r53types.HostedZone{hostedZone("Z1", "example.com", false), hostedZone("Z2", "example.com", true), hostedZone("Z3", "other.org", false)}

	p := prompttest.New(t, "other.org")
	h.rt.Picker = p
	if err := h.run("route53", "zone", "get"); err != nil || !strings.Contains(h.stdout.String(), "Z3") {
		t.Fatalf("get = %v, %s", err, h.stdout.String())
	}

	p = prompttest.New(t, prompttest.Label("Z2"))
	h.rt.Picker = p
	if err := h.run("route53", "zone", "get", "example.com"); err != nil || !strings.Contains(h.stdout.String(), "Z2") {
		t.Errorf("ambiguous get = %v, %s", err, h.stdout.String())
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "example.com  Z2  private") {
		t.Errorf("labels: %s", l)
	}

	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	var amb *app.AmbiguousError
	if err := h.run("route53", "zone", "get", "example.com"); !errors.As(err, &amb) {
		t.Errorf("non-interactive ambiguous = %v", err)
	}
}

// record upsert without --type and --value asks for both (the current
// value proposed); record delete without --type offers the record sets of
// the zone, the apex NS and SOA left out.
func TestRoute53RecordAsks(t *testing.T) {
	h, r53, _ := dnsPickHarness(t)
	r53.zones = []r53types.HostedZone{hostedZone("Z3", "other.org", false)}
	r53.sets["Z3"] = []r53types.ResourceRecordSet{
		valueSet("other.org.", "NS", 172800, "ns-1.awsdns-00.org."), valueSet("other.org.", "SOA", 900, "ns-1.awsdns-00.org. hostmaster. 1 7200 900 1209600 86400"),
		valueSet("www.other.org.", "A", 300, "198.51.100.7"),
	}

	p := prompttest.New(t, "A", prompttest.KeepDefault{}, "")
	h.rt.Picker = p
	if err := h.run("route53", "record", "upsert", "other.org", "--name", "www"); err != nil {
		t.Fatalf("upsert: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if d := p.Asked[1].Default; d != "198.51.100.7" {
		t.Errorf("value proposed %q", d)
	}

	p = prompttest.New(t, prompttest.Label("www.other.org  A"))
	h.rt.Picker = p
	h.rt.Stdin = strings.NewReader("y\n") // the confirmation
	if err := h.run("route53", "record", "delete", "other.org"); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if v := prompttest.Labels(p.Asked[0].Options); strings.Contains(v, "SOA") || strings.Contains(v, "NS") {
		t.Errorf("sets offered: %s", v)
	}
	if got := r53.values("Z3", "www.other.org.", "A"); len(got) != 0 {
		t.Errorf("set left: %v", got)
	}

	// Nothing left to delete: nothing to do.
	h.rt.Picker = prompttest.New(t)
	if err := h.run("route53", "record", "delete", "other.org"); !errors.Is(err, platform.ErrNothingToDo) {
		t.Errorf("empty = %v", err)
	}
	h.rt.Picker = nil
	h.rt.Flags.NonInteractive = true
	if err := h.run("route53", "record", "delete", "other.org"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("non-interactive = %v", err)
	}
}

// route53domains ns set without arguments asks for the domain, then the
// nameservers.
func TestRoute53DomainsNSSetAsks(t *testing.T) {
	h, _, r53d := dnsPickHarness(t)
	r53d.summaries = []r53dtypes.DomainSummary{{DomainName: awssdk.String("example.com")}}
	p := prompttest.New(t, "example.com", prompttest.Label("Enter nameservers"), "ns1.example.net, ns2.example.net")
	h.rt.Picker = p
	if err := h.run("route53domains", "ns", "set"); err != nil {
		t.Fatalf("ns set: %v\n%s", err, h.stderr.String())
	}
	p.Done()
	if got := strings.Join(r53d.updated["example.com"], ","); got != "ns1.example.net,ns2.example.net" {
		t.Errorf("nameservers = %s", got)
	}
}
