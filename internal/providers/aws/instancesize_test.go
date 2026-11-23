package aws

import (
	"context"
	"errors"
	"strings"
	"testing"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func mustSize(t *testing.T, v string) platform.TypeShorthand {
	t.Helper()
	s, ok, err := platform.ParseTypeShorthand(v)
	if !ok || err != nil {
		t.Fatalf("ParseTypeShorthand(%q) = %v, %v", v, ok, err)
	}
	return s
}

// sizeClient is a client over the fake EC2 API of a fresh harness.
func sizeClient(t *testing.T) (*client, *awsHarness) {
	t.Helper()
	h := newInstanceHarness(t, app.Flags{})
	h.ec2.inst.init()
	return &client{region: "ap-east-1", ec2For: func(r string) ec2API { return newEC2(awssdk.Config{Region: r}) }}, h
}

func TestPresetFor(t *testing.T) {
	for _, tc := range []struct {
		size string
		want string
	}{
		{"2H0.5G", "t3.nano"}, {"2H1G", "t3.micro"}, {"2H2G", "t3.small"}, {"2H4G", "t3.medium"},
		{"2H8G", "t3.large"}, {"4H16G", "t3.xlarge"}, {"8H32G", "t3.2xlarge"},
		{"4H8G", ""}, {"1H1G", ""}, {"2H3G", ""},
	} {
		s := mustSize(t, tc.size)
		if got := presetFor(s.Cores, s.MemoryMiB()); got != tc.want {
			t.Errorf("presetFor(%s) = %q, want %q", tc.size, got, tc.want)
		}
	}
	if got := presetSizes(); got != "2H0.5G, 2H1G, 2H2G, 2H4G, 2H8G, 4H16G, 8H32G" {
		t.Errorf("presetSizes = %s", got)
	}
}

func TestSortByPreference(t *testing.T) {
	types := []string{"z1d.large", "c5.large", "a1.large", "m7i.large", "t3a.medium", "c6a.large", "c7i.large", "t3.medium"}
	sortByPreference(types)
	if got := strings.Join(types, ","); got != "t3.medium,t3a.medium,m7i.large,c7i.large,c5.large,a1.large,c6a.large,z1d.large" {
		t.Errorf("order = %s", got)
	}
}

func TestResolveTypeSizePreset(t *testing.T) {
	c, h := sizeClient(t)
	ch, err := c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "2h4g"))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != "t3.medium" || !ch.Preset || ch.Location != "ap-east-1a" {
		t.Errorf("choice = %+v", ch)
	}
	if got := ch.note(); got != "2h4g -> t3.medium (ap-east-1a, T3 preset)" {
		t.Errorf("note = %s", got)
	}
	// The preset was enough: one offering call, no type listing.
	if h.ec2.count("DescribeInstanceTypes") != 0 || h.ec2.count("DescribeInstanceTypeOfferings") != 1 {
		t.Errorf("calls = %v", h.ec2.calls())
	}
	call := h.ec2.inst.offeringCalls[0]
	if call.LocationType != ec2types.LocationTypeAvailabilityZone || awssdk.ToString(call.Filters[0].Name) != "location" || call.Filters[0].Values[0] != "ap-east-1a" {
		t.Errorf("offering call = %+v", call)
	}
}

func TestResolveTypeSizeFamilyPreference(t *testing.T) {
	c, h := sizeClient(t)
	// t3.medium is not offered in ap-east-1a: the next family that has
	// that size wins (t3a), then m7i/c7i/c5, the arm64 a1 never.
	h.ec2.inst.offerings["t3.medium"] = []string{"ap-east-1b"}
	ch, err := c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "2H4G"))
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != "t3a.medium" || ch.Preset || !strings.Contains(ch.note(), "family preference") {
		t.Errorf("choice = %+v", ch)
	}
	h.ec2.inst.offerings["t3a.medium"] = nil
	h.ec2.inst.offerings["c7i.large"] = nil
	if ch, err = c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "2H4G")); err != nil || ch.Type != "c5.large" {
		t.Errorf("without t3a and c7i = %+v, %v", ch, err)
	}

	// No preset at all: 2H8G has t3.large; 4H8G only c6a.xlarge.
	if ch, err = c.resolveTypeSize(context.Background(), "ap-east-1", "", mustSize(t, "4H8G")); err != nil || ch.Type != "c6a.xlarge" || ch.Location != "ap-east-1" {
		t.Errorf("4H8G = %+v, %v", ch, err)
	}
	// Previous-generation types (m4.large) are skipped.
	h.ec2.inst.offerings["t3.large"] = nil
	h.ec2.inst.offerings["m7i.large"] = nil
	if _, err = c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "2H8G")); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("2H8G without current types = %v", err)
	}
}

func TestResolveTypeSizeRegionOffering(t *testing.T) {
	c, h := sizeClient(t)
	ch, err := c.resolveTypeSize(context.Background(), "ap-east-1", "", mustSize(t, "2H2G"))
	if err != nil || ch.Type != "t3.small" || ch.Location != "ap-east-1" {
		t.Fatalf("choice = %+v, %v", ch, err)
	}
	call := h.ec2.inst.offeringCalls[0]
	if call.LocationType != ec2types.LocationTypeRegion || call.Filters[0].Values[0] != "ap-east-1" {
		t.Errorf("offering call = %+v", call)
	}
}

func TestResolveTypeSizeNotFound(t *testing.T) {
	c, h := sizeClient(t)
	// No type of that size at all.
	_, err := c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "3H5G"))
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "3H5G") || !strings.Contains(err.Error(), "--type") || !strings.Contains(err.Error(), "2H4G") {
		t.Errorf("no type = %v", err)
	}
	// Types of that size, none offered in the zone: they are named.
	for _, typ := range []string{"t3.medium", "t3a.medium", "c6a.large", "c7i.large", "c5.large"} {
		h.ec2.inst.offerings[typ] = []string{"ap-east-1b"}
	}
	_, err = c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "2H4G"))
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "ap-east-1a") || !strings.Contains(err.Error(), "t3.medium, t3a.medium") {
		t.Errorf("not offered = %v", err)
	}
	// An API failure is not "not found".
	h.ec2.inst.errs["DescribeInstanceTypes"] = &fakeAPIError{"InternalError", "boom"}
	if _, err = c.resolveTypeSize(context.Background(), "ap-east-1", "ap-east-1a", mustSize(t, "2H4G")); err == nil || errors.Is(err, platform.ErrNotFound) {
		t.Errorf("api failure = %v", err)
	}
}

func TestTypesOfSizePagesAndOfferingBatches(t *testing.T) {
	c, h := sizeClient(t)
	h.ec2.inst.typePage = 2
	types, err := c.typesOfSize(context.Background(), "ap-east-1", mustSize(t, "2H4G"))
	if err != nil {
		t.Fatal(err)
	}
	// Every x86_64 current-generation type of 2 vCPUs and 4096 MiB, from
	// all pages; a1.large (arm64) is not one.
	if got := strings.Join(types, ","); got != "c5.large,c6a.large,c7i.large,t3.medium,t3a.medium" {
		t.Errorf("types = %s", got)
	}
	if n := h.ec2.count("DescribeInstanceTypes"); n != 3 {
		t.Errorf("pages = %d", n)
	}

	// More types than one offering call takes: several batches.
	var many []string
	for i := 0; i < offeringBatch*2+3; i++ {
		many = append(many, "x"+strings.Repeat("y", i%3)+".t"+string(rune('a'+i%26)))
	}
	many = append(many, "t3.medium")
	h.ec2.inst.offeringCalls = nil
	offered, err := c.offeredIn(context.Background(), "ap-east-1", "ap-east-1a", many)
	if err != nil {
		t.Fatal(err)
	}
	if len(h.ec2.inst.offeringCalls) != 3 || !offered["t3.medium"] || len(offered) != 1 {
		t.Errorf("batches = %d, offered %v", len(h.ec2.inst.offeringCalls), offered)
	}
	for _, call := range h.ec2.inst.offeringCalls {
		if n := len(call.Filters[1].Values); n > offeringBatch {
			t.Errorf("batch of %d types", n)
		}
	}
}

func TestTypeShape(t *testing.T) {
	c, _ := sizeClient(t)
	cores, mem, err := c.typeShape(context.Background(), "ap-east-1", "c6a.large")
	if err != nil || cores != 2 || mem != 4096 {
		t.Errorf("c6a.large = %d %d %v", cores, mem, err)
	}
	if _, _, err := c.typeShape(context.Background(), "ap-east-1", "t9.bogus"); !errors.Is(err, platform.ErrInvalidInput) {
		t.Errorf("unknown = %v", err)
	}
}
