package aliyun

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

// fakeType is an instance type of the fake catalog.
type fakeType struct {
	Cores  int
	Memory float64
	Arch   string
}

// fakeCatalog answers the stock, type, disk and price queries a
// <cores>H<memory>G size is resolved with, as documented and as verified
// on real accounts (DescribeAvailableResource answers zones and values
// with Status and StatusCategory, WithStock when in stock).
type fakeCatalog struct {
	types map[string]fakeType
	// stock lists the types each zone offers; soldOut[type/zone] answers
	// that value without stock, and closedZones answer the whole zone
	// without stock.
	stock       map[string][]string
	soldOut     map[string]bool
	closedZones map[string]bool
	// disks are the system disk categories of a type (every zone; default
	// cloud_essd_entry and cloud_essd).
	disks map[string][]string
	// prices are the hourly prices of type/zone; priceErr[type/zone] is the
	// error code DescribePrice answers instead.
	prices   map[string]float64
	priceErr map[string]string
	// typeBatches are the InstanceTypes of every DescribeInstanceTypes.
	typeBatches [][]string
	// goneImage is an image DescribePrice answers InvalidImageId.NotFound
	// for (a price without an image is then accepted).
	goneImage string
	// priceHook, when set, runs first for every DescribePrice and may
	// answer it.
	priceHook func(q url.Values) (int, any, bool)
}

func newFakeCatalog() *fakeCatalog {
	return &fakeCatalog{types: map[string]fakeType{}, stock: map[string][]string{}, soldOut: map[string]bool{}, closedZones: map[string]bool{},
		disks: map[string][]string{}, prices: map[string]float64{}, priceErr: map[string]string{}}
}

// add puts a type in stock in zones at the price of each zone.
func (c *fakeCatalog) add(typ string, cores int, mem float64, arch string, prices map[string]float64) {
	c.types[typ] = fakeType{Cores: cores, Memory: mem, Arch: arch}
	for z, p := range prices {
		if !slices.Contains(c.stock[z], typ) {
			c.stock[z] = append(c.stock[z], typ)
		}
		c.prices[typ+"/"+z] = p
	}
}

func (c *fakeCatalog) register(api *fakeAPI) {
	api.on("DescribeAvailableResource", c.describeAvailableResource)
	api.on("DescribeResourcesModification", c.describeResourcesModification)
	api.on("DescribeInstanceTypes", c.describeInstanceTypes)
	api.on("DescribePrice", c.describePrice)
}

func (c *fakeCatalog) zonesAnswer(zone string, values func(z string) []map[string]any, typ string) map[string]any {
	var zones []string
	for z := range c.stock {
		if zone == "" || z == zone {
			zones = append(zones, z)
		}
	}
	slices.Sort(zones)
	var out []map[string]any
	for _, z := range zones {
		vals := values(z)
		if len(vals) == 0 {
			continue
		}
		st := map[string]string{"Status": "Available", "StatusCategory": stockWithStock}
		if c.closedZones[z] {
			st = map[string]string{"Status": "SoldOut", "StatusCategory": "WithoutStock"}
		}
		out = append(out, map[string]any{"RegionId": "cn-shanghai", "ZoneId": z, "Status": st["Status"], "StatusCategory": st["StatusCategory"],
			"AvailableResources": map[string]any{"AvailableResource": []map[string]any{{"Type": typ,
				"SupportedResources": map[string]any{"SupportedResource": vals}}}}})
	}
	return map[string]any{"RequestId": "r", "AvailableZones": map[string]any{"AvailableZone": out}}
}

// sizeMatch reads Cores and Memory (an exact match) or InstanceType.
func (c *fakeCatalog) sizeMatch(q url.Values) (func(typ string) bool, error) {
	if it := q.Get("InstanceType"); it != "" {
		return func(typ string) bool { return typ == it }, nil
	}
	cores, err := strconv.Atoi(q.Get("Cores"))
	if err != nil {
		return nil, err
	}
	mem, err := strconv.ParseFloat(q.Get("Memory"), 64)
	if err != nil {
		return nil, err
	}
	return func(typ string) bool { t := c.types[typ]; return t.Cores == cores && t.Memory == mem }, nil
}

func (c *fakeCatalog) typeValues(match func(string) bool) func(z string) []map[string]any {
	return func(z string) []map[string]any {
		var vals []map[string]any
		for _, typ := range c.stock[z] {
			if !match(typ) {
				continue
			}
			v := map[string]any{"Value": typ, "Status": "Available", "StatusCategory": stockWithStock}
			if c.soldOut[typ+"/"+z] {
				v["Status"], v["StatusCategory"] = "SoldOut", "WithoutStock"
			}
			vals = append(vals, v)
		}
		return vals
	}
}

func (c *fakeCatalog) describeAvailableResource(q url.Values) (int, any) {
	if q.Get("InstanceChargeType") != "PostPaid" || q.Get("IoOptimized") != "optimized" || q.Get("ResourceType") != "instance" {
		return 400, apiErr("InvalidParameter", "unexpected settings")
	}
	switch q.Get("DestinationResource") {
	case "InstanceType":
		match, err := c.sizeMatch(q)
		if err != nil {
			return 400, apiErr("InvalidParameter", err.Error())
		}
		return 200, c.zonesAnswer(q.Get("ZoneId"), c.typeValues(match), "InstanceType")
	case "SystemDisk":
		typ := q.Get("InstanceType")
		disks, ok := c.disks[typ]
		if !ok {
			disks = []string{"cloud_essd_entry", "cloud_essd"}
		}
		return 200, c.zonesAnswer(q.Get("ZoneId"), func(z string) []map[string]any {
			if !slices.Contains(c.stock[z], typ) {
				return nil
			}
			var vals []map[string]any
			for _, d := range disks {
				vals = append(vals, map[string]any{"Value": d, "Status": "Available", "StatusCategory": stockWithStock, "Min": 20, "Max": 2048, "Unit": "GiB"})
			}
			return vals
		}, "SystemDisk")
	}
	return 400, apiErr("InvalidParameter", "DestinationResource")
}

func (c *fakeCatalog) describeResourcesModification(q url.Values) (int, any) {
	if q.Get("ResourceId") == "" || q.Get("DestinationResource") != "InstanceType" {
		return 400, apiErr("InvalidParameter", "ResourceId")
	}
	match, err := c.sizeMatch(q)
	if err != nil {
		return 400, apiErr("InvalidParameter", err.Error())
	}
	return 200, c.zonesAnswer(q.Get("ZoneId"), c.typeValues(match), "InstanceType")
}

func (c *fakeCatalog) describeInstanceTypes(q url.Values) (int, any) {
	var names []string
	for i := 1; q.Get(fmt.Sprintf("InstanceTypes.%d", i)) != ""; i++ {
		names = append(names, q.Get(fmt.Sprintf("InstanceTypes.%d", i)))
	}
	if len(names) > 10 {
		return 400, apiErr("InvalidParameter.InstanceTypes", "at most 10 instance types")
	}
	c.typeBatches = append(c.typeBatches, names)
	var out []map[string]any
	for _, n := range names {
		t, ok := c.types[n]
		if !ok || (q.Get("CpuArchitecture") != "" && t.Arch != q.Get("CpuArchitecture")) {
			continue
		}
		out = append(out, map[string]any{"InstanceTypeId": n, "CpuCoreCount": t.Cores, "MemorySize": t.Memory, "CpuArchitecture": t.Arch})
	}
	return 200, map[string]any{"RequestId": "r", "NextToken": "", "InstanceTypes": map[string]any{"InstanceType": out}}
}

func (c *fakeCatalog) describePrice(q url.Values) (int, any) {
	if c.priceHook != nil {
		if code, body, ok := c.priceHook(q); ok {
			return code, body
		}
	}
	if c.goneImage != "" && q.Get("ImageId") == c.goneImage {
		return 404, apiErr("InvalidImageId.NotFound", "The specified ImageId does not exist.")
	}
	if q.Get("ResourceType") != "instance" || q.Get("PriceUnit") != "Hour" || (q.Get("ImageId") == "" && c.goneImage == "") || q.Get("SystemDisk.Category") == "" ||
		q.Get("InternetChargeType") != "PayByTraffic" || q.Get("InternetMaxBandwidthOut") != "0" {
		return 400, apiErr("InvalidParameter", "unexpected price settings")
	}
	key := q.Get("InstanceType") + "/" + q.Get("ZoneId")
	if code := c.priceErr[key]; code != "" {
		return 400, apiErr(code, "refused")
	}
	p, ok := c.prices[key]
	if !ok {
		return 400, apiErr("InvalidInstanceType.ValueNotSupported", "The specified InstanceType is not supported.")
	}
	return 200, map[string]any{"RequestId": "r", "PriceInfo": map[string]any{"Price": map[string]any{"TradePrice": p, "OriginalPrice": p, "Currency": "CNY"}}}
}

// sizeCatalog is a 2H4G market of cn-shanghai: the cheapest x86 type in
// zones b and c is ecs.e-c1m2.large in c; an ARM type and zone d are
// cheaper still, a sold-out value is cheaper too.
func sizeCatalog() *fakeCatalog {
	c := newFakeCatalog()
	c.add("ecs.u1-c1m2.large", 2, 4, "X86", map[string]float64{"cn-shanghai-b": 0.3, "cn-shanghai-c": 0.3})
	c.add("ecs.e-c1m2.large", 2, 4, "X86", map[string]float64{"cn-shanghai-b": 0.2, "cn-shanghai-c": 0.1})
	c.add("ecs.g8y.large", 2, 4, "ARM", map[string]float64{"cn-shanghai-b": 0.01})
	c.add("ecs.c7.large", 2, 4, "X86", map[string]float64{"cn-shanghai-d": 0.05})
	c.add("ecs.c9i.large", 2, 4, "X86", map[string]float64{"cn-shanghai-b": 0.02})
	c.soldOut["ecs.c9i.large/cn-shanghai-b"] = true
	c.add("ecs.u1-c1m1.large", 2, 2, "X86", map[string]float64{"cn-shanghai-b": 0.05})
	c.add("ecs.n4.large", 2, 3.5, "X86", map[string]float64{"cn-shanghai-b": 0.04})
	return c
}

func size(t *testing.T, v string) platform.TypeShorthand {
	t.Helper()
	s, ok, err := platform.ParseTypeShorthand(v)
	if !ok || err != nil {
		t.Fatalf("%q: %v %v", v, ok, err)
	}
	return s
}

func TestResolveTypeSizeCheapestInStock(t *testing.T) {
	api := newFakeAPI(t)
	cat := sizeCatalog()
	cat.register(api)
	c := api.client()
	r := typeRequest{Size: size(t, "2H4G"), Zones: []string{"cn-shanghai-b", "cn-shanghai-c"}, Image: alinux4, DiskGiB: 40, DiskCategory: defaultSystemDiskCat}
	ch, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r)
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != "ecs.e-c1m2.large" || ch.Zone != "cn-shanghai-c" || ch.Price != 0.1 || ch.Currency != "CNY" || ch.DiskCategory != "cloud_essd_entry" {
		t.Fatalf("choice = %+v", ch)
	}
	if got := ch.note(); got != "2H4G -> ecs.e-c1m2.large (cn-shanghai-c, 0.1 CNY/hour)" {
		t.Errorf("note = %q", got)
	}
	ar := api.callsFor("DescribeAvailableResource")[0]
	if ar.Get("Cores") != "2" || ar.Get("InstanceType") != "" || ar.Get("ZoneId") != "" || ar.Get("DestinationResource") != "InstanceType" {
		t.Errorf("DescribeAvailableResource = %v", ar)
	}
	if ar.Get("Memory") != "4" {
		t.Errorf("Memory = %q", ar.Get("Memory"))
	}
	// Only the x86 candidates in stock in zones b and c are priced, with the
	// image, the disk and the bandwidth of the instance.
	var priced []string
	for _, q := range api.callsFor("DescribePrice") {
		priced = append(priced, q.Get("InstanceType")+"/"+q.Get("ZoneId"))
		if q.Get("ImageId") != alinux4 || q.Get("SystemDisk.Size") != "40" || q.Get("SystemDisk.Category") != "cloud_essd_entry" {
			t.Errorf("DescribePrice = %v", q)
		}
	}
	slices.Sort(priced)
	want := []string{"ecs.e-c1m2.large/cn-shanghai-b", "ecs.e-c1m2.large/cn-shanghai-c", "ecs.u1-c1m2.large/cn-shanghai-b", "ecs.u1-c1m2.large/cn-shanghai-c"}
	if !slices.Equal(priced, want) {
		t.Errorf("priced %v, want %v", priced, want)
	}
	if q := api.callsFor("DescribeInstanceTypes")[0]; q.Get("CpuArchitecture") != "X86" {
		t.Errorf("DescribeInstanceTypes = %v", q)
	}

	// Any zone: zone d is cheaper.
	r.Zones = nil
	if ch, err = c.resolveTypeSize(context.Background(), "cn-shanghai", r); err != nil || ch.Type != "ecs.c7.large" || ch.Zone != "cn-shanghai-d" {
		t.Errorf("any zone = %+v, %v", ch, err)
	}
	// One zone is asked for directly.
	r.Zones = []string{"cn-shanghai-b"}
	if ch, err = c.resolveTypeSize(context.Background(), "cn-shanghai", r); err != nil || ch.Type != "ecs.e-c1m2.large" || ch.Zone != "cn-shanghai-b" {
		t.Errorf("zone b = %+v, %v", ch, err)
	}
	calls := api.callsFor("DescribeAvailableResource")
	var stock url.Values
	for _, q := range calls {
		if q.Get("DestinationResource") == "InstanceType" {
			stock = q
		}
	}
	if stock.Get("ZoneId") != "cn-shanghai-b" {
		t.Errorf("one zone: ZoneId = %q", stock.Get("ZoneId"))
	}
}

func TestResolveTypeSizeTiesAndBatches(t *testing.T) {
	api := newFakeAPI(t)
	cat := newFakeCatalog()
	cat.register(api)
	// 12 types of the same price: two DescribeInstanceTypes calls, and the
	// tie goes to the type name, then the zone.
	for i := 12; i >= 1; i-- {
		cat.add(fmt.Sprintf("ecs.t%02d.large", i), 4, 8, "X86", map[string]float64{"cn-shanghai-c": 0.5, "cn-shanghai-b": 0.5})
	}
	ch, err := api.client().resolveTypeSize(context.Background(), "cn-shanghai", typeRequest{Size: size(t, "4h8g"), Image: alinux4, DiskGiB: 20, DiskCategory: defaultSystemDiskCat})
	if err != nil {
		t.Fatal(err)
	}
	if ch.Type != "ecs.t01.large" || ch.Zone != "cn-shanghai-b" {
		t.Errorf("choice = %+v", ch)
	}
	if len(cat.typeBatches) != 2 || len(cat.typeBatches[0]) != 10 || len(cat.typeBatches[1]) != 2 {
		t.Errorf("batches = %v", cat.typeBatches)
	}
	if n := len(api.callsFor("DescribePrice")); n != 24 {
		t.Errorf("DescribePrice calls = %d, want 24", n)
	}
}

func TestResolveTypeSizeNoMatch(t *testing.T) {
	api := newFakeAPI(t)
	cat := sizeCatalog()
	cat.register(api)
	c := api.client()
	base := typeRequest{Image: alinux4, DiskGiB: 20, DiskCategory: defaultSystemDiskCat}

	// No type of the size at all (3.5 GiB is not 4 GiB, nor 4 GiB 3.5).
	r := base
	r.Size = size(t, "2H3G")
	if _, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "2H3G (2 vCPUs, 3 GiB)") {
		t.Errorf("no size = %v", err)
	}
	// In stock only in another zone: the hint names it, but never a zone
	// that only an ARM type of the size is in stock in (zone g).
	cat.add("ecs.g8y.xlarge", 2, 4, "ARM", map[string]float64{"cn-shanghai-g": 0.01})
	r.Size, r.Zones = size(t, "2H4G"), []string{"cn-shanghai-e", "cn-shanghai-f"}
	_, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r)
	if !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "zones cn-shanghai-e, cn-shanghai-f of cn-shanghai") || !strings.Contains(err.Error(), "in stock in cn-shanghai-b, cn-shanghai-c, cn-shanghai-d:") {
		t.Errorf("other zones = %v", err)
	}
	// A zone without stock counts as none.
	cat.closedZones["cn-shanghai-c"] = true
	cat.closedZones["cn-shanghai-b"] = true
	r.Zones = []string{"cn-shanghai-b", "cn-shanghai-c"}
	if _, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("closed zones = %v", err)
	}
}

func TestResolveTypeSizePriceAndDiskRefusals(t *testing.T) {
	api := newFakeAPI(t)
	cat := sizeCatalog()
	cat.register(api)
	c := api.client()
	r := typeRequest{Size: size(t, "2H4G"), Zones: []string{"cn-shanghai-b", "cn-shanghai-c"}, Image: alinux4, DiskGiB: 20, DiskCategory: defaultSystemDiskCat}

	// A refusal that says the type cannot be had leaves it out.
	cat.priceErr["ecs.e-c1m2.large/cn-shanghai-c"] = "InvalidInstanceType.NotSupported"
	ch, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r)
	if err != nil || ch.Type != "ecs.e-c1m2.large" || ch.Zone != "cn-shanghai-b" {
		t.Fatalf("skipped = %+v, %v", ch, err)
	}
	// Any other error stops the resolution.
	cat.priceErr["ecs.e-c1m2.large/cn-shanghai-c"] = "InvalidParameter"
	if _, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r); err == nil || !strings.Contains(err.Error(), "InvalidParameter") {
		t.Fatalf("price error = %v", err)
	}
	delete(cat.priceErr, "ecs.e-c1m2.large/cn-shanghai-c")

	// A type that offers no cloud_essd_entry gets the next category...
	cat.disks["ecs.e-c1m2.large"] = []string{"cloud_efficiency", "cloud_essd"}
	if ch, err = c.resolveTypeSize(context.Background(), "cn-shanghai", r); err != nil || ch.Type != "ecs.e-c1m2.large" || ch.DiskCategory != "cloud_essd" {
		t.Fatalf("disk fallback = %+v, %v", ch, err)
	}
	// ...unless the category was asked for.
	r.DiskFixed = true
	if ch, err = c.resolveTypeSize(context.Background(), "cn-shanghai", r); err != nil || ch.Type != "ecs.u1-c1m2.large" || ch.DiskCategory != "cloud_essd_entry" {
		t.Fatalf("disk fixed = %+v, %v", ch, err)
	}
	cat.disks["ecs.u1-c1m2.large"] = []string{"cloud_efficiency"}
	if _, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r); !errors.Is(err, platform.ErrNotFound) || !strings.Contains(err.Error(), "system disk cloud_essd_entry") {
		t.Errorf("no disk = %v", err)
	}
}

func TestPickSystemDisk(t *testing.T) {
	for _, tc := range []struct {
		offered []string
		want    string
		fixed   bool
		got     string
	}{
		{[]string{"cloud_essd", "cloud_essd_entry"}, "cloud_essd_entry", false, "cloud_essd_entry"},
		{[]string{"cloud_efficiency", "cloud_essd"}, "cloud_essd_entry", false, "cloud_essd"},
		{[]string{"cloud_efficiency", "cloud_essd"}, "cloud_essd_entry", true, ""},
		{[]string{"cloud_x"}, "cloud_essd_entry", false, "cloud_x"},
		{nil, "cloud_essd_entry", false, ""},
	} {
		if got := pickSystemDisk(tc.offered, tc.want, tc.fixed); got != tc.got {
			t.Errorf("%v %s %v = %q, want %q", tc.offered, tc.want, tc.fixed, got, tc.got)
		}
	}
}

func TestResolveTypeSizeFirstErrorWins(t *testing.T) {
	api := newFakeAPI(t)
	cat := sizeCatalog()
	cat.register(api)
	// The last candidate (by type name) is refused at once; the others are
	// still waiting for their answer and are cancelled by that refusal.
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	cat.priceHook = func(q url.Values) (int, any, bool) {
		if q.Get("InstanceType") == "ecs.u1-c1m2.large" {
			return 403, apiErr("Forbidden.RAM", "denied"), true
		}
		<-release
		return 0, nil, false
	}
	c := api.client()
	r := typeRequest{Size: size(t, "2H4G"), Zones: []string{"cn-shanghai-b"}, Image: alinux4, DiskGiB: 20, DiskCategory: defaultSystemDiskCat}
	_, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r)
	if !errors.Is(err, platform.ErrForbidden) || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want the Forbidden.RAM refusal", err)
	}
}

func TestResolveTypeSizePricesWithoutAGoneImage(t *testing.T) {
	api := newFakeAPI(t)
	cat := sizeCatalog()
	cat.goneImage = "m-gone"
	cat.register(api)
	c := api.client()
	r := typeRequest{Size: size(t, "2H4G"), Zones: []string{"cn-shanghai-b", "cn-shanghai-c"}, Image: "m-gone", DiskGiB: 20, DiskCategory: defaultSystemDiskCat}
	ch, err := c.resolveTypeSize(context.Background(), "cn-shanghai", r)
	if err != nil || ch.Type != "ecs.e-c1m2.large" || ch.Zone != "cn-shanghai-c" {
		t.Fatalf("choice = %+v, %v", ch, err)
	}
	var without int
	for _, q := range api.callsFor("DescribePrice") {
		if q.Get("ImageId") == "" {
			without++
		}
	}
	if without == 0 {
		t.Error("no price query without the image")
	}
}
