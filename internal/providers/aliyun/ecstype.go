package aliyun

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/platform"
)

// The settings of the stock and price queries behind an instance size
// written as <cores>H<memory>G: the same pay-as-you-go, I/O optimized
// instances polyctl creates.
const (
	stockWithStock     = "WithStock"
	destInstanceType   = "InstanceType"
	destSystemDisk     = "SystemDisk"
	ioOptimized        = "optimized"
	resourceInstance   = "instance"
	cpuArchX86         = "X86"
	priceUnitHour      = "Hour"
	instanceTypesBatch = 10
	// typeQueryWorkers bounds the system disk and price queries that run at
	// the same time.
	typeQueryWorkers = 4
)

// systemDiskPreference is the order in which a system disk category is
// chosen for a resolved type when the one asked for (--disk-category,
// default cloud_essd_entry) is not offered with it.
var systemDiskPreference = []string{"cloud_essd_entry", "cloud_essd", "cloud_auto", "cloud_efficiency", "cloud_ssd"}

// typeZone is an instance type in stock in a zone.
type typeZone struct {
	Type, Zone string
}

// stockQuery asks DescribeAvailableResource for the types in stock: by
// size (Cores and Memory, matched exactly) or by an exact InstanceType;
// Zone limits the answer to one zone.
type stockQuery struct {
	Cores        int
	Memory       float64
	InstanceType string
	Zone         string
}

// withStock walks an AvailableZones answer and keeps the values that are
// in stock: both the zone and the value must say WithStock.
func withStock(zones []ecs.AvailableZone) []typeZone {
	var out []typeZone
	for _, z := range zones {
		if z.StatusCategory != stockWithStock {
			continue
		}
		for _, r := range z.AvailableResources.AvailableResource {
			for _, v := range r.SupportedResources.SupportedResource {
				if v.StatusCategory == stockWithStock && v.Value != "" {
					out = append(out, typeZone{Type: v.Value, Zone: z.ZoneId})
				}
			}
		}
	}
	return out
}

// stockedTypes returns the instance types in stock for pay-as-you-go
// instances, with their zones.
func (c *client) stockedTypes(ctx context.Context, region string, q stockQuery) ([]typeZone, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	req := ecs.CreateDescribeAvailableResourceRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.DestinationResource = destInstanceType
	req.InstanceChargeType = instanceChargeType
	req.IoOptimized = ioOptimized
	req.ResourceType = resourceInstance
	if q.InstanceType != "" {
		req.InstanceType = q.InstanceType
	} else {
		req.Cores = requests.NewInteger(q.Cores)
		req.Memory = requests.NewFloat(q.Memory)
	}
	req.ZoneId = q.Zone
	resp, err := cl.DescribeAvailableResource(req)
	if err != nil {
		return nil, wrapErr("ecs DescribeAvailableResource "+region, err)
	}
	return withStock(resp.AvailableZones.AvailableZone), nil
}

// modifiableTypes returns the instance types of the size an instance can
// change to (DescribeResourcesModification), in stock, with their zones.
func (c *client) modifiableTypes(ctx context.Context, region, id string, cores int, memory float64) ([]typeZone, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	req := ecs.CreateDescribeResourcesModificationRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.ResourceId = id
	req.DestinationResource = destInstanceType
	req.Cores = requests.NewInteger(cores)
	req.Memory = requests.NewFloat(memory)
	resp, err := cl.DescribeResourcesModification(req)
	if err != nil {
		return nil, wrapErr("ecs DescribeResourcesModification "+id, err)
	}
	return withStock(resp.AvailableZones.AvailableZone), nil
}

// x86Types returns which of types are x86 types (DescribeInstanceTypes
// with CpuArchitecture X86, at most 10 types a call).
func (c *client) x86Types(ctx context.Context, region string, types []string) (map[string]bool, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	out := map[string]bool{}
	for batch := range slices.Chunk(types, instanceTypesBatch) {
		next := ""
		for {
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			req := ecs.CreateDescribeInstanceTypesRequest()
			c.route(req, endpointECS)
			req.RegionId = region
			req.CpuArchitecture = cpuArchX86
			names := slices.Clone(batch)
			req.InstanceTypes = &names
			req.NextToken = next
			resp, err := cl.DescribeInstanceTypes(req)
			if err != nil {
				return nil, wrapErr("ecs DescribeInstanceTypes "+region, err)
			}
			for _, t := range resp.InstanceTypes.InstanceType {
				if t.CpuArchitecture == "" || t.CpuArchitecture == cpuArchX86 {
					out[t.InstanceTypeId] = true
				}
			}
			if resp.NextToken == "" || resp.NextToken == next {
				break
			}
			next = resp.NextToken
		}
	}
	return out, nil
}

// systemDiskCategories returns the system disk categories in stock for a
// type in a zone.
func (c *client) systemDiskCategories(ctx context.Context, region, typ, zone string) ([]string, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	req := ecs.CreateDescribeAvailableResourceRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.DestinationResource = destSystemDisk
	req.InstanceChargeType = instanceChargeType
	req.IoOptimized = ioOptimized
	req.ResourceType = resourceInstance
	req.InstanceType = typ
	req.ZoneId = zone
	resp, err := cl.DescribeAvailableResource(req)
	if err != nil {
		return nil, wrapErr("ecs DescribeAvailableResource "+typ+" "+zone, err)
	}
	var out []string
	for _, v := range withStock(resp.AvailableZones.AvailableZone) {
		if v.Zone == zone && !slices.Contains(out, v.Type) {
			out = append(out, v.Type)
		}
	}
	return out, nil
}

// priceSpec is the instance DescribePrice prices.
type priceSpec struct {
	Type, Zone, Image string
	DiskCategory      string
	DiskGiB           int
}

// instancePrice returns the hourly pay-as-you-go price of an instance as
// polyctl creates it (pay by traffic, no bandwidth of its own) and its
// currency.
func (c *client) instancePrice(ctx context.Context, region string, p priceSpec) (float64, string, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return 0, "", err
	}
	req := ecs.CreateDescribePriceRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.ResourceType = resourceInstance
	req.PriceUnit = priceUnitHour
	req.InstanceType = p.Type
	req.ZoneId = p.Zone
	req.ImageId = p.Image
	req.SystemDiskCategory = p.DiskCategory
	if p.DiskGiB > 0 {
		req.SystemDiskSize = requests.NewInteger(p.DiskGiB)
	}
	req.IoOptimized = ioOptimized
	req.InternetChargeType = instanceInternetCharge
	req.InternetMaxBandwidthOut = requests.NewInteger(instanceBandwidthOut)
	resp, err := cl.DescribePrice(req)
	if err != nil {
		return 0, "", wrapErr("ecs DescribePrice "+p.Type+" "+p.Zone, err)
	}
	return resp.PriceInfo.Price.TradePrice, resp.PriceInfo.Price.Currency, nil
}

// priceSkipped reports a price query refused because the type cannot be
// had there (no stock, not offered, a disk it does not take): that
// candidate is left out, and any other error stops the resolution.
func priceSkipped(err error) bool {
	if errors.Is(err, platform.ErrNotFound) {
		return true
	}
	code := platform.ErrorCode(err)
	for _, s := range []string{"NoStock", "OutOfStock", "NotSupport", "Unsupported", "Unavailable", "InvalidInstanceType", "InvalidSystemDiskCategory", "InvalidDiskCategory", "InvalidZoneId"} {
		if strings.Contains(code, s) {
			return true
		}
	}
	return false
}

// typeChoice is the instance type a <cores>H<memory>G size resolved to.
type typeChoice struct {
	Size         platform.TypeShorthand
	Type, Zone   string
	DiskCategory string
	Price        float64
	Currency     string
}

// price writes the hourly price ("0.0123 CNY/hour").
func (t typeChoice) price() string {
	p := strconv.FormatFloat(t.Price, 'f', -1, 64)
	if t.Currency != "" {
		p += " " + t.Currency
	}
	return p + "/hour"
}

// note is the line printed on stderr: "2H4G -> ecs.e-c1m2.large
// (cn-hongkong-b, 0.0123 CNY/hour)".
func (t typeChoice) note() string {
	return fmt.Sprintf("%s -> %s (%s, %s)", t.Size, t.Type, t.Zone, t.price())
}

// label is what the change report adds to the type: "(2H4G, 0.0123
// CNY/hour)".
func (t typeChoice) label() string {
	return fmt.Sprintf("(%s, %s)", t.Size, t.price())
}

// typeRequest is what a size is resolved for.
type typeRequest struct {
	Size platform.TypeShorthand
	// Zones are the zones the instance may be placed in (nil: any zone of
	// the region).
	Zones []string
	// Image and DiskGiB are the image and system disk size it is priced
	// with.
	Image   string
	DiskGiB int
	// DiskCategory is the system disk category asked for. DiskFixed takes
	// only types that offer it; otherwise it is preferred, and
	// systemDiskPreference decides when it is not offered.
	DiskCategory string
	DiskFixed    bool
	// Resize names the instance whose type changes: the candidates are the
	// types it can change to (DescribeResourcesModification) in Zones,
	// priced with its own disk (DiskCategory, no disk query); Current is
	// its type, left out.
	Resize  string
	Current string
}

// resolveTypeSize resolves an instance size to the x86 type in stock, in
// one of the zones allowed, with the lowest hourly price. Ties go to the
// type name, then the zone. It reads only, and is never cached: stock and
// prices change.
func (c *client) resolveTypeSize(ctx context.Context, region string, r typeRequest) (*typeChoice, error) {
	region = c.regionOr(region)
	var found []typeZone
	var err error
	if r.Resize != "" {
		found, err = c.modifiableTypes(ctx, region, r.Resize, r.Size.Cores, r.Size.MemoryGiB)
	} else {
		q := stockQuery{Cores: r.Size.Cores, Memory: r.Size.MemoryGiB}
		if len(r.Zones) == 1 {
			q.Zone = r.Zones[0]
		}
		found, err = c.stockedTypes(ctx, region, q)
	}
	if err != nil {
		return nil, err
	}
	var cands []typeZone
	var elsewhere []string
	for _, tz := range found {
		switch {
		case tz.Type == r.Current:
		case len(r.Zones) > 0 && !slices.Contains(r.Zones, tz.Zone):
			if !slices.Contains(elsewhere, tz.Zone) {
				elsewhere = append(elsewhere, tz.Zone)
			}
		case !slices.Contains(cands, tz):
			cands = append(cands, tz)
		}
	}
	if len(cands) > 0 {
		var types []string
		for _, tz := range cands {
			if !slices.Contains(types, tz.Type) {
				types = append(types, tz.Type)
			}
		}
		sort.Strings(types)
		x86, err := c.x86Types(ctx, region, types)
		if err != nil {
			return nil, err
		}
		cands = slices.DeleteFunc(cands, func(tz typeZone) bool { return !x86[tz.Type] })
	}
	sort.Slice(cands, func(i, j int) bool {
		if cands[i].Type != cands[j].Type {
			return cands[i].Type < cands[j].Type
		}
		return cands[i].Zone < cands[j].Zone
	})
	priced, err := c.priceCandidates(ctx, region, r, cands)
	if err != nil {
		return nil, err
	}
	var best *typeChoice
	for i := range priced {
		if p := &priced[i]; p.Type != "" && (best == nil || p.Price < best.Price) {
			best = p
		}
	}
	if best == nil {
		sort.Strings(elsewhere)
		return nil, noTypeError(region, r, len(cands) > 0, elsewhere)
	}
	return best, nil
}

// priceCandidates picks the system disk of every candidate and prices it,
// typeQueryWorkers at a time. A candidate without a usable disk, or whose
// price is refused as not available, comes back with an empty Type.
func (c *client) priceCandidates(ctx context.Context, region string, r typeRequest, cands []typeZone) ([]typeChoice, error) {
	out := make([]typeChoice, len(cands))
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	// The first error stops the others: the context errors of the queries
	// it cancels come later and are not the cause.
	var mu sync.Mutex
	var firstErr error
	fail := func(err error) {
		mu.Lock()
		if firstErr == nil {
			firstErr = err
		}
		mu.Unlock()
		cancel()
	}
	sem := make(chan struct{}, typeQueryWorkers)
	var wg sync.WaitGroup
	for i, tz := range cands {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if ctx.Err() != nil {
				return
			}
			category := r.DiskCategory
			if r.Resize == "" {
				offered, err := c.systemDiskCategories(ctx, region, tz.Type, tz.Zone)
				if err != nil {
					fail(err)
					return
				}
				if category = pickSystemDisk(offered, r.DiskCategory, r.DiskFixed); category == "" {
					return
				}
			}
			price, currency, err := c.instancePrice(ctx, region, priceSpec{Type: tz.Type, Zone: tz.Zone, Image: r.Image, DiskCategory: category, DiskGiB: r.DiskGiB})
			if err != nil {
				if !priceSkipped(err) {
					fail(err)
				}
				return
			}
			out[i] = typeChoice{Size: r.Size, Type: tz.Type, Zone: tz.Zone, DiskCategory: category, Price: price, Currency: currency}
		}()
	}
	wg.Wait()
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// pickSystemDisk returns the system disk category for a type that offers
// offered: want when offered; with fixed, nothing else; otherwise the first
// of systemDiskPreference offered, else the first offered.
func pickSystemDisk(offered []string, want string, fixed bool) string {
	if slices.Contains(offered, want) {
		return want
	}
	if fixed || len(offered) == 0 {
		return ""
	}
	for _, p := range systemDiskPreference {
		if slices.Contains(offered, p) {
			return p
		}
	}
	return offered[0]
}

// noTypeError is the "not found" (exit code 4) of a size nothing matched.
func noTypeError(region string, r typeRequest, priced bool, elsewhere []string) error {
	where := region
	if len(r.Zones) > 0 {
		where = "zone " + strings.Join(r.Zones, ", ") + " of " + region
		if len(r.Zones) > 1 {
			where = "zones " + strings.Join(r.Zones, ", ") + " of " + region
		}
	}
	what := "in stock"
	if r.Resize != "" {
		what = "that instance " + r.Resize + " can change to"
	}
	if priced {
		what += " with a price"
		if r.DiskFixed {
			what += " and system disk " + r.DiskCategory
		}
	}
	hint := "the size must match a type exactly (some types have 3.5 or 7.5 GiB); try another size, or pass an exact type id with --type"
	if len(elsewhere) > 0 && r.Resize == "" {
		hint = "in stock in " + strings.Join(elsewhere, ", ") + ": pass --vswitch in one of those zones; or " + hint
	}
	return fmt.Errorf("%w: no x86 instance type of %s (%d vCPUs, %s GiB) %s in %s (%s)", platform.ErrNotFound, r.Size, r.Size.Cores, r.Size.Memory(), what, where, hint)
}
