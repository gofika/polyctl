package aliyun

import (
	"context"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// imagePageSize is the largest page DescribeImages accepts.
const imagePageSize = 100

// Operating systems (--os) and architectures (--arch) the newest public
// image can be picked for.
const (
	osAlibabaCloudLinux = "alibaba-cloud-linux"
	osWindows           = "windows"
	archX86             = "x86_64"
	archARM             = "arm64"
	// windowsMinDiskGiB is the smallest system disk of the public Windows
	// Server images (their image size).
	windowsMinDiskGiB = 40
)

// osImageRule says how the public images of an operating system are found:
// the OSType of the DescribeImages query, and per architecture the pattern
// of the image family of its plain images, whose first group is the OS
// version. Nothing else (no family name, no image id) is written down, so
// a new version is picked as soon as Alibaba Cloud publishes it.
type osImageRule struct {
	OSType   string
	Label    string
	Families map[string]*regexp.Regexp
}

// osImageFamilyPatterns are the operating systems --os takes. Alibaba
// Cloud Linux: the standard LTS images (acs:alibaba_cloud_linux_4_lts_x64,
// acs:alibaba_cloud_linux_3_2104_lts_x64); the pro, container optimized,
// agentic, GPU and compliance variants have families of their own that do
// not match. Windows Server: the Chinese Datacenter edition
// (acs:win_2025_datacenter_x64_zh); the English, Core, UEFI and container
// editions do not match, and there is no arm64 edition.
var osImageFamilyPatterns = map[string]osImageRule{
	osAlibabaCloudLinux: {OSType: "linux", Label: "Alibaba Cloud Linux", Families: map[string]*regexp.Regexp{
		archX86: regexp.MustCompile(`^acs:alibaba_cloud_linux_(\d+)(?:_\d+)?_lts_x64$`),
		archARM: regexp.MustCompile(`^acs:alibaba_cloud_linux_(\d+)(?:_\d+)?_lts_arm64$`),
	}},
	osWindows: {OSType: "windows", Label: "Windows Server", Families: map[string]*regexp.Regexp{
		archX86: regexp.MustCompile(`^acs:win_(\d+)_datacenter_x64_zh$`),
	}},
}

// supportedOSes lists the values of --os.
const supportedOSes = osAlibabaCloudLinux + " or " + osWindows

// checkImageOS refuses an --os or --arch the image cannot be picked for
// (a usage error, before any request).
func checkImageOS(osName, arch string) error {
	rule, ok := osImageFamilyPatterns[osName]
	if !ok {
		return app.UsageErrf("unsupported os %q: --os takes %s (pass --image <id> for any other system)", osName, supportedOSes)
	}
	if arch != archX86 && arch != archARM {
		return app.UsageErrf("unsupported architecture %q: --arch takes %s or %s", arch, archX86, archARM)
	}
	if rule.Families[arch] == nil {
		return app.UsageErrf("--os %s has no %s image: use an %s instance type (or pass --image <id>)", osName, arch, archX86)
	}
	return nil
}

// imageInfo is the output of `image latest`.
type imageInfo struct {
	ImageID      string `json:"image_id" yaml:"image_id"`
	ImageName    string `json:"image_name" yaml:"image_name"`
	OSName       string `json:"os_name" yaml:"os_name"`
	Architecture string `json:"architecture" yaml:"architecture"`
	CreationTime string `json:"creation_time" yaml:"creation_time"`
	Region       string `json:"region" yaml:"region"`
}

func imageFrom(region string, im ecs.Image) imageInfo {
	osName := im.OSNameEn
	if osName == "" {
		osName = im.OSName
	}
	return imageInfo{ImageID: im.ImageId, ImageName: im.ImageName, OSName: strings.Join(strings.Fields(osName), " "),
		Architecture: im.Architecture, CreationTime: im.CreationTime, Region: region}
}

// usableImage reports whether a system image can be used: available (or
// without a status), of the architecture asked for (or without one).
func usableImage(im ecs.Image, arch string) bool {
	if im.ImageId == "" {
		return false
	}
	if im.Status != "" && !strings.EqualFold(im.Status, "Available") {
		return false
	}
	return im.Architecture == "" || strings.EqualFold(im.Architecture, arch)
}

// describeImages lists the available public (system) images of a region
// of one OS type and architecture, every page.
func (c *client) describeImages(ctx context.Context, region, osType, arch string) ([]ecs.Image, error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return nil, err
	}
	var out []ecs.Image
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := ecs.CreateDescribeImagesRequest()
		c.route(req, endpointECS)
		req.RegionId = region
		req.ImageOwnerAlias = "system"
		req.OSType = osType
		req.Architecture = arch
		req.Status = "Available"
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(imagePageSize)
		resp, err := cl.DescribeImages(req)
		if err != nil {
			return nil, wrapErr("ecs DescribeImages "+region, err)
		}
		out = append(out, resp.Images.Image...)
		if len(resp.Images.Image) == 0 || page*imagePageSize >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// pickLatestImage picks the newest image whose family matches family:
// the highest OS version (the first group) first, then the newest
// CreationTime (UTC ISO 8601, compared as text), then the image id.
// Names and OS names are never used to tell versions apart ("2.1903"
// holds a 3).
func pickLatestImage(images []ecs.Image, family *regexp.Regexp, arch string) (ecs.Image, bool) {
	type cand struct {
		im      ecs.Image
		version int
	}
	var cands []cand
	for _, im := range images {
		m := family.FindStringSubmatch(im.ImageFamily)
		if m == nil || !usableImage(im, arch) {
			continue
		}
		v, err := strconv.Atoi(m[1])
		if err != nil {
			continue
		}
		cands = append(cands, cand{im, v})
	}
	if len(cands) == 0 {
		return ecs.Image{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		a, b := cands[i], cands[j]
		if a.version != b.version {
			return a.version > b.version
		}
		if a.im.CreationTime != b.im.CreationTime {
			return a.im.CreationTime > b.im.CreationTime
		}
		return a.im.ImageId < b.im.ImageId
	})
	return cands[0].im, true
}

// latestImage returns the newest public image of an OS (a key of
// osImageFamilyPatterns) for an architecture in a region; none is
// platform.ErrNotFound.
func (c *client) latestImage(ctx context.Context, region, osName, arch string) (imageInfo, error) {
	if err := checkImageOS(osName, arch); err != nil {
		return imageInfo{}, err
	}
	region = c.regionOr(region)
	rule := osImageFamilyPatterns[osName]
	family := rule.Families[arch]
	images, err := c.describeImages(ctx, region, rule.OSType, arch)
	if err != nil {
		return imageInfo{}, err
	}
	if im, ok := pickLatestImage(images, family, arch); ok {
		return imageFrom(region, im), nil
	}
	return imageInfo{}, fmt.Errorf("%w: no public %s image matching %s in %s for %s; pass --image <id>",
		platform.ErrNotFound, rule.Label, family, region, arch)
}

// typeArch returns the architecture of an instance type (x86_64 or arm64)
// from DescribeInstanceTypes; known is false when the region does not
// list the type.
func (c *client) typeArch(ctx context.Context, region, typ string) (arch string, known bool, err error) {
	region = c.regionOr(region)
	cl, err := c.ecsClient(ctx, region)
	if err != nil {
		return "", false, err
	}
	req := ecs.CreateDescribeInstanceTypesRequest()
	c.route(req, endpointECS)
	req.RegionId = region
	req.InstanceTypes = &[]string{typ}
	resp, err := cl.DescribeInstanceTypes(req)
	if err != nil {
		return "", false, wrapErr("ecs DescribeInstanceTypes "+typ, err)
	}
	for _, t := range resp.InstanceTypes.InstanceType {
		if t.InstanceTypeId != typ {
			continue
		}
		if strings.EqualFold(t.CpuArchitecture, cpuArchARM) {
			return archARM, true, nil
		}
		return archX86, true, nil
	}
	return archX86, false, nil
}
