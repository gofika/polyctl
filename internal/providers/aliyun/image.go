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
)

// imagePageSize is the largest page DescribeImages accepts.
const imagePageSize = 100

// Operating systems and architectures `image latest` knows.
const (
	osAlibabaCloudLinux = "alibaba-cloud-linux"
	archX86             = "x86_64"
	archARM             = "arm64"
)

// alinuxFamilies are the image families of the plain Alibaba Cloud Linux
// images, newest major version first. A family query returns the newest
// image of that family only, and every variant (pro, container optimized,
// agentic, GPU, ...) has a family of its own, so the plain image is never
// confused with a newer variant. The arm64 3.2104 family name is not
// verified; a family that answers nothing is skipped.
var alinuxFamilies = map[string][]string{
	archX86: {"acs:alibaba_cloud_linux_4_lts_x64", "acs:alibaba_cloud_linux_3_2104_lts_x64", "acs:alibaba_cloud_linux_2_1903_lts_x64"},
	archARM: {"acs:alibaba_cloud_linux_4_lts_arm64", "acs:alibaba_cloud_linux_3_2104_lts_arm64"},
}

// alinuxFamilyRE matches the family of a plain Alibaba Cloud Linux image
// (the fallback when the family constants stop answering): the variants'
// families do not match it.
var alinuxFamilyRE = regexp.MustCompile(`^acs:alibaba_cloud_linux_(\d+)(_\d+)?_lts_(x64|arm64)$`)

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

// familyArch is the architecture suffix of the families ("x64", "arm64").
func familyArch(arch string) string {
	if arch == archX86 {
		return "x64"
	}
	return arch
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

// newestFirst sorts images by CreationTime, newest first (ISO 8601 sorts
// as text).
func newestFirst(images []ecs.Image) {
	sort.SliceStable(images, func(i, j int) bool { return images[i].CreationTime > images[j].CreationTime })
}

// describeImages runs DescribeImages for the available system images of a
// region, of one family when family is not "", of one architecture when
// arch is not "", every page.
func (c *client) describeImages(ctx context.Context, region, family, arch string) ([]ecs.Image, error) {
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
		req.Status = "Available"
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(imagePageSize)
		if family != "" {
			req.ImageFamily = family
		} else {
			req.OSType = "linux"
			req.Architecture = arch
		}
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

// pickLatestAlinux picks the newest plain Alibaba Cloud Linux image of an
// architecture from a listing: images whose family is a plain one (by
// alinuxFamilyRE), highest major version first, then the newest. Names and
// OSNameEn are never used to tell versions apart ("2.1903" holds a 3).
func pickLatestAlinux(images []ecs.Image, arch string) (ecs.Image, bool) {
	type cand struct {
		im    ecs.Image
		major int
	}
	var cands []cand
	for _, im := range images {
		m := alinuxFamilyRE.FindStringSubmatch(im.ImageFamily)
		if m == nil || m[3] != familyArch(arch) || !usableImage(im, arch) {
			continue
		}
		major, _ := strconv.Atoi(m[1])
		cands = append(cands, cand{im, major})
	}
	if len(cands) == 0 {
		return ecs.Image{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].major != cands[j].major {
			return cands[i].major > cands[j].major
		}
		return cands[i].im.CreationTime > cands[j].im.CreationTime
	})
	return cands[0].im, true
}

// latestAlinuxImage returns the newest plain Alibaba Cloud Linux image of a
// region and architecture: the first family of alinuxFamilies that answers
// (at most one request per family), else the whole listing of system
// images filtered by pickLatestAlinux.
func (c *client) latestAlinuxImage(ctx context.Context, region, arch string) (imageInfo, error) {
	region = c.regionOr(region)
	for _, fam := range alinuxFamilies[arch] {
		images, err := c.describeImages(ctx, region, fam, "")
		if err != nil {
			return imageInfo{}, err
		}
		var ok []ecs.Image
		for _, im := range images {
			if usableImage(im, arch) && (im.ImageFamily == "" || im.ImageFamily == fam) {
				ok = append(ok, im)
			}
		}
		if len(ok) > 0 {
			newestFirst(ok)
			return imageFrom(region, ok[0]), nil
		}
	}
	images, err := c.describeImages(ctx, region, "", arch)
	if err != nil {
		return imageInfo{}, err
	}
	if im, ok := pickLatestAlinux(images, arch); ok {
		return imageFrom(region, im), nil
	}
	return imageInfo{}, fmt.Errorf("no available Alibaba Cloud Linux system image for %s in %s", arch, region)
}
