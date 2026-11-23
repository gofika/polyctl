package aliyun

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func img(id, family, osName, arch, created string) map[string]any {
	return map[string]any{"ImageId": id, "ImageName": id, "ImageFamily": family, "OSNameEn": osName, "Architecture": arch,
		"CreationTime": created, "Status": "Available", "ImageOwnerAlias": "system", "Platform": "Aliyun", "OSType": "linux"}
}

// realImages is shaped like the system images of cn-hongkong (2026-11-17):
// variants of version 4 share its name prefix, and the agentic one is
// newer than the plain image; 2.1903 holds a "3" in its OS name.
func realImages() []map[string]any {
	return []map[string]any{
		img("aliyun_4_x64_20G_alibase_20261103.vhd", "acs:alibaba_cloud_linux_4_lts_x64", "Alibaba Cloud Linux  4 LTS 64 bit", "x86_64", "2026-11-05T12:55:52Z"),
		img("aliyun_4_x64_20G_alibase_20260901.vhd", "acs:alibaba_cloud_linux_4_lts_x64", "Alibaba Cloud Linux  4 LTS 64 bit", "x86_64", "2026-09-03T00:00:00Z"),
		img("aliyun_4_x64_20G_agentic_20261115.vhd", "acs:alibaba_cloud_linux_4_x64_agentic", "Alibaba Cloud Linux  4 LTS 64 bit", "x86_64", "2026-11-16T08:00:00Z"),
		img("aliyun_4_x64_20G_pro_20261101.vhd", "acs:alibaba_cloud_linux_4_pro_lts_x64", "Alibaba Cloud Linux  4 LTS 64 bit Pro", "x86_64", "2026-11-10T00:00:00Z"),
		img("aliyun_4_x64_20G_container_optimized_20261101.vhd", "acs:alibaba_cloud_linux_4_x64_container_optimized", "Alibaba Cloud Linux  4", "x86_64", "2026-11-11T00:00:00Z"),
		img("aliyun_4_x64_100G_gpu_cuda_20261101.vhd", "acs:alibaba_cloud_linux_4_x64_gpu", "Alibaba Cloud Linux  4", "x86_64", "2026-11-12T00:00:00Z"),
		img("aliyun_3_x64_20G_alibase_20261105.vhd", "acs:alibaba_cloud_linux_3_2104_lts_x64", "Alibaba Cloud Linux 3.2104 LTS 64 bit", "x86_64", "2026-11-06T00:00:00Z"),
		img("aliyun_2_1903_x64_20G_alibase_20260720.vhd", "acs:alibaba_cloud_linux_2_1903_lts_x64", "Alibaba Cloud Linux 2.1903 LTS 64 bit", "x86_64", "2026-07-21T00:00:00Z"),
		img("aliyun_4_arm64_20G_alibase_20261103.vhd", "acs:alibaba_cloud_linux_4_lts_arm64", "Alibaba Cloud Linux  4 LTS 64 bit", "arm64", "2026-11-05T00:00:00Z"),
	}
}

func TestImageLatestUsesFamilyChain(t *testing.T) {
	h, f := sgHarness(t, app.Flags{DryRun: true, Output: "table"}) // read-only: --dry-run changes nothing
	f.images = realImages()
	if err := h.run("ecs", "image", "latest"); err != nil {
		t.Fatal(err)
	}
	if got := h.stdout.String(); got != "aliyun_4_x64_20G_alibase_20261103.vhd\n" {
		t.Errorf("table output = %q, want the image id alone", got)
	}
	calls := h.api.callsFor("DescribeImages")
	if len(calls) != 1 || calls[0].Get("ImageFamily") != "acs:alibaba_cloud_linux_4_lts_x64" || calls[0].Get("ImageOwnerAlias") != "system" || calls[0].Get("Status") != "Available" {
		t.Errorf("DescribeImages calls = %v", calls)
	}
	h, f = sgHarness(t, app.Flags{})
	f.images = realImages()
	if err := h.run("ecs", "image", "latest", "--arch", "arm64", "--region", "cn-hongkong"); err != nil {
		t.Fatal(err)
	}
	var im imageInfo
	h.jsonOut(&im)
	if im.ImageID != "aliyun_4_arm64_20G_alibase_20261103.vhd" || im.Region != "cn-hongkong" || im.Architecture != "arm64" || im.OSName != "Alibaba Cloud Linux 4 LTS 64 bit" || im.CreationTime == "" {
		t.Errorf("arm64 json = %+v", im)
	}
}

func TestImageLatestFallsBackToVersion3(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	for _, im := range realImages() {
		if im["ImageFamily"] != "acs:alibaba_cloud_linux_4_lts_x64" {
			f.images = append(f.images, im)
		}
	}
	if err := h.run("ecs", "image", "latest"); err != nil {
		t.Fatal(err)
	}
	var im imageInfo
	h.jsonOut(&im)
	if im.ImageID != "aliyun_3_x64_20G_alibase_20261105.vhd" || len(h.api.callsFor("DescribeImages")) != 2 {
		t.Errorf("fallback to 3 = %+v after %d call(s)", im, len(h.api.callsFor("DescribeImages")))
	}
}

// When no family constant answers any more, the listing (every page) is
// filtered by the family pattern: a new plain major version wins, the
// newer variants never do.
func TestImageLatestListingFallback(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	for i := 0; i < 150; i++ {
		f.images = append(f.images, img(fmt.Sprintf("ubuntu_%03d.vhd", i), "acs:ubuntu_24_04_x64", "Ubuntu 24.04 64 bit", "x86_64", "2026-11-20T00:00:00Z"))
	}
	f.images = append(f.images,
		img("aliyun_5_x64_20G_agentic.vhd", "acs:alibaba_cloud_linux_5_x64_agentic", "Alibaba Cloud Linux 5", "x86_64", "2027-03-01T00:00:00Z"),
		img("aliyun_5_x64_20G_alibase.vhd", "acs:alibaba_cloud_linux_5_lts_x64", "Alibaba Cloud Linux 5 LTS 64 bit", "x86_64", "2027-02-01T00:00:00Z"),
		img("aliyun_5_arm64_20G_alibase.vhd", "acs:alibaba_cloud_linux_5_lts_arm64", "Alibaba Cloud Linux 5 LTS 64 bit", "x86_64", "2027-02-02T00:00:00Z"),
	)
	if err := h.run("ecs", "image", "latest"); err != nil {
		t.Fatal(err)
	}
	var im imageInfo
	h.jsonOut(&im)
	if im.ImageID != "aliyun_5_x64_20G_alibase.vhd" {
		t.Errorf("listing fallback = %+v", im)
	}
	var listed int
	for _, c := range h.api.callsFor("DescribeImages") {
		if c.Get("ImageFamily") == "" {
			listed++
			if c.Get("OSType") != "linux" || c.Get("Architecture") != "x86_64" || c.Get("PageSize") != "100" {
				t.Errorf("listing call = %v", c)
			}
		}
	}
	if listed != 2 {
		t.Errorf("listing took %d page(s), want 2", listed)
	}
}

// pickLatestAlinux on the real shapes: the plain 4, not the newer agentic
// variant; 3.2104 over 2.1903.
func TestPickLatestAlinuxIgnoresVariants(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.images = realImages()
	images, err := h.api.client().describeImages(t.Context(), "cn-shanghai", "", "x86_64")
	if err != nil {
		t.Fatal(err)
	}
	im, ok := pickLatestAlinux(images, "x86_64")
	if !ok || im.ImageId != "aliyun_4_x64_20G_alibase_20261103.vhd" {
		t.Errorf("picked %q", im.ImageId)
	}
	var only2and3 = images[:0:0]
	for _, im := range images {
		if strings.Contains(im.ImageFamily, "_2_1903_") || strings.Contains(im.ImageFamily, "_3_2104_") {
			only2and3 = append(only2and3, im)
		}
	}
	if im, ok := pickLatestAlinux(only2and3, "x86_64"); !ok || im.ImageId != "aliyun_3_x64_20G_alibase_20261105.vhd" {
		t.Errorf("3 over 2.1903: picked %q", im.ImageId)
	}
}

func TestImageLatestErrors(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.images = []map[string]any{img("ubuntu.vhd", "acs:ubuntu_24_04_x64", "Ubuntu", "x86_64", "2026-01-01T00:00:00Z")}
	err := h.run("ecs", "image", "latest")
	if err == nil || errors.Is(err, platform.ErrNotFound) || errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "no available Alibaba Cloud Linux") {
		t.Errorf("no image = %v, want a general failure", err)
	}
	calls := len(h.api.calls)
	if err := h.run("ecs", "image", "latest", "--os", "ubuntu"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "unsupported os") {
		t.Errorf("--os ubuntu = %v", err)
	}
	if err := h.run("ecs", "image", "latest", "--arch", "i386"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("--arch i386 = %v", err)
	}
	if len(h.api.calls) != calls {
		t.Error("usage errors sent requests")
	}
}
