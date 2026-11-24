package aliyun

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"

	"github.com/aliyun/alibaba-cloud-sdk-go/services/ecs"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

func img(id, family, osName, arch, created string) map[string]any {
	return map[string]any{"ImageId": id, "ImageName": id, "ImageFamily": family, "OSNameEn": osName, "Architecture": arch,
		"CreationTime": created, "Status": "Available", "ImageOwnerAlias": "system", "Platform": "Aliyun", "OSType": "linux"}
}

func winImg(id, family, created string) map[string]any {
	im := img(id, family, "Windows Server", "x86_64", created)
	im["OSType"], im["Platform"] = "windows", "Windows Server 2025"
	return im
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
		img("aliyun_3_arm64_20G_alibase_20261106.vhd", "acs:alibaba_cloud_linux_3_2104_lts_arm64", "Alibaba Cloud Linux 3.2104 LTS 64 bit", "arm64", "2026-11-07T00:00:00Z"),
		winImg("win2022_datacenter_zh.vhd", "acs:win_2022_datacenter_x64_zh", "2026-11-14T00:00:00Z"),
		winImg("win2025_datacenter_zh.vhd", "acs:win_2025_datacenter_x64_zh", "2026-11-01T00:00:00Z"),
		winImg("win2025_datacenter_en.vhd", "acs:win_2025_datacenter_x64_en", "2026-11-15T00:00:00Z"),
		winImg("win2025_core_zh.vhd", "acs:win_2025_core_x64_zh", "2026-11-15T00:00:00Z"),
		winImg("win2025_datacenter_uefi_zh.vhd", "acs:win_2025_datacenter_x64_uefi_zh", "2026-11-15T00:00:00Z"),
		winImg("win2025_container_zh.vhd", "acs:win_2025_datacenter_x64_container_zh", "2026-11-15T00:00:00Z"),
	}
}

// The family patterns: the plain images match (the first group is the
// version), every variant and edition is left out.
func TestOSImageFamilyPatterns(t *testing.T) {
	for _, tc := range []struct {
		os, arch, family, version string
	}{
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_4_lts_x64", "4"},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_3_2104_lts_x64", "3"},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_2_1903_lts_x64", "2"},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_5_lts_x64", "5"},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_4_pro_lts_x64", ""},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_4_x64_container_optimized", ""},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_4_x64_agentic", ""},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_3_2104_lts_x64_dengbao", ""},
		{osAlibabaCloudLinux, archX86, "acs:alibaba_cloud_linux_4_lts_arm64", ""},
		{osAlibabaCloudLinux, archARM, "acs:alibaba_cloud_linux_4_lts_arm64", "4"},
		{osAlibabaCloudLinux, archARM, "acs:alibaba_cloud_linux_3_2104_lts_arm64", "3"},
		{osAlibabaCloudLinux, archARM, "acs:alibaba_cloud_linux_4_lts_x64", ""},
		{osWindows, archX86, "acs:win_2025_datacenter_x64_zh", "2025"},
		{osWindows, archX86, "acs:win_2022_datacenter_x64_zh", "2022"},
		{osWindows, archX86, "acs:win_2025_datacenter_x64_en", ""},
		{osWindows, archX86, "acs:win_2025_core_x64_zh", ""},
		{osWindows, archX86, "acs:win_2025_datacenter_x64_uefi_zh", ""},
		{osWindows, archX86, "acs:win_2025_datacenter_x64_container_zh", ""},
		{osWindows, archX86, "acs:ubuntu_24_04_x64", ""},
	} {
		m := osImageFamilyPatterns[tc.os].Families[tc.arch].FindStringSubmatch(tc.family)
		got := ""
		if m != nil {
			got = m[1]
		}
		if got != tc.version {
			t.Errorf("%s %s %s: version %q, want %q", tc.os, tc.arch, tc.family, got, tc.version)
		}
	}
	if osImageFamilyPatterns[osWindows].Families[archARM] != nil {
		t.Error("windows has an arm64 pattern")
	}
}

// The highest version wins over a newer image of a lower one, then the
// newest creation time; equal times fall back to the id.
func TestPickLatestImageOrder(t *testing.T) {
	re := osImageFamilyPatterns[osAlibabaCloudLinux].Families[archX86]
	images := []ecs.Image{
		{ImageId: "v3-new", ImageFamily: "acs:alibaba_cloud_linux_3_2104_lts_x64", CreationTime: "2026-12-01T00:00:00Z"},
		{ImageId: "v4-old", ImageFamily: "acs:alibaba_cloud_linux_4_lts_x64", CreationTime: "2026-01-01T00:00:00Z"},
		{ImageId: "v4-new-b", ImageFamily: "acs:alibaba_cloud_linux_4_lts_x64", CreationTime: "2026-06-01T00:00:00Z"},
		{ImageId: "v4-new-a", ImageFamily: "acs:alibaba_cloud_linux_4_lts_x64", CreationTime: "2026-06-01T00:00:00Z"},
		{ImageId: "v4-gone", ImageFamily: "acs:alibaba_cloud_linux_4_lts_x64", CreationTime: "2026-09-01T00:00:00Z", Status: "Deprecated"},
		{ImageId: "v4-arm", ImageFamily: "acs:alibaba_cloud_linux_4_lts_x64", CreationTime: "2026-09-01T00:00:00Z", Architecture: "arm64"},
	}
	if im, ok := pickLatestImage(images, re, archX86); !ok || im.ImageId != "v4-new-a" {
		t.Errorf("picked %q", im.ImageId)
	}
	if _, ok := pickLatestImage(images[:0], re, archX86); ok {
		t.Error("picked from nothing")
	}
}

func TestImageLatestListsAndPicks(t *testing.T) {
	h, f := sgHarness(t, app.Flags{DryRun: true, Output: "table"}) // read-only: --dry-run changes nothing
	f.images = realImages()
	if err := h.run("ecs", "image", "latest"); err != nil {
		t.Fatal(err)
	}
	if got := h.stdout.String(); got != alinux4+"\n" {
		t.Errorf("table output = %q, want the image id alone", got)
	}
	calls := h.api.callsFor("DescribeImages")
	if len(calls) != 1 {
		t.Fatalf("DescribeImages calls = %v", calls)
	}
	q := calls[0]
	for k, v := range map[string]string{"ImageOwnerAlias": "system", "OSType": "linux", "Architecture": "x86_64", "Status": "Available", "PageSize": "100", "ImageFamily": ""} {
		if q.Get(k) != v {
			t.Errorf("DescribeImages %s = %q, want %q", k, q.Get(k), v)
		}
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
	if q := h.api.callsFor("DescribeImages")[0]; q.Get("Architecture") != "arm64" {
		t.Errorf("arm64 query = %v", q)
	}
}

func TestImageLatestWindows(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.images = realImages()
	if err := h.run("ecs", "image", "latest", "--os", "windows"); err != nil {
		t.Fatal(err)
	}
	var im imageInfo
	h.jsonOut(&im)
	// 2025 over the newer 2022 image; the English, Core, UEFI and container
	// editions are never picked.
	if im.ImageID != "win2025_datacenter_zh.vhd" {
		t.Errorf("windows = %+v", im)
	}
	if q := h.api.callsFor("DescribeImages")[0]; q.Get("OSType") != "windows" || q.Get("Architecture") != "x86_64" {
		t.Errorf("windows query = %v", q)
	}
	calls := len(h.api.calls)
	if err := h.run("ecs", "image", "latest", "--os", "windows", "--arch", "arm64"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("windows arm64 = %v", err)
	}
	if len(h.api.calls) != calls {
		t.Error("windows arm64 sent requests")
	}
}

// A new major version is picked from the listing (every page) without any
// change: nothing is written down but the family pattern.
func TestImageLatestNewVersionAndPages(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.images = realImages()
	for i := 0; i < 150; i++ {
		f.images = append(f.images, img(fmt.Sprintf("ubuntu_%03d.vhd", i), "acs:ubuntu_24_04_x64", "Ubuntu 24.04 64 bit", "x86_64", "2026-11-20T00:00:00Z"))
	}
	f.images = append(f.images,
		img("aliyun_5_x64_20G_agentic.vhd", "acs:alibaba_cloud_linux_5_x64_agentic", "Alibaba Cloud Linux 5", "x86_64", "2027-03-01T00:00:00Z"),
		img("aliyun_5_x64_20G_alibase.vhd", "acs:alibaba_cloud_linux_5_lts_x64", "Alibaba Cloud Linux 5 LTS 64 bit", "x86_64", "2027-02-01T00:00:00Z"),
		img("aliyun_5_arm64_20G_alibase.vhd", "acs:alibaba_cloud_linux_5_lts_arm64", "Alibaba Cloud Linux 5 LTS 64 bit", "arm64", "2027-02-02T00:00:00Z"),
	)
	if err := h.run("ecs", "image", "latest"); err != nil {
		t.Fatal(err)
	}
	var im imageInfo
	h.jsonOut(&im)
	if im.ImageID != "aliyun_5_x64_20G_alibase.vhd" {
		t.Errorf("new version = %+v", im)
	}
	var pages []string
	for _, c := range h.api.callsFor("DescribeImages") {
		pages = append(pages, c.Get("PageNumber"))
	}
	if !slices.Equal(pages, []string{"1", "2"}) {
		t.Errorf("pages = %v", pages)
	}
}

func TestImageLatestErrors(t *testing.T) {
	h, f := sgHarness(t, app.Flags{})
	f.images = []map[string]any{img("ubuntu.vhd", "acs:ubuntu_24_04_x64", "Ubuntu", "x86_64", "2026-01-01T00:00:00Z")}
	err := h.run("ecs", "image", "latest")
	if !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("no image = %v, want not found", err)
	} else {
		for _, want := range []string{"no public Alibaba Cloud Linux image matching", "cn-shanghai", "x86_64", "--image <id>"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("no image = %v, want %q", err, want)
			}
		}
	}
	calls := len(h.api.calls)
	if err := h.run("ecs", "image", "latest", "--os", "ubuntu"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "alibaba-cloud-linux or windows") {
		t.Errorf("--os ubuntu = %v", err)
	}
	if err := h.run("ecs", "image", "latest", "--arch", "i386"); !errors.Is(err, app.ErrUsage) {
		t.Errorf("--arch i386 = %v", err)
	}
	if err := h.run("ecs", "image", "latest", "--os", "windows", "--arch", "arm64"); !errors.Is(err, app.ErrUsage) || !strings.Contains(err.Error(), "--arch x86_64") {
		t.Errorf("--os windows --arch arm64 = %v", err)
	}
	if len(h.api.calls) != calls {
		t.Error("usage errors sent requests")
	}
}
