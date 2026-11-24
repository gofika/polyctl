package gcp

import (
	"errors"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
)

func img(name, arch, deprecated, created string) imageCandidate {
	return imageCandidate{Name: name, Architecture: arch, Deprecated: deprecated, Created: created, DiskSizeGB: 10}
}

func TestSelectImage(t *testing.T) {
	const (
		t1 = "2026-11-01T00:00:00.000-07:00"
		t2 = "2026-11-10T00:00:00.000-07:00"
		t3 = "2026-11-17T00:00:00.000-07:00"
	)
	debian := []imageCandidate{
		img("debian-13-trixie-v20261116", "X86_64", "", t2),
		img("debian-13-trixie-arm64-v20261116", "ARM64", "", t3),
		// A patch image of the old major version, created later.
		img("debian-12-bookworm-v20261117", "X86_64", "", t3),
		img("debian-14-forky-v20260101", "X86_64", "DEPRECATED", t3),
		img("debian-13-backports-v20261117", "X86_64", "", t3),
		img("debian-11-bullseye-v20200101", "", "OBSOLETE", t1),
		{Name: "debian-13-trixie-v20261118", Architecture: "X86_64", Status: "PENDING", Created: t3},
		{Name: "debian-13-trixie-v20261119", Architecture: "X86_64", Status: "FAILED", Created: t3},
	}
	ubuntu := []imageCandidate{
		img("ubuntu-2204-jammy-v20261101", "X86_64", "", t1),
		img("ubuntu-2404-noble-amd64-v20261101", "X86_64", "", t2),
		img("ubuntu-2604-resolute-amd64-v20261107", "X86_64", "", t2),
		img("ubuntu-2604-resolute-arm64-v20261107", "ARM64", "", t3),
		img("ubuntu-2610-interim-amd64-v20261110", "X86_64", "", t3),
		img("ubuntu-2504-plucky-amd64-v20261110", "X86_64", "", t3),
		img("ubuntu-minimal-2804-x-amd64-v20261110", "X86_64", "", t3),
		img("ubuntu-pro-2804-x-amd64-v20261110", "X86_64", "", t3),
		{Name: "ubuntu-2604-resolute-amd64-v20261120", Architecture: "X86_64", Status: "DELETING", Created: t3},
	}
	rocky := []imageCandidate{
		img("rocky-linux-9-v20261101", "X86_64", "", t3),
		img("rocky-linux-10-v20261101", "X86_64", "", t2),
		img("rocky-linux-10-optimized-gcp-v20261101", "X86_64", "", t2),
		img("rocky-linux-10-optimized-gcp-oot-gve-v20261101", "X86_64", "", t2),
	}
	rhel := []imageCandidate{
		img("rhel-9-v20261113", "X86_64", "", t2),
		img("rhel-9-8-eus-lvm-v20261113", "X86_64", "", t3),
		img("rhel-9-sap-ha-v20261113", "X86_64", "", t3),
		img("rhel-10-2-eus-gvnic-baremetal-v20261113", "X86_64", "", t3),
	}
	windows := []imageCandidate{
		img("windows-server-2022-dc-v20261101", "X86_64", "", t1),
		img("windows-server-2025-dc-v20261101", "X86_64", "", t2),
		img("windows-server-2025-dc-core-v20261110", "X86_64", "", t3),
		img("windows-server-2025-dc-sql-v20261110", "X86_64", "", t3),
	}
	centos := []imageCandidate{
		img("centos-stream-9-v20261101", "X86_64", "", t2),
		img("centos-stream-10-v20261101", "X86_64", "", t3),
		img("centos-7-v20200101", "X86_64", "", t3),
	}
	cos := []imageCandidate{img("cos-121-18867-652-66", "X86_64", "", t2), img("cos-125-1-1-1", "X86_64", "", t3), img("cos-arm64-125", "ARM64", "", t3)}
	for _, tc := range []struct {
		os, version string
		images      []imageCandidate
		want        string
	}{
		{"debian", "", debian, "debian-13-trixie-v20261116"},
		{"debian", "12", debian, "debian-12-bookworm-v20261117"},
		{"debian", "1", debian, ""},
		{"ubuntu", "", ubuntu, "ubuntu-2604-resolute-amd64-v20261107"},
		{"ubuntu", "22.04", ubuntu, "ubuntu-2204-jammy-v20261101"},
		{"ubuntu", "26.10", ubuntu, "ubuntu-2610-interim-amd64-v20261110"},
		{"rocky", "", rocky, "rocky-linux-10-v20261101"},
		{"rocky", "9", rocky, "rocky-linux-9-v20261101"},
		{"rhel", "", rhel, "rhel-9-v20261113"},
		{"rhel", "10", rhel, ""},
		{"windows", "", windows, "windows-server-2025-dc-v20261101"},
		{"windows", "2022", windows, "windows-server-2022-dc-v20261101"},
		{"centos", "", centos, "centos-stream-10-v20261101"},
		{"centos", "9", centos, "centos-stream-9-v20261101"},
		{"cos", "", cos, "cos-125-1-1-1"},
		// Exclusions match whole name parts, not letters inside a codename.
		{"ubuntu", "", append(ubuntu[:len(ubuntu):len(ubuntu)], img("ubuntu-2804-prowler-amd64-v20280501", "X86_64", "", t3)), "ubuntu-2804-prowler-amd64-v20280501"},
	} {
		got, ok := selectImage(tc.os, tc.version, archX86, tc.images)
		if tc.want == "" {
			if ok {
				t.Errorf("%s %q picked %s, want none", tc.os, tc.version, got.Name)
			}
			continue
		}
		if !ok || got.Name != tc.want {
			t.Errorf("%s %q = %q (%v), want %q", tc.os, tc.version, got.Name, ok, tc.want)
		}
	}
}

// TestSelectDebianImage checks the Debian name rule, the architecture
// filter and the version-then-time order.
func TestSelectDebianImage(t *testing.T) {
	const (
		t1 = "2026-11-01T00:00:00.000-07:00"
		t2 = "2026-11-10T00:00:00.000-07:00"
		t3 = "2026-11-17T00:00:00.000-07:00"
	)
	// Which names the rule takes at all (one image each, x86_64).
	for name, want := range map[string]bool{
		"debian-13-trixie-v20261116":             true,
		"debian-13-trixie-amd64-v20261116":       true,
		"debian-12-bookworm-v20261117":           true,
		"debian-11-bullseye-backports-v2024":     false,
		"debian-12-bookworm-backports-v20261117": false,
		"debian-13-trixie-sid-test-v20261116":    false,
		"debian-13-backports-v20261117":          false,
		"debian-sid-v20261116":                   false,
		"my-debian-13-trixie-v20261116":          false,
		"debian-13-trixie-v2026":                 false,
	} {
		_, ok := selectImage("debian", "", archX86, []imageCandidate{img(name, "X86_64", "", t1)})
		if ok != want {
			t.Errorf("debian rule takes %s = %v, want %v", name, ok, want)
		}
	}
	images := []imageCandidate{
		img("debian-12-bookworm-v20261117", "X86_64", "", t3),
		img("debian-12-bookworm-arm64-v20261117", "ARM64", "", t3),
		img("debian-13-trixie-v20261101", "X86_64", "", t1),
		img("debian-13-trixie-v20261110", "X86_64", "", t2),
		img("debian-13-trixie-arm64-v20261110", "ARM64", "", t2),
		img("debian-13-trixie-arm64-v20261117", "ARM64", "DEPRECATED", t3),
		// An old image without an architecture: its name tells.
		img("debian-13-trixie-arm64-v20261101", "", "", t1),
	}
	for _, tc := range []struct{ version, arch, want string }{
		{"", archX86, "debian-13-trixie-v20261110"},
		{"", archARM, "debian-13-trixie-arm64-v20261110"},
		{"12", archX86, "debian-12-bookworm-v20261117"},
		{"12", archARM, "debian-12-bookworm-arm64-v20261117"},
		{"13", archARM, "debian-13-trixie-arm64-v20261110"},
		{"14", archX86, ""},
	} {
		got, ok := selectImage("debian", tc.version, tc.arch, images)
		if tc.want == "" {
			if ok {
				t.Errorf("debian %q %s picked %s, want none", tc.version, tc.arch, got.Name)
			}
			continue
		}
		if !ok || got.Name != tc.want {
			t.Errorf("debian %q %s = %q (%v), want %q", tc.version, tc.arch, got.Name, ok, tc.want)
		}
	}
	// A new major version is chosen as soon as it is published, even when
	// an older one has a later image.
	newer := append(images[:len(images):len(images)], img("debian-14-forky-v20261101", "X86_64", "", t1), img("debian-14-forky-arm64-v20261101", "ARM64", "", t1))
	for arch, want := range map[string]string{archX86: "debian-14-forky-v20261101", archARM: "debian-14-forky-arm64-v20261101"} {
		if got, ok := selectImage("debian", "", arch, newer); !ok || got.Name != want {
			t.Errorf("debian %s with 14 = %q, want %q", arch, got.Name, want)
		}
	}
	// The other systems follow the architecture too.
	rocky := []imageCandidate{img("rocky-linux-10-v20261101", "X86_64", "", t2), img("rocky-linux-10-arm64-v20261101", "ARM64", "", t2), img("rocky-linux-10-optimized-gcp-arm64-v20261101", "ARM64", "", t3)}
	if got, ok := selectImage("rocky", "", archARM, rocky); !ok || got.Name != "rocky-linux-10-arm64-v20261101" {
		t.Errorf("rocky arm64 = %q", got.Name)
	}
	if _, ok := selectImage("windows", "", archARM, []imageCandidate{img("windows-server-2025-dc-v20261101", "X86_64", "", t2)}); ok {
		t.Error("windows arm64 picked an x86_64 image")
	}
}

func TestMachineArch(t *testing.T) {
	for _, tc := range []struct {
		mt   *compute.MachineType
		want string
	}{
		{nil, archX86},
		{&compute.MachineType{Name: "e2-medium"}, archX86},
		{&compute.MachineType{Name: "e2-medium", Architecture: "ARCHITECTURE_UNSPECIFIED"}, archX86},
		{&compute.MachineType{Name: "t2a-standard-4"}, archARM},
		{&compute.MachineType{Name: "c4a-highcpu-8"}, archARM},
		{&compute.MachineType{Name: "n4a-standard-2"}, archARM},
		{&compute.MachineType{Name: "a4x-highgpu-4g"}, archARM},
		{&compute.MachineType{Name: "c4-standard-8"}, archX86},
		{&compute.MachineType{Name: "x9-new-1", Architecture: "arm64"}, archARM},
		{&compute.MachineType{Name: "c4a-standard-1", Architecture: "X86_64"}, archX86},
	} {
		if got := machineArch(tc.mt); got != tc.want {
			t.Errorf("machineArch(%+v) = %s, want %s", tc.mt, got, tc.want)
		}
	}
}

func TestParseImagePath(t *testing.T) {
	for in, want := range map[string]string{
		"projects/debian-cloud/global/images/debian-12-bookworm-v1":                           "debian-cloud|false|debian-12-bookworm-v1",
		"projects/debian-cloud/global/images/family/debian-12":                                "debian-cloud|true|debian-12",
		"https://www.googleapis.com/compute/v1/projects/my-proj/global/images/golden-image-1": "my-proj|false|golden-image-1",
	} {
		p, fam, name, err := parseImagePath(in)
		got := p + "|" + map[bool]string{true: "true", false: "false"}[fam] + "|" + name
		if err != nil || got != want {
			t.Errorf("parseImagePath(%q) = %s, %v; want %s", in, got, err, want)
		}
	}
	for _, bad := range []string{"debian-12", "projects/x/images/y", "projects/p/global/images/", "global/images/family/debian-12"} {
		if _, _, _, err := parseImagePath(bad); !errors.Is(err, app.ErrUsage) {
			t.Errorf("parseImagePath(%q) = %v, want a usage error", bad, err)
		}
	}
}
