package gcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// osImageProjects maps --os to the public image project that holds its
// images.
var osImageProjects = map[string]string{
	"debian":    "debian-cloud",
	"ubuntu":    "ubuntu-os-cloud",
	"centos":    "centos-cloud",
	"rocky":     "rocky-linux-cloud",
	"almalinux": "almalinux-cloud",
	"alma":      "almalinux-cloud",
	"rhel":      "rhel-cloud",
	"windows":   "windows-cloud",
	"suse":      "suse-cloud",
	"opensuse":  "opensuse-cloud",
	"cos":       "cos-cloud",
}

// supportedOS lists --os values in the order the help shows them.
var supportedOS = []string{"debian", "ubuntu", "centos", "rocky", "almalinux", "alma", "rhel", "windows", "suse", "opensuse", "cos"}

// defaultImageMinDiskGB is the boot disk minimum assumed for an --image
// whose size cannot be read.
const defaultImageMinDiskGB = 10

// Image and machine type architectures, as the Compute Engine API writes
// them.
const (
	archX86 = "X86_64"
	archARM = "ARM64"
)

// armMachineFamilies are the Arm machine families (Ampere Altra T2A, Axion
// C4A and N4A, Grace A4X), used only when the API does not report the
// architecture of a machine type.
var armMachineFamilies = []string{"t2a", "c4a", "n4a", "a4x"}

// machineArch is the architecture of a machine type: the Architecture the
// API reports, else ARM64 for the families of armMachineFamilies and
// X86_64 for every other one.
func machineArch(mt *compute.MachineType) string {
	if mt == nil {
		return archX86
	}
	switch a := strings.ToUpper(mt.Architecture); a {
	case archX86, archARM:
		return a
	}
	family, _, _ := strings.Cut(strings.ToLower(mt.Name), "-")
	if slices.Contains(armMachineFamilies, family) {
		return archARM
	}
	return archX86
}

// archText is an architecture in messages: "x86_64" or "arm64".
func archText(arch string) string { return strings.ToLower(arch) }

// imageCandidate is the part of a public image that the selection looks at.
type imageCandidate struct {
	Name         string
	Architecture string // "X86_64", "ARM64" or "" (old images)
	Deprecated   string // Deprecated.State: "", "ACTIVE", "DEPRECATED", "OBSOLETE", "DELETED"
	Created      string // CreationTimestamp, RFC 3339
	DiskSizeGB   int64
}

// imageChoice is the image create boots from.
type imageChoice struct {
	// Path is the image as Insert takes it: projects/<p>/global/images/<name>
	// (or .../family/<f> for an --image family that could not be read).
	Path string
	// Name is the image name, for reports.
	Name string
	// Label names the image in reports: the --os value, or "custom".
	Label string
	// MinDiskGB is the smallest boot disk the image accepts.
	MinDiskGB int64
	// Known says MinDiskGB was read from the image rather than assumed.
	Known bool
	// Arch is the architecture of the image ("" when unknown).
	Arch string
	// Windows says the image declares the WINDOWS guest OS feature (an
	// image of one's own built from a Windows Server image).
	Windows bool
}

func (c imageCandidate) created() time.Time {
	t, err := time.Parse(time.RFC3339Nano, c.Created)
	if err != nil {
		return time.Time{}
	}
	return t
}

// arch is the architecture of the image: the one it carries, else (old
// images carry none) ARM64 for a name with an "arm64" part and X86_64
// otherwise.
func (c imageCandidate) arch() string {
	if a := strings.ToUpper(c.Architecture); a == archX86 || a == archARM {
		return a
	}
	if hasToken(strings.ToLower(c.Name), "arm64", "aarch64") {
		return archARM
	}
	return archX86
}

// unusable reports deprecated, obsolete and deleted images.
func (c imageCandidate) unusable() bool {
	switch strings.ToUpper(c.Deprecated) {
	case "DEPRECATED", "OBSOLETE", "DELETED":
		return true
	}
	return false
}

var ubuntuVerRe = regexp.MustCompile(`ubuntu-(\d{2})(\d{2})`)

// debianImageRe matches the standard Debian images of debian-cloud,
// "debian-<major>-<codename>[-amd64|-arm64]-vYYYYMMDD"
// (debian-13-trixie-v20261116, debian-12-bookworm-arm64-v20261116), with
// the major version (major "" for any) as the first group: other variants
// do not match (selectImage also drops names with a "backports" part).
func debianImageRe(major string) *regexp.Regexp {
	if major == "" {
		major = `\d+`
	} else {
		major = regexp.QuoteMeta(major)
	}
	return regexp.MustCompile(`^debian-(` + major + `)-[a-z]+(?:-(?:amd64|arm64))?-v\d{8}`)
}

// standardVariantRe matches the standard image of a family whose
// projects also hold variants with the same creation time
// (rocky-linux-10-optimized-gcp-v..., rhel-9-8-eus-lvm-v...): only
// "<prefix>-<major>[-arm64]-vYYYYMMDD" names are candidates.
func standardVariantRe(prefix, major string) *regexp.Regexp {
	if major == "" {
		major = `\d+`
	} else {
		major = regexp.QuoteMeta(major)
	}
	return regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `-(` + major + `)(?:-arm64)?-v\d{8}`)
}

// majorOf returns the major version of --os-version ("9.4" -> "9").
func majorOf(version string) string {
	major, _, _ := strings.Cut(version, ".")
	return major
}

// containsAny reports whether s contains one of subs.
func containsAny(s string, subs ...string) bool {
	for _, sub := range subs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// hasToken reports whether one of the hyphen-separated parts of an image
// name is one of tokens: "ubuntu-pro-2204-..." has "pro", while a codename
// that merely contains those letters does not.
func hasToken(name string, tokens ...string) bool {
	for _, part := range strings.Split(name, "-") {
		for _, t := range tokens {
			if part == t {
				return true
			}
		}
	}
	return false
}

// ranked is a candidate with the version number it is ranked by (-1 when
// the OS is ranked by creation time only).
type ranked struct {
	imageCandidate
	version int
}

// selectImage picks the image of osName (and version, "" for the latest)
// for arch (X86_64 or ARM64) among the images of its project: deprecated,
// obsolete and deleted images and those of another architecture are left
// out, the OS's name rules are applied, and the newest is chosen: by
// version number for debian, for ubuntu without a version and for the
// standard images of rocky, almalinux and rhel (a patch image of an old
// major version can be newer than the newest major version), by creation
// time otherwise. No version is written into polyctl: a new major
// version is chosen as soon as its images are published. ok is false
// when nothing matches.
func selectImage(osName, version, arch string, images []imageCandidate) (imageCandidate, bool) {
	version = strings.TrimSpace(version)
	var cands []ranked
	for _, img := range images {
		if img.unusable() {
			continue
		}
		if img.arch() != arch {
			continue
		}
		name := strings.ToLower(img.Name)
		r := ranked{imageCandidate: img, version: -1}
		keep := false
		switch osName {
		case "debian":
			if hasToken(name, "backports") {
				break
			}
			if m := debianImageRe(version).FindStringSubmatch(name); m != nil {
				keep = true
				r.version, _ = strconv.Atoi(m[1])
			}
		case "ubuntu":
			if hasToken(name, "minimal", "pro", "accelerator", "nvidia") {
				break
			}
			if version != "" {
				keep = strings.Contains(name, "ubuntu-"+strings.ReplaceAll(version, ".", ""))
			} else if m := ubuntuVerRe.FindStringSubmatch(name); m != nil {
				year, _ := strconv.Atoi(m[1])
				if m[2] == "04" && year%2 == 0 {
					keep = true
					r.version, _ = strconv.Atoi(m[1] + m[2])
				}
			}
		case "centos":
			if version != "" {
				keep = containsAny(name, "centos-"+version+"-", "centos-stream-"+version+"-") ||
					strings.HasSuffix(name, "centos-"+version) || strings.HasSuffix(name, "centos-stream-"+version)
			} else {
				keep = strings.Contains(name, "centos-")
			}
		case "rocky", "almalinux", "alma", "rhel":
			prefix := map[string]string{"rocky": "rocky-linux", "almalinux": "almalinux", "alma": "almalinux", "rhel": "rhel"}[osName]
			if hasToken(name, "sap", "byos") {
				break
			}
			if m := standardVariantRe(prefix, majorOf(version)).FindStringSubmatch(name); m != nil {
				keep = true
				r.version, _ = strconv.Atoi(m[1])
			}
		case "windows":
			if hasToken(name, "core", "sql") {
				break
			}
			if version != "" {
				keep = strings.Contains(name, "windows-server-"+version)
			} else {
				keep = strings.Contains(name, "windows-server")
			}
		default:
			keep = true
		}
		if keep {
			cands = append(cands, r)
		}
	}
	if osName == "centos" && version == "" {
		// CentOS Stream first, the classic releases only without it.
		var stream []ranked
		for _, c := range cands {
			if strings.Contains(strings.ToLower(c.Name), "centos-stream") {
				stream = append(stream, c)
			}
		}
		if len(stream) > 0 {
			cands = stream
		}
	}
	if len(cands) == 0 {
		return imageCandidate{}, false
	}
	sort.SliceStable(cands, func(i, j int) bool {
		if cands[i].version != cands[j].version {
			return cands[i].version > cands[j].version
		}
		ti, tj := cands[i].created(), cands[j].created()
		if !ti.Equal(tj) {
			return ti.After(tj)
		}
		return cands[i].Name > cands[j].Name
	})
	return cands[0].imageCandidate, true
}

func candidateFrom(img *compute.Image) imageCandidate {
	c := imageCandidate{Name: img.Name, Architecture: img.Architecture, Created: img.CreationTimestamp, DiskSizeGB: img.DiskSizeGb}
	if img.Deprecated != nil {
		c.Deprecated = img.Deprecated.State
	}
	return c
}

// resolveImage finds the latest public image of osName (version "" for
// the latest release) for arch, the architecture of the machine type
// (machineType and zone name it in messages): every page of the OS's
// image project is listed (most images there are deprecated) and
// selectImage picks one. Nothing found is "not found" (exit code 4):
// polyctl never falls back to another system or architecture.
func (c *client) resolveImage(ctx context.Context, osName, version, arch, machineType, zone string) (imageChoice, error) {
	project, ok := osImageProjects[osName]
	if !ok {
		return imageChoice{}, app.UsageErrf("--os %q is not supported (supported: %s)", osName, strings.Join(supportedOS, ", "))
	}
	var all []imageCandidate
	err := c.compute.Images.List(project).MaxResults(500).Pages(ctx, func(l *compute.ImageList) error {
		for _, img := range l.Items {
			all = append(all, candidateFrom(img))
		}
		return nil
	})
	if err != nil {
		return imageChoice{}, computeErr(err)
	}
	img, ok := selectImage(osName, version, arch, all)
	if !ok {
		what := osName
		if version != "" {
			what += " " + version
		}
		return imageChoice{}, fmt.Errorf("%w: no current %s image of %s in project %s for machine type %s (zone %s, region %s); check --os / --os-version, or pass --image projects/<project>/global/images/<name>",
			platform.ErrNotFound, archText(arch), what, project, machineType, zone, regionOf(zone))
	}
	min := img.DiskSizeGB
	known := min > 0
	if !known {
		min = defaultImageMinDiskGB
	}
	return imageChoice{Path: "projects/" + project + "/global/images/" + img.Name, Name: img.Name, Label: osName, MinDiskGB: min, Known: known, Arch: img.arch()}, nil
}

// imagePathRe matches --image: projects/<p>/global/images/<name> or
// projects/<p>/global/images/family/<family>.
var imagePathRe = regexp.MustCompile(`^projects/([a-z][-a-z0-9.:]*[a-z0-9])/global/images/(?:(family)/)?([a-z][-a-z0-9]*)$`)

// parseImagePath validates --image and returns its project, whether it
// names a family, and the image or family name. A full API URL is
// accepted too.
func parseImagePath(s string) (project string, family bool, name string, err error) {
	p := strings.TrimSpace(s)
	for _, prefix := range []string{"https://www.googleapis.com/compute/v1/", "https://compute.googleapis.com/compute/v1/"} {
		p = strings.TrimPrefix(p, prefix)
	}
	m := imagePathRe.FindStringSubmatch(p)
	if m == nil {
		return "", false, "", app.UsageErrf("--image %q: expected projects/<project>/global/images/<name> or projects/<project>/global/images/family/<family>", s)
	}
	return m[1], m[2] == "family", m[3], nil
}

// explicitImage reads --image to learn its minimum disk size. An image
// that does not exist is "not found"; when it cannot be read for another
// reason (no permission on that project), it is used as given with a
// minimum of 10 GB, and warn says so.
func (c *client) explicitImage(ctx context.Context, path string, warn func(string)) (imageChoice, error) {
	project, family, name, err := parseImagePath(path)
	if err != nil {
		return imageChoice{}, err
	}
	var img *compute.Image
	if family {
		img, err = c.compute.Images.GetFromFamily(project, name).Context(ctx).Do()
	} else {
		img, err = c.compute.Images.Get(project, name).Context(ctx).Do()
	}
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return imageChoice{}, fmt.Errorf("image %s: %w", path, err)
		}
		warn(fmt.Sprintf("warning: cannot read image %s (%v); assuming a minimum boot disk of %d GB", path, err, defaultImageMinDiskGB))
		p := "projects/" + project + "/global/images/" + name
		if family {
			p = "projects/" + project + "/global/images/family/" + name
		}
		return imageChoice{Path: p, Name: name, Label: "custom", MinDiskGB: defaultImageMinDiskGB}, nil
	}
	cand := candidateFrom(img)
	if cand.unusable() {
		warn(fmt.Sprintf("warning: image %s is %s", img.Name, strings.ToLower(cand.Deprecated)))
	}
	min, known := img.DiskSizeGb, img.DiskSizeGb > 0
	if !known {
		min = defaultImageMinDiskGB
	}
	choice := imageChoice{Path: "projects/" + project + "/global/images/" + img.Name, Name: img.Name, Label: "custom", MinDiskGB: min, Known: known}
	if a := strings.ToUpper(img.Architecture); a == archX86 || a == archARM {
		choice.Arch = a
	}
	for _, f := range img.GuestOsFeatures {
		if f != nil && strings.EqualFold(f.Type, "WINDOWS") {
			choice.Windows = true
		}
	}
	return choice, nil
}
