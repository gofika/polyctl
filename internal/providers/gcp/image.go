package gcp

import (
	"context"
	"errors"
	"fmt"
	"regexp"
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
}

func (c imageCandidate) created() time.Time {
	t, err := time.Parse(time.RFC3339Nano, c.Created)
	if err != nil {
		return time.Time{}
	}
	return t
}

// unusable reports deprecated, obsolete and deleted images.
func (c imageCandidate) unusable() bool {
	switch strings.ToUpper(c.Deprecated) {
	case "DEPRECATED", "OBSOLETE", "DELETED":
		return true
	}
	return false
}

var (
	debianMajorRe = regexp.MustCompile(`debian-(\d+)`)
	ubuntuVerRe   = regexp.MustCompile(`ubuntu-(\d{2})(\d{2})`)
)

// standardVariantRe matches the standard image of a family whose
// projects also hold variants with the same creation time
// (rocky-linux-10-optimized-gcp-v..., rhel-9-8-eus-lvm-v...): only
// "<prefix>-<major>-vYYYYMMDD" names are candidates.
func standardVariantRe(prefix, major string) *regexp.Regexp {
	if major == "" {
		major = `\d+`
	} else {
		major = regexp.QuoteMeta(major)
	}
	return regexp.MustCompile(`^` + regexp.QuoteMeta(prefix) + `-(` + major + `)-v\d{8}`)
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

// ranked is a candidate with the version number it is ranked by (-1 when
// the OS is ranked by creation time only).
type ranked struct {
	imageCandidate
	version int
}

// selectImage picks the image of osName (and version, "" for the latest)
// among the images of its project: deprecated, obsolete, deleted and
// non-x86_64 images are left out, the OS's name rules are applied, and the
// newest is chosen: by version number for debian and ubuntu without a
// version and for the standard images of rocky, almalinux and rhel (a
// patch image of an old major version can be newer than the newest major
// version), by creation time otherwise. ok is false when nothing matches.
func selectImage(osName, version string, images []imageCandidate) (imageCandidate, bool) {
	version = strings.TrimSpace(version)
	var cands []ranked
	for _, img := range images {
		if img.unusable() {
			continue
		}
		if a := strings.ToUpper(img.Architecture); a != "" && a != "X86_64" {
			continue
		}
		name := strings.ToLower(img.Name)
		r := ranked{imageCandidate: img, version: -1}
		keep := false
		switch osName {
		case "debian":
			if strings.Contains(name, "backports") {
				break
			}
			if version != "" {
				keep = strings.Contains(name, "debian-"+version+"-") || strings.HasSuffix(name, "debian-"+version)
			} else if m := debianMajorRe.FindStringSubmatch(name); m != nil {
				keep = true
				r.version, _ = strconv.Atoi(m[1])
			}
		case "ubuntu":
			if containsAny(name, "minimal", "pro", "accelerator", "nvidia") {
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
			if containsAny(name, "sap", "byos") {
				break
			}
			if m := standardVariantRe(prefix, majorOf(version)).FindStringSubmatch(name); m != nil {
				keep = true
				r.version, _ = strconv.Atoi(m[1])
			}
		case "windows":
			if containsAny(name, "core", "sql") {
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

// resolveImage finds the latest x86_64 public image of osName (version ""
// for the latest release): every page of the OS's image project is listed
// (most images there are deprecated) and selectImage picks one. Nothing
// found is "not found" (exit code 4): polyctl never falls back to another
// system.
func (c *client) resolveImage(ctx context.Context, osName, version string) (imageChoice, error) {
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
	img, ok := selectImage(osName, version, all)
	if !ok {
		what := osName
		if version != "" {
			what += " " + version
		}
		return imageChoice{}, fmt.Errorf("%w: no current x86_64 image of %s in project %s; check --os / --os-version, or pass --image projects/<project>/global/images/<name>", platform.ErrNotFound, what, project)
	}
	min := img.DiskSizeGB
	known := min > 0
	if !known {
		min = defaultImageMinDiskGB
	}
	return imageChoice{Path: "projects/" + project + "/global/images/" + img.Name, Name: img.Name, Label: osName, MinDiskGB: min, Known: known}, nil
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
	return imageChoice{Path: "projects/" + project + "/global/images/" + img.Name, Name: img.Name, Label: "custom", MinDiskGB: min, Known: known}, nil
}
