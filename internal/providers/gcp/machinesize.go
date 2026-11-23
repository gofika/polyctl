package gcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/gofika/polyctl/internal/platform"
)

// e2Preset is a predefined E2 machine type and its shape.
type e2Preset struct {
	Name   string
	Cores  int
	MemMiB int
}

// e2Presets are the predefined E2 machine types, in the order a size
// prefers them when two share a shape: the shared-core types first, then
// standard, highcpu and highmem.
var e2Presets = func() []e2Preset {
	p := []e2Preset{
		{"e2-micro", 2, 1024},
		{"e2-small", 2, 2048},
		{"e2-medium", 2, 4096},
	}
	for _, n := range []int{2, 4, 8, 16, 32} {
		p = append(p, e2Preset{"e2-standard-" + strconv.Itoa(n), n, 4 * n * 1024})
	}
	for _, n := range []int{2, 4, 8, 16, 32} {
		p = append(p, e2Preset{"e2-highcpu-" + strconv.Itoa(n), n, n * 1024})
	}
	for _, n := range []int{2, 4, 8, 16} {
		p = append(p, e2Preset{"e2-highmem-" + strconv.Itoa(n), n, 8 * n * 1024})
	}
	return p
}()

// E2 custom machine type limits: an even number of 2 to 32 vCPUs, 0.5 to
// 8 GiB of memory per vCPU, at most 128 GiB, in multiples of 256 MiB.
const (
	e2CustomMinCores     = 2
	e2CustomMaxCores     = 32
	e2CustomMinMiBPerCPU = 512
	e2CustomMaxMiBPerCPU = 8192
	e2CustomMaxMiB       = 128 * 1024
	e2CustomMiBStep      = 256
)

// e2ProbeType is a predefined E2 type read to tell whether a zone offers
// E2 machine types at all before a custom one is chosen.
const e2ProbeType = "e2-standard-2"

// e2PresetFor returns the preferred predefined E2 type of exactly that
// shape, or "".
func e2PresetFor(cores, memMiB int) string {
	for _, p := range e2Presets {
		if p.Cores == cores && p.MemMiB == memMiB {
			return p.Name
		}
	}
	return ""
}

// e2CustomFits reports whether an E2 custom type can have that shape.
func e2CustomFits(cores, memMiB int) bool {
	return cores >= e2CustomMinCores && cores <= e2CustomMaxCores && cores%2 == 0 &&
		memMiB >= cores*e2CustomMinMiBPerCPU && memMiB <= cores*e2CustomMaxMiBPerCPU &&
		memMiB <= e2CustomMaxMiB && memMiB%e2CustomMiBStep == 0
}

// e2CustomName is the machine type name of an E2 custom shape.
func e2CustomName(cores, memMiB int) string {
	return fmt.Sprintf("e2-custom-%d-%d", cores, memMiB)
}

// nearestE2Size returns the E2 shape closest to cores and memMiB that a
// predefined or custom type has: the vCPUs raised to an even number within
// 2..32, the memory brought within the per-vCPU limits and rounded up to a
// multiple of 256 MiB.
func nearestE2Size(cores, memMiB int) (int, int) {
	c := max(cores, e2CustomMinCores)
	if c%2 == 1 {
		c++
	}
	c = min(c, e2CustomMaxCores)
	hi := min(c*e2CustomMaxMiBPerCPU, e2CustomMaxMiB)
	m := min(max(memMiB, c*e2CustomMinMiBPerCPU), hi)
	if r := m % e2CustomMiBStep; r != 0 {
		m += e2CustomMiBStep - r
		if m > hi {
			m -= e2CustomMiBStep
		}
	}
	return c, m
}

// sizeText writes a shape as a size: "2H4G", "2H0.5G".
func sizeText(cores, memMiB int) string {
	return fmt.Sprintf("%dH%sG", cores, strconv.FormatFloat(float64(memMiB)/1024, 'f', -1, 64))
}

// machineChoice is the machine type a size was resolved to.
type machineChoice struct {
	Size   platform.TypeShorthand
	Type   string
	Zone   string
	Custom bool
}

func (m machineChoice) kind() string {
	if m.Custom {
		return "E2 custom"
	}
	return "E2 predefined"
}

// note is the line printed on stderr: "2H4G -> e2-medium (us-central1-a,
// E2 predefined)".
func (m machineChoice) note() string {
	return fmt.Sprintf("%s -> %s (%s, %s)", m.Size, m.Type, m.Zone, m.kind())
}

// label is what the change report adds to the type: "(2H4G)", or
// "(2H3G, E2 custom)".
func (m machineChoice) label() string {
	if m.Custom {
		return fmt.Sprintf("(%s, %s)", m.Size, m.kind())
	}
	return fmt.Sprintf("(%s)", m.Size)
}

// resolveMachineSize resolves a <cores>H<memory>G size to a machine type
// of zone (read-only; done on every run, in a dry run too): the predefined
// E2 type of exactly that shape when the zone has it, else an E2 custom
// type when that shape is a valid one and the zone offers E2. No fit is
// ErrNotFound (exit code 4).
func (c *client) resolveMachineSize(ctx context.Context, zone string, s platform.TypeShorthand) (machineChoice, error) {
	mem := s.MemoryMiB()
	if p := e2PresetFor(s.Cores, mem); p != "" {
		_, err := c.machineType(ctx, zone, p)
		if err == nil {
			return machineChoice{Size: s, Type: p, Zone: zone}, nil
		}
		if !errors.Is(err, platform.ErrInvalidInput) {
			return machineChoice{}, err
		}
	}
	if !e2CustomFits(s.Cores, mem) {
		nc, nm := nearestE2Size(s.Cores, mem)
		near := e2PresetFor(nc, nm)
		if near == "" {
			near = e2CustomName(nc, nm)
		}
		return machineChoice{}, fmt.Errorf("%w: no predefined or custom E2 machine type of %s (%d vCPUs, %s GiB) in zone %s of project %s "+
			"(a custom E2 type needs an even number of 2 to 32 vCPUs, 0.5 to 8 GiB of memory per vCPU, at most 128 GiB, in multiples of 0.25 GiB): "+
			"the nearest E2 size is %s (%s); pass that, or an exact machine type with --machine-type",
			platform.ErrNotFound, s, s.Cores, s.Memory(), zone, c.project, sizeText(nc, nm), near)
	}
	if _, err := c.machineType(ctx, zone, e2ProbeType); err != nil {
		if errors.Is(err, platform.ErrInvalidInput) {
			return machineChoice{}, fmt.Errorf("%w: zone %s of project %s offers no E2 machine types for size %s: pass another --zone, or an exact machine type with --machine-type",
				platform.ErrNotFound, zone, c.project, s)
		}
		return machineChoice{}, err
	}
	return machineChoice{Size: s, Type: e2CustomName(s.Cores, mem), Zone: zone, Custom: true}, nil
}
