package gcp

import (
	"context"
	"slices"
	"sort"
	"strings"

	"google.golang.org/api/compute/v1"
)

// The catalogs the interactive flow offers: zones, regions and machine
// types, each listed with only what can be used (UP, not deprecated,
// x86_64).

// deprecated reports a Deprecated status that is set to anything but
// ACTIVE: a deprecated, obsolete or deleted zone, region or machine type.
func deprecated(d *compute.DeprecationStatus) bool {
	return d != nil && d.State != "" && !strings.EqualFold(d.State, "ACTIVE")
}

// listZonesUp lists the zones of the project that are UP and not
// deprecated, sorted by name.
func (c *client) listZonesUp(ctx context.Context) ([]*compute.Zone, error) {
	var out []*compute.Zone
	err := c.compute.Zones.List(c.project).Pages(ctx, func(l *compute.ZoneList) error {
		for _, z := range l.Items {
			if z.Status == "UP" && !deprecated(z.Deprecated) {
				out = append(out, z)
			}
		}
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// listRegionsUp lists the regions of the project that are UP and not
// deprecated, sorted by name.
func (c *client) listRegionsUp(ctx context.Context) ([]*compute.Region, error) {
	var out []*compute.Region
	err := c.compute.Regions.List(c.project).Pages(ctx, func(l *compute.RegionList) error {
		for _, r := range l.Items {
			if r.Status == "UP" && !deprecated(r.Deprecated) {
				out = append(out, r)
			}
		}
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// pickMachineFamilies are the machine families the type pick offers: the
// current general-purpose and compute-optimized x86_64 families. Older
// generations (N1), Arm families, accelerator (GPU) and memory-optimized
// families are left out; a type of theirs can still be named with
// --machine-type.
var pickMachineFamilies = []string{"e2", "n4", "n4d", "n2", "n2d", "c4", "c4d", "c3", "c3d", "t2d"}

// usableMachineType reports a machine type the pick offers: x86_64, not
// deprecated, without accelerators, of a family of pickMachineFamilies,
// not bare metal.
func usableMachineType(mt *compute.MachineType) bool {
	if mt == nil || machineArch(mt) != archX86 || deprecated(mt.Deprecated) || len(mt.Accelerators) > 0 {
		return false
	}
	family, _, _ := strings.Cut(strings.ToLower(mt.Name), "-")
	return slices.Contains(pickMachineFamilies, family) && !strings.Contains(mt.Name, "-metal")
}

// listMachineTypes lists the machine types of a zone that the pick offers
// (usableMachineType).
func (c *client) listMachineTypes(ctx context.Context, zone string) ([]*compute.MachineType, error) {
	var out []*compute.MachineType
	err := c.compute.MachineTypes.List(c.project, zone).Pages(ctx, func(l *compute.MachineTypeList) error {
		for _, mt := range l.Items {
			if usableMachineType(mt) {
				out = append(out, mt)
			}
		}
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}
