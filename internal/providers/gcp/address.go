package gcp

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// Static addresses of an instance. Compute Engine does not stop anyone
// from deleting an address that is IN_USE (the instance keeps the IP as an
// ephemeral one, and loses it at the next stop), so polyctl deletes
// RESERVED addresses only.

const (
	addrReserved = "RESERVED"
	addrInUse    = "IN_USE"

	addrExternal = "EXTERNAL"
	addrInternal = "INTERNAL"
	// purposeSharedVIP is the purpose of an internal address that several
	// internal forwarding rules (the :80 and :443 rules of a load
	// balancer) share.
	purposeSharedVIP = "SHARED_LOADBALANCER_VIP"
)

// getAddress reads a regional address, nil when it does not exist.
func (c *client) getAddress(ctx context.Context, region, name string) (*compute.Address, error) {
	a, err := c.compute.Addresses.Get(c.project, region, name).Context(ctx).Do()
	if err != nil {
		err = computeErr(err)
		if errors.Is(err, platform.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	return a, nil
}

// insertAddress reserves an address, waits for the operation and reads it
// back (the IP is known right after the operation).
func (c *client) insertAddress(ctx context.Context, region string, a *compute.Address) (*compute.Address, error) {
	op, err := c.compute.Addresses.Insert(c.project, region, a).Context(ctx).Do()
	if err != nil {
		return nil, computeErr(err)
	}
	if err := c.waitRegionOp(ctx, region, op); err != nil {
		return nil, err
	}
	got, err := c.getAddress(ctx, region, a.Name)
	if err != nil {
		return nil, err
	}
	if got == nil {
		return nil, fmt.Errorf("address %s was reserved but cannot be read back", a.Name)
	}
	return got, nil
}

// deleteAddress releases an address and waits for the operation.
func (c *client) deleteAddress(ctx context.Context, region, name string) error {
	op, err := c.compute.Addresses.Delete(c.project, region, name).Context(ctx).Do()
	if err != nil {
		return computeErr(err)
	}
	return c.waitRegionOp(ctx, region, op)
}

// listAddresses lists the addresses of a region.
func (c *client) listAddresses(ctx context.Context, region string) ([]*compute.Address, error) {
	var out []*compute.Address
	err := c.compute.Addresses.List(c.project, region).Pages(ctx, func(l *compute.AddressList) error {
		out = append(out, l.Items...)
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// addressByIP finds the address of a type holding ip.
func addressByIP(list []*compute.Address, ip, typ string) *compute.Address {
	for _, a := range list {
		if a.Address == ip && addressType(a) == typ {
			return a
		}
	}
	return nil
}

// addressType is the type of an address; unspecified means EXTERNAL.
func addressType(a *compute.Address) string {
	if a.AddressType == "" {
		return addrExternal
	}
	return a.AddressType
}

// users names the resources using an address (their last path segments).
func users(a *compute.Address) string {
	var out []string
	for _, u := range a.Users {
		out = append(out, lastSegment(u))
	}
	if len(out) == 0 {
		return "another resource"
	}
	return strings.Join(out, ", ")
}

// usedOnlyBy reports whether instance (its self link or name) is the only
// user of an address.
func usedOnlyBy(a *compute.Address, instance string) bool {
	if len(a.Users) == 0 {
		return false
	}
	for _, u := range a.Users {
		if u != instance && lastSegment(u) != lastSegment(instance) {
			return false
		}
	}
	return true
}

// subnetURL is the regional subnetwork path addresses and NICs take.
func (c *client) subnetURL(region, subnet string) string {
	return "projects/" + c.project + "/regions/" + region + "/subnetworks/" + subnet
}

// externalAddressStep is the create step of the external static address
// name: an existing reserved address is reused (unchanged), a missing one
// is reserved. An address of that name that another resource uses, or
// that is internal, stops create before anything is written. The IP is
// stored in *ip once known.
func (c *client) externalAddressStep(region, name string, existing *compute.Address, ip *string) (platform.Step, error) {
	res := "address/" + name
	if existing != nil {
		if addressType(existing) != addrExternal {
			return platform.Step{}, fmt.Errorf("address %s in %s is %s, not external: rename it, set naming.gcp_instance_external_ip, or pass --static-ip=false", name, region, strings.ToLower(addressType(existing)))
		}
		if existing.Status == addrInUse {
			return platform.Step{}, fmt.Errorf("address %s (%s) in %s is already used by %s: release it, or pass --static-ip=false", name, existing.Address, region, users(existing))
		}
		*ip = existing.Address
		return platform.Step{Resource: res, Action: platform.Unchanged, ID: existing.Address, Desc: existing.Address}, nil
	}
	return platform.Step{Resource: res, Action: platform.Created, Desc: "EXTERNAL PREMIUM", Apply: func(ctx context.Context) (platform.Change, error) {
		a, err := c.insertAddress(ctx, region, &compute.Address{Name: name, NetworkTier: "PREMIUM", AddressType: addrExternal})
		if err != nil {
			return platform.Change{}, err
		}
		*ip = a.Address
		return platform.Change{ID: a.Address, Detail: a.Address}, nil
	}}, nil
}

// internalAddressStep is the create step of the internal static address
// name in subnet: an existing address in that subnet is reused; one that
// is RESERVED in another subnet is deleted and reserved again in subnet; a
// missing one is reserved. The subnet is always given: without it Compute
// Engine silently reserves the address in the "default" subnet. An
// address that another resource uses stops create before anything is
// written.
func (c *client) internalAddressStep(region, name, subnet string, existing *compute.Address, ip *string) (platform.Step, error) {
	res := "address/" + name
	insert := func(ctx context.Context) (*compute.Address, error) {
		return c.insertAddress(ctx, region, &compute.Address{Name: name, AddressType: addrInternal, Purpose: "GCE_ENDPOINT", Subnetwork: c.subnetURL(region, subnet)})
	}
	if existing != nil {
		if addressType(existing) != addrInternal {
			return platform.Step{}, fmt.Errorf("address %s in %s is %s, not internal: rename it, set naming.gcp_instance_internal_ip, or pass --static-ip=false", name, region, strings.ToLower(addressType(existing)))
		}
		if existing.Status == addrInUse {
			return platform.Step{}, fmt.Errorf("address %s (%s) in %s is already used by %s: release it, or pass --static-ip=false", name, existing.Address, region, users(existing))
		}
		was := lastSegment(existing.Subnetwork)
		if was == subnet {
			*ip = existing.Address
			return platform.Step{Resource: res, Action: platform.Unchanged, ID: existing.Address, Desc: existing.Address + " (subnet " + subnet + ")"}, nil
		}
		return platform.Step{Resource: res, Action: platform.Updated, Desc: fmt.Sprintf("re-reserve in subnet %s (was %s in subnet %s)", subnet, existing.Address, was),
			Apply: func(ctx context.Context) (platform.Change, error) {
				if err := c.deleteAddress(ctx, region, name); err != nil {
					return platform.Change{}, err
				}
				a, err := insert(ctx)
				if err != nil {
					return platform.Change{}, err
				}
				*ip = a.Address
				return platform.Change{ID: a.Address, Detail: fmt.Sprintf("%s (subnet %s, re-reserved from subnet %s)", a.Address, subnet, was)}, nil
			}}, nil
	}
	return platform.Step{Resource: res, Action: platform.Created, Desc: "INTERNAL subnet " + subnet, Apply: func(ctx context.Context) (platform.Change, error) {
		a, err := insert(ctx)
		if err != nil {
			return platform.Change{}, err
		}
		*ip = a.Address
		return platform.Change{ID: a.Address, Detail: a.Address + " (subnet " + subnet + ")"}, nil
	}}, nil
}

// promoteSpec describes the promotion of an instance's ephemeral IP to a
// static address before the instance is stopped.
type promoteSpec struct {
	Region, Name, IP, Type string
	// SubnetURL is the NIC's subnetwork (internal addresses only).
	SubnetURL string
	// NetworkTier is the tier of the access config holding an external IP
	// (an ephemeral IP can only become a static address of its own tier);
	// empty means PREMIUM.
	NetworkTier string
	// Fatal makes a failure stop the command (external); otherwise it is
	// a warning and a skipped row (internal).
	Fatal bool
	// List is the region's addresses; ByName the address already called
	// Name, if any.
	List   []*compute.Address
	ByName *compute.Address
	Warn   func(string)
}

// tierOr is the network tier, PREMIUM when the API reports none.
func tierOr(tier string) string {
	if tier == "" {
		return "PREMIUM"
	}
	return tier
}

// accessTier is the network tier of the instance's access config that
// holds ip, "" when none does.
func accessTier(in *compute.Instance, ip string) string {
	for _, nic := range in.NetworkInterfaces {
		for _, ac := range nic.AccessConfigs {
			if ac.NatIP == ip && ip != "" {
				return ac.NetworkTier
			}
		}
	}
	return ""
}

// promoteStep returns the step that makes ip static: unchanged when an
// address already holds it, else an address Name reserved with that IP
// (Compute Engine accepts the IP a running instance uses). ok is false
// when there is no IP to promote.
func (c *client) promoteStep(p promoteSpec) (step platform.Step, ok bool, err error) {
	if p.IP == "" {
		return platform.Step{}, false, nil
	}
	if a := addressByIP(p.List, p.IP, p.Type); a != nil {
		return platform.Step{Resource: "address/" + a.Name, Action: platform.Unchanged, ID: p.IP, Desc: p.IP + " already static"}, true, nil
	}
	res := "address/" + p.Name
	if p.ByName != nil {
		msg := fmt.Sprintf("address %s already exists with IP %s, while the instance uses %s: the IP cannot be made static under that name", p.Name, p.ByName.Address, p.IP)
		if p.Fatal {
			return platform.Step{}, false, fmt.Errorf("%s; release or rename that address first (otherwise the IP changes when the instance stops)", msg)
		}
		return platform.Step{Resource: res, Action: platform.Skipped, Desc: msg}, true, nil
	}
	body := &compute.Address{Name: p.Name, Address: p.IP, AddressType: p.Type}
	if p.Type == addrExternal {
		body.NetworkTier = tierOr(p.NetworkTier)
	} else {
		body.Purpose = "GCE_ENDPOINT"
		body.Subnetwork = p.SubnetURL
	}
	return platform.Step{Resource: res, Action: platform.Created, ID: p.IP, Desc: "promote " + p.IP + " to a static " + strings.ToLower(p.Type) + " address",
		Apply: func(ctx context.Context) (platform.Change, error) {
			_, err := c.insertAddress(ctx, p.Region, body)
			if isReason(err, "alreadyExists") {
				// Reserved meanwhile: fine when it holds the IP.
				a, gerr := c.getAddress(ctx, p.Region, p.Name)
				if gerr == nil && a != nil && a.Address == p.IP {
					return platform.Change{Action: platform.Unchanged, Detail: p.IP + " already static"}, nil
				}
			}
			if err != nil {
				if p.Fatal {
					return platform.Change{}, fmt.Errorf("promote %s to a static address (the instance was not stopped): %w", p.IP, err)
				}
				msg := fmt.Sprintf("could not promote %s to a static address: %v", p.IP, err)
				if p.Warn != nil {
					p.Warn("warning: " + msg)
				}
				return platform.Change{Action: platform.Skipped, Detail: msg}, nil
			}
			return platform.Change{Detail: p.IP + " is static now"}, nil
		}}, true, nil
}

// releaseStep is the delete --release-ips step of the address name: a
// RESERVED address is deleted, one in use by something else is skipped,
// a missing one is skipped. existing is the address as observed before the
// instance was deleted, instance the instance's self link.
func (c *client) releaseStep(region, name string, existing *compute.Address, instance string) platform.Step {
	res := "address/" + name
	if existing == nil {
		return platform.Step{Resource: res, Action: platform.Skipped, Desc: "does not exist"}
	}
	if existing.Status == addrInUse && !usedOnlyBy(existing, instance) {
		return platform.Step{Resource: res, Action: platform.Skipped, ID: existing.Address, Desc: "in use by " + users(existing) + "; kept"}
	}
	return platform.Step{Resource: res, Action: platform.Deleted, ID: existing.Address, Desc: existing.Address, Apply: func(ctx context.Context) (platform.Change, error) {
		a, err := c.getAddress(ctx, region, name)
		if err != nil {
			return platform.Change{}, err
		}
		if a == nil {
			return platform.Change{Action: platform.Skipped, Detail: "does not exist any more"}, nil
		}
		if a.Status != addrReserved {
			return platform.Change{Action: platform.Skipped, Detail: fmt.Sprintf("%s by %s; kept", strings.ToLower(a.Status), users(a))}, nil
		}
		if err := c.deleteAddress(ctx, region, name); err != nil {
			return platform.Change{}, err
		}
		return platform.Change{Detail: a.Address + " released"}, nil
	}}
}
