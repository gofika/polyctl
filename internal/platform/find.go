package platform

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"sync"
)

// IPKind classifies an entry of the IP index of the inventory.
type IPKind string

const (
	// IPInternal is a private address (or prefix) of a resource.
	IPInternal IPKind = "internal"
	// IPExternal is a public address (or prefix) of a resource.
	IPExternal IPKind = "external"
	// IPDNS is a DNS name of a resource (a load balancer's DNS name, a
	// database endpoint, an instance's public or private DNS name).
	IPDNS IPKind = "dns"
	// IPReserved is an address reserved for a resource another inventory
	// row already holds (a GCP static address in use by an instance or a
	// forwarding rule). It annotates the match of that row instead of
	// being a match of its own.
	IPReserved IPKind = "reserved"
)

// IPRef is one address, prefix or DNS name a resource holds. Value is
// canonical: an address as netip.Addr.String() (IPv4-mapped IPv6 unmapped),
// a prefix as the masked netip.Prefix.String(), a DNS name lower case
// without the trailing dot.
type IPRef struct {
	Value string `json:"value" yaml:"value"`
	Kind  IPKind `json:"kind" yaml:"kind"`
}

// CanonicalAddr parses an IP address and returns its canonical text: zone
// dropped, IPv4-mapped IPv6 addresses unmapped (::ffff:192.0.2.1 is
// 192.0.2.1), IPv6 in its compressed lower-case form.
func CanonicalAddr(s string) (netip.Addr, bool) {
	a, err := netip.ParseAddr(strings.TrimSpace(s))
	if err != nil {
		return netip.Addr{}, false
	}
	return a.WithZone("").Unmap(), true
}

// IPAddr returns the IPRef of an address or prefix ("10.1.2.0/24"), or
// false when s is neither (an empty string, a mask without an address).
// A prefix as long as the address is stored as that address.
func IPAddr(kind IPKind, s string) (IPRef, bool) {
	s = strings.TrimSpace(s)
	if s == "" {
		return IPRef{}, false
	}
	if strings.Contains(s, "/") {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return IPRef{}, false
		}
		addr := p.Addr().WithZone("")
		bits := p.Bits()
		if addr.Is4In6() && bits >= 96 {
			addr, bits = addr.Unmap(), bits-96
		}
		if bits == addr.BitLen() {
			return IPRef{Value: addr.String(), Kind: kind}, true
		}
		return IPRef{Value: netip.PrefixFrom(addr, bits).Masked().String(), Kind: kind}, true
	}
	a, ok := CanonicalAddr(s)
	if !ok {
		return IPRef{}, false
	}
	return IPRef{Value: a.String(), Kind: kind}, true
}

// DNSRef returns the IPRef of a DNS name, or false for an empty one.
func DNSRef(name string) (IPRef, bool) {
	n := NormalizeDomain(name)
	if n == "" {
		return IPRef{}, false
	}
	return IPRef{Value: n, Kind: IPDNS}, true
}

// IPSet collects the IPRefs of a resource without duplicates, in the order
// they were added.
type IPSet struct {
	refs []IPRef
	seen map[IPRef]bool
}

// Add adds an address or prefix of the given kind; invalid or empty values
// are skipped.
func (s *IPSet) Add(kind IPKind, values ...string) {
	for _, v := range values {
		if r, ok := IPAddr(kind, v); ok {
			s.add(r)
		}
	}
}

// AddDNS adds DNS names; empty ones are skipped.
func (s *IPSet) AddDNS(names ...string) {
	for _, n := range names {
		if r, ok := DNSRef(n); ok {
			s.add(r)
		}
	}
}

func (s *IPSet) add(r IPRef) {
	if s.seen == nil {
		s.seen = map[IPRef]bool{}
	}
	if s.seen[r] {
		return
	}
	s.seen[r] = true
	s.refs = append(s.refs, r)
}

// Refs returns the collected IPRefs.
func (s *IPSet) Refs() []IPRef { return append([]IPRef(nil), s.refs...) }

// Values returns the values of one kind, in the order added.
func (s *IPSet) Values(kind IPKind) []string {
	out := []string{}
	for _, r := range s.refs {
		if r.Kind == kind {
			out = append(out, r.Value)
		}
	}
	return out
}

// FindKind is what a find query is: an IP address or a DNS name.
type FindKind string

const (
	FindIP  FindKind = "ip"
	FindDNS FindKind = "dns"
)

// FindQuery is a parsed `polyctl find` argument.
type FindQuery struct {
	// Raw is the argument as given.
	Raw  string
	Kind FindKind
	// Value is the canonical address or the normalized DNS name.
	Value string
	// Addr is the address of an IP query.
	Addr netip.Addr
}

// ParseFindQuery parses the argument of find: an IPv4 or IPv6 address
// (canonicalized), else a DNS name (lower case, without the trailing dot).
// Anything that is neither, such as an empty string, a string with spaces
// or a URL, is ErrInvalidInput.
func ParseFindQuery(s string) (FindQuery, error) {
	raw := s
	s = strings.TrimSpace(s)
	if s == "" {
		return FindQuery{}, fmt.Errorf("%w: the query is empty: pass an IP address or a DNS name", ErrInvalidInput)
	}
	if a, ok := CanonicalAddr(s); ok {
		return FindQuery{Raw: raw, Kind: FindIP, Value: a.String(), Addr: a}, nil
	}
	name := strings.ToLower(strings.TrimSuffix(s, "."))
	if name == "" || len(name) > 253 {
		return FindQuery{}, fmt.Errorf("%w: %q is neither an IP address nor a DNS name", ErrInvalidInput, raw)
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return FindQuery{}, fmt.Errorf("%w: %q is neither an IP address nor a DNS name", ErrInvalidInput, raw)
		}
		for _, r := range label {
			if !(r >= 'a' && r <= 'z' || r >= '0' && r <= '9' || r == '-' || r == '_') {
				return FindQuery{}, fmt.Errorf("%w: %q is neither an IP address nor a DNS name", ErrInvalidInput, raw)
			}
		}
	}
	return FindQuery{Raw: raw, Kind: FindDNS, Value: name}, nil
}

// Fields a find match names in matched_field.
const (
	MatchedInternalIP = "internal_ip"
	MatchedExternalIP = "external_ip"
	MatchedDNSName    = "dns_name"
	MatchedEndpoint   = "endpoint"
)

// MatchedField returns the matched_field of a hit of kind on a resource of
// type rt: a database's DNS name is its endpoint.
func MatchedField(kind IPKind, rt ResourceType) string {
	switch kind {
	case IPInternal:
		return MatchedInternalIP
	case IPDNS:
		if rt == ResDBInstance {
			return MatchedEndpoint
		}
		return MatchedDNSName
	}
	return MatchedExternalIP
}

// FindMatch is one resource found by `polyctl find`.
type FindMatch struct {
	Platform ID           `json:"platform" yaml:"platform"`
	Profile  string       `json:"profile" yaml:"profile"`
	Type     ResourceType `json:"type" yaml:"type"`
	ID       string       `json:"id" yaml:"id"`
	Name     string       `json:"name" yaml:"name"`
	// Project is the Google Cloud project of the resource.
	Project      string   `json:"project,omitempty" yaml:"project,omitempty"`
	Region       string   `json:"region" yaml:"region"`
	Zone         string   `json:"zone,omitempty" yaml:"zone,omitempty"`
	State        string   `json:"state" yaml:"state"`
	MatchedField string   `json:"matched_field" yaml:"matched_field"`
	InternalIPs  []string `json:"internal_ips" yaml:"internal_ips"`
	ExternalIPs  []string `json:"external_ips" yaml:"external_ips"`
	DNSNames     []string `json:"dns_names,omitempty" yaml:"dns_names,omitempty"`
	Network      string   `json:"network" yaml:"network"`
	// Subnet is the subnet (or vSwitch) of the matched address, as stored;
	// --detail looks it up.
	Subnet string `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	URL    string `json:"url" yaml:"url"`
	// Note says more about what the match is, as the platform describes it
	// (the description of a network interface without an instance, what an
	// address is bound to).
	Note string `json:"note,omitempty" yaml:"note,omitempty"`
	// Addresses are the static addresses reserved for the resource that
	// hold the queried IP (GCP).
	Addresses []string       `json:"addresses,omitempty" yaml:"addresses,omitempty"`
	Detail    *NetworkDetail `json:"detail,omitempty" yaml:"detail,omitempty"`

	// Data is the stored inventory data of the resource.
	Data json.RawMessage `json:"-" yaml:"-"`
	// Matched is the index value that matched the query: the address, the
	// prefix holding it, or the DNS name. A describer uses it to tell which
	// network interface of a resource holds the address.
	Matched string `json:"-" yaml:"-"`
	// Holders are the ids or names of the resources a reserved address
	// (IPReserved) is in use by, as the describer knows them; its
	// annotation goes to the matches among them, else to every match of
	// the account holding the address.
	Holders []string `json:"-" yaml:"-"`
}

// Holds reports whether an address or prefix value (an IPRef value) holds
// the Matched value of m: equal, or a prefix containing it.
func (m *FindMatch) Holds(value string) bool {
	if value == "" || m.Matched == "" {
		return false
	}
	if value == m.Matched {
		return true
	}
	r, ok := IPAddr(IPInternal, value)
	if !ok {
		return NormalizeDomain(value) == m.Matched
	}
	if r.Value == m.Matched {
		return true
	}
	if p, err := netip.ParsePrefix(r.Value); err == nil {
		if a, ok := CanonicalAddr(m.Matched); ok {
			return p.Contains(a)
		}
	}
	return false
}

// NetworkDetail is what --detail adds to a match: the subnet of the
// matched address, looked up live.
type NetworkDetail struct {
	VPC            string   `json:"vpc,omitempty" yaml:"vpc,omitempty"`
	Subnet         string   `json:"subnet,omitempty" yaml:"subnet,omitempty"`
	SubnetRegion   string   `json:"subnet_region,omitempty" yaml:"subnet_region,omitempty"`
	SubnetCIDR     string   `json:"subnet_cidr,omitempty" yaml:"subnet_cidr,omitempty"`
	SubnetIPv6CIDR []string `json:"subnet_ipv6_cidr,omitempty" yaml:"subnet_ipv6_cidr,omitempty"`
	SubnetGateway  string   `json:"subnet_gateway,omitempty" yaml:"subnet_gateway,omitempty"`
}

// IPSource is implemented by providers whose inventory rows carry their
// addresses (Resource.IPs), so `polyctl find` can look them up. FindTypes
// lists the resource types that do, all of which the provider syncs across
// every enabled region of the account.
type IPSource interface {
	FindTypes() []ResourceType
}

// MatchDescriber is implemented by IPSource providers: it fills the fields
// of a match (name, region, zone, state, addresses, network) from its
// stored data m.Data, without the network. meta is the account's metadata.
type MatchDescriber interface {
	DescribeMatch(meta map[string]string, m *FindMatch) error
}

// ConsoleLinker is implemented by providers that know the web console page
// of a match. It returns "" when there is no reliable link.
type ConsoleLinker interface {
	ConsoleURL(meta map[string]string, m *FindMatch) string
}

// OwnerHinter is implemented by providers that can say how to choose among
// several resources of one account that own the same domain (ids are their
// resource ids): the hint of the ambiguity error of domain routing, which
// otherwise only says that the account holds several of them. An empty
// hint keeps that default.
type OwnerHinter interface {
	OwnerHint(kind ResourceType, ids []string) string
}

// CoverageChanger is implemented by providers whose account covers a set
// of inventory trees named in its metadata (the selected projects of a
// Google Cloud account). After a re-login replaced the metadata before by
// after, dropped are the trees the account no longer covers, whose cached
// rows must go at once (a fresh set would otherwise keep serving them, and
// domain routing would keep sending writes to them), and changed reports
// whether what the account covers changed at all, so that its cached sets
// are due.
type CoverageChanger interface {
	CoverageChange(before, after map[string]string) (dropped []string, changed bool)
}

// DetailProvider is implemented by clients that can look up the network
// details of a matched instance (find --detail). It returns ErrNotSupported
// for matches it has nothing to add to.
type DetailProvider interface {
	NetworkDetail(ctx context.Context, m *FindMatch) (*NetworkDetail, error)
}

// RegionError is the failure of one region of a multi-region sync.
type RegionError struct {
	Region string
	Err    error
	// Partial marks a failure that lost details only: the resources of
	// the region were read and returned (without, say, their secondary
	// addresses), so the stored rows of the region are replaced by them
	// instead of kept.
	Partial bool
	// Tree marks a failure of a whole tree of parents: the stored rows
	// whose parent is Region or starts with Region + "/" are kept (a
	// Google Cloud project, whose rows have the parent "<project>" or
	// "<project>/<zone or region>").
	Tree bool
}

// RegionSyncError is returned by Client.Sync, together with the resources
// of the regions that worked, when some regions of a multi-region sync
// failed and others did not. The set is still stored; the failures are
// reported.
type RegionSyncError struct {
	Failures []RegionError
	// Noun names what failed in the message: "region" when empty.
	Noun string
}

func (e *RegionSyncError) Error() string {
	parts := make([]string, 0, len(e.Failures))
	for _, f := range e.Failures {
		parts = append(parts, f.Region+": "+f.Err.Error())
	}
	noun := e.Noun
	if noun == "" {
		noun = "region"
	}
	return fmt.Sprintf("%d %s(s) failed: %s", len(e.Failures), noun, strings.Join(parts, "; "))
}

// SyncRegions runs fn for every region, at most concurrency at a time, and
// returns the resources of all regions. When some regions fail, it returns
// what the others found and a *RegionSyncError; when every region fails,
// no resources and the failures, wrapping the first one (so an
// authentication failure keeps its exit code).
//
// fn may itself return resources with a *RegionSyncError (a region read in
// part): the resources are kept, the region counts as one that worked, and
// its failures are reported. A failure of it that is not Partial is
// reported under the region fn ran for, so the stored rows of that region
// are kept.
func SyncRegions(ctx context.Context, regions []string, concurrency int, fn func(ctx context.Context, region string) ([]Resource, error)) ([]Resource, error) {
	if concurrency < 1 {
		concurrency = 1
	}
	type result struct {
		res []Resource
		err error
	}
	results := make([]result, len(regions))
	sem := make(chan struct{}, concurrency)
	var wg sync.WaitGroup
	for i, r := range regions {
		wg.Add(1)
		go func() {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			if err := ctx.Err(); err != nil {
				results[i] = result{err: err}
				return
			}
			res, err := fn(ctx, r)
			results[i] = result{res: res, err: err}
		}()
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var out []Resource
	var failures []RegionError
	failed := 0
	for i, r := range results {
		var rse *RegionSyncError
		if r.err != nil && !errors.As(r.err, &rse) {
			failed++
			failures = append(failures, RegionError{Region: regions[i], Err: r.err})
			continue
		}
		out = append(out, r.res...)
		if rse == nil {
			continue
		}
		for _, f := range rse.Failures {
			if !f.Partial && f.Region != regions[i] {
				f = RegionError{Region: regions[i], Err: fmt.Errorf("%s: %w", f.Region, f.Err)}
			}
			failures = append(failures, f)
		}
	}
	if len(failures) == 0 {
		return out, nil
	}
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Region < failures[j].Region })
	if failed == len(regions) {
		// Every failure is a whole region's, none a RegionSyncError: the
		// error is not one either, so no stored row is kept by region.
		e := &RegionSyncError{Failures: failures}
		return nil, fmt.Errorf("every region failed (%s): %w", e.Error(), failures[0].Err)
	}
	return out, &RegionSyncError{Failures: failures}
}

// AsRegionSyncError returns the RegionSyncError in err's chain, or nil.
func AsRegionSyncError(err error) *RegionSyncError {
	var e *RegionSyncError
	if errors.As(err, &e) {
		return e
	}
	return nil
}

// LastPathSegment returns the last element of a resource URL or path
// ("https://.../zones/us-central1-a" is "us-central1-a").
func LastPathSegment(u string) string {
	u = strings.TrimSuffix(u, "/")
	if i := strings.LastIndex(u, "/"); i >= 0 {
		return u[i+1:]
	}
	return u
}
