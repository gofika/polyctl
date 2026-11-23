package platform

import (
	"context"
	"net/netip"
	"strconv"
	"strings"
)

// LoadBalancer is a load balancer as a platform reports it.
type LoadBalancer struct {
	// ID is the platform id (an AWS ARN).
	ID            string   `json:"arn" yaml:"arn"`
	Name          string   `json:"name" yaml:"name"`
	Type          string   `json:"type" yaml:"type"`
	Scheme        string   `json:"scheme" yaml:"scheme"`
	State         string   `json:"state" yaml:"state"`
	VPC           string   `json:"vpc_id" yaml:"vpc_id"`
	DNSName       string   `json:"dns_name" yaml:"dns_name"`
	IPAddressType string   `json:"ip_address_type" yaml:"ip_address_type"`
	Zones         []LBZone `json:"zones" yaml:"zones"`
	// SecurityGroups is empty for a load balancer created without any.
	SecurityGroups []string `json:"security_groups" yaml:"security_groups"`
	Region         string   `json:"region" yaml:"region"`
}

// ZoneNames returns the availability zones the load balancer is enabled in.
func (l LoadBalancer) ZoneNames() []string {
	var out []string
	for _, z := range l.Zones {
		out = append(out, z.Zone)
	}
	return out
}

// Subnets returns the subnets of the load balancer.
func (l LoadBalancer) Subnets() []string {
	var out []string
	for _, z := range l.Zones {
		out = append(out, z.Subnet)
	}
	return out
}

// LBZone is one availability zone of a load balancer.
type LBZone struct {
	Zone   string `json:"zone" yaml:"zone"`
	Subnet string `json:"subnet_id" yaml:"subnet_id"`
	// Addresses are the addresses set on the zone (elastic or fixed
	// private addresses); usually empty.
	Addresses []string `json:"addresses,omitempty" yaml:"addresses,omitempty"`
}

// LoadBalancerAttributes are the attributes of a load balancer polyctl
// reads and writes.
type LoadBalancerAttributes struct {
	DeletionProtection bool `json:"deletion_protection" yaml:"deletion_protection"`
	CrossZone          bool `json:"cross_zone" yaml:"cross_zone"`
}

// LoadBalancerAttributeChange sets the attributes that are not nil.
type LoadBalancerAttributeChange struct {
	DeletionProtection *bool
	CrossZone          *bool
}

// LBHealthCheck is the health check of a target group.
type LBHealthCheck struct {
	Enabled  bool   `json:"enabled" yaml:"enabled"`
	Protocol string `json:"protocol" yaml:"protocol"`
	// Port is "traffic-port" or a port number.
	Port               string `json:"port" yaml:"port"`
	Path               string `json:"path,omitempty" yaml:"path,omitempty"`
	IntervalSeconds    int32  `json:"interval_seconds" yaml:"interval_seconds"`
	TimeoutSeconds     int32  `json:"timeout_seconds" yaml:"timeout_seconds"`
	HealthyThreshold   int32  `json:"healthy_threshold" yaml:"healthy_threshold"`
	UnhealthyThreshold int32  `json:"unhealthy_threshold" yaml:"unhealthy_threshold"`
}

// LBTargetGroup is a target group (a backend pool) of a load balancer.
type LBTargetGroup struct {
	ID         string `json:"arn" yaml:"arn"`
	Name       string `json:"name" yaml:"name"`
	Protocol   string `json:"protocol" yaml:"protocol"`
	Port       int32  `json:"port" yaml:"port"`
	VPC        string `json:"vpc_id" yaml:"vpc_id"`
	TargetType string `json:"target_type" yaml:"target_type"`
	// LoadBalancers are the ids of the load balancers whose listeners or
	// rules forward to the group.
	LoadBalancers []string      `json:"load_balancers" yaml:"load_balancers"`
	HealthCheck   LBHealthCheck `json:"health_check" yaml:"health_check"`
	Region        string        `json:"region" yaml:"region"`
}

// LBTarget is a target registered in a target group, with its health.
type LBTarget struct {
	ID   string `json:"id" yaml:"id"`
	Port int32  `json:"port" yaml:"port"`
	Zone string `json:"zone,omitempty" yaml:"zone,omitempty"`
	// State is the health state: healthy, unhealthy, initial, draining,
	// unused, unavailable.
	State       string `json:"state" yaml:"state"`
	Reason      string `json:"reason,omitempty" yaml:"reason,omitempty"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// LBListener is a listener of a load balancer.
type LBListener struct {
	ID           string `json:"arn" yaml:"arn"`
	LoadBalancer string `json:"load_balancer_arn" yaml:"load_balancer_arn"`
	Protocol     string `json:"protocol" yaml:"protocol"`
	Port         int32  `json:"port" yaml:"port"`
	// TargetGroups are the target groups the default action forwards to
	// (none when it does something else: redirect, fixed response).
	TargetGroups []string `json:"target_groups" yaml:"target_groups"`
	// DefaultAction is the type of the first default action (forward,
	// redirect, fixed-response, ...).
	DefaultAction string   `json:"default_action" yaml:"default_action"`
	Certificates  []string `json:"certificates" yaml:"certificates"`
}

// ForwardsTo reports whether the default action forwards to exactly the
// target group id.
func (l LBListener) ForwardsTo(id string) bool {
	return l.DefaultAction == "forward" && len(l.TargetGroups) == 1 && l.TargetGroups[0] == id
}

// LoadBalancerSpec describes a load balancer to create.
type LoadBalancerSpec struct {
	Region        string
	Name          string
	Type          string
	Scheme        string
	Subnets       []string
	IPAddressType string
	// SecurityGroups is left out of the request when empty.
	SecurityGroups []string
	Tags           map[string]string
}

// TargetGroupSpec describes a target group to create. Empty health check
// fields keep the platform defaults.
type TargetGroupSpec struct {
	Region              string
	Name                string
	Protocol            string
	Port                int32
	VPC                 string
	TargetType          string
	HealthCheckProtocol string
	HealthCheckPort     string
	HealthCheckInterval int32
	Tags                map[string]string
}

// HealthCheckChange changes the health check fields that are set.
type HealthCheckChange struct {
	Protocol string
	Interval int32
}

// ListenerCreateSpec describes a listener to create: Protocol on Port,
// forwarding to the target group TargetGroup.
type ListenerCreateSpec struct {
	Region       string
	LoadBalancer string
	Protocol     string
	Port         int32
	TargetGroup  string
	// Certificate is required for TLS and HTTPS listeners.
	Certificate string
}

// LBTargetSpec is a target given on the command line, "<id>[:<port>]": an
// instance id or an IP address, and a port (0: the target group's port).
type LBTargetSpec struct {
	ID   string `json:"id" yaml:"id"`
	Port int32  `json:"port,omitempty" yaml:"port,omitempty"`
}

// String renders "id:port", or the id alone without a port.
func (t LBTargetSpec) String() string {
	if t.Port == 0 {
		return t.ID
	}
	if strings.Contains(t.ID, ":") {
		return "[" + t.ID + "]:" + strconv.Itoa(int(t.Port))
	}
	return t.ID + ":" + strconv.Itoa(int(t.Port))
}

// ParseTarget parses "<id>[:<port>]". An IPv6 address with a port is
// written in brackets ("[2001:db8::1]:80"); a bare IPv6 address is an id
// without a port.
func ParseTarget(s string) (LBTargetSpec, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return LBTargetSpec{}, invalid("target is empty: expected <id>[:<port>], e.g. i-0123456789abcdef0:80 or 10.0.1.5")
	}
	id, port := s, ""
	switch {
	case strings.HasPrefix(s, "["):
		end := strings.Index(s, "]")
		if end < 0 {
			return LBTargetSpec{}, invalid("target %q: unbalanced [", s)
		}
		id, port = s[1:end], strings.TrimPrefix(s[end+1:], ":")
		if s[end+1:] != "" && !strings.HasPrefix(s[end+1:], ":") {
			return LBTargetSpec{}, invalid("target %q: expected [<ipv6>]:<port>", s)
		}
	case strings.Count(s, ":") == 1:
		id, port, _ = strings.Cut(s, ":")
	}
	if id == "" {
		return LBTargetSpec{}, invalid("target %q: the id is empty", s)
	}
	if port == "" && strings.HasSuffix(s, ":") {
		return LBTargetSpec{}, invalid("target %q: the port after ':' is empty", s)
	}
	t := LBTargetSpec{ID: id}
	if port != "" {
		p, err := parsePort(port)
		if err != nil {
			return LBTargetSpec{}, invalid("target %q: %v", s, err)
		}
		t.Port = int32(p)
	}
	return t, nil
}

// ParseTargets parses "<id>[:<port>]" values, dropping repeats.
func ParseTargets(specs []string) ([]LBTargetSpec, error) {
	var out []LBTargetSpec
	seen := map[LBTargetSpec]bool{}
	for _, s := range specs {
		t, err := ParseTarget(s)
		if err != nil {
			return nil, err
		}
		if !seen[t] {
			seen[t] = true
			out = append(out, t)
		}
	}
	return out, nil
}

// IsIPTarget reports whether a target id is an IP address (the targets of
// an "ip" target group).
func IsIPTarget(id string) bool {
	_, err := netip.ParseAddr(id)
	return err == nil
}

// LoadBalancerService is the load balancer side of a platform: load
// balancers, their target groups (backend pools) and listeners. Each
// method is one platform operation in one region; the comparison of what
// exists with what is wanted, the order of the steps, the waits and the
// confirmations belong to the command. Find* methods return nil, not an
// error, when the resource does not exist.
type LoadBalancerService interface {
	ListLoadBalancers(ctx context.Context, region string) ([]LoadBalancer, error)
	// FindLoadBalancer finds a load balancer by name or id.
	FindLoadBalancer(ctx context.Context, region, ref string) (*LoadBalancer, error)
	// FindLoadBalancerByDNS finds a load balancer by its DNS name.
	FindLoadBalancerByDNS(ctx context.Context, region, dns string) (*LoadBalancer, error)
	CreateLoadBalancer(ctx context.Context, spec LoadBalancerSpec) (LoadBalancer, error)
	DeleteLoadBalancer(ctx context.Context, region, id string) error
	SetLoadBalancerSecurityGroups(ctx context.Context, region, id string, groups []string) error
	SetLoadBalancerSubnets(ctx context.Context, region, id string, subnets []string) error
	SetLoadBalancerIPAddressType(ctx context.Context, region, id, ipType string) error
	LoadBalancerAttributes(ctx context.Context, region, id string) (LoadBalancerAttributes, error)
	ModifyLoadBalancerAttributes(ctx context.Context, region, id string, change LoadBalancerAttributeChange) error

	// ListTargetGroups lists the target groups of a region, or those of
	// one load balancer when lb is not "".
	ListTargetGroups(ctx context.Context, region, lb string) ([]LBTargetGroup, error)
	// FindTargetGroup finds a target group by name or id.
	FindTargetGroup(ctx context.Context, region, ref string) (*LBTargetGroup, error)
	CreateTargetGroup(ctx context.Context, spec TargetGroupSpec) (LBTargetGroup, error)
	ModifyTargetGroupHealthCheck(ctx context.Context, region, id string, change HealthCheckChange) error
	DeleteTargetGroup(ctx context.Context, region, id string) error
	// TargetHealth lists the targets of a group with their health.
	TargetHealth(ctx context.Context, region, id string) ([]LBTarget, error)
	RegisterTargets(ctx context.Context, region, id string, targets []LBTargetSpec) error
	DeregisterTargets(ctx context.Context, region, id string, targets []LBTargetSpec) error

	ListListeners(ctx context.Context, region, lb string) ([]LBListener, error)
	// FindListener finds a listener by id.
	FindListener(ctx context.Context, region, id string) (*LBListener, error)
	CreateListener(ctx context.Context, spec ListenerCreateSpec) (LBListener, error)
	// ModifyListener changes the protocol ("" keeps it) and the target
	// group the listener forwards to ("" keeps the default actions).
	ModifyListener(ctx context.Context, region, id, protocol, targetGroup string) (LBListener, error)
	DeleteListener(ctx context.Context, region, id string) error
}
