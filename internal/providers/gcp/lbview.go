package gcp

import (
	"context"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// A load balancer of Compute Engine is no resource of its own: it is a
// forwarding rule and the chain behind it (a target proxy, a URL map,
// backend services, their health checks and instance groups). polyctl
// groups forwarding rules into load balancers by name (lbNameOf): the
// polyctl-lb label, else the URL map of the target proxy, else the rule's
// own name. lbIndex reads every component of a project once, in every
// scope, to resolve those chains.

// lbIndex holds every load balancer component of a project, keyed by the
// resourceKey of their self links.
type lbIndex struct {
	rules       []*compute.ForwardingRule
	httpProxies map[string]*compute.TargetHttpProxy
	httpsProxy  map[string]*compute.TargetHttpsProxy
	tcpProxies  map[string]*compute.TargetTcpProxy
	urlMaps     map[string]*compute.UrlMap
	backends    map[string]*compute.BackendService
	checks      map[string]*compute.HealthCheck
	// unreachable are the scopes an aggregated list could not read.
	unreachable []string
}

// loadLBIndex reads the forwarding rules, proxies, URL maps, backend
// services and health checks of every scope of the project.
func (c *client) loadLBIndex(ctx context.Context) (*lbIndex, error) {
	x := &lbIndex{httpProxies: map[string]*compute.TargetHttpProxy{}, httpsProxy: map[string]*compute.TargetHttpsProxy{},
		tcpProxies: map[string]*compute.TargetTcpProxy{}, urlMaps: map[string]*compute.UrlMap{},
		backends: map[string]*compute.BackendService{}, checks: map[string]*compute.HealthCheck{}}
	seen := map[string]bool{}
	p := c.project
	cs := c.compute
	steps := []func() error{
		func() error {
			scopes, err := aggregatedPages(ctx, cs.ForwardingRules.AggregatedList(p), func(l *compute.ForwardingRuleAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, fr := range s.ForwardingRules {
						if k := resourceKey(fr.SelfLink); fr.SelfLink == "" || !seen[k] {
							seen[k] = true
							x.rules = append(x.rules, fr)
						}
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
		func() error {
			scopes, err := aggregatedPages(ctx, cs.TargetHttpProxies.AggregatedList(p), func(l *compute.TargetHttpProxyAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, v := range s.TargetHttpProxies {
						x.httpProxies[resourceKey(v.SelfLink)] = v
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
		func() error {
			scopes, err := aggregatedPages(ctx, cs.TargetHttpsProxies.AggregatedList(p), func(l *compute.TargetHttpsProxyAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, v := range s.TargetHttpsProxies {
						x.httpsProxy[resourceKey(v.SelfLink)] = v
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
		func() error {
			scopes, err := aggregatedPages(ctx, cs.TargetTcpProxies.AggregatedList(p), func(l *compute.TargetTcpProxyAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, v := range s.TargetTcpProxies {
						x.tcpProxies[resourceKey(v.SelfLink)] = v
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
		func() error {
			scopes, err := aggregatedPages(ctx, cs.UrlMaps.AggregatedList(p), func(l *compute.UrlMapsAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, v := range s.UrlMaps {
						x.urlMaps[resourceKey(v.SelfLink)] = v
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
		func() error {
			scopes, err := aggregatedPages(ctx, cs.BackendServices.AggregatedList(p), func(l *compute.BackendServiceAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, v := range s.BackendServices {
						x.backends[resourceKey(v.SelfLink)] = v
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
		func() error {
			scopes, err := aggregatedPages(ctx, cs.HealthChecks.AggregatedList(p), func(l *compute.HealthChecksAggregatedList) (string, []string) {
				u := l.Unreachables
				for scope, s := range l.Items {
					if s.Warning != nil {
						u = append(u, warnedUnreachable(scope, s.Warning.Code)...)
					}
					for _, v := range s.HealthChecks {
						x.checks[resourceKey(v.SelfLink)] = v
					}
				}
				return l.NextPageToken, u
			})
			x.unreachable = append(x.unreachable, scopes...)
			return err
		},
	}
	for _, f := range steps {
		if err := f(); err != nil {
			return nil, computeErr(err)
		}
	}
	x.unreachable = uniqueScopes(x.unreachable)
	sort.Slice(x.rules, func(i, j int) bool {
		a, b := x.rules[i], x.rules[j]
		if lastSegment(a.Region) != lastSegment(b.Region) {
			return lastSegment(a.Region) < lastSegment(b.Region)
		}
		return a.Name < b.Name
	})
	return x, nil
}

// urlMapNames maps proxies to the name of their URL map (lbNameOf).
func (x *lbIndex) urlMapNames() map[string]string {
	out := map[string]string{}
	for k, p := range x.httpProxies {
		out[k] = lastSegment(p.UrlMap)
	}
	for k, p := range x.httpsProxy {
		out[k] = lastSegment(p.UrlMap)
	}
	return out
}

// lbEntry is one forwarding rule of a load balancer with its chain.
type lbEntry struct {
	name   string
	region string // "" for a global rule
	rule   *compute.ForwardingRule
	// proxyKind and proxyName are empty for a rule without a target proxy.
	proxyKind lbKind
	proxyName string
	proxyKey  string
	urlMap    *compute.UrlMap
	// backendKeys are the backend services the chain reaches.
	backendKeys []string
}

func (e lbEntry) scope() string {
	if e.region == "" {
		return "global"
	}
	return "regional"
}

// protocol is the front end protocol of the rule.
func (e lbEntry) protocol() string {
	switch e.proxyKind {
	case kindHTTPProxy:
		return "HTTP"
	case kindHTTPSProxy:
		return "HTTPS"
	case kindTCPProxy:
		return "TCP"
	}
	if strings.Contains(e.rule.Target, "/targetSslProxies/") {
		return "SSL"
	}
	return e.rule.IPProtocol
}

// urlMapServices returns the backend services a URL map uses.
func urlMapServices(m *compute.UrlMap) []string {
	var out []string
	add := func(u string) {
		if u != "" && strings.Contains(u, "/backendServices/") {
			out = append(out, resourceKey(u))
		}
	}
	add(m.DefaultService)
	for _, pm := range m.PathMatchers {
		add(pm.DefaultService)
		for _, r := range pm.PathRules {
			add(r.Service)
		}
		for _, r := range pm.RouteRules {
			add(r.Service)
		}
	}
	return dedupe(out)
}

// entries resolves every forwarding rule to its load balancer entry.
func (x *lbIndex) entries() []lbEntry {
	names := x.urlMapNames()
	var out []lbEntry
	for _, fr := range x.rules {
		e := lbEntry{name: lbNameOf(fr, names), region: lastSegment(fr.Region), rule: fr}
		key := resourceKey(fr.Target)
		switch kind := proxyKind(fr.Target); kind {
		case kindHTTPProxy:
			e.proxyKind, e.proxyName, e.proxyKey = kind, lastSegment(fr.Target), key
			if p := x.httpProxies[key]; p != nil {
				e.urlMap = x.urlMaps[resourceKey(p.UrlMap)]
			}
		case kindHTTPSProxy:
			e.proxyKind, e.proxyName, e.proxyKey = kind, lastSegment(fr.Target), key
			if p := x.httpsProxy[key]; p != nil {
				e.urlMap = x.urlMaps[resourceKey(p.UrlMap)]
			}
		case kindTCPProxy:
			e.proxyKind, e.proxyName, e.proxyKey = kind, lastSegment(fr.Target), key
			if p := x.tcpProxies[key]; p != nil && p.Service != "" {
				e.backendKeys = append(e.backendKeys, resourceKey(p.Service))
			}
		}
		if e.urlMap != nil {
			e.backendKeys = append(e.backendKeys, urlMapServices(e.urlMap)...)
		}
		if fr.BackendService != "" {
			e.backendKeys = append(e.backendKeys, resourceKey(fr.BackendService))
		}
		e.backendKeys = dedupe(e.backendKeys)
		out = append(out, e)
	}
	return out
}

// lbRow is a row of load-balancer list: one forwarding rule.
type lbRow struct {
	Name           string   `json:"name" yaml:"name"`
	Scope          string   `json:"scope" yaml:"scope"`
	Region         string   `json:"region,omitempty" yaml:"region,omitempty"`
	Protocol       string   `json:"protocol" yaml:"protocol"`
	IPAddress      string   `json:"ip_address" yaml:"ip_address"`
	Port           string   `json:"port" yaml:"port"`
	ForwardingRule string   `json:"forwarding_rule" yaml:"forwarding_rule"`
	Target         string   `json:"target,omitempty" yaml:"target,omitempty"`
	URLMap         string   `json:"url_map,omitempty" yaml:"url_map,omitempty"`
	Backends       []string `json:"backend_services" yaml:"backend_services"`
	Health         string   `json:"health" yaml:"health"`
	Profile        string   `json:"profile" yaml:"profile"`
}

// portLabel renders a port range as a port when it is a single one.
func portLabel(pr string) string {
	if a, b, ok := strings.Cut(pr, "-"); ok && a == b {
		return a
	}
	return pr
}

// healthOf reads the health of every instance group behind the backend
// services (best effort: a failed read counts for nothing) and summarises
// it ("HEALTHY", "1/2 HEALTHY", "-").
func (c *client) healthOf(ctx context.Context, x *lbIndex, keys []string) string {
	healthy, total := 0, 0
	read := false
	for _, k := range keys {
		bs := x.backends[k]
		if bs == nil {
			continue
		}
		s := certScope{c: c, region: lastSegment(bs.Region)}
		for _, b := range bs.Backends {
			if !strings.Contains(b.Group, "/instanceGroups/") {
				continue
			}
			list, err := s.backendHealth(ctx, bs.Name, b.Group)
			if err != nil {
				continue
			}
			read = true
			for _, h := range list {
				total++
				if h.HealthState == "HEALTHY" {
					healthy++
				}
			}
		}
	}
	switch {
	case !read:
		return "-"
	case total == 0:
		return "no status yet"
	case healthy == total:
		return "HEALTHY"
	case healthy == 0:
		return "UNHEALTHY"
	}
	return strconv.Itoa(healthy) + "/" + strconv.Itoa(total) + " HEALTHY"
}

func (x *lbIndex) row(e lbEntry, profile, health string) lbRow {
	r := lbRow{Name: e.name, Scope: e.scope(), Region: e.region, Protocol: e.protocol(), IPAddress: e.rule.IPAddress,
		Port: portLabel(e.rule.PortRange), ForwardingRule: e.rule.Name, Health: health, Profile: profile, Backends: []string{}}
	if e.proxyName != "" {
		r.Target = string(e.proxyKind) + "/" + e.proxyName
	} else if e.rule.Target != "" {
		r.Target = lastSegment(e.rule.Target)
	}
	if e.urlMap != nil {
		r.URLMap = e.urlMap.Name
	}
	for _, k := range e.backendKeys {
		r.Backends = append(r.Backends, lastSegment(k))
	}
	return r
}

// ---------------------------------------------------------------- component views

type backendGroupView struct {
	Group  string   `json:"group" yaml:"group"`
	Zone   string   `json:"zone,omitempty" yaml:"zone,omitempty"`
	Mode   string   `json:"balancing_mode,omitempty" yaml:"balancing_mode,omitempty"`
	Health []string `json:"health,omitempty" yaml:"health,omitempty"`
}

type backendView struct {
	Name         string             `json:"name" yaml:"name"`
	Scope        string             `json:"scope" yaml:"scope"`
	Region       string             `json:"region,omitempty" yaml:"region,omitempty"`
	Protocol     string             `json:"protocol" yaml:"protocol"`
	Scheme       string             `json:"scheme" yaml:"scheme"`
	PortName     string             `json:"port_name,omitempty" yaml:"port_name,omitempty"`
	TimeoutSec   int64              `json:"timeout_sec,omitempty" yaml:"timeout_sec,omitempty"`
	HealthChecks []string           `json:"health_checks" yaml:"health_checks"`
	Backends     []backendGroupView `json:"backends" yaml:"backends"`
	// Health summarises the health of every backend instance (get only).
	Health string `json:"health,omitempty" yaml:"health,omitempty"`
}

func scopeName(region string) string {
	if region == "" {
		return "global"
	}
	return "regional"
}

func backendViewOf(bs *compute.BackendService) backendView {
	v := backendView{Name: bs.Name, Region: lastSegment(bs.Region), Protocol: bs.Protocol, Scheme: bs.LoadBalancingScheme, PortName: bs.PortName,
		TimeoutSec: bs.TimeoutSec, HealthChecks: []string{}, Backends: []backendGroupView{}}
	v.Scope = scopeName(v.Region)
	for _, h := range bs.HealthChecks {
		v.HealthChecks = append(v.HealthChecks, lastSegment(h))
	}
	for _, b := range bs.Backends {
		v.Backends = append(v.Backends, backendGroupView{Group: lastSegment(b.Group), Zone: zoneOfGroup(b.Group), Mode: b.BalancingMode})
	}
	return v
}

// withHealth reads the health of every backend group (failures are
// ignored: the view is read-only).
func (v *backendView) withHealth(ctx context.Context, c *client, bs *compute.BackendService) {
	s := certScope{c: c, region: lastSegment(bs.Region)}
	var all []string
	read := false
	for i, b := range bs.Backends {
		if !strings.Contains(b.Group, "/instanceGroups/") {
			continue
		}
		list, err := s.backendHealth(ctx, bs.Name, b.Group)
		if err != nil {
			continue
		}
		read = true
		states := []string{}
		for _, h := range list {
			states = append(states, lastSegment(h.Instance)+":"+h.HealthState)
			all = append(all, h.HealthState)
		}
		v.Backends[i].Health = states
	}
	v.Health = "-"
	if read {
		v.Health = healthSummary(all)
	}
}

type healthCheckRow struct {
	Name     string `json:"name" yaml:"name"`
	Scope    string `json:"scope" yaml:"scope"`
	Region   string `json:"region,omitempty" yaml:"region,omitempty"`
	Type     string `json:"type" yaml:"type"`
	Port     string `json:"port" yaml:"port"`
	Interval int64  `json:"check_interval_sec" yaml:"check_interval_sec"`
	Timeout  int64  `json:"timeout_sec" yaml:"timeout_sec"`
	Healthy  int64  `json:"healthy_threshold,omitempty" yaml:"healthy_threshold,omitempty"`
	Unhealty int64  `json:"unhealthy_threshold,omitempty" yaml:"unhealthy_threshold,omitempty"`
}

// checkPort returns the port of a health check of any type ("" when it
// has none, "serving" for USE_SERVING_PORT).
func checkPort(hc *compute.HealthCheck) string {
	var port int64
	spec := ""
	switch {
	case hc.TcpHealthCheck != nil:
		port, spec = hc.TcpHealthCheck.Port, hc.TcpHealthCheck.PortSpecification
	case hc.HttpHealthCheck != nil:
		port, spec = hc.HttpHealthCheck.Port, hc.HttpHealthCheck.PortSpecification
	case hc.HttpsHealthCheck != nil:
		port, spec = hc.HttpsHealthCheck.Port, hc.HttpsHealthCheck.PortSpecification
	case hc.Http2HealthCheck != nil:
		port, spec = hc.Http2HealthCheck.Port, hc.Http2HealthCheck.PortSpecification
	case hc.SslHealthCheck != nil:
		port, spec = hc.SslHealthCheck.Port, hc.SslHealthCheck.PortSpecification
	case hc.GrpcHealthCheck != nil:
		port, spec = hc.GrpcHealthCheck.Port, hc.GrpcHealthCheck.PortSpecification
	}
	if spec == "USE_SERVING_PORT" {
		return "serving"
	}
	if port == 0 {
		return ""
	}
	return strconv.FormatInt(port, 10)
}

func healthCheckRowOf(hc *compute.HealthCheck) healthCheckRow {
	r := healthCheckRow{Name: hc.Name, Region: lastSegment(hc.Region), Type: hc.Type, Port: checkPort(hc), Interval: hc.CheckIntervalSec,
		Timeout: hc.TimeoutSec, Healthy: hc.HealthyThreshold, Unhealty: hc.UnhealthyThreshold}
	r.Scope = scopeName(r.Region)
	return r
}

type groupRow struct {
	Name       string   `json:"name" yaml:"name"`
	Zone       string   `json:"zone" yaml:"zone"`
	Size       int64    `json:"size" yaml:"size"`
	NamedPorts []string `json:"named_ports" yaml:"named_ports"`
	Network    string   `json:"network,omitempty" yaml:"network,omitempty"`
}

type groupMember struct {
	Instance string `json:"instance" yaml:"instance"`
	Status   string `json:"status,omitempty" yaml:"status,omitempty"`
}

type groupDetail struct {
	groupRow `yaml:",inline"`
	Members  []groupMember `json:"members" yaml:"members"`
}

func groupRowOf(g *compute.InstanceGroup) groupRow {
	r := groupRow{Name: g.Name, Zone: lastSegment(g.Zone), Size: g.Size, NamedPorts: []string{}, Network: lastSegment(g.Network)}
	if l := namedPortLabel(g.NamedPorts); l != "" {
		r.NamedPorts = strings.Split(l, ",")
	}
	return r
}

// groupDetailOf reads the members of a group (best effort).
func groupDetailOf(ctx context.Context, c *client, g *compute.InstanceGroup) groupDetail {
	d := groupDetail{groupRow: groupRowOf(g), Members: []groupMember{}}
	if members, err := c.groupMembers(ctx, d.Zone, g.Name); err == nil {
		for _, m := range members {
			d.Members = append(d.Members, groupMember{Instance: lastSegment(m.Instance), Status: m.Status})
		}
	}
	return d
}

type ruleRow struct {
	Name         string `json:"name" yaml:"name"`
	Scope        string `json:"scope" yaml:"scope"`
	Region       string `json:"region,omitempty" yaml:"region,omitempty"`
	IPAddress    string `json:"ip_address" yaml:"ip_address"`
	Port         string `json:"port" yaml:"port"`
	IPProtocol   string `json:"ip_protocol" yaml:"ip_protocol"`
	Scheme       string `json:"scheme" yaml:"scheme"`
	Target       string `json:"target,omitempty" yaml:"target,omitempty"`
	Backend      string `json:"backend_service,omitempty" yaml:"backend_service,omitempty"`
	Network      string `json:"network,omitempty" yaml:"network,omitempty"`
	NetworkTier  string `json:"network_tier,omitempty" yaml:"network_tier,omitempty"`
	LoadBalancer string `json:"load_balancer,omitempty" yaml:"load_balancer,omitempty"`
}

func ruleRowOf(fr *compute.ForwardingRule) ruleRow {
	r := ruleRow{Name: fr.Name, Region: lastSegment(fr.Region), IPAddress: fr.IPAddress, Port: portLabel(fr.PortRange), IPProtocol: fr.IPProtocol,
		Scheme: fr.LoadBalancingScheme, Backend: lastSegment(fr.BackendService), Network: lastSegment(fr.Network), NetworkTier: fr.NetworkTier,
		LoadBalancer: fr.Labels[lbLabel]}
	r.Scope = scopeName(r.Region)
	if k := proxyKind(fr.Target); k != "" {
		r.Target = string(k) + "/" + lastSegment(fr.Target)
	} else if fr.Target != "" {
		r.Target = lastSegment(fr.Target)
	}
	return r
}

// inUseByRef names the component an "in use" error says uses the
// resource, as kind/name ("backend-service/bs-web-1").
func inUseByRef(err error) string {
	if m := inUseRe.FindStringSubmatch(err.Error()); m != nil {
		return componentLabel(resourceKey(m[1]))
	}
	return "another resource"
}

// inventorySetLB is the inventory set of the forwarding rules of a profile.
func inventorySetLB(profile string) inventory.Set {
	return inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResLoadBalancer}
}
