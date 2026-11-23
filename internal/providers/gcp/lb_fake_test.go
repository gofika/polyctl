package gcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"slices"
	"sort"
	"strings"

	"google.golang.org/api/compute/v1"
)

// lbParts is the rest of the load balancer side of the fake Compute
// Engine: health checks, backend services, target TCP proxies (regional
// and global), unmanaged instance groups (zonal), and the writes of URL
// maps, target HTTP proxies and forwarding rules. It behaves as observed:
// a component another one refers to cannot be deleted (400
// resourceInUseByAnotherResource at submission), SetNamedPorts replaces
// the named ports as a whole and checks the fingerprint (412
// conditionNotMet), adding a member twice is 400 memberAlreadyExists, and
// a new backend reports no health status before it turns HEALTHY.
type lbParts struct {
	checks     map[string]*compute.HealthCheck    // project/scope/name
	backends   map[string]*compute.BackendService // project/scope/name
	tcpProxies map[string]*compute.TargetTcpProxy // project/scope/name
	groups     map[string]*compute.InstanceGroup  // project/zone/name
	members    map[string][]string                // project/zone/name -> instance names
	// health answers GetHealth in turn ("" is no status, "HEALTHY", ...);
	// the last answer repeats. Empty: HEALTHY.
	health      []string
	healthCalls int
	// race makes the next Insert of a collection ("backendServices", ...)
	// store the resource and still answer 409, as when another run created
	// it meanwhile.
	race map[string]bool
	// staleGroup makes the next SetNamedPorts see a changed fingerprint.
	staleGroup bool
}

func (f *fakeCompute) parts() *lbParts {
	if f.lbParts == nil {
		f.lbParts = &lbParts{checks: map[string]*compute.HealthCheck{}, backends: map[string]*compute.BackendService{},
			tcpProxies: map[string]*compute.TargetTcpProxy{}, groups: map[string]*compute.InstanceGroup{}, members: map[string][]string{},
			race: map[string]bool{}}
	}
	return f.lbParts
}

// addProxyOnlySubnet gives the default network a proxy-only subnetwork
// in region.
func (f *fakeCompute) addProxyOnlySubnet(region string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.subnets["proj/"+region] = append(f.subnets["proj/"+region], &compute.Subnetwork{Name: "proxy-only", Network: apiBase + "projects/proj/global/networks/default",
		IpCidrRange: "10.129.0.0/23", Purpose: "REGIONAL_MANAGED_PROXY", Role: "ACTIVE", Region: apiBase + "projects/proj/regions/" + region})
}

func (f *fakeCompute) addCheck(scope, name string, port int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	hc := &compute.HealthCheck{Name: name, Type: "TCP", TcpHealthCheck: &compute.TCPHealthCheck{Port: port}, CheckIntervalSec: 10, TimeoutSec: 5,
		HealthyThreshold: 2, UnhealthyThreshold: 2, SelfLink: selfLink("proj", scope, "healthChecks", name)}
	if scope != "global" {
		hc.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.parts().checks["proj/"+scope+"/"+name] = hc
}

// addGroup puts an instance group with named ports and members into the
// fake.
func (f *fakeCompute) addGroup(zone, name string, ports map[string]int64, members ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	g := &compute.InstanceGroup{Name: name, Zone: apiBase + "projects/proj/zones/" + zone, Network: apiBase + "projects/proj/global/networks/default",
		Fingerprint: "igfp-1", SelfLink: apiBase + "projects/proj/zones/" + zone + "/instanceGroups/" + name}
	var keys []string
	for k := range ports {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		g.NamedPorts = append(g.NamedPorts, &compute.NamedPort{Name: k, Port: ports[k]})
	}
	key := "proj/" + zone + "/" + name
	f.parts().groups[key] = g
	f.parts().members[key] = members
	g.Size = int64(len(members))
}

// addBackend puts a backend service with one health check and instance
// groups ("zone/name") into the fake.
func (f *fakeCompute) addBackend(scope, name, protocol, portName, check string, groups ...string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	bs := &compute.BackendService{Name: name, Protocol: protocol, PortName: portName, LoadBalancingScheme: "EXTERNAL_MANAGED", TimeoutSec: 30,
		Fingerprint: "bsfp-1", SelfLink: selfLink("proj", scope, "backendServices", name)}
	if check != "" {
		bs.HealthChecks = []string{selfLink("proj", scope, "healthChecks", check)}
	}
	for _, g := range groups {
		zone, gname, _ := strings.Cut(g, "/")
		bs.Backends = append(bs.Backends, &compute.Backend{Group: apiBase + "projects/proj/zones/" + zone + "/instanceGroups/" + gname, BalancingMode: "UTILIZATION", MaxUtilization: 0.8})
	}
	if scope != "global" {
		bs.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.parts().backends["proj/"+scope+"/"+name] = bs
}

func (f *fakeCompute) addURLMapTo(scope, name, backend string) {
	f.addURLMap(scope, name)
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lb().urlMaps["proj/"+scope+"/"+name].DefaultService = selfLink("proj", scope, "backendServices", backend)
}

func (f *fakeCompute) addTCPProxy(scope, name, backend string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p := &compute.TargetTcpProxy{Name: name, Service: selfLink("proj", scope, "backendServices", backend), ProxyHeader: "NONE",
		SelfLink: selfLink("proj", scope, "targetTcpProxies", name)}
	if scope != "global" {
		p.Region = apiBase + "projects/proj/regions/" + scope
	}
	f.parts().tcpProxies["proj/"+scope+"/"+name] = p
}

func (f *fakeCompute) group(zone, name string) *compute.InstanceGroup {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.parts().groups["proj/"+zone+"/"+name]
}

func (f *fakeCompute) backend(scope, name string) *compute.BackendService {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.parts().backends["proj/"+scope+"/"+name]
}

// lbOps lists the load balancer writes in order, without the reads that
// are POSTs (getHealth, listInstances), as "METHOD scope/kind/name[/verb]".
func (f *fakeCompute) lbOps() []string {
	var out []string
	for _, w := range f.lbWrites() {
		if strings.HasSuffix(w, "/getHealth") || strings.HasSuffix(w, "/listInstances") {
			continue
		}
		out = append(out, w)
	}
	return out
}

// refersTo reports whether any component of the project refers to the
// resource key, and which.
func (f *fakeCompute) refersTo(project, key string) string {
	p := f.parts()
	lb := f.lb()
	for _, fr := range f.forwardingRules[project] {
		if resourceKey(fr.Target) == key || resourceKey(fr.BackendService) == key {
			return resourceKey(fr.SelfLink)
		}
	}
	for _, x := range lb.httpProxies {
		if resourceKey(x.UrlMap) == key {
			return resourceKey(x.SelfLink)
		}
	}
	for _, x := range lb.httpsProxies {
		if resourceKey(x.UrlMap) == key {
			return resourceKey(x.SelfLink)
		}
	}
	for _, x := range p.tcpProxies {
		if resourceKey(x.Service) == key {
			return resourceKey(x.SelfLink)
		}
	}
	for _, m := range lb.urlMaps {
		if resourceKey(m.DefaultService) == key {
			return resourceKey(m.SelfLink)
		}
	}
	for _, bs := range p.backends {
		for _, h := range bs.HealthChecks {
			if resourceKey(h) == key {
				return resourceKey(bs.SelfLink)
			}
		}
		for _, b := range bs.Backends {
			if resourceKey(b.Group) == key {
				return resourceKey(bs.SelfLink)
			}
		}
	}
	return ""
}

// inUse answers the delete of a component another one refers to.
func inUse(w http.ResponseWriter, key, by string) {
	apiError(w, fakeErr{400, reasonInUse, "The resource '" + key + "' is already being used by '" + by + "'"})
}

func (f *fakeCompute) exists(project, ref string) bool {
	k := resourceKey(ref)
	p, lb := f.parts(), f.lb()
	parts := strings.Split(k, "/")
	if len(parts) < 4 {
		return false
	}
	name := parts[len(parts)-1]
	kind := parts[len(parts)-2]
	scope := "global"
	if parts[2] == "regions" || parts[2] == "zones" {
		scope = parts[3]
	}
	key := project + "/" + scope + "/" + name
	switch kind {
	case "healthChecks":
		return p.checks[key] != nil
	case "backendServices":
		return p.backends[key] != nil
	case "instanceGroups":
		return p.groups[key] != nil
	case "urlMaps":
		return lb.urlMaps[key] != nil
	case "targetHttpProxies":
		return lb.httpProxies[key] != nil
	case "targetHttpsProxies":
		return lb.httpsProxies[key] != nil
	case "targetTcpProxies":
		return p.tcpProxies[key] != nil
	}
	return false
}

func invalidRef(w http.ResponseWriter, field, ref string) {
	apiError(w, fakeErr{400, "invalid", "Invalid value for field '" + field + "': '" + ref + "'. The resource was not found."})
}

// handleLBParts serves the components lbParts holds and the writes of the
// others; false when the request is not one of them.
func (f *fakeCompute) handleLBParts(w http.ResponseWriter, r *http.Request, project string, rest []string) bool {
	p := f.parts()
	if len(rest) == 2 && rest[0] == "aggregated" {
		switch rest[1] {
		case "healthChecks":
			items := map[string]compute.HealthChecksScopedList{}
			for _, k := range sortedKeys(p.checks, project) {
				s := scopePath(strings.Split(k, "/")[1])
				l := items[s]
				l.HealthChecks = append(l.HealthChecks, p.checks[k])
				items[s] = l
			}
			writeJSONStatus(w, 200, &compute.HealthChecksAggregatedList{Items: items})
		case "backendServices":
			items := map[string]compute.BackendServicesScopedList{}
			for _, k := range sortedKeys(p.backends, project) {
				s := scopePath(strings.Split(k, "/")[1])
				l := items[s]
				l.BackendServices = append(l.BackendServices, p.backends[k])
				items[s] = l
			}
			writeJSONStatus(w, 200, &compute.BackendServiceAggregatedList{Items: items})
		case "targetTcpProxies":
			items := map[string]compute.TargetTcpProxiesScopedList{}
			for _, k := range sortedKeys(p.tcpProxies, project) {
				s := scopePath(strings.Split(k, "/")[1])
				l := items[s]
				l.TargetTcpProxies = append(l.TargetTcpProxies, p.tcpProxies[k])
				items[s] = l
			}
			writeJSONStatus(w, 200, &compute.TargetTcpProxyAggregatedList{Items: items})
		case "targetHttpProxies":
			items := map[string]compute.TargetHttpProxiesScopedList{}
			for _, k := range sortedKeys(f.lb().httpProxies, project) {
				s := scopePath(strings.Split(k, "/")[1])
				l := items[s]
				l.TargetHttpProxies = append(l.TargetHttpProxies, f.lb().httpProxies[k])
				items[s] = l
			}
			writeJSONStatus(w, 200, &compute.TargetHttpProxyAggregatedList{Items: items})
		case "instanceGroups":
			items := map[string]compute.InstanceGroupsScopedList{}
			for _, k := range sortedKeys(p.groups, project) {
				s := "zones/" + strings.Split(k, "/")[1]
				l := items[s]
				l.InstanceGroups = append(l.InstanceGroups, p.groups[k])
				items[s] = l
			}
			writeJSONStatus(w, 200, &compute.InstanceGroupAggregatedList{Items: items})
		default:
			return false
		}
		return true
	}
	if len(rest) >= 3 && rest[0] == "zones" && rest[2] == "instanceGroups" {
		f.handleGroups(w, r, project, rest[1], rest[3:])
		return true
	}
	var scope string
	var tail []string
	switch {
	case len(rest) >= 2 && rest[0] == "global":
		scope, tail = "global", rest[1:]
	case len(rest) >= 3 && rest[0] == "regions":
		scope, tail = rest[1], rest[2:]
	default:
		return false
	}
	prefix := project + "/" + scope + "/"
	switch tail[0] {
	case "healthChecks":
		handleCollection(f, w, r, project, scope, tail, "healthChecks", p.checks,
			func(hc *compute.HealthCheck) *string { return &hc.Name },
			func(hc *compute.HealthCheck) {
				hc.SelfLink = selfLink(project, scope, "healthChecks", hc.Name)
				if hc.HealthyThreshold == 0 {
					hc.HealthyThreshold, hc.UnhealthyThreshold = 2, 2
				}
			}, nil)
	case "backendServices":
		if len(tail) == 3 && tail[2] == "getHealth" && r.Method == http.MethodPost {
			bs := p.backends[prefix+tail[1]]
			if bs == nil {
				notFound(w, "backendServices/"+tail[1])
				return true
			}
			state := "HEALTHY"
			if len(p.health) > 0 {
				i := min(p.healthCalls, len(p.health)-1)
				state = p.health[i]
			}
			p.healthCalls++
			res := &compute.BackendServiceGroupHealth{}
			if state != "" {
				res.HealthStatus = []*compute.HealthStatus{{HealthState: state, Instance: "projects/proj/zones/us-central1-a/instances/web-1", IpAddress: "10.128.0.2", Port: 80}}
			}
			writeJSONStatus(w, 200, res)
			return true
		}
		if len(tail) == 2 && r.Method == http.MethodPatch {
			bs := p.backends[prefix+tail[1]]
			if bs == nil {
				notFound(w, "backendServices/"+tail[1])
				return true
			}
			var body compute.BackendService
			_ = json.NewDecoder(r.Body).Decode(&body)
			if body.Fingerprint != bs.Fingerprint {
				apiError(w, fakeErr{412, "conditionNotMet", "Invalid fingerprint."})
				return true
			}
			if body.Backends != nil {
				bs.Backends = body.Backends
			}
			bs.Fingerprint += "x"
			writeJSONStatus(w, 200, f.op("patchBackendService", bs.SelfLink))
			return true
		}
		handleCollection(f, w, r, project, scope, tail, "backendServices", p.backends,
			func(bs *compute.BackendService) *string { return &bs.Name },
			func(bs *compute.BackendService) {
				bs.SelfLink = selfLink(project, scope, "backendServices", bs.Name)
				bs.Fingerprint = "bsfp-0"
				if bs.Port == 0 {
					bs.Port = 80
				}
			},
			func(bs *compute.BackendService) (string, string) {
				for _, h := range bs.HealthChecks {
					if !f.exists(project, h) {
						return "resource.healthChecks", h
					}
				}
				for _, b := range bs.Backends {
					if !f.exists(project, b.Group) {
						return "resource.backends.group", b.Group
					}
				}
				return "", ""
			})
	case "targetTcpProxies":
		handleCollection(f, w, r, project, scope, tail, "targetTcpProxies", p.tcpProxies,
			func(x *compute.TargetTcpProxy) *string { return &x.Name },
			func(x *compute.TargetTcpProxy) {
				x.SelfLink = selfLink(project, scope, "targetTcpProxies", x.Name)
				x.Service = apiBase + resourceKey(x.Service)
				x.ProxyHeader = "NONE"
			},
			func(x *compute.TargetTcpProxy) (string, string) {
				if !f.exists(project, x.Service) {
					return "resource.service", x.Service
				}
				return "", ""
			})
	case "urlMaps":
		if r.Method == http.MethodGet && len(tail) == 2 {
			return false // the GET of lbFake
		}
		handleCollection(f, w, r, project, scope, tail, "urlMaps", f.lb().urlMaps,
			func(x *compute.UrlMap) *string { return &x.Name },
			func(x *compute.UrlMap) {
				x.SelfLink = selfLink(project, scope, "urlMaps", x.Name)
				x.DefaultService = apiBase + resourceKey(x.DefaultService)
			},
			func(x *compute.UrlMap) (string, string) {
				if !f.exists(project, x.DefaultService) {
					return "resource.defaultService", x.DefaultService
				}
				return "", ""
			})
	case "targetHttpProxies":
		if r.Method == http.MethodGet {
			return false
		}
		handleCollection(f, w, r, project, scope, tail, "targetHttpProxies", f.lb().httpProxies,
			func(x *compute.TargetHttpProxy) *string { return &x.Name },
			func(x *compute.TargetHttpProxy) {
				x.SelfLink = selfLink(project, scope, "targetHttpProxies", x.Name)
				x.UrlMap = apiBase + resourceKey(x.UrlMap)
			},
			func(x *compute.TargetHttpProxy) (string, string) {
				if !f.exists(project, x.UrlMap) {
					return "resource.urlMap", x.UrlMap
				}
				return "", ""
			})
	case "targetHttpsProxies":
		if r.Method != http.MethodDelete {
			return false
		}
		handleCollection(f, w, r, project, scope, tail, "targetHttpsProxies", f.lb().httpsProxies,
			func(x *compute.TargetHttpsProxy) *string { return &x.Name }, nil, nil)
	case "forwardingRules":
		switch {
		case r.Method == http.MethodDelete && len(tail) == 2:
			list := f.forwardingRules[project]
			for i, fr := range list {
				frScope := "global"
				if fr.Region != "" {
					frScope = lastSegment(fr.Region)
				}
				if fr.Name == tail[1] && frScope == scope {
					f.forwardingRules[project] = slices.Delete(list, i, i+1)
					writeJSONStatus(w, 200, f.op("deleteForwardingRule", fr.SelfLink))
					return true
				}
			}
			notFound(w, "forwardingRules/"+tail[1])
		case r.Method == http.MethodPost && len(tail) == 1:
			var fr compute.ForwardingRule
			if err := json.NewDecoder(r.Body).Decode(&fr); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return true
			}
			if fr.Target != "" && !f.exists(project, fr.Target) {
				invalidRef(w, "resource.target", fr.Target)
				return true
			}
			if fr.LoadBalancingScheme == "EXTERNAL_MANAGED" && fr.Network == "" {
				apiError(w, fakeErr{400, "", "Invalid value for field 'resource.target': '" + fr.Target + "'. An active proxy-only subnetwork is required in the same region and VPC as the forwarding rule."})
				return true
			}
			b, _ := json.Marshal(&fr)
			r.Body = io.NopCloser(bytes.NewReader(b))
			return false // stored by lbFake.handleRules
		default:
			return false
		}
	default:
		return false
	}
	return true
}

// handleCollection serves list, get, insert and delete of a regional or
// global collection of the fake.
func handleCollection[T any](f *fakeCompute, w http.ResponseWriter, r *http.Request, project, scope string, tail []string, kind string,
	store map[string]*T, name func(*T) *string, fill func(*T), check func(*T) (string, string)) {
	prefix := project + "/" + scope + "/"
	p := f.parts()
	if len(tail) == 1 {
		switch r.Method {
		case http.MethodGet:
			var items []*T
			for _, k := range sortedKeys(store, project) {
				if strings.HasPrefix(k, prefix) {
					items = append(items, store[k])
				}
			}
			writeJSONStatus(w, 200, map[string]any{"items": items})
		case http.MethodPost:
			var v T
			if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			n := *name(&v)
			if !certNameRe.MatchString(n) {
				apiError(w, fakeErr{400, "invalid", "Invalid value for field 'resource.name': '" + n + "'. Must be a match of regex '[a-z]([-a-z0-9]{0,61}[a-z0-9])?'"})
				return
			}
			if store[prefix+n] != nil {
				apiError(w, fakeErr{409, reasonAlreadyExists, "The resource 'projects/" + project + "/" + scopePath(scope) + "/" + kind + "/" + n + "' already exists"})
				return
			}
			if check != nil {
				if field, ref := check(&v); field != "" {
					invalidRef(w, field, ref)
					return
				}
			}
			if fill != nil {
				fill(&v)
			}
			setRegion(&v, project, scope)
			store[prefix+n] = &v
			if p.race[kind] {
				delete(p.race, kind)
				apiError(w, fakeErr{409, reasonAlreadyExists, "The resource '" + kind + "/" + n + "' already exists"})
				return
			}
			writeJSONStatus(w, 200, f.op("insert:"+kind, selfLink(project, scope, kind, n)))
		default:
			http.NotFound(w, r)
		}
		return
	}
	v := store[prefix+tail[1]]
	if v == nil {
		notFound(w, "projects/"+project+"/"+scopePath(scope)+"/"+kind+"/"+tail[1])
		return
	}
	switch {
	case r.Method == http.MethodGet && len(tail) == 2:
		writeJSONStatus(w, 200, v)
	case r.Method == http.MethodDelete && len(tail) == 2:
		key := "projects/" + project + "/" + scopePath(scope) + "/" + kind + "/" + tail[1]
		if by := f.refersTo(project, key); by != "" {
			inUse(w, key, by)
			return
		}
		delete(store, prefix+tail[1])
		writeJSONStatus(w, 200, f.op("delete:"+kind, apiBase+key))
	default:
		http.NotFound(w, r)
	}
}

// setRegion sets the Region field of a regional component.
func setRegion(v any, project, scope string) {
	if scope == "global" {
		return
	}
	region := apiBase + "projects/" + project + "/regions/" + scope
	switch x := v.(type) {
	case *compute.HealthCheck:
		x.Region = region
	case *compute.BackendService:
		x.Region = region
	case *compute.TargetTcpProxy:
		x.Region = region
	case *compute.UrlMap:
		x.Region = region
	case *compute.TargetHttpProxy:
		x.Region = region
	}
}

func (f *fakeCompute) handleGroups(w http.ResponseWriter, r *http.Request, project, zone string, rest []string) {
	p := f.parts()
	prefix := project + "/" + zone + "/"
	if len(rest) == 0 {
		switch r.Method {
		case http.MethodGet:
			var items []*compute.InstanceGroup
			for _, k := range sortedKeys(p.groups, project) {
				if strings.HasPrefix(k, prefix) {
					items = append(items, p.groups[k])
				}
			}
			writeJSONStatus(w, 200, &compute.InstanceGroupList{Items: items})
		case http.MethodPost:
			var g compute.InstanceGroup
			if err := json.NewDecoder(r.Body).Decode(&g); err != nil {
				apiError(w, fakeErr{400, "invalid", err.Error()})
				return
			}
			if !certNameRe.MatchString(g.Name) {
				apiError(w, fakeErr{400, "invalid", "Invalid value for field 'resource.name': '" + g.Name + "'. Must be a match of regex '[a-z]([-a-z0-9]{0,61}[a-z0-9])?'"})
				return
			}
			if p.groups[prefix+g.Name] != nil {
				apiError(w, fakeErr{409, reasonAlreadyExists, "The resource 'instanceGroups/" + g.Name + "' already exists"})
				return
			}
			g.Zone = apiBase + "projects/" + project + "/zones/" + zone
			g.SelfLink = g.Zone + "/instanceGroups/" + g.Name
			g.Network = apiBase + resourceKey(g.Network)
			g.Fingerprint = "igfp-0"
			p.groups[prefix+g.Name] = &g
			writeJSONStatus(w, 200, f.op("insertInstanceGroup", g.SelfLink))
		default:
			http.NotFound(w, r)
		}
		return
	}
	key := prefix + rest[0]
	g := p.groups[key]
	if g == nil {
		notFound(w, "projects/"+project+"/zones/"+zone+"/instanceGroups/"+rest[0])
		return
	}
	switch {
	case r.Method == http.MethodGet && len(rest) == 1:
		writeJSONStatus(w, 200, g)
	case r.Method == http.MethodDelete && len(rest) == 1:
		ref := "projects/" + project + "/zones/" + zone + "/instanceGroups/" + rest[0]
		if by := f.refersTo(project, ref); by != "" {
			inUse(w, ref, by)
			return
		}
		delete(p.groups, key)
		writeJSONStatus(w, 200, f.op("deleteInstanceGroup", g.SelfLink))
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "listInstances":
		var items []*compute.InstanceWithNamedPorts
		for _, m := range p.members[key] {
			items = append(items, &compute.InstanceWithNamedPorts{Instance: apiBase + "projects/" + project + "/zones/" + zone + "/instances/" + m,
				Status: statusRunning, NamedPorts: g.NamedPorts})
		}
		writeJSONStatus(w, 200, &compute.InstanceGroupsListInstances{Items: items})
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "setNamedPorts":
		var req compute.InstanceGroupsSetNamedPortsRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		if p.staleGroup {
			p.staleGroup = false
			g.Fingerprint += "x"
		}
		if req.Fingerprint != g.Fingerprint {
			apiError(w, fakeErr{412, "conditionNotMet", "Invalid fingerprint."})
			return
		}
		g.NamedPorts = req.NamedPorts
		g.Fingerprint += "n"
		writeJSONStatus(w, 200, f.op("setNamedPorts", g.SelfLink))
	case r.Method == http.MethodPost && len(rest) == 2 && rest[1] == "addInstances":
		var req compute.InstanceGroupsAddInstancesRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		for _, ref := range req.Instances {
			name := lastSegment(ref.Instance)
			if !strings.Contains(resourceKey(ref.Instance), "/zones/"+zone+"/") {
				apiError(w, fakeErr{400, "invalid", "The instance resource '" + ref.Instance + "' is in another zone, which is incompatible with the using resource in 'zones/" + zone + "'"})
				return
			}
			if slices.Contains(p.members[key], name) {
				apiError(w, fakeErr{400, reasonMemberExists, "Resource '" + ref.Instance + "' is already a member of '" + g.SelfLink + "'."})
				return
			}
			p.members[key] = append(p.members[key], name)
		}
		g.Size = int64(len(p.members[key]))
		writeJSONStatus(w, 200, f.op("addInstances", g.SelfLink))
	default:
		http.NotFound(w, r)
	}
}
