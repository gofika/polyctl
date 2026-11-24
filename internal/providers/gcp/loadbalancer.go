package gcp

import (
	"context"
	"fmt"
	"maps"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// `load-balancer ensure` builds, or completes, a regional external load
// balancer in front of one instance: the health check firewall rule and
// network tag, a regional TCP health check, a zonal instance group with
// the named port of the backend and the instance as member, a regional
// EXTERNAL_MANAGED backend service, then a URL map and a target HTTP or
// HTTPS proxy (http, https) or a target TCP proxy (tcp), and the
// forwarding rule. Each component is read first, created when missing,
// completed in place where that is safe (named ports, members, backends)
// and otherwise compared: a component that differs in a field polyctl
// cannot change in place stops the ensure (exit code 1), and nothing is
// ever deleted or rolled back.

const (
	lbProtoHTTP  = "http"
	lbProtoHTTPS = "https"
	lbProtoTCP   = "tcp"

	lbScheme = "EXTERNAL_MANAGED"

	// Health check settings of the checks ensure creates (the thresholds
	// keep the server defaults, 2 and 2).
	lbCheckInterval = 10
	lbCheckTimeout  = 5

	// defaultHealthTimeout bounds the wait for a HEALTHY backend: a new
	// backend reports no status for about two minutes first.
	defaultHealthTimeout = 3 * time.Minute

	reasonAlreadyExists = "alreadyExists"
	reasonMemberExists  = "memberAlreadyExists"
)

// lbNames are the names of the components of one load balancer.
type lbNames struct {
	lb, group, check, backend, proxy, rule, namedPort string
}

// lbEnsure is one load balancer ensure: what was asked and what was read.
type lbEnsure struct {
	rt      *app.Runtime
	c       *client
	scope   certScope
	profile string
	zone    string
	network string
	inst    *compute.Instance

	protocol        string // http, https, tcp
	backendProtocol string // HTTP, HTTPS, TCP
	port            int64
	backendPort     int64
	checkPort       int64
	sslCert         string
	// newCert, when set, is a certificate to create as sslCert first (the
	// "Create a new certificate..." choice of the interactive flow).
	newCert       *platform.CertMaterial
	newCertDesc   string
	address       string
	wait          bool
	timeout       time.Duration
	healthTimeout time.Duration
	names         lbNames

	// ip is the IP of the forwarding rule, once known.
	ip string
}

// namedPortName is the named port of a backend port: http for port 80
// behind HTTP(S) (as load balancers built before polyctl have it), else
// port-<port>. The backend service's port name is always this name.
func namedPortName(protocol string, port int64) string {
	if port == 80 && protocol != lbProtoTCP {
		return "http"
	}
	return "port-" + strconv.FormatInt(port, 10)
}

// normPortRange writes a port range as Compute Engine reads it back:
// "80" is "80-80".
func normPortRange(pr string) string {
	if pr != "" && !strings.Contains(pr, "-") {
		return pr + "-" + pr
	}
	return pr
}

// componentName joins a prefix and a base name, shortened with a hash when
// longer than 63 characters, and checks it against the Compute Engine name
// rule (a bad prefix in naming.* is exit code 2).
func componentName(what, name string) (string, error) {
	name = fitName(name)
	if !certNameRe.MatchString(name) {
		return "", app.UsageErrf("invalid %s name %q: a lower-case letter first, then lower-case letters, digits and hyphens, not ending with a hyphen, at most 63 characters", what, name)
	}
	return name, nil
}

// lbBaseName is the base the component names derive from: the instance
// name, or the name given with --name without the load balancer prefix
// (--name lb-tcp-db gives bs-tcp-db, --name site gives bs-site).
func lbBaseName(instance, name, lbPrefix, protocol string) string {
	if name == "" {
		return instance
	}
	base := name
	if protocol == lbProtoTCP && lbPrefix != "" && strings.HasPrefix(base, lbPrefix+"tcp-") {
		base = strings.TrimPrefix(base, lbPrefix+"tcp-")
	} else if lbPrefix != "" && strings.HasPrefix(base, lbPrefix) && len(base) > len(lbPrefix) {
		base = strings.TrimPrefix(base, lbPrefix)
	}
	return base
}

// deriveNames computes the component names (the naming keys in
// docs/configuration.md): prefixes from naming.gcp_*_prefix, the protocol inserted for
// the components a protocol owns.
func (e *lbEnsure) deriveNames(name, checkName string) error {
	cfg, err := e.rt.Config()
	if err != nil {
		return err
	}
	pre := func(key string) string { return cfg.NamingTemplate(key) }
	base := lbBaseName(e.inst.Name, name, pre("gcp_lb_prefix"), e.protocol)
	own := ""
	switch e.protocol {
	case lbProtoHTTPS:
		own = "https-"
	case lbProtoTCP:
		own = "tcp-"
	}
	shared := ""
	if e.protocol == lbProtoTCP {
		shared = "tcp-"
	}
	n := &e.names
	if name == "" {
		name = pre("gcp_lb_prefix") + shared + e.inst.Name
	}
	if n.lb, err = componentName("load balancer", name); err != nil {
		return err
	}
	if checkName == "" {
		checkName = "check-" + strconv.FormatInt(e.checkPort, 10)
	}
	if n.check, err = componentName("health check", checkName); err != nil {
		return err
	}
	for _, x := range []struct {
		dst  *string
		what string
		name string
	}{
		{&n.group, "instance group", pre("gcp_instance_group_prefix") + base},
		{&n.backend, "backend service", pre("gcp_backend_service_prefix") + shared + base},
		{&n.proxy, "target proxy", pre("gcp_proxy_prefix") + own + base},
		{&n.rule, "forwarding rule", pre("gcp_forwarding_rule_prefix") + own + base},
	} {
		if *x.dst, err = componentName(x.what, x.name); err != nil {
			return err
		}
	}
	n.namedPort = namedPortName(e.protocol, e.backendPort)
	return nil
}

// alreadyExists reports the 409 of an Insert that lost a race: the
// component is then read again and compared like an existing one.
func alreadyExists(err error) bool { return isReason(err, reasonAlreadyExists) }

// plan observes every component (read-only, in a dry run too) and returns
// the steps of the ensure.
func (e *lbEnsure) plan(ctx context.Context) (*platform.Plan, error) {
	if err := e.precheck(ctx); err != nil {
		return nil, err
	}
	var plan platform.Plan
	if e.newCert != nil {
		mat, s := e.newCert, e.scope
		plan.Add(platform.Step{Resource: "ssl-certificate/" + e.sslCert, Action: platform.Created, ID: s.certURL(e.sslCert),
			Desc: fmt.Sprintf("%s, %s, expires %s", s.label(), strings.Join(mat.Names(), ","), mat.Leaf.NotAfter.UTC().Format("2006-01-02")),
			Apply: func(ctx context.Context) (platform.Change, error) {
				if err := s.insertCert(ctx, e.sslCert, e.newCertDesc, mat); err != nil {
					return platform.Change{}, err
				}
				if sc, err := s.getCert(ctx, e.sslCert); err == nil {
					storeSSLCert(ctx, e.rt, e.profile, sc)
				}
				return platform.Change{Resource: "ssl-certificate/" + e.sslCert, Action: platform.Created, ID: s.certURL(e.sslCert)}, nil
			}})
	}
	steps := []func(context.Context) ([]platform.Step, error){
		e.firewallSteps, e.checkSteps, e.groupSteps, e.backendSteps, e.frontendSteps, e.ruleSteps, e.healthSteps,
	}
	for _, f := range steps {
		s, err := f(ctx)
		if err != nil {
			return nil, err
		}
		plan.Add(s...)
	}
	return &plan, nil
}

// precheck reads what must exist before anything is written: the
// certificate of an https load balancer and a proxy-only subnetwork of
// the network in the region. A failed check is reported in a dry run too.
func (e *lbEnsure) precheck(ctx context.Context) error {
	if e.protocol == lbProtoHTTPS && e.newCert == nil {
		sc, err := e.scope.findCert(ctx, e.sslCert)
		if err != nil {
			return err
		}
		if sc == nil {
			return fmt.Errorf("%w: SSL certificate %s (%s, gcp/%s): upload it first with `polyctl gcp compute ssl-certificate create %s --region %s --cert-file ... --key-file ...`",
				platform.ErrNotFound, e.sslCert, e.scope.label(), e.profile, e.sslCert, e.scope.region)
		}
	}
	subnets, err := e.c.subnetworksOf(ctx, e.scope.region, e.network)
	if err != nil {
		return err
	}
	for _, s := range subnets {
		if s.Purpose == "REGIONAL_MANAGED_PROXY" && s.Role == "ACTIVE" {
			return nil
		}
	}
	return fmt.Errorf("network %s has no active proxy-only subnetwork in region %s (gcp/%s): a regional external load balancer needs one (purpose REGIONAL_MANAGED_PROXY, role ACTIVE); create it first, for example: gcloud compute networks subnets create proxy-only-%s --purpose=REGIONAL_MANAGED_PROXY --role=ACTIVE --network=%s --region=%s --range=<CIDR, e.g. 10.129.0.0/23>",
		e.network, e.scope.region, e.profile, e.scope.region, e.network, e.scope.region)
}

// firewallSteps: the health check rule of the network (a missing
// permission is a skipped step: a shared VPC host project may manage the
// rules) and the network tag of the instance.
func (e *lbEnsure) firewallSteps(ctx context.Context) ([]platform.Step, error) {
	rendered, err := e.rt.ResourceName("gcp_lb_firewall", "", map[string]string{"network": e.network, "region": e.scope.region})
	if err != nil {
		return nil, app.UsageErrf("%v", err)
	}
	name := fitName(rendered)
	if err := checkFirewallName(name); err != nil {
		return nil, err
	}
	tag, err := e.rt.Setting(e.profile, platform.GCP, "lb_network_tag", "")
	if err != nil {
		return nil, err
	}
	fw, err := e.c.EnsureLBFirewall(ctx, LBFirewallOptions{Network: e.network, Region: e.scope.region, Name: name, TargetTag: tag,
		Wait: true, Timeout: e.timeout, SkipForbidden: true})
	if err != nil {
		return nil, err
	}
	rt, profile := e.rt, e.profile
	tagStep := e.c.EnsureInstanceTag(e.zone, e.inst, tag, true, e.timeout, func(in *compute.Instance) { storeInstance(ctx, rt, profile, in) })
	return []platform.Step{fw, tagStep}, nil
}

// checkDesc describes a health check of polyctl's shape.
func (e *lbEnsure) checkDesc(port int64) string {
	return fmt.Sprintf("%s TCP :%d", e.scope.kind(), port)
}

// compareCheck accepts an existing health check: TCP on the health check
// port. Another one may be shared by other load balancers and is not
// changed.
func (e *lbEnsure) compareCheck(hc *compute.HealthCheck) error {
	port := int64(0)
	if hc.TcpHealthCheck != nil {
		port = hc.TcpHealthCheck.Port
	}
	if hc.Type != "TCP" || port != e.checkPort {
		return fmt.Errorf("health check %s exists as %s :%d, not TCP :%d; it may serve other load balancers, so polyctl does not change it: pass --health-check-name for another one, or delete it first (gcp compute health-check delete %s --region %s)",
			hc.Name, hc.Type, port, e.checkPort, hc.Name, e.scope.region)
	}
	return nil
}

func (e *lbEnsure) checkSteps(ctx context.Context) ([]platform.Step, error) {
	name := e.names.check
	res := string(kindHealthCheck) + "/" + name
	hc, err := e.scope.findHealthCheck(ctx, name)
	if err != nil {
		return nil, err
	}
	if hc != nil {
		if err := e.compareCheck(hc); err != nil {
			return nil, err
		}
		return []platform.Step{{Resource: res, Action: platform.Unchanged, ID: e.scope.healthCheckURL(name), Desc: e.checkDesc(e.checkPort)}}, nil
	}
	desc := fmt.Sprintf("%s interval %ds timeout %ds", e.checkDesc(e.checkPort), lbCheckInterval, lbCheckTimeout)
	body := &compute.HealthCheck{Name: name, Type: "TCP", TcpHealthCheck: &compute.TCPHealthCheck{Port: e.checkPort},
		CheckIntervalSec: lbCheckInterval, TimeoutSec: lbCheckTimeout}
	return []platform.Step{{Resource: res, Action: platform.Created, ID: e.scope.healthCheckURL(name), Desc: desc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			err := e.scope.insertHealthCheck(ctx, body)
			if alreadyExists(err) {
				got, gerr := e.scope.findHealthCheck(ctx, name)
				if gerr != nil || got == nil {
					return platform.Change{}, err
				}
				if cerr := e.compareCheck(got); cerr != nil {
					return platform.Change{}, cerr
				}
				return platform.Change{Action: platform.Unchanged, Detail: e.checkDesc(e.checkPort) + " (created meanwhile)"}, nil
			}
			return platform.Change{}, err
		}}}, nil
}

// findLBGroup returns the instance group of the zone that holds the
// instance and that a backend service uses (an instance may belong to one
// such group only, so a second load balancer of the instance must reuse
// it), with the backend services using it; nil when there is none.
func (e *lbEnsure) findLBGroup(ctx context.Context) (*compute.InstanceGroup, []string, error) {
	groups, err := e.c.listInstanceGroups(ctx, e.zone)
	if err != nil {
		return nil, nil, err
	}
	var holding []*compute.InstanceGroup
	for _, g := range groups {
		members, err := e.c.groupMembers(ctx, e.zone, g.Name)
		if err != nil {
			return nil, nil, err
		}
		if hasMember(members, e.inst.Name) {
			holding = append(holding, g)
		}
	}
	if len(holding) == 0 {
		return nil, nil, nil
	}
	var services []*compute.BackendService
	for _, s := range []certScope{{c: e.c}, e.scope} {
		list, err := s.listBackendServices(ctx)
		if err != nil {
			return nil, nil, err
		}
		services = append(services, list...)
	}
	for _, g := range holding {
		url := e.c.instanceGroupURL(e.zone, g.Name)
		var users []string
		for _, bs := range services {
			for _, b := range bs.Backends {
				if sameResource(b.Group, url) {
					users = append(users, bs.Name)
					break
				}
			}
		}
		if len(users) > 0 {
			sort.Strings(users)
			return g, users, nil
		}
	}
	return nil, nil, nil
}

// namedPortLabel renders named ports as name:port, sorted.
func namedPortLabel(ports []*compute.NamedPort) string {
	var out []string
	for _, p := range ports {
		out = append(out, p.Name+":"+strconv.FormatInt(p.Port, 10))
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// namedPortState tells whether the group has the named port: present,
// missing, or taken by another port (an error: other backends use it).
func (e *lbEnsure) namedPortState(g *compute.InstanceGroup) (present bool, err error) {
	for _, p := range g.NamedPorts {
		if p.Name == e.names.namedPort {
			if p.Port == e.backendPort {
				return true, nil
			}
			return false, fmt.Errorf("instance group %s has the named port %s:%d, not %s:%d; other backend services may use it, so polyctl does not change it: pass --backend-port %d, or a --name of its own for a separate load balancer",
				g.Name, p.Name, p.Port, e.names.namedPort, e.backendPort, p.Port)
		}
	}
	return false, nil
}

// addNamedPort adds the named port to the group, keeping the ports it has
// (SetNamedPorts replaces the list as a whole), with the fingerprint as
// read; a stale fingerprint is read again and retried once.
func (e *lbEnsure) addNamedPort(ctx context.Context, g *compute.InstanceGroup) (bool, error) {
	cur := g
	for attempt := 0; ; attempt++ {
		present, err := e.namedPortState(cur)
		if err != nil || present {
			return false, err
		}
		ports := append(slices.Clone(cur.NamedPorts), &compute.NamedPort{Name: e.names.namedPort, Port: e.backendPort})
		op, err := e.c.compute.InstanceGroups.SetNamedPorts(e.c.project, e.zone, cur.Name,
			&compute.InstanceGroupsSetNamedPortsRequest{NamedPorts: ports, Fingerprint: cur.Fingerprint}).Context(ctx).Do()
		if err != nil && attempt == 0 && isFingerprintMismatch(err) {
			next, gerr := e.c.findInstanceGroup(ctx, e.zone, cur.Name)
			if gerr != nil {
				return false, gerr
			}
			if next == nil {
				return false, computeErr(err)
			}
			cur = next
			continue
		}
		return true, e.c.zoneSubmitted(ctx, e.zone, e.timeout, op, err)
	}
}

func (e *lbEnsure) groupSteps(ctx context.Context) ([]platform.Step, error) {
	g, users, err := e.findLBGroup(ctx)
	if err != nil {
		return nil, err
	}
	reused := g != nil
	if reused {
		e.names.group = g.Name
	} else if g, err = e.c.findInstanceGroup(ctx, e.zone, e.names.group); err != nil {
		return nil, err
	}
	name := e.names.group
	res := string(kindInstanceGroup) + "/" + name
	np := e.names.namedPort + ":" + strconv.FormatInt(e.backendPort, 10)
	member := platform.Step{Resource: res + "/member", Action: platform.Created, Desc: e.inst.Name,
		Apply: func(ctx context.Context) (platform.Change, error) {
			op, err := e.c.compute.InstanceGroups.AddInstances(e.c.project, e.zone, name, &compute.InstanceGroupsAddInstancesRequest{
				Instances: []*compute.InstanceReference{{Instance: e.c.instanceRef(e.zone, e.inst.Name)}}}).Context(ctx).Do()
			if err != nil && isReason(err, reasonMemberExists) {
				return platform.Change{Action: platform.Unchanged, Detail: e.inst.Name + " (already a member)"}, nil
			}
			return platform.Change{}, e.c.zoneSubmitted(ctx, e.zone, e.timeout, op, err)
		}}
	if g == nil {
		body := &compute.InstanceGroup{Name: name, Network: e.c.networkPath(e.network),
			NamedPorts: []*compute.NamedPort{{Name: e.names.namedPort, Port: e.backendPort}}}
		create := platform.Step{Resource: res, Action: platform.Created, ID: e.c.instanceGroupURL(e.zone, name),
			Desc: "zone " + e.zone + ", named-port " + np,
			Apply: func(ctx context.Context) (platform.Change, error) {
				op, err := e.c.compute.InstanceGroups.Insert(e.c.project, e.zone, body).Context(ctx).Do()
				if err != nil && alreadyExists(err) {
					got, gerr := e.c.findInstanceGroup(ctx, e.zone, name)
					if gerr != nil || got == nil {
						return platform.Change{}, computeErr(err)
					}
					added, aerr := e.addNamedPort(ctx, got)
					if aerr != nil {
						return platform.Change{}, aerr
					}
					if added {
						return platform.Change{Action: platform.Updated, Detail: "+named-port " + np + " (group created meanwhile)"}, nil
					}
					return platform.Change{Action: platform.Unchanged, Detail: "zone " + e.zone + ", named-port " + np + " (created meanwhile)"}, nil
				}
				return platform.Change{}, e.c.zoneSubmitted(ctx, e.zone, e.timeout, op, err)
			}}
		return []platform.Step{create, member}, nil
	}
	if zone := lastSegment(g.Zone); zone != "" && zone != e.zone {
		return nil, fmt.Errorf("instance group %s is in zone %s, not in zone %s of instance %s: an instance group and its members share one zone; pass a --name of its own to build the load balancer with a new instance group in %s",
			name, zone, e.zone, e.inst.Name, e.zone)
	}
	if n := lastSegment(g.Network); n != "" && n != e.network {
		return nil, fmt.Errorf("instance group %s is on network %s, not on network %s of instance %s: pass a --name of its own for a new instance group", name, n, e.network, e.inst.Name)
	}
	present, err := e.namedPortState(g)
	if err != nil {
		return nil, err
	}
	desc := "zone " + e.zone + ", named-port " + np
	if reused {
		desc += " (used by backend service " + strings.Join(users, ", ") + ")"
	}
	var steps []platform.Step
	if present {
		steps = append(steps, platform.Step{Resource: res, Action: platform.Unchanged, ID: e.c.instanceGroupURL(e.zone, name), Desc: desc})
	} else {
		kept := namedPortLabel(g.NamedPorts)
		upd := "+named-port " + np
		if kept != "" {
			upd += " (kept " + kept + ")"
		}
		steps = append(steps, platform.Step{Resource: res, Action: platform.Updated, ID: e.c.instanceGroupURL(e.zone, name), Desc: upd,
			Apply: func(ctx context.Context) (platform.Change, error) {
				cur, err := e.c.findInstanceGroup(ctx, e.zone, name)
				if err != nil {
					return platform.Change{}, err
				}
				if cur == nil {
					return platform.Change{}, fmt.Errorf("%w: instance group %s disappeared", platform.ErrNotFound, name)
				}
				added, err := e.addNamedPort(ctx, cur)
				if err == nil && !added {
					return platform.Change{Action: platform.Unchanged, Detail: desc}, nil
				}
				return platform.Change{}, err
			}})
	}
	members, err := e.c.groupMembers(ctx, e.zone, name)
	if err != nil {
		return nil, err
	}
	if hasMember(members, e.inst.Name) {
		member.Action, member.Apply = platform.Unchanged, nil
	}
	return append(steps, member), nil
}

// backendDesc describes the backend service ensure wants.
func (e *lbEnsure) backendDesc() string {
	return e.backendProtocol + ", port-name " + e.names.namedPort + ", " + lbScheme
}

// compareBackend checks an existing backend service: protocol, port name,
// scheme and health check must be as wanted; a missing backend (the
// instance group) is the one thing ensure adds in place.
func (e *lbEnsure) compareBackend(bs *compute.BackendService) (missingGroup bool, err error) {
	var diffs []string
	if bs.Protocol != e.backendProtocol {
		diffs = append(diffs, "protocol "+bs.Protocol+" (want "+e.backendProtocol+")")
	}
	if bs.PortName != e.names.namedPort {
		diffs = append(diffs, "port name "+dash(bs.PortName)+" (want "+e.names.namedPort+")")
	}
	if bs.LoadBalancingScheme != lbScheme {
		diffs = append(diffs, "scheme "+dash(bs.LoadBalancingScheme)+" (want "+lbScheme+")")
	}
	checkURL := e.scope.healthCheckURL(e.names.check)
	if !slices.ContainsFunc(bs.HealthChecks, func(u string) bool { return sameResource(u, checkURL) }) {
		var have []string
		for _, u := range bs.HealthChecks {
			have = append(have, lastSegment(u))
		}
		diffs = append(diffs, "health checks "+dash(strings.Join(have, ","))+" (want "+e.names.check+")")
	}
	if len(diffs) > 0 {
		return false, fmt.Errorf("backend service %s exists with %s: polyctl does not change these in place; delete it first (gcp compute backend-service delete %s --region %s) or pass a --name of its own",
			bs.Name, strings.Join(diffs, ", "), bs.Name, e.scope.region)
	}
	group := e.c.instanceGroupURL(e.zone, e.names.group)
	return !slices.ContainsFunc(bs.Backends, func(b *compute.Backend) bool { return sameResource(b.Group, group) }), nil
}

func (e *lbEnsure) newBackend() *compute.Backend {
	return &compute.Backend{Group: e.c.instanceGroupURL(e.zone, e.names.group), BalancingMode: "UTILIZATION", MaxUtilization: 0.8}
}

// appendBackend adds the instance group to the backends of a backend
// service, keeping the others.
func (e *lbEnsure) appendBackend(ctx context.Context, bs *compute.BackendService) error {
	backends := append(slices.Clone(bs.Backends), e.newBackend())
	return e.scope.patchBackendService(ctx, bs.Name, &compute.BackendService{Backends: backends, Fingerprint: bs.Fingerprint})
}

func (e *lbEnsure) backendSteps(ctx context.Context) ([]platform.Step, error) {
	name := e.names.backend
	res := string(kindBackendService) + "/" + name
	id := e.scope.backendServiceURL(name)
	bs, err := e.scope.findBackendService(ctx, name)
	if err != nil {
		return nil, err
	}
	if bs != nil {
		missing, err := e.compareBackend(bs)
		if err != nil {
			return nil, err
		}
		if !missing {
			return []platform.Step{{Resource: res, Action: platform.Unchanged, ID: id, Desc: e.backendDesc()}}, nil
		}
		return []platform.Step{{Resource: res, Action: platform.Updated, ID: id, Desc: "+backend " + e.names.group,
			Apply: func(ctx context.Context) (platform.Change, error) {
				cur, err := e.scope.findBackendService(ctx, name)
				if err != nil {
					return platform.Change{}, err
				}
				if cur == nil {
					return platform.Change{}, fmt.Errorf("%w: backend service %s disappeared", platform.ErrNotFound, name)
				}
				return platform.Change{}, e.appendBackend(ctx, cur)
			}}}, nil
	}
	body := &compute.BackendService{Name: name, Protocol: e.backendProtocol, PortName: e.names.namedPort, TimeoutSec: 30,
		HealthChecks: []string{e.scope.healthCheckURL(e.names.check)}, LoadBalancingScheme: lbScheme, Backends: []*compute.Backend{e.newBackend()}}
	return []platform.Step{{Resource: res, Action: platform.Created, ID: id, Desc: e.backendDesc(),
		Apply: func(ctx context.Context) (platform.Change, error) {
			err := e.scope.insertBackendService(ctx, body)
			if !alreadyExists(err) {
				return platform.Change{}, err
			}
			got, gerr := e.scope.findBackendService(ctx, name)
			if gerr != nil || got == nil {
				return platform.Change{}, err
			}
			missing, cerr := e.compareBackend(got)
			if cerr != nil {
				return platform.Change{}, cerr
			}
			if missing {
				return platform.Change{Action: platform.Updated, Detail: "+backend " + e.names.group + " (created meanwhile)"}, e.appendBackend(ctx, got)
			}
			return platform.Change{Action: platform.Unchanged, Detail: e.backendDesc() + " (created meanwhile)"}, nil
		}}}, nil
}

// frontendSteps: the URL map and the target HTTP(S) proxy, or the target
// TCP proxy.
func (e *lbEnsure) frontendSteps(ctx context.Context) ([]platform.Step, error) {
	if e.protocol == lbProtoTCP {
		return e.tcpProxySteps(ctx)
	}
	m, err := e.urlMapStep(ctx)
	if err != nil {
		return nil, err
	}
	var p platform.Step
	if e.protocol == lbProtoHTTPS {
		p, err = e.httpsProxyStep(ctx)
	} else {
		p, err = e.httpProxyStep(ctx)
	}
	if err != nil {
		return nil, err
	}
	return []platform.Step{m, p}, nil
}

// createStep is the step of a component created by insert; a 409 (created
// meanwhile) reads it again and compares it with compare.
func createStep(res, id, desc string, insert func(context.Context) error, recheck func(context.Context) (bool, error)) platform.Step {
	return platform.Step{Resource: res, Action: platform.Created, ID: id, Desc: desc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			err := insert(ctx)
			if !alreadyExists(err) {
				return platform.Change{}, err
			}
			found, cerr := recheck(ctx)
			if cerr != nil {
				return platform.Change{}, cerr
			}
			if !found {
				return platform.Change{}, err
			}
			return platform.Change{Action: platform.Unchanged, Detail: desc + " (created meanwhile)"}, nil
		}}
}

func (e *lbEnsure) compareURLMap(m *compute.UrlMap) error {
	if lastSegment(m.DefaultService) != e.names.backend || !strings.Contains(m.DefaultService, "/backendServices/") {
		return fmt.Errorf("URL map %s exists with default service %s, not backend service %s: polyctl does not change it; delete it first or pass a --name of its own",
			m.Name, dash(lastSegment(m.DefaultService)), e.names.backend)
	}
	return nil
}

func (e *lbEnsure) urlMapStep(ctx context.Context) (platform.Step, error) {
	name := e.names.lb
	res := string(kindURLMap) + "/" + name
	desc := "default -> " + e.names.backend
	m, err := e.scope.findURLMap(ctx, name)
	if err != nil {
		return platform.Step{}, err
	}
	if m != nil {
		if err := e.compareURLMap(m); err != nil {
			return platform.Step{}, err
		}
		return platform.Step{Resource: res, Action: platform.Unchanged, ID: e.scope.urlMapURL(name), Desc: desc}, nil
	}
	body := &compute.UrlMap{Name: name, DefaultService: e.scope.backendServiceURL(e.names.backend)}
	return createStep(res, e.scope.urlMapURL(name), desc,
		func(ctx context.Context) error { return e.scope.insertURLMap(ctx, body) },
		func(ctx context.Context) (bool, error) {
			got, err := e.scope.findURLMap(ctx, name)
			if err != nil || got == nil {
				return false, err
			}
			return true, e.compareURLMap(got)
		}), nil
}

func (e *lbEnsure) compareProxyMap(kind lbKind, name, urlMap string) error {
	if lastSegment(urlMap) != e.names.lb {
		return fmt.Errorf("%s %s exists with URL map %s, not %s: polyctl does not change it; delete it first or pass a --name of its own", kind, name, dash(lastSegment(urlMap)), e.names.lb)
	}
	return nil
}

func (e *lbEnsure) httpProxyStep(ctx context.Context) (platform.Step, error) {
	name := e.names.proxy
	res := string(kindHTTPProxy) + "/" + name
	desc := "-> " + e.names.lb
	p, err := e.scope.findHTTPProxy(ctx, name)
	if err != nil {
		return platform.Step{}, err
	}
	if p != nil {
		if err := e.compareProxyMap(kindHTTPProxy, name, p.UrlMap); err != nil {
			return platform.Step{}, err
		}
		return platform.Step{Resource: res, Action: platform.Unchanged, ID: e.scope.httpProxyURL(name), Desc: desc}, nil
	}
	body := &compute.TargetHttpProxy{Name: name, UrlMap: e.scope.urlMapURL(e.names.lb)}
	return createStep(res, e.scope.httpProxyURL(name), desc,
		func(ctx context.Context) error { return e.scope.insertHTTPProxy(ctx, body) },
		func(ctx context.Context) (bool, error) {
			got, err := e.scope.findHTTPProxy(ctx, name)
			if err != nil || got == nil {
				return false, err
			}
			return true, e.compareProxyMap(kindHTTPProxy, name, got.UrlMap)
		}), nil
}

// compareHTTPSProxy accepts an HTTPS proxy on the URL map that holds
// certificates; which ones is the business of `load-balancer cert set`.
func (e *lbEnsure) compareHTTPSProxy(p *compute.TargetHttpsProxy) error {
	if err := e.compareProxyMap(kindHTTPSProxy, p.Name, p.UrlMap); err != nil {
		return err
	}
	if len(p.SslCertificates) == 0 && p.CertificateMap == "" {
		return fmt.Errorf("target HTTPS proxy %s exists without certificates: put one on it with `polyctl gcp compute load-balancer cert set %s --domain <d>`", p.Name, e.names.lb)
	}
	return nil
}

func (e *lbEnsure) httpsProxyStep(ctx context.Context) (platform.Step, error) {
	name := e.names.proxy
	res := string(kindHTTPSProxy) + "/" + name
	p, err := e.scope.findHTTPSProxy(ctx, name)
	if err != nil {
		return platform.Step{}, err
	}
	if p != nil {
		if err := e.compareHTTPSProxy(p); err != nil {
			return platform.Step{}, err
		}
		var certs []string
		for _, u := range p.SslCertificates {
			certs = append(certs, lastSegment(u))
		}
		desc := "-> " + e.names.lb + ", certs: " + dash(strings.Join(certs, ","))
		if !slices.Contains(certs, e.sslCert) {
			desc += " (certificates are changed by load-balancer cert set)"
		}
		return platform.Step{Resource: res, Action: platform.Unchanged, ID: e.scope.proxyURL(name), Desc: desc}, nil
	}
	desc := "-> " + e.names.lb + ", certs: " + e.sslCert
	body := &compute.TargetHttpsProxy{Name: name, UrlMap: e.scope.urlMapURL(e.names.lb), SslCertificates: []string{e.scope.certURL(e.sslCert)}}
	return createStep(res, e.scope.proxyURL(name), desc,
		func(ctx context.Context) error { return e.scope.insertHTTPSProxy(ctx, body) },
		func(ctx context.Context) (bool, error) {
			got, err := e.scope.findHTTPSProxy(ctx, name)
			if err != nil || got == nil {
				return false, err
			}
			return true, e.compareHTTPSProxy(got)
		}), nil
}

func (e *lbEnsure) compareTCPProxy(p *compute.TargetTcpProxy) error {
	if lastSegment(p.Service) != e.names.backend {
		return fmt.Errorf("target TCP proxy %s exists with backend service %s, not %s: polyctl does not change it; delete it first or pass a --name of its own", p.Name, dash(lastSegment(p.Service)), e.names.backend)
	}
	return nil
}

func (e *lbEnsure) tcpProxySteps(ctx context.Context) ([]platform.Step, error) {
	name := e.names.proxy
	res := string(kindTCPProxy) + "/" + name
	desc := "-> " + e.names.backend
	p, err := e.scope.findTCPProxy(ctx, name)
	if err != nil {
		return nil, err
	}
	if p != nil {
		if err := e.compareTCPProxy(p); err != nil {
			return nil, err
		}
		return []platform.Step{{Resource: res, Action: platform.Unchanged, ID: e.scope.tcpProxyURL(name), Desc: desc}}, nil
	}
	body := &compute.TargetTcpProxy{Name: name, Service: e.scope.backendServiceURL(e.names.backend)}
	return []platform.Step{createStep(res, e.scope.tcpProxyURL(name), desc,
		func(ctx context.Context) error { return e.scope.insertTCPProxy(ctx, body) },
		func(ctx context.Context) (bool, error) {
			got, err := e.scope.findTCPProxy(ctx, name)
			if err != nil || got == nil {
				return false, err
			}
			return true, e.compareTCPProxy(got)
		})}, nil
}

// proxyRef is the reference of the target proxy the rule forwards to.
func (e *lbEnsure) proxyRef() (lbKind, string) {
	switch e.protocol {
	case lbProtoHTTPS:
		return kindHTTPSProxy, e.scope.proxyURL(e.names.proxy)
	case lbProtoTCP:
		return kindTCPProxy, e.scope.tcpProxyURL(e.names.proxy)
	}
	return kindHTTPProxy, e.scope.httpProxyURL(e.names.proxy)
}

// compareRule checks an existing forwarding rule: its target, ports and
// scheme, and with --address its IP, cannot change in place.
func (e *lbEnsure) compareRule(fr *compute.ForwardingRule, addressIP string) error {
	kind, target := e.proxyRef()
	var diffs []string
	if !sameResource(fr.Target, target) && (lastSegment(fr.Target) != e.names.proxy || proxyKind(fr.Target) != kind) {
		diffs = append(diffs, "target "+dash(lastSegment(fr.Target))+" (want "+string(kind)+" "+e.names.proxy+")")
	}
	if want := normPortRange(strconv.FormatInt(e.port, 10)); normPortRange(fr.PortRange) != want {
		diffs = append(diffs, "ports "+dash(fr.PortRange)+" (want "+strconv.FormatInt(e.port, 10)+")")
	}
	if fr.LoadBalancingScheme != lbScheme {
		diffs = append(diffs, "scheme "+dash(fr.LoadBalancingScheme)+" (want "+lbScheme+")")
	}
	if addressIP != "" && fr.IPAddress != addressIP {
		diffs = append(diffs, "IP "+dash(fr.IPAddress)+" (want "+addressIP+" of address "+e.address+")")
	}
	if len(diffs) > 0 {
		return fmt.Errorf("forwarding rule %s exists with %s: polyctl does not change a forwarding rule in place; delete it first (gcp compute forwarding-rule delete %s --region %s) or pass a --name of its own",
			fr.Name, strings.Join(diffs, ", "), fr.Name, e.scope.region)
	}
	return nil
}

func (e *lbEnsure) ruleSteps(ctx context.Context) ([]platform.Step, error) {
	var steps []platform.Step
	region := e.scope.region
	name := e.names.rule
	res := string(kindRule) + "/" + name
	fr, err := e.scope.findRule(ctx, name)
	if err != nil {
		return nil, err
	}
	addressIP := ""
	if e.address != "" {
		a, err := e.c.getAddress(ctx, region, e.address)
		if err != nil {
			return nil, err
		}
		switch {
		case a == nil:
			// A forwarding rule that exists keeps its IP (it cannot change in
			// place), so the missing address is reserved with that IP: the
			// rule's ephemeral IP becomes static. A new rule gets a new
			// address.
			addr := e.address
			body := &compute.Address{Name: addr, AddressType: addrExternal, NetworkTier: "PREMIUM"}
			desc := "external, premium tier, " + region
			if fr != nil && fr.IPAddress != "" {
				body.Address = fr.IPAddress
				desc = "promote " + fr.IPAddress + " of forwarding rule " + fr.Name + ", premium tier, " + region
			}
			steps = append(steps, platform.Step{Resource: "address/" + addr, Action: platform.Created, Desc: desc,
				Apply: func(ctx context.Context) (platform.Change, error) {
					wctx, cancel, conv := deadline(ctx, e.timeout, "address/"+addr, "RESERVED")
					defer cancel()
					got, err := e.c.insertAddress(wctx, region, body)
					if err != nil {
						return platform.Change{}, conv(err)
					}
					return platform.Change{Detail: "reserved " + got.Address}, nil
				}})
		case addressType(a) != addrExternal:
			return nil, fmt.Errorf("address %s is an internal address (%s): a forwarding rule of an external load balancer needs an external one", e.address, a.Address)
		default:
			addressIP = a.Address
			steps = append(steps, platform.Step{Resource: "address/" + e.address, Action: platform.Unchanged, Desc: "reserved " + a.Address})
		}
	}
	portLabel := ":" + strconv.FormatInt(e.port, 10)
	if fr != nil {
		if err := e.compareRule(fr, addressIP); err != nil {
			return nil, err
		}
		e.ip = fr.IPAddress
		steps = append(steps, platform.Step{Resource: res, Action: platform.Unchanged, ID: e.scope.prefix() + "forwardingRules/" + name, Desc: fr.IPAddress + portLabel})
		return append(steps, e.labelStep(fr)), nil
	}
	_, target := e.proxyRef()
	ipDesc := addressIP
	if ipDesc == "" {
		ipDesc = "ip " + platform.Pending
		if e.address == "" {
			ipDesc += " (ephemeral)"
		}
	}
	var created *compute.ForwardingRule
	steps = append(steps, platform.Step{Resource: res, Action: platform.Created, ID: e.scope.prefix() + "forwardingRules/" + name, Desc: portLabel + ", " + ipDesc,
		Apply: func(ctx context.Context) (platform.Change, error) {
			body := &compute.ForwardingRule{Name: name, Target: target, PortRange: strconv.FormatInt(e.port, 10), IPProtocol: "TCP",
				LoadBalancingScheme: lbScheme, NetworkTier: "PREMIUM", Network: e.c.networkPath(e.network)}
			if e.address != "" {
				a, err := e.c.getAddress(ctx, region, e.address)
				if err != nil {
					return platform.Change{}, err
				}
				if a == nil {
					return platform.Change{}, fmt.Errorf("%w: address %s", platform.ErrNotFound, e.address)
				}
				body.IPAddress = a.Address
			}
			err := e.scope.insertRule(ctx, body)
			if err != nil && !alreadyExists(err) {
				return platform.Change{}, err
			}
			got, gerr := e.scope.findRule(ctx, name)
			if gerr != nil {
				return platform.Change{}, gerr
			}
			if got == nil {
				if err != nil {
					return platform.Change{}, err
				}
				return platform.Change{}, fmt.Errorf("forwarding rule %s was created but cannot be read back", name)
			}
			created = got
			e.ip = got.IPAddress
			if err != nil {
				if cerr := e.compareRule(got, body.IPAddress); cerr != nil {
					return platform.Change{}, cerr
				}
				return platform.Change{Action: platform.Unchanged, Detail: got.IPAddress + portLabel + " (created meanwhile)"}, nil
			}
			return platform.Change{Detail: got.IPAddress + portLabel}, nil
		}})
	label := e.labelStep(nil)
	label.Apply = func(ctx context.Context) (platform.Change, error) {
		if created == nil {
			return platform.Change{Action: platform.Skipped, Detail: "the forwarding rule was not read back"}, nil
		}
		return e.writeLabel(ctx, created)
	}
	return append(steps, label), nil
}

// labelStep is the step that labels the forwarding rule with the load
// balancer name (labels sent with the creation are ignored by Compute
// Engine, so they are written afterwards). A rule labelled with another
// load balancer name keeps its label.
func (e *lbEnsure) labelStep(fr *compute.ForwardingRule) platform.Step {
	res := string(kindRule) + "/" + e.names.rule + "/labels"
	want := lbLabel + "=" + e.names.lb
	step := platform.Step{Resource: res, Action: platform.Created, Desc: want}
	if fr == nil {
		return step
	}
	switch have, ok := fr.Labels[lbLabel]; {
	case ok && have == e.names.lb:
		step.Action = platform.Unchanged
	case ok:
		step.Action, step.Desc = platform.Skipped, "labelled "+lbLabel+"="+have+", left as it is"
	default:
		if len(fr.Labels) > 0 {
			step.Action = platform.Updated
		}
		step.Apply = func(ctx context.Context) (platform.Change, error) { return e.writeLabel(ctx, fr) }
	}
	return step
}

// writeLabel adds the load balancer label to the rule's labels with the
// fingerprint as read. A failure does not undo anything: it is reported
// as skipped with a warning (load-balancer list then groups the rule by
// its URL map or its own name).
func (e *lbEnsure) writeLabel(ctx context.Context, fr *compute.ForwardingRule) (platform.Change, error) {
	labels := maps.Clone(fr.Labels)
	if labels == nil {
		labels = map[string]string{}
	}
	labels[lbLabel] = e.names.lb
	if err := e.scope.setRuleLabels(ctx, fr.Name, labels, fr.LabelFingerprint); err != nil {
		e.rt.Infof("warning: forwarding rule %s works, but its label %s=%s could not be written: %v", fr.Name, lbLabel, e.names.lb, err)
		return platform.Change{Action: platform.Skipped, Detail: "label not written: " + err.Error()}, nil
	}
	return platform.Change{}, nil
}

// healthSteps waits for a HEALTHY backend (http and https; --no-wait and
// a dry run skip it). Running out of time is not an error: the load
// balancer is built, and a troubleshooting list goes to stderr.
func (e *lbEnsure) healthSteps(context.Context) ([]platform.Step, error) {
	if e.protocol == lbProtoTCP {
		return nil, nil
	}
	res := "load-balancer/" + e.names.lb + "/backend-health"
	group := e.c.instanceGroupURL(e.zone, e.names.group)
	return []platform.Step{{Resource: res, Check: func(ctx context.Context) (platform.Change, bool, error) {
		switch {
		case e.rt.DryRun():
			return platform.Change{Action: platform.Skipped, Detail: "dry-run"}, true, nil
		case !e.wait:
			return platform.Change{Action: platform.Skipped, Detail: "--no-wait"}, true, nil
		}
		e.rt.Infof("waiting up to %s for a HEALTHY backend of %s...", e.healthTimeout, e.names.backend)
		ok, last, err := e.scope.waitBackendHealthy(ctx, e.names.backend, group, e.healthTimeout, lbHealthInterval, instanceClock)
		if err != nil {
			return platform.Change{}, false, err
		}
		if ok {
			return platform.Change{Action: platform.Unchanged, Detail: "HEALTHY"}, true, nil
		}
		e.troubleshoot(last)
		return platform.Change{Action: platform.Skipped, Detail: fmt.Sprintf("not HEALTHY after %s (last: %s)", e.healthTimeout, last)}, true, nil
	}}}, nil
}

// troubleshoot prints what to check when the backend did not turn HEALTHY.
func (e *lbEnsure) troubleshoot(last string) {
	rt := e.rt
	tag, _ := rt.Setting(e.profile, platform.GCP, "lb_network_tag", "")
	fw, _ := rt.ResourceName("gcp_lb_firewall", "", map[string]string{"network": e.network, "region": e.scope.region})
	rt.Infof("warning: no HEALTHY backend behind %s after %s (last: %s); the load balancer is built. Check:", e.names.backend, e.healthTimeout, last)
	rt.Infof("  - instance %s is running and listens on port %d (health checks probe TCP :%d)", e.inst.Name, e.backendPort, e.checkPort)
	rt.Infof("  - firewall rule %s allows 35.191.0.0/16, 130.211.0.0/22 and the proxy-only subnetwork of %s", fitName(fw), e.scope.region)
	rt.Infof("  - instance %s has the network tag %s", e.inst.Name, tag)
	rt.Infof("  polyctl gcp compute backend-service get %s --region %s", e.names.backend, e.scope.region)
	rt.Infof("  polyctl gcp compute firewall get %s", fitName(fw))
	rt.Infof("  polyctl gcp compute instance get %s --zone %s", e.inst.Name, e.zone)
}

// summary is the "load_balancer" object of the ensure output.
func (e *lbEnsure) summary() lbSummary {
	s := lbSummary{Name: e.names.lb, Protocol: strings.ToUpper(e.protocol), Scope: e.scope.kind(), Region: e.scope.region, IPAddress: e.ip, Port: e.port}
	if e.ip != "" {
		s.URL = accessURL(e.protocol, e.ip, e.port)
	}
	return s
}

// accessURL is the address of the load balancer: http://ip/, https://ip/
// (the port when it is not the protocol's own), ip:port for tcp.
func accessURL(protocol, ip string, port int64) string {
	p := strconv.FormatInt(port, 10)
	switch {
	case protocol == lbProtoTCP:
		return ip + ":" + p
	case protocol == lbProtoHTTP && port == 80, protocol == lbProtoHTTPS && port == 443:
		return protocol + "://" + ip + "/"
	}
	return protocol + "://" + ip + ":" + p + "/"
}

// lbSummary describes the load balancer an ensure built.
type lbSummary struct {
	Name      string `json:"name" yaml:"name"`
	Protocol  string `json:"protocol" yaml:"protocol"`
	Scope     string `json:"scope" yaml:"scope"`
	Region    string `json:"region" yaml:"region"`
	IPAddress string `json:"ip_address" yaml:"ip_address"`
	Port      int64  `json:"port" yaml:"port"`
	URL       string `json:"url" yaml:"url"`
}

// lbEnsureResult is the output of ensure: a change report with the load
// balancer.
type lbEnsureResult struct {
	Target       lbEnsureTarget    `json:"target" yaml:"target"`
	DryRun       bool              `json:"dry_run" yaml:"dry_run"`
	LoadBalancer lbSummary         `json:"load_balancer" yaml:"load_balancer"`
	Changes      []platform.Change `json:"changes" yaml:"changes"`
}

// lbEnsureTarget is the target of an ensure with the project it wrote to.
type lbEnsureTarget struct {
	platform.Target `yaml:",inline"`
	Project         string `json:"project" yaml:"project"`
}

// storeRule upserts a forwarding rule into the inventory as a load
// balancer row named after the rule, with the load balancer name.
func storeRule(ctx context.Context, rt *app.Runtime, profile string, fr *compute.ForwardingRule, lb string) {
	db, err := rt.DB()
	if err != nil || fr == nil {
		return
	}
	cfg, err := rt.Config()
	if err != nil {
		return
	}
	v := forwardingRuleFrom(fr)
	if v.LoadBalancer == "" {
		v.LoadBalancer = lb
	}
	if err := db.Upsert(ctx, inventory.Set{Platform: platform.GCP, Profile: profile, Type: platform.ResLoadBalancer}, v.resource(), cfg.TTLFor(platform.ResLoadBalancer)); err != nil {
		rt.Verbosef("inventory: %v", err)
	}
}
