package gcp

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// The components of a load balancer, one small function per call, in the
// regional or global scope of a certScope (instance groups are zonal).
// find* functions return nil, not an error, for a component that does not
// exist; every write waits for its operation.

// Component URLs as a resource refers to another ("projects/p/regions/r/...").
func (s certScope) healthCheckURL(name string) string { return s.prefix() + "healthChecks/" + name }
func (s certScope) backendServiceURL(name string) string {
	return s.prefix() + "backendServices/" + name
}
func (s certScope) urlMapURL(name string) string    { return s.prefix() + "urlMaps/" + name }
func (s certScope) httpProxyURL(name string) string { return s.prefix() + "targetHttpProxies/" + name }
func (s certScope) tcpProxyURL(name string) string  { return s.prefix() + "targetTcpProxies/" + name }

func (c *client) instanceGroupURL(zone, name string) string {
	return "projects/" + c.project + "/zones/" + zone + "/instanceGroups/" + name
}

func (c *client) instanceRef(zone, name string) string {
	return "projects/" + c.project + "/zones/" + zone + "/instances/" + name
}

// sameResource compares two resource references: a full URL and a
// relative "projects/..." reference of one resource are equal.
func sameResource(a, b string) bool { return a != "" && resourceKey(a) == resourceKey(b) }

// nilIfMissing turns "not found" into a nil result without error.
func nilIfMissing[T any](v *T, err error) (*T, error) {
	if err == nil {
		return v, nil
	}
	err = computeErr(err)
	if errors.Is(err, platform.ErrNotFound) {
		return nil, nil
	}
	return nil, err
}

// ---------------------------------------------------------------- reads

func (s certScope) findHealthCheck(ctx context.Context, name string) (*compute.HealthCheck, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.HealthChecks.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.RegionHealthChecks.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (s certScope) findBackendService(ctx context.Context, name string) (*compute.BackendService, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.BackendServices.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.RegionBackendServices.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (s certScope) findURLMap(ctx context.Context, name string) (*compute.UrlMap, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.UrlMaps.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.RegionUrlMaps.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (s certScope) findHTTPProxy(ctx context.Context, name string) (*compute.TargetHttpProxy, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.TargetHttpProxies.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.RegionTargetHttpProxies.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (s certScope) findHTTPSProxy(ctx context.Context, name string) (*compute.TargetHttpsProxy, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.TargetHttpsProxies.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.RegionTargetHttpsProxies.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (s certScope) findTCPProxy(ctx context.Context, name string) (*compute.TargetTcpProxy, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.TargetTcpProxies.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.RegionTargetTcpProxies.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (s certScope) findRule(ctx context.Context, name string) (*compute.ForwardingRule, error) {
	if s.global() {
		return nilIfMissing(s.c.compute.GlobalForwardingRules.Get(s.c.project, name).Context(ctx).Do())
	}
	return nilIfMissing(s.c.compute.ForwardingRules.Get(s.c.project, s.region, name).Context(ctx).Do())
}

func (c *client) findInstanceGroup(ctx context.Context, zone, name string) (*compute.InstanceGroup, error) {
	return nilIfMissing(c.compute.InstanceGroups.Get(c.project, zone, name).Context(ctx).Do())
}

// listInstanceGroups lists the instance groups of a zone.
func (c *client) listInstanceGroups(ctx context.Context, zone string) ([]*compute.InstanceGroup, error) {
	var out []*compute.InstanceGroup
	err := c.compute.InstanceGroups.List(c.project, zone).Pages(ctx, func(l *compute.InstanceGroupList) error {
		out = append(out, l.Items...)
		return nil
	})
	if err != nil {
		return nil, computeErr(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// groupMembers lists the instances of an instance group (every state).
func (c *client) groupMembers(ctx context.Context, zone, name string) ([]*compute.InstanceWithNamedPorts, error) {
	var out []*compute.InstanceWithNamedPorts
	err := c.compute.InstanceGroups.ListInstances(c.project, zone, name, &compute.InstanceGroupsListInstancesRequest{InstanceState: "ALL"}).
		Pages(ctx, func(l *compute.InstanceGroupsListInstances) error {
			out = append(out, l.Items...)
			return nil
		})
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// hasMember reports whether an instance of that exact name is a member:
// the last segment of the member URL is compared, never a part of it
// (instance web is not a member because web-2 is).
func hasMember(members []*compute.InstanceWithNamedPorts, instance string) bool {
	for _, m := range members {
		if lastSegment(m.Instance) == instance {
			return true
		}
	}
	return false
}

// listBackendServices lists the backend services of the scope.
func (s certScope) listBackendServices(ctx context.Context) ([]*compute.BackendService, error) {
	var out []*compute.BackendService
	var err error
	if s.global() {
		err = s.c.compute.BackendServices.List(s.c.project).Pages(ctx, func(l *compute.BackendServiceList) error {
			out = append(out, l.Items...)
			return nil
		})
	} else {
		err = s.c.compute.RegionBackendServices.List(s.c.project, s.region).Pages(ctx, func(l *compute.BackendServiceList) error {
			out = append(out, l.Items...)
			return nil
		})
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return out, nil
}

// backendHealth reads the health of the instances of group behind a
// backend service.
func (s certScope) backendHealth(ctx context.Context, bs, group string) ([]*compute.HealthStatus, error) {
	ref := &compute.ResourceGroupReference{Group: group}
	var res *compute.BackendServiceGroupHealth
	var err error
	if s.global() {
		res, err = s.c.compute.BackendServices.GetHealth(s.c.project, bs, ref).Context(ctx).Do()
	} else {
		res, err = s.c.compute.RegionBackendServices.GetHealth(s.c.project, s.region, bs, ref).Context(ctx).Do()
	}
	if err != nil {
		return nil, computeErr(err)
	}
	return res.HealthStatus, nil
}

// ---------------------------------------------------------------- writes

// done returns the function that waits for the operation of a write
// submitted in the scope: s.done(ctx)(call.Do()).
func (s certScope) done(ctx context.Context) func(*compute.Operation, error) error {
	return func(op *compute.Operation, err error) error { return s.submitted(ctx, op, err) }
}

// submitted waits for the operation of a write submitted in the scope.
func (s certScope) submitted(ctx context.Context, op *compute.Operation, err error) error {
	if err != nil {
		return computeErr(err)
	}
	return s.wait(ctx, op)
}

// zoneSubmitted waits for a zonal operation of a write, bounded by
// timeout (0: the default limit).
func (c *client) zoneSubmitted(ctx context.Context, zone string, timeout time.Duration, op *compute.Operation, err error) error {
	if err != nil {
		return computeErr(err)
	}
	wctx, cancel, conv := deadline(ctx, timeout, "operation/"+op.Name, "DONE")
	defer cancel()
	return conv(c.waitZoneOp(wctx, zone, op))
}

func (s certScope) insertHealthCheck(ctx context.Context, hc *compute.HealthCheck) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.HealthChecks.Insert(s.c.project, hc).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionHealthChecks.Insert(s.c.project, s.region, hc).Context(ctx).Do())
}

func (s certScope) insertBackendService(ctx context.Context, bs *compute.BackendService) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.BackendServices.Insert(s.c.project, bs).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionBackendServices.Insert(s.c.project, s.region, bs).Context(ctx).Do())
}

func (s certScope) patchBackendService(ctx context.Context, name string, bs *compute.BackendService) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.BackendServices.Patch(s.c.project, name, bs).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionBackendServices.Patch(s.c.project, s.region, name, bs).Context(ctx).Do())
}

func (s certScope) insertURLMap(ctx context.Context, m *compute.UrlMap) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.UrlMaps.Insert(s.c.project, m).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionUrlMaps.Insert(s.c.project, s.region, m).Context(ctx).Do())
}

func (s certScope) insertHTTPProxy(ctx context.Context, p *compute.TargetHttpProxy) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.TargetHttpProxies.Insert(s.c.project, p).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionTargetHttpProxies.Insert(s.c.project, s.region, p).Context(ctx).Do())
}

func (s certScope) insertHTTPSProxy(ctx context.Context, p *compute.TargetHttpsProxy) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.TargetHttpsProxies.Insert(s.c.project, p).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionTargetHttpsProxies.Insert(s.c.project, s.region, p).Context(ctx).Do())
}

func (s certScope) insertTCPProxy(ctx context.Context, p *compute.TargetTcpProxy) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.TargetTcpProxies.Insert(s.c.project, p).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.RegionTargetTcpProxies.Insert(s.c.project, s.region, p).Context(ctx).Do())
}

func (s certScope) insertRule(ctx context.Context, fr *compute.ForwardingRule) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.GlobalForwardingRules.Insert(s.c.project, fr).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.ForwardingRules.Insert(s.c.project, s.region, fr).Context(ctx).Do())
}

// setRuleLabels replaces the labels of a forwarding rule; fingerprint is
// the label fingerprint as read.
func (s certScope) setRuleLabels(ctx context.Context, name string, labels map[string]string, fingerprint string) error {
	if s.global() {
		return s.done(ctx)(s.c.compute.GlobalForwardingRules.SetLabels(s.c.project, name,
			&compute.GlobalSetLabelsRequest{Labels: labels, LabelFingerprint: fingerprint}).Context(ctx).Do())
	}
	return s.done(ctx)(s.c.compute.ForwardingRules.SetLabels(s.c.project, s.region, name,
		&compute.RegionSetLabelsRequest{Labels: labels, LabelFingerprint: fingerprint}).Context(ctx).Do())
}

// lbKind names a load balancer component as the change reports and the
// delete commands do.
type lbKind string

const (
	kindRule           lbKind = "forwarding-rule"
	kindHTTPProxy      lbKind = "target-http-proxy"
	kindHTTPSProxy     lbKind = "target-https-proxy"
	kindTCPProxy       lbKind = "target-tcp-proxy"
	kindURLMap         lbKind = "url-map"
	kindBackendService lbKind = "backend-service"
	kindHealthCheck    lbKind = "health-check"
	kindInstanceGroup  lbKind = "instance-group"
)

// proxyKind returns the component kind of a target URL
// (".../targetHttpProxies/x" -> target-http-proxy), "" for another target.
func proxyKind(target string) lbKind {
	switch {
	case strings.Contains(target, "/targetHttpProxies/"):
		return kindHTTPProxy
	case strings.Contains(target, "/targetHttpsProxies/"):
		return kindHTTPSProxy
	case strings.Contains(target, "/targetTcpProxies/"):
		return kindTCPProxy
	}
	return ""
}

// deleteComponent deletes a regional or global component and waits for
// the operation. Instance groups are deleted by deleteInstanceGroup.
func (s certScope) deleteComponent(ctx context.Context, kind lbKind, name string) error {
	p, r, g := s.c.project, s.region, s.global()
	cs := s.c.compute
	var op *compute.Operation
	var err error
	switch kind {
	case kindRule:
		if g {
			op, err = cs.GlobalForwardingRules.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.ForwardingRules.Delete(p, r, name).Context(ctx).Do()
		}
	case kindHTTPProxy:
		if g {
			op, err = cs.TargetHttpProxies.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.RegionTargetHttpProxies.Delete(p, r, name).Context(ctx).Do()
		}
	case kindHTTPSProxy:
		if g {
			op, err = cs.TargetHttpsProxies.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.RegionTargetHttpsProxies.Delete(p, r, name).Context(ctx).Do()
		}
	case kindTCPProxy:
		if g {
			op, err = cs.TargetTcpProxies.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.RegionTargetTcpProxies.Delete(p, r, name).Context(ctx).Do()
		}
	case kindURLMap:
		if g {
			op, err = cs.UrlMaps.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.RegionUrlMaps.Delete(p, r, name).Context(ctx).Do()
		}
	case kindBackendService:
		if g {
			op, err = cs.BackendServices.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.RegionBackendServices.Delete(p, r, name).Context(ctx).Do()
		}
	case kindHealthCheck:
		if g {
			op, err = cs.HealthChecks.Delete(p, name).Context(ctx).Do()
		} else {
			op, err = cs.RegionHealthChecks.Delete(p, r, name).Context(ctx).Do()
		}
	default:
		return errors.New("cannot delete a " + string(kind) + " in a region")
	}
	return s.submitted(ctx, op, err)
}

// deleteInstanceGroup deletes a zonal instance group and waits.
func (c *client) deleteInstanceGroup(ctx context.Context, zone, name string, timeout time.Duration) error {
	op, err := c.compute.InstanceGroups.Delete(c.project, zone, name).Context(ctx).Do()
	return c.zoneSubmitted(ctx, zone, timeout, op, err)
}
