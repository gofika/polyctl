package aliyun

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

// fakeALB keeps ALB load balancers, server groups, listeners and ACLs in
// memory behind a fakeAPI, answering as verified on real accounts: names
// are not unique, NextToken pages, statuses that pass through Provisioning
// / Creating / Configuring for a few reads after a write, writes to a
// listener or ACL that is not settled refused with IncorrectStatus.*, ALB's
// "not found" as HTTP 404 ResourceNotFound.*, server groups that need the
// health check and session persistence configurations. Its writes are
// logged in the fakeECS write log, after the VPC writes.
type fakeALB struct {
	t   *testing.T
	net *fakeECS

	lbs        []map[string]any
	groups     []map[string]any
	servers    map[string][]map[string]any
	listeners  []map[string]any
	acls       []map[string]any
	aclEntries map[string][]map[string]any
	zones      []string

	// pending counts the reads a resource still answers with its
	// transitional status (load balancer Provisioning, server group
	// Creating, listener Provisioning / Configuring, ACL Configuring).
	pending map[string]int
	// lbPending, listenerPending, configuring: the counts new load
	// balancers, new listeners and updated listeners start with.
	lbPending       int
	listenerPending int
	configuring     int
	// page is the page size of the List actions (0: MaxResults).
	page int
	// lbFail, when set, answers every ListLoadBalancers with that code.
	lbFail       string
	lbFailStatus int
	next         int
}

func newFakeALB(t *testing.T, api *fakeAPI, net *fakeECS) *fakeALB {
	f := &fakeALB{t: t, net: net, servers: map[string][]map[string]any{}, aclEntries: map[string][]map[string]any{},
		pending: map[string]int{}, zones: []string{"cn-shanghai-b", "cn-shanghai-c", "cn-shanghai-d"},
		lbPending: 2, listenerPending: 1, configuring: 2}
	api.on("ListLoadBalancers", f.listLoadBalancers)
	api.on("GetLoadBalancerAttribute", f.getLoadBalancer)
	api.on("CreateLoadBalancer", net.write(f.createLoadBalancer))
	api.on("DeleteLoadBalancer", net.write(f.deleteLoadBalancer))
	api.on("UpdateLoadBalancerAttribute", net.write(f.updateLoadBalancer))
	api.on("EnableDeletionProtection", net.write(f.setDeletionProtection(true)))
	api.on("DisableDeletionProtection", net.write(f.setDeletionProtection(false)))
	api.on("DescribeZones", f.describeZones)
	api.on("ListServerGroups", f.listServerGroups)
	api.on("CreateServerGroup", net.write(f.createServerGroup))
	api.on("DeleteServerGroup", net.write(f.deleteServerGroup))
	api.on("UpdateServerGroupAttribute", net.write(f.updateServerGroup))
	api.on("ListServerGroupServers", f.listServers)
	api.on("AddServersToServerGroup", net.write(f.addServers))
	api.on("ListListeners", f.listListeners)
	api.on("GetListenerAttribute", f.getListener)
	api.on("CreateListener", net.write(f.createListener))
	api.on("UpdateListenerAttribute", net.write(f.updateListener))
	api.on("DeleteListener", net.write(f.deleteListener))
	api.on("ListAcls", f.listACLs)
	api.on("ListAclEntries", f.listACLEntries)
	api.on("CreateAcl", net.write(f.createACL))
	api.on("DeleteAcl", net.write(f.deleteACL))
	api.on("AddEntriesToAcl", net.write(f.addACLEntries))
	api.on("RemoveEntriesFromAcl", net.write(f.removeACLEntries))
	return f
}

func (f *fakeALB) id(prefix string) string {
	f.next++
	return fmt.Sprintf("%s%04d", prefix, f.next)
}

// rep collects a repeated parameter: name.1, name.2, ...
func rep(q url.Values, name string) []string {
	var out []string
	for i := 1; ; i++ {
		v, ok := q[name+"."+strconv.Itoa(i)]
		if !ok {
			return out
		}
		out = append(out, v[0])
	}
}

func (f *fakeALB) pageOf(q url.Values, n int) (int, int, string) {
	size := f.page
	if size == 0 {
		size, _ = strconv.Atoi(q.Get("MaxResults"))
		if size <= 0 {
			size = 20
		}
	}
	return tokenPage(q, n, size)
}

// settle answers the status of a resource that may still be transitional.
func (f *fakeALB) settle(id string, m map[string]any, key, transitional, final string) {
	if f.pending[id] > 0 {
		f.pending[id]--
		m[key] = transitional
		return
	}
	if m[key] == transitional {
		m[key] = final
	}
}

func notFound(what string) map[string]string {
	return apiErr("ResourceNotFound."+what, "The specified resource is not found.")
}

// ------------------------------------------------------- load balancers

// addLB stores a load balancer with an EIP in each zone given as
// zone=allocation:ip.
func (f *fakeALB) addLB(id, name, vpc, status string, zones ...string) map[string]any {
	var mappings []map[string]any
	for _, z := range zones {
		zone, eip, _ := strings.Cut(z, "=")
		alloc, ip, _ := strings.Cut(eip, ":")
		mappings = append(mappings, map[string]any{"ZoneId": zone, "VSwitchId": "vsw-" + zone, "Status": "Active",
			"LoadBalancerAddresses": []map[string]any{{"Address": ip, "AllocationId": alloc, "EipType": "Common", "IntranetAddress": "172.16.0.9"}}})
	}
	lb := map[string]any{"LoadBalancerId": id, "LoadBalancerName": name, "LoadBalancerStatus": status, "VpcId": vpc,
		"DNSName": id + ".cn-shanghai.alb.aliyuncs.com", "AddressType": "Internet", "AddressIpVersion": "IPv4", "LoadBalancerEdition": "Standard",
		"ResourceGroupId": "rg-default0001", "ZoneMappings": mappings, "DeletionProtectionConfig": map[string]any{"Enabled": false}}
	f.lbs = append(f.lbs, lb)
	return lb
}

func (f *fakeALB) lb(id string) map[string]any {
	for _, l := range f.lbs {
		if l["LoadBalancerId"] == id {
			return l
		}
	}
	return nil
}

func (f *fakeALB) listLoadBalancers(q url.Values) (int, any) {
	if f.lbFail != "" {
		return f.lbFailStatus, apiErr(f.lbFail, "refused")
	}
	if n, _ := strconv.Atoi(q.Get("MaxResults")); n > 100 {
		return 400, apiErr("IllegalParam.MaxResults", "MaxResults")
	}
	names, ids := rep(q, "LoadBalancerNames"), rep(q, "LoadBalancerIds")
	var out []map[string]any
	for _, l := range f.lbs {
		if len(names) > 0 && !contains(names, l["LoadBalancerName"].(string)) {
			continue
		}
		if len(ids) > 0 && !contains(ids, l["LoadBalancerId"].(string)) {
			continue
		}
		// The list carries no zones nor addresses.
		out = append(out, map[string]any{"LoadBalancerId": l["LoadBalancerId"], "LoadBalancerName": l["LoadBalancerName"],
			"LoadBalancerStatus": l["LoadBalancerStatus"], "VpcId": l["VpcId"], "DNSName": l["DNSName"]})
	}
	s, e, next := f.pageOf(q, len(out))
	return 200, map[string]any{"NextToken": next, "TotalCount": len(out), "LoadBalancers": out[s:e]}
}

func (f *fakeALB) getLoadBalancer(q url.Values) (int, any) {
	l := f.lb(q.Get("LoadBalancerId"))
	if l == nil {
		return 404, notFound("LoadBalancer")
	}
	transitional := "Provisioning"
	if l["LoadBalancerStatus"] == "Configuring" {
		transitional = "Configuring"
	}
	f.settle(l["LoadBalancerId"].(string), l, "LoadBalancerStatus", transitional, "Active")
	return 200, l
}

// updateLoadBalancer renames a load balancer, which is Configuring for
// f.configuring reads after; one that is not Active refuses the write.
func (f *fakeALB) updateLoadBalancer(q url.Values) (int, any) {
	if q.Get("ClientToken") == "" {
		f.t.Errorf("UpdateLoadBalancerAttribute without ClientToken")
	}
	l := f.lb(q.Get("LoadBalancerId"))
	if l == nil {
		return 404, notFound("LoadBalancer")
	}
	if l["LoadBalancerStatus"] != "Active" {
		return 400, apiErr("IncorrectStatus.LoadBalancer", "The status of the load balancer is incorrect.")
	}
	if n := q.Get("LoadBalancerName"); n != "" {
		l["LoadBalancerName"] = n
	}
	l["LoadBalancerStatus"] = "Configuring"
	f.pending[l["LoadBalancerId"].(string)] = f.configuring
	return 200, map[string]any{"JobId": "job-1", "RequestId": "r"}
}

func (f *fakeALB) setDeletionProtection(on bool) func(q url.Values) (int, any) {
	return func(q url.Values) (int, any) {
		l := f.lb(q.Get("ResourceId"))
		if l == nil {
			return 404, notFound("LoadBalancer")
		}
		l["DeletionProtectionConfig"] = map[string]any{"Enabled": on}
		return 200, map[string]any{"RequestId": "r"}
	}
}

func (f *fakeALB) createLoadBalancer(q url.Values) (int, any) {
	if q.Get("ClientToken") == "" {
		f.t.Errorf("CreateLoadBalancer without ClientToken")
	}
	if q.Get("VpcId") == "" {
		return 400, apiErr("MissingVpcId", "VpcId is mandatory for this action.")
	}
	id := f.id("alb-new")
	var zones []string
	for i := 1; ; i++ {
		p := "ZoneMappings." + strconv.Itoa(i) + "."
		if q.Get(p+"ZoneId") == "" {
			break
		}
		alloc := q.Get(p + "AllocationId")
		e := f.net.eip(alloc)
		if e == nil {
			return 404, apiErr("ResourceNotFound.Eip", "eip")
		}
		if e["InstanceId"] != "" {
			return 400, apiErr("ResourceAlreadyAssociated.Eip", "eip in use")
		}
		e["Status"], e["InstanceId"], e["InstanceType"], e["ServiceManaged"] = "InUse", "eni-"+id, "NetworkInterface", 1
		zones = append(zones, q.Get(p+"ZoneId")+"="+alloc+":"+e["IpAddress"].(string))
	}
	l := f.addLB(id, q.Get("LoadBalancerName"), q.Get("VpcId"), "Provisioning", zones...)
	// The zones come back in reverse order (as verified: asked b, c;
	// answered c, b).
	m := l["ZoneMappings"].([]map[string]any)
	for i, j := 0, len(m)-1; i < j; i, j = i+1, j-1 {
		m[i], m[j] = m[j], m[i]
	}
	f.pending[id] = f.lbPending
	return 200, map[string]any{"LoadBalancerId": id, "RequestId": "r"}
}

func (f *fakeALB) deleteLoadBalancer(q url.Values) (int, any) {
	id := q.Get("LoadBalancerId")
	for i, l := range f.lbs {
		if l["LoadBalancerId"] != id {
			continue
		}
		if l["DeletionProtectionConfig"].(map[string]any)["Enabled"] == true {
			return 400, apiErr("OperationDenied.DeletionProtectionEnabled", "deletion protection")
		}
		f.lbs = append(f.lbs[:i], f.lbs[i+1:]...)
		return 200, map[string]any{"JobId": "job-1", "RequestId": "r"}
	}
	return 404, notFound("LoadBalancer")
}

func (f *fakeALB) describeZones(q url.Values) (int, any) {
	var out []map[string]any
	// Not sorted: the client sorts.
	for i := len(f.zones) - 1; i >= 0; i-- {
		out = append(out, map[string]any{"ZoneId": f.zones[i], "LocalName": f.zones[i]})
	}
	return 200, map[string]any{"Zones": out, "RequestId": "r"}
}

// -------------------------------------------------------- server groups

func (f *fakeALB) addGroup(id, name, protocol, vpc string) map[string]any {
	g := map[string]any{"ServerGroupId": id, "ServerGroupName": name, "Protocol": protocol, "VpcId": vpc, "ServerGroupStatus": "Available",
		"ServerGroupType": "Instance", "ResourceGroupId": "rg-default0001", "Scheduler": "Wrr", "HealthCheckConfig": map[string]any{"HealthCheckEnabled": false},
		"StickySessionConfig": map[string]any{"StickySessionEnabled": false}}
	f.groups = append(f.groups, g)
	return g
}

func (f *fakeALB) addServer(group, instance string, port int) {
	f.servers[group] = append(f.servers[group], map[string]any{"ServerId": instance, "ServerType": "Ecs", "Port": port, "Weight": 100,
		"Status": "Available", "ServerIp": "172.16.0.5", "ServerGroupId": group})
}

func (f *fakeALB) listServerGroups(q url.Values) (int, any) {
	if n, _ := strconv.Atoi(q.Get("MaxResults")); n > 100 {
		return 400, apiErr("InvalidMaxResults", "MaxResults")
	}
	names, ids := rep(q, "ServerGroupNames"), rep(q, "ServerGroupIds")
	var out []map[string]any
	for _, g := range f.groups {
		if len(names) > 0 && !contains(names, g["ServerGroupName"].(string)) {
			continue
		}
		if len(ids) > 0 && !contains(ids, g["ServerGroupId"].(string)) {
			continue
		}
		transitional := "Creating"
		if g["ServerGroupStatus"] == "Configuring" {
			transitional = "Configuring"
		}
		f.settle(g["ServerGroupId"].(string), g, "ServerGroupStatus", transitional, "Available")
		g["ServerCount"] = len(f.servers[g["ServerGroupId"].(string)])
		out = append(out, g)
	}
	s, e, next := f.pageOf(q, len(out))
	return 200, map[string]any{"NextToken": next, "TotalCount": len(out), "ServerGroups": out[s:e]}
}

func (f *fakeALB) createServerGroup(q url.Values) (int, any) {
	if q.Get("HealthCheckConfig.HealthCheckEnabled") == "" {
		return 400, apiErr("MissingHealthCheckConfig", "HealthCheckConfig is mandatory")
	}
	if q.Get("StickySessionConfig.StickySessionEnabled") == "" {
		return 400, apiErr("MissingParam.StickySession", "StickySessionConfig is mandatory")
	}
	id := f.id("sgp-new")
	g := f.addGroup(id, q.Get("ServerGroupName"), q.Get("Protocol"), q.Get("VpcId"))
	g["ServerGroupStatus"] = "Creating"
	f.pending[id] = 1
	return 200, map[string]any{"ServerGroupId": id, "JobId": "job-1", "RequestId": "r"}
}

func (f *fakeALB) group(id string) map[string]any {
	for _, g := range f.groups {
		if g["ServerGroupId"] == id {
			return g
		}
	}
	return nil
}

// updateServerGroup writes the attributes given; the group is Configuring
// for one read after. Turning the health check on without a path gives it
// the API's defaults (HTTP, /); session persistence needs its type.
func (f *fakeALB) updateServerGroup(q url.Values) (int, any) {
	g := f.group(q.Get("ServerGroupId"))
	if g == nil {
		return 404, notFound("ServerGroup")
	}
	if g["ServerGroupStatus"] != "Available" {
		return 400, apiErr("IncorrectStatus.ServerGroup", "The status of the server group is incorrect.")
	}
	if n := q.Get("ServerGroupName"); n != "" {
		g["ServerGroupName"] = n
	}
	if s := q.Get("Scheduler"); s != "" {
		g["Scheduler"] = s
	}
	switch q.Get("HealthCheckConfig.HealthCheckEnabled") {
	case "true":
		hc := map[string]any{"HealthCheckEnabled": true, "HealthCheckProtocol": "HTTP", "HealthCheckPath": "/"}
		if old, _ := g["HealthCheckConfig"].(map[string]any); old["HealthCheckEnabled"] == true {
			hc = old
		}
		if p := q.Get("HealthCheckConfig.HealthCheckPath"); p != "" {
			hc["HealthCheckPath"] = p
		}
		g["HealthCheckConfig"] = hc
	case "false":
		g["HealthCheckConfig"] = map[string]any{"HealthCheckEnabled": false}
	case "":
		if q.Get("HealthCheckConfig.HealthCheckPath") != "" {
			return 400, apiErr("MissingParam.HealthCheckEnabled", "HealthCheckEnabled is mandatory")
		}
	}
	switch q.Get("StickySessionConfig.StickySessionEnabled") {
	case "true":
		if q.Get("StickySessionConfig.StickySessionType") == "" {
			return 400, apiErr("MissingParam.StickySessionType", "StickySessionType is mandatory")
		}
		g["StickySessionConfig"] = map[string]any{"StickySessionEnabled": true, "StickySessionType": q.Get("StickySessionConfig.StickySessionType"), "CookieTimeout": 1000}
	case "false":
		g["StickySessionConfig"] = map[string]any{"StickySessionEnabled": false}
	}
	g["ServerGroupStatus"] = "Configuring"
	f.pending[g["ServerGroupId"].(string)] = 1
	return 200, map[string]any{"JobId": "job-1", "RequestId": "r"}
}

func (f *fakeALB) deleteServerGroup(q url.Values) (int, any) {
	id := q.Get("ServerGroupId")
	for _, l := range f.listeners {
		if contains(l["groups"].([]string), id) {
			return 400, apiErr("ResourceInUse.ServerGroup", "in use")
		}
	}
	for i, g := range f.groups {
		if g["ServerGroupId"] == id {
			f.groups = append(f.groups[:i], f.groups[i+1:]...)
			return 200, map[string]any{"JobId": "job-1"}
		}
	}
	return 404, notFound("ServerGroup")
}

func (f *fakeALB) listServers(q url.Values) (int, any) {
	list := f.servers[q.Get("ServerGroupId")]
	s, e, next := f.pageOf(q, len(list))
	body := map[string]any{"NextToken": next, "TotalCount": len(list), "RequestId": "r"}
	if len(list) > 0 {
		// An empty group answers no Servers field at all.
		body["Servers"] = list[s:e]
	}
	return 200, body
}

func (f *fakeALB) addServers(q url.Values) (int, any) {
	g := f.group(q.Get("ServerGroupId"))
	if g == nil {
		return 404, notFound("ServerGroup")
	}
	id, port := q.Get("Servers.1.ServerId"), q.Get("Servers.1.Port")
	if q.Get("Servers.1.ServerType") != "Ecs" {
		return 400, apiErr("Mismatch.ServerType", "server type")
	}
	var inst map[string]any
	for _, in := range f.net.instances {
		if in["InstanceId"] == id {
			inst = in
		}
	}
	if inst == nil {
		return 404, apiErr("ResourceNotFound.Ecs", "ecs")
	}
	if inst["VpcAttributes"].(map[string]any)["VpcId"] != g["VpcId"] {
		return 400, apiErr("Mismatch.VpcId", "The VpcId is mismatched for servergroup and Ecs.")
	}
	for _, s := range f.servers[g["ServerGroupId"].(string)] {
		if s["ServerId"] == id && strconv.Itoa(s["Port"].(int)) == port {
			return 400, apiErr("DuplicatedParam.BackendServer", "duplicate")
		}
	}
	n, _ := strconv.Atoi(port)
	f.addServer(g["ServerGroupId"].(string), id, n)
	return 200, map[string]any{"JobId": "job-1"}
}

// ------------------------------------------------------------ listeners

func (f *fakeALB) addListener(id, lb, protocol string, port int, group string, certs ...string) map[string]any {
	l := map[string]any{"ListenerId": id, "LoadBalancerId": lb, "ListenerProtocol": protocol, "ListenerPort": port, "ListenerStatus": "Running",
		"groups": []string{group}, "certs": certs}
	f.listeners = append(f.listeners, l)
	return l
}

func (f *fakeALB) listener(id string) map[string]any {
	for _, l := range f.listeners {
		if l["ListenerId"] == id {
			return l
		}
	}
	return nil
}

func (f *fakeALB) listenerBody(l map[string]any, withCerts bool) map[string]any {
	var tuples []map[string]any
	for _, g := range l["groups"].([]string) {
		tuples = append(tuples, map[string]any{"ServerGroupId": g, "Weight": 100})
	}
	out := map[string]any{"ListenerId": l["ListenerId"], "LoadBalancerId": l["LoadBalancerId"], "ListenerProtocol": l["ListenerProtocol"],
		"ListenerPort": l["ListenerPort"], "ListenerStatus": l["ListenerStatus"],
		"DefaultActions": []map[string]any{{"Type": "ForwardGroup", "ForwardGroupConfig": map[string]any{"ServerGroupTuples": tuples}}}}
	if withCerts {
		var certs []map[string]any
		for _, c := range l["certs"].([]string) {
			certs = append(certs, map[string]any{"CertificateId": c})
		}
		out["Certificates"] = certs
	}
	return out
}

func (f *fakeALB) settleListener(l map[string]any) {
	id := l["ListenerId"].(string)
	if f.pending[id] > 0 {
		f.pending[id]--
		if f.pending[id] == 0 {
			l["ListenerStatus"] = "Running"
		}
		return
	}
	l["ListenerStatus"] = "Running"
}

func (f *fakeALB) listListeners(q url.Values) (int, any) {
	lbs := rep(q, "LoadBalancerIds")
	var out []map[string]any
	for _, l := range f.listeners {
		if len(lbs) > 0 && !contains(lbs, l["LoadBalancerId"].(string)) {
			continue
		}
		if p := q.Get("ListenerProtocol"); p != "" && l["ListenerProtocol"] != p {
			continue
		}
		// The list carries no certificates.
		out = append(out, f.listenerBody(l, false))
	}
	s, e, next := f.pageOf(q, len(out))
	return 200, map[string]any{"NextToken": next, "TotalCount": len(out), "Listeners": out[s:e]}
}

func (f *fakeALB) getListener(q url.Values) (int, any) {
	l := f.listener(q.Get("ListenerId"))
	if l == nil {
		return 404, notFound("Listener")
	}
	body := f.listenerBody(l, true)
	f.settleListener(l)
	return 200, body
}

func (f *fakeALB) createListener(q url.Values) (int, any) {
	lb := f.lb(q.Get("LoadBalancerId"))
	if lb == nil {
		return 404, notFound("LoadBalancer")
	}
	port, _ := strconv.Atoi(q.Get("ListenerPort"))
	for _, l := range f.listeners {
		if l["LoadBalancerId"] == q.Get("LoadBalancerId") && l["ListenerPort"] == port {
			return 400, apiErr("ResourceAlreadyExist.Listener", "listener exists")
		}
	}
	group := q.Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId")
	if q.Get("DefaultActions.1.Type") != "ForwardGroup" || f.group(group) == nil {
		return 400, apiErr("IllegalParam.DefaultActions", "default actions")
	}
	var certs []string
	if c := q.Get("Certificates.1.CertificateId"); c != "" {
		certs = append(certs, c)
	}
	if q.Get("ListenerProtocol") == "HTTPS" && len(certs) == 0 {
		return 400, apiErr("MissingParam.Certificates", "certificates")
	}
	id := f.id("lsn-new")
	l := f.addListener(id, q.Get("LoadBalancerId"), q.Get("ListenerProtocol"), port, group, certs...)
	l["ListenerStatus"] = "Provisioning"
	f.pending[id] = f.listenerPending
	return 200, map[string]any{"ListenerId": id, "JobId": "job-1"}
}

func (f *fakeALB) updateListener(q url.Values) (int, any) {
	l := f.listener(q.Get("ListenerId"))
	if l == nil {
		return 404, notFound("Listener")
	}
	if l["ListenerStatus"] != "Running" {
		return 400, apiErr("IncorrectStatus.Listener", fmt.Sprintf("The status of %s [%s] is incorrect.", l["ListenerId"], l["ListenerStatus"]))
	}
	if c := q.Get("Certificates.1.CertificateId"); c != "" {
		l["certs"] = []string{c}
	}
	if g := q.Get("DefaultActions.1.ForwardGroupConfig.ServerGroupTuples.1.ServerGroupId"); g != "" {
		l["groups"] = []string{g}
	}
	l["ListenerStatus"] = "Configuring"
	f.pending[l["ListenerId"].(string)] = f.configuring
	return 200, map[string]any{"JobId": "job-1"}
}

func (f *fakeALB) deleteListener(q url.Values) (int, any) {
	for i, l := range f.listeners {
		if l["ListenerId"] == q.Get("ListenerId") {
			f.listeners = append(f.listeners[:i], f.listeners[i+1:]...)
			return 200, map[string]any{"JobId": "job-1"}
		}
	}
	return 404, notFound("Listener")
}

// ----------------------------------------------------------------- ACLs

func (f *fakeALB) addACL(id, name string) map[string]any {
	a := map[string]any{"AclId": id, "AclName": name, "AclStatus": "Available", "ResourceGroupId": "rg-default0001", "AddressIPVersion": "IPv4"}
	f.acls = append(f.acls, a)
	return a
}

func (f *fakeALB) acl(id string) map[string]any {
	for _, a := range f.acls {
		if a["AclId"] == id {
			return a
		}
	}
	return nil
}

func (f *fakeALB) listACLs(q url.Values) (int, any) {
	names, ids := rep(q, "AclNames"), rep(q, "AclIds")
	var out []map[string]any
	for _, a := range f.acls {
		if len(names) > 0 && !contains(names, a["AclName"].(string)) {
			continue
		}
		if len(ids) > 0 && !contains(ids, a["AclId"].(string)) {
			continue
		}
		f.settle(a["AclId"].(string), a, "AclStatus", "Configuring", "Available")
		out = append(out, a)
	}
	s, e, next := f.pageOf(q, len(out))
	return 200, map[string]any{"NextToken": next, "TotalCount": len(out), "Acls": out[s:e]}
}

func (f *fakeALB) listACLEntries(q url.Values) (int, any) {
	if n, _ := strconv.Atoi(q.Get("MaxResults")); n > 100 {
		return 400, apiErr("InvalidMaxResults", "MaxResults")
	}
	list := f.aclEntries[q.Get("AclId")]
	s, e, next := f.pageOf(q, len(list))
	return 200, map[string]any{"NextToken": next, "TotalCount": len(list), "AclEntries": list[s:e]}
}

func (f *fakeALB) createACL(q url.Values) (int, any) {
	id := f.id("acl-new")
	f.addACL(id, q.Get("AclName"))["AclStatus"] = "Configuring"
	f.pending[id] = 1
	return 200, map[string]any{"AclId": id, "JobId": "job-1"}
}

func (f *fakeALB) deleteACL(q url.Values) (int, any) {
	for i, a := range f.acls {
		if a["AclId"] == q.Get("AclId") {
			f.acls = append(f.acls[:i], f.acls[i+1:]...)
			return 200, map[string]any{"JobId": "job-1"}
		}
	}
	return 404, notFound("Acl")
}

// writable refuses a write to an ACL that is still Configuring.
func (f *fakeALB) aclWritable(a map[string]any) (int, any, bool) {
	if a == nil {
		return 404, notFound("Acl"), false
	}
	if f.pending[a["AclId"].(string)] > 0 {
		return 400, apiErr("IncorrectStatus.Acl", "acl is configuring"), false
	}
	return 0, nil, true
}

func (f *fakeALB) addACLEntries(q url.Values) (int, any) {
	a := f.acl(q.Get("AclId"))
	if st, body, ok := f.aclWritable(a); !ok {
		return st, body
	}
	id := a["AclId"].(string)
	var add []map[string]any
	for i := 1; ; i++ {
		e := q.Get("AclEntries." + strconv.Itoa(i) + ".Entry")
		if e == "" {
			break
		}
		if !strings.Contains(e, "/") {
			return 400, apiErr("IllegalParam.AclEntry", "entry")
		}
		for _, have := range f.aclEntries[id] {
			if have["Entry"] == e {
				return 400, apiErr("ResourceAlreadyExist.AclEntry", "entry exists")
			}
		}
		add = append(add, map[string]any{"Entry": e, "Description": q.Get("AclEntries." + strconv.Itoa(i) + ".Description"), "Status": "Available"})
	}
	if len(add) > 20 {
		return 400, apiErr("InvalidAclEntries", "too many")
	}
	if len(f.aclEntries[id])+len(add) > 500 {
		return 400, apiErr("ResourceQuotaExceeded.AclEntriesNum", fmt.Sprintf("The quota of alb_quota_acl_entries_num is exceeded for resource %s, usage %d/500", id, len(f.aclEntries[id])+len(add)))
	}
	// The newest first.
	for _, e := range add {
		f.aclEntries[id] = append([]map[string]any{e}, f.aclEntries[id]...)
	}
	f.pending[id] = 1
	a["AclStatus"] = "Configuring"
	return 200, map[string]any{"JobId": "job-1"}
}

func (f *fakeALB) removeACLEntries(q url.Values) (int, any) {
	a := f.acl(q.Get("AclId"))
	if st, body, ok := f.aclWritable(a); !ok {
		return st, body
	}
	id := a["AclId"].(string)
	gone := rep(q, "Entries")
	for _, g := range gone {
		found := false
		for _, have := range f.aclEntries[id] {
			if have["Entry"] == g {
				found = true
			}
		}
		if !found {
			return 404, notFound("AclEntry")
		}
	}
	var keep []map[string]any
	for _, have := range f.aclEntries[id] {
		if !contains(gone, have["Entry"].(string)) {
			keep = append(keep, have)
		}
	}
	f.aclEntries[id] = keep
	f.pending[id] = 1
	a["AclStatus"] = "Configuring"
	return 200, map[string]any{"JobId": "job-1"}
}
