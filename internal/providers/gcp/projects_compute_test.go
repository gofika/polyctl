package gcp

import (
	"strconv"
	"strings"
	"testing"

	"google.golang.org/api/compute/v1"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt/prompttest"
)

// twoProjects is a harness on the Compute Engine fake with the lab account
// on the projects proj (default) and p2.
func twoProjects(t *testing.T) *gcpHarness {
	t.Helper()
	h, _ := interactiveGCP(t, nil)
	h.nonInteractive()
	h.selectProjects("proj", "proj", "p2")
	return h
}

// interactive switches the harness back to the interactive flow with
// scripted answers.
func (h *gcpHarness) interactive(answers ...any) *prompttest.Picker {
	h.rt.Flags.NonInteractive = false
	return h.answer(answers...)
}

// has reports whether err names every one of wants.
func has(err error, wants ...string) bool {
	if err == nil {
		return false
	}
	for _, w := range wants {
		if !strings.Contains(err.Error(), w) {
			return false
		}
	}
	return true
}

// An instance name held in two projects: the non-interactive flow fails
// with exit code 5, lists both and names the flags that differ and the id;
// --project, the id, or a pick in the interactive flow choose.
func TestInstanceOfTwoProjectsIsAmbiguous(t *testing.T) {
	h := twoProjects(t)
	h.gce.addInstance("proj", "us-central1-a", "web", "10.0.0.1", "34.0.0.1")
	b := h.gce.addInstance("p2", "us-central1-a", "web", "10.0.0.2", "34.0.0.2")
	get := func(args ...string) (string, error) {
		err := h.run(append([]string{"compute", "instance", "get", "--field", "internal-ip"}, args...)...)
		return strings.TrimSpace(h.stdout.String()), err
	}

	_, err := get("web")
	if exitClass(err) != "ambiguous" || !has(err, "gcp/lab project proj us-central1-a (", "gcp/lab project p2 us-central1-a (", "RUNNING)",
		"pass --project <id>, or the instance id, to choose") || strings.Contains(err.Error(), "--zone") || strings.Contains(err.Error(), "--profile") {
		t.Fatalf("same name in two projects = %v", err)
	}
	// --zone does not tell them apart; --project does, alone or with it.
	if _, err := get("web", "--zone", "us-central1-a"); exitClass(err) != "ambiguous" {
		t.Errorf("--zone alone = %v", err)
	}
	if ip, err := get("web", "--project", "p2"); err != nil || ip != "10.0.0.2" {
		t.Errorf("--project p2 = %q, %v", ip, err)
	}
	if ip, err := get("web", "--zone", "us-central1-a", "--project", "proj"); err != nil || ip != "10.0.0.1" {
		t.Errorf("--zone and --project = %q, %v", ip, err)
	}
	if ip, err := get(strconv.FormatUint(b.Id, 10)); err != nil || ip != "10.0.0.2" {
		t.Errorf("by id = %q, %v", ip, err)
	}
	if _, err := get("web", "--project", "p2", "--zone", "europe-west1-b"); exitClass(err) != "notfound" {
		t.Errorf("--project with a zone that does not hold it = %v", err)
	}

	// Another zone as well: both flags are named.
	h.gce.addInstance("p2", "europe-west1-b", "web", "10.0.0.3", "")
	h.rt.Flags.Refresh = true
	if _, err = get("web"); !has(err, "pass --project <id> or --zone <zone>, or the instance id, to choose") {
		t.Errorf("two projects and two zones = %v", err)
	}
	h.rt.Flags.Refresh = false

	// The interactive flow asks which one this call means.
	p := h.interactive(prompttest.Label("10.0.0.2"))
	if ip, err := get("web"); err != nil || ip != "10.0.0.2" {
		t.Fatalf("interactive = %q, %v", ip, err)
	}
	p.Done()
	a := p.Asked[0]
	if l := prompttest.Labels(a.Options); !strings.Contains(a.Title, `instance "web"`) || len(a.Options) != 3 ||
		!strings.Contains(l, "us-central1-a  10.0.0.1  34.0.0.1  project proj  gcp/lab") || !strings.Contains(l, "us-central1-a  10.0.0.2  34.0.0.2  project p2  gcp/lab") {
		t.Errorf("pick %q:\n%s", a.Title, l)
	}
}

// The stop report of TestInstanceOfTwoProjectsIsAmbiguous names the
// project; so does the instance list.
func TestInstanceRowsCarryTheirProject(t *testing.T) {
	h := twoProjects(t)
	h.gce.addInstance("proj", "us-central1-a", "a", "10.0.0.1", "")
	h.gce.addInstance("p2", "us-central1-a", "b", "10.0.0.2", "")
	if err := h.run("compute", "instance", "list"); err != nil {
		t.Fatal(err)
	}
	var res instanceResult
	h.jsonOut(&res)
	if len(res.Instances) != 2 || res.Instances[0].Project != "p2" || res.Instances[0].Name != "b" || res.Instances[1].Project != "proj" {
		t.Errorf("list = %+v", res.Instances)
	}
	if err := h.run("compute", "instance", "list", "--project", "p2"); err != nil {
		t.Fatal(err)
	}
	h.jsonOut(&res)
	if len(res.Instances) != 1 || res.Instances[0].Name != "b" {
		t.Errorf("list --project p2 = %+v", res.Instances)
	}
	h.rt.Flags.DryRun = true
	if err := h.run("compute", "instance", "stop", "b", "--yes"); err != nil {
		t.Fatal(err)
	}
	if rep := h.report(); rep.Target.Project != "p2" || rep.Target.Zone != "us-central1-a" {
		t.Errorf("target = %+v", rep.Target)
	}
}

// --project may name a project outside the selection: the instance is
// found live, and nothing of that project is written to the inventory.
func TestInstanceOfUnselectedProject(t *testing.T) {
	h := twoProjects(t)
	h.gce.addInstance("proj", "us-central1-a", "web", "10.0.0.1", "")
	h.gce.addInstance("p3", "us-central1-a", "solo", "10.0.0.9", "")
	if err := h.run("compute", "instance", "get", "solo"); exitClass(err) != "notfound" {
		t.Fatalf("without --project = %v", err)
	}
	for _, args := range [][]string{{"solo", "--project", "p3"}, {"solo", "--project", "p3", "--zone", "us-central1-a"}} {
		if err := h.run(append([]string{"compute", "instance", "get", "--field", "internal-ip"}, args...)...); err != nil || strings.TrimSpace(h.stdout.String()) != "10.0.0.9" {
			t.Errorf("%v = %q, %v", args, h.stdout.String(), err)
		}
	}
	if err := h.run("compute", "instance", "list", "--project", "p3"); err != nil || !strings.Contains(h.stdout.String(), `"name": "solo"`) || strings.Contains(h.stdout.String(), `"name": "web"`) {
		t.Errorf("list --project p3 = %v\n%s", err, h.stdout.String())
	}
	for _, row := range h.rowsOf(platform.ResInstance) {
		if strings.Contains(row, " p3") {
			t.Errorf("a row of the unselected project was cached: %s", row)
		}
	}
	if err := h.run("compute", "instance", "get", "web", "--project", "p3"); exitClass(err) != "notfound" || !has(err, "project p3") {
		t.Errorf("an instance of another project under --project p3 = %v", err)
	}
}

func (h *gcpHarness) addFirewallIn(project, name string) {
	h.gce.mu.Lock()
	defer h.gce.mu.Unlock()
	h.gce.firewalls[project+"/"+name] = &compute.Firewall{Name: name, Network: apiBase + "projects/" + project + "/global/networks/default",
		Direction: dirIngress, Priority: 1000, SourceRanges: []string{"10.0.0.0/8"}, Allowed: []*compute.FirewallAllowed{{IPProtocol: "tcp", Ports: []string{"22"}}},
		SelfLink: apiBase + "projects/" + project + "/global/firewalls/" + name}
}

// Firewall rules: the list covers every selected project and names the
// project of each rule; a rule one project holds is found without a flag;
// a name two projects hold is a pick in the interactive flow and exit code
// 5 otherwise; a create goes to the default project, or to --project.
func TestFirewallAcrossProjects(t *testing.T) {
	h := twoProjects(t)
	h.gce.addVPCs()
	h.addFirewallIn("proj", "allow-ssh")
	h.addFirewallIn("p2", "allow-ssh")
	h.addFirewallIn("p2", "only-p2")

	if err := h.run("compute", "firewall", "list"); err != nil {
		t.Fatal(err)
	}
	var rows []firewallView
	h.jsonOut(&rows)
	got := ""
	for _, r := range rows {
		got += r.Project + "/" + r.Name + " "
	}
	if got != "p2/allow-ssh p2/only-p2 proj/allow-ssh " || !strings.Contains(h.stderr.String(), "projects proj, p2") {
		t.Errorf("list = %s / %s", got, h.stderr.String())
	}
	if err := h.run("compute", "firewall", "list", "--project", "proj"); err != nil {
		t.Fatal(err)
	}
	if h.jsonOut(&rows); len(rows) != 1 || rows[0].Project != "proj" {
		t.Errorf("list --project proj = %+v", rows)
	}

	var v firewallView
	if err := h.run("compute", "firewall", "get", "only-p2"); err != nil {
		t.Fatalf("a rule of one project = %v", err)
	}
	if h.jsonOut(&v); v.Project != "p2" {
		t.Errorf("get only-p2 = %+v", v)
	}
	err := h.run("compute", "firewall", "get", "allow-ssh")
	if exitClass(err) != "ambiguous" || !has(err, "gcp/lab project p2", "gcp/lab project proj", "pass --project <id> to choose") {
		t.Fatalf("a rule of two projects = %v", err)
	}
	if err := h.run("compute", "firewall", "get", "allow-ssh", "--project", "p2"); err != nil {
		t.Fatalf("--project p2 = %v", err)
	}
	if h.jsonOut(&v); v.Project != "p2" {
		t.Errorf("get --project p2 = %+v", v)
	}
	if err := h.run("compute", "firewall", "get", "nosuch"); exitClass(err) != "notfound" || !has(err, "proj, p2") {
		t.Errorf("missing rule = %v", err)
	}
	if err := h.run("compute", "firewall", "delete", "allow-ssh", "--yes"); exitClass(err) != "ambiguous" {
		t.Errorf("delete of a rule of two projects = %v", err)
	}
	if err := h.run("compute", "firewall", "delete", "allow-ssh", "--project", "p2", "--yes"); err != nil {
		t.Fatalf("delete --project p2 = %v", err)
	}
	if rep := h.report(); rep.Target.Project != "p2" {
		t.Errorf("delete target = %+v", rep.Target)
	}
	h.gce.mu.Lock()
	_, inP2 := h.gce.firewalls["p2/allow-ssh"]
	_, inProj := h.gce.firewalls["proj/allow-ssh"]
	h.gce.mu.Unlock()
	if inP2 || !inProj {
		t.Errorf("after delete --project p2: p2 %v, proj %v", inP2, inProj)
	}

	// The interactive flow asks which one.
	h.addFirewallIn("p2", "allow-ssh")
	p := h.interactive(prompttest.Label("project p2"))
	if err := h.run("compute", "firewall", "get", "allow-ssh"); err != nil {
		t.Fatalf("interactive = %v", err)
	}
	p.Done()
	if h.jsonOut(&v); v.Project != "p2" {
		t.Errorf("interactive get = %+v", v)
	}
	// Without a name the rules of every project are offered.
	p = h.interactive(prompttest.Label("only-p2"))
	if err := h.run("compute", "firewall", "get"); err != nil {
		t.Fatalf("pick = %v", err)
	}
	if l := prompttest.Labels(p.Asked[0].Options); !strings.Contains(l, "project proj") || !strings.Contains(l, "project p2") {
		t.Errorf("rules offered:\n%s", l)
	}
	h.nonInteractive()

	// A create goes to the default project unless --project names one.
	h.gce.mu.Lock()
	net := *h.gce.networks["proj/default"]
	h.gce.networks["p2/default"] = &net
	h.gce.mu.Unlock()
	created := func(key string) bool {
		h.gce.mu.Lock()
		defer h.gce.mu.Unlock()
		return h.gce.firewalls[key] != nil
	}
	if err := h.run("compute", "firewall", "create", "new-a", "--network", "default", "--allow", "tcp:80", "--source-range", "10.0.0.0/8"); err != nil || !created("proj/new-a") || created("p2/new-a") {
		t.Errorf("create = %v (proj %v, p2 %v)", err, created("proj/new-a"), created("p2/new-a"))
	}
	if err := h.run("compute", "firewall", "create", "new-b", "--network", "default", "--allow", "tcp:80", "--source-range", "10.0.0.0/8", "--project", "p2"); err != nil || !created("p2/new-b") || created("proj/new-b") {
		t.Errorf("create --project p2 = %v (proj %v, p2 %v)", err, created("proj/new-b"), created("p2/new-b"))
	}
	if rep := h.report(); rep.Target.Project != "p2" {
		t.Errorf("create target = %+v", rep.Target)
	}
}

func (h *gcpHarness) addCertIn(project, scope, name string, chain []byte) {
	h.gce.mu.Lock()
	defer h.gce.mu.Unlock()
	sc := &compute.SslCertificate{Name: name, Certificate: string(chain)}
	h.gce.fillCert(project, scope, sc)
	h.gce.lb().certs[project+"/"+scope+"/"+name] = sc
}

// Certificates: the list covers every selected project; a certificate two
// projects hold in one scope is exit code 5 unless --project chooses.
func TestSSLCertificateAcrossProjects(t *testing.T) {
	h := twoProjects(t)
	p := newPair(t, []string{"example.com"}, 90)
	h.addCertIn("proj", "global", "web", p.chain)
	h.addCertIn("p2", "global", "web", p.chain)
	h.addCertIn("p2", "us-central1", "regional", p.chain)
	if err := h.run("compute", "ssl-certificate", "list"); err != nil {
		t.Fatal(err)
	}
	var rows []sslCertView
	h.jsonOut(&rows)
	got := ""
	for _, r := range rows {
		got += r.Project + "/" + r.Name + " "
	}
	if got != "proj/web p2/web p2/regional " && got != "proj/web p2/regional p2/web " {
		t.Errorf("list = %s", got)
	}
	err := h.run("compute", "ssl-certificate", "delete", "web", "--global", "--yes")
	if exitClass(err) != "ambiguous" || !has(err, "project p2", "project proj", "--project <id>") {
		t.Fatalf("delete of a certificate of two projects = %v", err)
	}
	if err := h.run("compute", "ssl-certificate", "delete", "web", "--global", "--yes", "--project", "p2"); err != nil {
		t.Fatalf("delete --project p2 = %v", err)
	}
	h.gce.mu.Lock()
	_, inP2 := h.gce.lb().certs["p2/global/web"]
	_, inProj := h.gce.lb().certs["proj/global/web"]
	h.gce.mu.Unlock()
	if inP2 || !inProj {
		t.Errorf("after delete --project p2: p2 %v, proj %v", inP2, inProj)
	}
	// One holder: found without the flag, in its project.
	if err := h.run("compute", "ssl-certificate", "delete", "regional", "--region", "us-central1", "--yes"); err != nil {
		t.Errorf("delete of a certificate of one project = %v", err)
	}
	if rep := h.report(); rep.Target.Project != "p2" {
		t.Errorf("target = %+v", rep.Target)
	}
	// The inventory keeps certificates of one name in two projects apart.
	h.addCertIn("p2", "global", "web", p.chain)
	if _, err := h.sync(platform.ResCertificate); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(h.rowsOf(platform.ResCertificate), "; "); got != "p2/global/web p2; proj/global/web proj" {
		t.Errorf("rows = %s", got)
	}
}

func (h *gcpHarness) addRuleIn(project, region, name, ip string) {
	h.gce.mu.Lock()
	defer h.gce.mu.Unlock()
	if h.gce.forwardingRules == nil {
		h.gce.forwardingRules = map[string][]*compute.ForwardingRule{}
	}
	h.gce.forwardingRules[project] = append(h.gce.forwardingRules[project], &compute.ForwardingRule{Name: name, IPAddress: ip, IPProtocol: "TCP", PortRange: "80-80",
		LoadBalancingScheme: "EXTERNAL", Region: apiBase + "projects/" + project + "/regions/" + region,
		SelfLink: selfLink(project, region, "forwardingRules", name), Labels: map[string]string{lbLabel: name}})
}

// Load balancers and their components: lists cover every selected project,
// and a name two projects hold is exit code 5 naming --project, a pick in
// the interactive flow.
func TestLoadBalancerAcrossProjects(t *testing.T) {
	h := twoProjects(t)
	h.addRuleIn("proj", "us-central1", "lb-x", "34.1.1.1")
	h.addRuleIn("p2", "us-central1", "lb-x", "34.2.2.2")
	if err := h.run("compute", "load-balancer", "list"); err != nil {
		t.Fatal(err)
	}
	var rows []lbRow
	h.jsonOut(&rows)
	if len(rows) != 2 || rows[0].Project != "p2" || rows[0].IPAddress != "34.2.2.2" || rows[1].Project != "proj" {
		t.Errorf("list = %+v", rows)
	}
	err := h.run("compute", "load-balancer", "get", "lb-x")
	if exitClass(err) != "ambiguous" || !has(err, "gcp/lab project p2 regional, us-central1", "gcp/lab project proj regional, us-central1", "pass --project <id> to choose") {
		t.Fatalf("a load balancer of two projects = %v", err)
	}
	var d lbDetail
	if err := h.run("compute", "load-balancer", "get", "lb-x", "--project", "p2"); err != nil {
		t.Fatalf("--project p2 = %v", err)
	}
	if h.jsonOut(&d); d.Project != "p2" || len(d.ForwardingRules) != 1 || d.ForwardingRules[0].IPAddress != "34.2.2.2" {
		t.Errorf("get --project p2 = %+v", d)
	}
	p := h.interactive(prompttest.Label("project proj"))
	if err := h.run("compute", "load-balancer", "get", "lb-x"); err != nil {
		t.Fatalf("interactive = %v", err)
	}
	p.Done()
	if h.jsonOut(&d); d.Project != "proj" {
		t.Errorf("interactive get = %+v", d)
	}
	h.nonInteractive()

	// A component (the forwarding rule) follows the same rule.
	err = h.run("compute", "forwarding-rule", "get", "lb-x")
	if exitClass(err) != "ambiguous" || !has(err, "project p2", "project proj", "pass --project <id> to choose") {
		t.Fatalf("a forwarding rule of two projects = %v", err)
	}
	if err := h.run("compute", "forwarding-rule", "get", "lb-x", "--project", "proj"); err != nil || !strings.Contains(h.stdout.String(), `"project": "proj"`) || !strings.Contains(h.stdout.String(), "34.1.1.1") {
		t.Errorf("forwarding-rule get --project proj = %v\n%s", err, h.stdout.String())
	}
	if err := h.run("compute", "forwarding-rule", "list"); err != nil || strings.Count(h.stdout.String(), `"project"`) != 2 {
		t.Errorf("forwarding-rule list = %v\n%s", err, h.stdout.String())
	}
	// The inventory keeps both rules, each under its project.
	rows2 := h.rowsOf(platform.ResLoadBalancer)
	if len(rows2) != 2 || !strings.HasSuffix(rows2[0], " p2/us-central1") && !strings.HasSuffix(rows2[1], " p2/us-central1") {
		t.Errorf("rows = %v", rows2)
	}
}

// The lists of a project in which the API is not enabled are empty when
// several projects are selected, instead of failing the whole list.
func TestListsSkipProjectWithoutTheAPI(t *testing.T) {
	h := twoProjects(t)
	h.gce.addVPCs()
	h.addFirewallIn("proj", "allow-ssh")
	h.gce.mu.Lock()
	h.gce.fail = map[string]fakeErr{"/projects/p2/": {code: 403, reason: "accessNotConfigured", message: "Compute Engine API has not been used in project p2 before or it is disabled."}}
	h.gce.mu.Unlock()
	if err := h.run("compute", "firewall", "list"); err != nil || !strings.Contains(h.stdout.String(), "allow-ssh") {
		t.Errorf("firewall list = %v\n%s", err, h.stdout.String())
	}
	if reps, err := h.sync(platform.ResInstance); err != nil || reps[0].Err != nil {
		t.Errorf("sync = %+v, %v", reps, err)
	}
	if err := h.run("compute", "firewall", "get", "allow-ssh"); err != nil {
		t.Errorf("get = %v", err)
	}
	// Pinned to it, the answer is the error it is.
	if err := h.run("compute", "firewall", "list", "--project", "p2"); exitClass(err) != "auth" {
		t.Errorf("list --project p2 = %v", err)
	}
}
