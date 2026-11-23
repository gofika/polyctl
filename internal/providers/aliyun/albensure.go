package aliyun

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// albEIPCount is the number of EIPs of a load balancer ensure builds: one
// in each of its two zones.
const albEIPCount = 2

// albListenerWant is a listener ensure makes sure of.
type albListenerWant struct {
	Protocol string // HTTP or HTTPS
	Port     int
}

func (w albListenerWant) key() string {
	return strings.ToLower(w.Protocol) + ":" + strconv.Itoa(w.Port)
}

// defaultPort reports whether the listener is on its protocol's usual port
// (80 for HTTP, 443 for HTTPS): such a listener matches the first existing
// listener of the protocol, whatever its port; any other matches by
// protocol and port.
func (w albListenerWant) defaultPort() bool {
	return (w.Protocol == "HTTP" && w.Port == 80) || (w.Protocol == "HTTPS" && w.Port == 443)
}

// matchListeners pairs each wanted listener with the existing one it stands
// for (absent: none). A listener on the wanted protocol and port always
// matches; a default-port want (http:80, https:443) otherwise takes the
// first listener of its protocol that no other want matched by port, so
// that two wants never claim the same listener.
func matchListeners(wants []albListenerWant, existing []albListener) map[string]*albListener {
	out := map[string]*albListener{}
	claimed := map[string]bool{}
	for _, w := range wants {
		for i := range existing {
			l := &existing[i]
			if strings.EqualFold(l.Protocol, w.Protocol) && l.Port == w.Port && !claimed[l.ID] {
				out[w.key()], claimed[l.ID] = l, true
				break
			}
		}
	}
	for _, w := range wants {
		if out[w.key()] != nil || !w.defaultPort() {
			continue
		}
		for i := range existing {
			l := &existing[i]
			if strings.EqualFold(l.Protocol, w.Protocol) && !claimed[l.ID] {
				out[w.key()], claimed[l.ID] = l, true
				break
			}
		}
	}
	return out
}

// parseListenerWants reads the --listener values: each protocol:port once.
func parseListenerWants(specs []string) ([]albListenerWant, error) {
	if len(specs) == 0 {
		return nil, app.UsageErrf("--listener is empty: give http:80, https:443 or both")
	}
	var out []albListenerWant
	seen := map[string]bool{}
	ports := map[int]bool{}
	for _, s := range specs {
		p, n, err := parseListenerSpec("listener", s)
		if err != nil {
			return nil, err
		}
		w := albListenerWant{Protocol: p, Port: n}
		if seen[w.key()] {
			continue
		}
		if ports[n] {
			return nil, app.UsageErrf("--listener names port %d twice", n)
		}
		seen[w.key()], ports[n] = true, true
		out = append(out, w)
	}
	return out, nil
}

// albEnsureLB names the load balancer in the result of ensure.
type albEnsureLB struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	DNSName string `json:"dns_name" yaml:"dns_name"`
}

// albEnsureReport is the output of load-balancer ensure: the change report,
// the load balancer and its addresses (what DNS should point to).
type albEnsureReport struct {
	platform.Report `yaml:",inline"`
	LoadBalancer    albEnsureLB `json:"load_balancer" yaml:"load_balancer"`
	Addresses       []string    `json:"addresses" yaml:"addresses"`
}

// pickCASCert chooses the certificate of domain among the uploaded ones:
// the certificates named upload_<root>_<date> first, else those whose
// common name is the root domain, its wildcard or the domain itself; of
// these, the one that expires last and has not expired.
func pickCASCert(certs []casCertificate, domain, root string, now time.Time) *casCertificate {
	best := func(keep func(casCertificate) bool) *casCertificate {
		var out *casCertificate
		for i := range certs {
			c := &certs[i]
			if !keep(*c) || c.expired(now) {
				continue
			}
			if out == nil || c.EndDate > out.EndDate || (c.EndDate == out.EndDate && c.ID > out.ID) {
				out = c
			}
		}
		return out
	}
	prefix := "upload_" + root + "_"
	if c := best(func(c casCertificate) bool { return strings.HasPrefix(strings.ToLower(c.Name), prefix) }); c != nil {
		return c
	}
	return best(func(c casCertificate) bool {
		cn := strings.ToLower(strings.TrimSpace(c.CommonName))
		return cn == root || cn == "*."+root || cn == domain
	})
}

// zoneSuffix is the last part of a zone id (cn-hongkong-b is b).
func zoneSuffix(region, zone string) string {
	if s, ok := strings.CutPrefix(zone, region+"-"); ok {
		return s
	}
	if i := strings.LastIndexByte(zone, '-'); i >= 0 {
		return zone[i+1:]
	}
	return zone
}

// strictIdleEIPs keeps the EIPs ensure may take for a load balancer: idle
// ones of the ISP (see eipAddress.idle) whose name and description are
// empty, so that an address someone set aside and labelled is never taken.
func strictIdleEIPs(eips []eipAddress, isp string) []eipAddress {
	var out []eipAddress
	for _, e := range eips {
		if e.idle(isp) && e.Name == "" && e.Description == "" {
			out = append(out, e)
		}
	}
	return out
}

func albLBEnsureCmd(rt *app.Runtime) *cobra.Command {
	var region, service, cert, groupFlag, vpcRef string
	var listeners, zones []string
	var eips int
	var httpsBackend bool
	var w app.WaitFlags
	cmd := &cobra.Command{
		Use:   "ensure <domain>",
		Short: "Make sure a dual-zone ALB with HTTP / HTTPS listeners serves an ECS instance",
		Long: `Make sure an Internet-facing ALB load balancer serves the ECS instance --service
(name or id, in the account and region of the command; required) for
<domain>, with two EIPs, HTTP and HTTPS listeners and the certificate of the
domain. Running it again changes nothing. Nothing created is rolled back
when a later step fails: run ensure again to go on (EIPs allocated for a
load balancer whose creation failed are named on stderr: they stay idle
and billed until the next run reuses them).

Before anything is written the instance and, when an HTTPS listener is
wanted, the certificate are looked up: a missing one is exit code 4 with
nothing created.

- The load balancer is named by naming.aliyun_alb_load_balancer (lb-{name},
  {name} being <domain> with every dot replaced by a hyphen) and looked up
  by name. An existing one is used as it is (its VPC, zones and EIPs are not
  touched); one that is not Active yet is waited for, an Inactive one is
  exit code 1.
- A missing one is created in the instance's VPC (--vpc, an id or name,
  has to be that VPC) in two zones: --zones, else the first two zones of
  the region that offer ALB (fewer than two is exit code 7). Each zone gets
  the vSwitch naming.aliyun_vswitch names in that VPC (a missing one is
  created on the first free /22) and an EIP: an idle EIP of the account of
  the ISP defaults.aliyun.eip.isp whose name and description are empty is
  reused, else one is allocated (BGP_PRO, 200 Mbps, pay by traffic; see
  aliyun eip address --help). The load balancer is Standard, pay as you
  go, and is waited for until Active (polled every 5 seconds, bounded by
  --timeout); --no-wait skips the wait and every later step.
- The server group naming.aliyun_alb_server_group ({service}-http, or
  --server-group) of the VPC is created when missing (health check and
  session persistence off) and gets the instance on port 80 when it has no
  server; a group that has servers is left as it is. With --https-backend
  the HTTPS listener forwards to its own group ({service}-https, port 443);
  otherwise it reuses the HTTP group.
- Listeners (--listener, http:80 and https:443 by default): a missing one is
  created and waited for until Running. A listener matches by protocol and
  port; http:80 and https:443 otherwise take an existing listener of their
  protocol whatever its port (one no other --listener matched). Of an
  existing listener only the certificate of an
  HTTPS one is compared: another one is replaced, and the listener waited
  for until Running again.
- The certificate is --cert (a CAS certificate id), else the latest valid
  certificate uploaded for the domain's registered domain (named
  upload_<root>_<date>, else whose common name is the root domain or its
  wildcard), from the CAS store of the region. ensure never issues one: run
  polyctl cert ensure and polyctl aliyun cas certificate upload first.
- DNS is not written: the last row (dns/addresses) and, in a table, a note
  on stderr name the addresses to point <domain> to (polyctl dns ensure).
  -o json adds "load_balancer": {"id", "name", "dns_name"} and
  "addresses".`,
		Example: `  polyctl aliyun alb load-balancer ensure example.com --service site-a --dry-run -o json
  polyctl aliyun alb load-balancer ensure example.com --service site-a --https-backend
  polyctl aliyun alb load-balancer ensure example.com --service site-a --cert 1234567`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			domain := platform.NormalizeDomain(args[0])
			if domain == "" {
				return app.UsageErrf("the domain is empty")
			}
			if strings.Contains(domain, "*") {
				return app.UsageErrf("%q: a wildcard domain makes no load balancer name; give the bare domain (%s)", args[0], strings.TrimPrefix(strings.TrimPrefix(domain, "*"), "."))
			}
			if service == "" {
				return app.UsageErrf("--service is required: name the ECS instance behind the load balancer")
			}
			if eips != albEIPCount {
				return app.UsageErrf("--eips must be %d (one per zone of a dual-zone load balancer), got %d", albEIPCount, eips)
			}
			wants, err := parseListenerWants(listeners)
			if err != nil {
				return err
			}
			if cert != "" {
				if _, err := strconv.ParseInt(cert, 10, 64); err != nil {
					return app.UsageErrf("--cert %q is not a CAS certificate id (an integer such as 1234567)", cert)
				}
			}
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			sc, err := openALBScope(ctx, rt, region)
			if err != nil {
				return err
			}
			var zoneWants []zoneTarget
			if cmd.Flags().Changed("zones") {
				if zoneWants, err = parseZones(sc.region, zones); err != nil {
					return err
				}
				if len(zoneWants) != 2 {
					return app.UsageErrf("--zones takes two zones (a dual-zone load balancer), got %d", len(zoneWants))
				}
			}
			e := &albEnsure{rt: rt, sc: sc, domain: domain, service: service, wants: wants, certFlag: cert, groupFlag: groupFlag,
				vpcRef: vpcRef, zones: zoneWants, httpsBackend: httpsBackend, wait: wait, timeout: timeout}
			if err := e.observe(ctx); err != nil {
				return err
			}
			return e.run(ctx)
		},
	}
	cmd.Flags().StringVar(&service, "service", "", "ECS instance behind the load balancer, name or id (required)")
	cmd.Flags().StringArrayVar(&listeners, "listener", []string{"http:80", "https:443"}, "listener <protocol>:<port>, protocol http or https (repeatable)")
	cmd.Flags().IntVar(&eips, "eips", albEIPCount, "EIPs of the load balancer (only 2 is supported)")
	cmd.Flags().BoolVar(&httpsBackend, "https-backend", false, "the HTTPS listener forwards to its own HTTPS server group ({service}-https, port 443)")
	cmd.Flags().StringVar(&cert, "cert", "", "CAS certificate id of the HTTPS listener (default: the latest valid one uploaded for the domain)")
	cmd.Flags().StringVar(&groupFlag, "server-group", "", "name of the HTTP server group (default naming.aliyun_alb_server_group); the HTTPS group drops a trailing -http and adds -https")
	cmd.Flags().StringSliceVar(&zones, "zones", nil, "the two zones of a new load balancer: suffixes (b,c) or zone ids (default: the first two zones offering ALB)")
	cmd.Flags().StringVar(&vpcRef, "vpc", "", "VPC of a new load balancer, id or name (default and only choice: the instance's VPC)")
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	app.AddWaitFlags(cmd, &w, true, app.DefaultWaitTimeout)
	return cmd
}

// albEnsure is one run of load-balancer ensure: what it observed, then the
// plan it built from it.
type albEnsure struct {
	rt           *app.Runtime
	sc           *albScope
	domain       string
	service      string
	wants        []albListenerWant
	certFlag     string
	groupFlag    string
	vpcRef       string
	zones        []zoneTarget
	httpsBackend bool
	wait         bool
	timeout      time.Duration

	lbName    string
	inst      *Instance
	certID    string // the listener certificate id ("" without HTTPS)
	lb        *albLB
	vpc       vpcInfo
	listeners []albListener
	rg        string
	rgDone    bool

	plan platform.Plan
	// lbID is the id of the load balancer once known (Pending in a dry run
	// that would create it).
	lbID      string
	addresses []string
	stopped   bool
}

func (e *albEnsure) needsHTTPS() bool {
	for _, w := range e.wants {
		if w.Protocol == "HTTPS" {
			return true
		}
	}
	return false
}

// resourceGroup resolves the resource group once, when something is to be
// created.
func (e *albEnsure) resourceGroup(ctx context.Context) (string, error) {
	if e.rgDone {
		return e.rg, nil
	}
	rg, err := resolveResourceGroup(ctx, e.rt, e.sc.ecsScope, "")
	if err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return "", fmt.Errorf("%w (set defaults.aliyun.resource_group to the group to use)", err)
		}
		return "", err
	}
	e.rg, e.rgDone = rg, true
	return rg, nil
}

// observe reads everything ensure depends on and checks the prerequisites
// before any write: the instance, the certificate, the load balancer and
// its VPC.
func (e *albEnsure) observe(ctx context.Context) error {
	sc := e.sc
	name, err := e.rt.ResourceName("aliyun_alb_load_balancer", "", map[string]string{"name": strings.ReplaceAll(e.domain, ".", "-")})
	if err != nil {
		return err
	}
	if err := checkLBName(name); err != nil {
		return err
	}
	e.lbName = name
	if e.inst, err = resolveInstanceIn(ctx, sc.ecsScope, e.service); err != nil {
		return err
	}
	if e.inst.VpcID == "" {
		return fmt.Errorf("instance %s is in no VPC: an ALB server group holds VPC instances only", e.inst.ID)
	}
	if e.needsHTTPS() {
		if err := e.resolveCert(ctx); err != nil {
			return err
		}
	}
	found, err := sc.a.findLoadBalancersByName(ctx, name)
	if err != nil {
		return err
	}
	switch len(found) {
	case 0:
	case 1:
		if e.lb, err = sc.a.getLoadBalancer(ctx, found[0].ID); err != nil {
			return err
		}
	default:
		var ids []string
		for _, f := range found {
			ids = append(ids, f.ID)
		}
		return &app.AmbiguousError{What: fmt.Sprintf("load balancer %q in %s", name, sc.where()), Candidates: ids,
			Hint: "Alibaba Cloud lets several load balancers share a name; delete or rename the extra ones"}
	}
	if e.lb != nil {
		if e.lb.Status == albStatusInactive {
			return fmt.Errorf("load balancer %s (%s) is Inactive: enable it in the console, then run ensure again", name, e.lb.ID)
		}
		if e.lb.VpcID != e.inst.VpcID {
			return fmt.Errorf("load balancer %s (%s) is in %s, instance %s in %s: a server group holds instances of its own VPC only; ensure does not move either", name, e.lb.ID, e.lb.VpcID, e.inst.ID, e.inst.VpcID)
		}
		if e.vpcRef != "" && e.vpcRef != e.lb.VpcID {
			if v, err := resolveVPC(ctx, sc.ecsScope, e.vpcRef); err != nil || v.ID != e.lb.VpcID {
				return fmt.Errorf("load balancer %s (%s) exists in %s, not in --vpc %s; ensure does not move it", name, e.lb.ID, e.lb.VpcID, e.vpcRef)
			}
		}
		storeLB(ctx, e.rt, sc.profile, *e.lb)
		e.lbID = e.lb.ID
		if e.vpc, err = resolveVPC(ctx, sc.ecsScope, e.lb.VpcID); err != nil {
			return err
		}
		if e.listeners, err = sc.a.listListeners(ctx, e.lb.ID); err != nil {
			return err
		}
		return nil
	}
	ref := e.inst.VpcID
	if e.vpcRef != "" {
		ref = e.vpcRef
	}
	if e.vpc, err = resolveVPC(ctx, sc.ecsScope, ref); err != nil {
		return err
	}
	if e.vpc.ID != e.inst.VpcID {
		return fmt.Errorf("--vpc %s is %s, but instance %s is in %s: the load balancer has to be in the instance's VPC", e.vpcRef, e.vpc.ID, e.inst.ID, e.inst.VpcID)
	}
	return nil
}

// resolveCert finds the certificate of the HTTPS listeners in the CAS
// store of the region and sets the listener certificate id.
func (e *albEnsure) resolveCert(ctx context.Context) error {
	sc := e.sc
	store, err := sc.c.casFor(sc.region)
	if err != nil {
		return err
	}
	certs, _, err := sc.c.listCASCertificatesIn(ctx, store)
	if err != nil {
		return err
	}
	var id string
	if e.certFlag != "" {
		for _, c := range certs {
			if c.ID == e.certFlag {
				id = c.ID
			}
		}
		if id == "" {
			return fmt.Errorf("%w: CAS certificate %s in %s (list them with polyctl aliyun cas certificate list)", platform.ErrNotFound, e.certFlag, store.Endpoint)
		}
	} else {
		root, err := platform.RegisteredDomain(e.domain)
		if err != nil {
			return app.UsageErrf("%v", err)
		}
		c := pickCASCert(certs, e.domain, root, casNow())
		if c == nil {
			return fmt.Errorf("%w: CAS (%s) holds no valid certificate of %s; run polyctl cert ensure %s, then polyctl aliyun cas certificate upload, or pass --cert", platform.ErrNotFound, store.Endpoint, root, e.domain)
		}
		id = c.ID
	}
	e.certID = listenerCertID(store.Region, id)
	return nil
}

// run builds the plan, runs it and prints the report.
func (e *albEnsure) run(ctx context.Context) error {
	if err := e.build(ctx); err != nil {
		return err
	}
	rep, err := e.rt.RunPlan(ctx, e.sc.target(), &e.plan)
	if rep.Changes == nil {
		rep.Changes = []platform.Change{}
	}
	out := albEnsureReport{Report: rep, LoadBalancer: albEnsureLB{ID: e.lbID, Name: e.lbName}, Addresses: []string{}}
	if out.LoadBalancer.ID == "" {
		out.LoadBalancer.ID = platform.Pending
	}
	if e.lb != nil {
		out.LoadBalancer.DNSName = e.lb.DNSName
	}
	out.Addresses = append(out.Addresses, e.addresses...)
	if rerr := e.rt.Render(out, func() output.Grid { return app.ChangeGrid(rep.Changes) }); rerr != nil && err == nil {
		err = rerr
	}
	if e.rt.Format() == output.Table {
		switch {
		case len(e.addresses) > 0:
			e.rt.Infof("DNS: point the A records of %s to %s (polyctl dns ensure); ensure does not write DNS", e.domain, strings.Join(e.addresses, ", "))
		case err == nil && rep.DryRun:
			e.rt.Infof("the load balancer does not exist yet: its addresses appear once a real run created it")
		}
	}
	if err != nil && !rep.DryRun && !errors.Is(err, app.ErrUsage) {
		e.rt.NotifyFailure(ctx, app.Failure{Event: "aliyun.alb.load_balancer.ensure.failed", Platform: string(platform.Aliyun), Profile: e.sc.profile,
			Domain: e.domain, Error: err.Error(), Changes: rep.Changes})
	}
	return err
}

// build turns what observe read into the plan.
func (e *albEnsure) build(ctx context.Context) error {
	sc := e.sc
	e.plan.Add(platform.Step{Resource: "vpc/" + orID(e.vpc.Name, e.vpc.ID), Action: platform.Unchanged, ID: e.vpc.ID, Desc: e.vpc.ID + " " + e.vpc.CIDR})
	if e.lb == nil {
		if err := e.buildNewLB(ctx); err != nil {
			return err
		}
	} else {
		e.buildExistingLB()
	}
	if e.stopped {
		return nil
	}
	if err := e.buildServerGroups(ctx); err != nil {
		return err
	}
	if err := e.buildListeners(ctx); err != nil {
		return err
	}
	e.plan.Add(platform.Step{Resource: "dns/addresses", Action: platform.Skipped,
		Check: func(ctx context.Context) (platform.Change, bool, error) {
			id := e.lbID
			if id == "" || id == platform.Pending {
				return platform.Change{Action: platform.Skipped, Detail: "the addresses appear once the load balancer exists"}, true, nil
			}
			lb, err := sc.a.getLoadBalancer(ctx, id)
			if err != nil {
				return platform.Change{}, true, err
			}
			if lb != nil {
				e.lb = lb
				e.addresses = lb.ips()
				storeLB(ctx, e.rt, sc.profile, *lb)
			}
			detail := "point the A records of " + e.domain + " to " + orDash(strings.Join(e.addresses, ", ")) + " (polyctl dns ensure; not written by ensure)"
			return platform.Change{Action: platform.Skipped, ID: id, Detail: detail}, true, nil
		}})
	return nil
}

// stop ends the plan after the load balancer step: the later steps need
// an Active load balancer.
func (e *albEnsure) stop(reason string) {
	e.plan.Add(platform.Step{Resource: "load-balancer/" + e.lbName + "/listeners", Action: platform.Skipped, Desc: reason})
	e.stopped = true
}

func (e *albEnsure) buildExistingLB() {
	sc, lb := e.sc, e.lb
	step := platform.Step{Resource: "load-balancer/" + e.lbName, Action: platform.Unchanged, ID: lb.ID, Desc: fmt.Sprintf("%s (%s)", lb.ID, lb.Status)}
	if lb.Status != albStatusActive {
		if !e.wait {
			e.plan.Add(step)
			e.stop("later steps need an Active load balancer; skipped by --no-wait")
			return
		}
		if e.rt.DryRun() {
			step.Desc += fmt.Sprintf("; currently %s, a real run waits until Active", lb.Status)
		}
		step.Apply = func(ctx context.Context) (platform.Change, error) {
			last, err := waitLBActive(ctx, sc.a, lb.ID, e.timeout)
			if err != nil {
				return platform.Change{}, err
			}
			return platform.Change{Detail: fmt.Sprintf("%s (was %s, now %s)", lb.ID, lb.Status, last)}, nil
		}
	}
	e.plan.Add(step)
}

func (e *albEnsure) buildNewLB(ctx context.Context) error {
	sc := e.sc
	zones := e.zones
	if len(zones) == 0 {
		offered, err := sc.a.describeZones(ctx)
		if err != nil {
			return err
		}
		if len(offered) < 2 {
			return fmt.Errorf("%w: region %s offers ALB in %d zone(s); a dual-zone load balancer needs 2", platform.ErrNotSupported, sc.region, len(offered))
		}
		for _, z := range offered[:2] {
			zones = append(zones, zoneTarget{ID: z, Suffix: zoneSuffix(sc.region, z)})
		}
	}
	var vswWants []vswWant
	for _, z := range zones {
		n, err := vswName(e.rt, sc.region, "", z)
		if err != nil {
			return err
		}
		vswWants = append(vswWants, vswWant{Name: n, Zone: z})
	}
	existing, err := sc.c.listVSwitches(ctx, sc.region, e.vpc.ID, "", "")
	if err != nil {
		return err
	}
	vp := vswPlan{rt: e.rt, s: sc.ecsScope, vpcID: func() string { return e.vpc.ID }, vpcCIDR: e.vpc.CIDR, existing: existing,
		mask: defaultVSwitchMask, wait: true}
	if err := vp.add(&e.plan, vswWants); err != nil {
		return err
	}

	spec, err := eipSettings(e.rt, sc.profile, "", "")
	if err != nil {
		return err
	}
	all, err := sc.c.listEIPs(ctx, sc.region, eipFilter{})
	if err != nil {
		return err
	}
	for _, x := range all {
		storeEIP(ctx, e.rt, sc.profile, x)
	}
	idle := strictIdleEIPs(all, spec.ISP)
	rg, err := e.resourceGroup(ctx)
	if err != nil {
		return err
	}
	spec.ResourceGroup = rg
	taken := map[string]bool{}
	var allocated []*eipAddress
	for i := range zones {
		res := "eip/" + strconv.Itoa(i+1)
		if x := pickIdleEIP(idle, spec.ISP, taken); x != nil {
			taken[x.AllocationID] = true
			id, ip := x.AllocationID, x.IP
			e.plan.Add(platform.Step{Resource: res, Action: platform.Updated, ID: id, Desc: "reuse " + id + " " + ip,
				Apply: func(ctx context.Context) (platform.Change, error) {
					// Reusing writes nothing yet: the load balancer binds it.
					return platform.Change{ID: id, Detail: "reuse " + id + " " + ip}, nil
				}})
			continue
		}
		fresh := &eipAddress{}
		allocated = append(allocated, fresh)
		e.plan.Add(allocateStep(e.rt, sc.ecsScope, res, spec, fresh))
	}

	token := clientToken()
	var desc []string
	for _, z := range zones {
		desc = append(desc, z.ID)
	}
	build := func() albLBSpec {
		s := albLBSpec{Name: e.lbName, VpcID: e.vpc.ID, ResourceGroup: rg, Token: token}
		for i, z := range zones {
			s.Zones = append(s.Zones, albZoneMapping{Zone: z.ID, VSwitchID: e.plan.ID("vswitch/" + vswWants[i].Name),
				AllocationID: e.plan.ID("eip/" + strconv.Itoa(i+1))})
		}
		return s
	}
	var id string
	step := lbCreateStep(e.rt, sc, e.lbName, fmt.Sprintf("%s %s %s, zones %s", albEdition, albAddressType, e.vpc.ID, strings.Join(desc, ",")), build, e.wait, e.timeout, &id)
	apply := step.Apply
	step.Apply = func(ctx context.Context) (platform.Change, error) {
		ch, err := apply(ctx)
		e.lbID = id
		if err != nil && id == "" {
			// The EIPs allocated for it stay idle and billed; the next
			// ensure reuses them.
			for _, x := range allocated {
				if x.AllocationID != "" {
					e.rt.Infof("note: EIP %s (%s) was allocated for the load balancer and stays idle (billed); ensure reuses it on the next run, or release it", x.AllocationID, orDash(x.IP))
				}
			}
		}
		return ch, err
	}
	e.plan.Add(step)
	if e.rt.DryRun() {
		e.lbID = platform.Pending
	}
	if !e.wait {
		e.stop("later steps need an Active load balancer; skipped by --no-wait")
	}
	return nil
}

// groupWant is a server group ensure makes sure of.
type groupWant struct {
	Name     string
	Protocol string
	Port     int
}

// serverGroupNames returns the names of the HTTP group and of the HTTPS
// group: --server-group (the HTTPS one drops a trailing -http and adds
// -https), else naming.aliyun_alb_server_group.
func (e *albEnsure) serverGroupNames() (string, string, error) {
	if e.groupFlag != "" {
		return e.groupFlag, strings.TrimSuffix(e.groupFlag, "-http") + "-https", nil
	}
	h, err := e.rt.ResourceName("aliyun_alb_server_group", "", map[string]string{"service": e.service, "protocol": "http"})
	if err != nil {
		return "", "", err
	}
	s, err := e.rt.ResourceName("aliyun_alb_server_group", "", map[string]string{"service": e.service, "protocol": "https"})
	return h, s, err
}

func (e *albEnsure) buildServerGroups(ctx context.Context) error {
	httpName, httpsName, err := e.serverGroupNames()
	if err != nil {
		return err
	}
	groups := []groupWant{{Name: httpName, Protocol: "HTTP", Port: 80}}
	if e.needsHTTPS() {
		if e.httpsBackend {
			if httpsName == httpName {
				return app.UsageErrf("the HTTPS server group would be named %q like the HTTP one; pass --server-group ending in -http", httpName)
			}
			groups = append(groups, groupWant{Name: httpsName, Protocol: "HTTPS", Port: 443})
		}
	}
	for _, g := range groups {
		if err := e.buildServerGroup(ctx, g); err != nil {
			return err
		}
		if g.Protocol == "HTTP" && e.needsHTTPS() && !e.httpsBackend {
			e.plan.Add(platform.Step{Resource: "server-group/" + httpsName, Action: platform.Skipped,
				Desc: "--https-backend not given; HTTPS reuses " + httpName})
		}
	}
	return nil
}

func (e *albEnsure) buildServerGroup(ctx context.Context, g groupWant) error {
	sc := e.sc
	res := "server-group/" + g.Name
	found, err := sc.a.listServerGroups(ctx, []string{g.Name}, nil)
	if err != nil {
		return err
	}
	var inVPC []albServerGroup
	for _, x := range found {
		if x.VpcID == e.vpc.ID {
			inVPC = append(inVPC, x)
		}
	}
	if len(inVPC) > 1 {
		var same []albServerGroup
		for _, x := range inVPC {
			if strings.EqualFold(x.Protocol, g.Protocol) {
				same = append(same, x)
			}
		}
		if len(same) != 1 {
			var ids []string
			for _, x := range inVPC {
				ids = append(ids, x.ID+" ("+x.Protocol+")")
			}
			return &app.AmbiguousError{What: fmt.Sprintf("server group %q in %s", g.Name, e.vpc.ID), Candidates: ids,
				Hint: "Alibaba Cloud lets several server groups share a name; delete the extra ones or pass --server-group"}
		}
		inVPC = same
	}
	label := orID(e.inst.Name, e.inst.ID)
	if len(inVPC) == 1 {
		have := inVPC[0]
		e.plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: have.ID, Desc: have.ID + " " + have.Protocol})
		srv, err := sc.a.listServerGroupServers(ctx, have.ID)
		if err != nil {
			return err
		}
		if len(srv) > 0 {
			var members []string
			for _, s := range srv {
				members = append(members, fmt.Sprintf("%s:%d", s.ServerID, s.Port))
			}
			e.plan.Add(platform.Step{Resource: res + "/server", Action: platform.Unchanged, Desc: strings.Join(members, ",")})
			return nil
		}
		e.plan.Add(serverAddStep(sc, res+"/server", label, func() string { return have.ID }, e.inst.ID, g.Port))
		return nil
	}
	rg, err := e.resourceGroup(ctx)
	if err != nil {
		return err
	}
	var id string
	e.plan.Add(serverGroupCreateStep(sc, g.Name, g.Protocol, func() string { return e.vpc.ID }, rg, &id))
	e.plan.Add(serverAddStep(sc, res+"/server", label, func() string { return id }, e.inst.ID, g.Port))
	return nil
}

func (e *albEnsure) buildListeners(ctx context.Context) error {
	sc := e.sc
	httpName, httpsName, err := e.serverGroupNames()
	if err != nil {
		return err
	}
	matched := matchListeners(e.wants, e.listeners)
	for _, w := range e.wants {
		group := httpName
		if w.Protocol == "HTTPS" && e.httpsBackend {
			group = httpsName
		}
		res := "load-balancer/" + e.lbName + "/listener/" + w.key()
		have := matched[w.key()]
		if have == nil {
			desc := "-> " + group
			certID := ""
			if w.Protocol == "HTTPS" {
				certID = e.certID
				desc += " cert=" + certID
			}
			e.plan.Add(listenerCreateStep(sc, res, desc, func() string { return e.lbID }, w.Protocol, w.Port,
				func() string { return e.plan.ID("server-group/" + group) }, certID))
			continue
		}
		if w.Protocol != "HTTPS" {
			e.plan.Add(platform.Step{Resource: res, Action: platform.Unchanged, ID: have.ID,
				Desc: fmt.Sprintf("%s %s:%d -> %s", have.ID, have.Protocol, have.Port, orDash(strings.Join(have.ServerGroups, ",")))})
			continue
		}
		full, err := sc.a.getListener(ctx, have.ID)
		if err != nil {
			return err
		}
		if full == nil {
			full = have
		}
		e.plan.Add(listenerCertStep(sc, res, full, e.certID))
	}
	return nil
}
