package aws

import (
	"context"
	"fmt"
	"slices"
	"strconv"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// lbOptionLabel: "site-lb  network  internet-facing  active  vpc-0abc
// site-lb-0123.elb.ap-east-1.amazonaws.com  aws/lab/ap-east-1".
func lbOptionLabel(profile string, l loadBalancer) string {
	return joinLabel(l.Name, l.Type, l.Scheme, l.State, l.VpcID, l.DNSName, "aws/"+profile+"/"+l.Region)
}

// pickLB asks for a load balancer of the selected AWS accounts in the
// interactive flow, from the inventory (synced first when stale): those in
// region when it is given, those keep accepts. The value is its ARN, which
// resolveLB finds directly. arg names the input ("<name|arn>", "<lb>");
// required turns an empty list into a usage error naming arg instead of
// "nothing to do".
func pickLB(ctx context.Context, rt *app.Runtime, arg, region, what string, required bool, keep func(loadBalancer) bool) (string, error) {
	return rt.PickResource(ctx, app.ResourcePick{Platform: platform.AWS, Kind: platform.ResLoadBalancer,
		Title: "Load balancer", Arg: arg, What: what, Required: required,
		Filter: func(r inventory.Resource) bool {
			var l loadBalancer
			if r.Decode(&l) != nil || l.ARN == "" || (region != "" && l.Region != region) {
				return false
			}
			return keep == nil || keep(l)
		},
		Label: func(r inventory.Resource) string {
			var l loadBalancer
			_ = r.Decode(&l)
			return lbOptionLabel(r.Profile, l)
		},
		Value: func(r inventory.Resource) string { return r.ID }})
}

// lbArg fills in a missing load balancer argument in the interactive flow
// with pickLB; with the argument given, args is returned as it is.
func lbArg(ctx context.Context, rt *app.Runtime, args []string, arg, region, what string, required bool, keep func(loadBalancer) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	v, err := pickLB(ctx, rt, arg, region, what, required, keep)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// activeLB keeps the active load balancers.
func activeLB(l loadBalancer) bool { return l.State == "active" }

// tgOptionLabel: "web-80  TCP:80  instance  vpc-0abc  2 load balancers".
func tgOptionLabel(g platform.LBTargetGroup) string {
	lbs := ""
	if n := len(g.LoadBalancers); n > 0 {
		lbs = fmt.Sprintf("%d load balancer(s)", n)
	}
	return joinLabel(g.Name, fmt.Sprintf("%s:%d", g.Protocol, g.Port), g.TargetType, g.VPC, lbs)
}

// pickTG asks for a target group of the scope in the interactive flow:
// those keep accepts, valued by ARN. arg names the input; required turns
// an empty list into a usage error naming arg.
func pickTG(ctx context.Context, rt *app.Runtime, s *lbScope, arg, what string, required bool, keep func(platform.LBTargetGroup) bool) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("%s is required", arg)
	}
	tgs, err := s.c.ListTargetGroups(ctx, s.region, "")
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, g := range tgs {
		if keep == nil || keep(g) {
			opts = append(opts, prompt.Option{Label: tgOptionLabel(g), Value: g.ID})
		}
	}
	return rt.Choose(app.Choice{Title: "Target group", Options: opts, Arg: arg, Required: required, What: what + " in " + s.where()})
}

// tgArg fills in a missing <name|arn> of a target group command in the
// interactive flow with the target groups of the region; with the argument
// given, args is returned as it is.
func tgArg(ctx context.Context, rt *app.Runtime, args []string, region string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	s, err := openELBScope(ctx, rt, region, "")
	if err != nil {
		return nil, err
	}
	v, err := pickTG(ctx, rt, s, "<name|arn>", "target group", false, nil)
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// listenerProtocols are the listener protocols of a load balancer type.
func listenerProtocols(lbType string) []string {
	if lbType == "application" {
		return []string{"HTTP", "HTTPS"}
	}
	return []string{"TCP", "TLS", "UDP", "TCP_UDP"}
}

// tgFits keeps the target groups a listener of lb can forward to: of its
// VPC, of a protocol of its type, used by no other load balancer.
func tgFits(lb platform.LoadBalancer) func(platform.LBTargetGroup) bool {
	protos := listenerProtocols(lb.Type)
	return func(g platform.LBTargetGroup) bool {
		if g.VPC != lb.VPC || !slices.Contains(protos, g.Protocol) {
			return false
		}
		for _, id := range g.LoadBalancers {
			if id != lb.ID {
				return false
			}
		}
		return true
	}
}

// listenerArg fills in a missing <listener-arn|lb:port> in the interactive
// flow: the load balancer, then one of its listeners (keep accepts; none is
// nothing to do). The value is the listener's ARN.
func listenerArg(ctx context.Context, rt *app.Runtime, args []string, region string, keep func(platform.LBListener) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	lbRef, err := pickLB(ctx, rt, "<listener-arn|lb:port>", region, "AWS load balancer", false, nil)
	if err != nil {
		return nil, err
	}
	s, lb, err := resolveLB(ctx, rt, lbRef, "")
	if err != nil {
		return nil, err
	}
	listeners, err := s.c.ListListeners(ctx, s.region, lb.ID)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	for _, l := range listeners {
		if keep == nil || keep(l) {
			opts = append(opts, prompt.Option{Label: joinLabel(strconv.Itoa(int(l.Port)), l.Protocol, listenerSummary(l), strings.Join(l.Certificates, ",")), Value: l.ID})
		}
	}
	v, err := rt.Choose(app.Choice{Title: "Listener of " + lb.Name, Options: opts, Arg: "<listener-arn|lb:port>",
		Empty: app.NothingToDof("load balancer %s has no listeners", lb.Name)})
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// certOptionLabel: "example.com  +2 names  ISSUED  expires 2027-03-01  in
// use  arn:...".
func certOptionLabel(c platform.Certificate) string {
	more := ""
	if n := len(c.Names) - 1; n > 0 {
		more = fmt.Sprintf("+%d names", n)
	}
	exp := ""
	if c.NotAfter != nil {
		exp = "expires " + c.NotAfter.UTC().Format("2006-01-02")
	}
	use := ""
	if c.InUse {
		use = "in use"
	}
	return joinLabel(c.Domain, more, c.Status, exp, use, c.ID)
}

// pickCert asks for the certificate of a TLS or HTTPS listener (--cert) in
// the interactive flow: the issued, unexpired ACM certificates of region,
// the one expiring last preselected. A certificate needs DNS validation
// and is not requested here: none is a usage error naming --cert.
func pickCert(ctx context.Context, rt *app.Runtime, s *lbScope) (string, error) {
	if !rt.Interactive() {
		return "", app.UsageErrf("--cert is required")
	}
	certs, err := s.c.ListCertificates(ctx, platform.CertificateFilter{Region: s.region, Statuses: []string{"ISSUED"}})
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	def, latest := "", time.Time{}
	for _, c := range certs {
		if c.NotAfter != nil && c.NotAfter.Before(time.Now()) {
			continue
		}
		if c.NotAfter != nil && c.NotAfter.After(latest) {
			def, latest = c.ID, *c.NotAfter
		}
		opts = append(opts, prompt.Option{Label: certOptionLabel(c), Value: c.ID})
	}
	return rt.Choose(app.Choice{Title: "Certificate", Options: opts, Default: def, Arg: "--cert", Required: true,
		What: "issued ACM certificate in " + s.where() + " (request one with `polyctl aws acm certificate request`)"})
}

// askListenerPort asks for the port of a new listener, checked as typed
// (a port the load balancer listens on already is refused).
func askListenerPort(rt *app.Runtime, used []platform.LBListener, def string) (int, error) {
	v, err := rt.AskInput("--port", "Port the load balancer listens on", def, func(s string) error {
		p, err := strconv.Atoi(strings.TrimSpace(s))
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("a port from 1 to 65535 is required")
		}
		for _, l := range used {
			if l.Port == int32(p) {
				return fmt.Errorf("the load balancer has a listener on port %d already", p)
			}
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	p, _ := strconv.Atoi(v)
	return p, nil
}

// askPort asks for a port, checked as typed.
func askPort(rt *app.Runtime, arg, title, def string) (int, error) {
	v, err := rt.AskInput(arg, title, def, func(s string) error {
		if p, err := strconv.Atoi(strings.TrimSpace(s)); err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("a port from 1 to 65535 is required")
		}
		return nil
	})
	if err != nil {
		return 0, err
	}
	p, _ := strconv.Atoi(v)
	return p, nil
}

// chooseOne asks for one of values (an enum of a flag) in the interactive
// flow, def preselected.
func chooseOne(rt *app.Runtime, title, arg string, values []string, def string) (string, error) {
	var opts []prompt.Option
	for _, v := range values {
		opts = append(opts, prompt.Option{Label: v, Value: v})
	}
	return rt.Choose(app.Choice{Title: title, Options: opts, Default: def, Arg: arg, Required: true})
}

// askELBName asks for the name of a new load balancer or target group,
// checked as typed (the ELB name rules, and not taken in the scope).
func askELBName(ctx context.Context, rt *app.Runtime, s *lbScope, kind string, lb bool) (string, error) {
	return rt.AskInput("<name>", "Name of the new "+kind, "", func(v string) error {
		v = strings.TrimSpace(v)
		if err := checkELBName(kind, v, lb); err != nil {
			return inline(err)
		}
		if lb {
			if found, err := s.c.FindLoadBalancer(ctx, s.region, v); err != nil {
				return err
			} else if found != nil {
				return fmt.Errorf("load balancer %q already exists in %s", v, s.where())
			}
			return nil
		}
		if found, err := s.c.FindTargetGroup(ctx, s.region, v); err != nil {
			return err
		} else if found != nil {
			return fmt.Errorf("target group %q already exists in %s", v, s.where())
		}
		return nil
	})
}

// pickLBSubnets asks for the subnets of a new load balancer in the
// interactive flow: the available subnets of vpc (multiple choice), at
// most one per availability zone, checked when the choice is made.
func pickLBSubnets(ctx context.Context, rt *app.Runtime, s *lbScope, vpc string) ([]string, error) {
	subnets, err := s.c.availableSubnets(ctx, s.region, vpc, "")
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	zoneOf := map[string]string{}
	for _, sn := range subnets {
		id := awssdk.ToString(sn.SubnetId)
		zoneOf[id] = awssdk.ToString(sn.AvailabilityZone)
		opts = append(opts, prompt.Option{Label: subnetLabel(sn), Value: id})
	}
	for {
		picked, err := rt.ChooseMany(app.Choice{Title: "Subnets of the load balancer (one per availability zone)", Options: opts, Arg: "--subnet",
			Required: true, What: "available subnet of " + vpc})
		if err != nil {
			return nil, err
		}
		seen := map[string]string{}
		clash := ""
		for _, id := range picked {
			if other, ok := seen[zoneOf[id]]; ok {
				clash = fmt.Sprintf("%s and %s are both in %s", other, id, zoneOf[id])
				break
			}
			seen[zoneOf[id]] = id
		}
		if clash == "" {
			return picked, nil
		}
		rt.Infof("one subnet per availability zone: %s; choose again", clash)
	}
}

// askLBCreate asks what load-balancer create misses in the interactive
// flow: the name (checked as typed), the type (network preselected), the
// VPC (defaults.aws.vpc_id without asking when set) and its subnets, one
// per availability zone, and then, when the subnets were asked, the
// security groups of that VPC (none is allowed, but a Network Load
// Balancer created without any can never get one).
func askLBCreate(ctx context.Context, rt *app.Runtime, s *lbScope, name, typ *string, subnets, sgs *[]string, sgGiven bool) error {
	var err error
	if *name == "" {
		if *name, err = askELBName(ctx, rt, s, "load balancer", true); err != nil {
			return err
		}
	}
	if *typ == "" {
		if *typ, err = chooseOne(rt, "Type of the load balancer", "--type", lbTypes, "network"); err != nil {
			return err
		}
	}
	if len(*subnets) > 0 {
		return nil
	}
	vpc, err := rt.Setting(s.profile, platform.AWS, "vpc_id", "")
	if err != nil {
		return err
	}
	if vpc == "" {
		if vpc, err = pickVPC(ctx, rt, s.c, s.region, nil); err != nil {
			return err
		}
	}
	if *subnets, err = pickLBSubnets(ctx, rt, s, vpc); err != nil {
		return err
	}
	if sgGiven {
		return nil
	}
	opts, err := sgOptions(ctx, &sgScope{c: s.c, profile: s.profile, region: s.region}, vpc, nil)
	if err != nil || len(opts) == 0 {
		return err
	}
	title := "Security groups of the load balancer (none is allowed)"
	if *typ == "network" {
		title = "Security groups of the load balancer (a Network Load Balancer created without any can never get one)"
	}
	picked, err := rt.Pick().MultiSelect(title, opts)
	if err != nil {
		return err
	}
	*sgs = picked
	return nil
}

// lbUpdateAnswers are the flags askLBUpdate fills in.
type lbUpdateAnswers struct {
	sgs, subnets                  *[]string
	ipType                        *string
	deletionProtection, crossZone *bool
}

func onOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// askLBUpdate asks what load-balancer update changes in the interactive
// flow and its new value: deletion protection or cross-zone (on/off, the
// opposite of the current setting preselected), the IP address type, the
// security groups (not for a Network Load Balancer created without any) or
// the subnets (of the load balancer's VPC). It returns the flag answered.
func askLBUpdate(ctx context.Context, rt *app.Runtime, s *lbScope, lb *platform.LoadBalancer, u lbUpdateAnswers) (string, error) {
	attrs, err := s.c.LoadBalancerAttributes(ctx, s.region, lb.ID)
	if err != nil {
		return "", err
	}
	opts := []prompt.Option{
		{Label: "Deletion protection (now " + onOff(attrs.DeletionProtection) + ")", Value: "deletion-protection"},
		{Label: "Cross-zone load balancing (now " + onOff(attrs.CrossZone) + ")", Value: "cross-zone"},
		{Label: "IP address type (now " + lb.IPAddressType + ")", Value: "ip-address-type"},
	}
	if lb.Type != "network" || len(lb.SecurityGroups) > 0 {
		opts = append(opts, prompt.Option{Label: "Security groups (now " + joinOrNone(lb.SecurityGroups) + ")", Value: "sg"})
	}
	opts = append(opts, prompt.Option{Label: "Subnets (now " + joinOrNone(lb.Subnets()) + ")", Value: "subnet"})
	key, err := rt.Pick().Select("What to change on "+lb.Name, opts, "")
	if err != nil {
		return "", err
	}
	toggle := func(cur bool, dst *bool, what string) error {
		v, err := chooseOne(rt, what+" of "+lb.Name, "--"+key, []string{"on", "off"}, onOff(!cur))
		*dst = v == "on"
		return err
	}
	switch key {
	case "deletion-protection":
		err = toggle(attrs.DeletionProtection, u.deletionProtection, "Deletion protection")
	case "cross-zone":
		err = toggle(attrs.CrossZone, u.crossZone, "Cross-zone load balancing")
	case "ip-address-type":
		def := "dualstack"
		if lb.IPAddressType == "dualstack" {
			def = "ipv4"
		}
		*u.ipType, err = chooseOne(rt, "IP address type of "+lb.Name, "--ip-address-type", lbIPAddressTypes, def)
	case "sg":
		var opts []prompt.Option
		if opts, err = sgOptions(ctx, &sgScope{c: s.c, profile: s.profile, region: s.region}, lb.VPC, nil); err == nil {
			*u.sgs, err = rt.ChooseMany(app.Choice{Title: "Security groups of " + lb.Name + " (the list replaces the current one)", Options: opts, Arg: "--sg",
				What: "security group of " + lb.VPC})
		}
	case "subnet":
		*u.subnets, err = pickLBSubnets(ctx, rt, s, lb.VPC)
	}
	return key, err
}

// askTargets asks what target-group update changes in the interactive
// flow: "Register targets..." (multiple choice among the running instances
// of the group's VPC not registered yet; their private addresses for an ip
// group) or "Deregister targets..." (among the registered ones). It
// returns the --add-target and --remove-target values.
func askTargets(ctx context.Context, rt *app.Runtime, s *lbScope, tg *platform.LBTargetGroup) (add, remove []string, err error) {
	current, err := s.c.TargetHealth(ctx, s.region, tg.ID)
	if err != nil {
		return nil, nil, err
	}
	opts := []prompt.Option{{Label: "Register targets...", Value: "add"}}
	if len(current) > 0 {
		opts = append(opts, prompt.Option{Label: fmt.Sprintf("Deregister targets (%d registered)...", len(current)), Value: "remove"})
	}
	action, err := rt.Pick().Select("What to change on "+tg.Name, opts, "")
	if err != nil {
		return nil, nil, err
	}
	if action == "remove" {
		var opts []prompt.Option
		for _, t := range current {
			spec := fmt.Sprintf("%s:%d", t.ID, t.Port)
			opts = append(opts, prompt.Option{Label: joinLabel(spec, t.Zone, t.State, t.Description), Value: spec})
		}
		remove, err = rt.ChooseMany(app.Choice{Title: "Targets to deregister from " + tg.Name, Options: opts, Arg: "--remove-target"})
		return nil, remove, err
	}
	insts, err := s.c.listInstancesFiltered(ctx, s.region, instanceFilters{States: []string{stateRunning}})
	if err != nil {
		return nil, nil, err
	}
	var cands []prompt.Option
	for _, in := range insts {
		if in.VpcID != tg.VPC {
			continue
		}
		id := in.ID
		if tg.TargetType == "ip" {
			id = in.PrivateIP
		}
		if id == "" || isRegistered(current, id, tg.Port) {
			continue
		}
		cands = append(cands, prompt.Option{Label: joinLabel(nameOr(in.Name, in.ID), in.ID, in.PrivateIP, in.AZ, in.Type), Value: id})
	}
	add, err = rt.ChooseMany(app.Choice{Title: "Targets to register in " + tg.Name, Options: cands, Arg: "--add-target",
		What: "running instance of " + tg.VPC + " that is not registered yet"})
	return add, nil, err
}

// askEnsureName asks for the <name> of load-balancer ensure in the
// interactive flow, the instance's name proposed, checked as typed: the
// names the templates make of it (naming.aws_elbv2_load_balancer and
// naming.aws_elbv2_target_group for every port) must be valid.
func askEnsureName(ctx context.Context, rt *app.Runtime, instance, region string, ports []int32) (string, error) {
	l, err := resolveInstance(ctx, rt, instance, region, false)
	if err != nil {
		return "", err
	}
	return rt.AskInput("<name>", "Main name (the load balancer and target groups are named after it)", instanceName(l.inst), func(v string) error {
		v = strings.TrimSpace(v)
		if v == "" {
			return fmt.Errorf("a name is required")
		}
		vars := map[string]string{"name": v, "region": l.region, "protocol": "tcp"}
		lbName, err := rt.ResourceName("aws_elbv2_load_balancer", "", vars)
		if err != nil {
			return err
		}
		if err := checkELBName("load balancer", lbName, true); err != nil {
			return inline(err)
		}
		for _, p := range ports {
			vars["port"] = strconv.Itoa(int(p))
			tgName, err := rt.ResourceName("aws_elbv2_target_group", "", vars)
			if err != nil {
				return err
			}
			if err := checkELBName("target group", tgName, false); err != nil {
				return inline(err)
			}
		}
		return nil
	})
}
