package aliyun

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/app"
)

// The labels of the interactive picks of the aliyun commands: what a
// resource is (name, id) and the facts that tell candidates apart (zone,
// CIDR, status, VPC). Empty facts are left out.

func joinLabel(parts ...string) string {
	var out []string
	for _, p := range parts {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return strings.Join(out, "  ")
}

// nameOr returns name, else id.
func nameOr(name, id string) string {
	if name != "" {
		return name
	}
	return id
}

// vpcLabel: "cn-shanghai-vpc  vpc-1  172.16.0.0/12  Available  [default]".
func vpcLabel(v vpcInfo) string {
	def := ""
	if v.IsDefault {
		def = "[default]"
	}
	return joinLabel(nameOr(v.Name, v.ID), v.ID, v.CIDR, v.Status, def)
}

// sgLabel: "sg-common  sg-1  vpc-1  description".
func sgLabel(g securityGroup) string {
	return joinLabel(nameOr(g.Name, g.ID), g.ID, g.VPC, g.Description)
}

// vswLabel: "cn-shanghai-switch-b  vsw-1  cn-shanghai-b  172.16.0.0/22
// vpc-name  N free IPs"; vpcNames, when given, names the VPC.
func vswLabel(v vSwitch, vpcNames map[string]string) string {
	vpc := v.VPC
	if n := vpcNames[v.VPC]; n != "" && n != v.VPC {
		vpc = n + " (" + v.VPC + ")"
	}
	free := ""
	if v.AvailableIPs > 0 {
		free = itoa64(v.AvailableIPs) + " free IPs"
	}
	return joinLabel(nameOr(v.Name, v.ID), v.ID, v.Zone, v.CIDR, vpc, free)
}

// instanceOptionLabel: "site-a  i-1  cn-shanghai-b  Running  ecs.u1  203.0.113.9".
func instanceOptionLabel(in Instance) string {
	ip := in.PublicIP
	if ip == "" {
		ip = in.EIP
	}
	return joinLabel(nameOr(in.Name, in.ID), in.ID, in.Zone, in.Status, in.Type, ip)
}

// lbOptionLabel: "web  alb-1  Active  dns-name".
func lbOptionLabel(l albRef) string {
	return joinLabel(nameOr(l.Name, l.ID), l.ID, l.Status, l.VpcID, l.DNSName)
}

// serverGroupLabel: "web  sgp-1  HTTP  vpc-1  2 servers".
func serverGroupLabel(g albServerGroup) string {
	return joinLabel(nameOr(g.Name, g.ID), g.ID, g.Protocol, g.VpcID, itoa64(int64(g.ServerCount))+" servers")
}

// aclLabel: "office  acl-1  Available".
func aclLabel(x albACL) string {
	return joinLabel(nameOr(x.Name, x.ID), x.ID, x.Status)
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }

// narrowVPCs turns several VPCs of the name into the one the user picks in
// the interactive flow; otherwise several are ambiguous (exit code 5) with
// hint. None or one is returned as it is.
func narrowVPCs(s *ecsScope, name string, vpcs []vpcInfo, hint string) ([]vpcInfo, error) {
	if len(vpcs) < 2 {
		return vpcs, nil
	}
	var ids []string
	for _, v := range vpcs {
		ids = append(ids, v.ID)
	}
	amb := &app.AmbiguousError{What: fmt.Sprintf("VPC %q in %s", name, s.where()), Candidates: ids, Hint: hint}
	v, err := pickAmong(s, amb, vpcs, func(v vpcInfo) string { return v.ID }, vpcLabel)
	if err != nil {
		return nil, err
	}
	return []vpcInfo{*v}, nil
}
