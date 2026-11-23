package platform

import (
	"fmt"
	"net/netip"
	"strconv"
	"strings"
)

// IngressRule is one inbound rule in the platform-neutral form every
// security group / firewall command parses with ParseIngressRule. The
// providers map it to their own shapes (AWS IpPermission, Alibaba Cloud
// PortRange "x/y", GCP allowed[]).
type IngressRule struct {
	// Protocol is tcp, udp, icmp or all.
	Protocol string `json:"protocol" yaml:"protocol"`
	// FromPort and ToPort are the port range; -1 for icmp and all.
	FromPort int `json:"from_port" yaml:"from_port"`
	ToPort   int `json:"to_port" yaml:"to_port"`
	// Source is a masked CIDR (single addresses get /32 or /128) or a
	// security group id.
	Source string `json:"source" yaml:"source"`
	// SourceKind is SourceIPv4, SourceIPv6 or SourceGroup.
	SourceKind  string `json:"source_kind" yaml:"source_kind"`
	Description string `json:"description,omitempty" yaml:"description,omitempty"`
}

// Kinds of IngressRule.Source.
const (
	SourceIPv4  = "ipv4"
	SourceIPv6  = "ipv6"
	SourceGroup = "sg"
)

// PortAliases are the port names a rule (and a listener) may use.
var PortAliases = map[string]int{
	"ssh": 22, "telnet": 23, "smtp": 25, "dns": 53, "http": 80, "pop3": 110,
	"imap": 143, "https": 443, "smb": 445, "mssql": 1433, "mysql": 3306, "rdp": 3389,
	"postgresql": 5432, "postgres": 5432, "redis": 6379,
	"elasticsearch": 9200, "elastic": 9200, "mongodb": 27017, "mongo": 27017,
}

// RuleFormat is the syntax of an ingress rule, for error messages.
const RuleFormat = "<protocol>:<port|from-to|alias|all>:<source>, e.g. tcp:443:0.0.0.0/0, tcp:8000-8999:10.0.0.0/8, tcp:ssh:203.0.113.7, icmp:all:::/0, all:all:sg-0123456789abcdef0"

// ParseIngressRule parses "<protocol>:<port|from-to|alias|all>:<source>".
//
// The protocol is tcp, udp, icmp or all. icmp takes only the port "all",
// the protocol all takes only "all", and tcp:all / udp:all mean every port
// (1-65535). The source is required: a firewall that gets no source may
// open the port to everybody (GCP turns a missing source into 0.0.0.0/0),
// so no rule is ever accepted without one. It is an IPv4 or IPv6 CIDR (a
// bare address gets /32 or /128, and host bits are masked, so 1.2.3.4 and
// 1.2.3.4/32 are the same rule) or a security group id (sg-...). IPv6
// sources contain colons: the source is everything after the second colon.
func ParseIngressRule(s string) (IngressRule, error) {
	bad := func(format string, args ...any) (IngressRule, error) {
		return IngressRule{}, invalid("rule %q: %s (format %s)", s, fmt.Sprintf(format, args...), RuleFormat)
	}
	parts := strings.SplitN(strings.TrimSpace(s), ":", 3)
	if len(parts) < 3 {
		return bad("expected three parts")
	}
	proto, port, source := strings.ToLower(strings.TrimSpace(parts[0])), strings.ToLower(strings.TrimSpace(parts[1])), strings.TrimSpace(parts[2])
	r := IngressRule{Protocol: proto}
	switch proto {
	case "tcp", "udp":
		switch {
		case port == "all":
			r.FromPort, r.ToPort = 1, 65535
		case strings.Contains(port, "-"):
			from, to, _ := strings.Cut(port, "-")
			f, err := parsePort(from)
			if err != nil {
				return bad("%v", err)
			}
			t, err := parsePort(to)
			if err != nil {
				return bad("%v", err)
			}
			if f > t {
				return bad("port range %d-%d is reversed", f, t)
			}
			r.FromPort, r.ToPort = f, t
		default:
			p, err := parsePort(port)
			if err != nil {
				return bad("%v", err)
			}
			r.FromPort, r.ToPort = p, p
		}
	case "icmp":
		if port != "all" {
			return bad("icmp takes no port: write icmp:all:<source>")
		}
		r.FromPort, r.ToPort = -1, -1
	case "all":
		if port != "all" {
			return bad("the protocol all covers every port: write all:all:<source>")
		}
		r.FromPort, r.ToPort = -1, -1
	default:
		return bad("unknown protocol %q (expected tcp, udp, icmp or all)", proto)
	}
	src, kind, err := parseRuleSource(source)
	if err != nil {
		return bad("%v", err)
	}
	r.Source, r.SourceKind = src, kind
	return r, nil
}

// parsePort reads a port number or alias (1-65535).
func parsePort(s string) (int, error) {
	s = strings.TrimSpace(s)
	if p, ok := PortAliases[s]; ok {
		return p, nil
	}
	p, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("unknown port or alias %q", s)
	}
	if p < 1 || p > 65535 {
		return 0, fmt.Errorf("port %d is out of range 1-65535", p)
	}
	return p, nil
}

// ParseRuleSource normalizes the source of a rule: a masked CIDR (a bare
// address gets /32 or /128) or a security group id. It parses with
// net/netip; it never guesses from whether the text holds a slash. Its
// errors map to the usage exit code.
func ParseRuleSource(s string) (source, kind string, err error) {
	source, kind, err = parseRuleSource(s)
	if err != nil {
		return "", "", invalid("%v", err)
	}
	return source, kind, nil
}

func parseRuleSource(s string) (source, kind string, err error) {
	s = strings.TrimSpace(s)
	switch {
	case s == "":
		return "", "", fmt.Errorf("a source is required (a CIDR, an address or a security group id); use 0.0.0.0/0 to allow everybody")
	case strings.HasPrefix(s, "sg-"):
		if len(s) == 3 {
			return "", "", fmt.Errorf("security group id %q is incomplete", s)
		}
		return s, SourceGroup, nil
	}
	if p, err := netip.ParsePrefix(s); err == nil {
		p = p.Masked()
		if p.Addr().Is4() {
			return p.String(), SourceIPv4, nil
		}
		return p.String(), SourceIPv6, nil
	}
	if a, err := netip.ParseAddr(s); err == nil {
		a = a.WithZone("")
		if a.Is4() {
			return netip.PrefixFrom(a, 32).String(), SourceIPv4, nil
		}
		return netip.PrefixFrom(a, 128).String(), SourceIPv6, nil
	}
	return "", "", fmt.Errorf("source %q is not a CIDR, an address or a security group id (sg-...)", s)
}

// Ports renders the port part ("443", "8000-8999", "all").
func (r IngressRule) Ports() string {
	switch {
	case r.FromPort < 0:
		return "all"
	case r.FromPort == r.ToPort:
		return strconv.Itoa(r.FromPort)
	}
	return fmt.Sprintf("%d-%d", r.FromPort, r.ToPort)
}

// String renders the rule as a change report shows it ("tcp 443 0.0.0.0/0").
func (r IngressRule) String() string { return r.Protocol + " " + r.Ports() + " " + r.Source }

// Key identifies the rule for comparisons: protocol, ports and source.
// The description is deliberately left out: platforms do not compare it
// either (AWS reports a rule that differs only in its description as a
// duplicate).
func (r IngressRule) Key() string {
	return fmt.Sprintf("%s|%d|%d|%s", r.Protocol, r.FromPort, r.ToPort, r.Source)
}

// ParseIngressRules parses every rule and drops repeated ones (by Key),
// keeping the first.
func ParseIngressRules(specs []string) ([]IngressRule, error) {
	seen := map[string]bool{}
	var out []IngressRule
	for _, s := range specs {
		r, err := ParseIngressRule(s)
		if err != nil {
			return nil, err
		}
		if !seen[r.Key()] {
			seen[r.Key()] = true
			out = append(out, r)
		}
	}
	return out, nil
}

// MissingRules returns the rules of want that have no equal (by Key) in
// have: what an ensure has to add.
func MissingRules(have, want []IngressRule) []IngressRule {
	set := map[string]bool{}
	for _, r := range have {
		set[r.Key()] = true
	}
	var out []IngressRule
	for _, r := range want {
		if !set[r.Key()] {
			out = append(out, r)
		}
	}
	return out
}

// Listener is a load balancer listener: "<protocol>:<port>".
type Listener struct {
	Protocol string `json:"protocol" yaml:"protocol"`
	Port     int    `json:"port" yaml:"port"`
}

// ListenerProtocols are the protocols a listener may name.
var ListenerProtocols = []string{"tcp", "udp", "tcp_udp", "tls", "http", "https"}

// ParseListener parses "<protocol>:<port>" (tcp:80, https:443). The
// protocol is case-insensitive and stored in lower case; the port may be
// an alias.
func ParseListener(s string) (Listener, error) {
	proto, port, ok := strings.Cut(strings.TrimSpace(s), ":")
	proto = strings.ToLower(strings.TrimSpace(proto))
	if !ok || proto == "" || strings.TrimSpace(port) == "" {
		return Listener{}, invalid("listener %q: expected <protocol>:<port>, e.g. tcp:80 or https:443", s)
	}
	valid := false
	for _, p := range ListenerProtocols {
		valid = valid || p == proto
	}
	if !valid {
		return Listener{}, invalid("listener %q: unknown protocol %q (expected one of %s)", s, proto, strings.Join(ListenerProtocols, ", "))
	}
	p, err := parsePort(strings.ToLower(port))
	if err != nil {
		return Listener{}, invalid("listener %q: %v", s, err)
	}
	return Listener{Protocol: proto, Port: p}, nil
}

// String renders "tcp:80".
func (l Listener) String() string { return l.Protocol + ":" + strconv.Itoa(l.Port) }
