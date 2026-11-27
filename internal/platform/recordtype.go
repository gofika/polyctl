package platform

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"golang.org/x/net/idna"
)

// The record types polyctl knows: every standard type that at least one of
// the platforms writes through its API. A record is checked here before it
// reaches a platform (CheckRecord): its type must be one of these, and one
// the platform writes, and its value must be valid for the type. Nothing is
// handed to a platform to sort out.

// RecordTypeInfo describes a record type: the form of its value in zone-file
// form and an example of one.
type RecordTypeInfo struct {
	Type    string
	Form    string
	Example string
	// Priority says where the priority of the type goes: "separate" (MX: in
	// front of the value or apart, --priority), "value" (a field of the
	// value: SRV, HTTPS, SVCB, URI, NAPTR), "" (none).
	Priority string
}

type recordType struct {
	RecordTypeInfo
	// priorityNote says, for a type whose priority is a field of the value,
	// which field it is.
	priorityNote string
	check        func(v string) (string, *int, error)
}

// recordTypes are the known types, in the order they are listed.
var recordTypes = []recordType{
	{RecordTypeInfo{"A", "<IPv4 address>", "203.0.113.10", ""}, "", checkA},
	{RecordTypeInfo{"AAAA", "<IPv6 address>", "2001:db8::10", ""}, "", checkAAAA},
	{RecordTypeInfo{"CNAME", "<host>", "target.example.net", ""}, "", checkHost},
	{RecordTypeInfo{"ALIAS", "<host>", "target.example.net", ""}, "", checkHost},
	{RecordTypeInfo{"ANAME", "<host>", "target.example.net", ""}, "", checkHost},
	{RecordTypeInfo{"MX", "[<priority>] <host>", "10 mail.example.com", "separate"}, "", checkMX},
	{RecordTypeInfo{"NS", "<host>", "ns1.example.net", ""}, "", checkHost},
	{RecordTypeInfo{"TXT", "<text> | \"<string>\" [\"<string>\"...]", `"v=spf1 include:_spf.example.net ~all"`, ""}, "", checkTXT},
	{RecordTypeInfo{"SPF", "<text> | \"<string>\" [\"<string>\"...]", `"v=spf1 -all"`, ""}, "", checkTXT},
	{RecordTypeInfo{"SRV", "<priority> <weight> <port> <target>", "10 5 5060 sip.example.com", "value"}, "the first field of the value", checkSRV},
	{RecordTypeInfo{"CAA", "<flags> <tag> \"<value>\"", `0 issue "letsencrypt.org"`, ""}, "", checkCAA},
	{RecordTypeInfo{"PTR", "<host>", "host.example.com", ""}, "", checkHost},
	{RecordTypeInfo{"NAPTR", "<order> <preference> \"<flags>\" \"<service>\" \"<regexp>\" <replacement>", `100 10 "S" "SIP+D2U" "" _sip._udp.example.com`, "value"}, "the order and preference, the first two fields of the value", checkNAPTR},
	{RecordTypeInfo{"HTTPS", "<priority> <target> [<key>=<value>...]", `1 . alpn="h3,h2"`, "value"}, "the first field of the value (0 is alias mode)", checkSVCB},
	{RecordTypeInfo{"SVCB", "<priority> <target> [<key>=<value>...]", "1 svc.example.net port=8443", "value"}, "the first field of the value (0 is alias mode)", checkSVCB},
	{RecordTypeInfo{"TLSA", "<usage> <selector> <matching-type> <hex data>", "3 1 1 " + strings.Repeat("ab", 32), ""}, "", checkTLSA},
	{RecordTypeInfo{"SMIMEA", "<usage> <selector> <matching-type> <hex data>", "3 1 1 " + strings.Repeat("ab", 32), ""}, "", checkTLSA},
	{RecordTypeInfo{"SSHFP", "<algorithm> <fingerprint-type> <hex fingerprint>", "4 2 " + strings.Repeat("cd", 32), ""}, "", checkSSHFP},
	{RecordTypeInfo{"DS", "<key-tag> <algorithm> <digest-type> <hex digest>", "12345 13 2 " + strings.Repeat("ef", 32), ""}, "", checkDS},
	{RecordTypeInfo{"DNSKEY", "<flags> <protocol 3> <algorithm> <base64 key>", "257 3 13 mdsswUyr3DPW132mOi8V9xESWE8jTo0dxCjjnopKl+GqJxpVXckHAeF+KkxLbxILfDLUT0rAK9iUzy1L53eKGQ==", ""}, "", checkDNSKEY},
	{RecordTypeInfo{"CERT", "<type> <key-tag> <algorithm> <base64 certificate>", "PKIX 0 0 MIIBszCCAVmgAwIBAgIU", ""}, "", checkCERT},
	{RecordTypeInfo{"URI", "<priority> <weight> \"<target URI>\"", `10 1 "https://www.example.com/"`, "value"}, "the first field of the value", checkURI},
	{RecordTypeInfo{"LOC", "<d> [<m> [<s>]] N|S <d> [<m> [<s>]] E|W <altitude>[m] [<size>[m] [<hp>[m] [<vp>[m]]]]", "52 22 23.000 N 4 53 32.000 E -2.00m", ""}, "", checkLOC},
	{RecordTypeInfo{"OPENPGPKEY", "<base64 key>", "mDMEXEcE6RYJKwYBBAHaRw8BAQdA", ""}, "", checkBase64Value},
	{RecordTypeInfo{"IPSECKEY", "<precedence> <gateway-type> <algorithm> <gateway> [<base64 key>]", "10 1 2 192.0.2.38 AQNRU3mG7TVTO2BkR47usntb102uFJtugbo6BSGvgqt4AQ==", ""}, "", checkIPSECKEY},
}

// KnownRecordTypes are the record types polyctl knows, in the order they are
// listed. Which of them a platform writes is for its provider to say
// (WritableRecordTypes).
var KnownRecordTypes = func() []string {
	out := make([]string, len(recordTypes))
	for i, t := range recordTypes {
		out[i] = t.Type
	}
	return out
}()

func lookupRecordType(typ string) (recordType, bool) {
	for _, t := range recordTypes {
		if t.Type == typ {
			return t, true
		}
	}
	return recordType{}, false
}

// RecordType returns what polyctl knows about the record type typ (upper
// case), and whether it knows it.
func RecordType(typ string) (RecordTypeInfo, bool) {
	t, ok := lookupRecordType(strings.ToUpper(strings.TrimSpace(typ)))
	return t.RecordTypeInfo, ok
}

// pseudoTypes are platform features that look like record types: URL
// forwarding (Alibaba Cloud, name.com, GoDaddy), redirects (Cloudflare).
// They are not DNS records and stay with the platform's own tools.
var pseudoTypes = []string{"URL", "URL301", "URL302", "FORWARD", "FORWARD_URL", "FORWORD_URL", "REDIRECT", "REDIRECT_URL", "FRAME"}

// RecordValue is a record value checked by CheckRecord: the type, the
// value in its normal form, and the priority of an MX record.
type RecordValue struct {
	Type string
	// Value is the normal form of the value: an address in its canonical
	// form, a host name in lower case without its trailing dot (punycode for
	// an internationalized name), numbers without leading zeros, hex in
	// lower case, the quoted fields of CAA, NAPTR and URI quoted. An MX value
	// is its host alone.
	Value string
	// Priority is the priority of an MX record, nil when it has none.
	Priority *int
}

// ZoneValue is the value in zone-file form: an MX value with its priority in
// front.
func (v RecordValue) ZoneValue() string {
	if v.Type == "MX" && v.Priority != nil {
		return strconv.Itoa(*v.Priority) + " " + v.Value
	}
	return v.Value
}

// RecordCheck is a record a command is about to write, as it was given.
type RecordCheck struct {
	// Platform is the platform the record is written to; "" when it is not
	// known yet: every known type is then accepted.
	Platform ID
	// Types are the types the platform writes; nil: those its provider
	// says (WritableRecordTypes).
	Types []string
	Type  string
	Value string
	// Priority is the priority given apart from the value (--priority, the
	// priority of a records file); nil when none was.
	Priority *int
	// New says the record is created: an MX record then needs a priority.
	New bool
	// Proxied is the proxied setting given (--proxied), nil when none was:
	// true belongs to a type that can be proxied (CheckProxied).
	Proxied *bool
}

// CheckRecord is the check every command that writes a record runs before
// any request: the type is known (exit code 2, listing the known types),
// one the platform writes (ErrNotSupported, exit code 7, naming the types it
// writes), a proxied setting and a separate priority belong to it, and the
// value is valid for it (exit code 2, saying what is wrong and showing a
// valid value). It returns the value in the normal form the providers take.
func CheckRecord(c RecordCheck) (RecordValue, error) {
	typ := strings.ToUpper(strings.TrimSpace(c.Type))
	if err := checkRecordType(c.Platform, c.Types, typ); err != nil {
		return RecordValue{}, err
	}
	if err := CheckProxied(typ, c.Proxied); err != nil {
		return RecordValue{}, err
	}
	v, err := checkValue(typ, c.Value, c.Priority)
	if err != nil {
		return RecordValue{}, invalid("%v", err)
	}
	if err := checkPlatformValue(c.Platform, typ, v.Value); err != nil {
		return RecordValue{}, invalid("%v", err)
	}
	if c.New && typ == "MX" && v.Priority == nil {
		return RecordValue{}, invalid(`an MX record needs a priority: write the value as "10 mail.example.com", or give the priority apart`)
	}
	return v, nil
}

// CheckRecordType is the part of CheckRecord that needs no value, for a
// type known before its value is asked: the type is known (exit code 2), one
// the platform writes (ErrNotSupported, exit code 7; Platform "": any known
// type), and a proxied setting and a priority given apart belong to it
// (exit code 2). c.Value and c.New are not read.
func CheckRecordType(c RecordCheck) error {
	typ := strings.ToUpper(strings.TrimSpace(c.Type))
	if err := checkRecordType(c.Platform, c.Types, typ); err != nil {
		return err
	}
	if err := CheckProxied(typ, c.Proxied); err != nil {
		return err
	}
	t, _ := lookupRecordType(typ)
	if err := checkPriority(t, c.Priority); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// checkRecordType checks typ (upper case) as CheckRecordType does; types
// are those p writes, nil: those its provider says.
func checkRecordType(p ID, types []string, typ string) error {
	if err := checkType(typ); err != nil {
		return invalid("%v", err)
	}
	if types == nil && p != "" {
		types = WritableRecordTypes(p)
	}
	if types != nil && !slices.Contains(types, typ) {
		return notWritable(p, typ, types)
	}
	return nil
}

// notWritable is the error of a known type that platform p does not write.
func notWritable(p ID, typ string, types []string) error {
	who := string(p)
	if who == "" {
		who = "the platform"
	}
	hint := ""
	switch {
	case typ == "SPF":
		hint = "; write the SPF policy as a TXT record"
	case p == NameCom && typ == "ALIAS":
		hint = "; name.com calls this type ANAME"
	case (p == GCP || p == Aliyun) && typ == "ANAME":
		hint = "; " + who + " calls this type ALIAS"
	case p == Cloudflare && (typ == "ALIAS" || typ == "ANAME"):
		hint = "; write a CNAME: Cloudflare flattens a CNAME at the zone apex"
	case p == AWS && (typ == "ALIAS" || typ == "ANAME"):
		hint = "; a Route 53 alias is an A or AAAA record set with an alias target, set up in the AWS console or CLI"
	}
	return fmt.Errorf("%w: %s cannot write %s records (it writes %s)%s", ErrNotSupported, who, typ, strings.Join(types, " "), hint)
}

// checkType checks that typ (upper case) is a type a record can be written
// with.
func checkType(typ string) error {
	switch {
	case typ == "":
		return errors.New("the type is empty")
	case typ == "SOA":
		return errors.New("SOA records are managed by the platform and cannot be set")
	case slices.Contains(pseudoTypes, typ):
		return fmt.Errorf("%s is URL forwarding, not a DNS record type: it is set up with the platform's own tools (on Cloudflare `polyctl cloudflare redirect rule set`), not with a record command", typ)
	}
	if _, ok := lookupRecordType(typ); !ok {
		return fmt.Errorf("unknown record type %q (known types: %s)", typ, strings.Join(KnownRecordTypes, " "))
	}
	return nil
}

// checkValue checks v as the value of a record of the known type typ, with
// the priority given apart (nil: none), and returns its normal form.
func checkValue(typ, v string, priority *int) (RecordValue, error) {
	t, ok := lookupRecordType(typ)
	if !ok {
		return RecordValue{}, checkType(typ)
	}
	if err := checkPriority(t, priority); err != nil {
		return RecordValue{}, err
	}
	v = strings.TrimSpace(v)
	if v == "" {
		return RecordValue{}, errors.New("the value is empty")
	}
	norm, prio, err := t.check(v)
	if err != nil {
		return RecordValue{}, fmt.Errorf("value %q is not valid for type %s: %v (form %s, e.g. %s)", v, typ, err, t.Form, t.Example)
	}
	if prio != nil && priority != nil && *prio != *priority {
		return RecordValue{}, fmt.Errorf("the priority is given twice (%d in the value, %d as priority)", *prio, *priority)
	}
	if prio == nil {
		prio = priority
	}
	return RecordValue{Type: typ, Value: norm, Priority: prio}, nil
}

// checkPriority checks a priority given apart (nil: none) for a record of
// the known type t.
func checkPriority(t recordType, priority *int) error {
	if priority == nil {
		return nil
	}
	switch t.Priority {
	case "value":
		return fmt.Errorf("a separate priority does not apply to %s records: the priority is %s, %s (e.g. %s)", t.Type, t.priorityNote, t.Form, t.Example)
	case "":
		return fmt.Errorf("a priority applies to MX records only, not to %s records", t.Type)
	}
	if *priority < 0 || *priority > 65535 {
		return fmt.Errorf("priority %d is not between 0 and 65535", *priority)
	}
	return nil
}

// RecordFields returns the fields of a value of type typ in its normal
// form, unquoted: what a provider maps onto the fields of its API (the
// priority, weight, port and target of an SRV value, ...). The value is
// checked first.
func RecordFields(typ, value string) ([]string, error) {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	v, err := checkValue(typ, value, nil)
	if err != nil {
		return nil, invalid("%v", err)
	}
	if typ == "TXT" || typ == "SPF" {
		return []string{JoinTXT(v.Value)}, nil
	}
	fs, err := zoneFields(v.Value)
	if err != nil {
		return nil, invalid("%v", err)
	}
	out := make([]string, len(fs))
	for i, f := range fs {
		out[i] = f.text
	}
	if typ == "MX" && v.Priority != nil {
		out = append([]string{strconv.Itoa(*v.Priority)}, out...)
	}
	return out, nil
}

// RecordTypesConflict reports whether records of the types a and b cannot
// share a name on platform p; apex says the name is the zone apex. A CNAME
// stands alone (Cloudflare lets one sit beside records other than A, AAAA
// and NS); NS below the apex delegates the name, which Cloudflare and
// Alibaba Cloud then let hold nothing else but DS (the NS records of the
// apex are the zone's own and sit beside anything but a CNAME); an ALIAS or
// ANAME answers for A and AAAA. Two CNAMEs of one name are not a type
// conflict but one too many, which the callers report themselves.
func RecordTypesConflict(p ID, apex bool, a, b string) bool {
	a, b = strings.ToUpper(a), strings.ToUpper(b)
	conflict := func(x, y string) bool {
		switch x {
		case "CNAME":
			if y == "CNAME" {
				return false
			}
			if p == Cloudflare {
				return y == "A" || y == "AAAA" || y == "NS"
			}
			return true
		case "NS":
			if (p == Cloudflare || p == Aliyun) && !apex {
				return y != "NS" && y != "DS"
			}
			return y == "CNAME"
		case "ALIAS", "ANAME":
			return y == "A" || y == "AAAA" || y == "CNAME"
		}
		return false
	}
	return conflict(a, b) || conflict(b, a)
}

// zoneField is one field of a value in zone-file form: its text, unquoted
// and unescaped, whether any of it was quoted, and whether it was one quoted
// string as a whole.
type zoneField struct {
	text   string
	quoted bool
	whole  bool
}

func isSpace(c byte) bool { return c == ' ' || c == '\t' || c == '\n' || c == '\r' }

// zoneFields splits a value in zone-file form at white space outside quotes.
// A backslash escapes the next character, or gives a byte as three decimal
// digits.
func zoneFields(s string) ([]zoneField, error) {
	var out []zoneField
	i := 0
	for i < len(s) {
		if isSpace(s[i]) {
			i++
			continue
		}
		var b strings.Builder
		in, quotes, start := false, 0, i
		for ; i < len(s); i++ {
			c := s[i]
			if !in && isSpace(c) {
				break
			}
			switch {
			case c == '"':
				in = !in
				quotes++
			case c == '\\' && i+3 < len(s) && isDigits(s[i+1:i+4]):
				n, _ := strconv.Atoi(s[i+1 : i+4])
				if n > 255 {
					return nil, fmt.Errorf("the escape \\%s is not a byte", s[i+1:i+4])
				}
				b.WriteByte(byte(n))
				i += 3
			case c == '\\' && i+1 < len(s):
				i++
				b.WriteByte(s[i])
			case c == '\\':
				return nil, errors.New("it ends in a backslash")
			default:
				b.WriteByte(c)
			}
		}
		if in {
			return nil, errors.New("a quote is not closed")
		}
		out = append(out, zoneField{text: b.String(), quoted: quotes > 0, whole: quotes == 2 && s[start] == '"' && s[i-1] == '"'})
	}
	return out, nil
}

// quoteZone quotes s for a value in zone-file form.
func quoteZone(s string) string {
	return `"` + strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s) + `"`
}

// numField reads a decimal number of at most max.
func numField(name, s string, max int) (int, error) {
	n, err := strconv.Atoi(s)
	if err != nil || n < 0 || strings.HasPrefix(s, "+") {
		return 0, fmt.Errorf("the %s %q is not a number", name, s)
	}
	if n > max {
		return 0, fmt.Errorf("the %s %d is over %d", name, n, max)
	}
	return n, nil
}

// hostIDNA turns an internationalized host name into punycode as name
// lookup does (UTS 46 mapping), without the STD3 rules: a label may hold
// "_" (_acme-challenge.bücher.example), as the same name in ASCII may.
// checkHostName checks the result.
var hostIDNA = idna.New(idna.MapForLookup(), idna.BidiRule(), idna.StrictDomainName(false))

// normalHost checks a host name in a value and returns it in lower case
// without its trailing dot, an internationalized name in punycode. root
// allows "." (no target).
func normalHost(name, h string, root bool) (string, error) {
	if h == "." {
		if root {
			return h, nil
		}
		return "", fmt.Errorf("the %s cannot be the root (.)", name)
	}
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			a, err := hostIDNA.ToASCII(strings.TrimSuffix(h, "."))
			if err != nil {
				return "", fmt.Errorf("the %s %q is not a host name: %v", name, h, err)
			}
			h = a
			break
		}
	}
	if err := checkHostName(h, false); err != nil {
		return "", fmt.Errorf("the %s %q is not a host name: %v", name, h, err)
	}
	return strings.ToLower(strings.TrimSuffix(h, ".")), nil
}

func checkA(v string) (string, *int, error) {
	a, err := netip.ParseAddr(v)
	if err != nil || !a.Is4() {
		return "", nil, errors.New("it is not an IPv4 address")
	}
	return a.String(), nil, nil
}

// checkAAAA takes any IPv6 address, an IPv4-mapped one (::ffff:192.0.2.1)
// too: it is a 128-bit address like any other.
func checkAAAA(v string) (string, *int, error) {
	a, err := netip.ParseAddr(v)
	if err != nil || !a.Is6() || a.Zone() != "" {
		return "", nil, errors.New("it is not an IPv6 address")
	}
	return a.String(), nil, nil
}

// apexHost is the zone-file name of the zone apex as the target of a
// record: GoDaddy stores and lists it as it is (its default `www CNAME @`).
const apexHost = "@"

// targetHost is normalHost for the host a CNAME, ALIAS, ANAME, NS, PTR, MX
// or SRV record points to, which may also be apexHost (see apexTarget).
func targetHost(name, h string, root bool) (string, error) {
	if h == apexHost {
		return h, nil
	}
	return normalHost(name, h, root)
}

// apexTarget reports whether v, the normal form of a value of type typ,
// points to apexHost.
func apexTarget(typ, v string) bool {
	switch typ {
	case "CNAME", "ALIAS", "ANAME", "NS", "PTR", "MX":
		return v == apexHost
	case "SRV":
		f := strings.Fields(v)
		return len(f) == 4 && f[3] == apexHost
	}
	return false
}

// checkApexTarget refuses a value of type typ pointing to apexHost on a
// platform other than GoDaddy, the one platform that takes "@" for the
// apex; elsewhere the zone's name is written. An unknown platform ("")
// accepts it.
func checkApexTarget(p ID, typ, v string) error {
	if p == "" || p == GoDaddy || !apexTarget(typ, v) {
		return nil
	}
	return fmt.Errorf("value %q is not valid for type %s on %s: %q for the zone apex is GoDaddy's form; write the zone's name", v, typ, p, apexHost)
}

// checkPlatformValue refuses a value of type typ, in its normal form, that
// platform p does not take although it is valid for the type: "@" for the
// apex off GoDaddy (checkApexTarget), an SRV port of 0 on GoDaddy.
func checkPlatformValue(p ID, typ, v string) error {
	if err := checkApexTarget(p, typ, v); err != nil {
		return err
	}
	if f := strings.Fields(v); p == GoDaddy && typ == "SRV" && len(f) == 4 && f[2] == "0" {
		return fmt.Errorf("value %q is not valid for type SRV on %s: GoDaddy takes an SRV port from 1 to 65535, not 0", v, p)
	}
	return nil
}

// CheckRecordName checks fqdn, the name of a record of type typ in zone, as
// platform p takes it, before any request: no CNAME at the zone apex where
// the platform refuses one there (apexCNAME), and on GoDaddy, which keeps
// the service and protocol of an SRV record in fields of their own, an SRV
// name of the form _service._proto[.owner].
func CheckRecordName(p ID, zone, fqdn, typ string) error {
	if err := checkRecordName(p, NormalizeDomain(zone), NormalizeDomain(fqdn), strings.ToUpper(strings.TrimSpace(typ)), false); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// checkRecordName is CheckRecordName with zone and fqdn normalized and typ
// upper case; skipped says the record is not written (proxySkipped), so the
// apex does not refuse it.
func checkRecordName(p ID, zone, fqdn, typ string, skipped bool) error {
	if fqdn == zone && !skipped && typ == "CNAME" && !apexCNAME(p) {
		return apexCNAMEError(p)
	}
	if p != GoDaddy || typ != "SRV" {
		return nil
	}
	rel := RelativeName(fqdn, zone)
	l := strings.Split(rel, ".")
	if len(l) < 2 || len(l[0]) < 2 || len(l[1]) < 2 || l[0][0] != '_' || l[1][0] != '_' {
		return fmt.Errorf("name %q: an SRV record on GoDaddy needs a name of the form _service._proto[.owner] (e.g. _sip._tcp)", rel)
	}
	return nil
}

// CheckEnsureName checks the name and type of a record dns ensure writes in
// zone on platform p as NormalizeRecordSpecs does, for a command that knows
// them before it reads the zone or asks for the value: proxied only on the
// types it applies to (CheckProxied), no NS record at the zone apex
// (checkEnsureApex), and a name the platform takes for the type
// (CheckRecordName). proxied is the proxied setting asked for, nil when
// none was: a record asking for proxied=true off Cloudflare is reported as
// skipped and never written, so the apex does not refuse it.
func CheckEnsureName(p ID, zone, fqdn, typ string, proxied *bool) error {
	typ = strings.ToUpper(strings.TrimSpace(typ))
	if err := CheckProxied(typ, proxied); err != nil {
		return err
	}
	if err := checkEnsureName(p, NormalizeDomain(zone), NormalizeDomain(fqdn), typ, proxySkipped(p, typ, proxied)); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// checkEnsureName is CheckEnsureName with zone and fqdn normalized and typ
// upper case; skipped says the record is not written (proxySkipped).
func checkEnsureName(p ID, zone, fqdn, typ string, skipped bool) error {
	if fqdn == zone && !skipped {
		if err := checkEnsureApex(typ); err != nil {
			return err
		}
	}
	return checkRecordName(p, zone, fqdn, typ, skipped)
}

// CheckProxied refuses (exit code 2) proxied=true (nil: none given; false
// is what any record without the proxy holds) on a record of type typ that cannot be proxied
// (proxiableTypes): every command that writes a record with one checks it
// here, before any request.
func CheckProxied(typ string, proxied *bool) error {
	if err := checkProxied(strings.ToUpper(strings.TrimSpace(typ)), proxied); err != nil {
		return invalid("%v", err)
	}
	return nil
}

// checkProxied is CheckProxied with typ upper case, the error unwrapped.
func checkProxied(typ string, proxied *bool) error {
	// proxied=false on any type is what the platform holds for a record
	// without the proxy, and is how a proxied record changing type drops it.
	if proxied != nil && *proxied && !slices.Contains(proxiableTypes, typ) {
		return fmt.Errorf("proxied applies to A, AAAA and CNAME records only, not %s", typ)
	}
	return nil
}

// proxySkipped reports whether a record of type typ asking for proxied
// (nil: not given) is skipped on platform p: proxied=true off Cloudflare,
// which has the only proxy, on a type that can be proxied (a type that
// cannot is refused, checkProxied).
func proxySkipped(p ID, typ string, proxied *bool) bool {
	return proxied != nil && *proxied && p != Cloudflare && slices.Contains(proxiableTypes, typ)
}

// apexCNAME reports whether platform p takes a CNAME at the zone apex:
// Cloudflare flattens one, Alibaba Cloud takes one beside its records there.
// Route 53, Cloud DNS, GoDaddy and name.com refuse it, as the apex holds the
// zone's NS records. An unknown platform ("") is left to decide.
func apexCNAME(p ID) bool { return p == "" || p == Cloudflare || p == Aliyun }

// checkEnsureApex refuses NS at the zone apex, which dns ensure does not
// write there: the zone's own nameservers, which dns ensure leaves alone as
// dns delete does.
func checkEnsureApex(typ string) error {
	if typ == "NS" {
		return errors.New("the NS records of the zone apex are the zone's own nameservers, which dns ensure neither counts nor changes")
	}
	return nil
}

// apexCNAMEError says that platform p, where apexCNAME is false, does not
// take a CNAME at the zone apex, and what to write instead: refused before
// any request, and so, for dns ensure, before the records it would replace
// are deleted.
func apexCNAMEError(p ID) error {
	hint := "write A or AAAA records"
	switch p {
	case GCP:
		hint = "write an ALIAS record, or A or AAAA records"
	case NameCom:
		hint = "write an ANAME record, or A or AAAA records"
	case AWS:
		hint = "write A or AAAA records; a Route 53 alias is an A or AAAA record set with an alias target, set up in the AWS console or CLI"
	}
	return fmt.Errorf("%s does not take a CNAME at the zone apex, which holds the zone's NS records: %s", p, hint)
}

func checkHost(v string) (string, *int, error) {
	if strings.ContainsAny(v, " \t") {
		return "", nil, errors.New("it is not one host name")
	}
	h, err := targetHost("host", v, false)
	return h, nil, err
}

func checkMX(v string) (string, *int, error) {
	f := strings.Fields(v)
	var prio *int
	switch len(f) {
	case 1:
	case 2:
		n, err := numField("priority", f[0], 65535)
		if err != nil {
			return "", nil, err
		}
		prio = &n
		f = f[1:]
	default:
		return "", nil, errors.New("it is not a host name or <priority> <host>")
	}
	h, err := targetHost("host", f[0], true)
	return h, prio, err
}

// txtString is the longest character-string of a TXT record.
const txtString = 255

// checkTXT accepts text as it is (the providers quote it and split it into
// strings of at most 255 bytes) or a list of quoted strings, each of at most
// 255 bytes.
func checkTXT(v string) (string, *int, error) {
	if !strings.HasPrefix(v, `"`) {
		return v, nil, nil
	}
	fs, err := zoneFields(v)
	if err != nil {
		return "", nil, fmt.Errorf("it starts with a quote but %v; write the text without quotes, or as quoted strings", err)
	}
	for _, f := range fs {
		if !f.whole {
			return "", nil, errors.New("it starts with a quote but is not a list of quoted strings; write the text without quotes, or every string in quotes")
		}
		if len(f.text) > txtString {
			return "", nil, fmt.Errorf("a quoted string is %d bytes long, over %d; split it into several quoted strings, or write the text without quotes", len(f.text), txtString)
		}
	}
	return v, nil, nil
}

func checkSRV(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) != 4 {
		return "", nil, fmt.Errorf("it has %d fields, not 4", len(f))
	}
	out := make([]string, 4)
	for i, name := range []string{"priority", "weight", "port"} {
		n, err := numField(name, f[i], 65535)
		if err != nil {
			return "", nil, err
		}
		out[i] = strconv.Itoa(n)
	}
	h, err := targetHost("target", f[3], true)
	if err != nil {
		return "", nil, err
	}
	out[3] = h
	return strings.Join(out, " "), nil, nil
}

func isTagChar(r rune) bool {
	return (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
}

func checkCAA(v string) (string, *int, error) {
	fs, err := zoneFields(v)
	if err != nil {
		return "", nil, err
	}
	if len(fs) < 3 {
		return "", nil, fmt.Errorf("it has %d fields, not 3", len(fs))
	}
	flags, err := numField("flags", fs[0].text, 255)
	if err != nil {
		return "", nil, err
	}
	tag := fs[1].text
	if tag == "" || strings.IndexFunc(tag, func(r rune) bool { return !isTagChar(r) }) >= 0 {
		return "", nil, fmt.Errorf("the tag %q is not letters and digits", tag)
	}
	value := fs[2].text
	if len(fs) > 3 {
		// An unquoted value with spaces ("letsencrypt.org; accounturi=...").
		var parts []string
		for _, f := range fs[2:] {
			if f.quoted {
				return "", nil, errors.New("the value is more than one quoted string")
			}
			parts = append(parts, f.text)
		}
		value = strings.Join(parts, " ")
	}
	if value == "" && !fs[2].quoted {
		return "", nil, errors.New("the value is empty")
	}
	return strconv.Itoa(flags) + " " + strings.ToLower(tag) + " " + quoteZone(value), nil, nil
}

func checkNAPTR(v string) (string, *int, error) {
	fs, err := zoneFields(v)
	if err != nil {
		return "", nil, err
	}
	if len(fs) != 6 {
		return "", nil, fmt.Errorf("it has %d fields, not 6", len(fs))
	}
	order, err := numField("order", fs[0].text, 65535)
	if err != nil {
		return "", nil, err
	}
	pref, err := numField("preference", fs[1].text, 65535)
	if err != nil {
		return "", nil, err
	}
	flags := fs[2].text
	if strings.IndexFunc(flags, func(r rune) bool { return !isTagChar(r) }) >= 0 {
		return "", nil, fmt.Errorf("the flags %q are not letters and digits", flags)
	}
	regexp := fs[4].text
	repl, err := normalHost("replacement", fs[5].text, true)
	if err != nil {
		return "", nil, err
	}
	if regexp != "" && repl != "." {
		return "", nil, errors.New("a regexp and a replacement exclude each other: with a regexp the replacement is .")
	}
	return fmt.Sprintf("%d %d %s %s %s %s", order, pref, quoteZone(flags), quoteZone(fs[3].text), quoteZone(regexp), repl), nil, nil
}

// svcKeys are the SvcParam keys of HTTPS and SVCB records (RFC 9460 and the
// keys registered since); keyNNNNN names any key by its number.
var svcKeys = []string{"mandatory", "alpn", "no-default-alpn", "port", "ipv4hint", "ech", "ipv6hint", "dohpath", "ohttp", "tls-supported-groups"}

func validSvcKey(k string) bool {
	if slices.Contains(svcKeys, k) {
		return true
	}
	if n, ok := strings.CutPrefix(k, "key"); ok && n != "" && isDigits(n) {
		x, err := strconv.Atoi(n)
		return err == nil && x <= 65535
	}
	return false
}

func checkSVCB(v string) (string, *int, error) {
	fs, err := zoneFields(v)
	if err != nil {
		return "", nil, err
	}
	if len(fs) < 2 {
		return "", nil, errors.New("it has no target")
	}
	prio, err := numField("priority", fs[0].text, 65535)
	if err != nil {
		return "", nil, err
	}
	target, err := normalHost("target", fs[1].text, true)
	if err != nil {
		return "", nil, err
	}
	if prio == 0 && len(fs) > 2 {
		return "", nil, errors.New("priority 0 is alias mode, which takes no parameters")
	}
	out := []string{strconv.Itoa(prio), target}
	seen := map[string]bool{}
	for _, f := range fs[2:] {
		key, val, hasVal := strings.Cut(f.text, "=")
		key = strings.ToLower(key)
		if !validSvcKey(key) {
			return "", nil, fmt.Errorf("%q is not a parameter key (%s or keyNNNNN)", key, strings.Join(svcKeys, ", "))
		}
		if seen[key] {
			return "", nil, fmt.Errorf("the parameter %s is given twice", key)
		}
		seen[key] = true
		switch key {
		case "no-default-alpn", "ohttp":
			if hasVal {
				return "", nil, fmt.Errorf("the parameter %s takes no value", key)
			}
		default:
			if !hasVal || (val == "" && !strings.HasPrefix(key, "key")) {
				return "", nil, fmt.Errorf("the parameter %s needs a value", key)
			}
		}
		switch key {
		case "port":
			if _, err := numField("port", val, 65535); err != nil {
				return "", nil, err
			}
		case "ipv4hint", "ipv6hint":
			var canon []string
			for _, a := range strings.Split(val, ",") {
				ip, err := netip.ParseAddr(a)
				if err != nil || (key == "ipv4hint" && !ip.Is4()) || (key == "ipv6hint" && !ip.Is6()) {
					return "", nil, fmt.Errorf("%q in %s is not an IPv%s address", a, key, map[string]string{"ipv4hint": "4", "ipv6hint": "6"}[key])
				}
				canon = append(canon, ip.String())
			}
			// Addresses canonical, as everywhere else.
			val = strings.Join(canon, ",")
		case "mandatory":
			for _, k := range strings.Split(val, ",") {
				if k == "mandatory" || !validSvcKey(k) {
					return "", nil, fmt.Errorf("%q in mandatory is not a parameter key", k)
				}
			}
		case "ech":
			if _, err := base64.StdEncoding.DecodeString(val); err != nil {
				return "", nil, errors.New("the value of ech is not base64")
			}
		case "alpn":
			for _, a := range strings.Split(val, ",") {
				if a == "" {
					return "", nil, errors.New("alpn holds an empty protocol id")
				}
			}
		}
		switch {
		case !hasVal:
			out = append(out, key)
		case strings.ContainsAny(val, " \t\"\\"):
			out = append(out, key+"="+quoteZone(val))
		default:
			out = append(out, key+"="+val)
		}
	}
	return strings.Join(out, " "), nil, nil
}

// hexData joins the hex fields of a value and checks them: want is the
// number of hex digits the digest type calls for, 0 for any even number.
func hexData(name string, fields []string, want int) (string, error) {
	h := strings.ToLower(strings.Join(fields, ""))
	if h == "" {
		return "", fmt.Errorf("the %s is missing", name)
	}
	for _, r := range h {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f')) {
			return "", fmt.Errorf("the %s is not hex (%q)", name, r)
		}
	}
	if len(h)%2 != 0 {
		return "", fmt.Errorf("the %s has an odd number of hex digits", name)
	}
	if want > 0 && len(h) != want {
		return "", fmt.Errorf("the %s has %d hex digits, not %d", name, len(h), want)
	}
	return h, nil
}

// base64Data joins the base64 fields of a value and checks them.
func base64Data(name string, fields []string) (string, error) {
	b := strings.Join(fields, "")
	if b == "" {
		return "", fmt.Errorf("the %s is missing", name)
	}
	if _, err := base64.StdEncoding.DecodeString(b); err != nil {
		return "", fmt.Errorf("the %s is not base64", name)
	}
	return b, nil
}

// numbers reads the leading numeric fields of a value, each with its
// maximum.
func numbers(f []string, names []string, max []int) ([]string, error) {
	out := make([]string, len(names))
	for i, name := range names {
		n, err := numField(name, f[i], max[i])
		if err != nil {
			return nil, err
		}
		out[i] = strconv.Itoa(n)
	}
	return out, nil
}

func checkTLSA(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) < 4 {
		return "", nil, fmt.Errorf("it has %d fields, not 4", len(f))
	}
	n, err := numbers(f, []string{"usage", "selector", "matching type"}, []int{255, 255, 255})
	if err != nil {
		return "", nil, err
	}
	want := map[string]int{"1": 64, "2": 128}[n[2]]
	h, err := hexData("data", f[3:], want)
	if err != nil {
		return "", nil, err
	}
	return strings.Join(append(n, h), " "), nil, nil
}

func checkSSHFP(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) < 3 {
		return "", nil, fmt.Errorf("it has %d fields, not 3", len(f))
	}
	n, err := numbers(f, []string{"algorithm", "fingerprint type"}, []int{255, 255})
	if err != nil {
		return "", nil, err
	}
	want := map[string]int{"1": 40, "2": 64}[n[1]]
	h, err := hexData("fingerprint", f[2:], want)
	if err != nil {
		return "", nil, err
	}
	return strings.Join(append(n, h), " "), nil, nil
}

func checkDS(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) < 4 {
		return "", nil, fmt.Errorf("it has %d fields, not 4", len(f))
	}
	n, err := numbers(f, []string{"key tag", "algorithm", "digest type"}, []int{65535, 255, 255})
	if err != nil {
		return "", nil, err
	}
	want := map[string]int{"1": 40, "2": 64, "3": 64, "4": 96}[n[2]]
	h, err := hexData("digest", f[3:], want)
	if err != nil {
		return "", nil, err
	}
	return strings.Join(append(n, h), " "), nil, nil
}

func checkDNSKEY(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) < 4 {
		return "", nil, fmt.Errorf("it has %d fields, not 4", len(f))
	}
	n, err := numbers(f, []string{"flags", "protocol", "algorithm"}, []int{65535, 255, 255})
	if err != nil {
		return "", nil, err
	}
	if n[1] != "3" {
		return "", nil, fmt.Errorf("the protocol is %s; it is always 3", n[1])
	}
	k, err := base64Data("key", f[3:])
	if err != nil {
		return "", nil, err
	}
	return strings.Join(append(n, k), " "), nil, nil
}

// certTypes are the mnemonics of the CERT types (RFC 4398).
var certTypes = map[string]int{"PKIX": 1, "SPKI": 2, "PGP": 3, "IPKIX": 4, "ISPKI": 5, "IPGP": 6, "ACPKIX": 7, "IACPKIX": 8, "URI": 253, "OID": 254}

func checkCERT(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) < 4 {
		return "", nil, fmt.Errorf("it has %d fields, not 4", len(f))
	}
	if n, ok := certTypes[strings.ToUpper(f[0])]; ok {
		f[0] = strconv.Itoa(n)
	}
	n, err := numbers(f, []string{"type", "key tag", "algorithm"}, []int{65535, 65535, 255})
	if err != nil {
		return "", nil, err
	}
	c, err := base64Data("certificate", f[3:])
	if err != nil {
		return "", nil, err
	}
	return strings.Join(append(n, c), " "), nil, nil
}

func checkURI(v string) (string, *int, error) {
	fs, err := zoneFields(v)
	if err != nil {
		return "", nil, err
	}
	if len(fs) != 3 {
		return "", nil, fmt.Errorf("it has %d fields, not 3", len(fs))
	}
	n, err := numbers([]string{fs[0].text, fs[1].text}, []string{"priority", "weight"}, []int{65535, 65535})
	if err != nil {
		return "", nil, err
	}
	target := fs[2].text
	if i := strings.Index(target, ":"); i <= 0 || strings.ContainsAny(target, " \t") {
		return "", nil, fmt.Errorf("the target %q is not a URI", target)
	}
	return n[0] + " " + n[1] + " " + quoteZone(target), nil, nil
}

func checkBase64Value(v string) (string, *int, error) {
	k, err := base64Data("key", strings.Fields(v))
	return k, nil, err
}

func checkIPSECKEY(v string) (string, *int, error) {
	f := strings.Fields(v)
	if len(f) != 4 && len(f) != 5 {
		return "", nil, fmt.Errorf("it has %d fields, not 5", len(f))
	}
	n, err := numbers(f, []string{"precedence", "gateway type", "algorithm"}, []int{255, 3, 255})
	if err != nil {
		return "", nil, err
	}
	gw := f[3]
	switch n[1] {
	case "0":
		if gw != "." {
			return "", nil, errors.New("gateway type 0 takes . as the gateway")
		}
	case "1", "2":
		a, err := netip.ParseAddr(gw)
		if err != nil || (n[1] == "1" && !a.Is4()) || (n[1] == "2" && !a.Is6()) {
			return "", nil, fmt.Errorf("the gateway %q is not an IPv%s address", gw, map[string]string{"1": "4", "2": "6"}[n[1]])
		}
		gw = a.String()
	case "3":
		if gw, err = normalHost("gateway", gw, false); err != nil {
			return "", nil, err
		}
	}
	out := append(n, gw)
	if len(f) == 5 {
		k, err := base64Data("key", f[4:])
		if err != nil {
			return "", nil, err
		}
		out = append(out, k)
	} else if n[2] != "0" {
		return "", nil, errors.New("the key is missing")
	}
	return strings.Join(out, " "), nil, nil
}

// locNumber reads a number of a LOC value, with an optional "m" suffix when
// meters is set, between lo and hi.
func locNumber(name, s string, meters bool, lo, hi float64) (float64, error) {
	if meters {
		s = strings.TrimSuffix(strings.TrimSuffix(s, "M"), "m")
	}
	x, err := strconv.ParseFloat(s, 64)
	if err != nil || math.IsNaN(x) || math.IsInf(x, 0) || strings.ContainsAny(s, "eExX") {
		return 0, fmt.Errorf("the %s %q is not a number", name, s)
	}
	if x < lo || x > hi {
		return 0, fmt.Errorf("the %s %s is not between %s and %s", name, s, locFormat(lo), locFormat(hi))
	}
	return x, nil
}

func locFormat(x float64) string { return strconv.FormatFloat(x, 'f', -1, 64) }

// checkLOC reads a LOC value (RFC 1876). The normal form has every field:
// minutes and seconds 0 when left out, the size 1m, the horizontal
// precision 10000m and the vertical precision 10m (the defaults of the RFC).
func checkLOC(v string) (string, *int, error) {
	f := strings.Fields(v)
	i := 0
	coord := func(what string, maxDeg float64, dirs string) ([]string, error) {
		parts := []float64{0, 0, 0}
		names := []string{what + " degrees", what + " minutes", what + " seconds"}
		max := []float64{maxDeg, 59, 59.999}
		n := 0
		for i < len(f) && n < 3 && !strings.Contains(dirs, strings.ToUpper(f[i])) {
			x, err := locNumber(names[n], f[i], false, 0, max[n])
			if err != nil {
				return nil, err
			}
			if n < 2 && x != math.Trunc(x) {
				return nil, fmt.Errorf("the %s %s is not a whole number", names[n], f[i])
			}
			parts[n] = x
			n++
			i++
		}
		if n == 0 {
			return nil, fmt.Errorf("the %s degrees are missing", what)
		}
		if parts[0] == maxDeg && (parts[1] != 0 || parts[2] != 0) {
			return nil, fmt.Errorf("the %s is over %s degrees", what, locFormat(maxDeg))
		}
		if i >= len(f) || len(f[i]) != 1 || !strings.Contains(dirs, strings.ToUpper(f[i])) {
			return nil, fmt.Errorf("the %s does not end in %s", what, strings.Join(strings.Split(dirs, ""), " or "))
		}
		dir := strings.ToUpper(f[i])
		i++
		return []string{locFormat(parts[0]), locFormat(parts[1]), strconv.FormatFloat(parts[2], 'f', 3, 64), dir}, nil
	}
	lat, err := coord("latitude", 90, "NS")
	if err != nil {
		return "", nil, err
	}
	long, err := coord("longitude", 180, "EW")
	if err != nil {
		return "", nil, err
	}
	rest := f[i:]
	if len(rest) == 0 {
		return "", nil, errors.New("the altitude is missing")
	}
	if len(rest) > 4 {
		return "", nil, errors.New("it has fields after the vertical precision")
	}
	alt, err := locNumber("altitude", rest[0], true, -100000, 42849672.95)
	if err != nil {
		return "", nil, err
	}
	sizes := []float64{1, 10000, 10}
	for j, name := range []string{"size", "horizontal precision", "vertical precision"} {
		if j+1 < len(rest) {
			if sizes[j], err = locNumber(name, rest[j+1], true, 0, 90000000); err != nil {
				return "", nil, err
			}
		}
	}
	out := append(lat, long...)
	out = append(out, strconv.FormatFloat(alt, 'f', 2, 64)+"m")
	for _, s := range sizes {
		out = append(out, locFormat(s)+"m")
	}
	return strings.Join(out, " "), nil, nil
}

// conflictReason says why records of the types a and b cannot share a name
// on platform p (RecordTypesConflict).
func conflictReason(p ID, a, b string) string {
	a, b = strings.ToUpper(a), strings.ToUpper(b)
	if b == "CNAME" || b == "NS" || (b == "ALIAS" || b == "ANAME") && a != "CNAME" && a != "NS" {
		a, b = b, a
	}
	switch a {
	case "CNAME":
		if p == Cloudflare {
			return "a CNAME cannot coexist with A, AAAA or NS records"
		}
		return "a CNAME cannot coexist with any other record"
	case "NS":
		if p == Cloudflare || p == Aliyun {
			return "a name delegated with NS records holds no other records but DS"
		}
		return "a CNAME cannot coexist with NS records"
	}
	return "an " + a + " record cannot coexist with A, AAAA or CNAME records"
}
