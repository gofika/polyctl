package platform

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/net/publicsuffix"
)

// RecordTyper is implemented by providers that host DNS zones: the record
// types their platform can write. `dns ensure` checks every desired record
// against it before it reads or writes anything; a provider without it
// accepts every type and leaves the decision to the platform.
type RecordTyper interface {
	RecordTypes() []string
}

// WritableRecordTypes returns the record types the provider of platform id
// can write, or nil when it does not say.
func WritableRecordTypes(id ID) []string {
	p, err := Get(id)
	if err != nil {
		return nil
	}
	if rt, ok := p.(RecordTyper); ok {
		return rt.RecordTypes()
	}
	return nil
}

// RecordPatch names the fields of a record to change; nil fields are left
// as they are on the platform.
type RecordPatch struct {
	Value    *string
	TTL      *int
	Proxied  *bool
	Priority *int
}

// RecordPatcher is implemented by DNS clients that can change single fields
// of a record without sending the others (Cloudflare's PATCH). Fields the
// platform keeps alongside a record (comments, tags) are then never at risk.
// current is the record as listed.
type RecordPatcher interface {
	PatchRecord(ctx context.Context, zoneID string, current Record, p RecordPatch) (*Record, error)
}

// DesiredRecord is a RecordSpec checked and normalized against a zone and a
// platform: what `dns ensure` converges the zone to.
type DesiredRecord struct {
	// Index is the 1-based position of the record in the input.
	Index int
	// Name is relative to the zone ("@" for the apex); FQDN is the full name.
	Name string
	FQDN string
	Type string
	// Value is what is sent to the platform: an MX record's host without its
	// priority, a host name without its trailing dot, an address in its
	// canonical form, any other value as given.
	Value    string
	TTL      *int
	Proxied  *bool
	Priority *int
	// ProxiedUnsupported marks a record asking for proxied=true on a
	// platform without a proxy: it is reported as skipped and not written.
	ProxiedUnsupported bool
}

// key is the (name, type) a desired or existing record is matched on.
func (d DesiredRecord) key() string { return d.FQDN + "\x00" + d.Type }

// Resource names the record in a change report: dns-record/<name>/<TYPE>,
// the name relative to the zone.
func (d DesiredRecord) Resource() string { return "dns-record/" + d.Name + "/" + d.Type }

func (d DesiredRecord) label() string {
	return fmt.Sprintf("record %d (%s %s)", d.Index, d.Name, d.Type)
}

// NormalizeRecordSpecs checks desired records against zone and platform p
// and returns them normalized. It reads nothing: every error is found
// before a zone is read. Malformed records are usage errors (naming the
// record), a type the platform cannot write (types, when not nil) is
// ErrNotSupported. warn receives notes that do not stop the command.
func NormalizeRecordSpecs(zone string, p ID, specs []RecordSpec, types []string, warn func(format string, args ...any)) ([]DesiredRecord, error) {
	if warn == nil {
		warn = func(string, ...any) {}
	}
	zone = NormalizeDomain(zone)
	out := make([]DesiredRecord, 0, len(specs))
	for i, s := range specs {
		d, err := normalizeSpec(zone, p, i+1, s, types, warn)
		if err != nil {
			return nil, err
		}
		out = append(out, d)
	}
	// Records of the input among themselves.
	seen := map[string]int{}
	names := map[string][]DesiredRecord{}
	for _, d := range out {
		k := d.key() + "\x00" + compareValue(d.Type, d.Value, d.Priority)
		if j, dup := seen[k]; dup {
			return nil, invalid("record %d repeats record %d (%s %s %s)", d.Index, j, d.Name, d.Type, d.Value)
		}
		seen[k] = d.Index
		names[d.FQDN] = append(names[d.FQDN], d)
	}
	for _, d := range out {
		for _, o := range names[d.FQDN] {
			switch {
			case o.Index <= d.Index:
			case o.Type == "CNAME" && d.Type == "CNAME":
				return nil, invalid("records %d and %d are both a CNAME of %s; a name has at most one CNAME", d.Index, o.Index, d.Name)
			case RecordTypesConflict(p, d.FQDN == zone, d.Type, o.Type):
				return nil, invalid("record %d is %s %s record of %s and record %d %s %s record of it; %s", d.Index, article(d.Type), d.Type, d.Name, o.Index, article(o.Type), o.Type, conflictReason(p, d.Type, o.Type))
			}
		}
	}
	return out, nil
}

func normalizeSpec(zone string, p ID, idx int, s RecordSpec, types []string, warn func(string, ...any)) (DesiredRecord, error) {
	s.Type = strings.ToUpper(strings.TrimSpace(s.Type))
	s.Value = strings.TrimSpace(s.Value)
	if err := s.validate(); err != nil {
		return DesiredRecord{}, invalid("record %d: %v", idx, err)
	}
	fqdn, err := zoneName(zone, s.Name)
	if err != nil {
		return DesiredRecord{}, invalid("record %d: %v", idx, err)
	}
	d := DesiredRecord{Index: idx, FQDN: fqdn, Name: RelativeName(fqdn, zone), Type: s.Type, TTL: s.TTL, Proxied: s.Proxied, Priority: s.Priority}
	if types != nil && !slices.Contains(types, d.Type) {
		return DesiredRecord{}, fmt.Errorf("%w (record %d)", notWritable(p, d.Type, types), idx)
	}
	if fqdn == zone {
		if err := checkEnsureApex(p, d.Type); err != nil {
			return DesiredRecord{}, invalid("%s: %v", d.label(), err)
		}
	}
	switch {
	case s.TTLAuto && d.TTL == nil && p == Cloudflare:
		// "auto" is Cloudflare's automatic TTL, 1 in the API.
		one := 1
		d.TTL = &one
	case d.TTL != nil && *d.TTL == 0 && p != Cloudflare:
		// The providers read a TTL of 0 as "platform default", so the
		// record would never be found as desired.
		return DesiredRecord{}, invalid("%s: ttl 0 cannot be set on %s; give a number of seconds, or leave the TTL out to keep it", d.label(), p)
	}
	if d.Value, err = normalizeValue(&d, s.Value, warn); err != nil {
		return DesiredRecord{}, invalid("%s: %v", d.label(), err)
	}
	if err := checkApexTarget(p, d.Type, d.Value); err != nil {
		return DesiredRecord{}, invalid("%s: %v", d.label(), err)
	}
	if d.Proxied != nil && p != Cloudflare {
		if *d.Proxied {
			d.ProxiedUnsupported = true
		}
		// false is the only setting such a platform has: nothing to do.
		d.Proxied = nil
	}
	if d.Proxied != nil && *d.Proxied && d.TTL != nil && *d.TTL != 1 && *d.TTL != 0 {
		warn("warning: %s: the TTL of a proxied record is always auto; ttl=%d is ignored", d.label(), *d.TTL)
	}
	return d, nil
}

// ZoneName is zoneName for the --name flag of the neutral dns commands, so
// that they read a name as dns ensure does. zone is normalized first.
func ZoneName(zone, name string) (string, error) {
	return zoneName(NormalizeDomain(zone), name)
}

// zoneName turns the name of a desired record into a FQDN in zone. "@" is
// the apex; a name ending with a dot is absolute; a name ending with the
// zone is taken as it is; any other name is relative to the zone, except
// one with several labels that ends in a top-level domain: that is a name
// outside the zone written without its trailing dot, and is refused rather
// than stored as <name>.<zone>.
func zoneName(zone, name string) (string, error) {
	raw := strings.TrimSpace(name)
	n := strings.ToLower(raw)
	var fqdn string
	switch {
	case n == "@" || n == "":
		fqdn = zone
	case strings.HasSuffix(n, "."):
		fqdn = NormalizeDomain(n)
		if fqdn != zone && !strings.HasSuffix(fqdn, "."+zone) {
			return "", fmt.Errorf("name %q is not in zone %s", raw, zone)
		}
	case n == zone || strings.HasSuffix(n, "."+zone):
		fqdn = n
	default:
		if i := strings.LastIndexByte(n, '.'); i >= 0 {
			if tld := n[i+1:]; tld != "" {
				if ps, icann := publicsuffix.PublicSuffix(tld); icann && ps == tld {
					return "", fmt.Errorf("name %q ends in the top-level domain .%s and is not in zone %s; write it relative to the zone (e.g. www) or as a name in the zone (www.%s)", raw, tld, zone, zone)
				}
			}
		}
		fqdn = n + "." + zone
	}
	if err := checkHostName(fqdn, true); err != nil {
		return "", fmt.Errorf("name %q: %v", raw, err)
	}
	return fqdn, nil
}

// checkHostName checks the labels of a domain name: none empty, none over
// 63 octets, the whole name at most 253. Record names may hold "_" and a
// leading "*" label.
func checkHostName(name string, recordName bool) error {
	name = strings.TrimSuffix(name, ".")
	if name == "" {
		return errors.New("the name is empty")
	}
	if len(name) > 253 {
		return errors.New("the name is longer than 253 characters")
	}
	for i, l := range strings.Split(name, ".") {
		switch {
		case l == "":
			return errors.New("the name has an empty label")
		case len(l) > 63:
			return fmt.Errorf("label %q is longer than 63 characters", l)
		case l == "*" && recordName && i == 0:
			continue
		}
		for _, r := range l {
			ok := r == '-' || r == '_' || (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')
			if !ok {
				return fmt.Errorf("label %q holds %q", l, r)
			}
		}
	}
	return nil
}

// normalizeValue checks the value of d with CheckRecord and returns the
// form sent to the platform; it also takes the priority out of an MX value.
// A host name of a single label is accepted with a warning.
func normalizeValue(d *DesiredRecord, v string, warn func(string, ...any)) (string, error) {
	rv, err := checkValue(d.Type, v, d.Priority)
	if err != nil {
		return "", err
	}
	d.Priority = rv.Priority
	switch d.Type {
	case "CNAME", "NS", "MX", "ALIAS", "ANAME":
		if h := rv.Value; h != "." && h != apexHost && !strings.Contains(h, ".") {
			warn("warning: %s: value %q is a single label; it is not completed with the zone name (write the full host name)", d.label(), h)
		}
	}
	return rv.Value, nil
}

// compareValue is the form two values of a type are compared in: host
// names lower-case without their trailing dot, addresses canonical, TXT
// text without quotes and with its strings joined, other values with their
// white space collapsed. An MX value is its host; its priority is compared
// on its own. The priority of an SRV value read as a separate field is put
// back in front.
func compareValue(typ, v string, priority *int) string {
	typ = strings.ToUpper(typ)
	v = strings.TrimSpace(v)
	switch typ {
	case "A", "AAAA":
		if a, err := netip.ParseAddr(v); err == nil {
			return a.String()
		}
		return strings.ToLower(v)
	case "CNAME", "NS", "PTR", "MX", "ALIAS", "ANAME":
		if v == "." {
			return v
		}
		return strings.TrimSuffix(strings.ToLower(v), ".")
	case "HTTPS", "SVCB", "SSHFP", "SMIMEA", "LOC", "IPSECKEY", "OPENPGPKEY":
		// The types polyctl came to write later compare in their normal
		// form, so that a platform's rendering (quotes, the trailing dot, the
		// default fields of LOC) equals the value given.
		if rv, err := checkValue(typ, v, nil); err == nil {
			if typ == "OPENPGPKEY" {
				return rv.Value
			}
			return strings.ToLower(rv.Value)
		}
	case "SRV", "NAPTR":
		f := strings.Fields(strings.ToLower(v))
		if typ == "SRV" && len(f) == 3 && priority != nil {
			f = append([]string{strconv.Itoa(*priority)}, f...)
		}
		if n := len(f); n > 0 && f[n-1] != "." {
			f[n-1] = strings.TrimSuffix(f[n-1], ".")
		}
		return strings.Join(f, " ")
	case "TXT", "SPF":
		return JoinTXT(v)
	case "URI":
		// "<priority> <weight> <target>"; a platform may hand the priority
		// back apart (Cloudflare) and the target quoted.
		f := strings.Fields(strings.ReplaceAll(v, `"`, ""))
		if len(f) == 2 && priority != nil {
			f = append([]string{strconv.Itoa(*priority)}, f...)
		}
		return strings.Join(f, " ")
	case "CAA":
		return strings.Join(strings.Fields(strings.ReplaceAll(v, `"`, "")), " ")
	}
	return strings.ToLower(strings.Join(strings.Fields(v), " "))
}

// JoinTXT turns a TXT value in zone-file form (one or more quoted strings,
// `"a" "b"`) into its text: the strings unescaped and concatenated. A value
// that does not start with a quote is returned as it is.
func JoinTXT(v string) string {
	if !strings.HasPrefix(v, `"`) {
		return v
	}
	var b strings.Builder
	in := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case !in:
			if c == '"' {
				in = true
			} else if c != ' ' && c != '\t' {
				// Not a list of quoted strings after all.
				return v
			}
		case c == '"':
			in = false
		case c == '\\' && i+3 < len(v) && isDigits(v[i+1:i+4]):
			n, _ := strconv.Atoi(v[i+1 : i+4])
			b.WriteByte(byte(n))
			i += 3
		case c == '\\' && i+1 < len(v):
			i++
			b.WriteByte(v[i])
		default:
			b.WriteByte(c)
		}
	}
	if in {
		return v
	}
	return b.String()
}

func isDigits(s string) bool {
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return s != ""
}

// existingCompareValue is compareValue of a record read from a platform.
func existingCompareValue(r Record) string {
	if v, ok := srvFields(r); ok {
		return compareValue("SRV", v, nil)
	}
	return compareValue(r.Type, r.Value, r.Priority)
}

// srvFields is "<priority> <weight> <port> <target>" of an SRV record whose
// platform keeps the fields apart: a Cloudflare SRV record carries them in
// data, a GoDaddy one its weight and port in fields of their own beside the
// target. ok is false for any other record.
func srvFields(r Record) (string, bool) {
	if !strings.EqualFold(r.Type, "SRV") {
		return "", false
	}
	if r.Priority != nil && len(strings.Fields(r.Value)) == 1 {
		if w, p := r.Extra["weight"], r.Extra["port"]; w != nil && p != nil {
			return fmt.Sprintf("%d %v %v %s", *r.Priority, w, p, r.Value), true
		}
	}
	if d, ok := r.Extra["data"].(map[string]any); ok {
		var f []string
		for _, k := range []string{"priority", "weight", "port", "target"} {
			if x, ok := d[k]; ok {
				f = append(f, fmt.Sprint(x))
			}
		}
		if len(f) == 4 {
			return strings.Join(f, " "), true
		}
	}
	return "", false
}

// RecordAddValue is the value of r as `dns add` takes it: the priority an
// MX, SRV or URI record holds apart put back in front, and the fields of an
// SRV record a platform keeps apart joined.
func RecordAddValue(r Record) string {
	if v, ok := srvFields(r); ok {
		return v
	}
	n := len(strings.Fields(r.Value))
	switch typ := strings.ToUpper(r.Type); {
	case r.Priority == nil:
	case typ == "MX" && n == 1, typ == "SRV" && n == 3, typ == "URI" && n == 2:
		return strconv.Itoa(*r.Priority) + " " + r.Value
	}
	return r.Value
}

// RestoreValue is RecordAddValue of r when `dns add` on platform p writes r
// again as it is, and otherwise an error that says why it cannot: a Route
// 53 alias record, a record of a routing policy (a Route 53 set identifier,
// a Cloud DNS routing policy), or a value dns add's own check refuses.
func RestoreValue(p ID, r Record) (string, error) {
	switch {
	case extraFlag(r.Extra, "alias"):
		return "", errors.New("it is an alias record, which dns add does not write")
	case r.Extra["set_identifier"] != nil && fmt.Sprint(r.Extra["set_identifier"]) != "":
		return "", fmt.Errorf("it belongs to a routing policy (set identifier %v), which dns add does not write", r.Extra["set_identifier"])
	case r.Extra["routing_policy"] != nil:
		return "", errors.New("it is a record set with a routing policy, which dns add does not write")
	}
	v := RecordAddValue(r)
	if _, err := CheckRecord(RecordCheck{Platform: p, Type: r.Type, Value: v, New: true}); err != nil {
		// The reason alone: the refusal is no usage error of the run.
		return "", fmt.Errorf("dns add refuses it: %s", strings.TrimPrefix(err.Error(), ErrInvalidInput.Error()+": "))
	}
	return v, nil
}

// RecordValueMatches reports whether value names the value of r, compared
// as dns ensure compares values: host names without case or trailing dot,
// addresses canonical, TXT text with or without its quotes. An MX value may
// be given as "<priority> <host>" (as dns list prints it), and then the
// priority must match too, or as the host alone.
func RecordValueMatches(r Record, value string) bool {
	value = strings.TrimSpace(value)
	if r.Value == value {
		return true
	}
	if strings.EqualFold(r.Type, "MX") {
		rp, rh := splitMX(r.Value, r.Priority)
		vp, vh := splitMX(value, nil)
		if compareValue("MX", rh, nil) != compareValue("MX", vh, nil) {
			return false
		}
		return vp == nil || (rp != nil && *rp == *vp)
	}
	return existingCompareValue(r) == compareValue(r.Type, value, r.Priority)
}

// splitMX splits an MX value written "<priority> <host>"; a value that is a
// host alone keeps the priority given.
func splitMX(v string, priority *int) (*int, string) {
	f := strings.Fields(v)
	if len(f) == 2 {
		if n, err := strconv.Atoi(f[0]); err == nil && n >= 0 {
			return &n, f[1]
		}
	}
	return priority, strings.TrimSpace(v)
}

// FieldChange is one field a record differs in from the desired one.
type FieldChange struct {
	Field    string // value, ttl, proxied or priority
	Old, New string
}

// DiffRecord compares an existing record with the desired one on platform
// p and returns the fields to change; none means the record already is as
// desired. TTL, proxied and priority are compared only when the desired
// record gives them, so a record keeps what it has unless told otherwise;
// a proxied record's TTL is never compared (Cloudflare fixes it to auto).
func DiffRecord(p ID, existing Record, d DesiredRecord) []FieldChange {
	var out []FieldChange
	if existingCompareValue(existing) != compareValue(d.Type, d.Value, d.Priority) {
		out = append(out, FieldChange{"value", displayValue(existing.Type, existing.Value), displayValue(d.Type, d.Value)})
	}
	if d.Type == "MX" && d.Priority != nil && (existing.Priority == nil || *existing.Priority != *d.Priority) {
		old := "none"
		if existing.Priority != nil {
			old = strconv.Itoa(*existing.Priority)
		}
		out = append(out, FieldChange{"priority", old, strconv.Itoa(*d.Priority)})
	}
	cur := existing.Proxied != nil && *existing.Proxied
	proxied := cur
	if p == Cloudflare && d.Proxied != nil {
		proxied = *d.Proxied
		if cur != proxied {
			out = append(out, FieldChange{"proxied", strconv.FormatBool(cur), strconv.FormatBool(proxied)})
		}
	}
	if d.TTL != nil && !(p == Cloudflare && proxied) {
		want := *d.TTL
		if p == Cloudflare && want == 0 {
			want = 1 // Cloudflare stores 0 as 1 (automatic)
		}
		if existing.TTL != want {
			out = append(out, FieldChange{"ttl", TTLLabel(p, existing), TTLLabel(p, Record{TTL: want})})
		}
	}
	return out
}

// displayValue renders a value for a change report: TXT text in quotes.
func displayValue(typ, v string) string {
	if t := strings.ToUpper(typ); (t == "TXT" || t == "SPF") && !strings.HasPrefix(v, `"`) {
		return `"` + v + `"`
	}
	return v
}

// recordDisplay renders an existing record for a change report:
// "<value> ttl=<ttl>[ proxied=<bool>]".
func recordDisplay(p ID, r Record) string {
	v := displayValue(r.Type, r.Value)
	if r.Priority != nil && strings.EqualFold(r.Type, "MX") {
		v = strconv.Itoa(*r.Priority) + " " + v
	}
	s := v + " ttl=" + TTLLabel(p, r)
	if p == Cloudflare {
		s += " proxied=" + strconv.FormatBool(r.Proxied != nil && *r.Proxied)
	}
	return s
}

// desiredDisplay renders a record about to be created.
func desiredDisplay(p ID, d DesiredRecord) string {
	v := displayValue(d.Type, d.Value)
	if d.Priority != nil && d.Type == "MX" {
		v = strconv.Itoa(*d.Priority) + " " + v
	}
	ttl := "default"
	if p == Cloudflare {
		ttl = "auto"
	}
	if d.TTL != nil && !(p == Cloudflare && (*d.TTL <= 1 || (d.Proxied != nil && *d.Proxied))) {
		ttl = strconv.Itoa(*d.TTL)
	}
	s := v + " ttl=" + ttl
	if p == Cloudflare {
		s += " proxied=" + strconv.FormatBool(d.Proxied != nil && *d.Proxied)
	}
	return s
}

// DNSEnsure is the input of PlanDNSEnsure.
type DNSEnsure struct {
	Platform ID
	// Zone is the name of the zone, ZoneID its id.
	Zone   string
	ZoneID string
	// Existing are the records of the zone, read in full.
	Existing []Record
	Desired  []DesiredRecord
	// PruneDuplicates deletes the other records of a name and type that has
	// several, once one of them is as desired.
	PruneDuplicates bool
	// Decide settles a name that holds records of types the run does not
	// name for it (see OccupiedName): replace=true deletes them before the
	// desired records of the name are written, false leaves them beside
	// those. It is called for each such name in input order, after every
	// other check and before any step runs; an error stops the plan before
	// anything is written. nil refuses every such name (OccupiedName.Refusal).
	// A name one of whose records belongs to another service of the platform
	// (RecordOwner: the CNAME of an R2 custom domain, which the DNS API
	// cannot delete), or is one dns add could not write again (RestoreValue:
	// a Route 53 alias, a routing policy), is refused before Decide is asked
	// (OccupiedName.BoundRefusal, OccupiedName.RestoreRefusal).
	Decide func(OccupiedName) (replace bool, err error)
	// Restore is the command that writes a deleted record again: the error
	// of a write that fails after the records it replaces were deleted
	// names it. nil names none.
	Restore func(Record) string
	// DNS performs the writes (inside Step.Apply only).
	DNS DNSService
	// Written is told about every record written (oldID is the id the
	// record had before an update, "" for a new one); Removed about every
	// record deleted. Both may be nil. They keep the inventory in step.
	Written func(ctx context.Context, oldID string, r Record)
	Removed func(ctx context.Context, id string)
}

// OccupiedName is a name of a dns ensure run that holds records of types
// the run does not name for it, and that needs a decision before anything
// is written: they are replaced by the desired records of the name (deleted
// first), or kept beside them. The SOA and the NS records of the zone apex
// are the zone's own and never count. A name whose records include one of a
// type the run names, and whose other records can share the name with the
// desired ones, needs no decision: those are left alone.
type OccupiedName struct {
	Platform ID
	// Name is relative to the zone ("@" for the apex); FQDN is the full name.
	Name, FQDN string
	// Types are the types the run names for the name, in input order, and
	// Count is the number of its desired records.
	Types []string
	Count int
	// Others are the records of other types, as the zone lists them: not of
	// a type the run names for the name, even one whose desired record is
	// not written (proxied=true off Cloudflare).
	Others []Record
	// Claimed says the name also holds a record of a type the run names.
	Claimed bool
	// Conflict says a type of Types cannot share the name with a record of
	// Others (RecordTypesConflict).
	Conflict bool
}

// Single says the name holds one record, of another type: it is replaced
// after a confirmation, without a choice.
func (o OccupiedName) Single() bool { return !o.Claimed && len(o.Others) == 1 }

// CanKeep says the desired records can be written beside Others.
func (o OccupiedName) CanKeep() bool { return !o.Conflict }

// What names the desired records of the name: "the A record", "the MX
// records", "the A, TXT records".
func (o OccupiedName) What() string {
	switch {
	case len(o.Types) > 1:
		return "the " + strings.Join(o.Types, ", ") + " records"
	case o.Count > 1:
		return "the " + strings.Join(o.Types, "") + " records"
	}
	return "the " + strings.Join(o.Types, "") + " record"
}

// OthersText lists Others: `TXT "x" ttl=300, MX 10 mail.example.com ttl=300`.
func (o OccupiedName) OthersText() string {
	parts := make([]string, len(o.Others))
	for i, r := range o.Others {
		parts[i] = strings.ToUpper(r.Type) + " " + recordDisplay(o.Platform, r)
	}
	return strings.Join(parts, ", ")
}

// othersCount is "a record of another type" or "3 records of other types".
func (o OccupiedName) othersCount() string {
	if len(o.Others) == 1 {
		return "a record of another type"
	}
	return fmt.Sprintf("%d records of other types", len(o.Others))
}

// conflictReason says why the desired records cannot share the name with
// Others, "" when they can.
func (o OccupiedName) conflictReason() string {
	apex := o.Name == "@"
	for _, t := range o.Types {
		for _, r := range o.Others {
			if RecordTypesConflict(o.Platform, apex, t, r.Type) {
				return conflictReason(o.Platform, t, r.Type)
			}
		}
	}
	return ""
}

// Ambiguous is the error of a name that needs a choice where nothing can be
// asked (exit code 5): dns ensure deletes several records of a name only
// after a choice on a terminal, never in a script, --yes or not.
func (o OccupiedName) Ambiguous() error {
	hint := fmt.Sprintf("add %s beside them with `polyctl dns add`, or delete them first with `polyctl dns delete` to replace them", o.What())
	if why := o.conflictReason(); why != "" {
		hint = fmt.Sprintf("%s cannot stay beside them (%s): delete them first with `polyctl dns delete`, then run dns ensure again", o.What(), why)
	}
	return fmt.Errorf("%w: %s holds %s (%s); dns ensure replaces several records of a name only after a choice on a terminal: %s (nothing was written)",
		ErrAmbiguous, o.FQDN, o.othersCount(), o.OthersText(), hint)
}

// Refusal is the error of a name nobody decided: Ambiguous, or for a single
// record that replacing it needs a confirmation.
func (o OccupiedName) Refusal() error {
	if !o.Single() {
		return o.Ambiguous()
	}
	return fmt.Errorf("%s holds %s (%s); replacing it with %s needs a confirmation (nothing was written)", o.FQDN, o.othersCount(), o.OthersText(), o.What())
}

// BoundRefusal is the error of a name whose record r of another type
// belongs to owner, another service of the platform: dns ensure does not
// replace it, as `dns delete` unbinds it there instead of deleting it.
func (o OccupiedName) BoundRefusal(r Record, owner string) error {
	hint := fmt.Sprintf("add %s beside it with `polyctl dns add`, or delete it first with `polyctl dns delete`, which unbinds it from %s", o.What(), owner)
	if !o.CanKeep() {
		hint = fmt.Sprintf("delete it first with `polyctl dns delete`, which unbinds it from %s, then run dns ensure again", owner)
	}
	return fmt.Errorf("%s holds %s %s, which belongs to %s and cannot be deleted through the DNS API; dns ensure does not replace it with %s: %s (nothing was written)",
		o.FQDN, strings.ToUpper(r.Type), recordDisplay(o.Platform, r), owner, o.What(), hint)
}

// RestoreRefusal is the error of a name whose record r of another type
// `dns add` cannot write again (RestoreValue, why): dns ensure does not
// replace it, as the record could not be restored should the write that
// replaces it fail.
func (o OccupiedName) RestoreRefusal(r Record, why error) error {
	hint := fmt.Sprintf("add %s beside it with `polyctl dns add`, or change it with the record commands of %s or delete it first with `polyctl dns delete`", o.What(), o.Platform)
	if !o.CanKeep() {
		hint = fmt.Sprintf("change it with the record commands of %s, or delete it first with `polyctl dns delete`, then run dns ensure again", o.Platform)
	}
	return fmt.Errorf("%s holds %s %s, which `polyctl dns add` could not write again: %v; dns ensure does not replace it with %s: %s (nothing was written)",
		o.FQDN, strings.ToUpper(r.Type), recordDisplay(o.Platform, r), why, o.What(), hint)
}

// irreplaceable is the refusal of o when one of its records of other types
// cannot be replaced: it belongs to another service of the platform
// (RecordOwner), or dns add could not write it again (RestoreValue).
func (in DNSEnsure) irreplaceable(o OccupiedName) error {
	zone := Zone{ID: in.ZoneID, Name: in.Zone}
	for _, r := range o.Others {
		if owner, ok := RecordOwner(in.DNS, zone, r); ok {
			return o.BoundRefusal(r, owner)
		}
		if _, err := RestoreValue(in.Platform, r); err != nil {
			return o.RestoreRefusal(r, err)
		}
	}
	return nil
}

// occupiedNames are the names of in that need a decision (OccupiedName), in
// input order. A desired record that is not written (proxied=true off
// Cloudflare) still names its type for its name: a record of that type is
// never one of the others, so it is never replaced. It does not count among
// the desired records, and a name with no other desired record needs no
// decision.
func occupiedNames(in DNSEnsure) []OccupiedName {
	var names []OccupiedName
	named := map[string][]string{} // every type of a name, written or not
	at := map[string]int{}
	for _, d := range in.Desired {
		i, ok := at[d.FQDN]
		if !ok {
			i = len(names)
			at[d.FQDN] = i
			names = append(names, OccupiedName{Platform: in.Platform, Name: d.Name, FQDN: d.FQDN})
		}
		if !slices.Contains(named[d.FQDN], d.Type) {
			named[d.FQDN] = append(named[d.FQDN], d.Type)
		}
		if d.ProxiedUnsupported {
			continue
		}
		names[i].Count++
		if !slices.Contains(names[i].Types, d.Type) {
			names[i].Types = append(names[i].Types, d.Type)
		}
	}
	for _, r := range in.Existing {
		i, ok := at[NormalizeDomain(r.Name)]
		if !ok {
			continue
		}
		o := &names[i]
		typ := strings.ToUpper(r.Type)
		switch {
		case slices.Contains(named[o.FQDN], typ):
			o.Claimed = true
		case typ == "SOA", typ == "NS" && o.Name == "@":
			// The zone's own records.
		default:
			o.Others = append(o.Others, r)
		}
	}
	var out []OccupiedName
	for _, o := range names {
		if len(o.Others) == 0 || o.Count == 0 {
			continue
		}
		o.Conflict = o.conflictReason() != ""
		if o.Claimed && !o.Conflict {
			continue
		}
		out = append(out, o)
	}
	return out
}

// PlanDNSEnsure computes the steps that bring the zone to the desired
// records. Each desired record gets one step, in input order: create when
// no record of its name and type exists, update when one exists and
// differs, unchanged when one is as desired. Desired records sharing a name
// and type form a set: each value missing is created, nothing is updated.
// One desired record against several existing ones is fine when one of
// them is as desired, or else when one has the desired value (that one is
// updated in its other fields, such as the TTL); the others are left alone,
// or deleted with PruneDuplicates. When none has the desired value it is
// ambiguous (ErrAmbiguous), unless PruneDuplicates picks the oldest one to
// update and deletes the rest; those deletions come last.
//
// Records of types the run does not name are left alone when the name also
// holds a record of a type it names and they can share the name with the
// desired records. Otherwise the name is an OccupiedName that Decide
// settles: replaced records are deleted right before the first step of
// their name. Errors are returned before any step runs.
func PlanDNSEnsure(in DNSEnsure) (*Plan, error) {
	existing := map[string][]Record{}
	for _, r := range in.Existing {
		r.Name, r.Type = NormalizeDomain(r.Name), strings.ToUpper(r.Type)
		k := r.Name + "\x00" + r.Type
		existing[k] = append(existing[k], r)
	}
	for k := range existing {
		sortOldestFirst(existing[k])
	}
	groups := map[string][]DesiredRecord{}
	for _, d := range in.Desired {
		groups[d.key()] = append(groups[d.key()], d)
	}

	type desiredStep struct {
		d    DesiredRecord
		step Step
	}
	var steps []desiredStep
	add := func(d DesiredRecord, s Step) { steps = append(steps, desiredStep{d, s}) }
	var deletes []Step
	for _, d := range in.Desired {
		recs := existing[d.key()]
		if d.ProxiedUnsupported {
			add(d, Step{Resource: d.Resource(), Action: Skipped, Desc: fmt.Sprintf("proxied=true applies to Cloudflare only, %s has no proxy; record not written", in.Platform)})
			continue
		}
		if len(groups[d.key()]) > 1 {
			// Set semantics: make sure this value exists.
			if r, ok := findValue(recs, d); ok {
				add(d, Step{Resource: d.Resource(), Action: Unchanged, ID: r.ID, Desc: recordDisplay(in.Platform, r)})
				continue
			}
			step, err := in.createStep(d)
			if err != nil {
				return nil, err
			}
			add(d, step)
			continue
		}
		switch len(recs) {
		case 0:
			step, err := in.createStep(d)
			if err != nil {
				return nil, err
			}
			add(d, step)
		case 1:
			add(d, in.updateOrKeep(d, recs[0], ""))
		default:
			keep := -1
			for i, r := range recs {
				if len(DiffRecord(in.Platform, r, d)) == 0 {
					keep = i
					break
				}
			}
			if keep < 0 {
				// A record holding the desired value is the one to
				// bring in line (TTL, proxied); only when none holds it
				// is the choice ambiguous.
				keep = findValueIndex(recs, d)
			}
			if keep < 0 && !in.PruneDuplicates {
				return nil, fmt.Errorf("%w: %s: %d records of %s %s exist and none has the desired value, so which one to update cannot be told; pass --prune-duplicates to update the oldest and delete the others, or remove them first with `polyctl dns delete`",
					ErrAmbiguous, d.label(), len(recs), d.Name, d.Type)
			}
			if keep < 0 {
				keep = 0
			}
			others := len(recs) - 1
			note := fmt.Sprintf("%d other record(s) of %s %s left alone", others, d.Name, d.Type)
			if in.PruneDuplicates {
				note = fmt.Sprintf("%d duplicate(s) deleted", others)
				for i, r := range recs {
					if i != keep {
						deletes = append(deletes, in.deleteStep(d, r))
					}
				}
			}
			add(d, in.updateOrKeep(d, recs[keep], note))
		}
	}

	// Every name that holds records of other types is decided, each of them
	// before anything is written.
	replaced := map[string]OccupiedName{}
	for _, o := range occupiedNames(in) {
		replace, err := false, error(nil)
		if err := in.irreplaceable(o); err != nil {
			return nil, err
		}
		if in.Decide == nil {
			err = o.Refusal()
		} else {
			replace, err = in.Decide(o)
		}
		if err != nil {
			return nil, err
		}
		if replace {
			replaced[o.FQDN] = o
		}
	}

	plan := &Plan{}
	started := map[string]bool{}
	for _, s := range steps {
		if o, ok := replaced[s.d.FQDN]; ok && s.step.Action != Skipped {
			if !started[o.FQDN] {
				started[o.FQDN] = true
				for i, r := range o.Others {
					// A delete after the first fails with the records of the
					// name already deleted gone.
					plan.Add(in.restorable(o.Others[:i], replacedLead(o, i), in.replaceStep(o, r)))
				}
			}
			s.step = in.restorable(o.Others, replacesLead(len(o.Others)), s.step)
		}
		plan.Add(s.step)
	}
	plan.Add(deletes...)
	return plan, nil
}

// replaceStep deletes r, a record of o that the desired records of o
// replace. Its attrs keep the full data of the record, as the report of
// `dns delete --all` does, and replaced_by the types that replace it.
func (in DNSEnsure) replaceStep(o OccupiedName, r Record) Step {
	attrs := recordAttrs(r)
	attrs["replaced_by"] = strings.Join(o.Types, ",")
	return Step{
		Resource: "dns-record/" + o.Name + "/" + strings.ToUpper(r.Type),
		Action:   Deleted,
		ID:       r.ID,
		Desc:     recordDisplay(in.Platform, r) + "; replaced by " + o.What(),
		Attrs:    attrs,
		Apply: func(ctx context.Context) (Change, error) {
			if err := in.DNS.DeleteRecord(ctx, in.ZoneID, r.ID); err != nil {
				return Change{}, fmt.Errorf("delete %s %s (%s) to replace it with %s: %w", o.FQDN, strings.ToUpper(r.Type), r.ID, o.What(), err)
			}
			if in.Removed != nil {
				in.Removed(ctx, r.ID)
			}
			return Change{}, nil
		},
	}
}

// replacesLead introduces the records a failed write of desired records
// replaces, n of them deleted before it.
func replacesLead(n int) string {
	if n == 1 {
		return "the record it replaces was deleted before and is gone: "
	}
	return fmt.Sprintf("the %d records it replaces were deleted before and are gone: ", n)
}

// replacedLead introduces the records of o deleted before its i-th replaced
// record, whose delete failed.
func replacedLead(o OccupiedName, i int) string {
	if i == 1 {
		return fmt.Sprintf("the record of %s deleted before it to make room for %s is gone: ", o.FQDN, o.What())
	}
	return fmt.Sprintf("the %d records of %s deleted before it to make room for %s are gone: ", i, o.FQDN, o.What())
}

// restorable makes the error of a step that runs after the records gone
// were deleted to make room for desired records say so: after lead, it
// names each deleted record with its name, type, value and TTL and the
// command that writes it again (Restore). The error is a general one (exit
// code 1) whatever the step failed for. With nothing gone, s is returned as
// it is.
func (in DNSEnsure) restorable(gone []Record, lead string, s Step) Step {
	apply := s.Apply
	if apply == nil || len(gone) == 0 {
		return s
	}
	s.Apply = func(ctx context.Context) (Change, error) {
		ch, err := apply(ctx)
		if err == nil {
			return ch, nil
		}
		var b strings.Builder
		fmt.Fprintf(&b, "%v; %s", err, lead)
		for i, r := range gone {
			if i > 0 {
				b.WriteString("; ")
			}
			fmt.Fprintf(&b, "%s %s %s", NormalizeDomain(r.Name), strings.ToUpper(r.Type), recordDisplay(in.Platform, r))
			if in.Restore != nil {
				fmt.Fprintf(&b, " (restore it with: %s)", in.Restore(r))
			}
		}
		return ch, errors.New(b.String())
	}
	return s
}

func article(typ string) string {
	if strings.HasPrefix(typ, "A") {
		return "an"
	}
	return "a"
}

// sortOldestFirst orders the records of one name and type: by creation
// time when every record carries one (Cloudflare's created_on), else by id.
func sortOldestFirst(recs []Record) {
	created := func(r Record) string {
		s, _ := r.Extra["created_on"].(string)
		return s
	}
	byTime := true
	for _, r := range recs {
		if created(r) == "" {
			byTime = false
		}
	}
	sort.SliceStable(recs, func(i, j int) bool {
		if byTime && created(recs[i]) != created(recs[j]) {
			return created(recs[i]) < created(recs[j])
		}
		return recs[i].ID < recs[j].ID
	})
}

// findValue returns the record of recs whose value (and, when given, MX
// priority) is the desired one.
func findValue(recs []Record, d DesiredRecord) (Record, bool) {
	if i := findValueIndex(recs, d); i >= 0 {
		return recs[i], true
	}
	return Record{}, false
}

// findValueIndex is findValue returning the index of the first such
// record, or -1.
func findValueIndex(recs []Record, d DesiredRecord) int {
	want := compareValue(d.Type, d.Value, d.Priority)
	for i, r := range recs {
		if existingCompareValue(r) != want {
			continue
		}
		if d.Type == "MX" && d.Priority != nil && (r.Priority == nil || *r.Priority != *d.Priority) {
			continue
		}
		return i
	}
	return -1
}

func (in DNSEnsure) record(d DesiredRecord) Record {
	r := Record{ZoneID: in.ZoneID, Name: d.FQDN, Type: d.Type, Value: d.Value, Priority: d.Priority, Proxied: d.Proxied}
	if d.TTL != nil {
		r.TTL = *d.TTL
	}
	return r
}

func (in DNSEnsure) createStep(d DesiredRecord) (Step, error) {
	if d.Type == "MX" && d.Priority == nil {
		return Step{}, invalid("%s: an MX record needs a priority (write the value as \"10 mail.example.com\", or give priority in the records file)", d.label())
	}
	return Step{
		Resource: d.Resource(),
		Action:   Created,
		Desc:     desiredDisplay(in.Platform, d),
		Apply: func(ctx context.Context) (Change, error) {
			out, err := in.DNS.CreateRecord(ctx, in.ZoneID, in.record(d))
			if err != nil {
				return Change{}, fmt.Errorf("%s: %w", d.label(), err)
			}
			if out == nil {
				return Change{}, nil
			}
			if in.Written != nil {
				in.Written(ctx, "", *out)
			}
			return Change{ID: out.ID}, nil
		},
	}, nil
}

func (in DNSEnsure) updateOrKeep(d DesiredRecord, cur Record, note string) Step {
	diff := DiffRecord(in.Platform, cur, d)
	join := func(s string) string {
		if note == "" {
			return s
		}
		return s + "; " + note
	}
	if len(diff) == 0 {
		return Step{Resource: d.Resource(), Action: Unchanged, ID: cur.ID, Desc: join(recordDisplay(in.Platform, cur))}
	}
	var parts, fields []string
	attrs := map[string]string{}
	var patch RecordPatch
	for _, c := range diff {
		parts = append(parts, c.Field+" "+c.Old+" -> "+c.New)
		fields = append(fields, c.Field)
		switch c.Field {
		case "value":
			v := d.Value
			patch.Value = &v
			attrs["old_value"], attrs["new_value"] = c.Old, c.New
		case "ttl":
			patch.TTL = d.TTL
			attrs["old_ttl"], attrs["new_ttl"] = c.Old, c.New
		case "proxied":
			patch.Proxied = d.Proxied
			attrs["old_proxied"], attrs["new_proxied"] = c.Old, c.New
		case "priority":
			patch.Priority = d.Priority
			attrs["old_priority"], attrs["new_priority"] = c.Old, c.New
		}
	}
	attrs["changed"] = strings.Join(fields, ",")
	return Step{
		Resource: d.Resource(),
		Action:   Updated,
		ID:       cur.ID,
		Desc:     join(strings.Join(parts, "; ")),
		Attrs:    attrs,
		Apply: func(ctx context.Context) (Change, error) {
			var out *Record
			var err error
			if pr, ok := in.DNS.(RecordPatcher); ok {
				out, err = pr.PatchRecord(ctx, in.ZoneID, cur, patch)
			} else {
				rec := cur
				rec.ZoneID = in.ZoneID
				if patch.Value != nil {
					rec.Value = *patch.Value
				}
				if patch.TTL != nil {
					rec.TTL = *patch.TTL
				}
				if patch.Proxied != nil {
					rec.Proxied = patch.Proxied
				}
				if patch.Priority != nil {
					rec.Priority = patch.Priority
				}
				if rec.Type == "SRV" && patch.Value != nil {
					// The new value holds the priority in front.
					rec.Priority = nil
				}
				out, err = in.DNS.UpdateRecord(ctx, in.ZoneID, rec)
			}
			if err != nil {
				return Change{}, fmt.Errorf("%s: %w", d.label(), err)
			}
			ch := Change{}
			if out != nil {
				ch.ID = out.ID
				if in.Written != nil {
					in.Written(ctx, cur.ID, *out)
				}
			}
			return ch, nil
		},
	}
}

func (in DNSEnsure) deleteStep(d DesiredRecord, r Record) Step {
	return Step{
		Resource: d.Resource(),
		Action:   Deleted,
		ID:       r.ID,
		Desc:     "duplicate " + recordDisplay(in.Platform, r),
		Apply: func(ctx context.Context) (Change, error) {
			if err := in.DNS.DeleteRecord(ctx, in.ZoneID, r.ID); err != nil {
				return Change{}, fmt.Errorf("%s: delete duplicate %s: %w", d.label(), r.ID, err)
			}
			if in.Removed != nil {
				in.Removed(ctx, r.ID)
			}
			return Change{}, nil
		},
	}
}
