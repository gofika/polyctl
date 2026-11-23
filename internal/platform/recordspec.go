package platform

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"slices"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// RecordSpec is a desired DNS record, as written on the command line
// ("name:type:value[:ttl[:proxied]]") or in a records file. TTL, Proxied
// and Priority are nil when not given: "keep what the record has".
type RecordSpec struct {
	// Name is relative to the zone ("www", "@"), or a FQDN.
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type" yaml:"type"`
	Value    string `json:"value" yaml:"value"`
	TTL      *int   `json:"ttl,omitempty" yaml:"ttl,omitempty"`
	Proxied  *bool  `json:"proxied,omitempty" yaml:"proxied,omitempty"`
	Priority *int   `json:"priority,omitempty" yaml:"priority,omitempty"`
}

// RecordSpecFormat is the inline syntax, for error messages.
const RecordSpecFormat = "name:type:value[:ttl[:proxied]], e.g. www:A:203.0.113.10:300:true or @:CNAME:example.com"

// RecordSpecTypes are the record types a spec may name. SOA is managed by
// the platforms and never accepted. Whether a platform can create a type is
// for its provider to say.
var RecordSpecTypes = []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA", "PTR", "NAPTR", "SPF", "TLSA", "URI", "CERT", "DNSKEY", "DS"}

// proxiableTypes are the types Cloudflare can proxy.
var proxiableTypes = []string{"A", "AAAA", "CNAME"}

// ParseRecordSpec parses "name:type:value[:ttl[:proxied]]".
//
// name and type are the first two fields; the rest is the value with an
// optional TTL (seconds, or "auto" / empty for "not given") and an optional
// proxied flag (true or false, only after a TTL field) peeled off from the
// right. Values may contain colons (IPv6 addresses, TXT text). For A and
// AAAA records a split is accepted only when the value is an address of
// that family; when the text can be read in more than one way (2001:db8::1:300
// is an address, and also 2001:db8::1 with TTL 300) nothing is guessed: it
// is an error, and the record has to be written in a records file. For the
// other types the TTL and proxied fields are peeled off whenever they look
// like ones, so a free-text value that itself ends in ":<number>" needs a
// records file too.
func ParseRecordSpec(s string) (RecordSpec, error) {
	bad := func(format string, args ...any) (RecordSpec, error) {
		return RecordSpec{}, fmt.Errorf("invalid record %q: %s (format %s)", s, fmt.Sprintf(format, args...), RecordSpecFormat)
	}
	parts := strings.SplitN(s, ":", 3)
	if len(parts) < 3 {
		return bad("expected at least name, type and value")
	}
	spec := RecordSpec{Name: strings.TrimSpace(parts[0]), Type: strings.ToUpper(strings.TrimSpace(parts[1]))}
	if err := checkSpecType(spec.Type); err != nil {
		return bad("%v", err)
	}
	rest := parts[2]
	type cand struct {
		value   string
		ttl     string
		proxied string
	}
	var cands []cand
	// value:ttl:proxied
	if i := strings.LastIndexByte(rest, ':'); i >= 0 {
		head, last := rest[:i], rest[i+1:]
		if isBoolField(last) {
			if j := strings.LastIndexByte(head, ':'); j >= 0 && isTTLField(head[j+1:]) {
				cands = append(cands, cand{value: head[:j], ttl: head[j+1:], proxied: last})
			}
		}
		// value:ttl
		if isTTLField(last) && last != "" {
			cands = append(cands, cand{value: head, ttl: last})
		}
	}
	cands = append(cands, cand{value: rest})
	var valid []cand
	for i, c := range cands {
		// A split that leaves the value ending in a colon cut through
		// something (the "::" of an IPv6 address): not a reading.
		// (Addresses are checked as addresses instead: "::" is one.)
		ip := spec.Type == "A" || spec.Type == "AAAA"
		if !ip && i < len(cands)-1 && strings.HasSuffix(strings.TrimSpace(c.value), ":") {
			continue
		}
		if validSpecValue(spec.Type, c.value) {
			valid = append(valid, c)
		}
	}
	if len(valid) == 0 {
		if spec.Type == "A" || spec.Type == "AAAA" {
			return bad("the value is not an IPv%s address", map[string]string{"A": "4", "AAAA": "6"}[spec.Type])
		}
		if strings.TrimSpace(rest) == "" {
			return bad("the value is empty")
		}
		return bad("value %q is not valid for a %s record", rest, spec.Type)
	}
	if len(valid) > 1 && (spec.Type == "A" || spec.Type == "AAAA") {
		return bad("the value can be read in more than one way (%q or %q); write this record in a records file (--file)", valid[0].value, valid[len(valid)-1].value)
	}
	c := valid[0]
	spec.Value = strings.TrimSpace(c.value)
	if t := strings.ToLower(strings.TrimSpace(c.ttl)); t != "" && t != "auto" {
		n, err := strconv.Atoi(t)
		if err != nil || n < 0 {
			return bad("TTL %q is not a number of seconds", c.ttl)
		}
		spec.TTL = &n
	}
	if c.proxied != "" {
		b := strings.EqualFold(c.proxied, "true")
		spec.Proxied = &b
	}
	if err := spec.Validate(); err != nil {
		return bad("%v", err)
	}
	return spec, nil
}

func isBoolField(s string) bool { return strings.EqualFold(s, "true") || strings.EqualFold(s, "false") }

func isTTLField(s string) bool {
	if s == "" || strings.EqualFold(s, "auto") {
		return true
	}
	for _, r := range s {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validSpecValue(typ, v string) bool {
	v = strings.TrimSpace(v)
	if v == "" {
		return false
	}
	switch typ {
	case "A":
		a, err := netip.ParseAddr(v)
		return err == nil && a.Is4()
	case "AAAA":
		a, err := netip.ParseAddr(v)
		return err == nil && a.Is6() && !a.Is4In6()
	case "CNAME", "NS", "PTR":
		return !strings.ContainsAny(v, ": ")
	}
	return true
}

func checkSpecType(t string) error {
	switch {
	case t == "":
		return errors.New("the type is empty")
	case t == "SOA":
		return errors.New("SOA records are managed by the platform and cannot be set")
	case !slices.Contains(RecordSpecTypes, t):
		return fmt.Errorf("unknown record type %q (expected one of %s)", t, strings.Join(RecordSpecTypes, " "))
	}
	return nil
}

// Validate checks a spec that did not come through ParseRecordSpec (a
// records file).
func (r RecordSpec) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return errors.New("the name is empty (use @ for the zone apex)")
	}
	if err := checkSpecType(r.Type); err != nil {
		return err
	}
	if !validSpecValue(r.Type, r.Value) {
		if r.Type == "A" || r.Type == "AAAA" {
			return fmt.Errorf("value %q is not an IPv%s address", r.Value, map[string]string{"A": "4", "AAAA": "6"}[r.Type])
		}
		return fmt.Errorf("value %q is not valid for a %s record", r.Value, r.Type)
	}
	if r.TTL != nil && *r.TTL < 0 {
		return fmt.Errorf("TTL %d is negative", *r.TTL)
	}
	if r.Proxied != nil && !slices.Contains(proxiableTypes, r.Type) {
		return fmt.Errorf("proxied applies to A, AAAA and CNAME records only, not %s", r.Type)
	}
	if r.Priority != nil && r.Type != "MX" {
		return fmt.Errorf("priority applies to MX records only (an SRV record carries it in its value)")
	}
	return nil
}

// FQDN returns the record's name under zone. "@" is the apex; a name with
// a trailing dot is absolute and must lie in the zone; other names are
// relative unless they already end with the zone.
func (r RecordSpec) FQDN(zone string) (string, error) {
	name := strings.TrimSpace(r.Name)
	zone = NormalizeDomain(zone)
	if strings.HasSuffix(name, ".") {
		n := NormalizeDomain(name)
		if n != zone && !strings.HasSuffix(n, "."+zone) {
			return "", fmt.Errorf("record name %q is not in zone %s", name, zone)
		}
		return n, nil
	}
	return FQDN(name, zone), nil
}

// recordsFile is the YAML shape of a records file.
type recordsFile struct {
	Records []fileRecord `yaml:"records"`
}

type fileRecord struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"`
	Value    string `yaml:"value"`
	TTL      any    `yaml:"ttl"`
	Proxied  *bool  `yaml:"proxied"`
	Priority *int   `yaml:"priority"`
}

// ParseRecordFile reads a records file:
//
//	records:
//	  - name: www
//	    type: A
//	    value: 203.0.113.10
//	    ttl: 300          # optional; a number or auto
//	    proxied: true     # optional
//	  - name: "@"
//	    type: MX
//	    value: mail.example.com
//	    priority: 10      # MX only
//
// Unknown fields are errors, so that a typo is not silently dropped.
func ParseRecordFile(r io.Reader) ([]RecordSpec, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var f recordsFile
	if err := dec.Decode(&f); err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("records file is empty")
		}
		return nil, fmt.Errorf("records file: %w", err)
	}
	out := make([]RecordSpec, 0, len(f.Records))
	for i, fr := range f.Records {
		spec := RecordSpec{Name: fr.Name, Type: strings.ToUpper(strings.TrimSpace(fr.Type)), Value: fr.Value, Proxied: fr.Proxied, Priority: fr.Priority}
		switch v := fr.TTL.(type) {
		case nil:
		case int:
			spec.TTL = &v
		case string:
			if !strings.EqualFold(strings.TrimSpace(v), "auto") && strings.TrimSpace(v) != "" {
				n, err := strconv.Atoi(strings.TrimSpace(v))
				if err != nil {
					return nil, fmt.Errorf("records file: record %d: ttl %q is not a number of seconds or auto", i+1, v)
				}
				spec.TTL = &n
			}
		default:
			return nil, fmt.Errorf("records file: record %d: ttl must be a number of seconds or auto", i+1)
		}
		if err := spec.Validate(); err != nil {
			return nil, fmt.Errorf("records file: record %d: %v", i+1, err)
		}
		out = append(out, spec)
	}
	return out, nil
}
