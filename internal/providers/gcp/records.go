package gcp

import (
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"google.golang.org/api/dns/v1"

	"github.com/gofika/polyctl/internal/platform"
)

// defaultTTL is used for new record sets when the caller does not specify one.
const defaultTTL = 300

// Cloud DNS stores records as multi-value resource record sets without
// per-value identifiers. polyctl exposes one platform.Record per rrdata
// value and encodes a stable identifier as "<zone>|<TYPE>|<fqdn>|<rrdata>",
// where the rrdata segment is query-escaped so values containing '|'
// survive. The managed zone name is part of the id because a project may
// hold a public and a private zone with the same dnsName (split-horizon),
// and the inventory keys records by id alone.

// routingPolicyMarker is the rrdata segment used for the read-only record
// that stands in for a record set driven by a routing policy.
const routingPolicyMarker = "routing-policy"

// routingPolicyValue is shown as the value of such a record.
const routingPolicyValue = "<routing policy>"

// encodeRecordID builds the per-value record identifier. zoneID is the
// managed zone name, fqdn the record name without trailing dot and rrdata
// the raw Cloud DNS value.
func encodeRecordID(zoneID, typ, fqdn, rrdata string) string {
	return zoneID + "|" + strings.ToUpper(typ) + "|" + platform.NormalizeDomain(fqdn) + "|" + url.QueryEscape(rrdata)
}

// decodeRecordID splits an identifier produced by encodeRecordID.
func decodeRecordID(id string) (zoneID, typ, fqdn, rrdata string, err error) {
	parts := strings.SplitN(id, "|", 4)
	if len(parts) != 4 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", "", fmt.Errorf("invalid Cloud DNS record id %q (expected zone|TYPE|name|value)", id)
	}
	v, err := url.QueryUnescape(parts[3])
	if err != nil {
		return "", "", "", "", fmt.Errorf("invalid Cloud DNS record id %q: %w", id, err)
	}
	return parts[0], strings.ToUpper(parts[1]), platform.NormalizeDomain(parts[2]), v, nil
}

// dnsName converts a FQDN (without trailing dot) into Cloud DNS form.
func dnsName(fqdn string) string {
	return platform.NormalizeDomain(fqdn) + "."
}

// ensureDot appends a trailing dot to a hostname unless already present.
func ensureDot(host string) string {
	host = strings.TrimSpace(host)
	if host == "" || strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}

// hostTypes are record types whose rrdata is (or ends with) a hostname that
// Cloud DNS writes with a trailing dot.
func isHostType(typ string) bool {
	switch strings.ToUpper(typ) {
	case "CNAME", "NS", "PTR", "DNAME", "ALIAS":
		return true
	}
	return false
}

// recordsFromRRSet expands a Cloud DNS record set into one Record per value.
// A set driven by a routing policy (geo, weighted, failover) carries no
// plain rrdatas; it is surfaced as a single read-only record so that
// listings and the inventory show it, while mutations refuse it.
func recordsFromRRSet(zoneID string, rs *dns.ResourceRecordSet) []platform.Record {
	if rs == nil {
		return nil
	}
	fqdn := platform.NormalizeDomain(rs.Name)
	typ := strings.ToUpper(rs.Type)
	out := make([]platform.Record, 0, len(rs.Rrdatas)+1)
	if rs.RoutingPolicy != nil {
		out = append(out, platform.Record{
			ID:     encodeRecordID(zoneID, typ, fqdn, routingPolicyMarker),
			ZoneID: zoneID,
			Name:   fqdn,
			Type:   typ,
			TTL:    int(rs.Ttl),
			Value:  routingPolicyValue,
			Extra:  map[string]any{"routing_policy": rs.RoutingPolicy},
		})
	}
	for _, v := range rs.Rrdatas {
		r := platform.Record{
			ID:     encodeRecordID(zoneID, typ, fqdn, v),
			ZoneID: zoneID,
			Name:   fqdn,
			Type:   typ,
			TTL:    int(rs.Ttl),
			Extra:  map[string]any{"rrdata": v},
		}
		r.Value, r.Priority = splitRRData(typ, v)
		out = append(out, r)
	}
	return out
}

// splitRRData converts a raw rrdata value into Record.Value and Priority.
func splitRRData(typ, v string) (string, *int) {
	switch strings.ToUpper(typ) {
	case "MX", "SRV":
		fields := strings.Fields(v)
		if len(fields) >= 2 {
			if p, err := strconv.Atoi(fields[0]); err == nil {
				rest := fields[1:]
				rest[len(rest)-1] = strings.TrimSuffix(rest[len(rest)-1], ".")
				return strings.Join(rest, " "), &p
			}
		}
		return strings.TrimSuffix(v, "."), nil
	case "TXT":
		if u, ok := unquoteTXT(v); ok {
			return u, nil
		}
		return v, nil
	}
	if isHostType(typ) {
		return strings.TrimSuffix(v, "."), nil
	}
	return v, nil
}

// unquoteTXT strips the outer quotes of a single-string TXT rrdata
// (`"v=spf1 -all"` -> `v=spf1 -all`) and restores escaped quotes, so that
// Value matches what a user types; quoteTXT is its inverse. Multi-string
// rrdatas (`"a" "b"`) and unquoted values are returned unchanged with ok
// false.
func unquoteTXT(v string) (string, bool) {
	if len(v) < 2 || !strings.HasPrefix(v, "\"") || !strings.HasSuffix(v, "\"") {
		return v, false
	}
	inner := v[1 : len(v)-1]
	var b strings.Builder
	b.Grow(len(inner))
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		switch {
		case c == '\\' && i+1 < len(inner):
			if inner[i+1] == '"' {
				b.WriteByte('"')
			} else {
				b.WriteByte(c)
				b.WriteByte(inner[i+1])
			}
			i++
		case c == '\\':
			// A trailing backslash would have escaped the closing quote.
			return v, false
		case c == '"':
			return v, false // multiple quoted strings
		default:
			b.WriteByte(c)
		}
	}
	return b.String(), true
}

// rrdataFromRecord converts a Record (Value + Priority) into the raw value
// Cloud DNS expects, re-adding trailing dots on hostnames and quoting TXT.
func rrdataFromRecord(r platform.Record) (string, error) {
	typ := strings.ToUpper(r.Type)
	content := strings.TrimSpace(r.Value)
	if content == "" {
		return "", fmt.Errorf("record value is required")
	}
	switch typ {
	case "MX", "SRV":
		fields := strings.Fields(content)
		prio := r.Priority
		if prio == nil {
			// Accept "10 mail.example.com" when no explicit priority was given.
			if len(fields) >= 2 {
				if p, err := strconv.Atoi(fields[0]); err == nil {
					prio = &p
					fields = fields[1:]
				}
			}
		}
		if prio == nil {
			return "", fmt.Errorf("%s records need --priority", typ)
		}
		if typ == "MX" && len(fields) != 1 {
			return "", fmt.Errorf("MX value must be a single mail server hostname")
		}
		if typ == "SRV" && len(fields) != 3 {
			return "", fmt.Errorf("SRV value must be \"<weight> <port> <target>\"")
		}
		fields[len(fields)-1] = ensureDot(fields[len(fields)-1])
		return fmt.Sprintf("%d %s", *prio, strings.Join(fields, " ")), nil
	case "TXT":
		return quoteTXT(content), nil
	}
	if isHostType(typ) {
		return ensureDot(content), nil
	}
	return content, nil
}

// quoteTXT wraps a TXT value in double quotes unless it already looks like a
// quoted (possibly multi-string) rrdata.
func quoteTXT(s string) string {
	if strings.HasPrefix(s, "\"") && strings.HasSuffix(s, "\"") && len(s) >= 2 {
		return s
	}
	return "\"" + strings.ReplaceAll(s, "\"", "\\\"") + "\""
}

// removeValue returns values without v and whether v was present.
func removeValue(values []string, v string) ([]string, bool) {
	out := make([]string, 0, len(values))
	found := false
	for _, x := range values {
		if x == v {
			found = true
			continue
		}
		out = append(out, x)
	}
	return out, found
}

// containsValue reports whether v is in values.
func containsValue(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

// sameValues reports whether a and b hold the same values in the same order.
func sameValues(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
