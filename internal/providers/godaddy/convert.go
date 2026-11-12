package godaddy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
)

// domainFromAPI converts a GoDaddy domain into the neutral representation.
func domainFromAPI(d apiDomain) platform.Domain {
	out := platform.Domain{
		Name:        platform.NormalizeDomain(d.Domain),
		Nameservers: append([]string(nil), d.NameServers...),
		Status:      d.Status,
		ExpiresAt:   d.Expires,
		AutoRenew:   d.RenewAuto,
		Locked:      d.Locked,
		Privacy:     d.Privacy,
	}
	extra := map[string]any{}
	if d.DomainID != 0 {
		extra["domain_id"] = d.DomainID
	}
	if d.CreatedAt != "" {
		extra["created_at"] = d.CreatedAt
	}
	if d.Renewable != nil {
		extra["renewable"] = *d.Renewable
	}
	if d.ExpirationProtected != nil {
		extra["expiration_protected"] = *d.ExpirationProtected
	}
	if d.TransferProtected != nil {
		extra["transfer_protected"] = *d.TransferProtected
	}
	if d.HoldRegistrar != nil {
		extra["hold_registrar"] = *d.HoldRegistrar
	}
	if len(extra) > 0 {
		out.Extra = extra
	}
	return out
}

// zoneFromDomain exposes a registered domain as a DNS zone: GoDaddy hosts
// one zone per domain and both are identified by the domain name.
func zoneFromDomain(d platform.Domain) platform.Zone {
	return platform.Zone{ID: d.Name, Name: d.Name, Nameservers: d.Nameservers, Status: d.Status}
}

// srvLabels splits a GoDaddy SRV record into its service, protocol and
// owner name. GoDaddy stores "_sip" / "_tcp" separately from the name.
func srvLabels(r apiRecord) (service, protocol, name string) {
	service, protocol, name = r.Service, r.Protocol, r.Name
	if name == "" {
		name = "@"
	}
	if service != "" && protocol != "" {
		return service, protocol, name
	}
	// Fall back to parsing "_service._proto.rest".
	labels := strings.Split(name, ".")
	if len(labels) >= 2 && strings.HasPrefix(labels[0], "_") && strings.HasPrefix(labels[1], "_") {
		rest := strings.Join(labels[2:], ".")
		if rest == "" {
			rest = "@"
		}
		return labels[0], labels[1], rest
	}
	return service, protocol, name
}

// recordFromAPI converts a GoDaddy record of zone into the neutral form.
// Name becomes the FQDN; the synthesized ID keeps the GoDaddy-native name.
func recordFromAPI(zone string, r apiRecord) platform.Record {
	zone = platform.NormalizeDomain(zone)
	typ := strings.ToUpper(r.Type)
	name := r.Name
	if name == "" {
		name = "@"
	}
	out := platform.Record{
		ID:     EncodeRecordID(typ, name, r.Data),
		ZoneID: zone,
		Name:   platform.FQDN(name, zone),
		Type:   typ,
		Value:  r.Data,
		TTL:    r.TTL,
	}
	if r.Priority != nil && (typ == "MX" || typ == "SRV") {
		p := *r.Priority
		out.Priority = &p
	}
	if typ == "SRV" {
		service, protocol, owner := srvLabels(r)
		if service != "" && protocol != "" {
			base := zone
			if owner != "@" {
				base = platform.FQDN(owner, zone)
			}
			out.Name = service + "." + protocol + "." + base
		}
		extra := map[string]any{}
		if service != "" {
			extra["service"] = service
		}
		if protocol != "" {
			extra["protocol"] = protocol
		}
		if r.Port != nil {
			extra["port"] = *r.Port
		}
		if r.Weight != nil {
			extra["weight"] = *r.Weight
		}
		if len(extra) > 0 {
			out.Extra = extra
		}
	}
	return out
}

// recordToAPI converts a neutral record into the GoDaddy form. The returned
// Name is relative to zone ("@" for the apex).
func recordToAPI(zone string, r platform.Record) (apiRecord, error) {
	zone = platform.NormalizeDomain(zone)
	typ := strings.ToUpper(strings.TrimSpace(r.Type))
	if typ == "" {
		return apiRecord{}, fmt.Errorf("record type is required")
	}
	if strings.TrimSpace(r.Value) == "" {
		return apiRecord{}, fmt.Errorf("record value is required")
	}
	if r.TTL < 0 {
		return apiRecord{}, fmt.Errorf("record ttl must not be negative")
	}
	out := apiRecord{
		Type: typ,
		Name: platform.RelativeName(r.Name, zone),
		Data: r.Value,
		TTL:  r.TTL,
	}
	if r.Priority != nil {
		p := *r.Priority
		out.Priority = &p
	}
	if typ == "SRV" {
		out.Service = extraString(r.Extra, "service")
		out.Protocol = extraString(r.Extra, "protocol")
		out.Port = extraInt(r.Extra, "port")
		out.Weight = extraInt(r.Extra, "weight")
		// Strip "_service._proto." from the owner name; GoDaddy stores
		// those labels in separate fields.
		if service, protocol, owner := srvLabels(apiRecord{Name: out.Name}); service != "" && protocol != "" {
			out.Name = owner
			if out.Service == "" {
				out.Service = service
			}
			if out.Protocol == "" {
				out.Protocol = protocol
			}
		}
		if out.Service == "" || out.Protocol == "" {
			return apiRecord{}, fmt.Errorf("SRV records need a name of the form _service._proto[.owner] or extra.service/extra.protocol")
		}
		if out.Port == nil {
			return apiRecord{}, fmt.Errorf("SRV records need extra.port")
		}
		if out.Weight == nil {
			w := 0
			out.Weight = &w
		}
		if out.Priority == nil {
			p := 0
			out.Priority = &p
		}
	}
	if typ == "MX" && out.Priority == nil {
		p := 0
		out.Priority = &p
	}
	return out, nil
}

func extraString(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	switch v := m[key].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

// extraInt reads an integer from a record's Extra map; values that went
// through JSON (inventory cache) arrive as float64 or json.Number.
func extraInt(m map[string]any, key string) *int {
	if m == nil {
		return nil
	}
	var n int
	switch v := m[key].(type) {
	case nil:
		return nil
	case int:
		n = v
	case int64:
		n = int(v)
	case float64:
		n = int(v)
	case json.Number:
		i, err := v.Int64()
		if err != nil {
			return nil
		}
		n = int(i)
	case string:
		i, err := strconv.Atoi(v)
		if err != nil {
			return nil
		}
		n = i
	default:
		return nil
	}
	return &n
}

// keyPrefix returns the non-sensitive leading characters of an API key id.
func keyPrefix(key string) string {
	if len(key) > 6 {
		return key[:6]
	}
	return key
}

// fingerprint returns a short one-way digest of a secret: enough to tell two
// tokens apart without revealing any part of either.
func fingerprint(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:4])
}
