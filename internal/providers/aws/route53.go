package aws

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53"
	r53types "github.com/aws/aws-sdk-go-v2/service/route53/types"

	"github.com/gofika/polyctl/internal/platform"
)

const (
	hostedZonePrefix = "/hostedzone/"
	defaultTTL       = 300
	recordIDSep      = "|"
)

// zoneID strips the "/hostedzone/" prefix Route 53 puts in front of ids.
func zoneID(s string) string {
	return strings.TrimPrefix(strings.TrimSpace(s), hostedZonePrefix)
}

// unescapeRRName decodes the octal escapes (\052 for "*", ...) Route 53 uses
// in record and zone names and strips the trailing dot.
func unescapeRRName(s string) string {
	if strings.Contains(s, `\`) {
		var b strings.Builder
		for i := 0; i < len(s); i++ {
			if s[i] == '\\' && i+4 <= len(s) {
				if v, err := strconv.ParseUint(s[i+1:i+4], 8, 8); err == nil {
					b.WriteByte(byte(v))
					i += 3
					continue
				}
			}
			if s[i] == '\\' && i+1 < len(s) {
				b.WriteByte(s[i+1])
				i++
				continue
			}
			b.WriteByte(s[i])
		}
		s = b.String()
	}
	return platform.NormalizeDomain(s)
}

// rrName is the Route 53 form of a FQDN (trailing dot).
func rrName(fqdn string) string { return platform.NormalizeDomain(fqdn) + "." }

// encodeRecordID builds the stable per-value record id
// "<zone>|<TYPE>|<fqdn>|<setIdentifier>|<value>", each part URL-encoded so
// the separator can never appear inside a part. The hosted zone id is part
// of the id because split-horizon setups (a public and a private zone of
// the same name) hold records whose other key parts are identical, and
// the inventory needs the id to be unique within a profile.
func encodeRecordID(zone, typ, fqdn, setID, value string) string {
	parts := []string{zoneID(zone), strings.ToUpper(typ), platform.NormalizeDomain(fqdn), setID, value}
	for i, p := range parts {
		parts[i] = url.QueryEscape(p)
	}
	return strings.Join(parts, recordIDSep)
}

// decodeRecordID is the inverse of encodeRecordID.
func decodeRecordID(id string) (zone, typ, fqdn, setID, value string, err error) {
	parts := strings.Split(id, recordIDSep)
	if len(parts) != 5 {
		return "", "", "", "", "", fmt.Errorf("invalid Route 53 record id %q (expected zone|TYPE|name|set-identifier|value)", id)
	}
	dec := make([]string, 5)
	for i, p := range parts {
		if dec[i], err = url.QueryUnescape(p); err != nil {
			return "", "", "", "", "", fmt.Errorf("invalid Route 53 record id %q: %w", id, err)
		}
	}
	return dec[0], strings.ToUpper(dec[1]), platform.NormalizeDomain(dec[2]), dec[3], dec[4], nil
}

// decodeRecordIDIn decodes id and checks that it belongs to zone.
func decodeRecordIDIn(zone, id string) (typ, fqdn, setID, value string, err error) {
	idZone, typ, fqdn, setID, value, err := decodeRecordID(id)
	if err != nil {
		return "", "", "", "", err
	}
	if idZone != zoneID(zone) {
		return "", "", "", "", fmt.Errorf("record %s belongs to hosted zone %s, not %s", id, idZone, zoneID(zone))
	}
	return typ, fqdn, setID, value, nil
}

// txtChunk is the longest character-string Route 53 accepts in a TXT value.
const txtChunk = 255

// isTXT reports whether values of the type are DNS character-strings that
// Route 53 expects in double quotes.
func isTXT(typ string) bool {
	switch strings.ToUpper(typ) {
	case "TXT", "SPF":
		return true
	}
	return false
}

// quoteTXT turns a plain TXT/SPF value into the form Route 53 requires:
// one or more double-quoted strings of at most 255 characters, inner
// quotes and backslashes escaped. Values that already start with a quote
// are passed through unchanged, and other types are never touched.
func quoteTXT(typ, v string) string {
	if !isTXT(typ) || strings.HasPrefix(v, `"`) {
		return v
	}
	var chunks []string
	var cur strings.Builder
	for _, r := range v {
		tok := string(r)
		if r == '"' || r == '\\' {
			tok = `\` + tok
		}
		if cur.Len()+len(tok) > txtChunk {
			chunks = append(chunks, cur.String())
			cur.Reset()
		}
		cur.WriteString(tok)
	}
	chunks = append(chunks, cur.String())
	for i, c := range chunks {
		chunks[i] = `"` + c + `"`
	}
	return strings.Join(chunks, " ")
}

// unquoteTXT is the inverse of quoteTXT for values read from Route 53: the
// quoted strings are unescaped and concatenated so Record.Value carries
// the plain text like every other platform. Unquoted values are returned
// as they are.
func unquoteTXT(typ, v string) string {
	if !isTXT(typ) || !strings.HasPrefix(v, `"`) {
		return v
	}
	var b strings.Builder
	inQuote := false
	for i := 0; i < len(v); i++ {
		c := v[i]
		switch {
		case !inQuote:
			if c == '"' {
				inQuote = true
			}
		case c == '"':
			inQuote = false
		case c == '\\' && i+4 <= len(v):
			if n, err := strconv.ParseUint(v[i+1:i+4], 8, 8); err == nil {
				b.WriteByte(byte(n))
				i += 3
				continue
			}
			fallthrough
		case c == '\\' && i+1 < len(v):
			i++
			b.WriteByte(v[i])
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// hasPriority reports whether the type carries a leading priority/preference number.
func hasPriority(typ string) bool {
	switch strings.ToUpper(typ) {
	case "MX", "SRV":
		return true
	}
	return false
}

// splitPriority separates the leading priority of MX/SRV values.
func splitPriority(typ, value string) (*int, string) {
	if !hasPriority(typ) {
		return nil, value
	}
	fields := strings.Fields(value)
	if len(fields) < 2 {
		return nil, value
	}
	p, err := strconv.Atoi(fields[0])
	if err != nil {
		return nil, value
	}
	return &p, strings.Join(fields[1:], " ")
}

// recordValue is the Route 53 value of a Record (priority re-attached,
// TXT quoted).
func recordValue(r platform.Record) string {
	if hasPriority(r.Type) && r.Priority != nil {
		return fmt.Sprintf("%d %s", *r.Priority, strings.TrimSpace(r.Value))
	}
	return quoteTXT(r.Type, r.Value)
}

func extraString(extra map[string]any, key string) string {
	if extra == nil {
		return ""
	}
	switch v := extra[key].(type) {
	case string:
		return v
	case nil:
		return ""
	default:
		return fmt.Sprint(v)
	}
}

func extraBool(extra map[string]any, key string) bool {
	if extra == nil {
		return false
	}
	switch v := extra[key].(type) {
	case bool:
		return v
	case string:
		return v == "true"
	}
	return false
}

// setExtras returns the routing-policy attributes of a set.
func setExtras(rs r53types.ResourceRecordSet) map[string]any {
	extra := map[string]any{}
	if v := awssdk.ToString(rs.SetIdentifier); v != "" {
		extra["set_identifier"] = v
	}
	if rs.Weight != nil {
		extra["weight"] = *rs.Weight
	}
	if rs.Region != "" {
		extra["region"] = string(rs.Region)
	}
	if rs.Failover != "" {
		extra["failover"] = string(rs.Failover)
	}
	if rs.MultiValueAnswer != nil && *rs.MultiValueAnswer {
		extra["multivalue"] = true
	}
	if v := awssdk.ToString(rs.HealthCheckId); v != "" {
		extra["health_check_id"] = v
	}
	if rs.GeoLocation != nil {
		extra["geolocation"] = strings.TrimSpace(strings.Join([]string{awssdk.ToString(rs.GeoLocation.ContinentCode), awssdk.ToString(rs.GeoLocation.CountryCode), awssdk.ToString(rs.GeoLocation.SubdivisionCode)}, " "))
	}
	if len(extra) == 0 {
		return nil
	}
	return extra
}

// recordsFromSet expands a record set into one Record per value.
func recordsFromSet(zoneID string, rs r53types.ResourceRecordSet) []platform.Record {
	name := unescapeRRName(awssdk.ToString(rs.Name))
	typ := string(rs.Type)
	setID := awssdk.ToString(rs.SetIdentifier)
	ttl := 0
	if rs.TTL != nil {
		ttl = int(*rs.TTL)
	}
	if rs.AliasTarget != nil {
		target := platform.NormalizeDomain(awssdk.ToString(rs.AliasTarget.DNSName))
		extra := setExtras(rs)
		if extra == nil {
			extra = map[string]any{}
		}
		extra["alias"] = true
		extra["alias_zone_id"] = awssdk.ToString(rs.AliasTarget.HostedZoneId)
		extra["evaluate_target_health"] = rs.AliasTarget.EvaluateTargetHealth
		return []platform.Record{{
			ID:     encodeRecordID(zoneID, typ, name, setID, target),
			ZoneID: zoneID,
			Name:   name,
			Type:   typ,
			Value:  target,
			TTL:    ttl,
			Extra:  extra,
		}}
	}
	out := make([]platform.Record, 0, len(rs.ResourceRecords))
	for _, rr := range rs.ResourceRecords {
		value := awssdk.ToString(rr.Value)
		prio, content := splitPriority(typ, value)
		content = unquoteTXT(typ, content)
		out = append(out, platform.Record{
			ID:       encodeRecordID(zoneID, typ, name, setID, value),
			ZoneID:   zoneID,
			Name:     name,
			Type:     typ,
			Value:    content,
			TTL:      ttl,
			Priority: prio,
			Extra:    setExtras(rs),
		})
	}
	return out
}

// setValues lists the raw values of a set.
func setValues(rs *r53types.ResourceRecordSet) []string {
	if rs == nil {
		return nil
	}
	out := make([]string, 0, len(rs.ResourceRecords))
	for _, rr := range rs.ResourceRecords {
		out = append(out, awssdk.ToString(rr.Value))
	}
	return out
}

func containsValue(values []string, v string) bool {
	for _, x := range values {
		if x == v {
			return true
		}
	}
	return false
}

func removeValue(values []string, v string) []string {
	out := make([]string, 0, len(values))
	for _, x := range values {
		if x != v {
			out = append(out, x)
		}
	}
	return out
}

// buildSet makes a value set, carrying over the routing attributes of base.
func buildSet(base *r53types.ResourceRecordSet, fqdn, typ, setID string, ttl int, values []string) r53types.ResourceRecordSet {
	rs := r53types.ResourceRecordSet{
		Name: awssdk.String(rrName(fqdn)),
		Type: r53types.RRType(strings.ToUpper(typ)),
		TTL:  awssdk.Int64(int64(ttl)),
	}
	if setID != "" {
		rs.SetIdentifier = awssdk.String(setID)
	}
	if base != nil {
		rs.Weight, rs.Region, rs.Failover = base.Weight, base.Region, base.Failover
		rs.MultiValueAnswer, rs.HealthCheckId = base.MultiValueAnswer, base.HealthCheckId
		rs.GeoLocation, rs.GeoProximityLocation, rs.CidrRoutingConfig = base.GeoLocation, base.GeoProximityLocation, base.CidrRoutingConfig
	}
	for _, v := range values {
		rs.ResourceRecords = append(rs.ResourceRecords, r53types.ResourceRecord{Value: awssdk.String(v)})
	}
	return rs
}

// buildAliasSet makes an alias set.
func buildAliasSet(base *r53types.ResourceRecordSet, fqdn, typ, setID, target, targetZone string, evaluate bool) r53types.ResourceRecordSet {
	rs := buildSet(base, fqdn, typ, setID, 0, nil)
	rs.TTL = nil
	rs.AliasTarget = &r53types.AliasTarget{
		DNSName:              awssdk.String(rrName(target)),
		HostedZoneId:         awssdk.String(targetZone),
		EvaluateTargetHealth: evaluate,
	}
	return rs
}

// ListZones lists every hosted zone from the (single, paginated)
// ListHostedZones call. Delegation sets are not fetched here: that is one
// GetHostedZone per zone, see listZonesWithNameservers.
func (c *client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	var out []platform.Zone
	pg := route53.NewListHostedZonesPaginator(c.r53, &route53.ListHostedZonesInput{})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list hosted zones: %w", mapErr(err))
		}
		for _, hz := range page.HostedZones {
			out = append(out, zoneFromHosted(hz))
		}
	}
	sortZones(out)
	return out, nil
}

// sortZones orders zones by name; a public zone sorts before a private
// zone of the same name so the public one is the stable first match.
func sortZones(zones []platform.Zone) {
	sort.SliceStable(zones, func(i, j int) bool {
		if zones[i].Name != zones[j].Name {
			return zones[i].Name < zones[j].Name
		}
		return zones[i].Status == "public" && zones[j].Status != "public"
	})
}

// listZonesWithNameservers lists the zones together with the delegation
// set of every public zone (one GetHostedZone each). A failing
// GetHostedZone is reported as an error, after the SDK retried throttling,
// instead of leaving the nameservers silently empty.
func (c *client) listZonesWithNameservers(ctx context.Context) ([]platform.Zone, error) {
	zones, err := c.ListZones(ctx)
	if err != nil {
		return nil, err
	}
	for i := range zones {
		if zones[i].Status != "public" {
			continue
		}
		gz, err := c.r53.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: awssdk.String(zones[i].ID)})
		if err != nil {
			return nil, fmt.Errorf("get delegation set of hosted zone %s (%s): %w", zones[i].ID, zones[i].Name, mapErr(err))
		}
		if gz.DelegationSet != nil {
			zones[i].Nameservers = append([]string(nil), gz.DelegationSet.NameServers...)
		}
	}
	return zones, nil
}

func zoneFromHosted(hz r53types.HostedZone) platform.Zone {
	z := platform.Zone{
		ID:     zoneID(awssdk.ToString(hz.Id)),
		Name:   unescapeRRName(awssdk.ToString(hz.Name)),
		Status: "public",
		Extra:  map[string]any{},
	}
	if hz.Config != nil {
		if hz.Config.PrivateZone {
			z.Status = "private"
		}
		if c := awssdk.ToString(hz.Config.Comment); c != "" {
			z.Extra["comment"] = c
		}
	}
	if hz.ResourceRecordSetCount != nil {
		z.Extra["record_count"] = *hz.ResourceRecordSetCount
	}
	z.Extra["private"] = z.Status == "private"
	return z
}

// GetZone returns one zone by id.
func (c *client) GetZone(ctx context.Context, id string) (*platform.Zone, error) {
	gz, err := c.r53.GetHostedZone(ctx, &route53.GetHostedZoneInput{Id: awssdk.String(zoneID(id))})
	if err != nil {
		return nil, fmt.Errorf("get hosted zone %s: %w", id, mapErr(err))
	}
	if gz.HostedZone == nil {
		return nil, fmt.Errorf("%w: hosted zone %s", platform.ErrNotFound, id)
	}
	z := zoneFromHosted(*gz.HostedZone)
	if gz.DelegationSet != nil {
		z.Nameservers = append([]string(nil), gz.DelegationSet.NameServers...)
	}
	return &z, nil
}

// listSets pages through the record sets of a zone, starting at (name, type)
// when given, calling fn for each set until it returns false.
func (c *client) listSets(ctx context.Context, zone, startName, startType string, fn func(rs r53types.ResourceRecordSet) bool) error {
	in := &route53.ListResourceRecordSetsInput{HostedZoneId: awssdk.String(zoneID(zone)), MaxItems: awssdk.Int32(300)}
	if startName != "" {
		in.StartRecordName = awssdk.String(rrName(startName))
		if startType != "" {
			in.StartRecordType = r53types.RRType(strings.ToUpper(startType))
		}
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		page, err := c.r53.ListResourceRecordSets(ctx, in)
		if err != nil {
			return fmt.Errorf("list records of zone %s: %w", zone, mapErr(err))
		}
		for _, rs := range page.ResourceRecordSets {
			if !fn(rs) {
				return nil
			}
		}
		if !page.IsTruncated || page.NextRecordName == nil {
			return nil
		}
		in.StartRecordName = page.NextRecordName
		in.StartRecordType = page.NextRecordType
		in.StartRecordIdentifier = page.NextRecordIdentifier
	}
}

// ListRecords lists every record (one per value) of a zone.
func (c *client) ListRecords(ctx context.Context, zone string) ([]platform.Record, error) {
	id := zoneID(zone)
	var out []platform.Record
	err := c.listSets(ctx, id, "", "", func(rs r53types.ResourceRecordSet) bool {
		out = append(out, recordsFromSet(id, rs)...)
		return true
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// findSet returns the record set with the given name, type and set
// identifier, or nil when it does not exist.
func (c *client) findSet(ctx context.Context, zone, fqdn, typ, setID string) (*r53types.ResourceRecordSet, error) {
	fqdn = platform.NormalizeDomain(fqdn)
	typ = strings.ToUpper(typ)
	var found *r53types.ResourceRecordSet
	err := c.listSets(ctx, zone, fqdn, typ, func(rs r53types.ResourceRecordSet) bool {
		if unescapeRRName(awssdk.ToString(rs.Name)) != fqdn || string(rs.Type) != typ {
			return false
		}
		if awssdk.ToString(rs.SetIdentifier) == setID {
			cp := rs
			found = &cp
			return false
		}
		return true
	})
	if err != nil {
		return nil, err
	}
	return found, nil
}

func (c *client) change(ctx context.Context, zone string, changes ...r53types.Change) error {
	if len(changes) == 0 {
		return nil
	}
	_, err := c.r53.ChangeResourceRecordSets(ctx, &route53.ChangeResourceRecordSetsInput{
		HostedZoneId: awssdk.String(zoneID(zone)),
		ChangeBatch:  &r53types.ChangeBatch{Changes: changes, Comment: awssdk.String("polyctl")},
	})
	if err != nil {
		return fmt.Errorf("change records of zone %s: %w", zone, mapErr(err))
	}
	return nil
}

func upsert(rs r53types.ResourceRecordSet) r53types.Change {
	return r53types.Change{Action: r53types.ChangeActionUpsert, ResourceRecordSet: &rs}
}

func deletion(rs r53types.ResourceRecordSet) r53types.Change {
	return r53types.Change{Action: r53types.ChangeActionDelete, ResourceRecordSet: &rs}
}

// recordFor finds the Record of value in the (already applied) set.
func recordFor(zone string, rs r53types.ResourceRecordSet, value string) *platform.Record {
	recs := recordsFromSet(zone, rs)
	for i := range recs {
		if rs.AliasTarget != nil || awssdk.ToString(rs.ResourceRecords[i].Value) == value {
			return &recs[i]
		}
	}
	if len(recs) > 0 {
		return &recs[0]
	}
	return nil
}

func ttlFor(requested int, base *r53types.ResourceRecordSet) int {
	if requested > 0 {
		return requested
	}
	if base != nil && base.TTL != nil && *base.TTL > 0 {
		return int(*base.TTL)
	}
	return defaultTTL
}

// CreateRecord adds a value to the (possibly new) set of the same name and type.
func (c *client) CreateRecord(ctx context.Context, zone string, r platform.Record) (*platform.Record, error) {
	zone = zoneID(zone)
	fqdn, typ, setID := platform.NormalizeDomain(r.Name), strings.ToUpper(r.Type), extraString(r.Extra, "set_identifier")
	if fqdn == "" || typ == "" || strings.TrimSpace(r.Value) == "" {
		return nil, errors.New("record name, type and value are required")
	}
	existing, err := c.findSet(ctx, zone, fqdn, typ, setID)
	if err != nil {
		return nil, err
	}
	if extraBool(r.Extra, "alias") {
		targetZone := extraString(r.Extra, "alias_zone_id")
		if targetZone == "" && existing != nil && existing.AliasTarget != nil {
			targetZone = awssdk.ToString(existing.AliasTarget.HostedZoneId)
		}
		if targetZone == "" {
			return nil, errors.New("alias records need extra.alias_zone_id (the hosted zone id of the target)")
		}
		rs := buildAliasSet(existing, fqdn, typ, setID, r.Value, targetZone, extraBool(r.Extra, "evaluate_target_health"))
		if err := c.change(ctx, zone, upsert(rs)); err != nil {
			return nil, err
		}
		return recordFor(zone, rs, r.Value), nil
	}
	if existing != nil && existing.AliasTarget != nil {
		return nil, fmt.Errorf("%s %s is an alias record set; delete it before adding plain values", fqdn, typ)
	}
	value := recordValue(r)
	values := setValues(existing)
	if !containsValue(values, value) {
		values = append(values, value)
	}
	rs := buildSet(existing, fqdn, typ, setID, ttlFor(r.TTL, existing), values)
	if err := c.change(ctx, zone, upsert(rs)); err != nil {
		return nil, err
	}
	return recordFor(zone, rs, value), nil
}

// UpdateRecord replaces the value identified by r.ID with r's value
// (moving it to another name/type when those changed).
func (c *client) UpdateRecord(ctx context.Context, zone string, r platform.Record) (*platform.Record, error) {
	zone = zoneID(zone)
	oldType, oldName, oldSetID, oldValue, err := decodeRecordIDIn(zone, r.ID)
	if err != nil {
		return nil, err
	}
	newName, newType := platform.NormalizeDomain(r.Name), strings.ToUpper(r.Type)
	if newName == "" {
		newName = oldName
	}
	if newType == "" {
		newType = oldType
	}
	newSetID := oldSetID
	if v, ok := r.Extra["set_identifier"]; ok {
		newSetID = fmt.Sprint(v)
	}
	oldSet, err := c.findSet(ctx, zone, oldName, oldType, oldSetID)
	if err != nil {
		return nil, err
	}
	if oldSet == nil {
		return nil, fmt.Errorf("%w: record %s %s in zone %s", platform.ErrNotFound, oldName, oldType, zone)
	}
	sameKey := newName == oldName && newType == oldType && newSetID == oldSetID

	if oldSet.AliasTarget != nil {
		targetZone := extraString(r.Extra, "alias_zone_id")
		if targetZone == "" {
			targetZone = awssdk.ToString(oldSet.AliasTarget.HostedZoneId)
		}
		evaluate := oldSet.AliasTarget.EvaluateTargetHealth
		if _, ok := r.Extra["evaluate_target_health"]; ok {
			evaluate = extraBool(r.Extra, "evaluate_target_health")
		}
		rs := buildAliasSet(oldSet, newName, newType, newSetID, r.Value, targetZone, evaluate)
		changes := []r53types.Change{upsert(rs)}
		if !sameKey {
			changes = []r53types.Change{deletion(*oldSet), r53types.Change{Action: r53types.ChangeActionCreate, ResourceRecordSet: &rs}}
		}
		if err := c.change(ctx, zone, changes...); err != nil {
			return nil, err
		}
		return recordFor(zone, rs, r.Value), nil
	}

	oldValues := setValues(oldSet)
	if !containsValue(oldValues, oldValue) {
		return nil, fmt.Errorf("%w: value %q of %s %s in zone %s", platform.ErrNotFound, oldValue, oldName, oldType, zone)
	}
	newValue := recordValue(platform.Record{Type: newType, Value: r.Value, Priority: r.Priority})
	if sameKey {
		values := make([]string, 0, len(oldValues))
		for _, v := range oldValues {
			if v == oldValue {
				v = newValue
			}
			if !containsValue(values, v) {
				values = append(values, v)
			}
		}
		rs := buildSet(oldSet, oldName, oldType, oldSetID, ttlFor(r.TTL, oldSet), values)
		if err := c.change(ctx, zone, upsert(rs)); err != nil {
			return nil, err
		}
		return recordFor(zone, rs, newValue), nil
	}

	var changes []r53types.Change
	remaining := removeValue(oldValues, oldValue)
	if len(remaining) == 0 {
		changes = append(changes, deletion(*oldSet))
	} else {
		changes = append(changes, upsert(buildSet(oldSet, oldName, oldType, oldSetID, ttlFor(0, oldSet), remaining)))
	}
	newSet, err := c.findSet(ctx, zone, newName, newType, newSetID)
	if err != nil {
		return nil, err
	}
	if newSet != nil && newSet.AliasTarget != nil {
		return nil, fmt.Errorf("%s %s is an alias record set; delete it before adding plain values", newName, newType)
	}
	values := setValues(newSet)
	if !containsValue(values, newValue) {
		values = append(values, newValue)
	}
	ttl := r.TTL
	if ttl == 0 && newSet == nil {
		ttl = ttlFor(0, oldSet)
	}
	// A new target set inherits the routing policy of the old one: Route 53
	// rejects a set with a set identifier but no routing policy.
	base := newSet
	if base == nil {
		base = oldSet
	}
	rs := buildSet(base, newName, newType, newSetID, ttlFor(ttl, newSet), values)
	changes = append(changes, upsert(rs))
	if err := c.change(ctx, zone, changes...); err != nil {
		return nil, err
	}
	return recordFor(zone, rs, newValue), nil
}

// DeleteRecord removes one value; the set is deleted when it was the last
// value. Alias sets are deleted whole.
func (c *client) DeleteRecord(ctx context.Context, zone, recordID string) error {
	zone = zoneID(zone)
	typ, name, setID, value, err := decodeRecordIDIn(zone, recordID)
	if err != nil {
		return err
	}
	rs, err := c.findSet(ctx, zone, name, typ, setID)
	if err != nil {
		return err
	}
	if rs == nil {
		return fmt.Errorf("%w: record %s %s in zone %s", platform.ErrNotFound, name, typ, zone)
	}
	if rs.AliasTarget != nil {
		return c.change(ctx, zone, deletion(*rs))
	}
	values := setValues(rs)
	if !containsValue(values, value) {
		return fmt.Errorf("%w: value %q of %s %s in zone %s", platform.ErrNotFound, value, name, typ, zone)
	}
	remaining := removeValue(values, value)
	if len(remaining) == 0 {
		return c.change(ctx, zone, deletion(*rs))
	}
	return c.change(ctx, zone, upsert(buildSet(rs, name, typ, setID, ttlFor(0, rs), remaining)))
}

// ReplaceSet replaces the whole value set of (name, type) with values
// (used by the native `route53 record upsert` command).
func (c *client) ReplaceSet(ctx context.Context, zone, fqdn, typ string, values []string, ttl int) ([]platform.Record, error) {
	zone = zoneID(zone)
	existing, err := c.findSet(ctx, zone, fqdn, typ, "")
	if err != nil {
		return nil, err
	}
	if existing != nil && existing.AliasTarget != nil {
		return nil, fmt.Errorf("%s %s is an alias record set; delete it first", fqdn, typ)
	}
	quoted := make([]string, 0, len(values))
	for _, v := range values {
		quoted = append(quoted, quoteTXT(typ, v))
	}
	rs := buildSet(existing, fqdn, typ, "", ttlFor(ttl, existing), quoted)
	if err := c.change(ctx, zone, upsert(rs)); err != nil {
		return nil, err
	}
	return recordsFromSet(zone, rs), nil
}

// DeleteSet deletes the whole record set of (name, type).
func (c *client) DeleteSet(ctx context.Context, zone, fqdn, typ string) ([]platform.Record, error) {
	zone = zoneID(zone)
	existing, err := c.findSet(ctx, zone, fqdn, typ, "")
	if err != nil {
		return nil, err
	}
	if existing == nil {
		return nil, fmt.Errorf("%w: record set %s %s in zone %s", platform.ErrNotFound, platform.NormalizeDomain(fqdn), strings.ToUpper(typ), zone)
	}
	if err := c.change(ctx, zone, deletion(*existing)); err != nil {
		return nil, err
	}
	return recordsFromSet(zone, *existing), nil
}
