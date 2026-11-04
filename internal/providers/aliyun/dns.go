package aliyun

import (
	"context"
	"fmt"
	"strings"

	"github.com/aliyun/alibaba-cloud-sdk-go/sdk/requests"
	"github.com/aliyun/alibaba-cloud-sdk-go/services/alidns"

	"github.com/gofika/polyctl/internal/platform"
)

// zoneFromDomain converts an alidns domain to a platform zone. The zone id
// is the domain name itself because every alidns record API is keyed by it.
func zoneFromDomain(d alidns.DomainInDescribeDomains) platform.Zone {
	name := platform.NormalizeDomain(d.DomainName)
	z := platform.Zone{
		ID:          name,
		Name:        name,
		Nameservers: append([]string(nil), d.DnsServers.DnsServer...),
		Status:      d.VersionCode,
		Extra: map[string]any{
			"domain_id":    d.DomainId,
			"record_count": d.RecordCount,
		},
	}
	if d.VersionName != "" {
		z.Extra["version_name"] = d.VersionName
	}
	if d.GroupName != "" {
		z.Extra["group"] = d.GroupName
	}
	if d.InstanceId != "" {
		z.Extra["instance_id"] = d.InstanceId
	}
	if d.AliDomain {
		z.Extra["ali_domain"] = true
	}
	return z
}

// recordFromAlidns converts an alidns record to the neutral form.
func recordFromAlidns(r alidns.Record) platform.Record {
	zone := platform.NormalizeDomain(r.DomainName)
	rec := platform.Record{
		ID:      r.RecordId,
		ZoneID:  zone,
		Name:    platform.FQDN(r.RR, zone),
		Type:    strings.ToUpper(r.Type),
		Content: r.Value,
		TTL:     int(r.TTL),
		Extra: map[string]any{
			"status": r.Status,
			"line":   r.Line,
			"locked": r.Locked,
		},
	}
	if rec.Type == "MX" {
		p := int(r.Priority)
		rec.Priority = &p
	}
	if r.Weight != 0 {
		rec.Extra["weight"] = r.Weight
	}
	if r.Remark != "" {
		rec.Extra["remark"] = r.Remark
	}
	return rec
}

// recordLine returns the resolution line stored in a record's Extra, if any.
func recordLine(r platform.Record) string {
	if r.Extra == nil {
		return ""
	}
	if l, ok := r.Extra["line"].(string); ok {
		return l
	}
	return ""
}

// ListZones lists every alidns domain (paginated).
func (c *client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	cl, err := c.dnsClient(ctx)
	if err != nil {
		return nil, err
	}
	var out []platform.Zone
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alidns.CreateDescribeDomainsRequest()
		c.route(req, endpointDNS)
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(pageSize)
		resp, err := cl.DescribeDomains(req)
		if err != nil {
			return nil, wrapErr("alidns DescribeDomains", err)
		}
		for _, d := range resp.Domains.Domain {
			out = append(out, zoneFromDomain(d))
		}
		if len(resp.Domains.Domain) == 0 || int64(len(out)) >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// ListRecords lists the records of a zone (paginated).
func (c *client) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	cl, err := c.dnsClient(ctx)
	if err != nil {
		return nil, err
	}
	zone := platform.NormalizeDomain(zoneID)
	var out []platform.Record
	for page := 1; ; page++ {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		req := alidns.CreateDescribeDomainRecordsRequest()
		c.route(req, endpointDNS)
		req.DomainName = zone
		req.PageNumber = requests.NewInteger(page)
		req.PageSize = requests.NewInteger(pageSize)
		resp, err := cl.DescribeDomainRecords(req)
		if err != nil {
			return nil, wrapErr("alidns DescribeDomainRecords "+zone, err)
		}
		for _, r := range resp.DomainRecords.Record {
			if r.DomainName == "" {
				r.DomainName = zone
			}
			out = append(out, recordFromAlidns(r))
		}
		if len(resp.DomainRecords.Record) == 0 || int64(len(out)) >= resp.TotalCount {
			break
		}
	}
	return out, nil
}

// CreateRecord adds a record to a zone.
func (c *client) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	cl, err := c.dnsClient(ctx)
	if err != nil {
		return nil, err
	}
	zone := platform.NormalizeDomain(zoneID)
	req := alidns.CreateAddDomainRecordRequest()
	c.route(req, endpointDNS)
	req.DomainName = zone
	req.RR = platform.RelativeName(r.Name, zone)
	req.Type = strings.ToUpper(r.Type)
	req.Value = r.Content
	if r.TTL > 0 {
		req.TTL = requests.NewInteger(r.TTL)
	}
	if r.Priority != nil {
		req.Priority = requests.NewInteger(*r.Priority)
	} else if req.Type == "MX" {
		req.Priority = requests.NewInteger(10)
	}
	if line := recordLine(r); line != "" {
		req.Line = line
	}
	resp, err := cl.AddDomainRecord(req)
	if err != nil {
		return nil, wrapErr("alidns AddDomainRecord", err)
	}
	return c.fetchRecord(ctx, zone, resp.RecordId, r, req.RR, req.Type, req.Line)
}

// UpdateRecord replaces the record identified by r.ID.
func (c *client) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	if r.ID == "" {
		return nil, fmt.Errorf("update record: record id is required")
	}
	cl, err := c.dnsClient(ctx)
	if err != nil {
		return nil, err
	}
	zone := platform.NormalizeDomain(zoneID)
	req := alidns.CreateUpdateDomainRecordRequest()
	c.route(req, endpointDNS)
	req.RecordId = r.ID
	req.RR = platform.RelativeName(r.Name, zone)
	req.Type = strings.ToUpper(r.Type)
	req.Value = r.Content
	ttl := r.TTL
	if ttl <= 0 {
		ttl = defaultRecordTTL
	}
	req.TTL = requests.NewInteger(ttl)
	if r.Priority != nil {
		req.Priority = requests.NewInteger(*r.Priority)
	} else if req.Type == "MX" {
		req.Priority = requests.NewInteger(10)
	}
	if line := recordLine(r); line != "" {
		req.Line = line
	}
	if _, err := cl.UpdateDomainRecord(req); err != nil {
		return nil, wrapErr("alidns UpdateDomainRecord "+r.ID, err)
	}
	return c.fetchRecord(ctx, zone, r.ID, r, req.RR, req.Type, req.Line)
}

// DeleteRecord removes a record.
func (c *client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	if recordID == "" {
		return fmt.Errorf("delete record: record id is required")
	}
	cl, err := c.dnsClient(ctx)
	if err != nil {
		return err
	}
	req := alidns.CreateDeleteDomainRecordRequest()
	c.route(req, endpointDNS)
	req.RecordId = recordID
	if _, err := cl.DeleteDomainRecord(req); err != nil {
		return wrapErr("alidns DeleteDomainRecord "+recordID, err)
	}
	return nil
}

// fetchRecord re-reads a record after a mutation; when the read fails the
// record is reconstructed from the request so the caller still gets an id.
func (c *client) fetchRecord(ctx context.Context, zone, id string, in platform.Record, rr, typ, line string) (*platform.Record, error) {
	cl, err := c.dnsClient(ctx)
	if err != nil {
		return nil, err
	}
	req := alidns.CreateDescribeDomainRecordInfoRequest()
	c.route(req, endpointDNS)
	req.RecordId = id
	resp, err := cl.DescribeDomainRecordInfo(req)
	if err == nil && resp.RecordId != "" {
		rec := recordFromAlidns(alidns.Record{
			RecordId: resp.RecordId, DomainName: zone, RR: resp.RR, Type: resp.Type, Value: resp.Value,
			TTL: resp.TTL, Priority: resp.Priority, Status: resp.Status, Line: resp.Line, Locked: resp.Locked, Remark: resp.Remark,
		})
		return &rec, nil
	}
	rec := platform.Record{
		ID: id, ZoneID: zone, Name: platform.FQDN(rr, zone), Type: typ, Content: in.Content, TTL: in.TTL,
		Priority: in.Priority, Extra: map[string]any{},
	}
	if rec.TTL <= 0 {
		rec.TTL = defaultRecordTTL
	}
	if line != "" {
		rec.Extra["line"] = line
	}
	if rec.Type == "MX" && rec.Priority == nil {
		p := 10
		rec.Priority = &p
	}
	return &rec, nil
}
