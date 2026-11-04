package gcp

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sort"
	"strconv"
	"strings"

	"golang.org/x/oauth2"
	"google.golang.org/api/cloudresourcemanager/v1"
	"google.golang.org/api/compute/v1"
	"google.golang.org/api/dns/v1"
	"google.golang.org/api/googleapi"
	"google.golang.org/api/option"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// client is an authenticated Google Cloud session bound to one project.
type client struct {
	project string
	email   string
	method  string

	dns     *dns.Service
	compute *compute.Service
	crm     *cloudresourcemanager.Service
}

var _ platform.Client = (*client)(nil)
var _ platform.DNSService = (*client)(nil)

// newClient builds the API services. opts must carry the credentials
// (option.WithTokenSource / WithCredentials) and, in tests, the endpoint.
func newClient(ctx context.Context, project, email, method string, opts ...option.ClientOption) (*client, error) {
	c := &client{project: project, email: email, method: method}
	var err error
	if c.dns, err = dns.NewService(ctx, opts...); err != nil {
		return nil, fmt.Errorf("init Cloud DNS client: %w", err)
	}
	if c.compute, err = compute.NewService(ctx, opts...); err != nil {
		return nil, fmt.Errorf("init Compute Engine client: %w", err)
	}
	if c.crm, err = cloudresourcemanager.NewService(ctx, opts...); err != nil {
		return nil, fmt.Errorf("init Resource Manager client: %w", err)
	}
	return c, nil
}

// mapErr wraps Google API errors with the platform sentinels so the CLI can
// map them to exit codes. Permission-denied is reported as unauthorized.
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var ge *googleapi.Error
	if errors.As(err, &ge) {
		switch ge.Code {
		case http.StatusUnauthorized, http.StatusForbidden:
			return fmt.Errorf("%w: %w", platform.ErrUnauthorized, err)
		case http.StatusNotFound:
			return fmt.Errorf("%w: %w", platform.ErrNotFound, err)
		}
		return err
	}
	var re *oauth2.RetrieveError
	if errors.As(err, &re) {
		return fmt.Errorf("%w: %w", platform.ErrUnauthorized, err)
	}
	return err
}

// isPermissionErr reports whether err is a 401/403 from the API.
func isPermissionErr(err error) bool {
	var ge *googleapi.Error
	return errors.As(err, &ge) && (ge.Code == http.StatusUnauthorized || ge.Code == http.StatusForbidden)
}

// Verify checks that the credentials can see the project.
func (c *client) Verify(ctx context.Context) (*platform.Identity, error) {
	id := &platform.Identity{Account: c.project, User: c.email, Extra: map[string]string{"method": c.method}}
	p, err := c.crm.Projects.Get(c.project).Context(ctx).Do()
	if err == nil {
		if p.Name != "" {
			id.Extra["project_name"] = p.Name
		}
		if p.ProjectNumber != 0 {
			id.Extra["project_number"] = strconv.FormatInt(p.ProjectNumber, 10)
		}
		if p.LifecycleState != "" {
			id.Extra["state"] = p.LifecycleState
		}
		return id, nil
	}
	first := err
	// Resource Manager access is optional; Cloud DNS visibility is enough.
	if _, err := c.dns.ManagedZones.List(c.project).Context(ctx).Do(); err == nil {
		id.Extra["note"] = "resourcemanager.projects.get not permitted; verified via Cloud DNS"
		return id, nil
	}
	return nil, mapErr(first)
}

// Sync fetches every resource of a type.
func (c *client) Sync(ctx context.Context, rt platform.ResourceType) ([]platform.Resource, error) {
	switch rt {
	case platform.ResZone:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		res := app.ZoneResources(zones)
		// Only public zones take part in domain routing: a private zone may
		// share its dnsName with a public one (split-horizon) and must never
		// be picked by the platform-neutral `polyctl dns ...` commands. It
		// stays in the inventory and is still addressable by managed zone
		// name through `polyctl gcp dns ...`.
		for i := range res {
			if !isPublicZone(zones[i]) {
				res[i].Domain = ""
			}
		}
		return res, nil
	case platform.ResDNSRecord:
		zones, err := c.ListZones(ctx)
		if err != nil {
			return nil, err
		}
		var out []platform.Resource
		for _, z := range zones {
			recs, err := c.ListRecords(ctx, z.ID)
			if err != nil {
				return nil, fmt.Errorf("zone %s: %w", z.ID, err)
			}
			out = append(out, app.RecordResources(z.ID, z.Name, recs)...)
		}
		return out, nil
	case platform.ResInstance:
		return c.ListInstances(ctx)
	}
	return nil, fmt.Errorf("%s: %w", rt, platform.ErrNotSupported)
}

// zoneFromManaged converts a managed zone into the neutral Zone type.
func zoneFromManaged(mz *dns.ManagedZone) platform.Zone {
	z := platform.Zone{
		ID:          mz.Name,
		Name:        platform.NormalizeDomain(mz.DnsName),
		Nameservers: mz.NameServers,
		Status:      mz.Visibility,
		Extra: map[string]any{
			"description": mz.Description,
			"id":          strconv.FormatUint(mz.Id, 10),
		},
	}
	if mz.CreationTime != "" {
		z.Extra["creation_time"] = mz.CreationTime
	}
	if len(mz.Labels) > 0 {
		z.Extra["labels"] = mz.Labels
	}
	if mz.DnssecConfig != nil && mz.DnssecConfig.State != "" {
		z.Extra["dnssec"] = mz.DnssecConfig.State
	}
	return z
}

// isPublicZone reports whether a zone is visible on the internet. Cloud DNS
// reports Visibility as "public" or "private"; an empty value is the
// public default.
func isPublicZone(z platform.Zone) bool {
	return z.Status == "" || strings.EqualFold(z.Status, "public")
}

// ListZones lists every managed zone of the project, ordered by DNS name
// and then by managed zone name so split-horizon pairs sort stably.
func (c *client) ListZones(ctx context.Context) ([]platform.Zone, error) {
	var out []platform.Zone
	err := c.dns.ManagedZones.List(c.project).Pages(ctx, func(resp *dns.ManagedZonesListResponse) error {
		for _, mz := range resp.ManagedZones {
			out = append(out, zoneFromManaged(mz))
		}
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].ID < out[j].ID
	})
	return out, nil
}

// GetZone fetches one managed zone by name.
func (c *client) GetZone(ctx context.Context, zoneID string) (*platform.Zone, error) {
	mz, err := c.dns.ManagedZones.Get(c.project, zoneID).Context(ctx).Do()
	if err != nil {
		return nil, mapErr(err)
	}
	z := zoneFromManaged(mz)
	return &z, nil
}

// listRRSets returns the raw record sets of a zone, optionally filtered by
// name (Cloud DNS form, with trailing dot) and type.
func (c *client) listRRSets(ctx context.Context, zoneID, name, typ string) ([]*dns.ResourceRecordSet, error) {
	call := c.dns.ResourceRecordSets.List(c.project, zoneID)
	if name != "" {
		call = call.Name(name)
	}
	if typ != "" {
		call = call.Type(strings.ToUpper(typ))
	}
	var out []*dns.ResourceRecordSet
	err := call.Pages(ctx, func(resp *dns.ResourceRecordSetsListResponse) error {
		out = append(out, resp.Rrsets...)
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	return out, nil
}

// ListRecords lists every record value in a zone (one Record per rrdata).
func (c *client) ListRecords(ctx context.Context, zoneID string) ([]platform.Record, error) {
	sets, err := c.listRRSets(ctx, zoneID, "", "")
	if err != nil {
		return nil, err
	}
	var out []platform.Record
	for _, rs := range sets {
		out = append(out, recordsFromRRSet(zoneID, rs)...)
	}
	return out, nil
}

// getRRSet returns the record set for name/type or nil when it does not exist.
func (c *client) getRRSet(ctx context.Context, zoneID, name, typ string) (*dns.ResourceRecordSet, error) {
	sets, err := c.listRRSets(ctx, zoneID, name, typ)
	if err != nil {
		if errors.Is(err, platform.ErrNotFound) {
			return nil, nil
		}
		return nil, err
	}
	for _, rs := range sets {
		if strings.EqualFold(rs.Name, name) && strings.EqualFold(rs.Type, typ) {
			return rs, nil
		}
	}
	return nil, nil
}

// rrOp describes a modification of one record set.
type rrOp struct {
	fqdn    string   // record name without trailing dot
	typ     string   // upper-case record type
	remove  []string // raw rrdata values to remove (must exist)
	add     []string // raw rrdata values to add (deduplicated)
	replace bool     // replace the whole set with add
	ttl     int64    // 0 keeps the existing TTL (or defaultTTL for new sets)
}

// applyOps computes and submits one Cloud DNS change covering every op.
// Each op is resolved against the live record set: the old set is deleted
// and the new content added, which Cloud DNS applies atomically.
func (c *client) applyOps(ctx context.Context, zoneID string, ops []rrOp) error {
	change := &dns.Change{}
	for _, op := range ops {
		name := dnsName(op.fqdn)
		typ := strings.ToUpper(op.typ)
		existing, err := c.getRRSet(ctx, zoneID, name, typ)
		if err != nil {
			return err
		}
		if existing != nil && existing.RoutingPolicy != nil {
			// Rewriting such a set would silently drop the geo/weighted/
			// failover policy and replace it with plain rrdatas.
			return fmt.Errorf("%w: %s %s uses a routing policy; manage it with gcloud or the console", platform.ErrNotSupported, op.fqdn, typ)
		}
		var values []string
		ttl := op.ttl
		if existing != nil {
			values = append(values, existing.Rrdatas...)
			if ttl == 0 {
				ttl = existing.Ttl
			}
		}
		if ttl == 0 {
			ttl = defaultTTL
		}
		if op.replace {
			values = nil
		}
		for _, v := range op.remove {
			var ok bool
			if values, ok = removeValue(values, v); !ok {
				return fmt.Errorf("%w: %s %s has no value %q", platform.ErrNotFound, op.fqdn, typ, v)
			}
		}
		for _, v := range op.add {
			if !containsValue(values, v) {
				values = append(values, v)
			}
		}
		if existing != nil && existing.Ttl == ttl && sameValues(existing.Rrdatas, values) {
			continue // nothing to change
		}
		if existing != nil {
			change.Deletions = append(change.Deletions, existing)
		}
		if len(values) > 0 {
			change.Additions = append(change.Additions, &dns.ResourceRecordSet{Name: name, Type: typ, Ttl: ttl, Rrdatas: values})
		}
	}
	if len(change.Additions) == 0 && len(change.Deletions) == 0 {
		return nil
	}
	if _, err := c.dns.Changes.Create(c.project, zoneID, change).Context(ctx).Do(); err != nil {
		return mapErr(err)
	}
	return nil
}

// CreateRecord adds a value to the record set of r.Name/r.Type.
func (c *client) CreateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	raw, err := rrdataFromRecord(r)
	if err != nil {
		return nil, err
	}
	typ := strings.ToUpper(r.Type)
	fqdn := platform.NormalizeDomain(r.Name)
	if err := c.applyOps(ctx, zoneID, []rrOp{{fqdn: fqdn, typ: typ, add: []string{raw}, ttl: int64(r.TTL)}}); err != nil {
		return nil, err
	}
	return c.findRecord(ctx, encodeRecordID(zoneID, typ, fqdn, raw))
}

// UpdateRecord replaces the value identified by r.ID with r's content. When
// the name or type changes the value moves between record sets.
func (c *client) UpdateRecord(ctx context.Context, zoneID string, r platform.Record) (*platform.Record, error) {
	oldZone, oldTyp, oldName, oldRaw, err := decodeRecordID(r.ID)
	if err != nil {
		return nil, err
	}
	if oldZone != zoneID {
		return nil, fmt.Errorf("record %s belongs to managed zone %q, not %q", r.ID, oldZone, zoneID)
	}
	if oldRaw == routingPolicyMarker {
		return nil, fmt.Errorf("%w: %s %s uses a routing policy; manage it with gcloud or the console", platform.ErrNotSupported, oldName, oldTyp)
	}
	if r.Type == "" {
		r.Type = oldTyp
	}
	if r.Name == "" {
		r.Name = oldName
	}
	raw, err := rrdataFromRecord(r)
	if err != nil {
		return nil, err
	}
	typ := strings.ToUpper(r.Type)
	fqdn := platform.NormalizeDomain(r.Name)
	var ops []rrOp
	if typ == oldTyp && fqdn == oldName {
		ops = []rrOp{{fqdn: fqdn, typ: typ, remove: []string{oldRaw}, add: []string{raw}, ttl: int64(r.TTL)}}
	} else {
		ops = []rrOp{
			{fqdn: oldName, typ: oldTyp, remove: []string{oldRaw}},
			{fqdn: fqdn, typ: typ, add: []string{raw}, ttl: int64(r.TTL)},
		}
	}
	if err := c.applyOps(ctx, zoneID, ops); err != nil {
		return nil, err
	}
	return c.findRecord(ctx, encodeRecordID(zoneID, typ, fqdn, raw))
}

// DeleteRecord removes one value; the record set is deleted when empty.
func (c *client) DeleteRecord(ctx context.Context, zoneID, recordID string) error {
	idZone, typ, fqdn, raw, err := decodeRecordID(recordID)
	if err != nil {
		return err
	}
	if idZone != zoneID {
		return fmt.Errorf("record %s belongs to managed zone %q, not %q", recordID, idZone, zoneID)
	}
	if raw == routingPolicyMarker {
		return fmt.Errorf("%w: %s %s uses a routing policy; manage it with gcloud or the console", platform.ErrNotSupported, fqdn, typ)
	}
	return c.applyOps(ctx, zoneID, []rrOp{{fqdn: fqdn, typ: typ, remove: []string{raw}}})
}

// SetRRSet replaces the whole record set with values (native upsert).
// An empty values slice deletes the set.
func (c *client) SetRRSet(ctx context.Context, zoneID, fqdn, typ string, ttl int64, values []string) error {
	return c.applyOps(ctx, zoneID, []rrOp{{fqdn: fqdn, typ: typ, add: values, replace: true, ttl: ttl}})
}

// DeleteRRSet removes an entire record set.
func (c *client) DeleteRRSet(ctx context.Context, zoneID, fqdn, typ string) error {
	existing, err := c.getRRSet(ctx, zoneID, dnsName(fqdn), strings.ToUpper(typ))
	if err != nil {
		return err
	}
	if existing == nil {
		return fmt.Errorf("%w: %s %s", platform.ErrNotFound, fqdn, strings.ToUpper(typ))
	}
	return c.applyOps(ctx, zoneID, []rrOp{{fqdn: fqdn, typ: typ, replace: true}})
}

// findRecord re-reads a record after a change so callers get the live state.
// The managed zone is taken from the id.
func (c *client) findRecord(ctx context.Context, id string) (*platform.Record, error) {
	zoneID, typ, fqdn, _, err := decodeRecordID(id)
	if err != nil {
		return nil, err
	}
	rs, err := c.getRRSet(ctx, zoneID, dnsName(fqdn), typ)
	if err != nil {
		return nil, err
	}
	for _, r := range recordsFromRRSet(zoneID, rs) {
		if r.ID == id {
			return &r, nil
		}
	}
	return nil, fmt.Errorf("%w: record %s after change", platform.ErrNotFound, id)
}

// ListProjects returns the active projects visible to the credentials.
func (c *client) ListProjects(ctx context.Context) ([]*cloudresourcemanager.Project, error) {
	return listProjects(ctx, c.crm)
}

func listProjects(ctx context.Context, crm *cloudresourcemanager.Service) ([]*cloudresourcemanager.Project, error) {
	var out []*cloudresourcemanager.Project
	err := crm.Projects.List().Filter("lifecycleState:ACTIVE").Pages(ctx, func(resp *cloudresourcemanager.ListProjectsResponse) error {
		out = append(out, resp.Projects...)
		return nil
	})
	if err != nil {
		return nil, mapErr(err)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ProjectId < out[j].ProjectId })
	return out, nil
}
