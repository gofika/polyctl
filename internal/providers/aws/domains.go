package aws

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	awssdk "github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/route53domains"
	r53dtypes "github.com/aws/aws-sdk-go-v2/service/route53domains/types"

	"github.com/gofika/polyctl/internal/platform"
)

const transferLockStatus = "clienttransferprohibited"

// domainFromSummary builds a Domain from a ListDomains entry.
func domainFromSummary(s r53dtypes.DomainSummary) platform.Domain {
	d := platform.Domain{
		Name:      platform.NormalizeDomain(awssdk.ToString(s.DomainName)),
		AutoRenew: s.AutoRenew,
		Locked:    s.TransferLock,
	}
	if s.Expiry != nil {
		d.ExpiresAt = s.Expiry.UTC().Format(time.RFC3339)
	}
	return d
}

// domainFromDetail merges GetDomainDetail output into d.
func domainFromDetail(d platform.Domain, out *route53domains.GetDomainDetailOutput) platform.Domain {
	if out == nil {
		return d
	}
	if n := awssdk.ToString(out.DomainName); n != "" {
		d.Name = platform.NormalizeDomain(n)
	}
	d.Nameservers = d.Nameservers[:0]
	for _, ns := range out.Nameservers {
		if n := platform.NormalizeDomain(awssdk.ToString(ns.Name)); n != "" {
			d.Nameservers = append(d.Nameservers, n)
		}
	}
	if len(d.Nameservers) == 0 {
		d.Nameservers = nil
	}
	if out.ExpirationDate != nil {
		d.ExpiresAt = out.ExpirationDate.UTC().Format(time.RFC3339)
	}
	if out.AutoRenew != nil {
		d.AutoRenew = out.AutoRenew
	}
	if out.AdminPrivacy != nil {
		d.Privacy = out.AdminPrivacy
	}
	if len(out.StatusList) > 0 {
		d.Status = strings.Join(out.StatusList, ",")
		if d.Locked == nil {
			locked := false
			for _, s := range out.StatusList {
				if strings.ToLower(s) == transferLockStatus {
					locked = true
				}
			}
			d.Locked = &locked
		}
	}
	extra := map[string]any{}
	if v := awssdk.ToString(out.RegistrarName); v != "" {
		extra["registrar_name"] = v
	}
	if out.CreationDate != nil {
		extra["created_at"] = out.CreationDate.UTC().Format(time.RFC3339)
	}
	if out.UpdatedDate != nil {
		extra["updated_at"] = out.UpdatedDate.UTC().Format(time.RFC3339)
	}
	if v := awssdk.ToString(out.DnsSec); v != "" {
		extra["dnssec"] = v
	}
	if out.RegistrantPrivacy != nil {
		extra["registrant_privacy"] = *out.RegistrantPrivacy
	}
	if out.TechPrivacy != nil {
		extra["tech_privacy"] = *out.TechPrivacy
	}
	if v := awssdk.ToString(out.RegistryDomainId); v != "" {
		extra["registry_domain_id"] = v
	}
	if len(extra) > 0 {
		d.Extra = extra
	}
	return d
}

// ListDomains lists the registered domains with their details.
func (c *client) ListDomains(ctx context.Context) ([]platform.Domain, error) {
	var out []platform.Domain
	pg := route53domains.NewListDomainsPaginator(c.r53d, &route53domains.ListDomainsInput{})
	for pg.HasMorePages() {
		page, err := pg.NextPage(ctx)
		if err != nil {
			return nil, fmt.Errorf("list registered domains: %w", mapErr(err))
		}
		for _, s := range page.Domains {
			d := domainFromSummary(s)
			detail, err := c.r53d.GetDomainDetail(ctx, &route53domains.GetDomainDetailInput{DomainName: s.DomainName})
			if err != nil {
				err = mapErr(err)
				if !errors.Is(err, platform.ErrUnauthorized) && !errors.Is(err, platform.ErrNotFound) {
					// Throttling, network and input errors are real failures:
					// a silently degraded domain would look like it has no
					// nameservers.
					return nil, fmt.Errorf("get domain detail %s: %w", d.Name, err)
				}
				// Keep the summary when the detail call is not permitted (or
				// the domain vanished between the two calls) and say why.
				d.Extra = map[string]any{"detail_error": apiErrorCode(err)}
				out = append(out, d)
				continue
			}
			out = append(out, domainFromDetail(d, detail))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// GetDomain returns one registered domain.
func (c *client) GetDomain(ctx context.Context, name string) (*platform.Domain, error) {
	name = platform.NormalizeDomain(name)
	if name == "" {
		return nil, errors.New("domain name is required")
	}
	detail, err := c.r53d.GetDomainDetail(ctx, &route53domains.GetDomainDetailInput{DomainName: awssdk.String(name)})
	if err != nil {
		return nil, fmt.Errorf("get domain %s: %w", name, mapErr(err))
	}
	d := domainFromDetail(platform.Domain{Name: name}, detail)
	return &d, nil
}

// SetNameservers replaces the nameservers of a registered domain.
func (c *client) SetNameservers(ctx context.Context, name string, ns []string) error {
	name = platform.NormalizeDomain(name)
	if len(ns) == 0 {
		return errors.New("at least one nameserver is required")
	}
	servers := make([]r53dtypes.Nameserver, 0, len(ns))
	for _, n := range ns {
		n = platform.NormalizeDomain(n)
		if n == "" {
			continue
		}
		servers = append(servers, r53dtypes.Nameserver{Name: awssdk.String(n)})
	}
	_, err := c.r53d.UpdateDomainNameservers(ctx, &route53domains.UpdateDomainNameserversInput{
		DomainName:  awssdk.String(name),
		Nameservers: servers,
	})
	if err != nil {
		return fmt.Errorf("update nameservers of %s: %w", name, mapErr(err))
	}
	return nil
}
