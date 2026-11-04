package aws

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Command returns the `polyctl aws` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aws",
		Short: "Amazon Web Services native commands",
		Long: `Native Amazon Web Services commands: STS identity, Route 53 hosted zones and
records, Route 53 Domains registrations and EC2 instances. The profile is
chosen with --profile (or the current profile); listing commands read the local
inventory unless --refresh is given or the cached data has expired.`,
	}
	cmd.AddCommand(stsCmd(rt), route53Cmd(rt), route53domainsCmd(rt), ec2Cmd(rt))
	return cmd
}

// openClient opens the AWS client for the selected profile.
func openClient(ctx context.Context, rt *app.Runtime) (*client, platform.Profile, error) {
	c, prof, err := rt.OpenFor(ctx, platform.AWS)
	if err != nil {
		return nil, prof, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, prof, fmt.Errorf("unexpected AWS client type %T", c)
	}
	return ac, prof, nil
}

// ---------------------------------------------------------------- sts

type whoami struct {
	Profile  string             `json:"profile" yaml:"profile"`
	Region   string             `json:"region" yaml:"region"`
	Identity *platform.Identity `json:"identity" yaml:"identity"`
}

func stsCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "sts", Short: "Security Token Service"}
	cmd.AddCommand(&cobra.Command{
		Use:   "whoami",
		Short: "Show the identity behind the current credentials (sts GetCallerIdentity)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			id, err := c.Verify(cmd.Context())
			if err != nil {
				return err
			}
			w := whoami{Profile: prof.Name, Region: c.region, Identity: id}
			return rt.Render(w, func() output.Grid {
				pairs := []string{"PROFILE", w.Profile, "ACCOUNT", id.Account, "ARN", id.User, "REGION", w.Region}
				if uid := id.Extra["user_id"]; uid != "" {
					pairs = append(pairs, "USER_ID", uid)
				}
				return output.KV(pairs...)
			})
		},
	})
	return cmd
}

// ------------------------------------------------------------ route53

// looksLikeZoneID reports whether s is a hosted zone id rather than a name.
func looksLikeZoneID(s string) bool {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, hostedZonePrefix) {
		return true
	}
	if strings.Contains(s, ".") || len(s) < 8 || !strings.HasPrefix(s, "Z") {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func matchZones(zones []platform.Zone, arg string) (exact *platform.Zone, byName []platform.Zone) {
	id, name := zoneID(arg), platform.NormalizeDomain(arg)
	for i := range zones {
		z := zones[i]
		if z.ID == id {
			return &z, nil
		}
		if z.Name == name {
			byName = append(byName, z)
		}
	}
	return nil, byName
}

func pickZone(zones []platform.Zone, arg string) (*platform.Zone, bool, error) {
	exact, byName := matchZones(zones, arg)
	switch {
	case exact != nil:
		return exact, true, nil
	case len(byName) == 1:
		return &byName[0], true, nil
	case len(byName) > 1:
		var ids []string
		for _, z := range byName {
			ids = append(ids, fmt.Sprintf("%s (%s)", z.ID, z.Status))
		}
		return nil, true, &app.AmbiguousError{What: fmt.Sprintf("hosted zone %q", platform.NormalizeDomain(arg)), Candidates: ids}
	}
	return nil, false, nil
}

// resolveZone turns a zone name or id into a zone, consulting the local
// inventory first and the platform when needed and allowed.
func resolveZone(ctx context.Context, rt *app.Runtime, arg string) (*platform.Zone, error) {
	profName, err := rt.ProfileFor(platform.AWS)
	if err != nil {
		return nil, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResZone}
	rows, err := db.List(ctx, inventory.Query{Platform: set.Platform, Profile: set.Profile, Type: set.Type})
	if err != nil {
		return nil, err
	}
	var cached []platform.Zone
	for _, r := range rows {
		var z platform.Zone
		if err := r.Decode(&z); err == nil {
			cached = append(cached, z)
		}
	}
	if !rt.Flags.Refresh {
		if z, found, err := pickZone(cached, arg); found {
			return z, err
		}
	}
	if rt.Flags.Offline {
		if looksLikeZoneID(arg) {
			return &platform.Zone{ID: zoneID(arg)}, nil
		}
		return nil, fmt.Errorf("%w: hosted zone %q is not in the local inventory (run `polyctl sync --platform aws` when online)", platform.ErrNotFound, arg)
	}
	c, prof, err := openClient(ctx, rt)
	if err != nil {
		return nil, err
	}
	zones, err := c.listZonesWithNameservers(ctx)
	if err != nil {
		return nil, err
	}
	cfg, _ := rt.Config()
	_ = db.Replace(ctx, inventory.Set{Platform: platform.AWS, Profile: prof.Name, Type: platform.ResZone}, zoneResources(zones), cfg.TTLFor(platform.ResZone))
	if z, found, err := pickZone(zones, arg); found {
		return z, err
	}
	if looksLikeZoneID(arg) {
		return c.GetZone(ctx, arg)
	}
	return nil, fmt.Errorf("%w: hosted zone %q in profile %s", platform.ErrNotFound, arg, prof.Name)
}

type zoneResult struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

func zoneGrid(zones []platform.Zone) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATUS", "RECORDS", "NAMESERVERS"}, Empty: "no hosted zones"}
	for _, z := range zones {
		g.Rows = append(g.Rows, []string{z.ID, z.Name, z.Status, output.Str(z.Extra["record_count"]), strings.Join(z.Nameservers, ",")})
	}
	return g
}

func zoneKV(z *platform.Zone) output.Grid {
	return output.KV("ID", z.ID, "NAME", z.Name, "STATUS", z.Status, "RECORDS", output.Str(z.Extra["record_count"]),
		"COMMENT", output.Str(z.Extra["comment"]), "NAMESERVERS", strings.Join(z.Nameservers, ","))
}

type recordResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    *platform.Zone    `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "CONTENT", "TTL", "SET", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Content
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Content)
		}
		if extraBool(r.Extra, "alias") {
			content = "ALIAS " + content
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, fmt.Sprint(r.TTL), extraString(r.Extra, "set_identifier"), r.ID})
	}
	return g
}

func sortRecords(recs []platform.Record) {
	sort.SliceStable(recs, func(i, j int) bool {
		if recs[i].Name != recs[j].Name {
			return recs[i].Name < recs[j].Name
		}
		if recs[i].Type != recs[j].Type {
			return recs[i].Type < recs[j].Type
		}
		return recs[i].Content < recs[j].Content
	})
}

func route53Cmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "route53", Short: "Route 53 hosted zones and records"}
	zone := &cobra.Command{Use: "zone", Short: "Hosted zones"}
	zone.AddCommand(zoneListCmd(rt), zoneGetCmd(rt))
	record := &cobra.Command{Use: "record", Short: "Record sets of a hosted zone (<zone> is a name or id)"}
	record.AddCommand(recordListCmd(rt), recordUpsertCmd(rt), recordDeleteCmd(rt))
	cmd.AddCommand(zone, record)
	return cmd
}

func zoneListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List hosted zones",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResZone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
				if err != nil {
					return nil, err
				}
				zones, err := c.listZonesWithNameservers(ctx)
				if err != nil {
					return nil, err
				}
				return zoneResources(zones), nil
			})
			if err != nil {
				return err
			}
			res := zoneResult{Profile: profName, Cached: cached, Zones: make([]platform.Zone, 0, len(rows))}
			for _, r := range rows {
				var z platform.Zone
				if err := r.Decode(&z); err != nil {
					return fmt.Errorf("decode cached zone %s: %w", r.ID, err)
				}
				res.Zones = append(res.Zones, z)
			}
			if cached {
				rt.Infof("%d hosted zone(s) via aws/%s (local inventory)", len(res.Zones), profName)
			}
			return rt.Render(res, func() output.Grid { return zoneGrid(res.Zones) })
		},
	}
}

func zoneGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <zone>",
		Short: "Show one hosted zone (by name or id)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			if !rt.Flags.Offline {
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if z, err = c.GetZone(cmd.Context(), z.ID); err != nil {
					return err
				}
			}
			return rt.Render(z, func() output.Grid { return zoneKV(z) })
		},
	}
}

func recordListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <zone>",
		Short: "List the records of a hosted zone (one row per value)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResDNSRecord, Scope: z.ID}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
				if err != nil {
					return nil, err
				}
				recs, err := c.ListRecords(ctx, z.ID)
				if err != nil {
					return nil, err
				}
				return app.RecordResources(z.ID, z.Name, recs), nil
			})
			if err != nil {
				return err
			}
			var recs []platform.Record
			for _, r := range rows {
				var rec platform.Record
				if err := r.Decode(&rec); err != nil {
					return fmt.Errorf("decode cached record %s: %w", r.ID, err)
				}
				recs = append(recs, rec)
			}
			if name != "" {
				fqdn := platform.FQDN(name, z.Name)
				recs = app.MatchRecords(recs, fqdn, typ, "")
			} else if typ != "" {
				var f []platform.Record
				for _, r := range recs {
					if strings.EqualFold(r.Type, typ) {
						f = append(f, r)
					}
				}
				recs = f
			}
			sortRecords(recs)
			if cached {
				rt.Infof("zone %s via aws/%s (local inventory)", z.Name, profName)
			}
			return rt.Render(recordResult{Profile: profName, Zone: z, Cached: cached, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

// zoneWithName makes sure the zone name is known (ids given with --offline
// may come without one).
func zoneWithName(ctx context.Context, rt *app.Runtime, c *client, z *platform.Zone) (*platform.Zone, error) {
	if z.Name != "" {
		return z, nil
	}
	return c.GetZone(ctx, z.ID)
}

// syncRecordRows replaces the inventory rows of (name, type) in a zone.
func syncRecordRows(ctx context.Context, rt *app.Runtime, prof string, z *platform.Zone, fqdn, typ string, recs []platform.Record) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	set := inventory.Set{Platform: platform.AWS, Profile: prof, Type: platform.ResDNSRecord}
	rows, _ := db.List(ctx, inventory.Query{Platform: set.Platform, Profile: set.Profile, Type: set.Type, ParentID: z.ID, Name: fqdn})
	for _, r := range rows {
		var rec platform.Record
		if r.Decode(&rec) == nil && strings.EqualFold(rec.Type, typ) {
			_ = db.Delete(ctx, set, platform.ResDNSRecord, r.ID)
		}
	}
	for _, res := range app.RecordResources(z.ID, z.Name, recs) {
		_ = db.Upsert(ctx, set, res, cfg.TTLFor(platform.ResDNSRecord))
	}
}

func recordUpsertCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	var values []string
	var ttl int
	cmd := &cobra.Command{
		Use:   "upsert <zone>",
		Short: "Create or replace a whole record set (name + type) with the given values",
		Long: `Create or replace the record set identified by --name and --type. Every
--value becomes one value of the set; existing values that are not repeated
are removed. MX and SRV values include their priority ("10 mail.example.com").`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" || len(values) == 0 {
				return app.UsageErrf("--type and at least one --value are required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if z, err = zoneWithName(cmd.Context(), rt, c, z); err != nil {
				return err
			}
			fqdn := platform.FQDN(name, z.Name)
			recs, err := c.ReplaceSet(cmd.Context(), z.ID, fqdn, typ, values, ttl)
			if err != nil {
				return err
			}
			syncRecordRows(cmd.Context(), rt, prof.Name, z, fqdn, typ, recs)
			rt.Infof("upserted %s %s (%d value(s)) in zone %s via aws/%s", fqdn, strings.ToUpper(typ), len(values), z.Name, prof.Name)
			return rt.Render(recordResult{Profile: prof.Name, Zone: z, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type (A, AAAA, CNAME, TXT, MX, ...)")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: the zone apex")
	cmd.Flags().StringArrayVar(&values, "value", nil, "record value (repeatable; replaces the whole set)")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = keep existing, or 300 for a new set)")
	return cmd
}

func recordDeleteCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "delete <zone>",
		Short: "Delete a whole record set (name + type)",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if typ == "" {
				return app.UsageErrf("--type is required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			z, err := resolveZone(cmd.Context(), rt, args[0])
			if err != nil {
				return err
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if z, err = zoneWithName(cmd.Context(), rt, c, z); err != nil {
				return err
			}
			fqdn := platform.FQDN(name, z.Name)
			recs, err := c.DeleteSet(cmd.Context(), z.ID, fqdn, typ)
			if err != nil {
				return err
			}
			syncRecordRows(cmd.Context(), rt, prof.Name, z, fqdn, typ, nil)
			rt.Infof("deleted %s %s (%d value(s)) from zone %s via aws/%s", fqdn, strings.ToUpper(typ), len(recs), z.Name, prof.Name)
			return rt.Render(recordResult{Profile: prof.Name, Zone: z, Records: recs}, func() output.Grid { return recordGrid(recs) })
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "record type")
	cmd.Flags().StringVar(&name, "name", "", "record name relative to the zone (www, @); default: the zone apex")
	return cmd
}

// ----------------------------------------------------- route53domains

type domainResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domains []platform.Domain `json:"domains" yaml:"domains"`
}

func domainGrid(domains []platform.Domain) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "EXPIRES", "AUTO_RENEW", "LOCKED", "PRIVACY", "NAMESERVERS"}, Empty: "no registered domains"}
	for _, d := range domains {
		g.Rows = append(g.Rows, []string{d.Name, d.ExpiresAt, output.Str(d.AutoRenew), output.Str(d.Locked), output.Str(d.Privacy), strings.Join(d.Nameservers, ",")})
	}
	return g
}

func domainKV(d *platform.Domain) output.Grid {
	return output.KV("NAME", d.Name, "STATUS", d.Status, "EXPIRES", d.ExpiresAt, "AUTO_RENEW", output.Str(d.AutoRenew),
		"LOCKED", output.Str(d.Locked), "PRIVACY", output.Str(d.Privacy), "NAMESERVERS", strings.Join(d.Nameservers, ","),
		"REGISTRAR", output.Str(d.Extra["registrar_name"]), "CREATED", output.Str(d.Extra["created_at"]))
}

func route53domainsCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "route53domains", Short: "Route 53 Domains (registrar)"}
	domain := &cobra.Command{Use: "domain", Short: "Registered domains"}
	domain.AddCommand(domainListCmd(rt), domainGetCmd(rt))
	ns := &cobra.Command{Use: "ns", Short: "Nameservers of a registered domain"}
	ns.AddCommand(nsSetCmd(rt))
	cmd.AddCommand(domain, ns)
	return cmd
}

func domainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List registered domains",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResDomain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
				if err != nil {
					return nil, err
				}
				domains, err := c.ListDomains(ctx)
				if err != nil {
					return nil, err
				}
				return app.DomainResources(domains), nil
			})
			if err != nil {
				return err
			}
			res := domainResult{Profile: profName, Cached: cached, Domains: make([]platform.Domain, 0, len(rows))}
			for _, r := range rows {
				var d platform.Domain
				if err := r.Decode(&d); err != nil {
					return fmt.Errorf("decode cached domain %s: %w", r.ID, err)
				}
				res.Domains = append(res.Domains, d)
			}
			if cached {
				rt.Infof("%d registered domain(s) via aws/%s (local inventory)", len(res.Domains), profName)
			}
			return rt.Render(res, func() output.Grid { return domainGrid(res.Domains) })
		},
	}
}

func cachedDomain(ctx context.Context, rt *app.Runtime, profName, name string) (*platform.Domain, error) {
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	r, err := db.Get(ctx, inventory.Set{Platform: platform.AWS, Profile: profName}, platform.ResDomain, platform.NormalizeDomain(name))
	if err != nil {
		return nil, fmt.Errorf("%w: domain %q is not in the local inventory", platform.ErrNotFound, name)
	}
	var d platform.Domain
	if err := r.Decode(&d); err != nil {
		return nil, err
	}
	return &d, nil
}

func storeDomain(ctx context.Context, rt *app.Runtime, profName string, d *platform.Domain) {
	if db, err := rt.DB(); err == nil {
		cfg, _ := rt.Config()
		_ = db.Upsert(ctx, inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResDomain},
			app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain))
	}
}

func domainGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show one registered domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			var d *platform.Domain
			if rt.Flags.Offline {
				if d, err = cachedDomain(cmd.Context(), rt, profName, args[0]); err != nil {
					return err
				}
			} else {
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if d, err = c.GetDomain(cmd.Context(), args[0]); err != nil {
					return err
				}
				storeDomain(cmd.Context(), rt, profName, d)
			}
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
}

func nsSetCmd(rt *app.Runtime) *cobra.Command {
	var ns []string
	cmd := &cobra.Command{
		Use:   "set <domain>",
		Short: "Replace the nameservers of a registered domain",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(ns) == 0 {
				return app.UsageErrf("--ns is required")
			}
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if err := c.SetNameservers(cmd.Context(), name, ns); err != nil {
				return err
			}
			rt.Infof("nameservers of %s set to %s via aws/%s", name, strings.Join(ns, ","), prof.Name)
			d, err := c.GetDomain(cmd.Context(), name)
			if err != nil {
				rt.Infof("note: could not re-read the domain: %v", err)
				d = &platform.Domain{Name: name, Nameservers: ns}
			} else {
				storeDomain(cmd.Context(), rt, prof.Name, d)
			}
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
	cmd.Flags().StringSliceVar(&ns, "ns", nil, "comma-separated nameservers (ns1.example.com,ns2.example.com)")
	return cmd
}

// ---------------------------------------------------------------- ec2

type instanceResult struct {
	Profile   string         `json:"profile" yaml:"profile"`
	Region    string         `json:"region" yaml:"region"`
	Cached    bool           `json:"cached" yaml:"cached"`
	Instances []instanceInfo `json:"instances" yaml:"instances"`
}

func instanceGrid(instances []instanceInfo) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATE", "TYPE", "AZ", "PRIVATE_IP", "PUBLIC_IP"}, Empty: "no instances"}
	for _, i := range instances {
		g.Rows = append(g.Rows, []string{i.ID, i.Name, i.State, i.Type, i.AZ, i.PrivateIP, i.PublicIP})
	}
	return g
}

func ec2Cmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "ec2", Short: "EC2 instances"}
	cmd.AddCommand(ec2ListCmd(rt), ec2StateCmd(rt, "start"), ec2StateCmd(rt, "stop"))
	return cmd
}

func ec2ListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List EC2 instances (the profile's default region is cached locally)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			profName, err := rt.ProfileFor(platform.AWS)
			if err != nil {
				return err
			}
			res := instanceResult{Profile: profName, Region: region}
			if region != "" {
				if rt.Flags.Offline {
					return app.ErrOffline
				}
				c, _, err := openClient(cmd.Context(), rt)
				if err != nil {
					return err
				}
				if res.Instances, err = c.describeInstances(cmd.Context(), region); err != nil {
					return err
				}
				return rt.Render(res, func() output.Grid { return instanceGrid(res.Instances) })
			}
			set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResInstance}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, _, err := openClient(ctx, rt)
				if err != nil {
					return nil, err
				}
				res.Region = c.region
				return c.Sync(ctx, platform.ResInstance)
			})
			if err != nil {
				return err
			}
			res.Cached = cached
			for _, r := range rows {
				var i instanceInfo
				if err := r.Decode(&i); err != nil {
					return fmt.Errorf("decode cached instance %s: %w", r.ID, err)
				}
				if res.Region == "" {
					res.Region = i.Region
				}
				res.Instances = append(res.Instances, i)
			}
			if cached {
				rt.Infof("%d instance(s) via aws/%s (local inventory)", len(res.Instances), profName)
			}
			return rt.Render(res, func() output.Grid { return instanceGrid(res.Instances) })
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "list another region (bypasses the local inventory)")
	return cmd
}

type stateChangeResult struct {
	Profile string                `json:"profile" yaml:"profile"`
	Region  string                `json:"region" yaml:"region"`
	Changes []instanceStateChange `json:"changes" yaml:"changes"`
}

func ec2StateCmd(rt *app.Runtime, action string) *cobra.Command {
	var region string
	var force bool
	cmd := &cobra.Command{
		Use:   action + " <instance-id>",
		Short: strings.ToUpper(action[:1]) + action[1:] + " an EC2 instance",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			c, prof, err := openClient(cmd.Context(), rt)
			if err != nil {
				return err
			}
			if region == "" {
				region = c.region
			}
			var changes []instanceStateChange
			if action == "start" {
				changes, err = c.startInstance(cmd.Context(), region, args[0])
			} else {
				changes, err = c.stopInstance(cmd.Context(), region, args[0], force)
			}
			if err != nil {
				return err
			}
			updateInstanceState(cmd.Context(), rt, prof.Name, changes)
			for _, ch := range changes {
				rt.Infof("%s %s: %s -> %s via aws/%s", action, ch.ID, ch.PreviousState, ch.CurrentState, prof.Name)
			}
			res := stateChangeResult{Profile: prof.Name, Region: region, Changes: changes}
			return rt.Render(res, func() output.Grid {
				g := output.Grid{Headers: []string{"ID", "PREVIOUS", "CURRENT"}}
				for _, ch := range changes {
					g.Rows = append(g.Rows, []string{ch.ID, ch.PreviousState, ch.CurrentState})
				}
				return g
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: the profile's region)")
	if action == "stop" {
		cmd.Flags().BoolVar(&force, "force", false, "force the instance to stop without a clean shutdown")
	}
	return cmd
}

// updateInstanceState reflects a start/stop in the cached instance row.
func updateInstanceState(ctx context.Context, rt *app.Runtime, profName string, changes []instanceStateChange) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	set := inventory.Set{Platform: platform.AWS, Profile: profName, Type: platform.ResInstance}
	for _, ch := range changes {
		r, err := db.Get(ctx, set, platform.ResInstance, ch.ID)
		if err != nil {
			continue
		}
		var i instanceInfo
		if r.Decode(&i) != nil {
			continue
		}
		i.State = ch.CurrentState
		_ = db.Upsert(ctx, set, i.resource(), cfg.TTLFor(platform.ResInstance))
	}
}
