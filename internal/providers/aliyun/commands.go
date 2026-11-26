package aliyun

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Command returns the `polyctl aliyun` command tree.
func Command(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "aliyun",
		Short: "Alibaba Cloud native commands",
		Long: `Alibaba Cloud native commands: the identity check, Alibaba Cloud DNS (alidns)
domains and records, the domain registrar, ECS instances, security groups and
key pairs, VPCs, vSwitches, elastic IP addresses, Application Load Balancers
(ALB) and the certificates uploaded to Certificate Management Service (CAS). The profile is chosen with --profile (or the current/only aliyun
profile); listing commands read the local inventory unless --refresh is given
or the data has expired.`,
	}
	cmd.AddCommand(
		app.WhoamiCommand(rt, platform.Aliyun, "On Alibaba Cloud this calls sts GetCallerIdentity and reports the account,\nthe ARN and the identity type."),
		newDNSCmd(rt), newDomainCmd(rt), newECSCmd(rt), newVPCCmd(rt), newEIPCmd(rt), newALBCmd(rt), newCASCmd(rt))
	return cmd
}

// openClient opens the aliyun client for the selected profile.
func openClient(rt *app.Runtime, ctx context.Context) (*client, platform.Profile, error) {
	c, p, err := rt.OpenFor(ctx, platform.Aliyun)
	if err != nil {
		return nil, p, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, p, fmt.Errorf("profile %q did not open an Alibaba Cloud client", p.Name)
	}
	return ac, p, nil
}

// openNamed opens a specific profile (used inside EnsureSet fetch callbacks).
func openNamed(rt *app.Runtime, ctx context.Context, name string) (*client, error) {
	c, _, err := rt.Open(ctx, name, platform.Aliyun)
	if err != nil {
		return nil, err
	}
	ac, ok := c.(*client)
	if !ok {
		return nil, fmt.Errorf("profile %q did not open an Alibaba Cloud client", name)
	}
	return ac, nil
}

func cacheNote(cached bool) string {
	if cached {
		return " (local inventory)"
	}
	return ""
}

func mustPositive(flag string, v int) error {
	if v < 0 {
		return fmt.Errorf("--%s must not be negative", flag)
	}
	return nil
}

// ---- dns -------------------------------------------------------------------

type zoneList struct {
	Profile string          `json:"profile" yaml:"profile"`
	Cached  bool            `json:"cached" yaml:"cached"`
	Zones   []platform.Zone `json:"zones" yaml:"zones"`
}

type recordList struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    string            `json:"zone" yaml:"zone"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func newDNSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "dns", Short: "Alibaba Cloud DNS (alidns) domains and records"}
	domain := &cobra.Command{Use: "domain", Short: "DNS domains hosted on alidns"}
	domain.AddCommand(newDNSDomainListCmd(rt))
	record := &cobra.Command{Use: "record", Short: "Records of an alidns domain"}
	record.AddCommand(newDNSRecordListCmd(rt), newDNSRecordCreateCmd(rt), newDNSRecordUpdateCmd(rt), newDNSRecordDeleteCmd(rt))
	cmd.AddCommand(domain, record)
	return cmd
}

func newDNSDomainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List DNS domains (zones) hosted on alidns",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: name, Type: platform.ResZone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, name)
				if err != nil {
					return nil, err
				}
				zones, err := c.ListZones(ctx)
				if err != nil {
					return nil, err
				}
				return app.ZoneResources(zones), nil
			})
			if err != nil {
				return err
			}
			zones := make([]platform.Zone, 0, len(rows))
			for _, r := range rows {
				var z platform.Zone
				if err := r.Decode(&z); err != nil {
					return fmt.Errorf("decode cached zone %s: %w", r.ID, err)
				}
				zones = append(zones, z)
			}
			rt.Infof("%d domain(s) via aliyun/%s%s", len(zones), name, cacheNote(cached))
			return rt.Render(zoneList{Profile: name, Cached: cached, Zones: zones}, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "VERSION", "RECORDS", "NAMESERVERS"}, Empty: "no domains"}
				for _, z := range zones {
					g.Rows = append(g.Rows, []string{z.Name, z.Status, output.Str(z.Extra["record_count"]), strings.Join(z.Nameservers, ",")})
				}
				return g
			})
		},
	}
}

func recordGrid(recs []platform.Record) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "VALUE", "TTL", "LINE", "STATUS", "ID"}, Empty: "no records"}
	for _, r := range recs {
		content := r.Value
		if r.Priority != nil {
			content = fmt.Sprintf("%d %s", *r.Priority, r.Value)
		}
		g.Rows = append(g.Rows, []string{r.Name, r.Type, content, platform.TTLLabel(platform.Aliyun, r), output.Str(r.Extra["line"]), output.Str(r.Extra["status"]), r.ID})
	}
	return g
}

func newDNSRecordListCmd(rt *app.Runtime) *cobra.Command {
	var typ, name string
	cmd := &cobra.Command{
		Use:   "list <domain>",
		Short: "List the records of an alidns domain",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.Aliyun, platform.ResZone, nil)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDNSRecord, Scope: zone}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				recs, err := c.ListRecords(ctx, zone)
				if err != nil {
					return nil, err
				}
				return app.RecordResources(zone, zone, recs), nil
			})
			if err != nil {
				return err
			}
			recs := make([]platform.Record, 0, len(rows))
			for _, r := range rows {
				var rec platform.Record
				if err := r.Decode(&rec); err != nil {
					return fmt.Errorf("decode cached record %s: %w", r.ID, err)
				}
				recs = append(recs, rec)
			}
			if name != "" {
				recs = app.MatchRecords(recs, platform.FQDN(name, zone), typ, "")
			} else if typ != "" {
				var f []platform.Record
				for _, r := range recs {
					if strings.EqualFold(r.Type, typ) {
						f = append(f, r)
					}
				}
				recs = f
			}
			sort.SliceStable(recs, func(i, j int) bool {
				if recs[i].Name != recs[j].Name {
					return recs[i].Name < recs[j].Name
				}
				return recs[i].Type < recs[j].Type
			})
			rt.Infof("%d record(s) in %s via aliyun/%s%s", len(recs), zone, prof, cacheNote(cached))
			return rt.Render(recordList{Profile: prof, Zone: zone, Cached: cached, Records: recs}, func() output.Grid {
				return recordGrid(recs)
			})
		},
	}
	cmd.Flags().StringVar(&typ, "type", "", "filter by record type")
	cmd.Flags().StringVar(&name, "name", "", "filter by record name (relative, @ or FQDN)")
	return cmd
}

// upsertRecord mirrors a mutated record into the inventory.
func upsertRecord(rt *app.Runtime, ctx context.Context, prof, zone string, rec platform.Record) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDNSRecord},
		app.RecordResources(zone, zone, []platform.Record{rec})[0], cfg.TTLFor(platform.ResDNSRecord))
}

func newDNSRecordCreateCmd(rt *app.Runtime) *cobra.Command {
	var line string
	var ttl, priority int
	cmd := &cobra.Command{
		Use:   "create <domain> <name> <type> <value>",
		Short: "Create a record in an alidns domain",
		Long: `Create one record in <domain>.

` + app.RecordArgsHelp("domain") + `
` + app.PlatformRecordTypesHelp(platform.Aliyun) + `

` + app.RecordAskHelp("domain"),
		Example: `  polyctl aliyun dns record create example.com www A 203.0.113.10
  polyctl aliyun dns record create example.com @ MX mail.example.com --priority 10
  polyctl aliyun dns record create example.com www CNAME target.example.net --line telecom`,
		Args:              app.RecordArgsOrInteractive(rt, 1, 1),
		ValidArgsFunction: app.CompleteRecordArgs(app.CompleteDomainArg(rt, platform.Aliyun), platform.Aliyun),
		RunE: func(cmd *cobra.Command, args []string) error {
			// The record is positional (<name> <type> <value>) or, in the
			// former form, given with --name, --type and --value.
			in, err := rt.RecordInput(cmd, args, app.RecordForm{MinValues: 1, MaxValues: 1, Platform: platform.Aliyun, Creates: true})
			if err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args[:min(len(args), 1)], platform.Aliyun, platform.ResZone, nil)
			if err != nil {
				return app.RequiredPick(err, "<domain>")
			}
			if err := mustPositive("ttl", ttl); err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			if err := rt.CompleteRecord(in, app.RecordPrompt{Platform: platform.Aliyun, Zone: zone,
				Existing: func() ([]platform.Record, error) { return c.ListRecords(cmd.Context(), zone) }}); err != nil {
				return err
			}
			checked, err := in.Check(cmd, "")
			if err != nil {
				return err
			}
			v := checked[0]
			rec := platform.Record{ZoneID: zone, Name: platform.FQDN(in.Name, zone), Type: v.Type, Value: v.Value, Priority: v.Priority, TTL: ttl}
			if line != "" {
				rec.Extra = map[string]any{"line": line}
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.Aliyun, Profile: p.Name, Domain: zone}, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Created, Detail: rec.Value}); done || err != nil {
				return err
			}
			out, err := c.CreateRecord(cmd.Context(), zone, rec)
			if err != nil {
				return err
			}
			upsertRecord(rt, cmd.Context(), p.Name, zone, *out)
			rt.Infof("created %s %s -> %s (id %s) via aliyun/%s", out.Name, out.Type, out.Value, out.ID, p.Name)
			return rt.Render(recordList{Profile: p.Name, Zone: zone, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	app.FormerRecordFlags(cmd, false)
	cmd.Flags().IntVar(&ttl, "ttl", 0, "TTL in seconds (0 = alidns default, 600)")
	cmd.Flags().IntVar(&priority, "priority", 0, "priority for MX records (1-50)")
	cmd.Flags().StringVar(&line, "line", "", "resolution line (default, telecom, unicom, mobile, oversea, ...)")
	return cmd
}

// recordTargetForm is the form of update and delete: the record by name,
// --id, or the former <record-id> after the first argument.
var recordTargetForm = app.RecordTargetForm{FormerID: true}

// recordTargetHelp says how update and delete find their record.
var recordTargetHelp = recordTargetForm.Help("domain", "polyctl aliyun dns record list")

// lineQualifier is the resolution line as one more way to tell records
// apart: alidns holds a record of one name, type and value once per line.
// flag is the flag of the command that says which line is meant.
func lineQualifier(flag, line string) []app.RecordQualifier {
	return []app.RecordQualifier{{Flag: flag, Noun: "line", Value: line, Of: recordLine}}
}

// lineMark notes the line of a record in a list when it is not the default
// one.
func lineMark(r platform.Record) string {
	if l := recordLine(r); l != "" && l != defaultLine {
		return "line " + l
	}
	return ""
}

// lineWithID refuses a line beside --id, which names the record already.
func lineWithID(cmd *cobra.Command, flag string) error {
	if cmd.Flags().Changed("id") && cmd.Flags().Changed(flag) {
		return app.UsageErrf("--id selects one record; it cannot be combined with --%s", flag)
	}
	return nil
}

func newDNSRecordUpdateCmd(rt *app.Runtime) *cobra.Command {
	var typ, name, value, line, id, currentLine string
	var ttl, priority int
	changeFlags := []string{"value", "ttl", "priority", "line", "name", "type"}
	cmd := &cobra.Command{
		Use:   "update <domain> [<name> [<type> [<value>]]]",
		Short: "Update one record (fields that are not given keep their value)",
		Long: `Update one record of <domain>: the record of <name>, or the one with --id.
Only the fields given with flags are changed; the positional <type> and
<value> say which record is meant, --type and --value what it becomes.

` + recordTargetHelp + `

A record can exist once per resolution line. --current-line says which line
the record meant is on, and is needed only when records of the name differ in
nothing else; --line is the line the record is moved to.

` + app.RecordUpdateHelp,
		Example: `  polyctl aliyun dns record update example.com www --value 203.0.113.20
  polyctl aliyun dns record update example.com www A 203.0.113.10 --value 203.0.113.20
  polyctl aliyun dns record update example.com www A --current-line telecom --ttl 900
  polyctl aliyun dns record update example.com --id 9001 --line unicom`,
		Args:              recordTargetForm.ArgsOrInteractive(rt),
		ValidArgsFunction: recordTargetForm.Complete(rt, app.CompleteDomainArg(rt, platform.Aliyun), platform.Aliyun),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := recordTargetForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			if err := lineWithID(cmd, "current-line"); err != nil {
				return err
			}
			changes, err := rt.RecordChanges(cmd, changeFlags...)
			if err != nil {
				return err
			}
			if err := mustPositive("ttl", ttl); err != nil {
				return err
			}
			if err := app.CheckRecordChange(cmd, platform.Aliyun, target.TypeOf()); err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args, platform.Aliyun, platform.ResZone, nil)
			if err != nil {
				return err
			}
			zone := platform.NormalizeDomain(args[0])
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			existing, err := c.ListRecords(cmd.Context(), zone)
			if err != nil {
				return err
			}
			chosen, err := rt.SelectRecords(target.Select(app.RecordSelect{Zone: zone, Records: existing, ID: id, One: true, Verb: "Update",
				Qualifiers: lineQualifier("--current-line", currentLine), Mark: lineMark, Grid: recordGrid}))
			if err != nil {
				return err
			}
			cur := chosen.Records[0]
			if !changes {
				if value, err = rt.AskNewRecordValue(cur); err != nil {
					return err
				}
			}
			rec := cur
			rec.Extra = make(map[string]any, len(cur.Extra)+1)
			for k, v := range cur.Extra {
				rec.Extra[k] = v
			}
			if typ != "" {
				rec.Type = strings.ToUpper(typ)
			}
			if cmd.Flags().Changed("name") {
				rec.Name = platform.FQDN(name, zone)
			}
			if value != "" {
				rec.Value = value
			}
			if cmd.Flags().Changed("ttl") {
				rec.TTL = ttl
			}
			if cmd.Flags().Changed("priority") {
				pr := priority
				rec.Priority = &pr
			}
			if line != "" {
				rec.Extra["line"] = line
			}
			if err := app.CheckRecordUpdate(cmd, platform.Aliyun, cur, &rec); err != nil {
				return err
			}
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.Aliyun, Profile: p.Name, Domain: zone}, platform.Change{Resource: app.RecordResource(rec.Name, rec.Type), Action: platform.Updated, ID: cur.ID, Detail: cur.Value + " -> " + rec.Value}); done || err != nil {
				return err
			}
			out, err := c.UpdateRecord(cmd.Context(), zone, rec)
			if err != nil {
				return err
			}
			upsertRecord(rt, cmd.Context(), p.Name, zone, *out)
			rt.Infof("updated %s %s -> %s (id %s) via aliyun/%s", out.Name, out.Type, out.Value, out.ID, p.Name)
			return rt.Render(recordList{Profile: p.Name, Zone: zone, Records: []platform.Record{*out}}, func() output.Grid {
				return recordGrid([]platform.Record{*out})
			})
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "update the record with this id")
	cmd.Flags().StringVar(&currentLine, "current-line", "", "the resolution line the record is on, to tell records apart")
	cmd.Flags().StringVar(&typ, "type", "", "new record type")
	cmd.Flags().StringVar(&name, "name", "", "new record name relative to the domain (www, @)")
	cmd.Flags().StringVar(&value, "value", "", "new record value")
	cmd.Flags().IntVar(&ttl, "ttl", 0, "new TTL in seconds")
	cmd.Flags().IntVar(&priority, "priority", 0, "new priority for MX records")
	cmd.Flags().StringVar(&line, "line", "", "new resolution line")
	return cmd
}

// recordDeleteResult is the output of dns record delete. Deleted is the id
// of the record when one was deleted, as the command printed it when it took
// one record id.
type recordDeleteResult struct {
	Profile string            `json:"profile" yaml:"profile"`
	Zone    string            `json:"zone" yaml:"zone"`
	Deleted string            `json:"deleted,omitempty" yaml:"deleted,omitempty"`
	Records []platform.Record `json:"records" yaml:"records"`
}

func newDNSRecordDeleteCmd(rt *app.Runtime) *cobra.Command {
	var id, line string
	cmd := &cobra.Command{
		Use:   "delete <domain> [<name> [<type> [<value>]]]",
		Short: "Delete the records of a name (optionally of one type, value and line), or one record by --id",
		Long: `Delete the records of <name> in <domain>, or the one record with --id.

` + recordTargetHelp + `

A record can exist once per resolution line. --line deletes the records on
that line only, and is needed only when records of the name differ in nothing
else.

` + app.RecordDeleteHelp + `

--dry-run reports what would be deleted and asks nothing.`,
		Example: `  polyctl aliyun dns record delete example.com www
  polyctl aliyun dns record delete example.com www A
  polyctl aliyun dns record delete example.com www A 203.0.113.10
  polyctl aliyun dns record delete example.com www A --line telecom
  polyctl aliyun dns record delete example.com --id 9001`,
		Args:              recordTargetForm.ArgsOrInteractive(rt),
		ValidArgsFunction: recordTargetForm.Complete(rt, app.CompleteDomainArg(rt, platform.Aliyun), platform.Aliyun),
		RunE: func(cmd *cobra.Command, args []string) error {
			target, err := recordTargetForm.Parse(cmd, args)
			if err != nil {
				return err
			}
			if err := lineWithID(cmd, "line"); err != nil {
				return err
			}
			args, err = rt.DomainArg(cmd.Context(), args, platform.Aliyun, platform.ResZone, nil)
			if err != nil {
				return err
			}
			domain := platform.NormalizeDomain(args[0])
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			existing, err := c.ListRecords(cmd.Context(), domain)
			if err != nil {
				return err
			}
			zone := platform.Zone{ID: domain, Name: domain}
			sel := target.Select(app.RecordSelect{Zone: domain, Records: existing, ID: id, Verb: "Delete",
				Qualifiers: lineQualifier("--line", line), Mark: lineMark, Grid: recordGrid})
			sel.Offer, _ = app.DeletableRecords(c, zone)
			chosen, err := rt.SelectRecords(sel)
			if err != nil {
				return err
			}
			del := app.RecordsDelete{Target: platform.Target{Platform: platform.Aliyun, Profile: p.Name, Domain: domain},
				Zone: zone, DNS: c, Records: chosen.Records, Grid: recordGrid, Exact: sel.Exact(chosen)}
			if done, err := rt.DeleteRecords(cmd.Context(), del); !done || err != nil {
				return err
			}
			res := recordDeleteResult{Profile: p.Name, Zone: domain, Records: chosen.Records}
			if len(chosen.Records) == 1 {
				res.Deleted = chosen.Records[0].ID
			}
			return rt.Render(res, func() output.Grid { return output.Grid{} })
		},
	}
	cmd.Flags().StringVar(&id, "id", "", "delete the record with this id")
	cmd.Flags().StringVar(&line, "line", "", "only the records on this resolution line, to tell records apart")
	return cmd
}

// ---- domain (registrar) ----------------------------------------------------

type domainList struct {
	Profile string            `json:"profile" yaml:"profile"`
	Cached  bool              `json:"cached" yaml:"cached"`
	Domains []platform.Domain `json:"domains" yaml:"domains"`
}

func newDomainCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "domain", Short: "Registered domains (Alibaba Cloud domain registrar)"}
	ns := &cobra.Command{Use: "ns", Short: "Nameservers of a registered domain"}
	ns.AddCommand(newDomainNSGetCmd(rt), newDomainNSSetCmd(rt))
	cmd.AddCommand(newDomainListCmd(rt), newDomainGetCmd(rt), ns)
	return cmd
}

// nameserversResult is the output of `aliyun domain ns get`.
type nameserversResult struct {
	Profile     string   `json:"profile" yaml:"profile"`
	Cached      bool     `json:"cached" yaml:"cached"`
	Domain      string   `json:"domain" yaml:"domain"`
	Nameservers []string `json:"nameservers" yaml:"nameservers"`
}

func newDomainNSGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show the nameservers of a registered domain (local inventory when fresh or --offline)",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.Aliyun, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(rt, cmd.Context(), prof, platform.NormalizeDomain(args[0]))
			if err != nil {
				return err
			}
			rt.Infof("domain %s via aliyun/%s%s", d.Name, prof, cacheNote(cached))
			res := nameserversResult{Profile: prof, Cached: cached, Domain: d.Name, Nameservers: d.Nameservers}
			return rt.Render(res, func() output.Grid {
				g := output.Grid{Headers: []string{"NAMESERVER"}, Empty: "no nameservers"}
				for _, n := range d.Nameservers {
					g.Rows = append(g.Rows, []string{n})
				}
				return g
			})
		},
	}
}

func newDomainListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List domains registered with Alibaba Cloud",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDomain}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
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
			domains := make([]platform.Domain, 0, len(rows))
			for _, r := range rows {
				var d platform.Domain
				if err := r.Decode(&d); err != nil {
					return fmt.Errorf("decode cached domain %s: %w", r.ID, err)
				}
				domains = append(domains, d)
			}
			rt.Infof("%d domain(s) via aliyun/%s%s", len(domains), prof, cacheNote(cached))
			return rt.Render(domainList{Profile: prof, Cached: cached, Domains: domains}, func() output.Grid {
				g := output.Grid{Headers: []string{"DOMAIN", "STATUS", "EXPIRES", "NAMESERVERS"}, Empty: "no domains"}
				for _, d := range domains {
					g.Rows = append(g.Rows, []string{d.Name, d.Status, d.ExpiresAt, strings.Join(d.Nameservers, ",")})
				}
				return g
			})
		},
	}
}

func domainKV(d *platform.Domain) output.Grid {
	pairs := []string{"DOMAIN", d.Name, "STATUS", d.Status, "EXPIRES", d.ExpiresAt, "NAMESERVERS", strings.Join(d.Nameservers, ","),
		"LOCKED", output.Str(d.Locked), "PRIVACY", output.Str(d.Privacy)}
	keys := make([]string, 0, len(d.Extra))
	for k := range d.Extra {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pairs = append(pairs, strings.ToUpper(k), output.Str(d.Extra[k]))
	}
	return output.KV(pairs...)
}

// domainDetail is the output of `aliyun domain get`: the domain plus where
// it came from.
type domainDetail struct {
	*platform.Domain `yaml:",inline"`
	Profile          string `json:"profile" yaml:"profile"`
	Cached           bool   `json:"cached" yaml:"cached"`
}

// loadDomain returns the registrar record of a domain from the local
// inventory when it is fresh (or --offline), otherwise from the registrar
// (mirroring it into the inventory).
func loadDomain(rt *app.Runtime, ctx context.Context, prof, name string) (*platform.Domain, bool, error) {
	set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDomain}
	need, err := rt.NeedsRefresh(ctx, set)
	if err != nil {
		return nil, false, err
	}
	if need {
		c, err := openNamed(rt, ctx, prof)
		if err != nil {
			return nil, false, err
		}
		d, err := c.GetDomain(ctx, name)
		if err != nil {
			return nil, false, err
		}
		upsertDomain(rt, ctx, prof, d)
		return d, false, nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil, false, err
	}
	r, err := db.Get(ctx, set, platform.ResDomain, name)
	if err != nil {
		return nil, false, fmt.Errorf("domain %s in the local inventory of aliyun/%s: %w", name, prof, err)
	}
	var d platform.Domain
	if err := r.Decode(&d); err != nil {
		return nil, false, fmt.Errorf("decode cached domain %s: %w", name, err)
	}
	return &d, true, nil
}

// upsertDomain mirrors a registrar record into the inventory.
func upsertDomain(rt *app.Runtime, ctx context.Context, prof string, d *platform.Domain) {
	db, err := rt.DB()
	if err != nil {
		return
	}
	cfg, _ := rt.Config()
	_ = db.Upsert(ctx, inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResDomain},
		app.DomainResources([]platform.Domain{*d})[0], cfg.TTLFor(platform.ResDomain))
}

func newDomainGetCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "get <domain>",
		Short: "Show a registered domain (QueryDomainByDomainName, or the local inventory when fresh)",
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.Aliyun, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			d, cached, err := loadDomain(rt, cmd.Context(), prof, platform.NormalizeDomain(args[0]))
			if err != nil {
				return err
			}
			rt.Infof("domain %s via aliyun/%s%s", d.Name, prof, cacheNote(cached))
			return rt.Render(domainDetail{Domain: d, Profile: prof, Cached: cached}, func() output.Grid { return domainKV(d) })
		},
	}
}

func newDomainNSSetCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "set <domain> <nameserver>...",
		Short:   "Replace the nameservers of a registered domain",
		Long:    "Replace the nameservers of <domain> with the ones given.\n" + app.NameserverHelp,
		Example: "  polyctl aliyun domain ns set example.com ns1.example.net ns2.example.net",
		Args:    app.NameserverArgsOrInteractive(rt),
		RunE: func(cmd *cobra.Command, args []string) error {
			args, err := rt.DomainArg(cmd.Context(), args, platform.Aliyun, platform.ResDomain, nil)
			if err != nil {
				return err
			}
			if len(args) < 2 {
				more, err := rt.PickNameservers(cmd.Context(), args[0])
				if err != nil {
					return err
				}
				args = append(args, more...)
			}
			ns, err := app.Nameservers(args[1:])
			if err != nil {
				return err
			}
			c, p, err := openClient(rt, cmd.Context())
			if err != nil {
				return err
			}
			name := platform.NormalizeDomain(args[0])
			if done, err := rt.WouldWrite(platform.Target{Platform: platform.Aliyun, Profile: p.Name, Domain: name}, app.NameserverChange(name, ns)); done || err != nil {
				return err
			}
			// SetNameservers waits for the registrar task; on ErrTaskPending
			// (or any failure) nothing is mirrored into the inventory.
			if err := c.SetNameservers(cmd.Context(), name, ns); err != nil {
				return err
			}
			rt.Infof("nameservers of %s updated via aliyun/%s", name, p.Name)
			d, err := c.GetDomain(cmd.Context(), name)
			if err != nil {
				return rt.Render(map[string]any{"profile": p.Name, "domain": name, "nameservers": ns}, func() output.Grid {
					return output.KV("DOMAIN", name, "NAMESERVERS", strings.Join(ns, ","))
				})
			}
			upsertDomain(rt, cmd.Context(), p.Name, d)
			return rt.Render(d, func() output.Grid { return domainKV(d) })
		},
	}
	return cmd
}

// ---- ecs -------------------------------------------------------------------

type instanceList struct {
	Profile   string     `json:"profile" yaml:"profile"`
	Region    string     `json:"region,omitempty" yaml:"region,omitempty"`
	Cached    bool       `json:"cached" yaml:"cached"`
	Instances []Instance `json:"instances" yaml:"instances"`
}

func instanceGrid(list []Instance) output.Grid {
	g := output.Grid{Headers: []string{"ID", "NAME", "STATUS", "TYPE", "ZONE", "PRIVATE IP", "PUBLIC IP"}, Empty: "no instances"}
	for _, in := range list {
		g.Rows = append(g.Rows, []string{in.ID, in.Name, in.Status, in.Type, in.Zone, in.PrivateIP, in.PublicIP})
	}
	return g
}

func newECSCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{Use: "ecs", Short: "Elastic Compute Service: instances, security groups, key pairs and images"}
	instance := &cobra.Command{Use: "instance", Short: "ECS instances"}
	instance.AddCommand(newECSListCmd(rt), ecsGetCmd(rt), ecsCreateCmd(rt), ecsDeleteCmd(rt), ecsRebootCmd(rt), ecsResizeCmd(rt),
		newECSStartCmd(rt), newECSStopCmd(rt), ecsEnsureCmd(rt), ecsPasswordCmd(rt), ecsSSHKeyCmd(rt))
	cmd.AddCommand(instance, newSecurityGroupCmd(rt), newKeyPairCmd(rt), newImageCmd(rt))
	return cmd
}

func newECSListCmd(rt *app.Runtime) *cobra.Command {
	var region string
	cmd := &cobra.Command{
		Use:   "list",
		Short: "List ECS instances in the profile region (or --region)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			prof, err := rt.ProfileFor(platform.Aliyun)
			if err != nil {
				return err
			}
			region, err := resolveRegion(rt, prof, region)
			if err != nil {
				return err
			}
			// The set is always scoped to a region: instances are stored with
			// their region as ParentID, and an unscoped read would return the
			// instances of every region listed before.
			set := inventory.Set{Platform: platform.Aliyun, Profile: prof, Type: platform.ResInstance, Scope: region}
			rows, cached, err := rt.EnsureSet(cmd.Context(), set, func(ctx context.Context) ([]platform.Resource, error) {
				c, err := openNamed(rt, ctx, prof)
				if err != nil {
					return nil, err
				}
				return c.instanceResources(ctx, region)
			})
			if err != nil {
				return err
			}
			list := make([]Instance, 0, len(rows))
			for _, r := range rows {
				var in Instance
				if err := r.Decode(&in); err != nil {
					return fmt.Errorf("decode cached instance %s: %w", r.ID, err)
				}
				list = append(list, in)
			}
			rt.Infof("%d instance(s) in %s via aliyun/%s%s", len(list), region, prof, cacheNote(cached))
			return rt.Render(instanceList{Profile: prof, Region: region, Cached: cached, Instances: list}, func() output.Grid {
				return instanceGrid(list)
			})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region id (default: the profile's region)")
	return cmd
}

// resolveRegion returns the explicit region or the profile's region
// (metadata "region", else DefaultRegion), as the client would use.
func resolveRegion(rt *app.Runtime, prof, region string) (string, error) {
	if region != "" {
		return region, nil
	}
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	p, err := cfg.Account(prof, platform.Aliyun)
	if err != nil {
		return "", err
	}
	if r := strings.TrimSpace(p.Metadata[metaRegion]); r != "" {
		return r, nil
	}
	return DefaultRegion, nil
}

// refreshInstance re-reads an instance after start/stop and mirrors it into the inventory.
func refreshInstance(rt *app.Runtime, ctx context.Context, c *client, prof, region, id string) *Instance {
	in, err := c.describeInstance(ctx, region, id)
	if err != nil {
		return nil
	}
	storeInstance(ctx, rt, prof, *in)
	return in
}

func newECSStartCmd(rt *app.Runtime) *cobra.Command { return newECSPowerCmd(rt, "start") }

func newECSStopCmd(rt *app.Runtime) *cobra.Command { return newECSPowerCmd(rt, "stop") }

// newECSPowerCmd builds `ecs instance start` and `stop`.
func newECSPowerCmd(rt *app.Runtime, verb string) *cobra.Command {
	var region string
	var force bool
	var w app.WaitFlags
	want := instRunning
	if verb == "stop" {
		want = instStopped
	}
	title := strings.ToUpper(verb[:1]) + verb[1:]
	long := title + ` an ECS instance, found like get finds it. An instance that is ` + want + `
already is unchanged (exit code 0). --wait waits until it is ` + want + ` (polled
every 2 seconds, bounded by --timeout).`
	if verb == "stop" {
		long += `

In the interactive flow the stop is confirmed first (default no); --yes
skips the question. In the non-interactive flow (no terminal,
--non-interactive or POLYCTL_NON_INTERACTIVE=1) nothing is asked: --yes is
required, and without it the command is a usage error (exit code 2) raised
before the account is opened. A declined confirmation is exit code 0.
--force stops the instance hard (ForceStop: like pulling the power).`
	}
	cmd := &cobra.Command{
		Use:   verb + " <name|id>",
		Short: title + " an ECS instance",
		Long:  long,
		Args:  app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			wait, timeout, err := w.Resolve(cmd)
			if err != nil {
				return err
			}
			// start offers the Stopped instances, stop the running ones.
			keep, what := statusIn(instStopped), "Stopped aliyun instance"
			if verb == "stop" {
				keep, what = statusIn(instRunning, instStarting), "Running aliyun instance"
			}
			if args, err = instanceArg(ctx, rt, args, region, what, keep); err != nil {
				return err
			}
			// Before anything else: the non-interactive flow without --yes
			// is refused without needing credentials or the network. A dry
			// run stops nothing, so it needs no confirmation.
			if verb == "stop" && !rt.DryRun() {
				if err := rt.CanConfirm("stop instance " + args[0]); err != nil {
					return err
				}
			}
			s, in, err := resolveECSInstance(ctx, rt, args[0], region)
			if err != nil {
				return err
			}
			label := instanceLabel(in)
			if in.Status == want {
				return rt.RenderReport(platform.Report{Target: s.target(), DryRun: rt.DryRun(), Changes: []platform.Change{
					{Resource: "instance/" + label, Action: platform.Unchanged, ID: in.ID, Detail: in.Status}}})
			}
			change := platform.Change{Resource: "instance/" + label, Action: platform.Updated, ID: in.ID, Detail: verb}
			if force {
				change.Detail = "stop (forced)"
			}
			if done, err := rt.WouldWrite(s.target(), change); done || err != nil {
				return err
			}
			if verb == "stop" {
				ok, err := rt.Confirm(ctx, fmt.Sprintf("Stop instance %s (%s)? It is unavailable until it is started again.", label, in.Status), false)
				if err != nil {
					return err
				}
				if !ok {
					return fmt.Errorf("%w: cancelled; instance %s was not stopped", platform.ErrNothingToDo, label)
				}
				err = s.c.StopInstance(ctx, s.region, in.ID, force)
			} else {
				err = s.c.StartInstance(ctx, s.region, in.ID)
			}
			if err != nil {
				return err
			}
			rt.Infof("%s of %s requested via aliyun/%s (was %s)", verb, label, s.profile, in.Status)
			if wait {
				if verb == "start" {
					took, err := waitInstanceRunning(ctx, s, in.ID, label, timeout)
					if err != nil {
						return fmt.Errorf("start of %s was requested: %w", label, err)
					}
					rt.Infof("instance %s is Running (waited %s)", label, took.Round(time.Second))
				} else {
					if err := waitInstanceStatus(ctx, s, in.ID, label, instStopped, timeout); err != nil {
						return fmt.Errorf("stop of %s was requested: %w", label, err)
					}
					rt.Infof("instance %s is Stopped", label)
				}
				change.Detail += "; " + want
			}
			if after := refreshInstance(rt, ctx, s.c, s.profile, s.region, in.ID); after != nil && verb == "start" && wait {
				change.Attrs = map[string]string{"public_ip": after.PublicIP, "private_ip": after.PrivateIP}
			}
			return rt.RenderReport(platform.Report{Target: s.target(), Changes: []platform.Change{change}})
		},
	}
	cmd.Flags().StringVar(&region, "region", "", "region of the instance (default: look it up in the inventory of every account)")
	if verb == "stop" {
		cmd.Flags().BoolVar(&force, "force", false, "force stop (like pulling the power)")
	}
	app.AddWaitFlags(cmd, &w, false, defaultInstanceTimeout)
	return cmd
}
