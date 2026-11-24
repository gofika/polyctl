package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// zoneLabel is how a zone is shown in a pick: "example.com  active  <id>".
func zoneLabel(z platform.Zone) string {
	parts := []string{z.Name}
	if z.Status != "" {
		parts = append(parts, z.Status)
	}
	return strings.Join(append(parts, z.ID), "  ")
}

// pickCachedZone asks for one of the zones of profile (the <zone> of the
// commands that work on the profile's zones). No zone is nothing to do.
func pickCachedZone(rt *app.Runtime, zones []platform.Zone, profile string) (string, error) {
	sorted := append([]platform.Zone(nil), zones...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	var opts []prompt.Option
	for _, z := range sorted {
		opts = append(opts, prompt.Option{Label: zoneLabel(z) + "  cloudflare/" + profile, Value: z.ID})
	}
	return rt.Choose(app.Choice{Title: "Zone", Options: opts, Arg: "<zone>", What: "zone in cloudflare/" + profile})
}

// pickLiveZone asks for one of the zones of every selected Cloudflare
// account, as the inventory knows them (the <zone> of the commands that
// route a zone among the accounts).
func pickLiveZone(ctx context.Context, rt *app.Runtime) (string, error) {
	return rt.PickResource(ctx, app.ResourcePick{Platform: platform.Cloudflare, Kind: platform.ResZone, Title: "Zone", Arg: "<zone>",
		Label: func(r inventory.Resource) string {
			var z platform.Zone
			_ = r.Decode(&z)
			if z.Name == "" {
				z.Name, z.ID = r.Name, r.ID
			}
			return zoneLabel(z) + "  cloudflare/" + r.Profile
		}})
}

// askPurge asks what cache purge removes: everything, or a list of URLs,
// hosts, tags or prefixes (the last three on Enterprise plans only).
func askPurge(rt *app.Runtime) (everything bool, urls, hosts, tags, prefixes []string, err error) {
	kind, err := rt.Choose(app.Choice{Title: "Purge what?", Arg: "--everything", Options: []prompt.Option{
		{Label: "Everything in the zone's cache", Value: "everything"},
		{Label: "URLs...", Value: "url"},
		{Label: "Hosts... (Enterprise)", Value: "host"},
		{Label: "Cache tags... (Enterprise)", Value: "tag"},
		{Label: "URL prefixes... (Enterprise)", Value: "prefix"},
	}})
	if err != nil || kind == "everything" {
		return kind == "everything", nil, nil, nil, nil, err
	}
	v, err := rt.AskInput("--"+kind, "Values to purge (separated by spaces or commas)", "", func(s string) error {
		if len(strings.Fields(strings.ReplaceAll(s, ",", " "))) == 0 {
			return errors.New("at least one value is required")
		}
		if kind == "url" {
			for _, u := range strings.Fields(strings.ReplaceAll(s, ",", " ")) {
				if !strings.HasPrefix(u, "http://") && !strings.HasPrefix(u, "https://") {
					return fmt.Errorf("%q is not a URL (http:// or https://)", u)
				}
			}
		}
		return nil
	})
	if err != nil {
		return false, nil, nil, nil, nil, err
	}
	list := strings.Fields(strings.ReplaceAll(v, ",", " "))
	switch kind {
	case "url":
		urls = list
	case "host":
		hosts = list
	case "tag":
		tags = list
	default:
		prefixes = list
	}
	return false, urls, hosts, tags, prefixes, nil
}

// pickSetting asks for a setting of the zone of s: the settings the zone
// lists (only the editable ones for a change), with their current values,
// plus argo_smart_routing and foundation_dns, which have endpoints of their
// own.
func pickSetting(ctx context.Context, rt *app.Runtime, s *zoneScope, editable bool) (string, error) {
	settings, err := s.c.api.listSettings(ctx, s.z.ID)
	if err != nil {
		return "", s.gone(ctx, rt, err)
	}
	sort.SliceStable(settings, func(i, j int) bool { return settings[i].ID < settings[j].ID })
	var opts []prompt.Option
	for _, st := range settings {
		if editable && !st.Editable {
			continue
		}
		opts = append(opts, prompt.Option{Label: st.ID + " = " + settingText(st.Value), Value: st.ID})
	}
	opts = append(opts, prompt.Option{Label: settingArgo + "  (Argo Smart Routing)", Value: settingArgo},
		prompt.Option{Label: settingFoundationDNS + "  (Foundation DNS)", Value: settingFoundationDNS})
	return rt.Choose(app.Choice{Title: "Setting of " + s.name(), Options: opts, Arg: "<setting>"})
}

// settingEnums are the values of the settings that take one of a few.
var settingEnums = map[string][]string{
	"ssl":             {"off", "flexible", "full", "strict"},
	"min_tls_version": {"1.0", "1.1", "1.2", "1.3"},
	"security_level":  {"off", "essentially_off", "low", "medium", "high", "under_attack"},
	"cache_level":     {"basic", "simplified", "aggressive"},
}

// askSettingValue asks for the new value of a setting: on or off (the
// opposite of the current one preselected) for a switch, one of the values
// of a setting that takes a few, free text otherwise (the current value as
// default).
func askSettingValue(rt *app.Runtime, name string, current any) (string, error) {
	cur := settingText(current)
	values := settingEnums[name]
	switch {
	case name == settingArgo || name == settingFoundationDNS || cur == "on" || cur == "off" || cur == "true" || cur == "false":
		values = []string{"on", "off"}
	}
	if len(values) > 0 {
		def := cur
		if cur == "on" || cur == "true" {
			def = "off"
		} else if cur == "off" || cur == "false" {
			def = "on"
		}
		var opts []prompt.Option
		for _, v := range values {
			label := v
			if v == cur || (cur == "true" && v == "on") || (cur == "false" && v == "off") {
				label += "  (current)"
			}
			opts = append(opts, prompt.Option{Label: label, Value: v})
		}
		return rt.Choose(app.Choice{Title: "New value of " + name, Options: opts, Default: def, Arg: "<value>"})
	}
	return rt.AskInput("<value>", "New value of "+name, cur, app.RequireValue("a value"))
}

// bucketArgs fills in a missing <bucket> in the interactive flow with a
// bucket of the Cloudflare accounts the command may use (as the inventory
// knows them, synced when stale), labelled with account and location.
func bucketArgs(ctx context.Context, rt *app.Runtime, args []string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	names, _, err := r2Profiles(rt)
	if err != nil {
		return nil, err
	}
	var opts []prompt.Option
	seen := map[string]bool{}
	for _, name := range names {
		rows, _, err := cachedBuckets(ctx, rt, name)
		if err != nil {
			rt.Infof("warning: buckets of cloudflare/%s: %v", name, err)
			continue
		}
		for _, r := range rows {
			if seen[r.Name] {
				continue // the same account in two profiles
			}
			seen[r.Name] = true
			label := r.Name + "  cloudflare/" + name
			if r.Location != "" {
				label += "  " + r.Location
			}
			if r.StorageClass != "" {
				label += "  " + r.StorageClass
			}
			opts = append(opts, prompt.Option{Label: label, Value: r.Name})
		}
	}
	v, err := rt.Choose(app.Choice{Title: "R2 bucket", Options: opts, Arg: "<bucket>", What: "R2 bucket"})
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// pickBucketDomain asks for one of the custom domains bound to bucket.
func pickBucketDomain(ctx context.Context, rt *app.Runtime, a *r2Acct, bucket string) (string, error) {
	ds, err := a.api.listCustomDomains(ctx, a.account, bucket)
	if err != nil {
		return "", r2Err(err, a, bucket)
	}
	sort.SliceStable(ds, func(i, j int) bool { return ds[i].Domain < ds[j].Domain })
	var opts []prompt.Option
	for _, d := range ds {
		label := d.Domain + "  disabled"
		if d.Enabled {
			label = d.Domain + "  enabled"
		}
		if d.MinTLS != "" {
			label += "  tls " + d.MinTLS
		}
		if d.ZoneName != "" {
			label += "  zone " + d.ZoneName
		}
		opts = append(opts, prompt.Option{Label: label, Value: d.Domain})
	}
	return rt.Choose(app.Choice{Title: "Custom domain of " + bucket, Options: opts, Arg: "<domain>", What: "custom domain of bucket " + bucket})
}

// askDomainUpdate asks what r2 domain update changes: switch the domain
// on or off (the opposite of now), or its minimum TLS version (the current
// one marked).
func askDomainUpdate(rt *app.Runtime, cur r2CustomDomain) (*bool, string, error) {
	toggle := "Disable the domain"
	if !cur.Enabled {
		toggle = "Enable the domain"
	}
	what, err := rt.Choose(app.Choice{Title: "What to change on " + cur.Domain, Arg: "--enabled / --min-tls", Options: []prompt.Option{
		{Label: toggle, Value: "toggle"},
		{Label: "Minimum TLS version (now " + nonEmpty(cur.MinTLS, "default") + ")...", Value: "tls"},
	}})
	if err != nil {
		return nil, "", err
	}
	if what == "toggle" {
		on := !cur.Enabled
		return &on, "", nil
	}
	var opts []prompt.Option
	for _, v := range minTLSValues {
		label := v
		if v == cur.MinTLS {
			label += "  (current)"
		}
		opts = append(opts, prompt.Option{Label: label, Value: v})
	}
	v, err := rt.Choose(app.Choice{Title: "Minimum TLS version", Options: opts, Default: cur.MinTLS, Arg: "--min-tls"})
	return nil, v, err
}

func nonEmpty(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// anotherDomain is the value of the "Another domain..." option of
// newZoneDomain.
const anotherDomain = "\x00other"

// newZoneDomain fills in the <domain> of zone create / ensure in the
// interactive flow: the domains registered at any registrar the index knows
// that have no Cloudflare zone yet, or another name, checked as it is
// typed.
func newZoneDomain(ctx context.Context, rt *app.Runtime, args []string) (string, error) {
	if len(args) > 0 {
		return args[0], nil
	}
	if !rt.Interactive() {
		return "", app.UsageErrf("<domain> is required")
	}
	var opts []prompt.Option
	if db, err := rt.DB(); err == nil {
		if entries, err := db.IndexEntries(ctx); err == nil {
			zoned := map[string]bool{}
			for _, e := range entries {
				if e.Type == platform.ResZone && e.Platform == platform.Cloudflare {
					zoned[e.Domain] = true
				}
			}
			seen := map[string]bool{}
			for _, e := range entries {
				if e.Type != platform.ResDomain || zoned[e.Domain] || seen[e.Domain] {
					continue
				}
				seen[e.Domain] = true
				opts = append(opts, prompt.Option{Label: fmt.Sprintf("%s  registered at %s/%s", e.Domain, e.Platform, e.Profile), Value: e.Domain})
			}
		}
	}
	opts = append(opts, prompt.Option{Label: "Another domain...", Value: anotherDomain})
	v, err := rt.Choose(app.Choice{Title: "Domain of the new zone", Options: opts, Arg: "<domain>"})
	if err != nil || v != anotherDomain {
		return v, err
	}
	return rt.AskInput("<domain>", "Domain of the new zone (such as example.com)", "", func(s string) error {
		_, err := zoneDomainArg(s)
		if err != nil {
			return errors.New(strings.TrimPrefix(err.Error(), app.ErrUsage.Error()+": "))
		}
		return nil
	})
}
