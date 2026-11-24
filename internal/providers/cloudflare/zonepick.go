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
