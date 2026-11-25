package app

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// DomainPick describes the question of PickDomain.
type DomainPick struct {
	// Title is the question ("Domain").
	Title string
	// Arg names the argument for messages ("<domain>").
	Arg string
	// Kinds are the index entries offered (ResZone, ResDomain); none means
	// both.
	Kinds []platform.ResourceType
	// Required says the command creates something in the domain (a record,
	// a certificate): an empty index is a usage error naming Arg. A command
	// acting on the domain itself (reading it, deleting records, setting
	// nameservers) leaves it false: an empty index is "nothing to do".
	Required bool
	// Filter, when set, keeps only the domains it accepts (one call per
	// domain with its index entries).
	Filter func(domain string, entries []inventory.IndexEntry) bool
	// Label, when set, adds to the label of a domain.
	Label func(domain string, entries []inventory.IndexEntry) string
	// Another, when set, adds a last option "Another domain..." that runs
	// it (a domain the index does not know, typed and checked); without
	// indexed domains it runs straight away.
	Another func() (string, error)
}

// PickDomain asks for one of the domains of the local index in the
// interactive flow, restricted by --profile and --platform like domain
// routing. Each domain is one option, labelled with its kinds and owners
// ("example.com  zone cloudflare/acme, domain namecom/acme"); when several
// accounts own the chosen one, ResolveDomain asks which.
func (rt *Runtime) PickDomain(ctx context.Context, p DomainPick) (string, error) {
	if !rt.Interactive() {
		return "", UsageErrf("%s is required", p.Arg)
	}
	db, err := rt.DB()
	if err != nil {
		return "", err
	}
	only, err := rt.RoutePlatform()
	if err != nil {
		return "", err
	}
	entries, err := db.IndexEntries(ctx)
	if err != nil {
		return "", err
	}
	if entries, err = rt.ConfiguredEntries(entries); err != nil {
		return "", err
	}
	byDomain := map[string][]inventory.IndexEntry{}
	var order []string
	for _, e := range entries {
		if len(p.Kinds) > 0 && !slices.Contains(p.Kinds, e.Type) {
			continue
		}
		if (rt.Flags.Profile != "" && e.Profile != rt.Flags.Profile) || (only != "" && e.Platform != only) {
			continue
		}
		if _, ok := byDomain[e.Domain]; !ok {
			order = append(order, e.Domain)
		}
		byDomain[e.Domain] = append(byDomain[e.Domain], e)
	}
	var opts []prompt.Option
	for _, d := range order {
		es := byDomain[d]
		if p.Filter != nil && !p.Filter(d, es) {
			continue
		}
		var owners []string
		for _, e := range es {
			owners = append(owners, fmt.Sprintf("%s %s/%s", e.Type, e.Platform, e.Profile))
		}
		label := d + "  " + strings.Join(owners, ", ")
		if p.Label != nil {
			if extra := p.Label(d, es); extra != "" {
				label += "  " + extra
			}
		}
		opts = append(opts, prompt.Option{Label: label, Value: d})
	}
	what := "indexed domain"
	if len(p.Kinds) == 1 {
		what = "indexed " + string(p.Kinds[0])
	}
	title := p.Title
	if title == "" {
		title = "Domain"
	}
	c := Choice{Title: title, Options: opts, Arg: p.Arg, Required: p.Required, What: what}
	if p.Another != nil {
		c.CreateLabel, c.Create = "Another domain...", p.Another
	}
	if len(opts) == 0 {
		hint := " (run `polyctl domain index`)"
		if rt.Flags.Profile != "" || only != "" {
			hint = " matching --profile / --platform"
		}
		if p.Required {
			c.Empty = UsageErrf("%s is required, and there is no %s to choose from%s", p.Arg, what, hint)
		} else {
			c.Empty = NothingToDof("no %s to choose from%s", what, hint)
		}
	}
	return rt.Choose(c)
}

// enterNameservers is the value of the "Enter nameservers..." option.
const enterNameservers = "\x00enter"

// PickNameservers asks for the nameservers of domain in the interactive
// flow (the <nameserver>... of an `ns set` command): the nameserver sets of
// the DNS zones of that name known to the index, labelled with their
// account, or "Enter nameservers..." for a list checked as it is typed.
// The non-interactive flow returns the usage error of a missing list.
func (rt *Runtime) PickNameservers(ctx context.Context, domain string) ([]string, error) {
	if !rt.Interactive() {
		return nil, UsageErrf("at least one nameserver is required")
	}
	domain = platform.NormalizeDomain(domain)
	var opts []prompt.Option
	if db, err := rt.DB(); err == nil {
		entries, err := db.LookupDomain(ctx, []string{domain}, platform.ResZone)
		if err != nil {
			return nil, err
		}
		if entries, err = rt.ConfiguredEntries(entries); err != nil {
			return nil, err
		}
		seen := map[string]bool{}
		for _, e := range entries {
			r, err := db.Get(ctx, inventory.Set{Platform: e.Platform, Profile: e.Profile, Type: platform.ResZone}, platform.ResZone, e.ResourceID)
			if err != nil {
				continue
			}
			var z platform.Zone
			if r.Decode(&z) != nil || len(z.Nameservers) == 0 {
				continue
			}
			v := strings.Join(z.Nameservers, ",")
			if seen[v] {
				continue
			}
			seen[v] = true
			opts = append(opts, prompt.Option{Label: fmt.Sprintf("zone %s at %s/%s: %s", z.Name, e.Platform, e.Profile, strings.Join(z.Nameservers, ", ")), Value: v})
		}
	}
	opts = append(opts, prompt.Option{Label: "Enter nameservers...", Value: enterNameservers})
	v, err := rt.Pick().Select("Nameservers for "+domain, opts, "")
	if err != nil {
		return nil, err
	}
	if v == enterNameservers {
		if v, err = rt.Pick().Input("Nameservers (separated by spaces or commas)", "", func(s string) error {
			fields := strings.Fields(strings.ReplaceAll(s, ",", " "))
			if len(fields) == 0 {
				return fmt.Errorf("at least one nameserver is required")
			}
			_, err := platform.Nameservers(fields)
			return err
		}); err != nil {
			return nil, err
		}
	}
	return Nameservers(strings.Fields(strings.ReplaceAll(v, ",", " ")))
}
