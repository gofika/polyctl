package app

import (
	"context"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// ResourcePick describes the question of PickResource.
type ResourcePick struct {
	// Platform and Kind select the inventory rows (Platform "" = every
	// platform able to hold Kind, narrowed by --platform).
	Platform platform.ID
	Kind     platform.ResourceType
	// Title is the question ("Zone"); Arg names the argument ("<zone>").
	Title, Arg string
	// Required says a missing candidate is a usage error naming Arg (a
	// command that needs the input to create something) rather than
	// "nothing to do".
	Required bool
	// Filter keeps the usable rows only (a running instance for stop, an
	// unlocked domain for lock, ...); nil keeps every row.
	Filter func(inventory.Resource) bool
	// Label describes a row; nil shows "name  id  platform/profile" ("-"
	// for the name of a row that has none but its id).
	Label func(inventory.Resource) string
	// Value is what the command resolves the pick with; nil means the id.
	Value func(inventory.Resource) string
	// What names the candidates in the message of an empty list ("stopped
	// aliyun instance"); "" names the platform and kind.
	What string
}

// PickResource asks for one of the resources of kind held by the accounts
// the command may use (--profile, --platform), as the local inventory knows
// them: the same rows ResolveResource searches, so the answer resolves to
// exactly the row picked. Sets that are missing or expired are synced first
// (not with --offline). The value returned is the row's id unless
// p.Value says otherwise. The non-interactive flow returns the usage error
// "<Arg> is required" without reading anything.
func (rt *Runtime) PickResource(ctx context.Context, p ResourcePick) (string, error) {
	if !rt.Interactive() {
		return "", UsageErrf("%s is required", p.Arg)
	}
	opts, what, err := rt.resourceOptions(ctx, p)
	if err != nil {
		return "", err
	}
	return rt.Choose(Choice{Title: p.Title, Options: opts, Arg: p.Arg, Required: p.Required, What: what})
}

// PickResources is PickResource for several resources (multiple choice);
// ticking none is "nothing to do".
func (rt *Runtime) PickResources(ctx context.Context, p ResourcePick) ([]string, error) {
	if !rt.Interactive() {
		return nil, UsageErrf("%s is required", p.Arg)
	}
	opts, what, err := rt.resourceOptions(ctx, p)
	if err != nil {
		return nil, err
	}
	return rt.ChooseMany(Choice{Title: p.Title, Options: opts, Arg: p.Arg, Required: p.Required, What: what})
}

// resourceOptions lists the rows of p as options, and what names them for
// the message of an empty list.
func (rt *Runtime) resourceOptions(ctx context.Context, p ResourcePick) ([]prompt.Option, string, error) {
	rows, err := rt.resourceRows(ctx, p.Platform, p.Kind)
	if err != nil {
		return nil, "", err
	}
	var opts []prompt.Option
	for _, r := range rows {
		if p.Filter != nil && !p.Filter(r) {
			continue
		}
		label := resourceLabel(r)
		if p.Label != nil {
			label = p.Label(r)
		}
		v := r.ID
		if p.Value != nil {
			v = p.Value(r)
		}
		opts = append(opts, prompt.Option{Label: label, Value: v})
	}
	what := string(p.Kind)
	if p.Platform != "" {
		what = string(p.Platform) + " " + what
	}
	if p.What != "" {
		what = p.What
	}
	return opts, what, nil
}

// resourceRows lists the inventory rows of kind of the selected accounts,
// syncing the sets that are missing or expired first (every one with
// --refresh, none with --offline). An account that cannot be synced is
// reported and left out: the pick offers what is known.
func (rt *Runtime) resourceRows(ctx context.Context, id platform.ID, kind platform.ResourceType) ([]inventory.Resource, error) {
	accounts, err := rt.resourceAccounts(id, kind)
	if err != nil {
		return nil, err
	}
	db, err := rt.DB()
	if err != nil {
		return nil, err
	}
	if !rt.Flags.Offline {
		var stale []config.AccountRef
		for _, a := range accounts {
			st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: kind})
			if err != nil {
				return nil, err
			}
			if rt.Flags.Refresh || !st.Fresh(time.Now()) {
				stale = append(stale, a)
			}
		}
		for _, a := range stale {
			reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{kind})
			for _, r := range reps {
				if err == nil && r.Err != nil {
					err = r.Err
				}
			}
			if err != nil {
				rt.Infof("warning: sync %s: %v", a.Label(), err)
			}
		}
	}
	var out []inventory.Resource
	for _, a := range accounts {
		rows, err := db.List(ctx, inventory.Query{Platform: a.Platform, Profile: a.Profile, Type: kind})
		if err != nil {
			return nil, err
		}
		out = append(out, rows...)
	}
	return out, nil
}

// DomainArg fills in a missing <domain> argument of a platform command in
// the interactive flow with a domain (kind ResDomain) or zone (ResZone) of
// the profile the command uses on platform id, as the inventory knows them
// (synced first when stale). filter keeps the usable ones (nil: all), such
// as the unlocked domains for lock. With the argument given, or in the
// non-interactive flow (where cobra already refused a missing argument),
// args is returned as it is.
func (rt *Runtime) DomainArg(ctx context.Context, args []string, id platform.ID, kind platform.ResourceType, filter func(platform.Domain) bool) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	profile, err := rt.ProfileFor(id)
	if err != nil {
		return nil, err
	}
	title := "Domain"
	if kind == platform.ResZone {
		title = "DNS zone"
	}
	v, err := rt.PickResource(ctx, ResourcePick{Platform: id, Kind: kind, Title: title, Arg: "<domain>",
		Filter: func(r inventory.Resource) bool {
			if r.Profile != profile {
				return false
			}
			if filter == nil {
				return true
			}
			var d platform.Domain
			_ = r.Decode(&d)
			return filter(d)
		},
		Label: func(r inventory.Resource) string { return domainLabel(r) },
		Value: func(r inventory.Resource) string {
			if r.Name != "" {
				return r.Name
			}
			return r.ID
		}})
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// resourceLabel shows an inventory row as the cells "name  id
// platform/profile  <more>...": a row whose id is its name has "-" for the
// name, so the ids stay in one column.
func resourceLabel(r inventory.Resource, more ...string) string {
	name := r.Name
	if name == r.ID {
		name = ""
	}
	return prompt.Cells(append([]string{name, r.ID, string(r.Platform) + "/" + r.Profile}, more...)...)
}

// domainLabel shows a domain or zone row as the cells "example.com  ACTIVE
// expires 2027-03-01  locked  autorenew  namecom/acme", "-" for what the
// row does not say.
func domainLabel(r inventory.Resource) string {
	name := r.Name
	if name == "" {
		name = r.ID
	}
	var status, expires, locked, autoRenew string
	if r.Type == platform.ResDomain {
		var d platform.Domain
		if r.Decode(&d) == nil {
			status = d.Status
			if d.ExpiresAt != "" {
				exp := d.ExpiresAt
				if len(exp) > 10 {
					exp = exp[:10]
				}
				expires = "expires " + exp
			}
			if d.Locked != nil && *d.Locked {
				locked = "locked"
			}
			if d.AutoRenew != nil && *d.AutoRenew {
				autoRenew = "autorenew"
			}
		}
	}
	return prompt.Cells(name, status, expires, locked, autoRenew, string(r.Platform)+"/"+r.Profile)
}
