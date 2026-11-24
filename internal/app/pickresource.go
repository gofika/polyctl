package app

import (
	"context"
	"fmt"
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
	// Label describes a row; nil shows "name  id  platform/profile".
	Label func(inventory.Resource) string
	// Value is what the command resolves the pick with; nil means the id.
	Value func(inventory.Resource) string
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
	rows, err := rt.resourceRows(ctx, p.Platform, p.Kind)
	if err != nil {
		return "", err
	}
	var opts []prompt.Option
	for _, r := range rows {
		if p.Filter != nil && !p.Filter(r) {
			continue
		}
		label := fmt.Sprintf("%s  %s  %s/%s", r.Name, r.ID, r.Platform, r.Profile)
		if r.Name == "" || r.Name == r.ID {
			label = fmt.Sprintf("%s  %s/%s", r.ID, r.Platform, r.Profile)
		}
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
	return rt.Choose(Choice{Title: p.Title, Options: opts, Arg: p.Arg, Required: p.Required, What: what})
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
