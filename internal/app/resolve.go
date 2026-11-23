package app

import (
	"context"
	"fmt"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// ResolveResource finds the account that holds a resource named by the
// user (an instance, a load balancer, ...) without the user naming the
// account, the way domains are routed: the inventory rows of kind are
// searched by id and by name across the accounts able to hold kind,
// restricted to the platform id (when not "") and to --profile. An id
// match wins over name matches. One match is the answer; several are
// ambiguous (exit code 5) with a hint naming --profile; none triggers one
// sync of the candidate accounts whose set of kind is missing or expired
// (all of them with --refresh, none with --offline), and the lookup is
// retried before it reports "not found".
func (rt *Runtime) ResolveResource(ctx context.Context, id platform.ID, kind platform.ResourceType, ref string) (inventory.Resource, error) {
	accounts, err := rt.resourceAccounts(id, kind)
	if err != nil {
		return inventory.Resource{}, err
	}
	what := string(kind)
	if id != "" {
		what = string(id) + " " + what
	}
	if len(accounts) == 0 {
		return inventory.Resource{}, fmt.Errorf("%w: no account selected by --profile is able to hold %ss", platform.ErrNotFound, what)
	}
	db, err := rt.DB()
	if err != nil {
		return inventory.Resource{}, err
	}
	lookup := func() ([]inventory.Resource, error) {
		var byID, byName []inventory.Resource
		for _, a := range accounts {
			rows, err := db.List(ctx, inventory.Query{Platform: a.Platform, Profile: a.Profile, Type: kind})
			if err != nil {
				return nil, err
			}
			for _, r := range rows {
				switch ref {
				case r.ID:
					byID = append(byID, r)
				case r.Name:
					byName = append(byName, r)
				}
			}
		}
		if len(byID) > 0 {
			return byID, nil
		}
		return byName, nil
	}
	found, err := lookup()
	if err != nil {
		return inventory.Resource{}, err
	}
	if len(found) == 0 && !rt.Flags.Offline {
		var stale []config.AccountRef
		for _, a := range accounts {
			st, err := db.GetState(ctx, inventory.Set{Platform: a.Platform, Profile: a.Profile, Type: kind})
			if err != nil {
				return inventory.Resource{}, err
			}
			if rt.Flags.Refresh || !st.Fresh(time.Now()) {
				stale = append(stale, a)
			}
		}
		if len(stale) > 0 {
			rt.Infof("looking up %s %q: syncing %s of %d account(s)...", what, ref, kind, len(stale))
			for _, a := range stale {
				if _, err := rt.SyncAccount(ctx, a, []platform.ResourceType{kind}); err != nil {
					rt.Infof("warning: sync %s: %v", a.Label(), err)
				}
			}
			if found, err = lookup(); err != nil {
				return inventory.Resource{}, err
			}
		}
	}
	switch len(found) {
	case 0:
		hint := "retry with --refresh, or pass the id"
		if rt.Flags.Offline {
			hint = "it is not in the local inventory; retry without --offline"
		}
		return inventory.Resource{}, fmt.Errorf("%w: %s %q in the selected accounts (%s)", platform.ErrNotFound, what, ref, hint)
	case 1:
		return found[0], nil
	}
	var names []string
	profiles := map[string]bool{}
	for _, r := range found {
		names = append(names, fmt.Sprintf("%s/%s (%s)", r.Platform, r.Profile, r.ID))
		profiles[string(r.Platform)+"/"+r.Profile] = true
	}
	hint := "pass --profile <name> to choose"
	if len(profiles) == 1 {
		hint = "the account holds several of them with this name; pass the id"
	}
	return inventory.Resource{}, &AmbiguousError{What: fmt.Sprintf("%s %q", what, ref), Candidates: names, Hint: hint}
}

// resourceAccounts returns the accounts able to hold kind on platform id
// ("" = any), restricted to --profile (an unknown profile is an error).
func (rt *Runtime) resourceAccounts(id platform.ID, kind platform.ResourceType) ([]config.AccountRef, error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, err
	}
	if rt.Flags.Profile != "" {
		if _, err := cfg.Profile(rt.Flags.Profile); err != nil {
			return nil, fmt.Errorf("%w: %v", platform.ErrNotFound, err)
		}
	}
	var out []config.AccountRef
	for _, ref := range cfg.Accounts(rt.Flags.Profile) {
		if id != "" && ref.Platform != id {
			continue
		}
		prov, err := platform.Get(ref.Platform)
		if err != nil || !platform.Supports(prov, kind) {
			continue
		}
		out = append(out, ref)
	}
	return out, nil
}
