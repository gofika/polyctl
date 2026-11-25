package app

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// ResolveResource finds the account that holds a resource named by the
// user (an instance, a load balancer, ...) without the user naming the
// account, the way domains are routed: the inventory rows of kind are
// searched by id and by name across the accounts able to hold kind,
// restricted to the platform id (when not "", else to --platform) and to
// --profile. An id match wins over name matches. One match is the answer;
// several are ambiguous (exit code 5) with a hint naming --profile (and
// --platform when they are on several platforms). None triggers one sync
// of the candidate accounts whose set of kind is missing or expired (all
// of them with --refresh, none with --offline), and the lookup is retried
// before it reports "not found" or, when an account could not be synced,
// the error of that sync (the resource may be in that account).
func (rt *Runtime) ResolveResource(ctx context.Context, id platform.ID, kind platform.ResourceType, ref string) (inventory.Resource, error) {
	return rt.ResolveResourceWith(ctx, ResourceLookup{Platform: id, Kind: kind, Ref: ref})
}

// ResourceLookup is a lookup of ResolveResource with what a platform knows
// about its rows. The zero value of each option keeps what ResolveResource
// does.
type ResourceLookup struct {
	// Platform restricts the lookup to one platform ("" = --platform, or
	// any), Kind is the type of the rows and Ref the id or name to find.
	Platform platform.ID
	Kind     platform.ResourceType
	Ref      string
	// Keep tells the rows the lookup may match; the others are not there
	// for it, before and after a sync (nil: every row).
	Keep func(inventory.Resource) bool
	// Hint returns the hint of the ambiguity of the rows found, "" to
	// keep the one of ResolveResource (nil: always that one).
	Hint func(found []inventory.Resource) string
	// Candidate describes one of several rows found, in the error and in
	// the question (nil: "platform/profile (id)").
	Candidate func(inventory.Resource) string
}

// ResolveResourceWith is ResolveResource with the options of l.
func (rt *Runtime) ResolveResourceWith(ctx context.Context, l ResourceLookup) (inventory.Resource, error) {
	id, kind, ref := l.Platform, l.Kind, l.Ref
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
				if l.Keep != nil && !l.Keep(r) {
					continue
				}
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
			var syncErr error
			for _, a := range stale {
				reps, err := rt.SyncAccount(ctx, a, []platform.ResourceType{kind})
				if err == nil {
					// A failed resource type is reported in the sync
					// report, not as the error of the account.
					for _, r := range reps {
						if r.Err != nil {
							err = r.Err
							break
						}
					}
				}
				if err != nil {
					rt.Infof("warning: sync %s: %v", a.Label(), err)
					if syncErr == nil {
						syncErr = fmt.Errorf("sync %s: %w", a.Label(), err)
					}
				}
			}
			if found, err = lookup(); err != nil {
				return inventory.Resource{}, err
			}
			if len(found) == 0 && syncErr != nil {
				// An account that could not be listed may hold it: that
				// is not "not found".
				return inventory.Resource{}, fmt.Errorf("cannot tell where %s %q is: %w", what, ref, syncErr)
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
	accountsHit := map[string]bool{}
	platformsHit := map[platform.ID]bool{}
	for _, r := range found {
		if l.Candidate != nil {
			names = append(names, l.Candidate(r))
		} else {
			names = append(names, fmt.Sprintf("%s/%s (%s)", r.Platform, r.Profile, r.ID))
		}
		accountsHit[string(r.Platform)+"/"+r.Profile] = true
		platformsHit[r.Platform] = true
	}
	hint := "pass --profile <name> to choose"
	switch {
	case len(accountsHit) == 1:
		hint = "the account holds several of them with this name; pass the id"
	case len(platformsHit) > 1:
		hint = "pass --profile <name> and/or --platform <name> to choose"
	}
	if l.Hint != nil {
		if h := l.Hint(found); h != "" {
			hint = h
		}
	}
	amb := &AmbiguousError{What: fmt.Sprintf("%s %q", what, ref), Candidates: names, Hint: hint}
	for i, r := range found {
		label := fmt.Sprintf("%s/%s  %s  %s", r.Platform, r.Profile, r.Name, r.ID)
		if r.ParentID != "" {
			label += "  in " + r.ParentID
		}
		if l.Candidate != nil {
			label = l.Candidate(r)
		}
		amb.Options = append(amb.Options, prompt.Option{Label: label, Value: strconv.Itoa(i)})
	}
	// The interactive flow asks which one; the non-interactive flow keeps
	// the error (exit code 5).
	v, err := rt.Disambiguate(amb)
	if err != nil {
		return inventory.Resource{}, err
	}
	i, _ := strconv.Atoi(v)
	return found[i], nil
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
	// --platform narrows the search of a platform-neutral command, as it
	// narrows domain routing.
	if id == "" && rt.Flags.Platform != "" {
		if id, err = platform.Parse(rt.Flags.Platform); err != nil {
			return nil, UsageErrf("--platform: %v", err)
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
