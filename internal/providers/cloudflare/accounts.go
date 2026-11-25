package cloudflare

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"
	"sync"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/platform"
)

// A Cloudflare login works on every account its credentials see, the ones
// created later included, unless an account was disabled: the metadata
// "disabled_accounts" (comma-separated ids) holds the disabled ones, and
// nothing else is stored about the others. The default account, stored as
// "account_id" (its name as "account_name"), is the one a command works on
// when nothing names an account; it is always enabled. A login without a
// default account (credentials that could not list accounts when it was
// made) is unbound: it covers the same, and needs --account where a single
// account is required.
//
// The metadata "accounts" held the accounts selected for a login while it
// had a selection. It is not read any more, and is dropped the next time
// the metadata is written.

const (
	// metaDisabledAccounts is the metadata key of the disabled accounts.
	metaDisabledAccounts = "disabled_accounts"
	// legacyAccounts is the metadata key of the former selection.
	legacyAccounts = "accounts"
)

// splitAccounts splits a comma-separated list of account ids, dropping
// blanks and repeats.
func splitAccounts(s string) []string {
	var out []string
	for _, f := range strings.Split(s, ",") {
		if f = strings.TrimSpace(f); f != "" && !slices.Contains(out, f) {
			out = append(out, f)
		}
	}
	return out
}

// disabledAccounts returns the disabled accounts of a login from its
// metadata, in stored order. The default account is never among them: a
// configuration edited by hand cannot disable it.
func disabledAccounts(meta map[string]string) []string {
	def := strings.TrimSpace(meta[metaAccountID])
	var out []string
	for _, a := range splitAccounts(meta[metaDisabledAccounts]) {
		if a != def {
			out = append(out, a)
		}
	}
	return out
}

// setAccounts writes the default account and the disabled accounts into
// meta: the disabled ones sorted and without the default, the key absent
// when there is none. The name is that of the default account; an unknown
// name removes the stored one, and a login without a default account
// stores neither. The former selection is dropped.
func setAccounts(meta map[string]string, def account, disabled []string) {
	if def.ID != "" {
		meta[metaAccountID] = def.ID
	} else {
		delete(meta, metaAccountID)
	}
	if def.ID != "" && def.Name != "" {
		meta[metaAccountName] = def.Name
	} else {
		delete(meta, metaAccountName)
	}
	delete(meta, legacyAccounts)
	var list []string
	for _, a := range splitAccounts(strings.Join(disabled, ",")) {
		if a != def.ID {
			list = append(list, a)
		}
	}
	if len(list) == 0 {
		delete(meta, metaDisabledAccounts)
		return
	}
	sort.Strings(list)
	meta[metaDisabledAccounts] = strings.Join(list, ",")
}

// checkAccountID refuses what cannot be an account id where one is given
// (--set account_id, --set disabled_accounts, account use/enable/disable).
func checkAccountID(id string) error {
	if id == "" || strings.ContainsAny(id, "/|, \t\r\n") {
		return fmt.Errorf("%q is not an account id", id)
	}
	return nil
}

// inAccount returns the API bound to another account: a shallow copy
// sharing the HTTP client and the browser login, the disabled accounts
// unchanged.
func (a *api) inAccount(id string) *api {
	if id == a.accountID {
		return a
	}
	cp := *a
	cp.accountID = id
	return &cp
}

// pin returns the API of --account: bound to that account, its lists and
// lookups reading that account alone.
func (a *api) pin(id string) *api {
	cp := *a
	cp.accountID = id
	cp.pinned = true
	return &cp
}

// unbound reports a login without a default account, not pinned to one by
// --account: where a single account is needed it has none to offer.
func (a *api) unbound() bool { return !a.pinned && a.accountID == "" }

// covers reports whether an object of the account id is one the API works
// on: of the pinned account with --account, of an account that is not
// disabled without it. An object that names no account is.
func (a *api) covers(id string) bool {
	switch {
	case id == "":
		return true
	case a.pinned:
		return id == a.accountID
	}
	return !slices.Contains(a.disabled, id)
}

// coveredZones returns the zones the API works on. Pinned to an account by
// --account it lists the zones of that account. Otherwise it is one
// listing of everything the credentials see, with the zones of the
// disabled accounts dropped: the enabled accounts are exactly what the
// credentials see minus the disabled ones, and one listing costs less
// than one per account.
func (a *api) coveredZones(ctx context.Context) ([]apiZone, error) {
	if a.pinned {
		return a.listZonesOf(ctx, a.accountID)
	}
	zs, err := a.listZonesOf(ctx, "")
	if err != nil {
		return nil, err
	}
	if len(a.disabled) == 0 {
		return zs, nil
	}
	out := make([]apiZone, 0, len(zs))
	for _, z := range zs {
		if a.covers(z.Account.ID) {
			out = append(out, z)
		}
	}
	return out, nil
}

// zonesNamedAll returns the zones named name the credentials see, with one
// request: covered are those in the accounts the API works on, others
// those in a disabled account. Pinned to an account it asks for that
// account alone and others is empty.
func (a *api) zonesNamedAll(ctx context.Context, name string) (covered, others []apiZone, err error) {
	if a.pinned {
		covered, err = a.findZonesNamed(ctx, name, a.accountID)
		return covered, nil, err
	}
	zs, err := a.findZonesNamed(ctx, name, "")
	if err != nil {
		return nil, nil, err
	}
	for _, z := range zs {
		if a.covers(z.Account.ID) {
			covered = append(covered, z)
		} else {
			others = append(others, z)
		}
	}
	return covered, others, nil
}

// zonesNamed returns the zones named name in the accounts the API covers.
func (a *api) zonesNamed(ctx context.Context, name string) ([]apiZone, error) {
	covered, _, err := a.zonesNamedAll(ctx, name)
	return covered, err
}

// clientMemo is what the copies of one opened client (inAccount, pin)
// share for the run.
type clientMemo struct {
	// def is the default account of the login, which a copy bound to
	// another account (inAccount) no longer names.
	def string
	mu  sync.Mutex
	// zones is the listing the zone sync read, kept for the record sync
	// of the same run, which takes it.
	zones    []apiZone
	hasZones bool
	// enabled are the accounts the per-account requests (R2) cover, once
	// they were asked for.
	enabled    []string
	hasEnabled bool
}

// keepZones remembers the zone listing of the zone sync.
func (c *Client) keepZones(zs []apiZone) {
	if c.memo == nil {
		return
	}
	c.memo.mu.Lock()
	defer c.memo.mu.Unlock()
	c.memo.zones, c.memo.hasZones = zs, true
}

// takeZones returns the zone listing the zone sync left, once.
func (c *Client) takeZones() ([]apiZone, bool) {
	if c.memo == nil {
		return nil, false
	}
	c.memo.mu.Lock()
	defer c.memo.mu.Unlock()
	zs, ok := c.memo.zones, c.memo.hasZones
	c.memo.zones, c.memo.hasZones = nil, false
	return zs, ok
}

// enabledAccounts returns the accounts the requests that are made per
// account (R2) cover, asked of the credentials once per opened client:
//
//   - pinned by --account: that account;
//   - the accounts the credentials list, minus the disabled ones, the
//     default account first and the others by id;
//   - credentials that may not list accounts, or list none: the default
//     account alone, and for a login without one the only account
//     r2Account finds (its error otherwise).
//
// A listing that fails for another reason is the error.
func (c *Client) enabledAccounts(ctx context.Context) ([]string, error) {
	if c.api.pinned {
		return []string{c.api.accountID}, nil
	}
	if c.memo != nil {
		c.memo.mu.Lock()
		ids, ok := c.memo.enabled, c.memo.hasEnabled
		c.memo.mu.Unlock()
		if ok {
			return ids, nil
		}
	}
	def := c.api.accountID
	if c.memo != nil {
		def = c.memo.def
	}
	accounts, err := c.api.listAccounts(ctx)
	if err != nil && !notPermitted(err) {
		return nil, fmt.Errorf("list the accounts of cloudflare/%s: %w", c.profile.Name, err)
	}
	var ids []string
	switch {
	case err == nil && len(accounts) > 0:
		for _, a := range accounts {
			if a.ID != def && c.api.covers(a.ID) && !slices.Contains(ids, a.ID) {
				ids = append(ids, a.ID)
			}
		}
		sort.Strings(ids)
		if def != "" {
			ids = append([]string{def}, ids...)
		}
	case def != "":
		ids = []string{def}
	case err != nil:
		return nil, fmt.Errorf("cloudflare profile %q has no default account and cannot list its accounts: %w", c.profile.Name, err)
	default:
		return nil, fmt.Errorf("%w: cloudflare profile %q sees no account", platform.ErrNotFound, c.profile.Name)
	}
	if c.memo != nil {
		c.memo.mu.Lock()
		c.memo.enabled, c.memo.hasEnabled = ids, true
		c.memo.mu.Unlock()
	}
	return ids, nil
}

// inAccount returns the client bound to another account of the login.
func (c *Client) inAccount(id string) *Client {
	if id == c.api.accountID {
		return c
	}
	cp := *c
	cp.api = c.api.inAccount(id)
	return &cp
}

// pin returns the client of --account: see api.pin.
func (c *Client) pin(id string) *Client {
	cp := *c
	cp.api = c.api.pin(id)
	return &cp
}

// eachAccount runs fn for every account of ids, one after the other, and
// returns the rows of all of them, for the inventory.
//
// With one account it is fn's result as it is. With several:
//
//   - an account that fails is a failure of its whole tree
//     (platform.RegionError.Tree): the rows stored for it are kept and the
//     rows of the other accounts replace theirs;
//   - when every account fails the result is a plain error wrapping the
//     first one, so that nothing is replaced and the exit code is kept.
//
// The accounts are not read at the same time: there are few of them, and
// Cloudflare limits the requests of a user, not of an account.
func (c *Client) eachAccount(ctx context.Context, ids []string, fn func(ctx context.Context, ac *Client) ([]platform.Resource, error)) ([]platform.Resource, error) {
	if len(ids) == 1 {
		return fn(ctx, c.inAccount(ids[0]))
	}
	var out []platform.Resource
	var failures []platform.RegionError
	var first error
	for _, id := range ids {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		res, err := fn(ctx, c.inAccount(id))
		if err != nil {
			if ctx.Err() != nil {
				return nil, ctx.Err()
			}
			if first == nil {
				first = err
			}
			if id != "" {
				err = fmt.Errorf("%w (if the account is not to be used any more: polyctl cloudflare account disable %s)", err, id)
			}
			failures = append(failures, platform.RegionError{Region: id, Tree: true, Err: err})
			continue
		}
		out = append(out, res...)
	}
	if len(failures) == 0 {
		return out, nil
	}
	sort.SliceStable(failures, func(i, j int) bool { return failures[i].Region < failures[j].Region })
	e := &platform.RegionSyncError{Failures: failures, Noun: "account"}
	if len(failures) == len(ids) {
		return nil, fmt.Errorf("every enabled account failed (%s): %w", e.Error(), first)
	}
	return out, e
}

// zoneResources converts zones to inventory resources whose parent is the
// account of the zone: a sync that fails for one account keeps what is
// stored of that account, and an account that is disabled takes its zones
// (and their records) with it.
func zoneResources(zones []platform.Zone) []platform.Resource {
	out := app.ZoneResources(zones)
	for i, z := range zones {
		if z.Extra != nil {
			out[i].ParentID, _ = z.Extra["account_id"].(string)
		}
	}
	return out
}

// toZones converts the zones of the API.
func toZones(zs []apiZone) []platform.Zone {
	out := make([]platform.Zone, 0, len(zs))
	for _, z := range zs {
		out = append(out, toZone(z))
	}
	return out
}
