package cloudflare

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
)

// A Cloudflare login works on several accounts: the selection, stored as
// the metadata "accounts" (comma-separated ids), with the default account,
// stored as "account_id" (its name as "account_name"), among them. A login
// without "accounts" (every login before the selection existed) has exactly
// its one account selected. A login without an account at all (credentials
// that cannot list accounts) is unscoped: it works on whatever the
// credentials see.

// metaAccounts is the metadata key of the selection.
const metaAccounts = "accounts"

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

// selectedAccounts returns the selection of a login from its metadata: the
// default account first, then the others in stored order. A selection
// stored without a default account (a configuration edited by hand) has its
// first account as the default. It is empty for an unscoped login only.
func selectedAccounts(meta map[string]string) []string {
	def := strings.TrimSpace(meta[metaAccountID])
	var out []string
	if def != "" {
		out = append(out, def)
	}
	for _, a := range splitAccounts(meta[metaAccounts]) {
		if !slices.Contains(out, a) {
			out = append(out, a)
		}
	}
	return out
}

// setSelection writes the default account and the selection into meta. A
// selection of the default account alone is stored without "accounts", as a
// login before the selection existed stored it. The name is that of the
// default account; an unknown name removes the stored one.
func setSelection(meta map[string]string, def account, selected []string) {
	meta[metaAccountID] = def.ID
	if def.Name != "" {
		meta[metaAccountName] = def.Name
	} else {
		delete(meta, metaAccountName)
	}
	sel := selectedAccounts(map[string]string{metaAccountID: def.ID, metaAccounts: strings.Join(selected, ",")})
	if len(sel) <= 1 {
		delete(meta, metaAccounts)
		return
	}
	meta[metaAccounts] = strings.Join(sel, ",")
}

// checkAccountID refuses what cannot be an account id where one is given
// (--set account_id, --set accounts, account use/add/remove).
func checkAccountID(id string) error {
	if id == "" || strings.ContainsAny(id, "/|, \t\r\n") {
		return fmt.Errorf("%q is not an account id", id)
	}
	return nil
}

// inAccount returns the API bound to another account: a shallow copy
// sharing the HTTP client and the browser login, the selection unchanged.
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

// unscoped reports a login without an account: it reads whatever the
// credentials see.
func (a *api) unscoped() bool { return !a.pinned && a.accountID == "" && len(a.accounts) == 0 }

// scopeIDs are the accounts the lists and the lookups by name cover: the
// selection, or the pinned account alone. An unscoped login has the one
// entry "", which filters nothing.
func (a *api) scopeIDs() []string {
	if a.pinned || len(a.accounts) == 0 {
		return []string{a.accountID}
	}
	return a.accounts
}

// covers reports whether an object of the account id is one the API works
// on. An object that names no account is.
func (a *api) covers(id string) bool {
	return id == "" || a.unscoped() || slices.Contains(a.scopeIDs(), id)
}

// zonesNamed returns the zones named name in the accounts the API covers.
func (a *api) zonesNamed(ctx context.Context, name string) ([]apiZone, error) {
	ids := a.scopeIDs()
	var out []apiZone
	for _, id := range ids {
		zs, err := a.findZonesNamed(ctx, name, id)
		if err != nil {
			if len(ids) > 1 {
				return nil, fmt.Errorf("account %s: %w", id, err)
			}
			return nil, err
		}
		out = append(out, zs...)
	}
	return out, nil
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

// toZones converts the zones of the API.
func toZones(zs []apiZone) []platform.Zone {
	out := make([]platform.Zone, 0, len(zs))
	for _, z := range zs {
		out = append(out, toZone(z))
	}
	return out
}
