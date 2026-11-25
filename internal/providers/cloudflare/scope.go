package cloudflare

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// A Cloudflare command works on the selected accounts of its login, or on
// the one account --account names. An account outside the selection is read
// live: nothing of it is stored in the inventory.

// accountFlag is the value of --account: an account id or name.
type accountFlag struct{ v *string }

func (f accountFlag) String() string {
	if f.v == nil {
		return ""
	}
	return *f.v
}
func (f accountFlag) Type() string { return "string" }
func (f accountFlag) Set(s string) error {
	s = strings.TrimSpace(s)
	if s == "" {
		return errors.New("an account id or name is required")
	}
	*f.v = s
	return nil
}

// accountFlagHelp is the usage text of --account.
const accountFlagHelp = "Cloudflare account of this call, by id or name (default: every selected account for lookups and lists, the default account for creates); an account outside the selection is read live and not cached"

// addAccountFlag adds --account to a command and everything below it. A
// command tree built without a runtime (to inspect it) gets a flag nothing
// reads.
func addAccountFlag(rt *app.Runtime, cmd *cobra.Command) {
	v := new(string)
	if rt != nil {
		rt.Flags.Account = ""
		v = &rt.Flags.Account
	}
	cmd.PersistentFlags().Var(accountFlag{v}, "account", accountFlagHelp)
}

// pinnedAccount is the value of --account, "" when the flag was not given.
func pinnedAccount(rt *app.Runtime) string { return strings.TrimSpace(rt.Flags.Account) }

// loginAccounts returns the default account, its name and the selection of
// a profile's Cloudflare login, from the config. All are empty for an
// unscoped login.
func loginAccounts(rt *app.Runtime, profile string) (def, defName string, selected []string, err error) {
	cfg, err := rt.Config()
	if err != nil {
		return "", "", nil, err
	}
	a, err := cfg.Account(profile, platform.Cloudflare)
	if err != nil {
		return "", "", nil, fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	selected = selectedAccounts(a.Metadata)
	if len(selected) > 0 {
		def = selected[0]
	}
	return def, strings.TrimSpace(a.Metadata[metaAccountName]), selected, nil
}

// zoneAccount is the account id a zone carries, "" when it names none.
func zoneAccount(z platform.Zone) string {
	id, _ := z.Extra["account_id"].(string)
	return id
}

// zoneAccountName is the account name a zone carries.
func zoneAccountName(z platform.Zone) string {
	name, _ := z.Extra["account_name"].(string)
	return name
}

// rowZone decodes a cached zone row.
func rowZone(r inventory.Resource) platform.Zone {
	var z platform.Zone
	_ = r.Decode(&z)
	if z.ID == "" {
		z.ID = r.ID
	}
	if z.Name == "" {
		z.Name = r.Name
	}
	return z
}

// rowAccount is the account of a cached zone row: its parent, or, for a
// row stored before the rows had one, the account the zone carries.
func rowAccount(r inventory.Resource) string {
	if r.ParentID != "" {
		return r.ParentID
	}
	return zoneAccount(rowZone(r))
}

// knownAccount resolves an account reference without the network: the id
// of a selected account, or a name the profile knows (that of the default
// account, and those the cached zones carry) when it names one account. A
// login without an account has no selection: the id of an account it
// cached zones of is known to it instead.
func knownAccount(ctx context.Context, rt *app.Runtime, profile, ref string) (string, bool) {
	def, defName, selected, err := loginAccounts(rt, profile)
	if err != nil {
		return "", false
	}
	if slices.Contains(selected, ref) {
		return ref, true
	}
	var ids []string
	add := func(id, name string) {
		if id != "" && strings.EqualFold(name, ref) && !slices.Contains(ids, id) {
			ids = append(ids, id)
		}
	}
	add(def, defName)
	if db, err := rt.DB(); err == nil {
		rows, _ := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone})
		for _, r := range rows {
			z := rowZone(r)
			if len(selected) == 0 && ref != "" && rowAccount(r) == ref {
				return ref, true
			}
			add(zoneAccount(z), zoneAccountName(z))
		}
	}
	if len(ids) == 1 {
		return ids[0], true
	}
	return "", false
}

// invalidCredentialCodes are the Cloudflare error codes of credentials
// that are refused altogether, whatever they ask for.
var invalidCredentialCodes = map[int]bool{
	9109: true, // Invalid access token
	9106: true, // Missing X-Auth-Key, X-Auth-Email or Authorization headers
	9103: true, // Unknown X-Auth-Key or X-Auth-Email
	6003: true, // Invalid request headers
	6111: true, // Invalid format for Authorization header
}

// notPermitted reports whether err is the answer to credentials that work
// but may not make this request (HTTP 403 without a code of refused
// credentials): a token without the permission, a browser login without
// the scope.
func notPermitted(err error) bool {
	var e *Error
	if !errors.As(err, &e) || e.Status != http.StatusForbidden {
		return false
	}
	for _, m := range e.Errors {
		if invalidCredentialCodes[m.Code] {
			return false
		}
	}
	return true
}

// visibleAccounts lists the accounts the credentials see. Credentials that
// may not list accounts have them read off their zones: that list holds
// the accounts with a zone only, and complete is false. It is empty,
// without an error, for credentials that may list neither, or that see no
// zone: they cannot list their accounts.
//
// A listing that fails for another reason (the network, a server error,
// credentials that are refused altogether) is an error: it says nothing
// about what the credentials may list.
func visibleAccounts(ctx context.Context, a *api) (accounts []account, complete bool, err error) {
	accounts, err = a.listAccounts(ctx)
	switch {
	case err == nil && len(accounts) > 0:
		return accounts, true, nil
	case err != nil && !notPermitted(err):
		return nil, false, err
	}
	byZone, err := a.accountsOfZones(ctx)
	if err != nil && !notPermitted(err) {
		return nil, false, err
	}
	return byZone, false, nil
}

// resolveAccountRef turns the account a user names for a profile, by id or
// by name, into its id:
//
//   - the id of a selected account, or a name the profile knows, without
//     the network;
//   - else among the accounts the credentials see, by id, then by name: a
//     name several of them carry is ambiguous (exit code 5), and an account
//     that is not among them is not found (exit code 4);
//   - credentials that cannot list their accounts have the reference taken
//     as the id.
//
// With --offline a reference the profile does not know cannot be resolved
// (exit code 6).
func resolveAccountRef(ctx context.Context, rt *app.Runtime, profile, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	if id, ok := knownAccount(ctx, rt, profile, ref); ok {
		return id, nil
	}
	if rt.Flags.Offline {
		return "", fmt.Errorf("%w: account %q is not selected for cloudflare/%s and cannot be looked up with --offline", app.ErrOffline, ref, profile)
	}
	c, err := openProfile(ctx, rt, profile)
	if err != nil {
		return "", err
	}
	accounts, complete, err := visibleAccounts(ctx, c.api)
	if err != nil {
		return "", fmt.Errorf("look up account %q: %w", ref, err)
	}
	return matchAccount(profile, ref, "--account: ", accounts, complete)
}

// matchAccount finds the account a reference names among the accounts the
// credentials of a profile see (see resolveAccountRef); complete says the
// list is not one read off the zones. prefix starts the usage error of a
// name that cannot be looked up.
func matchAccount(profile, ref, prefix string, accounts []account, complete bool) (string, error) {
	if len(accounts) == 0 {
		if cerr := checkAccountID(ref); cerr != nil {
			return "", app.UsageErrf("%sthe credentials of cloudflare/%s cannot list accounts, so an account name cannot be looked up: pass the account id", prefix, profile)
		}
		return ref, nil
	}
	for _, a := range accounts {
		if a.ID == ref {
			return ref, nil
		}
	}
	var named []account
	for _, a := range accounts {
		if strings.EqualFold(a.Name, ref) {
			named = append(named, a)
		}
	}
	switch {
	case len(named) == 1:
		return named[0].ID, nil
	case len(named) > 1:
		cands := make([]string, 0, len(named))
		for _, a := range named {
			cands = append(cands, fmt.Sprintf("%s (%s)", a.Name, a.ID))
		}
		return "", &app.AmbiguousError{What: fmt.Sprintf("account %q", ref), Candidates: cands, Hint: "pass the account id to choose"}
	case !complete && checkAccountID(ref) == nil:
		// The list holds the accounts with a zone only: the reference may
		// be the id of one without.
		return ref, nil
	}
	return "", fmt.Errorf("%w: account %q is not visible to the credentials of cloudflare/%s (visible: %s)", platform.ErrNotFound, ref, profile, accountNames(accounts))
}

// acctScope is what one call covers in one profile.
type acctScope struct {
	profile string
	// def is the default account of the login: a row that names no account
	// counts as one of it.
	def string
	// selected is the selection of the login, empty for an unscoped one
	// (which covers whatever its credentials see).
	selected []string
	// pin is the account of --account, "" without the flag.
	pin string
	// live says --account names an account outside the selection: it is
	// read live and nothing of it is stored.
	live bool
}

// keeps reports whether an object of account is in the scope: of the
// account of --account with the flag, of a selected account without it.
//
// A cached row of an account that is no longer selected is out of scope:
// the selection may have changed (a new login, an edited config.yaml)
// while the set that holds the row is still fresh, and a command must not
// find, let alone change, a zone of an account the login was taken off.
func (s acctScope) keeps(account string) bool {
	if account == "" {
		account = s.def
	}
	switch {
	case account == "":
		return true
	case s.pin != "":
		return account == s.pin
	}
	return len(s.selected) == 0 || slices.Contains(s.selected, account)
}

// several reports whether the scope spans more than one account, so that
// what it lists has to say which account it is of.
func (s acctScope) several() bool { return s.pin == "" && len(s.selected) != 1 }

// profileScope is the scope of the call in profile: the selection of its
// login, or the account of --account. An unscoped login covers every
// account its credentials see, so --account only filters it.
func profileScope(ctx context.Context, rt *app.Runtime, profile string) (acctScope, error) {
	def, _, selected, err := loginAccounts(rt, profile)
	if err != nil {
		return acctScope{}, err
	}
	s := acctScope{profile: profile, def: def, selected: selected}
	ref := pinnedAccount(rt)
	if ref == "" {
		return s, nil
	}
	if s.pin, err = resolveAccountRef(ctx, rt, profile, ref); err != nil {
		return acctScope{}, err
	}
	s.live = len(selected) > 0 && !slices.Contains(selected, s.pin)
	return s, nil
}

// localScope is profileScope without the network, for shell completion: an
// --account the profile does not know filters nothing.
func localScope(ctx context.Context, rt *app.Runtime, profile string) acctScope {
	def, _, selected, _ := loginAccounts(rt, profile)
	s := acctScope{profile: profile, def: def, selected: selected}
	if ref := pinnedAccount(rt); ref != "" {
		s.pin, _ = knownAccount(ctx, rt, profile, ref)
	}
	return s
}

// cloudflareProfiles are the profiles with a Cloudflare login, restricted
// by --profile.
func cloudflareProfiles(rt *app.Runtime) ([]config.AccountRef, error) {
	all, err := rt.Accounts()
	if err != nil {
		return nil, err
	}
	var out []config.AccountRef
	for _, a := range all {
		if a.Platform == platform.Cloudflare {
			out = append(out, a)
		}
	}
	return out, nil
}

// routeScopes are the scopes of a command that finds its zone among the
// Cloudflare logins (restricted by --profile): the selection of each, or,
// with --account, that account in the logins that select it (or are
// unscoped). When no login selects the account it is read live through the
// profile every Cloudflare command would use: the one scope returned then
// has live set.
func routeScopes(ctx context.Context, rt *app.Runtime) ([]acctScope, error) {
	profiles, err := cloudflareProfiles(rt)
	if err != nil {
		return nil, err
	}
	ref := pinnedAccount(rt)
	var out, unscoped []acctScope
	pin := ""
	for _, p := range profiles {
		def, _, selected, err := loginAccounts(rt, p.Profile)
		if err != nil {
			return nil, err
		}
		s := acctScope{profile: p.Profile, def: def, selected: selected}
		switch {
		case ref == "":
			out = append(out, s)
		case len(selected) == 0:
			unscoped = append(unscoped, s)
		default:
			if id, ok := knownAccount(ctx, rt, p.Profile, ref); ok && slices.Contains(selected, id) {
				s.pin, pin = id, id
				out = append(out, s)
			}
		}
	}
	if ref == "" {
		return out, nil
	}
	if len(out) > 0 {
		for _, s := range unscoped {
			s.pin = pin
			out = append(out, s)
		}
		return out, nil
	}
	profile, err := rt.ProfileFor(platform.Cloudflare)
	if err != nil {
		return nil, err
	}
	s, err := profileScope(ctx, rt, profile)
	if err != nil {
		return nil, err
	}
	return []acctScope{s}, nil
}

// cacheable reports whether what a profile reads of account belongs in the
// inventory: the account is selected, or the login is unscoped. Something
// that names no account is of the default one.
func cacheable(rt *app.Runtime, profile, account string) bool {
	_, _, selected, err := loginAccounts(rt, profile)
	return err != nil || account == "" || len(selected) == 0 || slices.Contains(selected, account)
}

// disambiguate settles an ambiguous lookup of the interactive flow by
// asking which of the candidates found is meant; the non-interactive flow
// gets the error (exit code 5).
func disambiguate[T any](rt *app.Runtime, amb *app.AmbiguousError, found []T, label func(T) string) (T, error) {
	var zero T
	for i, f := range found {
		amb.Options = append(amb.Options, prompt.Option{Label: label(f), Value: strconv.Itoa(i)})
	}
	v, err := rt.Disambiguate(amb)
	if err != nil {
		return zero, err
	}
	i, err := strconv.Atoi(v)
	if err != nil || i < 0 || i >= len(found) {
		return zero, fmt.Errorf("unexpected choice %q", v)
	}
	return found[i], nil
}

// zoneCand is one candidate of an ambiguous zone lookup.
type zoneCand struct {
	profile              string
	account, accountName string
	id, status           string
}

func (c zoneCand) String() string {
	s := "cloudflare/" + c.profile
	if c.account != "" {
		s += " account " + accountLabel(c.account, c.accountName)
	}
	s += " zone " + c.id
	if c.status != "" {
		s += " " + c.status
	}
	return s
}

// cells is the candidate as an option of the pick that settles the lookup:
// "<zone id>  active  account acc1  Acme  cloudflare/work". A fact the
// candidate does not have shows "-" in its cell.
func (c zoneCand) cells() string {
	account := ""
	if c.account != "" {
		account = "account " + c.account
	}
	return prompt.Cells(c.id, c.status, account, c.accountName, "cloudflare/"+c.profile)
}

func candOfZone(profile string, z platform.Zone) zoneCand {
	return zoneCand{profile: profile, account: zoneAccount(z), accountName: zoneAccountName(z), id: z.ID, status: z.Status}
}

func candOfAPIZone(profile string, z apiZone) zoneCand {
	return zoneCand{profile: profile, account: z.Account.ID, accountName: z.Account.Name, id: z.ID, status: z.Status}
}

// zoneHint is the hint of an ambiguous zone: the flags whose value differs
// among the candidates, and, for a command that takes a zone id (byID), the
// zone id when the ids differ. They do not when the candidates are one
// zone seen through two logins: only --profile chooses then.
func zoneHint(cands []zoneCand, byID bool) string {
	distinct := func(get func(zoneCand) string) bool {
		for _, c := range cands[1:] {
			if get(c) != get(cands[0]) {
				return true
			}
		}
		return false
	}
	var flags []string
	if distinct(func(c zoneCand) string { return c.profile }) {
		flags = append(flags, "--profile <name>")
	}
	if distinct(func(c zoneCand) string { return c.account }) {
		flags = append(flags, "--account <id or name>")
	}
	byID = byID && distinct(func(c zoneCand) string { return c.id })
	switch {
	case len(flags) == 0 && byID:
		return "pass the zone id to choose"
	case len(flags) == 0:
		return "name the account or the login of the zone to choose"
	case !byID:
		return "pass " + strings.Join(flags, " or ") + " to choose"
	}
	return "pass " + strings.Join(flags, " or ") + ", or the zone id, to choose"
}

// ambiguousZone is the error of a zone name several accounts hold a zone
// of: every candidate with its account, and what chooses one (byID: the
// command takes a zone id as well). The interactive flow turns it into a
// pick (disambiguate); the non-interactive flow returns it (exit code 5).
func ambiguousZone(ref string, cands []zoneCand, byID bool) *app.AmbiguousError {
	names := make([]string, 0, len(cands))
	for _, c := range cands {
		names = append(names, c.String())
	}
	return &app.AmbiguousError{What: fmt.Sprintf("zone %q", ref), Candidates: names, Hint: zoneHint(cands, byID)}
}

// pickAmbiguousZone settles a zone name that several zones of the API
// carry. byID says the command takes a zone id in place of the name.
func pickAmbiguousZone(rt *app.Runtime, profile, ref string, zs []apiZone, byID bool) (*apiZone, error) {
	cands := make([]zoneCand, 0, len(zs))
	for _, z := range zs {
		cands = append(cands, candOfAPIZone(profile, z))
	}
	z, err := disambiguate(rt, ambiguousZone(ref, cands, byID), zs, func(z apiZone) string { return candOfAPIZone(profile, z).cells() })
	if err != nil {
		return nil, err
	}
	return &z, nil
}

// unselectedZoneErr is the answer for a zone in an account the login does
// not select.
func unselectedZoneErr(name, id, account string) error {
	return fmt.Errorf("%w: zone %s (%s) is in account %s, which is not selected for this login: add it with \"polyctl cloudflare account add %s\", or pass --account %s to the cloudflare commands",
		platform.ErrNotFound, platform.NormalizeDomain(name), id, account, account, account)
}

// otherAccountErr is the usage error of a zone id given with the --account
// of another account.
func otherAccountErr(ref, account, pin string) error {
	return app.UsageErrf("zone %q is of account %s, not of --account %s: drop --account or name a zone of that account", ref, account, pin)
}

// findLiveZone looks a zone up on the platform for a scope: a name among
// the accounts of the scope (several zones of it are a pick in the
// interactive flow and exit code 5 otherwise), an id with a check of its
// account. a is the API of the profile's login.
func findLiveZone(ctx context.Context, rt *app.Runtime, a *api, sc acctScope, ref string) (*apiZone, error) {
	if sc.pin != "" {
		a = a.pin(sc.pin)
	}
	name := platform.NormalizeDomain(ref)
	if !strings.Contains(name, ".") {
		z, err := a.getZone(ctx, ref)
		if err != nil {
			return nil, err
		}
		switch acc := z.Account.ID; {
		case acc == "" || a.covers(acc):
		case sc.pin != "":
			return nil, otherAccountErr(ref, acc, sc.pin)
		default:
			return nil, unselectedZoneErr(z.Name, z.ID, acc)
		}
		return z, nil
	}
	zs, err := a.zonesNamed(ctx, name)
	if err != nil {
		return nil, err
	}
	switch len(zs) {
	case 1:
		return &zs[0], nil
	case 0:
		if sc.pin != "" {
			return nil, fmt.Errorf("%w: zone %q in account %s of cloudflare/%s", platform.ErrNotFound, name, sc.pin, sc.profile)
		}
		if !a.unscoped() {
			// The credentials may see it in an account the login does not
			// select: say so.
			if others, oerr := a.findZonesNamed(ctx, name, ""); oerr == nil {
				for _, z := range others {
					if acc := z.Account.ID; acc != "" && !a.covers(acc) {
						return nil, fmt.Errorf("%w: zone %q (it is in account %s, which is not selected: polyctl cloudflare account add %s, or --account %s)",
							platform.ErrNotFound, name, acc, acc, acc)
					}
				}
			}
		}
		return nil, fmt.Errorf("%w: zone %q", platform.ErrNotFound, name)
	}
	return pickAmbiguousZone(rt, sc.profile, name, zs, true)
}
