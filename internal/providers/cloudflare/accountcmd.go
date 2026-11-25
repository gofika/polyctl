package cloudflare

import (
	"context"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// ---------------------------------------------------------------- account

func newAccountCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "account",
		Short: "Cloudflare accounts of the login: the selected ones and the default",
		Long: `A Cloudflare login works on the accounts selected for it: the inventory, name
lookups and domain routing cover all of them. One of them is the default
account, where new zones are created. The login selects them; use, add and
remove change the selection without a new login.

An account that is not selected can still be named with --account on the
cloudflare zone, dns, cache, redirect, dev-mode, ssl-mode and r2 commands: it
is read live and nothing of it is cached.`,
	}
	cmd.AddCommand(newAccountListCmd(rt), newAccountCurrentCmd(rt), newAccountUseCmd(rt), newAccountAddCmd(rt), newAccountRemoveCmd(rt))
	return cmd
}

// accountRow is an account as account list shows it. The first three
// fields are the account as Cloudflare lists it.
type accountRow struct {
	ID       string `json:"id" yaml:"id"`
	Name     string `json:"name" yaml:"name"`
	Type     string `json:"type,omitempty" yaml:"type,omitempty"`
	Selected bool   `json:"selected" yaml:"selected"`
	Default  bool   `json:"default" yaml:"default"`
}

type accountListResult struct {
	Profile  string       `json:"profile" yaml:"profile"`
	Accounts []accountRow `json:"accounts" yaml:"accounts"`
}

// accountRows marks the selection of a login in the accounts its
// credentials list. A selected account the list does not show is appended
// without a type, and returned as unseen.
func accountRows(accounts []account, def, defName string, selected []string) (rows []accountRow, unseen []string) {
	rows = make([]accountRow, 0, len(accounts))
	seen := map[string]bool{}
	for _, a := range accounts {
		seen[a.ID] = true
		rows = append(rows, accountRow{ID: a.ID, Name: a.Name, Type: a.Type, Selected: slices.Contains(selected, a.ID), Default: a.ID == def})
	}
	for _, id := range selected {
		if seen[id] {
			continue
		}
		row := accountRow{ID: id, Selected: true, Default: id == def}
		if row.Default {
			row.Name = defName
		}
		rows = append(rows, row)
		unseen = append(unseen, id)
	}
	return rows, unseen
}

// accountGrid is the table of account list: * marks the default account.
func accountGrid(rows []accountRow) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "ID", "SELECTED"}, Empty: "no accounts"}
	for _, r := range rows {
		name, sel := r.Name, ""
		if r.Default {
			name += " *"
		}
		if r.Selected {
			sel = "yes"
		}
		g.Rows = append(g.Rows, []string{name, r.Type, r.ID, sel})
	}
	return g
}

// listedAccounts reads the accounts the credentials of a profile list,
// with the selection of its login marked.
func listedAccounts(ctx context.Context, rt *app.Runtime, s *session) ([]accountRow, []string, error) {
	accounts, err := s.client.api.listAccounts(ctx)
	if err != nil {
		return nil, nil, err
	}
	def, defName, selected, err := loginAccounts(rt, s.profile)
	if err != nil {
		return nil, nil, err
	}
	rows, unseen := accountRows(accounts, def, defName, selected)
	return rows, unseen, nil
}

func newAccountListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the accounts visible to the credentials, with the selected and the default ones marked",
		Long: `List the accounts visible to the profile's credentials (API token:
Account:Read; browser login: the account-settings.read scope). SELECTED marks
the accounts the login works on, and * the default one; a selected account the
credentials do not list is shown without a type, with a note.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			rows, unseen, err := listedAccounts(cmd.Context(), rt, s)
			if err != nil {
				return err
			}
			selected := 0
			for _, r := range rows {
				if r.Selected {
					selected++
				}
			}
			for _, id := range unseen {
				rt.Infof("note: selected account %s is not visible to the credentials (to take it out: polyctl cloudflare account remove %s)", id, id)
			}
			rt.Infof("%d account(s) via cloudflare/%s, %d selected", len(rows), s.profile, selected)
			return rt.Render(accountListResult{Profile: s.profile, Accounts: rows}, func() output.Grid { return accountGrid(rows) })
		},
	}
}

type currentAccount struct {
	Profile string `json:"profile" yaml:"profile"`
	// AccountID is the default account ("" for a login that is not bound
	// to an account); Accounts the selection, the default first.
	AccountID   string   `json:"account_id" yaml:"account_id"`
	AccountName string   `json:"account_name,omitempty" yaml:"account_name,omitempty"`
	Accounts    []string `json:"accounts" yaml:"accounts"`
	Method      string   `json:"method" yaml:"method"`
	Email       string   `json:"email,omitempty" yaml:"email,omitempty"`
}

// currentOf reads the accounts of a profile's Cloudflare login from the
// config.
func currentOf(rt *app.Runtime, profile string) (currentAccount, error) {
	cfg, err := rt.Config()
	if err != nil {
		return currentAccount{}, err
	}
	a, err := cfg.Account(profile, platform.Cloudflare)
	if err != nil {
		return currentAccount{}, fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	cur := currentAccount{Profile: profile, Accounts: selectedAccounts(a.Metadata), Method: a.Metadata[metaMethod], Email: a.Metadata[metaEmail]}
	if cur.Accounts == nil {
		cur.Accounts = []string{}
	}
	if len(cur.Accounts) > 0 {
		cur.AccountID, cur.AccountName = cur.Accounts[0], strings.TrimSpace(a.Metadata[metaAccountName])
	}
	return cur, nil
}

func renderCurrent(rt *app.Runtime, cur currentAccount) error {
	return rt.Render(cur, func() output.Grid {
		def := "(none: every account the credentials see)"
		if cur.AccountID != "" {
			def = accountLabel(cur.AccountID, cur.AccountName)
		}
		return output.KV("profile", cur.Profile, "account", def, "accounts", strings.Join(cur.Accounts, ", "), "method", cur.Method, "email", cur.Email)
	})
}

func newAccountCurrentCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the default account and the selected accounts of the Cloudflare login",
		Long: `Show the default account and the selected accounts of the profile's
Cloudflare login, as the local configuration holds them. Nothing is requested:
it works with --offline.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			name, err := rt.ProfileFor(platform.Cloudflare)
			if err != nil {
				return err
			}
			cur, err := currentOf(rt, name)
			if err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
}

// accountBook resolves and checks the accounts named to use, add and
// remove for the login of one profile.
type accountBook struct {
	rt      *app.Runtime
	profile string
	cur     currentAccount
	// The accounts the credentials see, read once (see visibleAccounts).
	fetched  bool
	visible  []account
	complete bool
	listErr  error
}

func openAccountBook(rt *app.Runtime) (*accountBook, error) {
	profile, err := rt.ProfileFor(platform.Cloudflare)
	if err != nil {
		return nil, err
	}
	cur, err := currentOf(rt, profile)
	if err != nil {
		return nil, err
	}
	return &accountBook{rt: rt, profile: profile, cur: cur}, nil
}

// list reads the accounts the credentials see. An empty list is that of
// credentials that cannot list their accounts; a listing that failed is an
// error (see visibleAccounts).
func (b *accountBook) list(ctx context.Context) ([]account, error) {
	if b.fetched {
		return b.visible, b.listErr
	}
	c, err := openProfile(ctx, b.rt, b.profile)
	if err != nil {
		return nil, err
	}
	b.visible, b.complete, err = visibleAccounts(ctx, c.api)
	if err != nil {
		b.listErr = fmt.Errorf("list the accounts of cloudflare/%s: %w", b.profile, err)
	}
	b.fetched = true
	return b.visible, b.listErr
}

// resolve turns the accounts named on the command line, by id or by name,
// into ids. A name the profile knows needs no request. With --offline what
// is not known is taken as an id.
func (b *accountBook) resolve(ctx context.Context, args []string) ([]string, error) {
	var out []string
	for _, ref := range args {
		ref = strings.TrimSpace(ref)
		id, ok := knownAccount(ctx, b.rt, b.profile, ref)
		switch {
		case ok:
		case b.rt.Flags.Offline:
			if err := checkAccountID(ref); err != nil {
				return nil, fmt.Errorf("%w: account %q is not known to cloudflare/%s and cannot be looked up with --offline: pass the account id", app.ErrOffline, ref, b.profile)
			}
			id = ref
		default:
			accounts, err := b.list(ctx)
			if err != nil {
				return nil, err
			}
			if id, err = matchAccount(b.profile, ref, "", accounts, b.complete); err != nil {
				return nil, err
			}
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// resolveSelected turns the accounts named to remove, by id or by name,
// into ids of the selection, which is where remove works: a name is one a
// selected account carries, as the credentials list it (they are not asked
// with --offline, and credentials that fail keep nothing from being removed
// by id) or as the profile knows it. A name several selected accounts carry
// is ambiguous (exit code 5); a reference that names no selected account is
// returned as it is, for the caller to report it as not selected.
func (b *accountBook) resolveSelected(ctx context.Context, args []string) ([]string, error) {
	var out []string
	for _, ref := range args {
		ref = strings.TrimSpace(ref)
		id := ref
		if !slices.Contains(b.cur.Accounts, ref) {
			if !b.rt.Flags.Offline {
				_, _ = b.list(ctx)
			}
			var named []string
			for _, sel := range b.cur.Accounts {
				if n := b.localName(ctx, sel); n != "" && strings.EqualFold(n, ref) {
					named = append(named, sel)
				}
			}
			switch len(named) {
			case 0:
			case 1:
				id = named[0]
			default:
				cands := make([]string, 0, len(named))
				for _, sel := range named {
					cands = append(cands, accountLabel(sel, b.localName(ctx, sel)))
				}
				return nil, &app.AmbiguousError{What: fmt.Sprintf("account %q", ref), Candidates: cands, Hint: "pass the account id to choose"}
			}
		}
		if !slices.Contains(out, id) {
			out = append(out, id)
		}
	}
	return out, nil
}

// localName is the name of an account as far as the profile knows it
// without a request: as the credentials listed it in this call, as the
// login stored it for its default account, or as the cached zones carry it.
func (b *accountBook) localName(ctx context.Context, id string) string {
	for _, a := range b.visible {
		if a.ID == id && a.Name != "" {
			return a.Name
		}
	}
	if id == b.cur.AccountID && b.cur.AccountName != "" {
		return b.cur.AccountName
	}
	if db, err := b.rt.DB(); err == nil {
		rows, _ := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: b.profile, Type: platform.ResZone})
		for _, r := range rows {
			if z := rowZone(r); zoneAccount(z) == id && zoneAccountName(z) != "" {
				return zoneAccountName(z)
			}
		}
	}
	return ""
}

// name is localName, with the accounts of the credentials asked for a name
// the profile does not know (not with --offline). "" is a name nobody
// could tell.
func (b *accountBook) name(ctx context.Context, id string) string {
	if n := b.localName(ctx, id); n != "" || b.fetched || b.rt.Flags.Offline {
		return n
	}
	_, _ = b.list(ctx)
	return b.localName(ctx, id)
}

// check verifies that the credentials see the accounts before they are
// selected. Offline, and with credentials that cannot list their accounts,
// nothing can be checked, which is said.
func (b *accountBook) check(ctx context.Context, ids []string) error {
	if b.rt.Flags.Offline {
		b.rt.Infof("note: --offline: access to %s was not checked", strings.Join(ids, ", "))
		return nil
	}
	accounts, err := b.list(ctx)
	if err != nil {
		return err
	}
	var unchecked []string
	for _, id := range ids {
		switch {
		case slices.ContainsFunc(accounts, func(a account) bool { return a.ID == id }):
		case len(accounts) > 0 && b.complete:
			return fmt.Errorf("%w: account %s is not visible to the credentials of cloudflare/%s (visible: %s)", platform.ErrNotFound, id, b.profile, accountNames(accounts))
		default:
			unchecked = append(unchecked, id)
		}
	}
	if len(unchecked) > 0 {
		b.rt.Infof("note: the credentials of cloudflare/%s cannot list accounts: access to %s was not checked", b.profile, strings.Join(unchecked, ", "))
	}
	return nil
}

// accountOption labels an account for a pick: "Acme (acc1)  default".
func accountOption(id, name, mark string) prompt.Option {
	label := id
	if name != "" {
		label = name + " (" + id + ")"
	}
	if mark != "" {
		label += "  " + mark
	}
	return prompt.Option{Label: label, Value: id}
}

// options are the accounts the credentials see, as options labelled with
// what the selection says about them. keep filters them.
func (b *accountBook) options(ctx context.Context, keep func(accountRow) bool) ([]prompt.Option, error) {
	if !b.rt.Interactive() {
		return nil, nil
	}
	if b.rt.Flags.Offline {
		return nil, app.ErrOffline
	}
	accounts, err := b.list(ctx)
	if err != nil {
		return nil, err
	}
	if len(accounts) == 0 {
		return nil, app.UsageErrf("the credentials of cloudflare/%s cannot list accounts: pass the account id", b.profile)
	}
	rows, _ := accountRows(accounts, b.cur.AccountID, b.cur.AccountName, b.cur.Accounts)
	var opts []prompt.Option
	for _, r := range rows {
		if keep != nil && !keep(r) {
			continue
		}
		mark := ""
		switch {
		case r.Default:
			mark = "default"
		case r.Selected:
			mark = "selected"
		}
		opts = append(opts, accountOption(r.ID, r.Name, mark))
	}
	return opts, nil
}

// save stores def as the default account, with its name, and selected as
// the selection.
func (b *accountBook) save(ctx context.Context, def string, selected []string) error {
	return saveSelection(ctx, b.rt, b.profile, account{ID: def, Name: b.name(ctx, def)}, selected)
}

// saveSelection stores a new default account and selection for the
// profile's Cloudflare login, drops what is cached for the accounts outside
// the new selection and makes every cached set of the login due, so that
// the next read syncs the new selection.
func saveSelection(ctx context.Context, rt *app.Runtime, profile string, def account, selected []string) error {
	cfg, err := rt.ReloadConfig()
	if err != nil {
		return err
	}
	a, err := cfg.Account(profile, platform.Cloudflare)
	if err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	before := selectedAccounts(a.Metadata)
	if a.Metadata == nil {
		a.Metadata = map[string]string{}
	}
	setSelection(a.Metadata, def, selected)
	if err := cfg.Save(); err != nil {
		return err
	}
	if _, err := rt.ReloadConfig(); err != nil {
		return err
	}
	db, err := rt.DB()
	if err != nil {
		return err
	}
	if err := forgetUnselected(ctx, rt, db, profile, before, selectedAccounts(a.Metadata)); err != nil {
		return err
	}
	return db.Expire(ctx, platform.Cloudflare, profile)
}

// forgetUnselected drops from the inventory of a profile what it holds of
// the accounts outside the selection after of its login: the trees of the
// accounts that left the selection before, and every other zone (with its
// records) and bucket row of an account that is not selected.
//
// Those other rows are the ones of a login that was not bound to an account
// (it cached whatever its credentials saw, and before is empty), and the
// ones stored before the rows had their account as parent, which the purge
// of a tree does not reach: they name the account in their data. A row that
// names no account at all is of the default account it was stored under.
// Nothing is dropped for a login that ends up without an account: it covers
// whatever its credentials see.
func forgetUnselected(ctx context.Context, rt *app.Runtime, db *inventory.DB, profile string, before, after []string) error {
	if len(after) == 0 {
		return nil
	}
	for _, id := range before {
		if slices.Contains(after, id) {
			continue
		}
		if err := db.PurgeTree(ctx, platform.Cloudflare, profile, id); err != nil {
			return err
		}
	}
	gone := func(account string) bool {
		if account == "" && len(before) > 0 {
			account = before[0]
		}
		return account != "" && !slices.Contains(after, account)
	}
	zones, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResZone})
	if err != nil {
		return err
	}
	for _, r := range zones {
		if gone(rowAccount(r)) {
			dropZone(ctx, rt, profile, r.ID)
		}
	}
	buckets, err := db.List(ctx, inventory.Query{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResR2Bucket})
	if err != nil {
		return err
	}
	for _, r := range buckets {
		account := r.ParentID
		if account == "" {
			var row r2BucketRow
			if r.Decode(&row) == nil {
				account = row.AccountID
			}
		}
		if !gone(account) {
			continue
		}
		if err := db.Delete(ctx, inventory.Set{Platform: platform.Cloudflare, Profile: profile, Type: platform.ResR2Bucket}, platform.ResR2Bucket, r.ID); err != nil {
			return err
		}
	}
	return nil
}

func newAccountUseCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <account>",
		Short: "Make an account the default account of the Cloudflare login",
		Long: `Make <account>, an account id or name, the default account of the profile's
Cloudflare login: the one new zones are created in when --account names no
other. An account that is not selected yet is added to the selection. The
credentials must see it (not checked with --offline, nor when they cannot
list their accounts). On a terminal, without <account> the visible accounts
are offered.

A login that is not bound to an account (its credentials could not list their
accounts when it was made) works on this account alone from then on: what the
inventory cached of every other account is dropped.

Only the local configuration changes; the cached inventory of the login is
synced again on its next use.`,
		Args: app.ArgsOrInteractive(rt, 1, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			b, err := openAccountBook(rt)
			if err != nil {
				return err
			}
			ids, err := b.resolve(ctx, args)
			if err != nil {
				return err
			}
			var id string
			if len(ids) > 0 {
				id = ids[0]
			} else {
				opts, err := b.options(ctx, nil)
				if err != nil {
					return err
				}
				if id, err = rt.Choose(app.Choice{Title: "Default account", Options: opts, Default: b.cur.AccountID, Arg: "<account>", What: "account visible to cloudflare/" + b.profile}); err != nil {
					return err
				}
			}
			if id == b.cur.AccountID {
				rt.Infof("account %s is already the default account of cloudflare/%s", id, b.profile)
				return renderCurrent(rt, b.cur)
			}
			if !slices.Contains(b.cur.Accounts, id) {
				if err := b.check(ctx, []string{id}); err != nil {
					return err
				}
			}
			if err := b.save(ctx, id, append([]string{id}, b.cur.Accounts...)); err != nil {
				return err
			}
			rt.Infof("account %s is now the default account of cloudflare/%s", id, b.profile)
			cur, err := currentOf(rt, b.profile)
			if err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
	app.MarkNoDryRun(cmd)
	return cmd
}

func newAccountAddCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "add <account>...",
		Short: "Add accounts to the selection of the Cloudflare login",
		Long: `Add accounts, by id or name, to the selection of the profile's Cloudflare
login, without a new login: the inventory, name lookups and domain routing
cover them from then on. The default account stays (the first account added
to a login that is not bound to one becomes its default). The credentials
must see each account (not checked with --offline, nor when they cannot list
their accounts). An account that is selected already is left as it is. On a
terminal, without <account> the visible accounts that are not selected are
offered (tick several).

Only the local configuration changes; the cached inventory of the login is
synced again on its next use.`,
		Args: app.RangeArgsOrInteractive(rt, 1, 100, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			b, err := openAccountBook(rt)
			if err != nil {
				return err
			}
			ids, err := b.resolve(ctx, args)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				opts, err := b.options(ctx, func(r accountRow) bool { return !r.Selected })
				if err != nil {
					return err
				}
				if ids, err = rt.ChooseMany(app.Choice{Title: "Accounts to add", Options: opts, Arg: "<account>", What: "visible account that is not selected yet"}); err != nil {
					return err
				}
			}
			var add []string
			for _, id := range ids {
				if !slices.Contains(b.cur.Accounts, id) {
					add = append(add, id)
				}
			}
			if len(add) == 0 {
				return app.NothingToDof("%s: already selected for cloudflare/%s", strings.Join(ids, ", "), b.profile)
			}
			if err := b.check(ctx, add); err != nil {
				return err
			}
			def := b.cur.AccountID
			if def == "" {
				def = add[0]
			}
			if err := b.save(ctx, def, append(slices.Clone(b.cur.Accounts), add...)); err != nil {
				return err
			}
			rt.Infof("added %s to the accounts of cloudflare/%s", strings.Join(add, ", "), b.profile)
			if def != b.cur.AccountID {
				rt.Infof("account %s is now the default account of cloudflare/%s", def, b.profile)
			}
			cur, err := currentOf(rt, b.profile)
			if err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
	app.MarkNoDryRun(cmd)
	return cmd
}

func newAccountRemoveCmd(rt *app.Runtime) *cobra.Command {
	var newDefault string
	cmd := &cobra.Command{
		Use:   "remove <account>...",
		Short: "Take accounts out of the selection of the Cloudflare login",
		Long: `Take accounts, by id or name, out of the selection of the profile's
Cloudflare login. Nothing at Cloudflare changes and the credentials stay as
they are: the accounts are no longer synced or searched, and what the
inventory cached of them (zones, their records, R2 buckets) is dropped. An
account that is not selected is not found (exit code 4).

The default account can be removed only together with --default <account>,
which names the selected account that becomes the default (on a terminal it
is asked); without it this is a usage error (exit code 2), as is removing
every account (log the login out with "polyctl auth logout cloudflare"
instead). On a terminal, without <account> the selected accounts are offered.

No confirmation is asked: only the local configuration and a cache that the
next sync rebuilds change. Works with --offline; a name is then one the
profile knows (that of the default account, or of an account with a cached
zone).`,
		Args: app.RangeArgsOrInteractive(rt, 1, 100, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			b, err := openAccountBook(rt)
			if err != nil {
				return err
			}
			cur := b.cur
			ids, err := b.resolveSelected(ctx, args)
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				var opts []prompt.Option
				for _, id := range cur.Accounts {
					mark := ""
					if id == cur.AccountID {
						mark = "default"
					}
					opts = append(opts, accountOption(id, b.localName(ctx, id), mark))
				}
				if ids, err = rt.ChooseMany(app.Choice{Title: "Accounts to remove", Options: opts, Arg: "<account>", What: "selected account"}); err != nil {
					return err
				}
			}
			var missing []string
			for _, id := range ids {
				if !slices.Contains(cur.Accounts, id) {
					missing = append(missing, id)
				}
			}
			if len(missing) > 0 {
				sort.Strings(missing)
				selected := "none"
				if len(cur.Accounts) > 0 {
					selected = strings.Join(cur.Accounts, ", ")
				}
				return fmt.Errorf("%w: %s is not selected for cloudflare/%s (selected: %s)", platform.ErrNotFound, strings.Join(missing, ", "), b.profile, selected)
			}
			var rest []string
			for _, id := range cur.Accounts {
				if !slices.Contains(ids, id) {
					rest = append(rest, id)
				}
			}
			if len(rest) == 0 {
				return app.UsageErrf("this would remove every account of cloudflare/%s; a login needs one (to drop the login: polyctl auth logout cloudflare --profile %s)", b.profile, b.profile)
			}
			def := cur.AccountID
			newDefault = strings.TrimSpace(newDefault)
			switch {
			case newDefault != "":
				picked, err := b.resolveSelected(ctx, []string{newDefault})
				if err != nil {
					return err
				}
				if !slices.Contains(rest, picked[0]) {
					return app.UsageErrf("--default %s: not one of the accounts that stay selected (%s)", newDefault, strings.Join(rest, ", "))
				}
				def = picked[0]
			case !slices.Contains(rest, def):
				if len(rest) == 1 && rt.Interactive() {
					def = rest[0]
					break
				}
				var opts []prompt.Option
				for _, id := range rest {
					opts = append(opts, accountOption(id, b.localName(ctx, id), ""))
				}
				if def, err = rt.Choose(app.Choice{Title: "New default account", Options: opts, Arg: "--default", Missing: func() error {
					return app.UsageErrf("%s is the default account of cloudflare/%s: pass --default <id> to name the one that replaces it (one of: %s)", cur.AccountID, b.profile, strings.Join(rest, ", "))
				}}); err != nil {
					return err
				}
			}
			if err := b.save(ctx, def, rest); err != nil {
				return err
			}
			rt.Infof("removed %s from the accounts of cloudflare/%s", strings.Join(ids, ", "), b.profile)
			if def != cur.AccountID {
				rt.Infof("account %s is now the default account of cloudflare/%s", def, b.profile)
			}
			if cur, err = currentOf(rt, b.profile); err != nil {
				return err
			}
			return renderCurrent(rt, cur)
		},
	}
	cmd.Flags().StringVar(&newDefault, "default", "", "the selected account, by id or name, that becomes the default when the default account is removed")
	app.MarkNoDryRun(cmd)
	return cmd
}
