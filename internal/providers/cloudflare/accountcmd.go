package cloudflare

import (
	"context"
	"errors"
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
		Short: "Cloudflare accounts of the login: the default one, and the ones kept out of every sync",
		Long: `A Cloudflare login works on every account its credentials see: the
inventory, name lookups and domain routing cover all of them, the ones the
credentials reach later included. One of them is the default account, where
new zones are created and which a command works on when nothing names an
account: use sets it.

disable keeps the accounts that are certainly not used out of every sync,
list and lookup, and enable takes them back.

A disabled account can still be named with --account on the cloudflare zone,
dns, cache, redirect, dev-mode, ssl-mode and r2 commands: it is read live and
nothing of it is cached.`,
	}
	cmd.AddCommand(newAccountListCmd(rt), newAccountCurrentCmd(rt), newAccountUseCmd(rt),
		newAccountEnableCmd(rt, "enable", false), newAccountDisableCmd(rt, "disable", false),
		// The names these two had while the login held a selection.
		newAccountEnableCmd(rt, "add", true), newAccountDisableCmd(rt, "remove", true))
	return cmd
}

// accountRow is an account as account list shows it. The first three
// fields are the account as Cloudflare lists it.
type accountRow struct {
	ID      string `json:"id" yaml:"id"`
	Name    string `json:"name" yaml:"name"`
	Type    string `json:"type,omitempty" yaml:"type,omitempty"`
	Enabled bool   `json:"enabled" yaml:"enabled"`
	Default bool   `json:"default" yaml:"default"`
	// hidden marks an account the credentials do not list.
	hidden bool
}

type accountListResult struct {
	Profile  string       `json:"profile" yaml:"profile"`
	Accounts []accountRow `json:"accounts" yaml:"accounts"`
}

// accountRows are the accounts the credentials list, each enabled unless
// it is disabled. The default account and the disabled accounts the list
// does not show are appended without a type, as hidden.
func accountRows(accounts []account, def, defName string, disabled []string) []accountRow {
	rows := make([]accountRow, 0, len(accounts))
	seen := map[string]bool{}
	add := func(r accountRow) {
		r.Default = r.ID == def
		r.Enabled = r.Default || !slices.Contains(disabled, r.ID)
		seen[r.ID] = true
		rows = append(rows, r)
	}
	for _, a := range accounts {
		add(accountRow{ID: a.ID, Name: a.Name, Type: a.Type})
	}
	if def != "" && !seen[def] {
		add(accountRow{ID: def, Name: defName, hidden: true})
	}
	rest := slices.Clone(disabled)
	sort.Strings(rest)
	for _, id := range rest {
		if !seen[id] {
			add(accountRow{ID: id, hidden: true})
		}
	}
	return rows
}

// accountGrid is the table of account list: * marks the default account.
func accountGrid(rows []accountRow) output.Grid {
	g := output.Grid{Headers: []string{"NAME", "TYPE", "ID", "ENABLED"}, Empty: "no accounts"}
	for _, r := range rows {
		name, enabled := r.Name, "no"
		if r.Default {
			name += " *"
		}
		if r.Enabled {
			enabled = "yes"
		}
		g.Rows = append(g.Rows, []string{name, r.Type, r.ID, enabled})
	}
	return g
}

func newAccountListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List the accounts visible to the credentials, with the default and the disabled ones marked",
		Long: `List the accounts visible to the profile's credentials (API token:
Account:Read; browser login: the account-settings.read scope). Every one is
enabled (synced, listed and searched) unless it was disabled: ENABLED says
which, and * marks the default account. The default account and the disabled
accounts the credentials do not list are shown without a type.`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return app.ErrOffline
			}
			s, err := open(cmd.Context(), rt)
			if err != nil {
				return err
			}
			accounts, err := s.client.api.listAccounts(cmd.Context())
			if err != nil {
				return err
			}
			def, defName, disabled, err := loginAccounts(rt, s.profile)
			if err != nil {
				return err
			}
			rows := accountRows(accounts, def, defName, disabled)
			enabled := 0
			for _, r := range rows {
				if r.Enabled {
					enabled++
				} else if r.hidden {
					rt.Infof("note: disabled account %s is not visible to the credentials (to forget it: polyctl cloudflare account enable %s)", r.ID, r.ID)
				}
			}
			rt.Infof("%d account(s) via cloudflare/%s, %d enabled, %d disabled", len(rows), s.profile, enabled, len(rows)-enabled)
			return rt.Render(accountListResult{Profile: s.profile, Accounts: rows}, func() output.Grid { return accountGrid(rows) })
		},
	}
}

type currentAccount struct {
	Profile string `json:"profile" yaml:"profile"`
	// AccountID is the default account ("" for a login that is not bound
	// to an account); Disabled the accounts kept out of every sync. The
	// enabled accounts are not stored: account list reads them.
	AccountID   string   `json:"account_id" yaml:"account_id"`
	AccountName string   `json:"account_name,omitempty" yaml:"account_name,omitempty"`
	Disabled    []string `json:"disabled_accounts" yaml:"disabled_accounts"`
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
	cur := currentAccount{Profile: profile, AccountID: strings.TrimSpace(a.Metadata[metaAccountID]), Disabled: disabledAccounts(a.Metadata),
		Method: a.Metadata[metaMethod], Email: a.Metadata[metaEmail]}
	sort.Strings(cur.Disabled)
	if cur.Disabled == nil {
		cur.Disabled = []string{}
	}
	if cur.AccountID != "" {
		cur.AccountName = strings.TrimSpace(a.Metadata[metaAccountName])
	}
	return cur, nil
}

func renderCurrent(rt *app.Runtime, cur currentAccount) error {
	return rt.Render(cur, func() output.Grid {
		def := "(none: every account the credentials see)"
		if cur.AccountID != "" {
			def = accountLabel(cur.AccountID, cur.AccountName)
		}
		return output.KV("profile", cur.Profile, "account", def, "disabled", strings.Join(cur.Disabled, ", "), "method", cur.Method, "email", cur.Email)
	})
}

func newAccountCurrentCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "current",
		Short: "Show the default account and the disabled accounts of the Cloudflare login",
		Long: `Show the default account and the disabled accounts of the profile's
Cloudflare login, as the local configuration holds them. Nothing is requested:
it works with --offline. The enabled accounts are every other account the
credentials see: "polyctl cloudflare account list" reads them.`,
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

// accountBook resolves and checks the accounts named to use, enable and
// disable for the login of one profile.
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

// stored reports whether the login names the account id: it is its default
// account or one of its disabled ones.
func (b *accountBook) stored(id string) bool {
	return id != "" && (id == b.cur.AccountID || slices.Contains(b.cur.Disabled, id))
}

// resolve turns the accounts named on the command line, by id or by name,
// into ids. The id of the default account or of a disabled one needs no
// request. Anything else is looked up among the accounts the credentials
// see, so that a name two of them carry is ambiguous (exit code 5)
// whatever the profile knows, and an account they do not see is not found
// (exit code 4). Credentials that cannot list their accounts leave that to
// the profile first. With --offline only the profile is asked, and what it
// does not know is taken as an id.
func (b *accountBook) resolve(ctx context.Context, args []string) ([]string, error) {
	var out []string
	for _, ref := range args {
		ref = strings.TrimSpace(ref)
		id := ref
		switch {
		case b.stored(ref):
		case b.rt.Flags.Offline:
			known, ok := knownAccount(ctx, b.rt, b.profile, ref)
			if !ok {
				if err := checkAccountID(ref); err != nil {
					return nil, fmt.Errorf("%w: account %q is not known to cloudflare/%s and cannot be looked up with --offline: pass the account id", app.ErrOffline, ref, b.profile)
				}
				known = ref
			}
			id = known
		default:
			accounts, err := b.list(ctx)
			if err != nil {
				return nil, err
			}
			known, ok := knownAccount(ctx, b.rt, b.profile, ref)
			if ok && !b.complete {
				// The list is not the whole truth: what the profile knows
				// comes first.
				id = known
				break
			}
			if id, err = matchAccount(b.profile, ref, "", accounts, b.complete); err != nil {
				var amb *app.AmbiguousError
				if errors.As(err, &amb) || !ok {
					return nil, err
				}
				id = known
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

// check verifies that the credentials see the accounts. Offline, and with
// credentials that cannot list their accounts (or whose list was read off
// the zones and does not show the account), nothing can be checked, which
// is said.
func (b *accountBook) check(ctx context.Context, ids []string) error {
	if len(ids) == 0 {
		return nil
	}
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

// accountOption labels an account for a pick, as cells: "Acme  acc1
// default". An account without a known name shows "-" in the name cell.
func accountOption(id, name, mark string) prompt.Option {
	return prompt.Option{Label: prompt.Cells(name, id, mark), Value: id}
}

// rows are the accounts of the login for a pick: the ones the credentials
// see, with the default and the disabled ones they do not. The list needs
// Cloudflare (not with --offline).
func (b *accountBook) rows(ctx context.Context) ([]accountRow, error) {
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
	return accountRows(accounts, b.cur.AccountID, b.cur.AccountName, b.cur.Disabled), nil
}

// accountOptions are account rows as the options of a pick, labelled with
// what the login says about them.
func accountOptions(rows []accountRow) []prompt.Option {
	var opts []prompt.Option
	for _, r := range rows {
		mark := ""
		switch {
		case r.Default:
			mark = "default"
		case !r.Enabled && r.hidden:
			mark = "disabled, not visible"
		case !r.Enabled:
			mark = "disabled"
		}
		opts = append(opts, accountOption(r.ID, r.Name, mark))
	}
	return opts
}

// saveAccounts stores a new default account and new disabled accounts for
// the profile's Cloudflare login. What the inventory cached of the
// accounts that are disabled now is dropped. The cached sets of the login
// are made due when an account was enabled again, so that the next read
// syncs it; an account that was only disabled leaves them as they are, its
// rows being gone, and so does a changed default account, which changes
// nothing of what the login covers.
func saveAccounts(ctx context.Context, rt *app.Runtime, profile string, def account, disabled []string) error {
	cfg, err := rt.ReloadConfig()
	if err != nil {
		return err
	}
	a, err := cfg.Account(profile, platform.Cloudflare)
	if err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	if a.Metadata == nil {
		a.Metadata = map[string]string{}
	}
	before := disabledAccounts(a.Metadata)
	setAccounts(a.Metadata, def, disabled)
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
	after := disabledAccounts(a.Metadata)
	var off []string
	for _, id := range after {
		if !slices.Contains(before, id) {
			off = append(off, id)
		}
	}
	if err := forgetDisabled(ctx, rt, db, profile, off); err != nil {
		return err
	}
	for _, id := range before {
		if !slices.Contains(after, id) {
			return db.Expire(ctx, platform.Cloudflare, profile)
		}
	}
	return nil
}

// forgetDisabled drops from the inventory of a profile what it holds of
// the disabled accounts: their trees, and every other zone (with its
// records) and bucket row that names one of them in its data. Those other
// rows are the ones stored before the rows had their account as parent,
// which the purge of a tree does not reach. A row that names no account at
// all is of the default account, which is never disabled.
func forgetDisabled(ctx context.Context, rt *app.Runtime, db *inventory.DB, profile string, disabled []string) error {
	if len(disabled) == 0 {
		return nil
	}
	for _, id := range disabled {
		if err := db.PurgeTree(ctx, platform.Cloudflare, profile, id); err != nil {
			return err
		}
	}
	gone := func(account string) bool { return account != "" && slices.Contains(disabled, account) }
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

// accountDiff tells the accounts that def and disabled disable (off) and
// enable again (on) against cur, each sorted.
func accountDiff(cur currentAccount, def string, disabled []string) (off, on []string) {
	for _, id := range disabled {
		if id != def && !slices.Contains(cur.Disabled, id) && !slices.Contains(off, id) {
			off = append(off, id)
		}
	}
	for _, id := range cur.Disabled {
		if id == def || !slices.Contains(disabled, id) {
			on = append(on, id)
		}
	}
	sort.Strings(off)
	sort.Strings(on)
	return off, on
}

// finish is the common end of enable and disable: nothing to do when def
// and disabled are what the login holds, the change report with --dry-run
// (nothing is saved, purged or made due), and apply otherwise.
func (b *accountBook) finish(ctx context.Context, def string, disabled []string) error {
	off, on := accountDiff(b.cur, def, disabled)
	if len(off)+len(on) == 0 && def == b.cur.AccountID {
		return app.NothingToDof("the enabled accounts and the default account of cloudflare/%s are unchanged", b.profile)
	}
	var changes []platform.Change
	for _, id := range off {
		changes = append(changes, app.ResourceChange("account", id, platform.Updated, "disabled"))
	}
	for _, id := range on {
		changes = append(changes, app.ResourceChange("account", id, platform.Updated, "enabled"))
	}
	if def != b.cur.AccountID {
		changes = append(changes, app.ResourceChange("account", def, platform.Updated, "default"))
	}
	if done, err := b.rt.WouldWrite(platform.Target{Platform: platform.Cloudflare, Profile: b.profile}, changes...); done || err != nil {
		return err
	}
	return b.apply(ctx, def, disabled)
}

// pick is enable and disable without arguments on a terminal: one list of
// every account the credentials see, and of the default and the disabled
// ones they do not, in which the enabled ones are ticked. What is ticked at
// the end is enabled and the rest disabled; a default account that was
// unticked is replaced as newDefault says. Credentials that cannot list
// their accounts have nothing to offer: the accounts are named by id then.
func (b *accountBook) pick(ctx context.Context, newDefault string) error {
	rows, err := b.rows(ctx)
	if err != nil {
		return err
	}
	if len(b.visible) == 0 {
		return app.UsageErrf("the credentials of cloudflare/%s cannot list accounts: pass the account id", b.profile)
	}
	var opts []prompt.Option
	var ticked []string
	for _, r := range rows {
		mark := ""
		switch {
		case r.Default:
			mark = "default"
		case r.hidden:
			mark = "not visible"
		}
		opts = append(opts, accountOption(r.ID, r.Name, mark))
		if r.Enabled {
			ticked = append(ticked, r.ID)
		}
	}
	keep, err := b.rt.ChooseMany(app.Choice{Title: fmt.Sprintf("Enabled accounts of cloudflare/%s (ticked: synced and searched)", b.profile),
		Options: opts, Selected: ticked, Arg: "<account>", What: "account visible to cloudflare/" + b.profile})
	if err != nil {
		return err
	}
	// An account the credentials do not list cannot become the default
	// here: ticking it only forgets that it was disabled.
	var disabled, rest []string
	for _, r := range rows {
		switch {
		case !slices.Contains(keep, r.ID):
			disabled = append(disabled, r.ID)
		case !r.hidden || r.Default:
			rest = append(rest, r.ID)
		}
	}
	sort.Strings(disabled)
	sort.Strings(rest)
	def, err := b.newDefault(ctx, disabled, rest, b.complete, newDefault)
	if err != nil {
		return err
	}
	return b.finish(ctx, def, disabled)
}

// apply stores the default account and the disabled accounts a command
// arrived at, says what changed against the login as it was and prints it
// as account current does.
func (b *accountBook) apply(ctx context.Context, def string, disabled []string) error {
	off, on := accountDiff(b.cur, def, disabled)
	acc := account{ID: def}
	if def != "" {
		acc.Name = b.name(ctx, def)
	}
	if err := saveAccounts(ctx, b.rt, b.profile, acc, disabled); err != nil {
		return err
	}
	if len(off) > 0 {
		b.rt.Infof("disabled %s for cloudflare/%s", strings.Join(off, ", "), b.profile)
	}
	if len(on) > 0 {
		b.rt.Infof("enabled %s for cloudflare/%s", strings.Join(on, ", "), b.profile)
	}
	if def != b.cur.AccountID {
		b.rt.Infof("account %s is now the default account of cloudflare/%s", def, b.profile)
	}
	cur, err := currentOf(b.rt, b.profile)
	if err != nil {
		return err
	}
	return renderCurrent(b.rt, cur)
}

func newAccountUseCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "use <account>",
		Short: "Make an account the default account of the Cloudflare login",
		Long: `Make <account>, an account id or name, the default account of the profile's
Cloudflare login: the one new zones are created in and commands work on when
--account names no other. A disabled account that becomes the default is
enabled again. The credentials must see it (not checked with --offline, nor
when they cannot list their accounts). On a terminal, without <account> the
visible accounts are offered.

Nothing else changes: the login keeps working on every account its
credentials see, also a login that had no default account before. Only the
local configuration is written; the cached inventory is synced again on its
next use when the account was disabled.`,
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
				rows, err := b.rows(ctx)
				if err != nil {
					return err
				}
				if rt.Interactive() && len(b.visible) == 0 {
					return app.UsageErrf("the credentials of cloudflare/%s cannot list accounts: pass the account id", b.profile)
				}
				if id, err = rt.Choose(app.Choice{Title: "Default account", Options: accountOptions(rows), Default: b.cur.AccountID, Arg: "<account>", What: "account visible to cloudflare/" + b.profile}); err != nil {
					return err
				}
			}
			if id == b.cur.AccountID {
				rt.Infof("account %s is already the default account of cloudflare/%s", id, b.profile)
				return renderCurrent(rt, b.cur)
			}
			if err := b.check(ctx, []string{id}); err != nil {
				return err
			}
			var disabled []string
			for _, d := range b.cur.Disabled {
				if d != id {
					disabled = append(disabled, d)
				}
			}
			if len(disabled) != len(b.cur.Disabled) {
				rt.Infof("account %s was disabled and is enabled again", id)
			}
			// What apply reports is the new default alone: that the account
			// is enabled again was said.
			b.cur.Disabled = disabled
			return b.apply(ctx, id, disabled)
		},
	}
	app.MarkNoDryRun(cmd)
	return cmd
}

// formerName says, in the help of a hidden command, which command it is
// the former name of.
func formerName(cmd *cobra.Command, now string) {
	if cmd.Hidden {
		cmd.Long = fmt.Sprintf("The former name of \"polyctl cloudflare account %s\"; it does the same.\n\n", now) + cmd.Long
	}
}

// newAccountEnableCmd builds enable, and add, the name it had while a
// login held a selection, kept hidden.
func newAccountEnableCmd(rt *app.Runtime, name string, hidden bool) *cobra.Command {
	var newDefault string
	cmd := &cobra.Command{
		Use:    name + " <account>...",
		Hidden: hidden,
		Short:  "Enable accounts of the Cloudflare login again, after they were disabled",
		Long: `Enable accounts, by id or name, of the profile's Cloudflare login that were
disabled: the inventory, name lookups and domain routing cover them again.
Nothing needs to be enabled otherwise: every account the credentials see is
enabled unless it was disabled.

An account that is enabled already is left as it is (exit code 0, nothing is
written). One that is neither disabled nor visible to the credentials is not
found (exit code 4): name it with --account, or make it the default account
with "polyctl cloudflare account use". A disabled account that is no longer
visible is forgotten.

On a terminal, without <account> every account the credentials see is listed
with the enabled ones ticked, as "polyctl cloudflare account disable" does:
what is ticked at the end is enabled, the rest is disabled. The list needs
Cloudflare (not with --offline) and credentials that can list their accounts.

Only the local configuration changes; the cached inventory of the login is
synced again on its next use. --dry-run reports what would change and writes
nothing. Works with --offline for accounts named by id.`,
		Args: app.RangeArgsOrInteractive(rt, 1, 100, nil),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			b, err := openAccountBook(rt)
			if err != nil {
				return err
			}
			ids, err := b.resolve(ctx, args)
			if err != nil {
				if errors.Is(err, platform.ErrNotFound) {
					return fmt.Errorf("%w: nothing to enable (name the account with --account, or make it the default: polyctl cloudflare account use <id>)", err)
				}
				return err
			}
			if len(ids) == 0 {
				return b.pick(ctx, newDefault)
			}
			var disabled []string
			for _, d := range b.cur.Disabled {
				if !slices.Contains(ids, d) {
					disabled = append(disabled, d)
				}
			}
			if len(disabled) == len(b.cur.Disabled) {
				return app.NothingToDof("%s: already enabled for cloudflare/%s", strings.Join(ids, ", "), b.profile)
			}
			return b.finish(ctx, b.cur.AccountID, disabled)
		},
	}
	cmd.Flags().StringVar(&newDefault, "default", "", "the enabled account, by id or name, that becomes the default when the default account is unticked in the list (enabling the accounts named never needs it)")
	formerName(cmd, "enable")
	return cmd
}

// newDefault tells the default account of a login whose disabled accounts
// become disabled: the one it has, unless that is among them or --default
// (ref) names another. rest are the accounts that stay enabled, as far as
// the credentials tell, and complete says they tell all of them. A default
// that is disabled is replaced by --default, by the only account left or
// by the answer on a terminal, and is a usage error otherwise. Disabling
// every account is a usage error too, also on a login without a default
// account.
func (b *accountBook) newDefault(ctx context.Context, disabled, rest []string, complete bool, ref string) (string, error) {
	def := b.cur.AccountID
	ref = strings.TrimSpace(ref)
	gone := def != "" && slices.Contains(disabled, def)
	needDefault := func() error {
		if len(rest) == 0 {
			return app.UsageErrf("%s is the default account of cloudflare/%s: pass --default <id> to name the one that replaces it", def, b.profile)
		}
		return app.UsageErrf("%s is the default account of cloudflare/%s: pass --default <id> to name the one that replaces it (one of: %s)", def, b.profile, strings.Join(rest, ", "))
	}
	switch {
	case complete && len(rest) == 0:
		return "", app.UsageErrf("this would disable every account of cloudflare/%s; a login needs one (to drop the login: polyctl auth logout cloudflare --profile %s)", b.profile, b.profile)
	case ref != "":
		picked, err := b.resolve(ctx, []string{ref})
		if err != nil {
			return "", err
		}
		// A list that is not complete does not tell every enabled account:
		// any account that is not disabled is taken then.
		if slices.Contains(disabled, picked[0]) || (complete && !slices.Contains(rest, picked[0])) {
			return "", app.UsageErrf("--default %s: not one of the accounts that stay enabled (%s)", ref, strings.Join(rest, ", "))
		}
		return picked[0], nil
	case gone && len(rest) == 0:
		return "", needDefault()
	case gone && len(rest) == 1 && complete && b.rt.Interactive():
		return rest[0], nil
	case gone:
		var opts []prompt.Option
		for _, id := range rest {
			opts = append(opts, accountOption(id, b.localName(ctx, id), ""))
		}
		return b.rt.Choose(app.Choice{Title: "New default account", Options: opts, Arg: "--default", Missing: needDefault})
	}
	return def, nil
}

// newAccountDisableCmd builds disable, and remove, the name it had while a
// login held a selection, kept hidden.
func newAccountDisableCmd(rt *app.Runtime, name string, hidden bool) *cobra.Command {
	var newDefault string
	cmd := &cobra.Command{
		Use:    name + " <account>...",
		Hidden: hidden,
		Short:  "Disable accounts of the Cloudflare login: keep them out of every sync, list and lookup",
		Long: `Disable accounts, by id or name, of the profile's Cloudflare login: the ones
that are certainly not used. Nothing at Cloudflare changes and the credentials
stay as they are: the accounts are no longer synced, listed or searched, and
what the inventory cached of them (zones, their records, R2 buckets) is
dropped. "polyctl cloudflare account enable" takes them back, and --account
still names one for a single call.

An account that is disabled already is left as it is (exit code 0, nothing is
written). One the credentials do not see is not found (exit code 4); when
they cannot list their accounts an id is taken as it is, which is said.

The default account can be disabled only together with --default <account>,
which names the enabled account that becomes the default (on a terminal it is
asked); without it this is a usage error (exit code 2), as is disabling every
account (log the login out with "polyctl auth logout cloudflare" instead).

On a terminal, without <account> every account the credentials see is listed
with the enabled ones ticked, as "polyctl cloudflare account enable" does:
what is ticked at the end is enabled, the rest is disabled, and a default
account that was unticked is replaced as above. The list needs Cloudflare
(not with --offline) and credentials that can list their accounts.

No confirmation is asked: only the local configuration and a cache that the
next sync rebuilds change. --dry-run reports what would change and writes
nothing. Works with --offline for the accounts named; a name is then one
the profile knows (that of the default account, or of an account with a
cached zone), and the accounts are not checked against what the credentials
see.`,
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
				return b.pick(ctx, newDefault)
			}
			disabled := slices.Clone(b.cur.Disabled)
			var off []string
			for _, id := range ids {
				if !slices.Contains(disabled, id) {
					off = append(off, id)
					disabled = append(disabled, id)
				}
			}
			if len(off) == 0 {
				return app.NothingToDof("%s: already disabled for cloudflare/%s", strings.Join(ids, ", "), b.profile)
			}
			// The default account is known to the login; the others are
			// checked against what the credentials see.
			var check []string
			for _, id := range off {
				if id != b.cur.AccountID {
					check = append(check, id)
				}
			}
			if err := b.check(ctx, check); err != nil {
				return err
			}
			// rest are the accounts that stay enabled, as far as the
			// credentials tell.
			var rest []string
			complete := false
			if !rt.Flags.Offline {
				accounts, err := b.list(ctx)
				if err != nil {
					return err
				}
				complete = b.complete && len(accounts) > 0
				for _, a := range accounts {
					if !slices.Contains(disabled, a.ID) {
						rest = append(rest, a.ID)
					}
				}
				sort.Strings(rest)
			}
			def, err := b.newDefault(ctx, disabled, rest, complete, newDefault)
			if err != nil {
				return err
			}
			return b.finish(ctx, def, disabled)
		},
	}
	cmd.Flags().StringVar(&newDefault, "default", "", "the enabled account, by id or name, that becomes the default when the default account is disabled")
	formerName(cmd, "disable")
	return cmd
}
