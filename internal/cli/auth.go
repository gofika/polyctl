package cli

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

func newAuthCmd(rt *app.Runtime) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "auth",
		Short: "Manage profiles and their platform accounts",
	}
	cmd.AddCommand(newAuthLoginCmd(rt), newAuthListCmd(rt), newAuthUseCmd(rt), newAuthStatusCmd(rt), newAuthLogoutCmd(rt),
		newAuthRenameCmd(rt), newAuthManageCmd(rt))
	return cmd
}

func loginHelp() string {
	var b strings.Builder
	indent := "\n" + strings.Repeat(" ", 14)
	for _, p := range platform.Providers() {
		fmt.Fprintf(&b, "  %-11s %s\n", p.ID(), strings.ReplaceAll(strings.TrimSpace(p.LoginHelp()), "\n", indent))
	}
	return b.String()
}

// secretOptionKeys are --set keys whose value is a credential. Passing one
// on the command line exposes it to process listings and shell history, so
// polyctl warns and points at the "-" form, which reads the value from
// stdin instead (any key may use that form). GoDaddy's legacy "api_key" is
// not listed: it is the public half of the pair, and the documented
// scripted form is --set api_key=<key> --set api_secret=-.
var secretOptionKeys = map[string]bool{
	"token":             true,
	"api_secret":        true,
	"client_secret":     true,
	"access_key_secret": true,
	"secret_access_key": true,
	"session_token":     true,
	"password":          true,
}

func newAuthLoginCmd(rt *app.Runtime) *cobra.Command {
	var sets []string
	cmd := &cobra.Command{
		Use:   "login <platform>",
		Short: "Authenticate with a platform and add the account to a profile",
		Long: "Authenticate with a platform and save the credentials in the system keyring\n" +
			"(or a 0600 file when no keyring is available).\n\n" +
			"A profile holds one account per platform, so a single profile can cover every\n" +
			"platform a project uses. The account is added to --profile, or to the current\n" +
			"profile, or to a profile named \"default\" when no profile is current (or the\n" +
			"current one no longer exists). When the platform is already configured in\n" +
			"another profile only, --profile is required.\n\n" +
			"In the interactive flow (a terminal, without --non-interactive) the platform\n" +
			"may be left out: it is then chosen from a list, and the login asks for what\n" +
			"it needs. Ctrl-C, or Ctrl-D on an empty line, leaves a question of the login\n" +
			"flow: nothing is stored then. Browser-based flows open the default browser;\n" +
			"--no-browser prints the URL instead.\n\n" +
			"In the non-interactive flow (no terminal on stdin and stderr,\n" +
			"--non-interactive or POLYCTL_NON_INTERACTIVE=1) nothing is asked, no browser\n" +
			"is opened and nothing is read from a terminal: the platform is required,\n" +
			"values come from --set and the documented environment variables, and a value\n" +
			"or choice that is still missing is a usage error (exit code 2) naming the\n" +
			"--set key to pass.\n\n" +
			"Login flows:\n" + loginHelp() +
			"\nPlatform-specific options are passed with --set key=value (see each platform's\n" +
			"section in the README); a key the platform does not know is a usage error\n" +
			"listing the valid ones. Any option may be given as --set key=- to read its\n" +
			"value from stdin instead of argv, which secrets (token, api_secret,\n" +
			"client_secret, ...) should: each one reads one line, in the order given.",
		Args:              oneArgOrInteractive(rt, errPlatformRequired),
		ValidArgsFunction: completePlatforms,
		RunE: quietAbort(rt, func(cmd *cobra.Command, args []string) error {
			var id platform.ID
			var err error
			if len(args) == 1 {
				if id, err = platform.Parse(args[0]); err != nil {
					return usageErr("%v", err)
				}
			}
			if rt.Flags.Offline {
				// Every login flow verifies against the platform: fail
				// before asking for anything or reading a secret.
				return app.ErrOffline
			}
			if len(args) == 0 {
				if id, err = pickPlatform(rt); err != nil {
					return err
				}
			}
			prov, err := platform.Get(id)
			if err != nil {
				return err
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			name := rt.Flags.Profile
			if name == "" {
				name = cfg.CurrentProfile
				if _, ok := cfg.Profiles[name]; name != "" && !ok {
					// A stale current_profile (hand-edited config) must not
					// quietly bring a profile of that name into being.
					rt.Infof("note: the current profile %q does not exist; using profile %q", name, config.DefaultProfile)
					name = ""
				}
			}
			if name == "" {
				name = config.DefaultProfile
			}
			if err := validateProfileName(name); err != nil {
				return usageErr("%v", err)
			}
			opts := map[string]string{}
			for _, s := range sets {
				k, v, ok := strings.Cut(s, "=")
				if !ok {
					return usageErr("--set expects key=value, got %q", s)
				}
				// Before anything is read or asked: an option the platform
				// does not know must not be dropped silently, or the login
				// would go on with other credentials than the ones named.
				if err := platform.CheckLoginOption(prov, k); err != nil {
					return usageErr("%v", err)
				}
				switch {
				case v == "-":
					// One line of stdin per key, in the order given.
					if v, err = rt.StdinValue(cmd.Context(), k, secretOptionKeys[k]); err != nil {
						return err
					}
				case secretOptionKeys[k] && v != "":
					rt.Infof("warning: --set %s=... is visible in process listings and shell history; pass %s=- to read it from stdin", k, k)
				}
				opts[k] = v
			}
			return loginAccount(cmd.Context(), rt, prov, name, rt.Flags.Profile != "", opts)
		}),
	}
	cmd.Flags().StringArrayVar(&sets, "set", nil, "platform-specific login option key=value (repeatable; key=- reads the value, one line, from stdin)")
	addNoBrowserFlag(rt, cmd)
	return cmd
}

// addNoBrowserFlag adds --no-browser to a command that can run a login
// flow. Only auth login and auth manage do, so the flag is theirs and not a
// global one.
func addNoBrowserFlag(rt *app.Runtime, cmd *cobra.Command) {
	cmd.Flags().BoolVar(&rt.Flags.NoBrowser, "no-browser", false, "do not open a browser during login; print the URL instead")
}

// validateProfileName rejects names that cannot be a profile: the name is
// part of the credential key and of command lines.
func validateProfileName(name string) error {
	if name == "" {
		return errors.New("profile name must not be empty")
	}
	if strings.ContainsAny(name, " /\\\t") {
		return fmt.Errorf("profile name %q must not contain spaces or slashes", name)
	}
	return nil
}

// loginAccount runs a platform's login flow and stores the account in the
// profile name, creating the profile when needed. explicit says the user
// named the profile; without it the login refuses to add a second account
// next to one that lives in another profile only.
func loginAccount(ctx context.Context, rt *app.Runtime, prov platform.Provider, name string, explicit bool, opts map[string]string) error {
	if rt.Flags.Offline {
		return app.ErrOffline // every login flow verifies against the platform
	}
	id := prov.ID()
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	prof := cfg.Profiles[name]
	var acct *config.Account
	if prof != nil {
		acct = prof.Platforms[id]
	}
	var existing map[string]string
	if acct == nil && !explicit {
		// Without --profile, do not quietly create a second account
		// next to one that lives in another profile: the user most
		// likely wants to re-authenticate that one.
		if others := cfg.ProfilesFor(id); len(others) > 0 {
			return usageErr("%s is already configured in profile(s) %s; pass --profile <name> to re-authenticate one of them, or --profile %s to add another %s account to this profile",
				id, strings.Join(others, ", "), name, id)
		}
	}
	if acct != nil {
		existing = acct.Metadata
		rt.Infof("re-authenticating the %s account of profile %q", id, name)
	}
	res, err := prov.Login(ctx, rt.LoginInput(name, opts, existing))
	if err != nil {
		return err
	}
	store, err := rt.Creds()
	if err != nil {
		return err
	}
	// The login flow can take minutes (browser, device code). Work on the
	// config as it is now, so that what another polyctl process saved in
	// the meantime is kept and the save below is not refused as stale.
	if fresh, err := rt.ReloadConfig(); err == nil {
		cfg = fresh
		prof, acct = cfg.Profiles[name], nil
		if prof != nil {
			acct = prof.Platforms[id]
		}
	} else {
		rt.Verbosef("reload config: %v", err)
	}
	key := creds.Key(name, string(id))
	isNew := acct == nil
	if err := store.Set(key, res.Secret); err != nil {
		if isNew {
			// Set may fail after writing the primary backend; an
			// account missing from the config could never be removed.
			_ = store.Delete(key)
		}
		return fmt.Errorf("store credentials: %w", err)
	}
	// What a failed save puts back, so that the config in memory keeps
	// matching the file: a later save must not write this login after all.
	newProfile, prevCurrent := prof == nil, cfg.CurrentProfile
	var before config.Account
	if !isNew {
		before = *acct
	}
	now := time.Now()
	if newProfile {
		prof = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
		cfg.Profiles[name] = prof
	}
	if isNew {
		acct = &config.Account{CreatedAt: now}
		prof.Platforms[id] = acct
	}
	if acct.LegacySecret && store.Has(acct.LegacySecretBackend()) {
		// The secret now lives under the profile/platform key. When
		// the backend holding the old entry is out of reach, or the
		// removal fails, the mark stays and a later run cleans up.
		if err := store.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
			rt.Verbosef("remove legacy credentials of profile %q: %v", name, err)
		} else {
			acct.ClearLegacySecret()
		}
	}
	acct.Metadata = res.Metadata
	// While the mark stays, this keeps the backend of the old entry on
	// record: it is the one that has to be within reach to clean up.
	acct.SetCredentialBackend(store.Name())
	acct.UpdatedAt = now
	if _, ok := cfg.Profiles[cfg.CurrentProfile]; !ok {
		// No current profile, or one that does not exist.
		cfg.CurrentProfile = name
	}
	if err := cfg.Save(); err != nil {
		// A new account that is not in the config cannot be removed
		// with `auth logout`, so do not leave its secret behind.
		kept := "kept"
		if isNew {
			if derr := store.Delete(key); derr == nil {
				kept = "removed"
			}
			delete(prof.Platforms, id)
			if newProfile {
				delete(cfg.Profiles, name)
			}
		} else {
			*acct = before
		}
		cfg.CurrentProfile = prevCurrent
		return fmt.Errorf("save config: %w (stored %s credentials for profile %q were %s)", err, id, name, kept)
	}
	label := res.Label
	if label != "" {
		label = " (" + label + ")"
	}
	rt.Infof("logged in to %s in profile %q%s; credentials stored in %s", prov.DisplayName(), name, label, store.Name())
	return nil
}

// profileRow is one row of `auth list`: an account, or a profile without
// accounts, which has no platform.
type profileRow struct {
	Name      string            `json:"name" yaml:"name"`
	Platform  platform.ID       `json:"platform,omitempty" yaml:"platform,omitempty"`
	Current   bool              `json:"current" yaml:"current"`
	Backend   string            `json:"credential_backend,omitempty" yaml:"credential_backend,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	UpdatedAt *time.Time        `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// noAccounts stands in for the account of a profile that has none.
const noAccounts = "(no accounts)"

func profileRows(cfg *config.Config) []profileRow {
	var rows []profileRow
	for _, n := range cfg.ProfileNames() {
		prof := cfg.Profiles[n]
		current := n == cfg.CurrentProfile
		if len(prof.Platforms) == 0 {
			// Listed too: it can be current, renamed, removed and logged in to.
			rows = append(rows, profileRow{Name: n, Current: current})
			continue
		}
		for _, id := range prof.PlatformIDs() {
			a := prof.Platforms[id]
			// Only a real timestamp: a pointer to the zero time is left out
			// of YAML but printed by JSON as year 1.
			var updated *time.Time
			if !a.UpdatedAt.IsZero() {
				u := a.UpdatedAt
				updated = &u
			}
			rows = append(rows, profileRow{Name: n, Platform: id, Current: current, Backend: a.CredentialBackend, Metadata: a.Metadata, UpdatedAt: updated})
		}
	}
	return rows
}

func metaSummary(m map[string]string) string {
	keys := []string{"account", "account_id", "email", "user", "username", "project", "region", "method"}
	var parts []string
	for _, k := range keys {
		if v, ok := m[k]; ok && v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	return strings.Join(parts, " ")
}

func newAuthListCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "list",
		Short: "List every profile and its platform accounts",
		Long: "List every profile and its platform accounts, one row per account. A profile\n" +
			"without accounts is listed too, as one row without a platform.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			rows := profileRows(cfg)
			return rt.Render(rows, func() output.Grid { return profileGrid(rows) })
		},
	}
}

// profileGrid is the table of `auth list`.
func profileGrid(rows []profileRow) output.Grid {
	g := output.Grid{Headers: []string{"", "PROFILE", "PLATFORM", "STORE", "DETAILS"}, Empty: "no accounts configured; run `polyctl auth login <platform> [--profile <name>]`"}
	for _, r := range rows {
		cur := ""
		if r.Current {
			cur = "*"
		}
		if r.Platform == "" {
			g.Rows = append(g.Rows, []string{cur, r.Name, "", "", noAccounts})
			continue
		}
		g.Rows = append(g.Rows, []string{cur, r.Name, string(r.Platform), r.Backend, metaSummary(r.Metadata)})
	}
	return g
}

func newAuthUseCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "use <profile>",
		Short: "Set the current profile",
		Long: "Set the current profile. In the interactive flow (a terminal, without\n" +
			"--non-interactive) the profile may be left out: it is then chosen from a\n" +
			"list. In the non-interactive flow the profile is required (usage error, exit\n" +
			"code 2).",
		Args: oneArgOrInteractive(rt, errProfileRequired),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, tc string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeProfiles(rt)(cmd, args, tc)
		},
		RunE: quietAbort(rt, func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				name, err := pickProfile(rt, "Switch to which profile?")
				if err != nil {
					return err
				}
				args = []string{name}
			}
			return useProfile(rt, args[0])
		}),
	}
}

// useProfile makes a profile the current one.
func useProfile(rt *app.Runtime, name string) error {
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	if _, err := cfg.Profile(name); err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	prev := cfg.CurrentProfile
	cfg.CurrentProfile = name
	if err := cfg.Save(); err != nil {
		cfg.CurrentProfile = prev
		return fmt.Errorf("save config: %w", err)
	}
	rt.Infof("current profile set to %q", name)
	return nil
}

type statusRow struct {
	Name     string      `json:"name" yaml:"name"`
	Platform platform.ID `json:"platform" yaml:"platform"`
	Current  bool        `json:"current" yaml:"current"`
	OK       bool        `json:"ok" yaml:"ok"`
	// Verified is false under --offline: the credentials are present but
	// were not checked against the platform, and Identity is empty.
	Verified bool               `json:"verified" yaml:"verified"`
	Identity *platform.Identity `json:"identity,omitempty" yaml:"identity,omitempty"`
	Error    string             `json:"error,omitempty" yaml:"error,omitempty"`
}

func newAuthStatusCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Verify stored credentials (every account, or those of --profile)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			refs, err := rt.Accounts()
			if err != nil {
				return err
			}
			rows, failed, err := verifyAccounts(cmd.Context(), rt, refs)
			if err != nil {
				return err
			}
			if err := rt.Render(rows, func() output.Grid { return statusGrid(rows) }); err != nil {
				return err
			}
			if failed {
				return errVerificationFailed()
			}
			return nil
		},
	}
}

func errVerificationFailed() error {
	return fmt.Errorf("%w: one or more accounts failed verification", platform.ErrUnauthorized)
}

// verifyAccounts checks the credentials of each account and reports whether
// any of them failed.
func verifyAccounts(ctx context.Context, rt *app.Runtime, refs []config.AccountRef) (rows []statusRow, failed bool, err error) {
	cfg, err := rt.Config()
	if err != nil {
		return nil, false, err
	}
	for _, ref := range refs {
		row := statusRow{Name: ref.Profile, Platform: ref.Platform, Current: ref.Profile == cfg.CurrentProfile}
		id, err := verifyAccount(ctx, rt, ref)
		if err != nil {
			row.Error = err.Error()
			failed = true
		} else {
			row.OK = true
			row.Verified = !rt.Flags.Offline
			row.Identity = id
		}
		rows = append(rows, row)
	}
	return rows, failed, nil
}

// statusGrid is the table of `auth status`.
func statusGrid(rows []statusRow) output.Grid {
	g := output.Grid{Headers: []string{"", "PROFILE", "PLATFORM", "STATUS", "IDENTITY"}, Empty: "no accounts configured"}
	for _, r := range rows {
		cur := ""
		if r.Current {
			cur = "*"
		}
		st, id := "ok", ""
		switch {
		case !r.OK:
			st, id = "FAILED", r.Error
		case !r.Verified:
			id = "present (not verified)"
		case r.Identity != nil:
			id = identitySummary(r.Identity)
		}
		g.Rows = append(g.Rows, []string{cur, r.Name, string(r.Platform), st, id})
	}
	return g
}

func identitySummary(id *platform.Identity) string {
	var parts []string
	if id.Account != "" {
		parts = append(parts, id.Account)
	}
	if id.User != "" {
		parts = append(parts, id.User)
	}
	for _, k := range []string{"email", "name", "arn", "project"} {
		if v := id.Extra[k]; v != "" {
			parts = append(parts, v)
		}
	}
	return strings.Join(parts, " ")
}

func verifyAccount(ctx context.Context, rt *app.Runtime, ref config.AccountRef) (*platform.Identity, error) {
	if rt.Flags.Offline {
		if _, err := rt.LoadProfile(ref.Profile, ref.Platform); err != nil {
			return nil, err
		}
		return nil, nil
	}
	c, _, err := rt.Open(ctx, ref.Profile, ref.Platform)
	if err != nil {
		return nil, err
	}
	return c.Verify(ctx)
}

func newAuthLogoutCmd(rt *app.Runtime) *cobra.Command {
	var keepInventory bool
	cmd := &cobra.Command{
		Use:   "logout [platform] --profile <name>",
		Short: "Remove a profile, or one platform account of it, with the stored credentials",
		Long: "Without a platform, remove the whole profile: every account in it and their\n" +
			"stored credentials. With a platform, remove only that account; the profile is\n" +
			"removed too when it was its last one.\n\n" +
			"In the interactive flow (a terminal, without --non-interactive) --profile may\n" +
			"be left out: the accounts to remove are then chosen from a list (only those on\n" +
			"the platform, when one is given) and confirmed before anything is removed;\n" +
			"--yes skips the confirmations. In the non-interactive flow --profile is\n" +
			"required (usage error, exit code 2); naming the profile is the confirmation,\n" +
			"so nothing is asked.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completePlatforms,
		RunE: quietAbort(rt, func(cmd *cobra.Command, args []string) error {
			name := rt.Flags.Profile
			if name == "" {
				if !rt.Interactive() {
					return usageErr("--profile <name> is required")
				}
				var only platform.ID
				if len(args) == 1 {
					id, err := platform.Parse(args[0])
					if err != nil {
						return usageErr("%v", err)
					}
					only = id
				}
				keep := keepUnset
				if cmd.Flags().Changed("keep-inventory") {
					keep = keepNo
					if keepInventory {
						keep = keepYes
					}
				}
				return removeInteractive(cmd.Context(), rt, only, keep)
			}
			var cfg *config.Config
			var ids []platform.ID
			// resolve names what to remove in the config as loaded now.
			resolve := func() error {
				var err error
				if cfg, err = rt.Config(); err != nil {
					return err
				}
				prof, err := cfg.Profile(name)
				if err != nil {
					return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
				}
				ids = prof.PlatformIDs()
				if len(args) == 1 {
					id, err := platform.Parse(args[0])
					if err != nil {
						return usageErr("%v", err)
					}
					if _, ok := prof.Platforms[id]; !ok {
						return fmt.Errorf("%w: profile %q has no %s account", platform.ErrNotFound, name, id)
					}
					ids = []platform.ID{id}
				}
				return nil
			}
			if err := resolve(); err != nil {
				return err
			}
			if _, err := rt.Creds(); err != nil {
				return err
			}
			if errors.Is(cfg.Unchanged(), config.ErrChanged) {
				// Another polyctl process saved the config since this one
				// started (two commands run together after an upgrade:
				// the other one moved the secrets). Remove from the file
				// as it is now.
				if _, err := rt.ReloadConfig(); err != nil {
					return err
				}
				if err := resolve(); err != nil {
					return err
				}
			}
			if len(ids) == 0 {
				if err := removeEmptyProfile(rt, name); err != nil {
					return err
				}
			}
			for _, id := range ids {
				if err := removeAccount(cmd.Context(), rt, config.AccountRef{Profile: name, Platform: id}, keepInventory); err != nil {
					return err
				}
			}
			_, kept := cfg.Profiles[name]
			removedProfile := !kept
			if removedProfile {
				rt.Infof("profile %q removed", name)
			} else {
				rt.Infof("%s account removed from profile %q", ids[0], name)
			}
			return nil
		}),
	}
	cmd.Flags().BoolVar(&keepInventory, "keep-inventory", false, "keep the cached resources of the removed accounts in the local inventory")
	return cmd
}

// removeEmptyProfile removes a profile without accounts (hand-edited config).
func removeEmptyProfile(rt *app.Runtime, name string) error {
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	prof, had := cfg.Profiles[name]
	prevCurrent := cfg.CurrentProfile
	delete(cfg.Profiles, name)
	if cfg.CurrentProfile == name {
		cfg.CurrentProfile = ""
	}
	if err := cfg.Save(); err != nil {
		if had {
			cfg.Profiles[name] = prof
		}
		cfg.CurrentProfile = prevCurrent
		return fmt.Errorf("save config: %w", err)
	}
	return nil
}

// removeAccount removes one account: its cached resources (unless
// keepInventory), its secret and its config entry, and the profile itself
// when that was its last account. The config is saved before returning.
// Nothing is removed when the config file is no longer the one in memory:
// the save at the end would be refused, after the steps that cannot be
// undone.
func removeAccount(ctx context.Context, rt *app.Runtime, ref config.AccountRef, keepInventory bool) error {
	name, id := ref.Profile, ref.Platform
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	prof, err := cfg.Profile(name)
	if err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	a, ok := prof.Platforms[id]
	if !ok {
		return fmt.Errorf("%w: profile %q has no %s account", platform.ErrNotFound, name, id)
	}
	store, err := rt.Creds()
	if err != nil {
		return err
	}
	if err := cfg.Unchanged(); err != nil {
		if errors.Is(err, config.ErrChanged) {
			return fmt.Errorf("%w; nothing was removed, run the command again", err)
		}
		return fmt.Errorf("read config: %w", err)
	}
	// Order matters: the inventory first, the secret next and
	// the config entry right after it, so that as little as possible can
	// fail between removing the secret and the account that names it.
	if !keepInventory {
		db, err := rt.DB()
		if err != nil {
			return err
		}
		if err := db.Purge(ctx, id, name); err != nil {
			return err
		}
	}
	if err := store.Delete(creds.Key(name, string(id))); err != nil && !errors.Is(err, creds.ErrNotFound) {
		return fmt.Errorf("remove credentials: %w", err)
	}
	if !store.Has(a.CredentialBackend) {
		rt.Infof("warning: the %s credentials of profile %q are stored in the %s backend, which is not available now, and were not removed", id, name, a.CredentialBackend)
	}
	if a.LegacySecret {
		switch legacy := a.LegacySecretBackend(); {
		case store.Has(legacy):
			if err := store.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
				return fmt.Errorf("remove credentials: %w", err)
			}
		case legacy != a.CredentialBackend:
			rt.Infof("warning: an older %s credentials entry of profile %q (stored by polyctl 0.1) is in the %s backend, which is not available now, and was not removed", id, name, legacy)
		}
	}
	prevCurrent := cfg.CurrentProfile
	delete(prof.Platforms, id)
	if len(prof.Platforms) == 0 {
		delete(cfg.Profiles, name)
		if cfg.CurrentProfile == name {
			cfg.CurrentProfile = ""
		}
	}
	// Save after every account, for the same reason.
	if err := cfg.Save(); err != nil {
		// Keep the config in memory equal to the file: the account is still
		// listed there, and running the command again finishes the removal.
		prof.Platforms[id] = a
		cfg.Profiles[name] = prof
		cfg.CurrentProfile = prevCurrent
		if errors.Is(err, config.ErrChanged) {
			// Changed between the check above and the save. Not the text of
			// Save, which says that nothing was saved: something was removed.
			return fmt.Errorf("%w (%s): the %s credentials of profile %q were already removed, but the account is still listed; run the command again to finish",
				config.ErrChanged, cfg.Path(), id, name)
		}
		return fmt.Errorf("save config: %w (the %s credentials of profile %q were already removed, but the account is still listed; run the command again to finish)", err, id, name)
	}
	return nil
}
