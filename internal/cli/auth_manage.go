package cli

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/config"
	"github.com/gofika/polyctl/internal/creds"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// oneArgOrInteractive requires exactly one argument, except on a terminal,
// where the argument may be left out and is then asked for.
func oneArgOrInteractive(rt *app.Runtime) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 && rt.Interactive() {
			return nil
		}
		return cobra.ExactArgs(1)(cmd, args)
	}
}

// quietAbort wraps a command so that leaving one of its prompts with Esc or
// Ctrl-C ends it with a short note instead of an error.
func quietAbort(rt *app.Runtime, run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := run(cmd, args)
		if errors.Is(err, prompt.ErrAborted) {
			rt.Infof("cancelled")
			return nil
		}
		return err
	}
}

// pickPlatform asks for one of the supported platforms.
func pickPlatform(rt *app.Runtime) (platform.ID, error) {
	var opts []prompt.Option
	for _, p := range platform.Providers() {
		opts = append(opts, prompt.Option{Label: p.DisplayName(), Value: string(p.ID())})
	}
	v, err := rt.Pick().Select("Platform", opts, "")
	if err != nil {
		return "", err
	}
	return platform.Parse(v)
}

func errNoProfiles() error {
	return fmt.Errorf("%w: no profiles configured; run `polyctl auth login <platform> [--profile <name>]`", platform.ErrNotFound)
}

// profileOptions lists the profiles with their platforms.
func profileOptions(cfg *config.Config) []prompt.Option {
	var opts []prompt.Option
	for _, n := range cfg.ProfileNames() {
		var ids []string
		for _, id := range cfg.Profiles[n].PlatformIDs() {
			ids = append(ids, string(id))
		}
		label := n
		if len(ids) > 0 {
			label += "  (" + strings.Join(ids, ", ") + ")"
		}
		if n == cfg.CurrentProfile {
			label += "  [current]"
		}
		opts = append(opts, prompt.Option{Label: label, Value: n})
	}
	return opts
}

// pickProfile asks for one of the configured profiles; the current one is
// preselected.
func pickProfile(rt *app.Runtime, title string) (string, error) {
	cfg, err := rt.Config()
	if err != nil {
		return "", err
	}
	opts := profileOptions(cfg)
	if len(opts) == 0 {
		return "", errNoProfiles()
	}
	return rt.Pick().Select(title, opts, cfg.CurrentProfile)
}

// accountLabel renders "profile / platform  details" for selection lists.
func accountLabel(cfg *config.Config, ref config.AccountRef) string {
	label := ref.Profile + " / " + string(ref.Platform)
	if a := cfg.Profiles[ref.Profile].Platforms[ref.Platform]; a != nil {
		if d := metaSummary(a.Metadata); d != "" {
			label += "  " + d
		}
	}
	return label
}

// accountOptions lists accounts for a selection prompt and returns the
// account behind each option value.
func accountOptions(cfg *config.Config, refs []config.AccountRef) ([]prompt.Option, map[string]config.AccountRef) {
	byValue := map[string]config.AccountRef{}
	var opts []prompt.Option
	for _, ref := range refs {
		opts = append(opts, prompt.Option{Label: accountLabel(cfg, ref), Value: ref.String()})
		byValue[ref.String()] = ref
	}
	return opts, byValue
}

// keepMode says what happens to the cached inventory of removed accounts.
type keepMode int

const (
	keepUnset keepMode = iota // ask
	keepNo
	keepYes
)

// removeInteractive lets the user choose accounts (and profiles without
// accounts) in a multi-select, shows what will be removed, asks for
// confirmation and removes them the way `auth logout` does. only restricts
// the list to one platform. --yes skips the confirmations.
func removeInteractive(ctx context.Context, rt *app.Runtime, only platform.ID, keep keepMode) error {
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	var refs []config.AccountRef
	for _, ref := range cfg.Accounts("") {
		if only == "" || ref.Platform == only {
			refs = append(refs, ref)
		}
	}
	opts, byValue := accountOptions(cfg, refs)
	// A profile without accounts (hand-edited config) has no account row to
	// pick, so it gets a row of its own. Its value ends in a slash, which no
	// account value does.
	emptyProfiles := map[string]string{}
	if only == "" {
		for _, n := range cfg.ProfileNames() {
			if len(cfg.Profiles[n].Platforms) == 0 {
				emptyProfiles[n+"/"] = n
				opts = append(opts, prompt.Option{Label: n + " / " + noAccounts, Value: n + "/"})
			}
		}
	}
	if len(opts) == 0 {
		if only != "" {
			return fmt.Errorf("%w: no %s account configured", platform.ErrNotFound, only)
		}
		return errNoProfiles()
	}
	chosen, err := rt.Pick().MultiSelect("Remove which accounts?", opts)
	if err != nil {
		return err
	}
	if len(chosen) == 0 {
		rt.Infof("nothing selected")
		return nil
	}

	var accounts []config.AccountRef
	var empties []string
	left := map[string]int{}
	for n, p := range cfg.Profiles {
		left[n] = len(p.Platforms)
	}
	for _, v := range chosen {
		if ref, ok := byValue[v]; ok {
			accounts = append(accounts, ref)
			left[ref.Profile]--
		} else if n, ok := emptyProfiles[v]; ok {
			empties = append(empties, n)
		}
	}
	rt.Infof("The following will be removed, with the stored credentials:")
	for _, ref := range accounts {
		rt.Infof("  account  %s", accountLabel(cfg, ref))
	}
	gone := map[string]bool{}
	for _, ref := range accounts {
		gone[ref.Profile] = true
	}
	for _, n := range empties {
		gone[n] = true
	}
	for _, n := range cfg.ProfileNames() {
		if gone[n] && left[n] == 0 {
			note := ""
			if n == cfg.CurrentProfile {
				note = " (the current profile)"
			}
			rt.Infof("  profile  %s%s", n, note)
		}
	}
	if !rt.Flags.Yes {
		ok, err := rt.Pick().Confirm(fmt.Sprintf("Remove %s?", countNoun(len(accounts)+len(empties), "entry", "entries")), false)
		if err != nil {
			return err
		}
		if !ok {
			rt.Infof("cancelled")
			return nil
		}
	}
	keepInventory := keep == keepYes
	if keep == keepUnset && !rt.Flags.Yes && len(accounts) > 0 {
		if keepInventory, err = rt.Pick().Confirm("Keep cached inventory?", false); err != nil {
			return err
		}
	}
	for _, ref := range accounts {
		if err := removeAccount(ctx, rt, ref, keepInventory); err != nil {
			return err
		}
		rt.Infof("%s account removed from profile %q", ref.Platform, ref.Profile)
		if _, kept := cfg.Profiles[ref.Profile]; !kept {
			rt.Infof("profile %q removed", ref.Profile)
		}
	}
	for _, n := range empties {
		if err := removeEmptyProfile(rt, n); err != nil {
			return err
		}
		rt.Infof("profile %q removed", n)
	}
	return nil
}

func countNoun(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}
	return fmt.Sprintf("%d %s", n, many)
}

func newAuthRenameCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "rename <old> <new>",
		Short: "Rename a profile",
		Long: "Rename a profile. Its accounts, their stored credentials and their cached\n" +
			"resources move to the new name; when the profile was current, the new name\n" +
			"becomes current.",
		Args: cobra.ExactArgs(2),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, tc string) ([]string, cobra.ShellCompDirective) {
			if len(args) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			return completeProfiles(rt)(cmd, args, tc)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			return renameProfile(cmd.Context(), rt, args[0], args[1])
		},
	}
}

// checkNewProfileName validates the name of a profile that must not exist
// yet.
func checkNewProfileName(cfg *config.Config, name string) error {
	if err := validateProfileName(name); err != nil {
		return err
	}
	if _, exists := cfg.Profiles[name]; exists {
		return fmt.Errorf("profile %q already exists", name)
	}
	return nil
}

// renameProfile renames a profile. Nothing is lost when a step fails: the
// secrets are copied to their new keys first, then the inventory rows are
// renamed and the config is saved, and only then are the old secrets
// removed. A failure before the config is saved undoes the earlier steps.
func renameProfile(ctx context.Context, rt *app.Runtime, oldName, newName string) error {
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	prof, err := cfg.Profile(oldName)
	if err != nil {
		return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
	}
	if err := checkNewProfileName(cfg, newName); err != nil {
		return usageErr("%v", err)
	}
	// Opening the store moves secrets still stored in the pre-0.2 layout.
	store, err := rt.Creds()
	if err != nil {
		return err
	}
	ids := prof.PlatformIDs()
	for _, id := range ids {
		if a := prof.Platforms[id]; a.LegacySecret {
			return fmt.Errorf("profile %q cannot be renamed yet: an entry for its %s credentials is still stored in the pre-0.2 layout and could not be moved or removed (credential backend %q); make that backend available, then retry",
				oldName, id, a.LegacySecretBackend())
		}
		if a := prof.Platforms[id]; !store.Has(a.CredentialBackend) {
			// Its secret cannot be read or moved now; renaming would
			// leave it behind under the old name.
			return fmt.Errorf("profile %q cannot be renamed now: its %s credentials are stored in the %s backend, which is not available in this session",
				oldName, id, a.CredentialBackend)
		}
	}
	// The undo steps must run even when the command was interrupted.
	undoCtx := context.WithoutCancel(ctx)

	var copied []platform.ID
	undoSecrets := func() {
		for _, id := range copied {
			_ = store.Delete(creds.Key(newName, string(id)))
		}
	}
	for _, id := range ids {
		newKey := creds.Key(newName, string(id))
		secret, err := store.Get(creds.Key(oldName, string(id)))
		if errors.Is(err, creds.ErrNotFound) {
			// An account without credentials stays without: an orphaned
			// entry under the new key must not become its secret.
			if err := store.Delete(newKey); err != nil && !errors.Is(err, creds.ErrNotFound) {
				undoSecrets()
				return fmt.Errorf("remove stale %s credentials of profile %q: %w", id, newName, err)
			}
			continue
		}
		if err != nil {
			undoSecrets()
			return fmt.Errorf("read %s credentials of profile %q: %w", id, oldName, err)
		}
		// Recorded before Set: a failing Set may have written already.
		copied = append(copied, id)
		if err := store.Set(newKey, secret); err != nil {
			undoSecrets()
			return fmt.Errorf("copy %s credentials to profile %q: %w", id, newName, err)
		}
	}

	db, err := rt.DB()
	if err != nil {
		undoSecrets()
		return err
	}
	var moved []platform.ID
	undoInventory := func() {
		for _, id := range moved {
			if err := db.RenameProfile(undoCtx, id, newName, oldName); err != nil {
				rt.Infof("warning: the cached %s resources of profile %q could not be restored: %v (run `polyctl sync --profile %s`)", id, oldName, err, oldName)
			}
		}
	}
	for _, id := range ids {
		if err := db.RenameProfile(ctx, id, oldName, newName); err != nil {
			undoInventory()
			undoSecrets()
			return fmt.Errorf("rename cached %s resources: %w", id, err)
		}
		moved = append(moved, id)
	}

	backends := map[platform.ID]string{}
	for _, id := range copied {
		a := prof.Platforms[id]
		backends[id] = a.CredentialBackend
		a.CredentialBackend = store.Name()
	}
	wasCurrent := cfg.CurrentProfile == oldName
	cfg.Profiles[newName] = prof
	delete(cfg.Profiles, oldName)
	if wasCurrent {
		cfg.CurrentProfile = newName
	}
	if err := cfg.Save(); err != nil {
		delete(cfg.Profiles, newName)
		cfg.Profiles[oldName] = prof
		if wasCurrent {
			cfg.CurrentProfile = oldName
		}
		for id, b := range backends {
			prof.Platforms[id].CredentialBackend = b
		}
		undoInventory()
		undoSecrets()
		return fmt.Errorf("save config: %w", err)
	}

	for _, id := range copied {
		key := creds.Key(oldName, string(id))
		if err := store.Delete(key); err != nil && !errors.Is(err, creds.ErrNotFound) {
			rt.Infof("warning: the old credentials entry %q could not be removed: %v", key, err)
		}
	}
	rt.Infof("profile %q renamed to %q", oldName, newName)
	return nil
}

func newAuthManageCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "manage",
		Short: "Manage profiles and accounts in an interactive menu",
		Long: "Open an interactive menu to view, add, verify, rename and remove profiles\n" +
			"and their accounts. Arrow keys (or j/k) move, space toggles in a multiple\n" +
			"choice, \"/\" filters a list, enter confirms (in a yes/no question y and n\n" +
			"select the answer, enter confirms it), Esc or Ctrl-C goes back (and leaves\n" +
			"the menu from its top level).\n\n" +
			"The configuration is read again before every action, so changes made by\n" +
			"other polyctl commands while the menu is open are kept.\n\n" +
			"The menu is drawn on stderr and needs a terminal on stdin and stderr. In\n" +
			"scripts use auth list, auth use, auth login, auth status, auth rename and\n" +
			"auth logout instead.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if !rt.Interactive() {
				return usageErr("auth manage needs an interactive terminal; use `polyctl auth list`, `auth use <profile>`, `auth login <platform>`, `auth status`, `auth rename <old> <new>` or `auth logout [platform] --profile <name>` instead")
			}
			return runManage(cmd.Context(), rt)
		},
	}
}

// Menu actions of `auth manage`.
const (
	actDetails = "details"
	actUse     = "use"
	actLogin   = "login"
	actVerify  = "verify"
	actRename  = "rename"
	actRemove  = "remove"
	actQuit    = "quit"
)

// newProfileValue is the option value of the "New profile..." entry. It
// contains a slash, which a profile name cannot.
const newProfileValue = "/new"

// runManage shows the account table and the action menu until the user
// quits. An action that fails or is aborted returns to the menu.
func runManage(ctx context.Context, rt *app.Runtime) error {
	actions := map[string]func(context.Context, *app.Runtime) error{
		actDetails: manageDetails,
		actUse:     manageUse,
		actLogin:   manageLogin,
		actVerify:  manageVerify,
		actRename:  manageRename,
		actRemove: func(ctx context.Context, rt *app.Runtime) error {
			return removeInteractive(ctx, rt, "", keepUnset)
		},
	}
	for first := true; ; first = false {
		if err := ctx.Err(); err != nil {
			return nil
		}
		// The menu stays open for as long as the user likes, and other
		// polyctl processes may change the config meanwhile: every round
		// starts from the file, never from the copy loaded at startup.
		cfg, err := rt.ReloadConfig()
		if err != nil {
			if first {
				return err
			}
			rt.Infof("error: %v", err)
			if cfg, err = rt.Config(); err != nil {
				return err
			}
		}
		fmt.Fprintln(rt.Stderr)
		if err := output.RenderGrid(rt.Stderr, profileGrid(profileRows(cfg))); err != nil {
			return err
		}
		fmt.Fprintln(rt.Stderr)

		var opts []prompt.Option
		if len(cfg.Profiles) > 0 {
			if len(cfg.Accounts("")) > 0 {
				opts = append(opts, prompt.Option{Label: "View account details", Value: actDetails})
			}
			opts = append(opts, prompt.Option{Label: "Switch current profile", Value: actUse})
		}
		opts = append(opts, prompt.Option{Label: "Add an account (log in)", Value: actLogin})
		if len(cfg.Profiles) > 0 {
			if len(cfg.Accounts("")) > 0 {
				opts = append(opts, prompt.Option{Label: "Verify credentials", Value: actVerify})
			}
			opts = append(opts,
				prompt.Option{Label: "Rename a profile", Value: actRename},
				prompt.Option{Label: "Remove accounts or profiles", Value: actRemove})
		}
		opts = append(opts, prompt.Option{Label: "Quit  (q)", Value: actQuit, Key: "q"})

		action, err := rt.Pick().Select("Profiles and accounts", opts, "")
		if errors.Is(err, prompt.ErrAborted) || (err == nil && action == actQuit) {
			return nil
		}
		if err != nil {
			return err
		}
		run, ok := actions[action]
		if !ok {
			return fmt.Errorf("unknown menu action %q", action)
		}
		// Again after the choice: the menu may have been waiting for long.
		if _, err := rt.ReloadConfig(); err != nil {
			rt.Infof("error: %v", err)
			continue
		}
		if err := run(ctx, rt); err != nil && !errors.Is(err, prompt.ErrAborted) {
			rt.Infof("error: %v", err)
		}
	}
}

// pickAccount asks for one account; a single account is taken as is.
func pickAccount(rt *app.Runtime, title string) (config.AccountRef, error) {
	cfg, err := rt.Config()
	if err != nil {
		return config.AccountRef{}, err
	}
	refs := cfg.Accounts("")
	switch len(refs) {
	case 0:
		return config.AccountRef{}, fmt.Errorf("%w: no accounts configured", platform.ErrNotFound)
	case 1:
		return refs[0], nil
	}
	opts, byValue := accountOptions(cfg, refs)
	v, err := rt.Pick().Select(title, opts, "")
	if err != nil {
		return config.AccountRef{}, err
	}
	return byValue[v], nil
}

func formatTime(t time.Time) string {
	if t.IsZero() {
		return "unknown"
	}
	return t.Local().Format("2006-01-02 15:04:05")
}

// manageDetails prints everything known locally about one account. It does
// not access the network.
func manageDetails(ctx context.Context, rt *app.Runtime) error {
	ref, err := pickAccount(rt, "View which account?")
	if err != nil {
		return err
	}
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	a := cfg.Profiles[ref.Profile].Platforms[ref.Platform]
	current := "no"
	if ref.Profile == cfg.CurrentProfile {
		current = "yes"
	}
	name := string(ref.Platform)
	if prov, err := platform.Get(ref.Platform); err == nil {
		name = fmt.Sprintf("%s (%s)", prov.DisplayName(), ref.Platform)
	}
	present := "yes"
	if _, err := rt.LoadProfile(ref.Profile, ref.Platform); err != nil {
		present = "no"
		if !errors.Is(err, platform.ErrUnauthorized) {
			present = fmt.Sprintf("unknown (%v)", err)
		}
	}
	backend := a.CredentialBackend
	if backend == "" {
		backend = "unknown"
	}
	pairs := []string{
		"Profile", ref.Profile,
		"Platform", name,
		"Current profile", current,
		"Credential store", backend,
		"Credentials present", present,
		"Created", formatTime(a.CreatedAt),
		"Updated", formatTime(a.UpdatedAt),
	}
	keys := make([]string, 0, len(a.Metadata))
	for k := range a.Metadata {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		pairs = append(pairs, "Metadata "+k, a.Metadata[k])
	}
	db, err := rt.DB()
	if err != nil {
		return err
	}
	stats, err := db.Stats(ctx)
	if err != nil {
		return err
	}
	cached := false
	for _, st := range stats {
		if st.Platform != ref.Platform || st.Profile != ref.Profile {
			continue
		}
		cached = true
		pairs = append(pairs, "Cached "+string(st.Type), fmt.Sprintf("%d (synced %s)", st.Count, formatTime(st.SyncedAt)))
	}
	if !cached {
		pairs = append(pairs, "Cached resources", "none (never synced)")
	}
	fmt.Fprintln(rt.Stderr)
	return output.RenderGrid(rt.Stderr, output.KV(pairs...))
}

func manageUse(ctx context.Context, rt *app.Runtime) error {
	name, err := pickProfile(rt, "Switch to which profile?")
	if err != nil {
		return err
	}
	return useProfile(rt, name)
}

// manageLogin asks for a platform and a target profile (an existing one or a
// new name) and runs the login flow of `auth login`.
func manageLogin(ctx context.Context, rt *app.Runtime) error {
	if rt.Flags.Offline {
		return app.ErrOffline // before asking for anything
	}
	id, err := pickPlatform(rt)
	if err != nil {
		return err
	}
	prov, err := platform.Get(id)
	if err != nil {
		return err
	}
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	name := newProfileValue
	if opts := profileOptions(cfg); len(opts) > 0 {
		opts = append(opts, prompt.Option{Label: "New profile...", Value: newProfileValue})
		if name, err = rt.Pick().Select("Add the account to which profile?", opts, cfg.CurrentProfile); err != nil {
			return err
		}
	}
	if name == newProfileValue {
		def := ""
		if len(cfg.Profiles) == 0 {
			def = config.DefaultProfile
		}
		if name, err = rt.Pick().Input("Name of the new profile", def, func(s string) error { return checkNewProfileName(cfg, s) }); err != nil {
			return err
		}
		// The terminal picker validates already; an injected one may not.
		if err := checkNewProfileName(cfg, name); err != nil {
			return usageErr("%v", err)
		}
	}
	// The profile was chosen explicitly, like with --profile.
	return loginAccount(ctx, rt, prov, name, true, map[string]string{})
}

// manageVerify checks the credentials of the chosen accounts, or of all of
// them when none is chosen.
func manageVerify(ctx context.Context, rt *app.Runtime) error {
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	refs := cfg.Accounts("")
	if len(refs) > 1 {
		opts, byValue := accountOptions(cfg, refs)
		chosen, err := rt.Pick().MultiSelect("Verify which accounts? (ctrl+a ticks all)", opts)
		if err != nil {
			return err
		}
		if len(chosen) > 0 {
			refs = refs[:0:0]
			for _, v := range chosen {
				refs = append(refs, byValue[v])
			}
		}
	}
	rows, _, err := verifyAccounts(ctx, rt, refs)
	if err != nil {
		return err
	}
	fmt.Fprintln(rt.Stderr)
	return output.RenderGrid(rt.Stderr, statusGrid(rows))
}

func manageRename(ctx context.Context, rt *app.Runtime) error {
	oldName, err := pickProfile(rt, "Rename which profile?")
	if err != nil {
		return err
	}
	cfg, err := rt.Config()
	if err != nil {
		return err
	}
	newName, err := rt.Pick().Input(fmt.Sprintf("New name for profile %q", oldName), "", func(s string) error { return checkNewProfileName(cfg, s) })
	if err != nil {
		return err
	}
	return renameProfile(ctx, rt, oldName, newName)
}
