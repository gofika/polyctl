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
	cmd.AddCommand(newAuthLoginCmd(rt), newAuthListCmd(rt), newAuthUseCmd(rt), newAuthStatusCmd(rt), newAuthLogoutCmd(rt))
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
// the value may be given as "-" to read it from stdin instead.
var secretOptionKeys = map[string]bool{
	"token":             true,
	"secret":            true,
	"key":               true,
	"client_secret":     true,
	"access_key_secret": true,
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
			"profile, or to a profile named \"default\" when no profile is current. When the\n" +
			"platform is already configured in another profile only, --profile is required.\n\nLogin flows:\n" + loginHelp() +
			"\nPlatform-specific options are passed with --set key=value (see each platform's\n" +
			"section in the README). A secret option (token, key, secret, client_secret, ...)\n" +
			"may be given as --set key=- to read the value from stdin instead of argv.",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: completePlatforms,
		RunE: func(cmd *cobra.Command, args []string) error {
			id, err := platform.Parse(args[0])
			if err != nil {
				return usageErr("%v", err)
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
			}
			if name == "" {
				name = config.DefaultProfile
			}
			if strings.ContainsAny(name, " /\\\t") {
				return usageErr("profile name %q must not contain spaces or slashes", name)
			}
			opts := map[string]string{}
			for _, s := range sets {
				k, v, ok := strings.Cut(s, "=")
				if !ok {
					return usageErr("--set expects key=value, got %q", s)
				}
				if secretOptionKeys[k] && v != "" {
					if v == "-" {
						if v, err = rt.Prompt().RequiredSecret(k); err != nil {
							return err
						}
					} else {
						rt.Infof("warning: --set %s=... is visible in process listings and shell history; pass %s=- to read it from stdin", k, k)
					}
				}
				opts[k] = v
			}
			prof := cfg.Profiles[name]
			var acct *config.Account
			if prof != nil {
				acct = prof.Platforms[id]
			}
			var existing map[string]string
			if acct == nil && rt.Flags.Profile == "" {
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
			res, err := prov.Login(cmd.Context(), rt.LoginInput(name, opts, existing))
			if err != nil {
				return err
			}
			store, err := rt.Creds()
			if err != nil {
				return err
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
			now := time.Now()
			if prof == nil {
				prof = &config.Profile{Platforms: map[platform.ID]*config.Account{}}
				cfg.Profiles[name] = prof
			}
			if isNew {
				acct = &config.Account{CreatedAt: now}
				prof.Platforms[id] = acct
			}
			if acct.LegacySecret && store.Has(acct.CredentialBackend) {
				// The secret now lives under the profile/platform key. When
				// the backend holding the old entry is out of reach, or the
				// removal fails, the mark stays and a later run cleans up.
				if err := store.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
					rt.Verbosef("remove legacy credentials of profile %q: %v", name, err)
				} else {
					acct.LegacySecret = false
				}
			}
			acct.Metadata = res.Metadata
			acct.CredentialBackend = store.Name()
			acct.UpdatedAt = now
			if cfg.CurrentProfile == "" {
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
				}
				return fmt.Errorf("save config: %w (stored %s credentials for profile %q were %s)", err, id, name, kept)
			}
			label := res.Label
			if label != "" {
				label = " (" + label + ")"
			}
			rt.Infof("logged in to %s in profile %q%s; credentials stored in %s", prov.DisplayName(), name, label, store.Name())
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&sets, "set", nil, "platform-specific login option key=value (repeatable; value - reads a secret from stdin)")
	return cmd
}

type profileRow struct {
	Name      string            `json:"name" yaml:"name"`
	Platform  platform.ID       `json:"platform" yaml:"platform"`
	Current   bool              `json:"current" yaml:"current"`
	Backend   string            `json:"credential_backend,omitempty" yaml:"credential_backend,omitempty"`
	Metadata  map[string]string `json:"metadata,omitempty" yaml:"metadata,omitempty"`
	UpdatedAt time.Time         `json:"updated_at" yaml:"updated_at"`
}

func profileRows(cfg *config.Config) []profileRow {
	var rows []profileRow
	for _, ref := range cfg.Accounts("") {
		a := cfg.Profiles[ref.Profile].Platforms[ref.Platform]
		rows = append(rows, profileRow{Name: ref.Profile, Platform: ref.Platform, Current: ref.Profile == cfg.CurrentProfile, Backend: a.CredentialBackend, Metadata: a.Metadata, UpdatedAt: a.UpdatedAt})
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
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			rows := profileRows(cfg)
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"", "PROFILE", "PLATFORM", "STORE", "DETAILS"}, Empty: "no accounts configured; run `polyctl auth login <platform> [--profile <name>]`"}
				for _, r := range rows {
					cur := ""
					if r.Current {
						cur = "*"
					}
					g.Rows = append(g.Rows, []string{cur, r.Name, string(r.Platform), r.Backend, metaSummary(r.Metadata)})
				}
				return g
			})
		},
	}
}

func newAuthUseCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "use <profile>",
		Short: "Set the current profile",
		Args:  cobra.ExactArgs(1),
		ValidArgsFunction: func(cmd *cobra.Command, args []string, tc string) ([]string, cobra.ShellCompDirective) {
			return completeProfiles(rt)(cmd, args, tc)
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			if _, err := cfg.Profile(args[0]); err != nil {
				return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
			}
			cfg.CurrentProfile = args[0]
			if err := cfg.Save(); err != nil {
				return err
			}
			rt.Infof("current profile set to %q", args[0])
			return nil
		},
	}
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
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			refs, err := rt.Accounts()
			if err != nil {
				return err
			}
			var rows []statusRow
			var failed bool
			for _, ref := range refs {
				row := statusRow{Name: ref.Profile, Platform: ref.Platform, Current: ref.Profile == cfg.CurrentProfile}
				id, err := verifyAccount(cmd.Context(), rt, ref)
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
			if err := rt.Render(rows, func() output.Grid {
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
			}); err != nil {
				return err
			}
			if failed {
				return fmt.Errorf("%w: one or more accounts failed verification", platform.ErrUnauthorized)
			}
			return nil
		},
	}
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
			"removed too when it was its last one.",
		Args:              cobra.MaximumNArgs(1),
		ValidArgsFunction: completePlatforms,
		RunE: func(cmd *cobra.Command, args []string) error {
			name := rt.Flags.Profile
			if name == "" {
				return usageErr("--profile <name> is required")
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			prof, err := cfg.Profile(name)
			if err != nil {
				return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
			}
			ids := prof.PlatformIDs()
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
			store, err := rt.Creds()
			if err != nil {
				return err
			}
			if len(ids) == 0 {
				// A profile without accounts (hand-edited config).
				delete(cfg.Profiles, name)
				if cfg.CurrentProfile == name {
					cfg.CurrentProfile = ""
				}
				if err := cfg.Save(); err != nil {
					return err
				}
			}
			for _, id := range ids {
				// Order matters: the inventory first, the secret next and
				// the config entry right after it, so a failure never
				// leaves the config listing an account whose secret is gone.
				if !keepInventory {
					db, err := rt.DB()
					if err != nil {
						return err
					}
					if err := db.Purge(cmd.Context(), id, name); err != nil {
						return err
					}
				}
				if err := store.Delete(creds.Key(name, string(id))); err != nil && !errors.Is(err, creds.ErrNotFound) {
					return fmt.Errorf("remove credentials: %w", err)
				}
				if a := prof.Platforms[id]; a.LegacySecret {
					if !store.Has(a.CredentialBackend) {
						rt.Infof("warning: the pre-0.2 %s credentials of profile %q are stored in the %s backend, which is not available now, and were not removed", id, name, a.CredentialBackend)
					} else if err := store.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
						return fmt.Errorf("remove credentials: %w", err)
					}
				}
				delete(prof.Platforms, id)
				if len(prof.Platforms) == 0 {
					delete(cfg.Profiles, name)
					if cfg.CurrentProfile == name {
						cfg.CurrentProfile = ""
					}
				}
				// Save after every account, for the same reason.
				if err := cfg.Save(); err != nil {
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
		},
	}
	cmd.Flags().BoolVar(&keepInventory, "keep-inventory", false, "keep the cached resources of the removed accounts in the local inventory")
	return cmd
}
