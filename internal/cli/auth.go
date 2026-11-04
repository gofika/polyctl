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
		Short: "Manage platform accounts (profiles)",
	}
	cmd.AddCommand(newAuthLoginCmd(rt), newAuthListCmd(rt), newAuthUseCmd(rt), newAuthStatusCmd(rt), newAuthLogoutCmd(rt))
	return cmd
}

func loginHelp() string {
	var b strings.Builder
	for _, p := range platform.Providers() {
		fmt.Fprintf(&b, "  %-11s %s\n", p.ID(), p.LoginHelp())
	}
	return b.String()
}

func newAuthLoginCmd(rt *app.Runtime) *cobra.Command {
	var name string
	var sets []string
	cmd := &cobra.Command{
		Use:   "login <platform>",
		Short: "Authenticate with a platform and save a profile",
		Long: "Authenticate with a platform and save the credentials in the system keyring\n" +
			"(or a 0600 file when no keyring is available).\n\nLogin flows:\n" + loginHelp() +
			"\nPlatform-specific options are passed with --set key=value (see each platform's\n" +
			"section in the README).",
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
			if name == "" {
				name = rt.Flags.Profile
			}
			if name == "" {
				name = string(id)
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
				opts[k] = v
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			var existing map[string]string
			if p, ok := cfg.Profiles[name]; ok {
				if p.Platform != id {
					return usageErr("profile %q already exists for platform %s; choose another --profile name", name, p.Platform)
				}
				existing = p.Metadata
				rt.Infof("re-authenticating existing profile %q", name)
			}
			res, err := prov.Login(cmd.Context(), rt.LoginInput(name, opts, existing))
			if err != nil {
				return err
			}
			store, err := rt.Creds()
			if err != nil {
				return err
			}
			if err := store.Set(name, res.Secret); err != nil {
				return fmt.Errorf("store credentials: %w", err)
			}
			now := time.Now()
			p := cfg.Profiles[name]
			if p == nil {
				p = &config.Profile{Platform: id, CreatedAt: now}
				cfg.Profiles[name] = p
			}
			p.Metadata = res.Metadata
			p.CredentialBackend = store.Name()
			p.UpdatedAt = now
			if cfg.CurrentProfile == "" {
				cfg.CurrentProfile = name
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			label := res.Label
			if label != "" {
				label = " (" + label + ")"
			}
			rt.Infof("logged in to %s as profile %q%s; credentials stored in %s", prov.DisplayName(), name, label, store.Name())
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "profile", "", "profile name (default: the platform name)")
	cmd.Flags().StringArrayVar(&sets, "set", nil, "platform-specific login option key=value (repeatable)")
	_ = cmd.RegisterFlagCompletionFunc("profile", completeProfiles(rt))
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
	for _, n := range cfg.ProfileNames() {
		p := cfg.Profiles[n]
		rows = append(rows, profileRow{Name: n, Platform: p.Platform, Current: n == cfg.CurrentProfile, Backend: p.CredentialBackend, Metadata: p.Metadata, UpdatedAt: p.UpdatedAt})
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
		Short: "List configured profiles",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			rows := profileRows(cfg)
			return rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"", "PROFILE", "PLATFORM", "STORE", "DETAILS"}, Empty: "no profiles configured; run `polyctl auth login <platform> --profile <name>`"}
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
		Short: "Set the default profile",
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
			rt.Infof("default profile set to %q", args[0])
			return nil
		},
	}
}

type statusRow struct {
	Name     string             `json:"name" yaml:"name"`
	Platform platform.ID        `json:"platform" yaml:"platform"`
	Current  bool               `json:"current" yaml:"current"`
	OK       bool               `json:"ok" yaml:"ok"`
	Identity *platform.Identity `json:"identity,omitempty" yaml:"identity,omitempty"`
	Error    string             `json:"error,omitempty" yaml:"error,omitempty"`
}

func newAuthStatusCmd(rt *app.Runtime) *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Verify stored credentials (all profiles, or --profile)",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			names := cfg.ProfileNames()
			if rt.Flags.Profile != "" {
				if _, err := cfg.Profile(rt.Flags.Profile); err != nil {
					return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
				}
				names = []string{rt.Flags.Profile}
			}
			var rows []statusRow
			var failed bool
			for _, n := range names {
				row := statusRow{Name: n, Platform: cfg.Profiles[n].Platform, Current: n == cfg.CurrentProfile}
				id, err := verifyProfile(cmd.Context(), rt, n)
				if err != nil {
					row.Error = err.Error()
					failed = true
				} else {
					row.OK = true
					row.Identity = id
				}
				rows = append(rows, row)
			}
			if err := rt.Render(rows, func() output.Grid {
				g := output.Grid{Headers: []string{"", "PROFILE", "PLATFORM", "STATUS", "IDENTITY"}, Empty: "no profiles configured"}
				for _, r := range rows {
					cur := ""
					if r.Current {
						cur = "*"
					}
					st, id := "ok", ""
					if !r.OK {
						st, id = "FAILED", r.Error
					} else if r.Identity != nil {
						id = identitySummary(r.Identity)
					}
					g.Rows = append(g.Rows, []string{cur, r.Name, string(r.Platform), st, id})
				}
				return g
			}); err != nil {
				return err
			}
			if failed {
				return fmt.Errorf("%w: one or more profiles failed verification", platform.ErrUnauthorized)
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

func verifyProfile(ctx context.Context, rt *app.Runtime, name string) (*platform.Identity, error) {
	if rt.Flags.Offline {
		if _, err := rt.LoadProfile(name); err != nil {
			return nil, err
		}
		return &platform.Identity{Extra: map[string]string{"name": "credentials present (offline, not verified)"}}, nil
	}
	c, _, err := rt.Open(ctx, name)
	if err != nil {
		return nil, err
	}
	return c.Verify(ctx)
}

func newAuthLogoutCmd(rt *app.Runtime) *cobra.Command {
	var name string
	var keepInventory bool
	cmd := &cobra.Command{
		Use:   "logout",
		Short: "Remove a profile and its stored credentials",
		Args:  cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if name == "" {
				name = rt.Flags.Profile
			}
			if name == "" {
				return usageErr("--profile <name> is required")
			}
			cfg, err := rt.Config()
			if err != nil {
				return err
			}
			p, err := cfg.Profile(name)
			if err != nil {
				return fmt.Errorf("%w: %v", platform.ErrNotFound, err)
			}
			store, err := rt.Creds()
			if err != nil {
				return err
			}
			if err := store.Delete(name); err != nil && !errors.Is(err, creds.ErrNotFound) {
				return fmt.Errorf("remove credentials: %w", err)
			}
			if !keepInventory {
				db, err := rt.DB()
				if err != nil {
					return err
				}
				if err := db.Purge(cmd.Context(), p.Platform, name); err != nil {
					return err
				}
			}
			delete(cfg.Profiles, name)
			if cfg.CurrentProfile == name {
				cfg.CurrentProfile = ""
			}
			if err := cfg.Save(); err != nil {
				return err
			}
			rt.Infof("profile %q removed", name)
			return nil
		},
	}
	cmd.Flags().StringVar(&name, "profile", "", "profile to remove")
	cmd.Flags().BoolVar(&keepInventory, "keep-inventory", false, "keep cached resources of this profile in the local inventory")
	_ = cmd.RegisterFlagCompletionFunc("profile", completeProfiles(rt))
	return cmd
}
