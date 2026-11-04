// Package cli defines the cobra command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// Exit codes.
const (
	ExitOK           = 0
	ExitError        = 1
	ExitUsage        = 2
	ExitAuth         = 3
	ExitNotFound     = 4
	ExitAmbiguous    = 5
	ExitOffline      = 6
	ExitNotSupported = 7
)

// Version is set at build time via -ldflags "-X github.com/gofika/polyctl/internal/cli.Version=...".
var Version = "dev"

// ExitCodeFor maps an error to a process exit code.
func ExitCodeFor(err error) int {
	var amb *app.AmbiguousError
	switch {
	case err == nil:
		return ExitOK
	case errors.As(err, &amb):
		return ExitAmbiguous
	case errors.Is(err, platform.ErrUnauthorized):
		return ExitAuth
	case errors.Is(err, platform.ErrNotFound), errors.Is(err, app.ErrDomainUnknown), errors.Is(err, inventory.ErrNeverSynced):
		return ExitNotFound
	case errors.Is(err, app.ErrOffline):
		return ExitOffline
	case errors.Is(err, platform.ErrNotSupported):
		return ExitNotSupported
	case errors.Is(err, app.ErrUsage):
		return ExitUsage
	}
	return ExitError
}

// usageErr wraps an error so it maps to ExitUsage.
func usageErr(format string, args ...any) error { return app.UsageErrf(format, args...) }

// Main runs the CLI and returns the exit code.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	httpx.UserAgent = "polyctl/" + Version
	rt := app.New(app.Flags{}, stdin, stdout, stderr)
	root := NewRoot(rt)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	_ = rt.Close()
	if err == nil {
		return ExitOK
	}
	code := ExitCodeFor(err)
	fmt.Fprintf(stderr, "error: %v\n", err)
	return code
}

// NewRoot builds the command tree bound to rt.
func NewRoot(rt *app.Runtime) *cobra.Command {
	root := &cobra.Command{
		Use:   "polyctl",
		Short: "Manage domains, DNS and cloud resources across platforms",
		Long: `polyctl is a multi-platform CLI for AWS, GCP, Alibaba Cloud, Cloudflare,
name.com and GoDaddy.

Platform-neutral commands (dns, domain) route automatically to the account
that owns a domain, using the local inventory (~/.config/polyctl/inventory.db).
Platform-specific commands (aws, gcp, aliyun, cf, namecom, godaddy) expose each
platform's native features.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if err := rt.Init(); err != nil {
				return usageErr("%v", err)
			}
			return nil
		},
	}
	pf := root.PersistentFlags()
	pf.StringVar(&rt.Flags.ConfigPath, "config", "", "config file (default ~/.config/polyctl/config.yaml)")
	pf.StringVarP(&rt.Flags.Profile, "profile", "p", "", "profile to use (overrides automatic routing)")
	pf.BoolVar(&rt.Flags.Refresh, "refresh", false, "force fetching from the platform and update the local inventory")
	pf.BoolVar(&rt.Flags.Offline, "offline", false, "never access the network; serve from the local inventory only")
	pf.StringVarP(&rt.Flags.Output, "output", "o", "", "output format: table, json or yaml (default table)")
	pf.BoolVarP(&rt.Flags.Verbose, "verbose", "v", false, "verbose logging to stderr")
	pf.BoolVar(&rt.Flags.NoBrowser, "no-browser", false, "do not open a browser during login; print the URL instead")
	pf.BoolVarP(&rt.Flags.Yes, "yes", "y", false, "assume yes for confirmation prompts")
	_ = root.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"table", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp))
	_ = root.RegisterFlagCompletionFunc("profile", completeProfiles(rt))

	root.AddCommand(
		newAuthCmd(rt),
		newDNSCmd(rt),
		newDomainCmd(rt),
		newSyncCmd(rt),
		newInventoryCmd(rt),
	)
	root.AddGroup(&cobra.Group{ID: "platforms", Title: "Platform-specific commands:"})
	root.AddCommand(platformCommands(rt)...)
	root.CompletionOptions.HiddenDefaultCmd = false
	return root
}

func completeProfiles(rt *app.Runtime) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		cfg, err := rt.Config()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		var out []string
		for _, n := range cfg.ProfileNames() {
			out = append(out, fmt.Sprintf("%s\t%s", n, cfg.Profiles[n].Platform))
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

func completePlatforms(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	var out []string
	for _, p := range platform.Providers() {
		out = append(out, fmt.Sprintf("%s\t%s", p.ID(), p.DisplayName()))
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}

// completeDomains completes domain names from the local index.
func completeDomains(rt *app.Runtime) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		db, err := rt.DB()
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		entries, err := db.IndexEntries(cmd.Context())
		if err != nil {
			return nil, cobra.ShellCompDirectiveError
		}
		seen := map[string]bool{}
		var out []string
		for _, e := range entries {
			if !seen[e.Domain] {
				seen[e.Domain] = true
				out = append(out, e.Domain)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}
