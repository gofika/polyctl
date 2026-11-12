// Package cli defines the cobra command tree.
package cli

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/httpx"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
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
	case err == nil, errors.Is(err, errNothingToDo):
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
	case errors.Is(err, app.ErrUsage), errors.Is(err, prompt.ErrNotInteractive):
		// The second one is the safety net of the non-interactive flow: a
		// question that could not be asked is a value the caller left out.
		return ExitUsage
	}
	return ExitError
}

// errNothingToDo marks a command that found nothing to act on: no account to
// sync, no profile to pick from, a confirmation answered with no. That is
// not a failure. The message is printed as a note and the exit code is 0,
// because callers judge a run by "exit code is zero"; non-zero codes are
// kept for requests that could not be carried out.
var errNothingToDo = errors.New("nothing to do")

// nothingToDo returns a note error wrapping errNothingToDo.
func nothingToDo(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errNothingToDo, fmt.Sprintf(format, args...))
}

// asksNothing reports whether cmd is help or shell completion (cobra's
// help, completion, __complete and __completeNoDesc commands, or anything
// below them). They never ask a question, so an invalid
// POLYCTL_NON_INTERACTIVE value does not concern them and must not break them.
func asksNothing(cmd *cobra.Command) bool {
	for c := cmd; c != nil && c.HasParent(); c = c.Parent() {
		if c.Parent().HasParent() {
			continue
		}
		switch c.Name() {
		case "help", "completion", cobra.ShellCompRequestCmd, cobra.ShellCompNoDescRequestCmd:
			return true
		}
	}
	return false
}

// isHelp reports whether cmd is the help command.
func isHelp(cmd *cobra.Command) bool {
	return cmd.Name() == "help" && cmd.HasParent() && !cmd.Parent().HasParent()
}

// usageErr wraps an error so it maps to ExitUsage.
func usageErr(format string, args ...any) error { return app.UsageErrf(format, args...) }

// usageArgs wraps a cobra positional-args validator so its error maps to
// ExitUsage like every other command-line mistake.
func usageArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(c *cobra.Command, a []string) error {
		if err := v(c, a); err != nil {
			if errors.Is(err, app.ErrUsage) {
				return err // already one, with its own message
			}
			return usageErr("%v", err)
		}
		return nil
	}
}

// wrapArgs applies usageArgs to every command of the tree that validates
// its positional arguments, so wrong argument counts exit with ExitUsage
// regardless of which tree (core or platform-specific) defined the command.
//
// A command group (one that only holds subcommands) gets the treatment the
// root has: it becomes runnable so that cobra validates its arguments.
// Without that cobra prints the group's help and exits 0 for any word it
// does not know, and a misspelled or removed subcommand would look like a
// success to a script.
func wrapArgs(cmd *cobra.Command) {
	if cmd.HasSubCommands() && !cmd.Runnable() {
		cmd.Args = unknownSubcommand
		cmd.RunE = func(c *cobra.Command, _ []string) error { return c.Help() }
		// Runnable() no longer tells a group from a command that does
		// something, so the group is marked (see isGroup).
		if cmd.Annotations == nil {
			cmd.Annotations = map[string]string{}
		}
		cmd.Annotations[groupAnnotation] = "1"
	}
	if cmd.Args != nil {
		cmd.Args = usageArgs(cmd.Args)
	}
	for _, c := range cmd.Commands() {
		wrapArgs(c)
	}
}

// groupAnnotation marks the command groups wrapArgs made runnable.
const groupAnnotation = "polyctl.group"

// isGroup reports whether cmd is a command group: run by itself it only
// prints its help, like the root.
func isGroup(cmd *cobra.Command) bool { return cmd.Annotations[groupAnnotation] != "" }

// newHelpCmd replaces cobra's help command, which prints the help of the
// deepest command it can find and exits 0 whatever words follow. Here a word
// that names no command is the same usage error as without `help`, so that
// `polyctl help dns update` and `polyctl dns update` agree.
func newHelpCmd(root *cobra.Command) *cobra.Command {
	return &cobra.Command{
		Use:     "help [command]",
		Short:   "Help about any command",
		Long:    "Help provides help for any command in the application.\nType `polyctl help [path to command]` for full details.",
		GroupID: "core",
		ValidArgsFunction: func(c *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			target, rest, err := root.Find(args)
			if err != nil || target == nil || len(rest) > 0 {
				return nil, cobra.ShellCompDirectiveNoFileComp
			}
			var out []string
			for _, sub := range target.Commands() {
				if (sub.IsAvailableCommand() || sub == c) && strings.HasPrefix(sub.Name(), toComplete) {
					out = append(out, sub.Name()+"\t"+sub.Short)
				}
			}
			return out, cobra.ShellCompDirectiveNoFileComp
		},
		RunE: func(c *cobra.Command, args []string) error {
			target, rest, err := root.Find(args)
			if err != nil || target == nil {
				return usageErr("unknown help topic %q; see `%s --help`", strings.Join(args, " "), root.CommandPath())
			}
			if len(rest) > 0 {
				if target.HasSubCommands() {
					return unknownSubcommand(target, rest)
				}
				return usageErr("unknown help topic %q: %q has no subcommands; see `%s --help`", strings.Join(args, " "), target.CommandPath(), target.CommandPath())
			}
			target.InitDefaultHelpFlag()
			target.InitDefaultVersionFlag()
			return target.Help()
		},
	}
}

// boolSetFlag is a boolean flag that also records that it was given, at the
// moment it is parsed: the flow is decided while cobra validates arguments,
// before any hook could look at Flags().Changed.
type boolSetFlag struct{ value, set *bool }

func (b boolSetFlag) String() string {
	if b.value == nil {
		return "false"
	}
	return strconv.FormatBool(*b.value)
}

func (b boolSetFlag) Set(s string) error {
	v, err := strconv.ParseBool(s)
	if err != nil {
		return err
	}
	*b.value, *b.set = v, true
	return nil
}

func (boolSetFlag) Type() string     { return "bool" }
func (boolSetFlag) IsBoolFlag() bool { return true }

// completeList completes a flag that takes a comma-separated list: the
// values already typed stay in front of every candidate (shells keep only
// candidates that start with the word being completed), values already in
// the list are not offered again, and no space is added, so that the list
// can go on.
func completeList(candidates func() []string) func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		prefix := toComplete[:strings.LastIndexByte(toComplete, ',')+1]
		chosen := map[string]bool{}
		for _, v := range strings.Split(prefix, ",") {
			chosen[strings.TrimSpace(v)] = true
		}
		var out []string
		for _, c := range candidates() {
			if name, _, _ := strings.Cut(c, "\t"); !chosen[name] {
				out = append(out, prefix+c)
			}
		}
		return out, cobra.ShellCompDirectiveNoFileComp | cobra.ShellCompDirectiveNoSpace
	}
}

// unknownSubcommand is the argument validator of a command group: anything
// that reaches it is a word that names no subcommand.
func unknownSubcommand(cmd *cobra.Command, args []string) error {
	if len(args) == 0 {
		return nil
	}
	msg := fmt.Sprintf("unknown command %q for %q", args[0], cmd.CommandPath())
	if s := cmd.SuggestionsFor(args[0]); len(s) > 0 {
		msg += " (did you mean " + strings.Join(s, ", ") + "?)"
	}
	return usageErr("%s; see `%s --help`", msg, cmd.CommandPath())
}

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
	if errors.Is(err, errNothingToDo) {
		fmt.Fprintf(stderr, "%v\n", err) // a note, not an error
		return code
	}
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
Platform-specific commands (aws, gcp, aliyun, cloudflare, namecom, godaddy)
expose each platform's native features.

polyctl has two flows. On a terminal it is interactive: a missing argument
may be asked for, destructive actions are confirmed and logins prompt for
credentials. Without a terminal on stdin and stderr (scripts, pipes, CI,
cron), with --non-interactive or with POLYCTL_NON_INTERACTIVE=1 it is
non-interactive: nothing is ever asked, a missing argument or an unconfirmed
action is a usage error (exit code 2) that names what to pass, and --yes
confirms.

Every setting is resolved in the same order: command-line flag, then
environment variable, then config.yaml, then the built-in default. So
--non-interactive=false keeps a terminal interactive although
POLYCTL_NON_INTERACTIVE is set.`,
		Version:       Version,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, args []string) error {
			if !cmd.HasParent() || isGroup(cmd) || isHelp(cmd) {
				// Bare `polyctl`, a bare group and `polyctl help ...` only
				// print help, like --help: they load no configuration,
				// create no directory and cannot fail on a setting.
				return nil
			}
			rt.SkipNonInteractiveEnvCheck = asksNothing(cmd)
			if err := rt.Init(); err != nil {
				return usageErr("%v", err)
			}
			return nil
		},
		// A runnable root lets cobra validate its arguments, so a stray
		// first argument is reported through Args (a usage error) instead
		// of cobra's bare "unknown command" error.
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error { return cmd.Help() },
	}
	pf := root.PersistentFlags()
	pf.StringVar(&rt.Flags.ConfigDir, "config-dir", "", "directory holding config.yaml, the file credential store and inventory.db (overrides POLYCTL_CONFIG_DIR; default ~/.config/polyctl)")
	pf.StringVarP(&rt.Flags.Profile, "profile", "p", "", "profile to use (overrides the current profile and automatic routing)")
	pf.BoolVar(&rt.Flags.Refresh, "refresh", false, "force fetching from the platform and update the local inventory")
	pf.BoolVar(&rt.Flags.Offline, "offline", false, "never access the network; serve from the local inventory only")
	pf.StringVarP(&rt.Flags.Output, "output", "o", "", "output format: table, json or yaml (overrides POLYCTL_OUTPUT and the config file; default table)")
	pf.BoolVarP(&rt.Flags.Verbose, "verbose", "v", false, "verbose logging to stderr")
	pf.BoolVarP(&rt.Flags.Yes, "yes", "y", false, "assume yes for confirmations (required for them in the non-interactive flow)")
	pf.VarPF(boolSetFlag{&rt.Flags.NonInteractive, &rt.Flags.NonInteractiveSet}, "non-interactive", "", "never ask questions, also on a terminal: missing arguments and unconfirmed actions are usage errors (overrides POLYCTL_NON_INTERACTIVE; --non-interactive=false keeps a terminal interactive)").NoOptDefVal = "true"
	_ = root.RegisterFlagCompletionFunc("output", cobra.FixedCompletions([]string{"table", "json", "yaml"}, cobra.ShellCompDirectiveNoFileComp))
	_ = root.RegisterFlagCompletionFunc("profile", completeProfiles(rt))
	_ = root.MarkPersistentFlagDirname("config-dir")

	root.AddGroup(&cobra.Group{ID: "core", Title: "Commands:"})
	for _, c := range []*cobra.Command{
		newAuthCmd(rt),
		newDNSCmd(rt),
		newDomainCmd(rt),
		newSyncCmd(rt),
		newInventoryCmd(rt),
	} {
		c.GroupID = "core"
		root.AddCommand(c)
	}
	root.AddGroup(&cobra.Group{ID: "platforms", Title: "Platform-specific Commands:"})
	root.AddCommand(platformCommands(rt)...)
	root.CompletionOptions.HiddenDefaultCmd = false
	root.SetHelpCommand(newHelpCmd(root))
	// A group is runnable only to have its arguments validated: its usage
	// shows the subcommand form alone, not a line of its own.
	root.SetUsageTemplate(strings.Replace(root.UsageTemplate(), "{{if .Runnable}}", `{{if and .Runnable (not (index .Annotations "`+groupAnnotation+`"))}}`, 1))
	root.SetCompletionCommandGroupID("core")

	// Mistakes caught by cobra/pflag (unknown flag or command, wrong number
	// of arguments) are usage errors too and must exit with ExitUsage.
	root.SetFlagErrorFunc(func(c *cobra.Command, err error) error {
		if c.HasSubCommands() && c.HasParent() {
			// A flag given to a group: most often a flag of a subcommand
			// that does not exist (any more), which cobra parses first.
			return usageErr("%v for %q, which takes a subcommand; see `%s --help`", err, c.CommandPath(), c.CommandPath())
		}
		return usageErr("%v", err)
	})
	wrapArgs(root)
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
			var ids []string
			for _, id := range cfg.Profiles[n].PlatformIDs() {
				ids = append(ids, string(id))
			}
			out = append(out, fmt.Sprintf("%s\t%s", n, strings.Join(ids, ", ")))
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}

func completePlatforms(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
	return platformCandidates(), cobra.ShellCompDirectiveNoFileComp
}

func platformCandidates() []string {
	var out []string
	for _, p := range platform.Providers() {
		out = append(out, fmt.Sprintf("%s\t%s", p.ID(), p.DisplayName()))
	}
	return out
}

// completePlatformList completes the --platform filters of sync and
// inventory list, which take a list; the routing --platform of dns and
// domain takes one platform and uses completePlatforms.
var completePlatformList = completeList(platformCandidates)

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

// addRouteFlags adds --platform to a platform-neutral command group. Together
// with --profile it selects one account when a domain is known to several.
// It takes one platform, unlike the --platform filters of sync and
// inventory list, which take a list.
func addRouteFlags(rt *app.Runtime, cmd *cobra.Command) {
	cmd.PersistentFlags().StringVar(&rt.Flags.Platform, "platform", "", "route to the account on this platform")
	_ = cmd.RegisterFlagCompletionFunc("platform", completePlatforms)
}
