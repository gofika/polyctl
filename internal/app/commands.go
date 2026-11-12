package app

import (
	"encoding/json"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
)

// Whoami is the result of `<platform> whoami`. It has the same shape in
// every platform tree; what differs is which Identity fields a platform can
// fill in.
type Whoami struct {
	Profile  string             `json:"profile" yaml:"profile"`
	Platform platform.ID        `json:"platform" yaml:"platform"`
	Identity *platform.Identity `json:"identity" yaml:"identity"`
}

// WhoamiCommand returns the `whoami` command of a platform tree: it checks
// the account's credentials against the platform (Client.Verify) and shows
// who they belong to. Every tree mounts it at its top level, so the
// identity check is spelled the same on all platforms. detail is the
// platform's own paragraph of the help, wrapped by the caller.
func WhoamiCommand(rt *Runtime, id platform.ID, detail string) *cobra.Command {
	return &cobra.Command{
		Use:   "whoami",
		Short: "Verify the account's credentials and show the identity behind them",
		Long: "Verify the credentials of the selected profile's account against the\n" +
			"platform and show the identity behind them.\n\n" + detail + "\n\n" +
			"The output has the same shape on every platform: profile, platform, account\n" +
			"and user, followed by what else the platform reports. It needs the network,\n" +
			"so it fails with --offline; credentials that no longer work exit with code 3.",
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			if rt.Flags.Offline {
				return ErrOffline
			}
			c, prof, err := rt.OpenFor(cmd.Context(), id)
			if err != nil {
				return err
			}
			ident, err := c.Verify(cmd.Context())
			if err != nil {
				return err
			}
			if ident == nil {
				ident = &platform.Identity{}
			}
			w := Whoami{Profile: prof.Name, Platform: id, Identity: ident}
			return rt.Render(w, func() output.Grid {
				pairs := []string{"PROFILE", w.Profile, "PLATFORM", string(id), "ACCOUNT", ident.Account, "USER", ident.User}
				keys := make([]string, 0, len(ident.Extra))
				for k := range ident.Extra {
					keys = append(keys, k)
				}
				sort.Strings(keys)
				for _, k := range keys {
					pairs = append(pairs, strings.ToUpper(strings.ReplaceAll(k, "_", " ")), ident.Extra[k])
				}
				return output.KV(pairs...)
			})
		},
	}
}

// RecordIDArgs validates the arguments of a command that addresses one
// record by its id: `<verb> <zone-or-domain> <record-id>`. A missing id is
// reported by name, with the usage line, instead of as a bare argument
// count.
func RecordIDArgs(cmd *cobra.Command, args []string) error {
	switch {
	case len(args) < 2:
		return UsageErrf("the record id is required (see the list command of this group for the ids): %s", cmd.UseLine())
	case len(args) > 2:
		return UsageErrf("expected 2 arguments, got %d: %s", len(args), cmd.UseLine())
	}
	if strings.TrimSpace(args[1]) == "" {
		return UsageErrf("the record id must not be empty: %s", cmd.UseLine())
	}
	return nil
}

// NameserverArgs validates the arguments of an `ns set` command: the domain
// and at least one nameserver.
func NameserverArgs(cmd *cobra.Command, args []string) error {
	switch len(args) {
	case 0:
		return UsageErrf("the domain and at least one nameserver are required: %s", cmd.UseLine())
	case 1:
		return UsageErrf("at least one nameserver is required: %s", cmd.UseLine())
	}
	return nil
}

// Nameservers reads the <nameserver>... arguments of an `ns set` command
// (see platform.Nameservers); a malformed list is a usage error.
func Nameservers(args []string) ([]string, error) {
	ns, err := platform.Nameservers(args)
	if err != nil {
		return nil, UsageErrf("%v", err)
	}
	return ns, nil
}

// NameserverHelp is the paragraph every `ns set` command shows about its
// nameserver arguments.
const NameserverHelp = "Pass one argument per nameserver; an argument may also be a comma-separated\nlist."

// ProxiedArgs wraps the argument validator of a command with a boolean
// --proxied flag. `--proxied true` (the spelling of polyctl 0.1.x, where
// the flag took a value) leaves a stray "true" or "false" argument behind;
// that is reported by name instead of as an argument count, or, worse, taken
// for a record id.
func ProxiedArgs(v cobra.PositionalArgs) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if f := cmd.Flags().Lookup("proxied"); f != nil && f.Changed {
			for _, a := range args {
				if a == "true" || a == "false" {
					return UsageErrf("--proxied takes no separate value (got %q): write --proxied or --proxied=false", a)
				}
			}
		}
		return v(cmd, args)
	}
}

// CompletionFunc is the signature of cobra's argument completion.
type CompletionFunc = func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective)

// CompleteDomainArg completes the first argument of a platform command with
// the zones and domains of that platform in the local inventory. Later
// arguments (nameservers, free-form values) complete to nothing rather than
// to file names.
func CompleteDomainArg(rt *Runtime, id platform.ID) CompletionFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) > 0 {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		return cachedDomains(cmd, rt, id), cobra.ShellCompDirectiveNoFileComp
	}
}

// CompleteRecordIDArgs completes `<zone-or-domain> <record-id>`: the first
// argument like CompleteDomainArg, the second with the ids of the zone's
// records in the local inventory, described as "TYPE name value".
func CompleteRecordIDArgs(rt *Runtime, id platform.ID) CompletionFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			return cachedDomains(cmd, rt, id), cobra.ShellCompDirectiveNoFileComp
		case 1:
			return cachedRecordIDs(cmd, rt, id, args[0]), cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

// completionRows lists inventory rows of the account a platform command
// would use. Completion never fails loudly: without an account or a cache
// there is simply nothing to offer.
func completionRows(cmd *cobra.Command, rt *Runtime, id platform.ID, q inventory.Query) []inventory.Resource {
	profile, err := rt.ProfileFor(id)
	if err != nil {
		return nil
	}
	db, err := rt.DB()
	if err != nil {
		return nil
	}
	q.Platform, q.Profile = id, profile
	rows, err := db.List(cmd.Context(), q)
	if err != nil {
		return nil
	}
	return rows
}

func cachedDomains(cmd *cobra.Command, rt *Runtime, id platform.ID) []string {
	seen := map[string]bool{}
	out := []string{}
	for _, t := range []platform.ResourceType{platform.ResZone, platform.ResDomain} {
		for _, r := range completionRows(cmd, rt, id, inventory.Query{Type: t}) {
			if r.Name != "" && !seen[r.Name] {
				seen[r.Name] = true
				out = append(out, r.Name)
			}
		}
	}
	sort.Strings(out)
	return out
}

func cachedRecordIDs(cmd *cobra.Command, rt *Runtime, id platform.ID, zone string) []string {
	out := []string{}
	for _, r := range completionRows(cmd, rt, id, inventory.Query{Type: platform.ResDNSRecord, Domain: zone}) {
		if r.ID == "" {
			continue
		}
		var rec platform.Record
		_ = json.Unmarshal(r.Data, &rec)
		desc := strings.Join(strings.Fields(rec.Type+" "+r.Name+" "+rec.Value), " ")
		out = append(out, r.ID+"\t"+desc)
	}
	return out
}

// CompletePlatformArgs gives every command of a platform tree that has no
// argument completion of its own one that fits its usage line, so that no
// positional argument falls back to the shell's file name completion:
// a leading <domain> or <zone> completes from the platform's cached zones
// and domains, a following <record-id> from the cached records of that
// zone, and everything else (nameservers, instance ids, names to check)
// completes to nothing.
func CompletePlatformArgs(rt *Runtime, id platform.ID, cmd *cobra.Command) {
	for _, c := range cmd.Commands() {
		CompletePlatformArgs(rt, id, c)
	}
	if cmd.HasSubCommands() || cmd.ValidArgsFunction != nil || len(cmd.ValidArgs) > 0 {
		return
	}
	words := strings.Fields(cmd.Use)[1:]
	switch {
	case len(words) > 1 && isDomainArg(words[0]) && words[1] == "<record-id>":
		cmd.ValidArgsFunction = CompleteRecordIDArgs(rt, id)
	case len(words) > 0 && isDomainArg(words[0]):
		cmd.ValidArgsFunction = CompleteDomainArg(rt, id)
	default:
		cmd.ValidArgsFunction = cobra.NoFileCompletions
	}
}

func isDomainArg(word string) bool { return word == "<domain>" || word == "<zone>" }
