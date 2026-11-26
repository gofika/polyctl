package app

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
)

// RecordArgs is the positional record of a record command: the arguments
// that follow the <domain> or <zone>, written like a zone file line,
// <name> <type> <value>...
type RecordArgs struct {
	// Name is as typed: relative to the zone ("www", "a.b"), "@" for the
	// apex, or a full name inside the zone.
	Name string
	// Type is upper-cased.
	Type string
	// Values holds one value per argument, in the order given.
	Values []string
}

// Value is the first value, "" when the record was given without one.
func (r *RecordArgs) Value() string {
	if r == nil || len(r.Values) == 0 {
		return ""
	}
	return r.Values[0]
}

// formerRecordFlags are the flags of the former form of a record command.
var formerRecordFlags = []string{"name", "type", "value"}

// recordShape says what the positional record of a command takes: minValues
// to maxValues values (maxValues < 0: any number), and whether the <type>
// may be left out (a record that is selected, not written).
type recordShape struct {
	minValues, maxValues int
	typeOptional         bool
}

// ParseRecordArgs reads the positional record of cmd. args are the
// arguments after the <domain> or <zone>; without any there is no
// positional record and it returns nil, nil (the flags of the former form,
// or the interactive flow, then say what to write).
//
// The record takes minValues to maxValues values (maxValues < 0: any
// number). Every mistake is a usage error: a wrong number of arguments (the
// message shows RecordUsage), an empty argument, and a positional record
// beside one of the flags of the former form. Those flags are --name,
// --type and --value unless formerFlags names the ones of the command.
func ParseRecordArgs(cmd *cobra.Command, args []string, minValues, maxValues int, formerFlags ...string) (*RecordArgs, error) {
	return recordShape{minValues: minValues, maxValues: maxValues}.parse(cmd, args, formerFlags)
}

// ParseRecordSelector reads the positional record of a command that
// selects records instead of writing one (delete): <name> [<type>
// [<value>]], at most maxValues values. Only the name is required: Type is
// "" when it was left out, and the command then finds out which records the
// name means (see RecordsOfName). Otherwise it is ParseRecordArgs.
func ParseRecordSelector(cmd *cobra.Command, args []string, maxValues int, formerFlags ...string) (*RecordArgs, error) {
	return recordShape{maxValues: maxValues, typeOptional: true}.parse(cmd, args, formerFlags)
}

func (sh recordShape) parse(cmd *cobra.Command, args []string, formerFlags []string) (*RecordArgs, error) {
	if len(args) == 0 {
		return nil, nil
	}
	usage := sh.usage(cmd)
	n := len(args) - 2
	if sh.typeOptional && len(args) == 1 {
		n = 0
	}
	if n < sh.minValues || (sh.maxValues >= 0 && n > sh.maxValues) {
		return nil, UsageErrf("%s", usage)
	}
	if len(formerFlags) == 0 {
		formerFlags = formerRecordFlags
	}
	var given []string
	for _, name := range formerFlags {
		if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
			given = append(given, "--"+name)
		}
	}
	if len(given) > 0 {
		return nil, UsageErrf("the record is given both as arguments and with %s; use one form: %s",
			strings.Join(given, ", "), usage)
	}
	rec := &RecordArgs{Name: strings.TrimSpace(args[0])}
	if rec.Name == "" {
		return nil, UsageErrf("<name> must not be empty (@ is the zone apex): %s", usage)
	}
	if len(args) == 1 {
		return rec, nil
	}
	rec.Type, rec.Values = strings.ToUpper(strings.TrimSpace(args[1])), args[2:]
	if rec.Type == "" {
		return nil, UsageErrf("<type> must not be empty: %s", usage)
	}
	for _, v := range rec.Values {
		if strings.TrimSpace(v) == "" {
			return nil, UsageErrf("<value> must not be empty: %s", usage)
		}
	}
	return rec, nil
}

// RecordUsage is the usage text of the positional form of a record command,
// "usage: polyctl dns set <domain> <name> <type> <value>". The first
// argument is named as the usage line of cmd names it (<domain>, <zone>).
func RecordUsage(cmd *cobra.Command, minValues, maxValues int) string {
	return recordShape{minValues: minValues, maxValues: maxValues}.usage(cmd)
}

// RecordSelectorUsage is RecordUsage for a command that reads its record
// with ParseRecordSelector, "usage: polyctl dns delete <domain> <name>
// [<type> [<value>]]".
func RecordSelectorUsage(cmd *cobra.Command, maxValues int) string {
	return recordShape{maxValues: maxValues, typeOptional: true}.usage(cmd)
}

func (sh recordShape) usage(cmd *cobra.Command) string {
	first := "<domain>"
	if words := strings.Fields(cmd.Use); len(words) > 1 {
		first = strings.Trim(words[1], "[]")
	}
	value := "<value>"
	if sh.maxValues < 0 || sh.maxValues > 1 {
		value += "..."
	}
	if sh.minValues == 0 {
		value = "[" + value + "]"
	}
	if sh.maxValues == 0 {
		value = ""
	}
	record := strings.TrimSpace("<type> " + value)
	if sh.typeOptional {
		record = "[" + record + "]"
	}
	return "usage: " + cmd.CommandPath() + " " + first + " <name> " + record
}

// RecordArgsOrInteractive validates the arguments of a record command:
// the <domain> or <zone> alone (the flags of the former form, or the
// interactive flow, say what to write), or followed by a positional record
// as ParseRecordArgs reads it. Without any argument the interactive flow
// asks for the domain; the non-interactive flow gets the usage text.
func RecordArgsOrInteractive(rt *Runtime, minValues, maxValues int, formerFlags ...string) cobra.PositionalArgs {
	return recordShape{minValues: minValues, maxValues: maxValues}.argsOrInteractive(rt, formerFlags)
}

// RecordSelectorArgsOrInteractive is RecordArgsOrInteractive for a command
// that reads its record with ParseRecordSelector.
func RecordSelectorArgsOrInteractive(rt *Runtime, maxValues int, formerFlags ...string) cobra.PositionalArgs {
	return recordShape{maxValues: maxValues, typeOptional: true}.argsOrInteractive(rt, formerFlags)
}

func (sh recordShape) argsOrInteractive(rt *Runtime, formerFlags []string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) == 0 {
			if rt.Interactive() {
				return nil
			}
			// See RangeArgsOrInteractive: an invalid POLYCTL_NON_INTERACTIVE
			// is reported rather than the missing argument it leads to.
			if err := CheckNonInteractiveEnv(); err != nil {
				return UsageErrf("%v", err)
			}
			return UsageErrf("%s", sh.usage(cmd))
		}
		_, err := sh.parse(cmd, args[1:], formerFlags)
		return err
	}
}

// CompleteRecordArgs completes the arguments of a record command: the first
// with first (the domains or zones), the <type> position with the record
// types, and the name and the values with nothing rather than file names.
// The types are those the provider of platform id can write when it says
// so; id is "" for a command that is not tied to one platform.
func CompleteRecordArgs(first CompletionFunc, id platform.ID) CompletionFunc {
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		switch len(args) {
		case 0:
			if first != nil {
				return first(cmd, args, toComplete)
			}
		case 2:
			if id != "" {
				if types := platform.WritableRecordTypes(id); len(types) > 0 {
					return types, cobra.ShellCompDirectiveNoFileComp
				}
			}
			return platform.RecordSpecTypes, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}
