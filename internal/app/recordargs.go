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
	// TypeArg names the type in messages, for a record read by
	// RecordTargetForm.Parse: "<type>" for the positional form, "--type"
	// for the former flags.
	TypeArg string
	// formerID says a name alone may be the record id of a former form, and
	// noValue that the form the record was given in takes no value.
	formerID, noValue bool
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
// may be left out (a record that is selected, not written). partial lets
// the record stop after the name or the type: the interactive flow of a
// command that writes a record asks for the rest (see Runtime.RecordInput).
type recordShape struct {
	minValues, maxValues int
	typeOptional         bool
	partial              bool
}

// parse reads the positional record of cmd. args are the arguments after
// the <domain> or <zone>; without any there is no positional record and it
// returns nil, nil (the flags of the former form, or the interactive flow,
// then say what to write).
//
// Every mistake is a usage error: a wrong number of arguments (the message
// shows the usage of the positional form), an empty argument, and a
// positional record beside one of the flags of the former form. Those
// flags are --name, --type and --value unless formerFlags names the ones of
// the command. With typeOptional only the name is required: Type is "" when
// it was left out, and the command then finds out which records the name
// means (see RecordsOfName).
func (sh recordShape) parse(cmd *cobra.Command, args []string, formerFlags []string) (*RecordArgs, error) {
	if len(args) == 0 {
		return nil, nil
	}
	usage := sh.usage(cmd)
	n := len(args) - 2
	if sh.typeOptional && len(args) == 1 {
		n = 0
	}
	if (n < sh.minValues && !sh.partial) || (sh.maxValues >= 0 && n > sh.maxValues) {
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
// as RecordInput reads it. The interactive flow asks for what is left
// out: the domain, and the end of a record that stops after its name or
// its type (see Runtime.CompleteRecord). The non-interactive flow gets the
// usage text for both.
func RecordArgsOrInteractive(rt *Runtime, minValues, maxValues int, formerFlags ...string) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		sh := recordShape{minValues: minValues, maxValues: maxValues, partial: rt.Interactive()}
		return sh.argsOrInteractive(rt, formerFlags)(cmd, args)
	}
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
			return platform.KnownRecordTypes, cobra.ShellCompDirectiveNoFileComp
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
}

// NoFormerFlags is the formerFlags of a command whose --name, --type and
// --value are not a former form of the positional record (an update, where
// they are the new values): a positional record beside them is no mistake.
const NoFormerFlags = ""

// RecordTargetForm is the form of a command that acts on existing records
// (update, delete): `<zone> [<name> [<type> [<value>]]]`, with the flag --id
// as the exact selector when the command defines one. The zero value is that
// form and nothing else; the fields say what else the command takes. The
// commands validate their arguments (ArgsOrInteractive), read the record
// (Parse) and complete it (Complete) through it, so the checks and their
// messages are the same everywhere.
type RecordTargetForm struct {
	// FormerID says the command once took `<zone> <record-id>`: a single
	// argument after the zone may be that id (see RecordSelect.IDOrName).
	FormerID bool
	// FormerFlags are the flags of the former form that name the record,
	// of "name", "type" and "value" those the command still reads. A record
	// is given with them or positionally, not both, and never beside --id.
	// Without --name they name no record: they filter the list of the
	// interactive flow.
	FormerFlags []string
	// FormerApex says --type without --name meant the records of the zone
	// apex in the former form (Name is then "@").
	FormerApex bool
	// Instead are the flags that say what to act on without a record
	// ("all"): one of them cannot stand beside a positional record, and it
	// satisfies the non-interactive flow, which otherwise needs a record or
	// --id. What else it excludes is the command's to say.
	Instead []string
	// NoValue says the record is `<name> [<type>]` only: the command acts on
	// record sets as a whole.
	NoValue bool
}

func (f RecordTargetForm) shape() recordShape {
	sh := recordShape{maxValues: 1, typeOptional: true}
	if f.NoValue {
		sh.maxValues = 0
	}
	return sh
}

// record is the positional record of the form as usage text names it,
// "<name> [<type> [<value>]]".
func (f RecordTargetForm) record() string {
	if f.NoValue {
		return "<name> [<type>]"
	}
	return "<name> [<type> [<value>]]"
}

// Usage is the usage text of the positional form, "usage: polyctl dns
// delete <domain> <name> [<type> [<value>]]". The first argument is named as
// the usage line of cmd names it (<domain>, <zone>).
func (f RecordTargetForm) Usage(cmd *cobra.Command) string { return f.shape().usage(cmd) }

// changed are those of flags that were given, as "--name".
func changedFlags(cmd *cobra.Command, flags []string) []string {
	var given []string
	for _, name := range flags {
		if fl := cmd.Flags().Lookup(name); fl != nil && fl.Changed {
			given = append(given, "--"+name)
		}
	}
	return given
}

// orList joins items as "a", "a or b", "a, b or c".
func orList(items []string) string {
	if len(items) < 2 {
		return strings.Join(items, "")
	}
	return strings.Join(items[:len(items)-1], ", ") + " or " + items[len(items)-1]
}

// byID reports whether --id was given. An empty id (--id "$ID" with the
// variable unset) names no record and is a usage error: it is not "no
// --id", which would list the zone.
func (f RecordTargetForm) byID(cmd *cobra.Command) (bool, error) {
	fl := cmd.Flags().Lookup("id")
	if fl == nil || !fl.Changed {
		return false, nil
	}
	if strings.TrimSpace(fl.Value.String()) == "" {
		return false, UsageErrf("--id must not be empty")
	}
	return true, nil
}

// ArgsOrInteractive validates the arguments of the command: everything
// Parse refuses, and that the non-interactive flow was given the zone and a
// record, --id or one of the Instead flags, before anything is read. The
// interactive flow may leave out the record and the zone: the command lists
// what there is.
func (f RecordTargetForm) ArgsOrInteractive(rt *Runtime) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		rec, err := f.Parse(cmd, args)
		if err != nil {
			return err
		}
		if rt.Interactive() {
			return nil
		}
		byID, _ := f.byID(cmd)
		if len(args) > 0 && ((rec != nil && rec.Name != "") || byID || len(changedFlags(cmd, f.Instead)) > 0) {
			return nil
		}
		// See RangeArgsOrInteractive: an invalid POLYCTL_NON_INTERACTIVE
		// is reported rather than the missing argument it leads to.
		if err := CheckNonInteractiveEnv(); err != nil {
			return UsageErrf("%v", err)
		}
		need := []string{"a record"}
		if cmd.Flags().Lookup("id") != nil {
			need = append(need, "--id <record-id>")
		}
		for _, name := range f.Instead {
			need = append(need, "--"+name)
		}
		return UsageErrf("%s is required: %s", orList(need), f.Usage(cmd))
	}
}

// Parse reads the record the command was given, from its arguments (the
// zone first) or from the flags of the former form; nil when there is none
// (the record is named by --id, by an Instead flag, or listed). A record of
// the former flags without a name (Name "") names none either: its type and
// value filter the list. Every
// mistake is a usage error: a malformed record, a record given in both
// forms, a record beside --id or beside an Instead flag, an empty --id, and
// a <type> that is not one type.
func (f RecordTargetForm) Parse(cmd *cobra.Command, args []string) (*RecordArgs, error) {
	byID, err := f.byID(cmd)
	if err != nil {
		return nil, err
	}
	former := f.FormerFlags
	if len(former) == 0 {
		former = []string{NoFormerFlags}
	}
	instead := changedFlags(cmd, f.Instead)
	if len(args) > 1 {
		rec, err := f.shape().parse(cmd, args[1:], former)
		if err != nil {
			return nil, err
		}
		if strings.Contains(rec.Type, ",") {
			return nil, UsageErrf("<type> is one record type: %s", f.Usage(cmd))
		}
		if byID {
			return nil, UsageErrf("--id selects one record; it cannot be combined with %s", f.record())
		}
		if len(instead) > 0 {
			return nil, UsageErrf("%s cannot be combined with a positional record (%s)", orList(instead), f.record())
		}
		rec.TypeArg, rec.formerID, rec.noValue = "<type>", f.FormerID, f.NoValue
		return rec, nil
	}
	given := changedFlags(cmd, f.FormerFlags)
	if len(instead) > 0 || len(given) == 0 {
		return nil, nil
	}
	if byID {
		// The id selects one record; a filter beside it would be ignored,
		// and a wrong id would then act on an unrelated record.
		all := make([]string, len(f.FormerFlags))
		for i, name := range f.FormerFlags {
			all[i] = "--" + name
		}
		return nil, UsageErrf("--id selects one record; it cannot be combined with %s", orList(all))
	}
	rec := &RecordArgs{TypeArg: "--type", noValue: true}
	for _, name := range f.FormerFlags {
		if name == "value" {
			rec.noValue = false
		}
		fl := cmd.Flags().Lookup(name)
		if fl == nil || !fl.Changed {
			continue
		}
		v := strings.TrimSpace(fl.Value.String())
		if sv, ok := fl.Value.(interface{ GetSlice() []string }); ok {
			// A flag that takes several types for another mode (--all).
			vs := sv.GetSlice()
			if len(vs) != 1 || strings.Contains(vs[0], ",") {
				if len(f.Instead) > 0 {
					return nil, UsageErrf("--%s takes one record %s without --%s", name, name, f.Instead[0])
				}
				return nil, UsageErrf("--%s takes one record %s", name, name)
			}
			v = strings.TrimSpace(vs[0])
		}
		switch name {
		case "name":
			if rec.Name = v; v == "" {
				rec.Name = "@"
			}
		case "type":
			rec.Type = strings.ToUpper(v)
		case "value":
			if v != "" {
				rec.Values = []string{v}
			}
		}
	}
	if rec.Name == "" && rec.Type != "" && f.FormerApex {
		rec.Name = "@"
	}
	return rec, nil
}

// Select fills in what the record r says about the records meant in s,
// whose Zone is set: the full name, the type and the value, and how the
// type is named in messages (the form r was given in). For a command that
// once took `<zone> <record-id>`, a name alone may also be that record id
// (see RecordSelect.IDOrName). A nil r leaves s as it is: the records are
// named by s.ID, or listed.
func (r *RecordArgs) Select(s RecordSelect) RecordSelect {
	if r == nil {
		return s
	}
	s.Type, s.Value = r.Type, r.Value()
	if r.Name != "" {
		s.Name = platform.FQDN(r.Name, s.Zone)
	}
	if r.TypeArg != "" {
		s.TypeArg = r.TypeArg
	}
	s.NoValue = r.noValue
	if r.formerID && r.Type == "" && s.ID == "" {
		s.IDOrName = r.Name
	}
	return s
}

// Complete completes the arguments of the command: the first with first
// (the zones or domains), then the names of the records of the zone in the
// local inventory (relative to the zone, described by their types and
// values), the types the name has there and the values of the name and
// type. The records are those of the profile of platform id, or of every
// platform for a command that is not tied to one (id "").
func (f RecordTargetForm) Complete(rt *Runtime, first CompletionFunc, id platform.ID) CompletionFunc {
	max := 3
	if f.NoValue {
		max = 2
	}
	return func(cmd *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 0 {
			if first != nil {
				return first(cmd, args, toComplete)
			}
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		if len(args) > max {
			return nil, cobra.ShellCompDirectiveNoFileComp
		}
		var names []string
		desc := map[string][]string{}
		seen := map[string]bool{}
		out := []string{}
		recs, zone := cachedRecords(cmd, rt, id, args[0])
		for _, r := range recs {
			rel := platform.RelativeName(r.Name, zone)
			switch len(args) {
			case 1:
				if _, ok := desc[rel]; !ok {
					names = append(names, rel)
				}
				desc[rel] = append(desc[rel], strings.Join(strings.Fields(r.Type+" "+r.Value), " "))
			case 2:
				if t := strings.ToUpper(r.Type); platform.NormalizeDomain(r.Name) == platform.FQDN(args[1], zone) && !seen[t] {
					seen[t] = true
					out = append(out, t)
				}
			case 3:
				if platform.NormalizeDomain(r.Name) == platform.FQDN(args[1], zone) && strings.EqualFold(r.Type, args[2]) && !seen[r.Value] {
					seen[r.Value] = true
					out = append(out, r.Value)
				}
			}
		}
		for _, n := range names {
			out = append(out, n+"\t"+strings.Join(desc[n], ", "))
		}
		return out, cobra.ShellCompDirectiveNoFileComp
	}
}
