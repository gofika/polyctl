package app

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
)

// RecordTargetHelp is the paragraph the update and delete commands of a
// platform with record ids show about how they find their record. first is
// what the first argument is called ("zone", "domain"), and list the
// command that shows the ids.
func RecordTargetHelp(first, list string) string {
	return strings.NewReplacer("{first}", first, "{list}", list).Replace(
		`<name> is relative to the {first} (www, a.b), @ for the apex, or a full name
inside the {first} (www.example.com). <type> and <value> narrow the
selection and are needed only to tell records apart; <type> is
case-insensitive. --id names one record by its id, as
` + "`{list}`" + ` shows it, and cannot be combined with a
positional record. The former form <{first}> <record-id> still works: a
single argument after the {first} that is the id of a record of the
{first}, and not the name of one, is taken for that id.

On a terminal, a missing <{first}> is picked from the {first}s of the
profile, and with only the {first} its records are listed to choose from.`)
}

// RecordUpdateHelp is the paragraph of an update command about the one
// record it changes.
const RecordUpdateHelp = `Exactly one record is updated. When several records match, the interactive
flow lists them to choose one, and the non-interactive flow lists them on
stderr and exits with code 5: add <type>, <value> or use --id.

Without a flag that changes something, the interactive flow asks for the new
value (the current one is the default); the non-interactive flow is a usage
error (exit code 2).`

// RecordDeleteHelp is the paragraph of a delete command about the records
// it deletes and when it asks.
const RecordDeleteHelp = `A name whose records all have one type needs no <type>. A name with records
of several types is not deleted as a whole: the interactive flow lists its
records to tick (ticking none deletes nothing), and the non-interactive flow
names the types and exits with code 5, also with --yes.

A single match is deleted at once. Several matches are listed on stderr with
their ids and a note on how to delete one of them only (<value> or --id), and
confirmed first (default no; a no deletes nothing, exit code 0); --yes skips
the question. The non-interactive flow asks nothing: --yes is required to
delete several records (exit code 2 without it).`

// RecordChanges reports whether one of flags, the flags of an update
// command that change the record, was given. Without any the interactive
// flow goes on (the command asks for the new value, see AskNewRecordValue)
// and the non-interactive flow gets a usage error that names the flags.
func (rt *Runtime) RecordChanges(cmd *cobra.Command, flags ...string) (bool, error) {
	for _, f := range flags {
		if cmd.Flags().Changed(f) {
			return true, nil
		}
	}
	if !rt.Interactive() {
		return false, UsageErrf("nothing to change: pass --%s", strings.Join(flags, ", --"))
	}
	return false, nil
}

// AskNewRecordValue asks for the new value of cur, the record an update
// command was given no change for; its value is the default. The same value
// again is "nothing to do" (exit code 0).
func (rt *Runtime) AskNewRecordValue(cur platform.Record) (string, error) {
	value, err := rt.AskRecordValue(strings.ToUpper(cur.Type), cur.Value)
	if err != nil {
		return "", err
	}
	if value == cur.Value {
		return "", NothingToDof("%s %s keeps the value %s", cur.Name, cur.Type, cur.Value)
	}
	return value, nil
}
