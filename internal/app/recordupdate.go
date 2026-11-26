package app

import (
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
)

// RecordNameHelp is the sentence every record command shows about its
// <name> and <type>; first is what the first argument is called ("zone",
// "domain").
func RecordNameHelp(first string) string {
	return strings.ReplaceAll(`<name> is relative to the {first} (www, a.b), @ for the apex, or a full name
inside the {first} (www.example.com). <type> is case-insensitive.`, "{first}", first)
}

// RecordArgsHelp is the paragraph the commands that write a record show
// about their positional record: RecordNameHelp, and how a value is typed.
func RecordArgsHelp(first string) string {
	return RecordNameHelp(first) + `
A value is one argument: quote one that contains spaces. A value that starts
with "-" goes after "--".`
}

// Help is the paragraph an update or delete command of the form shows about
// how it finds its record. first is what the first argument is called
// ("zone", "domain"), and list the command that shows the ids.
func (f RecordTargetForm) Help(first, list string) string {
	text := RecordNameHelp(first) + `
<type> and <value> narrow the selection and are needed only to tell records
apart. --id names one record by its id, as ` + "`{list}`" + `
shows it, and cannot be combined with a positional record.`
	sets := "records are listed to choose from"
	if f.NoValue {
		text = RecordNameHelp(first) + `
<type> is needed only to tell record sets apart.`
		sets = "record sets are listed to choose one"
	}
	if f.FormerID {
		text += `
The former form <{first}> <record-id> still works: a single argument after
the {first} that is the id of a record of the {first}, and not the name of
one, is taken for that id.`
	}
	text += `

On a terminal, a missing <{first}> is picked from a list, and with only the
{first} its {sets}.`
	return strings.NewReplacer("{first}", first, "{list}", list, "{sets}", sets).Replace(text)
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

// RecordSetDeleteHelp is the paragraph of a delete command of a platform
// that keeps the records of a name and type as one record set (Route 53,
// Cloud DNS) about when it needs the <type>.
const RecordSetDeleteHelp = `A name with one record set needs no <type>. A name with record sets of
several types is not deleted as a whole: on a terminal its record sets are
offered to pick one, and the non-interactive flow names the types and exits
with code 5, also with --yes. The SOA and NS sets of the zone apex are never
meant by the name alone.`

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
