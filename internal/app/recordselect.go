package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// NameRecords is what a record name means in a zone for a command that
// selects records (delete): the records of the name, and the types they
// have. A command asks for a <type> only when Types holds several: one type
// is the answer already.
type NameRecords struct {
	// Zone is the zone name and Name the full record name, for messages.
	Zone, Name string
	// Records are the records selected: of Name, of the type and with the
	// value when those were given.
	Records []platform.Record
	// Types are the types of Records, sorted, each once.
	Types []string
}

// RecordsOfName selects the records of fqdn in the records of a zone, of
// typ and with value when those are given ("" is "any"). Without a type the
// SOA and the NS records of the zone apex are never meant: they are not
// deleted by name alone. No record selected is not found (exit code 4).
func RecordsOfName(zone string, recs []platform.Record, fqdn, typ, value string) (NameRecords, error) {
	n := NameRecords{Zone: platform.NormalizeDomain(zone), Name: platform.NormalizeDomain(fqdn)}
	seen := map[string]bool{}
	for _, r := range MatchRecords(recs, fqdn, typ, value) {
		t := strings.ToUpper(r.Type)
		if typ == "" && n.Name == n.Zone && (t == "SOA" || t == "NS") {
			continue
		}
		n.Records = append(n.Records, r)
		if !seen[t] {
			seen[t] = true
			n.Types = append(n.Types, t)
		}
	}
	sort.Strings(n.Types)
	if len(n.Records) == 0 {
		return n, fmt.Errorf("%w: no matching record in zone %s", platform.ErrNotFound, n.Zone)
	}
	return n, nil
}

// Type is the one type of the records, "" when they have several.
func (n NameRecords) Type() string {
	if len(n.Types) == 1 {
		return n.Types[0]
	}
	return ""
}

// AmbiguousType is the error of a name with records of several types where
// nothing can be asked (exit code 5): it names the types and says to give
// typeArg ("<type>", "--type").
func (n NameRecords) AmbiguousType(typeArg string) error {
	return fmt.Errorf("%w: %s has records of %d types in zone %s (%s); give %s to say which (nothing was deleted)",
		platform.ErrAmbiguous, n.Name, len(n.Types), n.Zone, strings.Join(n.Types, ", "), typeArg)
}

// NeedsType reports whether the type of the records is still open: false
// when they have one type. With several, the non-interactive flow gets
// AmbiguousType (also with --yes: several types are never deleted in one
// go by a name alone) and the interactive flow true, after a line that says
// that the name has records of several types: the command then offers its
// list (PickRecords, or the record sets of the name).
func (rt *Runtime) NeedsType(n NameRecords, typeArg string) (bool, error) {
	if len(n.Types) <= 1 {
		return false, nil
	}
	if !rt.Interactive() {
		return false, n.AmbiguousType(typeArg)
	}
	rt.Infof("%s has records of %d types (%s)", n.Name, len(n.Types), strings.Join(n.Types, ", "))
	return true, nil
}

// ExactRecordHint says how to delete one record of several, for
// RecordDelete.Exact: by its value when the command takes one (byValue),
// by its id with --id when it takes that (byID). typeArg is the type
// argument of the form the command was called in: "<type>" names the
// positional <value>, "--type" the former --value. "" for a command that
// has neither.
func ExactRecordHint(typeArg string, byValue, byID bool) string {
	var ways []string
	if byValue {
		if typeArg == "--type" {
			ways = append(ways, "its value with --value")
		} else {
			ways = append(ways, "its <value> after the <type>")
		}
	}
	if byID {
		ways = append(ways, "its id with --id <id>")
	}
	if len(ways) == 0 {
		return ""
	}
	return "give " + strings.Join(ways, ", or ")
}

// PickRecords asks which of recs to act on (a multiple choice, nothing
// ticked), labelled as PickRecordID labels them: "name  type  value  ttl
// 300  proxied  [note]  id". A record without an id cannot be picked and is
// left out. Ticking nothing is "nothing to do" (exit code 0).
func (rt *Runtime) PickRecords(title, what string, recs []platform.Record, mark func(platform.Record) string) ([]platform.Record, error) {
	byID := map[string]platform.Record{}
	var opts []prompt.Option
	for _, r := range recs {
		if strings.TrimSpace(r.ID) == "" {
			continue
		}
		byID[r.ID] = r
		opts = append(opts, prompt.Option{Label: recordOptionLabel(r, mark), Value: r.ID})
	}
	ids, err := rt.ChooseMany(Choice{Title: title, Options: opts, What: what})
	if err != nil {
		return nil, err
	}
	out := make([]platform.Record, 0, len(ids))
	for _, id := range ids {
		out = append(out, byID[id])
	}
	return out, nil
}

// recordOptionLabel is the label of a record in PickRecordID and
// PickRecords: RecordLabel, the note of mark in brackets, and the id.
func recordOptionLabel(r platform.Record, mark func(platform.Record) string) string {
	note := ""
	if mark != nil {
		if m := mark(r); m != "" {
			note = "[" + m + "]"
		}
	}
	return RecordLabel(r, note, r.ID)
}

// RecordDelete is the confirmation of a record delete command that is
// about to delete several records, or a whole record set.
type RecordDelete struct {
	// Records lists what would be deleted, with the ids (the record grid
	// of the command).
	Records output.Grid
	// Question is asked (default no): "delete 3 records in zone
	// example.com".
	Question string
	// Refusal names the deletion in the refusal of the non-interactive
	// flow without --yes ("would <Refusal>"), for a Question that does not
	// read as one: "delete the A record set of www.example.com". Default:
	// Question.
	Refusal string
	// Exact says how to delete one of the records only: "give its <value>,
	// or --id <id>". "" for a command that has no way to; it is not shown
	// for a single record.
	Exact string
}

// ConfirmRecordDelete is the one confirmation of the record delete
// commands. With --yes nothing is shown or asked. Otherwise the records are
// listed on stderr with their ids, a line says how many there are and how
// to delete one of them only, and the question is asked (default no). A no
// is "nothing to do" (exit code 0) with that hint again; the
// non-interactive flow gets the usage error of Confirm, after the list.
func (rt *Runtime) ConfirmRecordDelete(ctx context.Context, d RecordDelete) error {
	if rt.Flags.Yes {
		return nil
	}
	_ = output.RenderGrid(rt.Stderr, d.Records)
	hint := ""
	if d.Exact != "" && len(d.Records.Rows) > 1 {
		hint = "to delete one of them only, " + d.Exact
		rt.Infof("%d records match; %s", len(d.Records.Rows), hint)
	}
	if d.Refusal != "" {
		if err := rt.CanConfirm(d.Refusal); err != nil {
			return err
		}
	}
	ok, err := rt.Confirm(ctx, d.Question, false)
	if err != nil {
		return err
	}
	if !ok {
		return NoRecordDeleted(hint)
	}
	return nil
}

// NoRecordDeleted is the declined confirmation of every record delete
// command: "nothing to do" (exit code 0), with hint (how to delete one
// record only) when there is one.
func NoRecordDeleted(hint string) error {
	if hint != "" {
		return NothingToDof("no record was deleted; %s", hint)
	}
	return NothingToDof("no record was deleted")
}
