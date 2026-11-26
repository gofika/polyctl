package app

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/gofika/polyctl/internal/inventory"
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
// has neither. more are further ways of the command ("its line with
// --line"), named before the id.
func ExactRecordHint(typeArg string, byValue, byID bool, more ...string) string {
	var ways []string
	if byValue {
		if typeArg == "--type" {
			ways = append(ways, "its value with --value")
		} else {
			ways = append(ways, "its <value> after the <type>")
		}
	}
	ways = append(ways, more...)
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

// RecordSelect says which records of a zone a command acts on: the one way
// the record commands find their records, by name, by id or from a list.
type RecordSelect struct {
	// Zone is the zone name and Records are its records, read live.
	Zone    string
	Records []platform.Record
	// Name is the full name of the records meant, "" when none was given:
	// the records of the zone are then listed to choose from. Type and
	// Value narrow the selection ("" is "any").
	Name, Type, Value string
	// Qualifiers are what else the platform tells records of one name, type
	// and value apart with (the line of an Alibaba Cloud record). One that
	// was given narrows the selection as Type and Value do; one that was not
	// is named as a way to say which record is meant when the candidates
	// differ in it.
	Qualifiers []RecordQualifier
	// ID is the exact selector (--id): the record with this id, whatever
	// Name, Type and Value say.
	ID string
	// IDOrName is the one argument after the zone as it was typed, when
	// nothing else was given: the <name>, or the record id of the former
	// form `<zone> <record-id>`. It is taken for an id when a record of
	// the zone has that id and no record has that name; an argument that
	// is both an id and a name is ambiguous (exit code 5). Name is the
	// full name it would be.
	IDOrName string
	// IDMatches reports whether id names r, for a platform whose ids have
	// several spellings; nil compares with the id of the record.
	IDMatches func(id string, r platform.Record) bool
	// One says the command acts on exactly one record (update): several
	// matches are a list to choose one from on a terminal and exit code 5
	// without one, never all of them. Without it (delete) the records of
	// one type are all selected and those of several types are a list to
	// tick, or exit code 5 (see NeedsType).
	One bool
	// Verb starts the title of a list: "Delete", "Update".
	Verb string
	// TypeArg names the type argument in messages: "<type>" (the default)
	// or "--type".
	TypeArg string
	// NoValue says the form the command was called in has no way to give a
	// value: none is named as a way to say which record is meant.
	NoValue bool
	// Offer filters the records a list offers (the records a delete may
	// touch, see DeletableRecords); nil offers every record. Mark adds a
	// note to a record in a list (the service owning it).
	Offer func([]platform.Record) []platform.Record
	Mark  func(platform.Record) string
	// Grid is the record grid of the command: the candidates of an
	// ambiguous selection are listed with it. nil lists them as the lists
	// label them.
	Grid func([]platform.Record) output.Grid
	// List replaces the list of the command: of is what the records are of
	// (the zone name, or the full name of the records), recs the
	// candidates. It returns the records chosen.
	List func(of string, recs []platform.Record) ([]platform.Record, error)
}

// RecordQualifier is one more fact that tells records apart on a platform,
// given with a flag.
type RecordQualifier struct {
	// Flag is how the command takes it ("--line") and Noun what it is
	// called ("line").
	Flag, Noun string
	// Value is what was given, "" for "any".
	Value string
	// Of is the fact of a record.
	Of func(platform.Record) string
}

// RecordSelection is the answer of SelectRecords.
type RecordSelection struct {
	// Records are the records selected, never empty.
	Records []platform.Record
	// Listed says they were chosen from a list, one by one. ByID says the
	// one record was named by its id.
	Listed, ByID bool
}

// Type is the one type of the records selected, "" when they have several.
func (s RecordSelection) Type() string {
	typ := ""
	for i, r := range s.Records {
		t := strings.ToUpper(r.Type)
		if i > 0 && t != typ {
			return ""
		}
		typ = t
	}
	return typ
}

// SelectRecords finds the records s means. An id selects its record, which
// must have every qualifier given (not found otherwise). A name
// selects its records, of the type and with the value when those are given:
// see RecordSelect.One for what several of them mean. Without a name the
// records of the zone (of the type and with the value, when given) are
// listed to choose from, which needs the interactive flow: a command checks
// before it reads the zone that the non-interactive flow was given a
// record. Nothing found is not found (exit code 4).
func (rt *Runtime) SelectRecords(s RecordSelect) (RecordSelection, error) {
	zone := platform.NormalizeDomain(s.Zone)
	if s.TypeArg == "" {
		s.TypeArg = "<type>"
	}
	if s.ID == "" && s.IDOrName != "" {
		named := MatchRecords(s.Records, s.Name, "", "")
		switch byID := s.withID(s.IDOrName); {
		case len(byID) > 0 && len(named) > 0:
			return RecordSelection{}, fmt.Errorf("%w: %s is the id of a record and the name of %d record(s) in zone %s; pass --id %s for the record with that id, or the full name %s for the records of the name",
				platform.ErrAmbiguous, s.IDOrName, len(named), zone, s.IDOrName, platform.NormalizeDomain(s.Name))
		case len(byID) > 0:
			s.ID = s.IDOrName
		case len(named) == 0:
			return RecordSelection{}, fmt.Errorf("%w: no record with the name or the id %s in zone %s", platform.ErrNotFound, s.IDOrName, zone)
		}
	}
	switch {
	case s.ID != "":
		recs := s.withID(s.ID)
		switch len(recs) {
		case 0:
			return RecordSelection{}, fmt.Errorf("%w: no record with the id %s in zone %s", platform.ErrNotFound, s.ID, zone)
		case 1:
			// A qualifier that was given holds for the record named by its
			// id too (the former form <zone> <record-id> beside --line):
			// a record on another line is not the one meant.
			for _, q := range s.Qualifiers {
				if q.Value != "" && !strings.EqualFold(q.Of(recs[0]), q.Value) {
					return RecordSelection{}, fmt.Errorf("%w: the record with the id %s in zone %s has the %s %s, not %s (%s); nothing was changed",
						platform.ErrNotFound, s.ID, zone, q.Noun, q.Of(recs[0]), q.Value, q.Flag)
				}
			}
			return RecordSelection{Records: recs, ByID: true}, nil
		}
		ids := make([]string, len(recs))
		for i, r := range recs {
			ids[i] = r.ID
		}
		return RecordSelection{}, fmt.Errorf("%w: record id %q matches %d records in zone %s (%s); pass the id of one of them",
			platform.ErrAmbiguous, s.ID, len(recs), zone, strings.Join(ids, ", "))
	case s.Name == "":
		if !rt.Interactive() {
			return RecordSelection{}, UsageErrf("a record is required: its <name>, or --id")
		}
		var cands []platform.Record
		for _, r := range s.qualified() {
			if (s.Type == "" || strings.EqualFold(r.Type, s.Type)) && (s.Value == "" || platform.RecordValueMatches(r, s.Value)) {
				cands = append(cands, r)
			}
		}
		return s.list(rt, zone, zone, cands)
	}
	found, err := RecordsOfName(zone, s.qualified(), s.Name, s.Type, s.Value)
	if err != nil {
		return RecordSelection{}, err
	}
	if s.One {
		if len(found.Records) == 1 {
			return RecordSelection{Records: found.Records}, nil
		}
		what := fmt.Sprintf("%s has %d records", found.Name, len(found.Records))
		if t := found.Type(); t != "" && (s.Type != "" || s.Value != "") {
			what = fmt.Sprintf("%d %s records of %s match", len(found.Records), t, found.Name)
		}
		if !rt.Interactive() {
			s.show(rt, found.Records)
			return RecordSelection{}, fmt.Errorf("%w: %s in zone %s; %s to say which (nothing was changed)",
				platform.ErrAmbiguous, what, zone, s.exactHint(found))
		}
		rt.Infof("%s", what)
		return s.list(rt, zone, found.Name, found.Records)
	}
	open, err := rt.NeedsType(found, s.TypeArg)
	if err != nil {
		return RecordSelection{}, err
	}
	if open {
		return s.list(rt, zone, found.Name, found.Records)
	}
	return RecordSelection{Records: found.Records}, nil
}

// qualified are the records of the zone that have every qualifier given.
func (s RecordSelect) qualified() []platform.Record {
	recs := s.Records
	for _, q := range s.Qualifiers {
		if q.Value == "" {
			continue
		}
		var keep []platform.Record
		for _, r := range recs {
			if strings.EqualFold(q.Of(r), q.Value) {
				keep = append(keep, r)
			}
		}
		recs = keep
	}
	return recs
}

// openQualifiers are the ways to name one of recs with a qualifier that
// was not given: those recs differ in ("its line with --line").
func (s RecordSelect) openQualifiers(recs []platform.Record) []string {
	var ways []string
	for _, q := range s.Qualifiers {
		if q.Value != "" {
			continue
		}
		for _, r := range recs[1:] {
			if !strings.EqualFold(q.Of(r), q.Of(recs[0])) {
				ways = append(ways, "its "+q.Noun+" with "+q.Flag)
				break
			}
		}
	}
	return ways
}

// Exact says how to delete one of the records chosen only, for
// RecordsDelete.Exact: "" when they were ticked in a list.
func (s RecordSelect) Exact(chosen RecordSelection) string {
	if chosen.Listed || len(chosen.Records) == 0 {
		return ""
	}
	typeArg := s.TypeArg
	if typeArg == "" {
		typeArg = "<type>"
	}
	return ExactRecordHint(typeArg, !s.NoValue, true, s.openQualifiers(chosen.Records)...)
}

// withID are the records id names.
func (s RecordSelect) withID(id string) []platform.Record {
	var out []platform.Record
	for _, r := range s.Records {
		if r.ID == id || (r.ID != "" && s.IDMatches != nil && s.IDMatches(id, r)) {
			out = append(out, r)
		}
	}
	return out
}

// list offers recs, the records of of (the zone, or a name of it), to
// choose from: one for RecordSelect.One, any number otherwise.
func (s RecordSelect) list(rt *Runtime, zone, of string, recs []platform.Record) (RecordSelection, error) {
	if s.Offer != nil {
		recs = s.Offer(recs)
	}
	var chosen []platform.Record
	var err error
	switch {
	case s.List != nil:
		chosen, err = s.List(of, recs)
	case s.One:
		var id string
		if id, err = rt.PickRecordID(s.Verb+" which record of "+of+"?", recs, s.Mark); err == nil {
			for _, r := range recs {
				if r.ID == id {
					chosen = []platform.Record{r}
					break
				}
			}
		}
	default:
		chosen, err = rt.PickRecords(s.Verb+" which records of "+of+"?", "record in zone "+zone, recs, s.Mark)
	}
	if err != nil {
		return RecordSelection{}, err
	}
	if len(chosen) == 0 {
		return RecordSelection{}, fmt.Errorf("%w: no matching record in zone %s", platform.ErrNotFound, zone)
	}
	return RecordSelection{Records: chosen, Listed: true}, nil
}

// show lists the candidates of an ambiguous selection on stderr.
func (s RecordSelect) show(rt *Runtime, recs []platform.Record) {
	if s.Grid != nil {
		_ = output.RenderGrid(rt.Stderr, s.Grid(recs))
		return
	}
	for _, r := range recs {
		rt.Infof("%s", recordOptionLabel(r, s.Mark))
	}
}

// exactHint says how to name one of the records of n: with what was not
// given yet and tells them apart, or with the id.
func (s RecordSelect) exactHint(n NameRecords) string {
	var ways []string
	if s.Type == "" && len(n.Types) > 1 {
		ways = append(ways, "its "+s.TypeArg)
	}
	if s.Value == "" && !s.NoValue {
		ways = append(ways, "its <value> after the <type>")
	}
	ways = append(ways, s.openQualifiers(n.Records)...)
	ways = append(ways, "its id with --id <id>")
	return "give " + strings.Join(ways, ", or ")
}

// DeletableRecords are the two hooks of a RecordSelect that deletes: offer
// keeps the records a delete may touch (every record but the zone's own,
// SOA and apex NS, and those without an id), and mark names the service
// that owns a record (the R2 bucket of a custom domain), which is then
// deleted by unbinding it there.
func DeletableRecords(dns platform.DNSService, zone platform.Zone) (offer func([]platform.Record) []platform.Record, mark func(platform.Record) string) {
	owners := map[string]string{}
	offer = func(recs []platform.Record) []platform.Record {
		var out []platform.Record
		for _, it := range platform.ClassifyDeleteAll(platform.DNSDeleteAll{Zone: zone, DNS: dns, Records: recs}) {
			if it.Disposition != platform.DispNormal && it.Disposition != platform.DispBound {
				continue
			}
			out = append(out, it.Record)
			owners[it.Record.ID] = it.Owner
		}
		return out
	}
	return offer, func(r platform.Record) string { return owners[r.ID] }
}

// RecordsDelete is the deletion of the records a command selected
// (SelectRecords) on a platform that addresses records by id.
type RecordsDelete struct {
	// Target is the account for the change report and the messages, Zone
	// the zone of the records and DNS the service that deletes them.
	Target platform.Target
	Zone   platform.Zone
	DNS    platform.DNSService
	// Records are deleted; a record owned by another service of the
	// platform (platform.RecordUnbinder) is unbound there instead.
	Records []platform.Record
	// Grid is the record grid of the command, for the confirmation.
	Grid func([]platform.Record) output.Grid
	// Exact says how to delete one of the records only (ExactRecordHint),
	// "" when they were ticked in a list.
	Exact string
}

// DeleteRecords deletes the records of d. One record is deleted at once;
// several are confirmed first (ConfirmRecordDelete). A dry run reports the
// changes and deletes nothing: done is then false. A record that cannot be
// deleted or unbound is left in place, the others are still deleted, and
// the error says so at the end (a platform.PartialError for several
// records). The inventory rows of the deleted records are removed.
func (rt *Runtime) DeleteRecords(ctx context.Context, d RecordsDelete) (done bool, err error) {
	unbinder, _ := d.DNS.(platform.RecordUnbinder)
	owners := make([]string, len(d.Records))
	var bound []string
	var changes []platform.Change
	for i, r := range d.Records {
		detail := r.Value
		if unbinder != nil {
			if owner, ok := unbinder.Match(d.Zone, r); ok {
				owners[i] = owner
				bound = append(bound, owner)
				detail += " (unbound from " + owner + ", which removes the record)"
			}
		}
		changes = append(changes, platform.Change{Resource: RecordResource(r.Name, r.Type), Action: platform.Deleted, ID: r.ID, Detail: detail})
	}
	// A dry run neither asks nor needs --yes: nothing is deleted.
	if dry, err := rt.WouldWrite(d.Target, changes...); dry || err != nil {
		return false, err
	}
	if len(d.Records) > 1 {
		// The list is shown in both flows, so the caller sees what is
		// affected: before the question, or with the refusal that asks for
		// --yes.
		question := fmt.Sprintf("delete %d records in zone %s", len(d.Records), d.Zone.Name)
		if len(bound) > 0 {
			question += fmt.Sprintf(" (%d of them by unbinding them from %s)", len(bound), strings.Join(bound, ", "))
		}
		if err := rt.ConfirmRecordDelete(ctx, RecordDelete{Records: d.Grid(d.Records), Question: question, Exact: d.Exact}); err != nil {
			return false, err
		}
	}
	db, _ := rt.DB()
	var failed []error
	fail := func(r platform.Record, err error) {
		err = fmt.Errorf("delete %s %s (%s): %w", r.Name, r.Type, r.ID, err)
		if len(d.Records) > 1 {
			rt.Infof("failed: %v", err)
		}
		failed = append(failed, err)
	}
	for i, r := range d.Records {
		if owners[i] != "" {
			rt.Infof("%s %s belongs to %s: unbinding it there removes the record", r.Name, r.Type, owners[i])
			handled, err := unbinder.Unbind(ctx, d.Zone, r)
			if err == nil && !handled {
				err = fmt.Errorf("%s could not be unbound", owners[i])
			}
			if err != nil {
				fail(r, err)
				continue
			}
		} else if err := d.DNS.DeleteRecord(ctx, d.Zone.ID, r.ID); err != nil {
			fail(r, err)
			continue
		}
		if db != nil {
			_ = db.Delete(ctx, inventory.Set{Platform: d.Target.Platform, Profile: d.Target.Profile}, platform.ResDNSRecord, r.ID)
		}
		rt.Infof("deleted %s %s %s via %s/%s", r.Name, r.Type, r.Value, d.Target.Platform, d.Target.Profile)
	}
	if len(failed) > 0 {
		if len(d.Records) == 1 {
			return false, failed[0]
		}
		return false, &platform.PartialError{Failed: len(failed), Total: len(d.Records), First: failed[0]}
	}
	return true, nil
}
