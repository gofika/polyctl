package app

import (
	"errors"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// RecordForm is the shape of the record a command writes: MinValues to
// MaxValues values (MaxValues < 0: any number).
type RecordForm struct {
	MinValues, MaxValues int
	// Optional says the command has another way to name what it writes
	// (--record and --file of dns ensure): no record at all is no mistake,
	// and the command decides what happens then. A record that was begun
	// is still completed, or refused, like any other.
	Optional bool
	// Platform is the platform the record is written to: the record is
	// checked against the types it writes (see RecordInput.Check). "" for
	// a command that finds the platform from the domain: it passes it to
	// Check once it knows it, and until then the value alone is checked.
	Platform platform.ID
	// Creates says the record is created, or makes up a whole record set:
	// an MX record then needs a priority.
	Creates bool
}

func (f RecordForm) shape() recordShape {
	return recordShape{minValues: f.MinValues, maxValues: f.MaxValues}
}

// RecordInput is the record a command that writes one was given, as far as
// it was given: Runtime.RecordInput reads it and Runtime.CompleteRecord
// asks for the rest on a terminal.
type RecordInput struct {
	// Name is as typed: relative to the zone, "@" for the apex, or a full
	// name inside the zone. "" when no name was given: the interactive
	// flow asks for it, and in the non-interactive flow (the former flag
	// form without --name) the command applies the default it always had.
	Name string
	// Type is upper-cased, "" when it was not given.
	Type string
	// Values holds the values given, in order.
	Values []string
	// NameArg names where Name comes from for messages: "<name>" or
	// "--name".
	NameArg string

	form  RecordForm
	usage string
	// priority is the --priority of the command, nil when none was given.
	priority *int
}

// Value is the first value, "" when none was given.
func (in *RecordInput) Value() string {
	if in == nil || len(in.Values) == 0 {
		return ""
	}
	return in.Values[0]
}

// Given reports whether any part of the record was given.
func (in *RecordInput) Given() bool {
	return in != nil && (in.Name != "" || in.Type != "" || len(in.Values) > 0)
}

// writable reports whether the record can be written without asking: it
// has a type and its values. The name is not needed for that (see Name).
func (in *RecordInput) writable() bool {
	min := in.form.MinValues
	if min < 1 {
		min = 1
	}
	return in.Type != "" && len(in.Values) >= min
}

// Usage is the usage text of the positional form of the command.
func (in *RecordInput) Usage() string { return in.usage }

// RecordInput reads the record of a command that writes one. args are the
// arguments of the command, the <domain> or <zone> first: what follows is
// the positional record `<name> <type> <value>...`; without it the flags of
// the former form (--name, --type and --value, see FormerRecordFlags) say
// what to write.
//
// The interactive flow accepts a record that stops early (the zone alone,
// `<zone> <name>`, `<zone> <name> <type>`): CompleteRecord asks for the
// rest. The non-interactive flow never asks: a record without its type or
// its value is the usage error that shows the positional form.
func (rt *Runtime) RecordInput(cmd *cobra.Command, args []string, form RecordForm) (*RecordInput, error) {
	sh := form.shape()
	sh.partial = rt.Interactive()
	in := &RecordInput{NameArg: "--name", form: form, usage: sh.usage(cmd), priority: PriorityFlag(cmd)}
	if len(args) > 1 {
		rec, err := sh.parse(cmd, args[1:], nil)
		if err != nil {
			return nil, err
		}
		in.Name, in.Type, in.Values, in.NameArg = rec.Name, rec.Type, rec.Values, "<name>"
	} else {
		in.Name = strings.TrimSpace(formerFlag(cmd, "name"))
		in.Type = strings.ToUpper(strings.TrimSpace(formerFlag(cmd, "type")))
		if f := cmd.Flags().Lookup("value"); f != nil && f.Changed {
			if vs, err := cmd.Flags().GetStringArray("value"); err == nil {
				in.Values = vs
			} else if v := f.Value.String(); v != "" {
				in.Values = []string{v}
			}
		}
	}
	if !rt.Interactive() && !in.writable() && (in.Given() || !form.Optional) {
		return nil, UsageErrf("%s", in.usage)
	}
	// A record that is complete is checked now, before anything is read,
	// and so is the type of one that is not, before its value is asked.
	if in.writable() {
		if _, err := in.Check(cmd, ""); err != nil {
			return nil, err
		}
	} else if err := in.CheckType(""); err != nil {
		return nil, err
	}
	return in, nil
}

// CheckType checks the type given, if any, before its value is asked or
// the zone read (platform.CheckRecordType): it is known (exit code 2), one
// platform p writes (the Platform of the form when p is "", exit code 7),
// and the --priority given belongs to it. A command that finds the platform
// from the domain calls it once it knows the platform.
func (in *RecordInput) CheckType(p platform.ID) error {
	if in == nil || in.Type == "" {
		return nil
	}
	return platform.CheckRecordType(in.check(p, false))
}

// check is the platform.RecordCheck of the record without its value, on
// platform p (the Platform of the form when ""), with the --priority given;
// exists says a record of its name and type exists: one the command writes
// is then not created unless the form says so.
func (in *RecordInput) check(p platform.ID, exists bool) platform.RecordCheck {
	if p == "" {
		p = in.form.Platform
	}
	return platform.RecordCheck{Platform: p, Type: in.Type, Priority: in.priority, New: in.form.Creates || !exists}
}

// Complete reports whether the record has its type and its values: it is
// written without asking.
func (in *RecordInput) Complete() bool { return in != nil && in.writable() }

// Check is the check every command that writes a record runs on it before
// any request (platform.CheckRecord), one value at a time with the
// --priority of cmd: the type is known and one platform p writes (the
// Platform of the form when p is ""; neither: any known type), a priority
// apart belongs to the type, and each value is valid for it. It returns the
// values checked, in the normal form the providers take.
func (in *RecordInput) Check(cmd *cobra.Command, p platform.ID) ([]platform.RecordValue, error) {
	if p == "" {
		p = in.form.Platform
	}
	prio := PriorityFlag(cmd)
	out := make([]platform.RecordValue, 0, len(in.Values))
	for _, v := range in.Values {
		rv, err := platform.CheckRecord(platform.RecordCheck{Platform: p, Type: in.Type, Value: v, Priority: prio, New: in.form.Creates})
		if err != nil {
			return nil, err
		}
		out = append(out, rv)
	}
	return out, nil
}

// PriorityFlag is the --priority of cmd, nil when it was not given.
func PriorityFlag(cmd *cobra.Command) *int {
	f := cmd.Flags().Lookup("priority")
	if f == nil || !f.Changed {
		return nil
	}
	n, err := cmd.Flags().GetInt("priority")
	if err != nil {
		return nil
	}
	return &n
}

// CheckRecordChange checks, before anything is read, what the flags of an
// update command say about the record it writes on platform p: the new type
// (--type, else typ, the <type> that selects the record; "" when neither
// says) is one p writes, and --value and --priority are valid for it. What
// is known only once the record is read is checked by CheckRecordUpdate.
func CheckRecordChange(cmd *cobra.Command, p platform.ID, typ string) error {
	if t := formerFlag(cmd, "type"); strings.TrimSpace(t) != "" {
		typ = t
	}
	if strings.TrimSpace(typ) == "" {
		return nil
	}
	value := formerFlag(cmd, "value")
	if value == "" {
		// The type alone, and a priority: checked against the example
		// value, which is valid.
		info, ok := platform.RecordType(typ)
		switch {
		case !ok:
			info.Example = "x"
		case info.Type == "MX":
			info.Example = "mail.example.com"
		}
		value = info.Example
	}
	_, err := platform.CheckRecord(platform.RecordCheck{Platform: p, Type: typ, Value: value, Priority: PriorityFlag(cmd)})
	return err
}

// CheckRecordUpdate checks rec, the record an update command writes on
// platform p in place of cur, before the request, as RecordInput.Check
// checks a record to write: whenever its type, its value or (--priority of
// cmd) its priority changes. rec then takes the normal form of the value,
// the priority of an MX value given in front of it, and loses a priority its
// new type has no place for. A record that keeps its type and value is not
// checked again: its value is the one the platform holds.
func CheckRecordUpdate(cmd *cobra.Command, p platform.ID, cur platform.Record, rec *platform.Record) error {
	prio := PriorityFlag(cmd)
	typeChanged := !strings.EqualFold(rec.Type, cur.Type)
	if !typeChanged && rec.Value == cur.Value && prio == nil {
		return nil
	}
	wasMX := strings.EqualFold(cur.Type, "MX")
	v, err := platform.CheckRecord(platform.RecordCheck{Platform: p, Type: rec.Type, Value: rec.Value, Priority: prio, New: typeChanged || !wasMX})
	if err != nil {
		return err
	}
	rec.Type, rec.Value = v.Type, v.Value
	switch {
	case v.Type == "MX" && v.Priority != nil:
		rec.Priority = v.Priority
	case v.Type == "MX":
		// The record keeps the priority it has.
	case typeChanged || rec.Value != cur.Value:
		// No priority apart: the type has none, or carries it in the value.
		rec.Priority = nil
	}
	return nil
}

func formerFlag(cmd *cobra.Command, name string) string {
	if f := cmd.Flags().Lookup(name); f != nil && f.Changed {
		return f.Value.String()
	}
	return ""
}

// FormerRecordFlags gives cmd the flags of the former form of its record,
// --name, --type and --value (repeatable when the command takes several
// values). They keep working and are left out of the help; RecordInput
// reads them.
func FormerRecordFlags(cmd *cobra.Command, many bool) {
	cmd.Flags().String("name", "", "former form of <name>")
	cmd.Flags().String("type", "", "former form of <type>")
	if many {
		cmd.Flags().StringArray("value", nil, "former form of <value> (repeatable)")
	} else {
		cmd.Flags().String("value", "", "former form of <value>")
	}
	HideFormerRecordFlags(cmd)
}

// HideFormerRecordFlags leaves flags of the former form of a record
// command out of its help; they keep working. Without names these are
// --name, --type and --value, as far as the command has them.
func HideFormerRecordFlags(cmd *cobra.Command, names ...string) {
	if len(names) == 0 {
		names = formerRecordFlags
	}
	for _, n := range names {
		if cmd.Flags().Lookup(n) != nil {
			_ = cmd.Flags().MarkHidden(n)
		}
	}
}

// RecordPrompt says how CompleteRecord asks for the missing parts of a
// record.
type RecordPrompt struct {
	// Platform is the platform of the zone: its writable record types are
	// the ones offered.
	Platform platform.ID
	// Zone is the name of the zone.
	Zone string
	// Existing reads the records of the zone. It is called once, and only
	// when something is asked: the names are listed from it, the type the
	// name already has is preselected, and the current value is proposed.
	// nil: nothing is known about the zone.
	Existing func() ([]platform.Record, error)
	// Replaces says the command changes the record the name and type hold
	// instead of adding one (dns ensure): the value of that record, when
	// there is exactly one, is the default of the value asked, and each
	// value is checked as dns ensure writes it in the set the values make
	// (platform.EnsureCreates, platform.EnsureSetError).
	Replaces bool
	// WholeSet says the command makes the record set of the name and type
	// equal to the values given (an upsert). The current values are then
	// shown, and the first one proposed, however many there are.
	WholeSet bool
	// Current, when set, limits the records whose value is proposed (the
	// routing-policy set a Route 53 upsert replaces).
	Current func(platform.Record) bool
	// ValueOf renders the value of an existing record as the command takes
	// it; nil: platform.RecordAddValue, the value with the priority and the
	// fields a platform keeps apart put back, as the record check takes it.
	ValueOf func(platform.Record) string
	// CheckName is the check of the record's full name and type that the
	// command runs before it writes. It runs as soon as both are known,
	// before a value is asked, and the types it refuses for the name are
	// left out of the type list. nil: platform.CheckRecordName on Platform,
	// the name a platform takes for a type.
	CheckName func(fqdn, typ string) error
}

// checkName is the CheckName of p.
func (p RecordPrompt) checkName(fqdn, typ string) error {
	if p.CheckName != nil {
		return p.CheckName(fqdn, typ)
	}
	return platform.CheckRecordName(p.Platform, p.Zone, fqdn, typ)
}

// CompleteRecord asks, in the interactive flow, for what in lacks, in the
// order name, type, value:
//
//   - the name from the names the zone already has, the apex (@), or a
//     name typed in; it is never taken to be the apex without asking;
//   - the type from the types the platform can write and the command
//     takes for the name (CheckName), the one type the name already has
//     preselected; a name and type both known are checked before the value
//     is asked;
//   - the value as text, checked as it is typed; a command that takes
//     several values asks for more until one is left empty.
//
// A complete record asks nothing and does not read the zone. The
// non-interactive flow asks nothing either: RecordInput has refused what
// cannot be written, and a name that was not given (the former flag form)
// stays "" for the command to apply its default.
func (rt *Runtime) CompleteRecord(in *RecordInput, p RecordPrompt) error {
	if !rt.Interactive() || (in.Name != "" && in.writable()) {
		return nil
	}
	var existing []platform.Record
	if p.Existing != nil {
		var err error
		if existing, err = p.Existing(); err != nil {
			return err
		}
	}
	var err error
	if in.Name == "" {
		if in.Name, err = rt.PickRecordName(p.Zone, existing); err != nil {
			return err
		}
		in.NameArg = "<name>"
	}
	fqdn := platform.FQDN(in.Name, p.Zone)
	if in.Type == "" {
		has, _ := RecordsOfName(p.Zone, existing, fqdn, "", "")
		if in.Type, err = rt.pickRecordType(p.Platform, has.Type(), func(typ string) error { return p.checkName(fqdn, typ) }); err != nil {
			return err
		}
	}
	// The name and type are checked together before the value is asked.
	if err := p.checkName(fqdn, in.Type); err != nil {
		return err
	}
	if in.writable() {
		return nil
	}
	def := ""
	if p.Replaces || p.WholeSet {
		var cur []string
		for _, r := range MatchRecords(existing, fqdn, in.Type, "") {
			if p.Current != nil && !p.Current(r) {
				continue
			}
			if p.ValueOf != nil {
				cur = append(cur, p.ValueOf(r))
			} else {
				cur = append(cur, platform.RecordAddValue(r))
			}
		}
		if len(cur) == 1 || (p.WholeSet && len(cur) > 0) {
			def = cur[0]
		}
		if p.WholeSet && len(cur) > 0 {
			rt.Infof("%s %s is now: %s (the set becomes what you enter)", fqdn, in.Type, strings.Join(cur, ", "))
		}
	}
	// The values are checked as the command checks them: on the platform,
	// with the --priority given, and as created when no record of the name
	// and type exists; for a command that replaces the record, when dns
	// ensure creates the value in a set of n.
	recs := MatchRecords(existing, fqdn, in.Type, "")
	check := func(v string, n int) platform.RecordCheck {
		c := in.check(p.Platform, len(recs) > 0)
		if p.Replaces && !in.form.Creates {
			c.New = platform.EnsureCreates(recs, in.Type, v, in.priority, n)
		}
		return c
	}
	if len(in.Values) == 0 {
		v, err := rt.AskRecordValue(check("", 1), def)
		if err != nil {
			return err
		}
		in.Values = append(in.Values, v)
	}
	for in.form.MaxValues < 0 || len(in.Values) < in.form.MaxValues {
		v, err := rt.askAnotherRecordValue(in.Type, func(s string) error {
			n := len(in.Values) + 1
			if err := recordValueError(check(s, n), s); err != nil {
				return err
			}
			if !p.Replaces || in.form.Creates {
				return nil
			}
			// The values given before are checked again in the set this
			// value makes: a value that would update the one record alone is
			// created in a set.
			if err := platform.EnsureSetError(recs, in.Type, append(slices.Clone(in.Values), s), in.priority); err != nil {
				return fmt.Errorf("%v; leave this empty to finish with the values given so far", err)
			}
			return nil
		})
		if err != nil {
			return err
		}
		if v == "" {
			break
		}
		in.Values = append(in.Values, v)
	}
	return nil
}

// PickRecordName asks for the name of a record to write in zone: one of
// the names the zone already has (described by the types they hold), the
// apex, or a name typed in. It returns the name as the command reads it
// (platform.InputName): relative to the zone, "@" for the apex, or the full
// name where the relative one would end in a top-level domain.
func (rt *Runtime) PickRecordName(zone string, existing []platform.Record) (string, error) {
	zone = platform.NormalizeDomain(zone)
	types := map[string][]string{}
	seen := map[string]bool{}
	var names []string
	for _, r := range existing {
		rel := platform.InputName(zone, r.Name)
		if _, ok := types[rel]; !ok && rel != "@" {
			names = append(names, rel)
		}
		if t := strings.ToUpper(r.Type); !seen[rel+"\x00"+t] {
			seen[rel+"\x00"+t] = true
			types[rel] = append(types[rel], t)
		}
	}
	sort.Strings(names)
	opts := []prompt.Option{{Label: prompt.Cells("@ (apex)", strings.Join(types["@"], " ")), Value: "@"}}
	for _, n := range names {
		opts = append(opts, prompt.Option{Label: prompt.Cells(n, strings.Join(types[n], " ")), Value: n})
	}
	return rt.Choose(Choice{
		Title: "Record name in " + zone, Options: opts, Arg: "<name>", Required: true, What: "record name",
		CreateLabel: "Another name...",
		Create: func() (string, error) {
			return rt.AskInput("<name>", "Record name (relative to "+zone+", or a full name inside it)", "", func(s string) error {
				if strings.TrimSpace(s) == "" {
					return errors.New("a name is required (@ is the apex)")
				}
				_, err := platform.ZoneName(zone, s)
				return err
			})
		},
	})
}

// askAnotherRecordValue asks for one more value of a record set of type
// typ, checked with check; an empty answer ends the set.
func (rt *Runtime) askAnotherRecordValue(typ string, check func(string) error) (string, error) {
	return rt.AskInput("<value>", "Another value of the "+strings.ToUpper(typ)+" record (empty to finish)", "", func(s string) error {
		if strings.TrimSpace(s) == "" {
			return nil
		}
		return check(s)
	})
}

// RecordAskHelp is the paragraph a command that writes a record shows
// about what its interactive flow asks. first is what the first argument
// is called ("zone", "domain").
func RecordAskHelp(first string) string {
	return strings.NewReplacer("{first}", first).Replace(
		`On a terminal, what is left out is asked, in the order {first}, name, type
and value: a record may stop after the {first}, the name or the type. The
name is chosen from the names the {first} already has, @ for the apex, or
typed in; the type from the types the platform can write at that name (the
one the name already has is preselected), and a type given is checked, with
the name when it is given too, before anything is read or asked; the value
is checked as it is typed. The
non-interactive flow asks nothing: an incomplete record is a usage error
(exit code 2).`)
}

// RecordSetAskHelp is the paragraph that follows RecordAskHelp on a command
// that replaces a whole record set (an upsert).
const RecordSetAskHelp = `The values the set has now are shown and the first one is proposed. Values
are asked until one is left empty; the set becomes the values entered.`
