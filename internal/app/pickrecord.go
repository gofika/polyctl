package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// pickRecordType asks for a record type the target platform can write. def
// is the type preselected (the one the name already has); "" or a type the
// platform does not write preselects A.
func (rt *Runtime) pickRecordType(id platform.ID, def string) (string, error) {
	types := platform.WritableRecordTypes(id)
	if types == nil {
		types = platform.RecordSpecTypes
	}
	var opts []prompt.Option
	pre := "A"
	for _, t := range types {
		opts = append(opts, prompt.Option{Label: t, Value: t})
		if def != "" && strings.EqualFold(t, def) {
			pre = t
		}
	}
	return rt.Choose(Choice{Title: "Record type", Options: opts, Default: pre, Arg: "<type>", Required: true, What: "record type"})
}

// AskRecordValue asks for the value of a record of type typ, checked as it
// is typed (an IPv4 address for A, IPv6 for AAAA, a host name for CNAME,
// ...); def is the current value of the record, if any.
func (rt *Runtime) AskRecordValue(typ, def string) (string, error) {
	return rt.AskInput("<value>", "Value of the "+typ+" record", def, func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("a value is required")
		}
		return recordValueError(typ, s)
	})
}

// recordValueError says what is wrong with s as a value of a record of
// type typ; nil when it is one.
func recordValueError(typ, s string) error {
	if err := (platform.RecordSpec{Name: "@", Type: typ, Value: s}).Validate(); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": record @: "))
	}
	return nil
}

// RecordLabel is the label of a record in a selection list: the cells
// "name  type  value  ttl 300  proxied  <more>...", "-" for a TTL the
// record does not carry or for a record that is not proxied when a later
// cell follows. more are the cells after them (a note, the record id).
func RecordLabel(r platform.Record, more ...string) string {
	ttl, proxied := "", ""
	if r.TTL > 0 {
		ttl = fmt.Sprintf("ttl %d", r.TTL)
	}
	if r.Proxied != nil && *r.Proxied {
		proxied = "proxied"
	}
	return prompt.Cells(append([]string{r.Name, r.Type, r.Value, ttl, proxied}, more...)...)
}

// PickRecordID asks for one record of a zone (the <record-id> of an
// update or delete command), labelled "name  type  value  ttl 300  proxied
// [note]  id" ("-" for what a record does not have). mark, when set, adds
// a note to a record (the service owning it).
func (rt *Runtime) PickRecordID(title string, recs []platform.Record, mark func(platform.Record) string) (string, error) {
	var opts []prompt.Option
	for _, r := range recs {
		if r.Type == "SOA" || strings.TrimSpace(r.ID) == "" {
			continue
		}
		opts = append(opts, prompt.Option{Label: recordOptionLabel(r, mark), Value: r.ID})
	}
	return rt.Choose(Choice{Title: title, Options: opts, Arg: "<record-id>", What: "record"})
}

// PickOnOff asks to switch something on or off, the opposite of the
// current state (nil: unknown) preselected; it returns "on" or "off".
func (rt *Runtime) PickOnOff(title string, current *bool) (string, error) {
	def, onLabel, offLabel := "on", "On", "Off"
	if current != nil {
		if *current {
			def, onLabel = "off", "On  (current)"
		} else {
			offLabel = "Off  (current)"
		}
	}
	return rt.Choose(Choice{Title: title, Arg: "on|off", Default: def,
		Options: []prompt.Option{{Label: onLabel, Value: "on"}, {Label: offLabel, Value: "off"}}})
}
