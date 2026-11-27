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
		types = platform.KnownRecordTypes
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

// AskRecordValue asks for the value of the record c (its Value aside),
// checked as it is typed with the check the command runs before it writes
// (platform.CheckRecord: the platform, the priority given apart, whether
// the record is created), so a value the command would refuse is asked
// again; def is the current value of the record, if any. A type or a
// priority no value can make valid is the error at once.
func (rt *Runtime) AskRecordValue(c platform.RecordCheck, def string) (string, error) {
	if err := platform.CheckRecordType(c); err != nil {
		return "", err
	}
	return rt.AskInput("<value>", "Value of the "+strings.ToUpper(c.Type)+" record", def, func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("a value is required")
		}
		return recordValueError(c, s)
	})
}

// recordValueError says what is wrong with s as the value of the record c;
// nil when it is one.
func recordValueError(c platform.RecordCheck, s string) error {
	c.Value = s
	if _, err := platform.CheckRecord(c); err != nil {
		return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": "))
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
