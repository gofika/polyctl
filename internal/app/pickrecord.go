package app

import (
	"errors"
	"fmt"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// PickRecordType asks for a record type the target platform can write.
func (rt *Runtime) PickRecordType(id platform.ID) (string, error) {
	types := platform.WritableRecordTypes(id)
	if types == nil {
		types = platform.RecordSpecTypes
	}
	var opts []prompt.Option
	for _, t := range types {
		opts = append(opts, prompt.Option{Label: t, Value: t})
	}
	return rt.Choose(Choice{Title: "Record type", Options: opts, Default: "A", Arg: "--type", Required: true, What: "record type"})
}

// AskRecordValue asks for the value of a record of type typ, checked as it
// is typed (an IPv4 address for A, IPv6 for AAAA, a host name for CNAME,
// ...); def is the current value of the record, if any.
func (rt *Runtime) AskRecordValue(typ, def string) (string, error) {
	return rt.AskInput("--value", "Value of the "+typ+" record", def, func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("a value is required")
		}
		if err := (platform.RecordSpec{Name: "@", Type: typ, Value: s}).Validate(); err != nil {
			return errors.New(strings.TrimPrefix(err.Error(), platform.ErrInvalidInput.Error()+": record @: "))
		}
		return nil
	})
}

// PickRecordID asks for one record of a zone (the <record-id> of an
// update or delete command), labelled "name  type  value  ttl  [proxied]
// id". mark, when set, adds a note to a record (the service owning it).
func (rt *Runtime) PickRecordID(title string, recs []platform.Record, mark func(platform.Record) string) (string, error) {
	var opts []prompt.Option
	for _, r := range recs {
		if r.Type == "SOA" || strings.TrimSpace(r.ID) == "" {
			continue
		}
		label := fmt.Sprintf("%s  %s  %s", r.Name, r.Type, r.Value)
		if r.TTL > 0 {
			label += fmt.Sprintf("  ttl %d", r.TTL)
		}
		if r.Proxied != nil && *r.Proxied {
			label += "  proxied"
		}
		if mark != nil {
			if m := mark(r); m != "" {
				label += "  [" + m + "]"
			}
		}
		label += "  " + r.ID
		opts = append(opts, prompt.Option{Label: label, Value: r.ID})
	}
	return rt.Choose(Choice{Title: title, Options: opts, Arg: "<record-id>", What: "record"})
}
