package platform

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SystemRecordMatcher is implemented by DNS clients whose zones list
// records the platform manages itself beyond the zone's apex NS and its
// SOA, which `dns delete --all` must leave alone. reason says why for the
// change report.
type SystemRecordMatcher interface {
	SystemRecord(zone Zone, rec Record) (reason string, ok bool)
}

// Disposition is what `dns delete --all` does with one record.
type Disposition string

const (
	// DispSystem: a record of the zone itself (its SOA, its apex NS), kept.
	DispSystem Disposition = "system"
	// DispBound: a record owned by another service, deleted by unbinding it.
	DispBound Disposition = "bound"
	// DispKept: a bound record left alone because of --keep-bound.
	DispKept Disposition = "kept"
	// DispNormal: deleted through the DNS API.
	DispNormal Disposition = "normal"
	// DispNoID: a record without an id, which cannot be deleted.
	DispNoID Disposition = "no-id"
)

// SystemRecordReason is the detail of a kept system record.
const SystemRecordReason = "system record"

// DNSDeleteAll is the input of PlanDNSDeleteAll.
type DNSDeleteAll struct {
	Platform ID
	Zone     Zone
	// Records are the records of the zone, read in full.
	Records []Record
	// Types limits the deletion to these record types (any case); empty
	// means every type.
	Types []string
	// KeepBound leaves records owned by another service alone instead of
	// unbinding them.
	KeepBound bool
	// DNS performs the deletions (inside Step.Apply only). When it is a
	// RecordUnbinder, owned records are unbound; when it is a
	// SystemRecordMatcher, the records it names are kept as well.
	DNS DNSService
	// Removed is told about every record deleted, to keep the inventory in
	// step. It may be nil.
	Removed func(ctx context.Context, id string)
}

// DeleteAllItem is one record of the zone and what happens to it.
type DeleteAllItem struct {
	Record      Record
	Disposition Disposition
	// Owner names the service that owns a bound or kept record.
	Owner string
	// Reason is the detail of a system record.
	Reason string
}

// DeleteAllPlan is the plan of `dns delete --all` with the classification
// it was built from, which the confirmation summarizes.
type DeleteAllPlan struct {
	*Plan
	Items []DeleteAllItem
}

// Deletes is the number of records the plan deletes (or unbinds).
func (p *DeleteAllPlan) Deletes() int {
	n := 0
	for _, it := range p.Items {
		if it.Disposition == DispNormal || it.Disposition == DispBound {
			n++
		}
	}
	return n
}

var recordTypeRe = regexp.MustCompile(`^[A-Z][A-Z0-9]*$`)

// ParseRecordTypes reads the values of a repeatable, comma-separated --type
// flag: upper-cased, without duplicates, in the order given. A value that
// is not a record type name is an ErrInvalidInput.
func ParseRecordTypes(values []string) ([]string, error) {
	var out []string
	seen := map[string]bool{}
	for _, v := range values {
		for _, t := range strings.Split(v, ",") {
			t = strings.ToUpper(strings.TrimSpace(t))
			if !recordTypeRe.MatchString(t) {
				return nil, fmt.Errorf("%w: --type %q is not a record type", ErrInvalidInput, t)
			}
			if !seen[t] {
				seen[t] = true
				out = append(out, t)
			}
		}
	}
	return out, nil
}

// IsSystemRecord reports whether rec is a record of the zone itself that
// `dns delete --all` never deletes: any SOA, and the NS records of the
// apex. Delegations (NS records of names below the apex) are not.
func IsSystemRecord(zone string, rec Record) bool {
	switch strings.ToUpper(rec.Type) {
	case "SOA":
		return true
	case "NS":
		return RelativeName(rec.Name, zone) == "@"
	}
	return false
}

// ClassifyDeleteAll sorts the records of the zone for `dns delete --all`,
// in their listed order: records outside Types are dropped, system records
// are kept, records owned by another service are unbound (or kept with
// KeepBound), records without an id cannot be deleted, the rest are
// deleted.
func ClassifyDeleteAll(in DNSDeleteAll) []DeleteAllItem {
	types := map[string]bool{}
	for _, t := range in.Types {
		types[strings.ToUpper(t)] = true
	}
	unbinder, _ := in.DNS.(RecordUnbinder)
	sys, _ := in.DNS.(SystemRecordMatcher)
	var items []DeleteAllItem
	for _, r := range in.Records {
		if len(types) > 0 && !types[strings.ToUpper(r.Type)] {
			continue
		}
		it := DeleteAllItem{Record: r}
		reason, system := SystemRecordReason, IsSystemRecord(in.Zone.Name, r)
		if !system && sys != nil {
			var why string
			if why, system = sys.SystemRecord(in.Zone, r); system && why != "" {
				reason = why
			}
		}
		switch {
		case system:
			it.Disposition, it.Reason = DispSystem, reason
		case strings.TrimSpace(r.ID) == "":
			it.Disposition = DispNoID
		default:
			it.Disposition = DispNormal
			if unbinder != nil {
				if owner, ok := unbinder.Match(in.Zone, r); ok {
					it.Owner = owner
					it.Disposition = DispBound
					if in.KeepBound {
						it.Disposition = DispKept
					}
				}
			}
		}
		items = append(items, it)
	}
	return items
}

// DeleteAllResource names a record in the report of `dns delete --all`:
// dns-record/<name relative to the zone>/<TYPE>, as `dns ensure` does.
func DeleteAllResource(zone string, r Record) string {
	return "dns-record/" + RelativeName(r.Name, zone) + "/" + strings.ToUpper(r.Type)
}

// PlanDNSDeleteAll computes the steps that empty the zone (or remove every
// record of Types from it), one per record in listed order. Every step
// goes on after a failure: one record that cannot be deleted does not stop
// the others. Kept records and records without an id are reported without
// a write. Nothing runs until the plan does.
func PlanDNSDeleteAll(in DNSDeleteAll) *DeleteAllPlan {
	items := ClassifyDeleteAll(in)
	plan := &Plan{ContinueOnError: true}
	unbinder, _ := in.DNS.(RecordUnbinder)
	for _, it := range items {
		r := it.Record
		res := DeleteAllResource(in.Zone.Name, r)
		switch it.Disposition {
		case DispSystem:
			plan.Add(Step{Resource: res, Action: Skipped, ID: r.ID, Desc: it.Reason})
		case DispKept:
			plan.Add(Step{Resource: res, Action: Skipped, ID: r.ID, Desc: "--keep-bound: owned by " + it.Owner})
		case DispNoID:
			plan.Add(Step{Resource: res, Action: Failed, Desc: "the record has no id"})
		case DispBound:
			owner := it.Owner
			via := "unbind:" + string(in.Platform)
			plan.Add(Step{
				Resource: res,
				Action:   Deleted,
				ID:       r.ID,
				Desc:     "unbind " + owner + " then record auto-removed",
				Attrs:    map[string]string{"via": via, "owner": owner, "value": r.Value},
				Apply: func(ctx context.Context) (Change, error) {
					handled, err := unbinder.Unbind(ctx, in.Zone, r)
					if err == nil && !handled {
						err = fmt.Errorf("%s could not be unbound", owner)
					}
					if err != nil {
						return Change{}, err
					}
					// The platform removes the record itself: no DeleteRecord.
					if in.Removed != nil {
						in.Removed(ctx, r.ID)
					}
					return Change{Detail: "unbound " + owner + " (" + r.Value + ")"}, nil
				},
			})
		default:
			plan.Add(Step{
				Resource: res,
				Action:   Deleted,
				ID:       r.ID,
				Desc:     recordDisplay(in.Platform, r),
				Attrs:    recordAttrs(r),
				Apply: func(ctx context.Context) (Change, error) {
					if err := in.DNS.DeleteRecord(ctx, in.Zone.ID, r.ID); err != nil {
						return Change{}, err
					}
					if in.Removed != nil {
						in.Removed(ctx, r.ID)
					}
					return Change{}, nil
				},
			})
		}
	}
	return &DeleteAllPlan{Plan: plan, Items: items}
}

// recordAttrs keeps the full data of a deleted record in the json / yaml
// report, so that the record can be written again.
func recordAttrs(r Record) map[string]string {
	a := map[string]string{"value": r.Value, "ttl": strconv.Itoa(r.TTL)}
	if r.Priority != nil {
		a["priority"] = strconv.Itoa(*r.Priority)
	}
	if r.Proxied != nil {
		a["proxied"] = strconv.FormatBool(*r.Proxied)
	}
	return a
}

// Summary counts the outcomes of a deleting command's report.
type Summary struct {
	// Deleted counts the records deleted, or in a dry run those that would be.
	Deleted int `json:"deleted" yaml:"deleted"`
	Skipped int `json:"skipped" yaml:"skipped"`
	Failed  int `json:"failed" yaml:"failed"`
}

// Summarize counts changes by outcome.
func Summarize(changes []Change) Summary {
	var s Summary
	for _, c := range changes {
		switch c.Action {
		case Deleted, WouldDelete:
			s.Deleted++
		case Failed:
			s.Failed++
		case Skipped, Unchanged:
			s.Skipped++
		}
	}
	return s
}

// FailedChanges returns the PartialError of a report whose changes include
// failures, or nil. Its first error is the detail of the first failure.
func FailedChanges(changes []Change) error {
	failed := 0
	var first error
	for _, c := range changes {
		if c.Action == Failed {
			failed++
			if first == nil {
				first = errors.New(c.Resource + ": " + c.Detail)
			}
		}
	}
	if failed == 0 {
		return nil
	}
	return &PartialError{Failed: failed, Total: len(changes), First: first}
}

// TypeCounts renders how many records of each type items hold, by type
// name: "A 4, CNAME 5, TXT 3". note, when set, adds a remark to a type
// ("CNAME 5 (2 ...)").
func TypeCounts(items []DeleteAllItem, note func(typ string) string) string {
	counts := map[string]int{}
	for _, it := range items {
		counts[strings.ToUpper(it.Record.Type)]++
	}
	types := make([]string, 0, len(counts))
	for t := range counts {
		types = append(types, t)
	}
	sort.Strings(types)
	parts := make([]string, 0, len(types))
	for _, t := range types {
		s := t + " " + strconv.Itoa(counts[t])
		if note != nil {
			if n := note(t); n != "" {
				s += " (" + n + ")"
			}
		}
		parts = append(parts, s)
	}
	return strings.Join(parts, ", ")
}
