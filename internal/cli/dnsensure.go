package cli

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/gofika/polyctl/internal/app"
	"github.com/gofika/polyctl/internal/output"
	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
	"github.com/gofika/polyctl/internal/shellquote"
)

// ensureReplace settles the names of a dns ensure run that hold records of
// other types (platform.OccupiedName), and confirms the replacements it
// decided before anything is written.
type ensureReplace struct {
	rt *app.Runtime
	t  *app.Target
	// replaced are the names whose records of other types are deleted.
	replaced []platform.OccupiedName
}

// The choices of a name with several records of other types.
const (
	replaceThem = "replace"
	keepThem    = "keep"
	cancelRun   = "cancel"
)

// decide is the platform.DNSEnsure.Decide of the run. One record of
// another type is replaced; outside a dry run that needs a confirmation,
// which the non-interactive flow refuses here without --yes (exit code 2).
// Several records are a choice on a terminal (replace them, keep them
// beside the desired records when they can share the name, or cancel) and
// exit code 5 without one, --yes or not.
func (e *ensureReplace) decide(o platform.OccupiedName) (bool, error) {
	if o.Single() {
		if !e.rt.DryRun() {
			if err := e.rt.CanConfirm(e.action([]platform.OccupiedName{o})); err != nil {
				return false, err
			}
		}
		e.replaced = append(e.replaced, o)
		return true, nil
	}
	if !e.rt.Interactive() {
		return false, o.Ambiguous()
	}
	e.rt.Infof("%s holds %d records of other types than %s:", o.FQDN, len(o.Others), strings.Join(o.Types, ", "))
	_ = output.RenderGrid(e.rt.Stderr, recordGrid(o.Others, e.t.Platform))
	opts := []prompt.Option{{Label: fmt.Sprintf("Replace them: delete the %d records, then write %s", len(o.Others), o.What()), Value: replaceThem}}
	if o.CanKeep() {
		opts = append(opts, prompt.Option{Label: fmt.Sprintf("Keep them and add %s beside them, as dns add does", o.What()), Value: keepThem})
	}
	opts = append(opts, prompt.Option{Label: "Cancel: write nothing", Value: cancelRun})
	v, err := e.rt.Choose(app.Choice{Title: fmt.Sprintf("What should dns ensure do with the records of %s?", o.FQDN), Options: opts, Default: cancelRun, Arg: "<name>"})
	if err != nil {
		return false, err
	}
	switch v {
	case replaceThem:
		e.replaced = append(e.replaced, o)
		return true, nil
	case keepThem:
		return false, nil
	}
	return false, app.NothingToDof("nothing was written")
}

// action names the replacement of names for a confirmation: "replace the
// TXT record of www.example.com with the A record in zone example.com".
func (e *ensureReplace) action(names []platform.OccupiedName) string {
	if len(names) == 1 {
		o := names[0]
		what := fmt.Sprintf("the %d records", len(o.Others))
		if len(o.Others) == 1 {
			what = "the " + strings.ToUpper(o.Others[0].Type) + " record"
		}
		return fmt.Sprintf("replace %s of %s with %s in zone %s", what, o.FQDN, o.What(), e.t.Domain)
	}
	n := 0
	for _, o := range names {
		n += len(o.Others)
	}
	return fmt.Sprintf("replace %d records of %d names in zone %s with the desired records", n, len(names), e.t.Domain)
}

// confirm asks once for every replacement decided (default no), after the
// records that go are listed: a no is "nothing to do" (exit code 0) and
// nothing is written. A dry run and --yes ask nothing.
func (e *ensureReplace) confirm(ctx context.Context) error {
	if len(e.replaced) == 0 || e.rt.DryRun() || e.rt.Flags.Yes {
		return nil
	}
	var gone []platform.Record
	for _, o := range e.replaced {
		e.rt.Infof("%s: %s deleted, then %s written", o.FQDN, plural(len(o.Others), "its record of another type is", "its records of other types are"), o.What())
		gone = append(gone, o.Others...)
	}
	return e.rt.ConfirmRecordDelete(ctx, app.RecordDelete{Records: recordGrid(gone, e.t.Platform), Question: e.action(e.replaced), Declined: "nothing was written"})
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// restoreCommand is the command that writes r, a record of the zone of t,
// again: `polyctl dns add` with its value, TTL and proxy setting, routed to
// the account it was deleted from.
func restoreCommand(t *app.Target, r platform.Record) string {
	args := []string{"polyctl", "dns", "add", t.Domain, platform.InputName(t.Domain, r.Name), strings.ToUpper(r.Type)}
	value := platform.RecordAddValue(r)
	var flags []string
	if r.TTL > 1 || (r.TTL == 1 && t.Platform != platform.Cloudflare) {
		flags = append(flags, "--ttl", strconv.Itoa(r.TTL))
	}
	if r.Proxied != nil && *r.Proxied {
		flags = append(flags, "--proxied")
	}
	flags = append(flags, "--platform", string(t.Platform), "--profile", t.Profile)
	if strings.HasPrefix(value, "-") {
		// Read as a flag otherwise.
		args = append(append(args, flags...), "--", value)
	} else {
		args = append(append(args, value), flags...)
	}
	return shellquote.Join(args...)
}
