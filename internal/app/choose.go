package app

import (
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/spf13/cobra"

	"github.com/gofika/polyctl/internal/platform"
	"github.com/gofika/polyctl/internal/prompt"
)

// The interactive flow never fails on a missing input whose valid values can
// be listed: it lists them and lets the user pick (see docs/interactive.md,
// "Interactive and non-interactive use"). The helpers of this file are the one way
// commands do that, so every command behaves the same:
//
//   - The non-interactive flow never asks: a missing input is a usage error
//     (exit code 2) naming the flag or argument to pass, before any write.
//   - An empty candidate list is "nothing to do" (exit code 0) for a command
//     that acts on an existing resource, and a usage error naming the flag
//     for a required input that cannot be created.
//   - Leaving a prompt (Esc, Ctrl-C, Ctrl-D) returns prompt.ErrAborted;
//     QuietAbort, which wraps every command, prints "cancelled" and exits 0.

// createValue is the value of the "Create a new ..." option of Choose.
const createValue = "\x00create"

// Choice describes one pick of Choose.
type Choice struct {
	// Title is the question ("Key pair").
	Title string
	// Options are the usable candidates, each with a label that says what
	// it is (name, id, key facts). Callers filter out what cannot be used
	// (unavailable, deprecated, arm64) before they get here.
	Options []prompt.Option
	// Default is the value preselected ("" for none).
	Default string
	// Selected are the values ticked at the start of ChooseMany.
	Selected []string
	// Arg names the input for messages: a flag ("--key-pair") or an
	// argument ("<domain>").
	Arg string
	// Missing is the usage error of the non-interactive flow; nil means
	// "<Arg> is required".
	Missing func() error
	// Empty is returned when there is nothing to choose from and nothing
	// can be created; nil means NothingToDo for a target (Required false)
	// and a usage error naming Arg for a required input of a create.
	Empty error
	// Required says the input is required by a command that creates
	// something, rather than the target of a command acting on an existing
	// resource. It only selects the default of Empty.
	Required bool
	// What names the candidates for the empty-list message ("indexed
	// domain").
	What string
	// CreateLabel and Create add a last option ("Create a new key
	// pair...") that runs Create, which asks what it needs and returns the
	// value to use. Without candidates Create runs straight away.
	CreateLabel string
	Create      func() (string, error)
}

// NothingToDof returns a note error wrapping platform.ErrNothingToDo: the
// command found nothing to act on, which exits 0.
func NothingToDof(format string, args ...any) error {
	return fmt.Errorf("%w: %s", platform.ErrNothingToDo, fmt.Sprintf(format, args...))
}

func (c Choice) missing() error {
	if c.Missing != nil {
		return c.Missing()
	}
	return UsageErrf("%s is required", c.Arg)
}

func (c Choice) empty() error {
	if c.Empty != nil {
		return c.Empty
	}
	what := c.What
	if what == "" {
		what = "candidate"
	}
	if c.Required {
		return UsageErrf("%s is required, and there is no %s to choose from", c.Arg, what)
	}
	return NothingToDof("no %s to choose from", what)
}

// Choose asks for one of c.Options in the interactive flow and returns its
// value; see Choice. The non-interactive flow returns c.Missing without
// reading the terminal.
func (rt *Runtime) Choose(c Choice) (string, error) {
	if !rt.Interactive() {
		return "", c.missing()
	}
	if len(c.Options) == 0 {
		if c.Create != nil {
			return c.Create()
		}
		return "", c.empty()
	}
	opts := c.Options
	if c.Create != nil {
		opts = append(append([]prompt.Option(nil), opts...), prompt.Option{Label: c.CreateLabel, Value: createValue})
	}
	v, err := rt.Pick().Select(c.Title, opts, c.Default)
	if err != nil {
		return "", err
	}
	if v == createValue {
		return c.Create()
	}
	return v, nil
}

// ChooseMany is Choose for several values (a MultiSelect). Ticking nothing
// is "nothing to do".
func (rt *Runtime) ChooseMany(c Choice) ([]string, error) {
	if !rt.Interactive() {
		return nil, c.missing()
	}
	if len(c.Options) == 0 {
		return nil, c.empty()
	}
	vs, err := prompt.MultiSelectWith(rt.Pick(), c.Title, c.Options, c.Selected)
	if err != nil {
		return nil, err
	}
	if len(vs) == 0 {
		return nil, NothingToDof("nothing was selected")
	}
	return vs, nil
}

// AskInput asks for a value that cannot be listed (a new name, a record
// value) in the interactive flow, re-asking while validate rejects it. The
// non-interactive flow returns the usage error "<arg> is required".
func (rt *Runtime) AskInput(arg, title, def string, validate func(string) error) (string, error) {
	if !rt.Interactive() {
		return "", UsageErrf("%s is required", arg)
	}
	v, err := rt.Pick().Input(title, def, validate)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(v), nil
}

// RequireValue is an Input validator that refuses an empty answer.
func RequireValue(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
}

// ArgsOrInteractive requires exactly n positional arguments, except in the
// interactive flow, where trailing ones may be left out: the command asks
// for them. missing is the usage error of the non-interactive flow (nil: a
// generic one naming the command's usage line).
func ArgsOrInteractive(rt *Runtime, n int, missing func(cmd *cobra.Command, args []string) error) cobra.PositionalArgs {
	return RangeArgsOrInteractive(rt, n, n, missing)
}

// RangeArgsOrInteractive is ArgsOrInteractive for min..max arguments.
func RangeArgsOrInteractive(rt *Runtime, min, max int, missing func(cmd *cobra.Command, args []string) error) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < min {
			if rt.Interactive() {
				return nil
			}
			// cobra validates arguments before Init runs. An invalid
			// POLYCTL_NON_INTERACTIVE is why nothing can be asked here:
			// report that, not the missing argument it leads to.
			if err := CheckNonInteractiveEnv(); err != nil {
				return UsageErrf("%v", err)
			}
			if missing != nil {
				return missing(cmd, args)
			}
		}
		if min == max {
			return cobra.ExactArgs(min)(cmd, args)
		}
		return cobra.RangeArgs(min, max)(cmd, args)
	}
}

// NoDryRunAnnotation marks commands that refuse --dry-run: they change
// local state only (the config, the credential store), which a dry run
// has no report for.
const NoDryRunAnnotation = "polyctl.nodryrun"

// MarkNoDryRun makes a command refuse --dry-run (see NoDryRunAnnotation).
func MarkNoDryRun(c *cobra.Command) {
	if c.Annotations == nil {
		c.Annotations = map[string]string{}
	}
	c.Annotations[NoDryRunAnnotation] = "1"
}

// QuietAbort wraps a command so that leaving one of its prompts with Esc or
// Ctrl-C ends it with the note "cancelled" and exit code 0, having changed
// nothing. The non-interactive flow has no prompt to leave: there the error
// is returned as it is, so an interrupted script never ends "cancelled" with
// exit code 0. The command tree applies it to every command.
func QuietAbort(rt *Runtime, run func(*cobra.Command, []string) error) func(*cobra.Command, []string) error {
	return func(cmd *cobra.Command, args []string) error {
		err := run(cmd, args)
		if errors.Is(err, prompt.ErrAborted) && rt.Interactive() {
			rt.Infof("cancelled")
			return nil
		}
		return err
	}
}

// Disambiguate turns an *AmbiguousError that carries Options into a pick in
// the interactive flow and returns the chosen value. Any other error, and
// every error of the non-interactive flow, is returned unchanged.
func (rt *Runtime) Disambiguate(err error) (string, error) {
	var amb *AmbiguousError
	if !errors.As(err, &amb) || len(amb.Options) == 0 || !rt.Interactive() {
		return "", err
	}
	return rt.Pick().Select("Ambiguous "+amb.What+"; use which one?", amb.Options, "")
}

// OneOf settles a lookup that found several candidates, the one way every
// command does it: one candidate is the answer; several are a list to
// choose from in the interactive flow (one option per candidate, labelled
// by label) and amb, which names the candidates and how to choose (exit
// code 5), in the non-interactive flow. No candidate is the caller's case
// (not found, or nothing to do) and is not expected here.
func OneOf[T any](rt *Runtime, amb *AmbiguousError, found []T, label func(T) string) (T, error) {
	return OneOfBy(rt, amb, found, nil, label)
}

// OneOfBy is OneOf with options whose value is value of the candidate (its
// id, its name) instead of its position; the values must differ.
func OneOfBy[T any](rt *Runtime, amb *AmbiguousError, found []T, value, label func(T) string) (T, error) {
	var zero T
	if len(found) == 1 {
		return found[0], nil
	}
	if len(found) == 0 || rt == nil {
		return zero, amb
	}
	valueOf := func(i int) string {
		if value == nil {
			return strconv.Itoa(i)
		}
		return value(found[i])
	}
	amb.Options = make([]prompt.Option, 0, len(found))
	for i, f := range found {
		amb.Options = append(amb.Options, prompt.Option{Label: label(f), Value: valueOf(i)})
	}
	v, err := rt.Disambiguate(amb)
	if err != nil {
		return zero, err
	}
	for i := range found {
		if valueOf(i) == v {
			return found[i], nil
		}
	}
	return zero, fmt.Errorf("unexpected choice %q", v)
}

// PickOf is Choose over items of any type: the options are the items,
// labelled by label, and the item chosen is returned. c.Options is not
// used; c.Default is not supported (nothing is preselected).
func PickOf[T any](rt *Runtime, c Choice, items []T, label func(T) string) (T, error) {
	var zero T
	c.Options = make([]prompt.Option, 0, len(items))
	for i, it := range items {
		c.Options = append(c.Options, prompt.Option{Label: label(it), Value: strconv.Itoa(i)})
	}
	c.Default, c.Create = "", nil
	v, err := rt.Choose(c)
	if err != nil {
		return zero, err
	}
	i, err := strconv.Atoi(v)
	if err != nil || i < 0 || i >= len(items) {
		return zero, fmt.Errorf("unexpected choice %q", v)
	}
	return items[i], nil
}

// Arg returns args[i], or "" when the argument was left out (the
// interactive flow then asks for it).
func Arg(args []string, i int) string {
	if i < len(args) {
		return args[i]
	}
	return ""
}

// ArgOr fills in a missing first argument: with it given, args is returned
// as it is; without it, pick (a Choose or PickResource of the command, which
// refuses in the non-interactive flow) supplies it.
func ArgOr(args []string, pick func() (string, error)) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	v, err := pick()
	if err != nil {
		return nil, err
	}
	return []string{v}, nil
}

// NamesArgs fills in a missing list of domain names (the <name>... of a
// registrar's domain check) in the interactive flow: names cannot be
// listed, so they are asked, separated by spaces or commas, and checked as
// they are typed. With names given it returns args as it is.
func (rt *Runtime) NamesArgs(args []string) ([]string, error) {
	if len(args) > 0 {
		return args, nil
	}
	v, err := rt.AskInput("<name>...", "Domain names to check (separated by spaces or commas)", "", func(s string) error {
		names := strings.Fields(strings.ReplaceAll(s, ",", " "))
		if len(names) == 0 {
			return errors.New("at least one name is required")
		}
		for _, n := range names {
			if d := platform.NormalizeDomain(n); !strings.Contains(d, ".") || strings.ContainsAny(d, " /:@?#*") {
				return fmt.Errorf("%q is not a domain name (such as example.com)", n)
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return strings.Fields(strings.ReplaceAll(v, ",", " ")), nil
}

// MinArgsOrInteractive requires at least min arguments, except in the
// interactive flow, where they may be left out: the command asks for them.
func MinArgsOrInteractive(rt *Runtime, min int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, args []string) error {
		if len(args) < min && rt.Interactive() {
			return nil
		}
		return cobra.MinimumNArgs(min)(cmd, args)
	}
}

// RequiredPick turns the "nothing to do" of an empty pick into the usage
// error of a required input: a command that creates something (a record in
// a zone) cannot do without the zone, so an empty list names the argument
// to pass instead of ending quietly. Other errors are returned unchanged.
func RequiredPick(err error, arg string) error {
	if !errors.Is(err, platform.ErrNothingToDo) {
		return err
	}
	why := strings.TrimPrefix(err.Error(), platform.ErrNothingToDo.Error()+": ")
	return UsageErrf("%s is required, and there is %s", arg, why)
}
