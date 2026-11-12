package prompt

import (
	"errors"
	"io"
	"os"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"golang.org/x/term"
)

// ErrAborted is returned by a Picker when the user leaves a prompt with Esc
// or Ctrl-C instead of answering it.
var ErrAborted = errors.New("prompt aborted")

// Option is one entry of a selection prompt: Label is shown, Value is
// returned. Key, when set, is a shortcut: in a Select, pressing that key
// picks the option at once.
type Option struct{ Label, Value, Key string }

// Picker asks questions on an interactive terminal. Commands depend on this
// interface rather than on a terminal library, so tests can script the
// answers.
type Picker interface {
	// Select returns the value of the chosen option. def preselects the
	// option with that value.
	Select(title string, opts []Option, def string) (string, error)
	// MultiSelect returns the values of the chosen options, in option order.
	MultiSelect(title string, opts []Option) ([]string, error)
	// Confirm asks a yes/no question; def is the preselected answer.
	Confirm(title string, def bool) (bool, error)
	// Input asks for a line of text. validate, when not nil, must accept the
	// value before it is returned.
	Input(title, def string, validate func(string) error) (string, error)
}

// IsTerminal reports whether v is a file attached to a terminal.
func IsTerminal(v any) bool {
	f, ok := v.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// NewPicker returns the terminal Picker: arrow keys (or j/k) move, space
// toggles in a multi-select, "/" filters, enter confirms, Esc or Ctrl-C
// aborts. It reads keys from in and draws on errw, never on stdout, which
// carries command results only.
func NewPicker(in io.Reader, errw io.Writer) Picker {
	if in == nil {
		in = os.Stdin
	}
	if errw == nil {
		errw = os.Stderr
	}
	return &terminalPicker{in: in, out: errw}
}

type terminalPicker struct {
	in  io.Reader
	out io.Writer
}

// filterer is implemented by the fields that have a "/" filter.
type filterer interface{ GetFiltering() bool }

// keyMap is the default key map with hints that say how to leave a prompt
// and that name the toggle key people expect.
func keyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Select.Submit.SetHelp("enter", leaveHint)
	km.MultiSelect.Submit.SetHelp("enter", leaveHint)
	km.Confirm.Submit.SetHelp("enter", leaveHint)
	km.Input.Submit.SetHelp("enter", leaveHint)
	km.MultiSelect.Toggle.SetHelp("space", "toggle")
	return km
}

const (
	leaveHint  = "confirm • esc cancel"
	filterHint = "confirm" // Esc belongs to the filter: the library's own hint says how
)

// syncFilterHint rewrites the Enter hint of a list field for the filter
// state the key being handled leads to: while a filter is typed or applied
// Esc acts on the filter, so "esc cancel" must not be shown. Applying a key
// map resets the bindings the field switches on and off by itself, so they
// are set to the field's current state (filtering, applied) first.
func syncFilterHint(field huh.Field, km *huh.KeyMap, filtering, applied, escLeaves bool) {
	hint := filterHint
	if escLeaves {
		hint = leaveHint
	}
	s, m := &km.Select, &km.MultiSelect
	s.Submit.SetHelp("enter", hint)
	s.SetFilter.SetEnabled(filtering)
	s.Filter.SetEnabled(!filtering)
	s.ClearFilter.SetEnabled(!filtering && applied)
	m.Submit.SetHelp("enter", hint)
	m.SetFilter.SetEnabled(filtering)
	m.Filter.SetEnabled(!filtering)
	m.ClearFilter.SetEnabled(!filtering && applied)
	m.Submit.SetEnabled(!filtering)
	// A prompt is a form with one field: there is no next or previous
	// field, and the form had switched these off before.
	for _, b := range []*key.Binding{&s.Next, &s.Prev, &m.Next, &m.Prev} {
		b.SetEnabled(false)
	}
	field.WithKeyMap(km)
}

// run shows one field and maps an abort to ErrAborted. shortcuts maps a key
// to an option value: pressing the key outside the filter input answers the
// prompt with that value, which is returned as the first result. mayConfirm,
// when not nil, is asked before Enter confirms; when it returns false the
// key is dropped and the prompt stays open. enterSetsFilter says that Enter
// in the filter input only applies the filter (multi-select); in a select it
// also confirms the highlighted match.
func (p *terminalPicker) run(field huh.Field, shortcuts map[string]string, mayConfirm func() bool, enterSetsFilter bool) (string, error) {
	km := keyMap()
	// submitted is set when Enter reaches the field. The form handles the
	// submission asynchronously, so keys still in the input buffer would
	// otherwise change the answer after it was confirmed (a "y" typed right
	// after Enter on a No). It is cleared when the field rejected the value.
	submitted := false
	// filtered is set while a "/" filter is applied: Esc then clears the
	// filter first and only the next Esc leaves the prompt.
	filtered := false
	shortcut, viaShortcut := "", false
	form := huh.NewForm(huh.NewGroup(field)).
		WithProgramOptions(tea.WithFilter(func(_ tea.Model, msg tea.Msg) tea.Msg {
			// Messages are filtered one at a time, after the previous one
			// was handled, so a rejection is visible here.
			if submitted && field.Error() != nil {
				submitted = false
			}
			k, isKey := msg.(tea.KeyPressMsg)
			if !isKey {
				return msg
			}
			if submitted || viaShortcut {
				return nil
			}
			f, canFilter := field.(filterer)
			filtering := canFilter && f.GetFiltering()
			switch k.String() {
			case "enter":
				if filtering && enterSetsFilter {
					filtered = true
					return msg
				}
				if !filtering && mayConfirm != nil && !mayConfirm() {
					// Enter is dropped; a size message makes the form lay
					// itself out again, which shows the changed hint.
					return p.sizeMsg()
				}
				submitted = true
			case "esc":
				if filtering {
					// Leaves the filter input and keeps the filter applied.
					filtered = true
					return msg
				}
				if filtered {
					// Clears the applied filter; Esc leaves again after it.
					syncFilterHint(field, km, false, true, true)
					filtered = false
					return msg
				}
				return tea.InterruptMsg{}
			case "/":
				if canFilter && !filtering {
					syncFilterHint(field, km, false, filtered, false)
				}
			default:
				if v, ok := shortcuts[k.String()]; ok && !filtering {
					shortcut, viaShortcut = v, true
					return tea.InterruptMsg{}
				}
			}
			return msg
		})).
		WithKeyMap(km).
		WithInput(p.in).
		WithOutput(p.out)
	err := mapAbort(form.Run())
	if viaShortcut {
		return shortcut, nil
	}
	if err != nil {
		return "", err
	}
	// A program ended from outside (SIGTERM, closed terminal) returns no
	// error; only a submitted form carries an answer.
	if form.State != huh.StateCompleted {
		return "", ErrAborted
	}
	return "", nil
}

// sizeMsg reports the current terminal size (80x24 when unknown).
func (p *terminalPicker) sizeMsg() tea.WindowSizeMsg {
	m := tea.WindowSizeMsg{Width: 80, Height: 24}
	if f, ok := p.out.(*os.File); ok {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil && w > 0 && h > 0 {
			m.Width, m.Height = w, h
		}
	}
	return m
}

// labelWidth is how many columns an option label may take so that every
// option stays on one row: a wrapped label hides other options.
func (p *terminalPicker) labelWidth() int {
	const fallback, margin, minimum = 80, 8, 20
	w := fallback
	if f, ok := p.out.(*os.File); ok {
		if cols, _, err := term.GetSize(int(f.Fd())); err == nil && cols > 0 {
			w = cols
		}
	}
	if w -= margin; w < minimum {
		w = minimum
	}
	return w
}

// truncate shortens s to at most n runes, ending in an ellipsis.
func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}

// mapAbort converts the library's abort error to ErrAborted.
func mapAbort(err error) error {
	if errors.Is(err, huh.ErrUserAborted) {
		return ErrAborted
	}
	return err
}

func huhOptions(opts []Option, width int) []huh.Option[string] {
	out := make([]huh.Option[string], 0, len(opts))
	for _, o := range opts {
		out = append(out, huh.NewOption(truncate(o.Label, width), o.Value))
	}
	return out
}

// defaultValue returns def when it is the value of one of opts, otherwise
// the value of the first option ("" when there is none).
func defaultValue(opts []Option, def string) string {
	for _, o := range opts {
		if o.Value == def {
			return def
		}
	}
	if len(opts) > 0 {
		return opts[0].Value
	}
	return ""
}

// orderValues returns the chosen values in the order of opts.
func orderValues(opts []Option, chosen []string) []string {
	picked := make(map[string]bool, len(chosen))
	for _, v := range chosen {
		picked[v] = true
	}
	var out []string
	for _, o := range opts {
		if picked[o.Value] {
			out = append(out, o.Value)
			delete(picked, o.Value)
		}
	}
	return out
}

// listHeight caps long lists so they scroll instead of filling the screen.
func listHeight(n int) int {
	const maxRows = 12
	if n > maxRows {
		return maxRows
	}
	return 0
}

func (p *terminalPicker) Select(title string, opts []Option, def string) (string, error) {
	if len(opts) == 0 {
		return "", errors.New("nothing to choose from")
	}
	value := defaultValue(opts, def)
	field := huh.NewSelect[string]().Title(title).Options(huhOptions(opts, p.labelWidth())...).Value(&value)
	if h := listHeight(len(opts)); h > 0 {
		field.Height(h)
	}
	shortcuts := map[string]string{}
	for _, o := range opts {
		if o.Key != "" {
			shortcuts[o.Key] = o.Value
		}
	}
	picked, err := p.run(field, shortcuts, nil, false)
	if err != nil {
		return "", err
	}
	if picked != "" {
		return picked, nil
	}
	return value, nil
}

func (p *terminalPicker) MultiSelect(title string, opts []Option) ([]string, error) {
	if len(opts) == 0 {
		return nil, errors.New("nothing to choose from")
	}
	var values []string
	const hint = "Tick with space, then press enter."
	field := huh.NewMultiSelect[string]().Title(title).Description(hint).
		Options(huhOptions(opts, p.labelWidth())...).Value(&values)
	// Enter on an unticked list is nearly always a slip (the highlighted row
	// is not selected): stay on the prompt and say what to do.
	ticked := func() bool {
		if v, ok := field.GetValue().([]string); ok && len(v) > 0 {
			field.Description(hint)
			return true
		}
		field.Description("Tick at least one row with space first, then press enter (esc cancels).")
		return false
	}
	// The height counts the title and description rows too; without an
	// explicit one short lists are cut off.
	rows := len(opts)
	if rows > 12 {
		rows = 12
	}
	field.Height(rows + 2)
	if _, err := p.run(field, nil, ticked, true); err != nil {
		return nil, err
	}
	return orderValues(opts, values), nil
}

func (p *terminalPicker) Confirm(title string, def bool) (bool, error) {
	value := def
	if _, err := p.run(huh.NewConfirm().Title(title).Value(&value), nil, nil, false); err != nil {
		return false, err
	}
	return value, nil
}

func (p *terminalPicker) Input(title, def string, validate func(string) error) (string, error) {
	value := def
	field := huh.NewInput().Title(title).Value(&value)
	if validate != nil {
		field.Validate(validate)
	}
	if _, err := p.run(field, nil, nil, false); err != nil {
		return "", err
	}
	return value, nil
}
