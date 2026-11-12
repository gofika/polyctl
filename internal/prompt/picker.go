package prompt

import (
	"errors"
	"io"
	"os"
	"sort"

	"charm.land/bubbles/v2/key"
	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
	"github.com/charmbracelet/x/ansi"
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
// toggles in a multi-select, "/" filters, enter confirms (y and n only
// select the answer of a yes/no question), Esc or Ctrl-C aborts. It reads
// keys from in and draws on errw, never on stdout, which carries command
// results only.
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

// hoverer is implemented by the list fields; Hovered reports false when the
// filter matches no option.
type hoverer interface{ Hovered() (string, bool) }

// keyMap is the default key map with hints that say how to leave a prompt
// and that name the toggle key people expect.
func keyMap() *huh.KeyMap {
	km := huh.NewDefaultKeyMap()
	km.Select.Submit.SetHelp("enter", leaveHint)
	km.MultiSelect.Submit.SetHelp("enter", leaveHint)
	km.Confirm.Submit.SetHelp("enter", leaveHint)
	km.Input.Submit.SetHelp("enter", leaveHint)
	km.MultiSelect.Toggle.SetHelp("space", "toggle")
	// Short enough for the whole hint line to fit 80 columns.
	km.MultiSelect.SelectAll.SetHelp("ctrl+a", "all")
	km.MultiSelect.SelectNone.SetHelp("ctrl+a", "none")
	return km
}

// hinted is a field whose key hints are laid out for the width at hand. The
// library lists them in a fixed order with the keys that confirm and leave
// near the end, where a narrow terminal cuts them off.
type hinted struct {
	huh.Field
	width int
}

// Update keeps the wrapper in the form: the form stores the model a field
// returns.
func (h *hinted) Update(msg tea.Msg) (huh.Model, tea.Cmd) {
	_, cmd := h.Field.Update(msg)
	return h, cmd
}

func (h *hinted) WithWidth(width int) huh.Field {
	h.width = width
	h.Field.WithWidth(width)
	return h
}

func (h *hinted) KeyBinds() []key.Binding {
	return fitHints(orderHints(h.Field.KeyBinds()), h.width)
}

// orderHints returns the bindings that are switched on with Enter and Esc
// first, which say how to confirm and how to leave, and with the two
// movement keys as one entry.
func orderHints(binds []key.Binding) []key.Binding {
	var first, rest []key.Binding
	for _, b := range binds {
		if !b.Enabled() {
			continue
		}
		switch b.Help().Key {
		case "enter", "esc":
			first = append(first, b)
			continue
		case "↑":
			b.SetHelp("↑/↓", "move")
		case "↓":
			continue
		}
		rest = append(rest, b)
	}
	// Enter before Esc, whatever order the field lists them in.
	sort.SliceStable(first, func(i, j int) bool { return first[i].Help().Key < first[j].Help().Key })
	return append(first, rest...)
}

// fitHints cuts the hints to what one row of width columns holds (all of
// them when the width is unknown). When some are left out, the first of
// those stays in the list if the help line will draw an ellipsis in its
// place: it does so for a hint that passes the edge when the ellipsis does
// not. Any other hint that does not fit it would print in full.
func fitHints(binds []key.Binding, width int) []key.Binding {
	const separator, ellipsis = 3, 2 // " • " and " …"
	if width <= 0 {
		return binds
	}
	total := 0
	for i, b := range binds {
		w := lipgloss.Width(b.Help().Key + " " + b.Help().Desc)
		if i > 0 {
			w += separator
		}
		// One column stays free: some terminals wrap when the last one is
		// written.
		if total+w > width-1 {
			if total+w > width && total+ellipsis < width {
				return binds[:i+1]
			}
			return binds[:i]
		}
		total += w
	}
	return binds
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

// filterApplied reports whether a list field has a filter in effect. The
// field enables its "clear filter" binding exactly then.
func filterApplied(field huh.Field, km *huh.KeyMap) bool {
	for _, b := range field.KeyBinds() {
		if !b.Enabled() {
			continue
		}
		if d := b.Help().Desc; d == km.Select.ClearFilter.Help().Desc || d == km.MultiSelect.ClearFilter.Help().Desc {
			return true
		}
	}
	return false
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
	// after Enter on a No). It is cleared when the field rejected the value
	// or did not take the Enter.
	submitted := false
	// filtered is set while a "/" filter is applied: Esc then clears the
	// filter first and only the next Esc leaves the prompt.
	filtered := false
	// leaveFilterInput hands the key that closes the filter input to the
	// field at once, so that its outcome is known: a filter is applied only
	// when text was typed and it matched something. Without one Esc leaves
	// the prompt again and the hint says so. The size message that replaces
	// the key makes the form draw the new state.
	leaveFilterInput := func(k tea.KeyPressMsg) tea.Msg {
		field.Update(k)
		filtered = filterApplied(field, km)
		// The key map is applied again in both outcomes: closing the filter
		// input makes a multi-select switch its next and previous bindings
		// back on, and Tab would then confirm the list unchecked.
		syncFilterHint(field, km, false, filtered, !filtered)
		return p.sizeMsg()
	}
	shortcut, viaShortcut := "", false
	// shortcutOr answers the prompt when k is a shortcut key pressed outside
	// the filter input, and passes the key on otherwise.
	shortcutOr := func(k tea.KeyPressMsg, filtering bool) tea.Msg {
		if v, ok := shortcuts[k.String()]; ok && !filtering {
			shortcut, viaShortcut = v, true
			return tea.InterruptMsg{}
		}
		return k
	}
	form := newForm(field, km).
		WithProgramOptions(tea.WithFilter(func(_ tea.Model, msg tea.Msg) tea.Msg {
			f, canFilter := field.(filterer)
			filtering := canFilter && f.GetFiltering()
			// Messages are filtered one at a time, after the previous one
			// was handled, so a rejection is visible here. A field still in
			// its filter input did not take the Enter either: a confirmed
			// field never is.
			if submitted && (field.Error() != nil || filtering) {
				submitted = false
			}
			if size, ok := msg.(tea.WindowSizeMsg); ok {
				return knownSize(size)
			}
			k, isKey := msg.(tea.KeyPressMsg)
			if !isKey {
				return msg
			}
			if viaShortcut {
				return nil
			}
			if submitted {
				// Ctrl-C always gets through, so the prompt can be left even
				// if a field ignores Enter in a way not foreseen here.
				if k.String() == "ctrl+c" {
					return msg
				}
				return nil
			}
			// noMatch: the filter being typed matches no option.
			noMatch := false
			if h, ok := field.(hoverer); ok && filtering {
				_, any := h.Hovered()
				noMatch = !any
			}
			switch k.String() {
			case "up", "down", "ctrl+p", "ctrl+n", "ctrl+k", "ctrl+j", "ctrl+u", "ctrl+d":
				if noMatch {
					// With nothing to move to, the lists put their cursor
					// before the first row: a multi-select then panics on
					// the next toggle, a select confirms a stale value.
					return nil
				}
			case "y", "Y", "n", "N":
				// Only Enter answers a yes/no question; these keys move the
				// selection. Answering at once would let the Enter typed
				// after them out of habit answer the next prompt unseen.
				if c, ok := field.(*huh.Confirm); ok {
					want := k.String() == "y" || k.String() == "Y"
					if cur, _ := c.GetValue().(bool); cur != want {
						return tea.KeyPressMsg{Code: tea.KeyLeft}
					}
					return nil
				}
				return shortcutOr(k, filtering)
			case "enter":
				if filtering && enterSetsFilter {
					return leaveFilterInput(k)
				}
				if noMatch {
					// A select takes no Enter while nothing matches. The
					// prompt stays in the filter input.
					return nil
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
					return leaveFilterInput(k)
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
				return shortcutOr(k, filtering)
			}
			return msg
		})).
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

// newForm returns the one-field form of a prompt.
func newForm(field huh.Field, km *huh.KeyMap) *huh.Form {
	return huh.NewForm(huh.NewGroup(&hinted{Field: field})).WithTheme(huh.ThemeFunc(theme)).WithKeyMap(km)
}

// theme is the library's default theme with the selected button of a yes/no
// question underlined: without colours (NO_COLOR, a monochrome terminal) the
// two buttons would otherwise look the same.
func theme(isDark bool) *huh.Styles {
	t := huh.ThemeCharm(isDark)
	t.Focused.FocusedButton = t.Focused.FocusedButton.Underline(true)
	return t
}

// Size assumed for a terminal that does not report one.
const fallbackCols, fallbackRows = 80, 24

// termSize returns the size of the terminal the prompt is drawn on (80x24
// when unknown).
func (p *terminalPicker) termSize() (cols, rows int) {
	if f, ok := p.out.(*os.File); ok {
		if w, h, err := term.GetSize(int(f.Fd())); err == nil {
			size := knownSize(tea.WindowSizeMsg{Width: w, Height: h})
			return size.Width, size.Height
		}
	}
	return fallbackCols, fallbackRows
}

// knownSize replaces the dimensions a terminal reports as zero (some serial
// consoles and containers do) by the fallback size: a form laid out for zero
// columns or rows draws nothing.
func knownSize(m tea.WindowSizeMsg) tea.WindowSizeMsg {
	if m.Width <= 0 {
		m.Width = fallbackCols
	}
	if m.Height <= 0 {
		m.Height = fallbackRows
	}
	return m
}

// sizeMsg reports the current terminal size.
func (p *terminalPicker) sizeMsg() tea.WindowSizeMsg {
	w, h := p.termSize()
	return tea.WindowSizeMsg{Width: w, Height: h}
}

// textRows is how many rows a title or description takes on a terminal of
// the given width. It mirrors how the library lays a field out: the text is
// wrapped inside the field's two-column frame (border and padding).
func textRows(s string, cols int) int {
	const frame = 2
	return lipgloss.Height(lipgloss.Wrap(s, cols-frame, ",.-; "))
}

// visibleRows is how many of n options a list shows at once on a terminal
// with termRows rows when headRows of them go to the title and description.
// Long lists are capped so they scroll instead of filling the screen, and
// the whole prompt (head, options, a blank row, the key hints and the row
// the cursor rests on) has to fit the terminal: when it does not, its first
// row, the title and with it the filter input, scrolls out of sight.
func visibleRows(n, termRows, headRows int) int {
	const maxRows, minRows, footRows = 12, 3, 3
	rows := min(n, maxRows)
	if fit := termRows - headRows - footRows; rows > fit {
		rows = max(fit, minRows)
	}
	return min(rows, n)
}

// Columns the library draws before an option label.
const (
	selectPrefix      = 4 // "┃ > "
	multiSelectPrefix = 6 // "┃ > • "
)

// labelWidth is how many columns an option label may take after a prefix of
// that many columns so that every option stays on one row: a wrapped label
// hides other options. One column is left free, because some terminals wrap
// when the last one is written.
func (p *terminalPicker) labelWidth(prefix int) int {
	const minimum = 4
	w, _ := p.termSize()
	return max(w-prefix-1, minimum)
}

// truncate shortens s to at most n terminal columns, ending in an ellipsis.
// Wide characters (CJK) count as the two columns they take.
func truncate(s string, n int) string {
	return ansi.Truncate(s, n, "…")
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

func (p *terminalPicker) Select(title string, opts []Option, def string) (string, error) {
	if len(opts) == 0 {
		return "", errors.New("nothing to choose from")
	}
	value := defaultValue(opts, def)
	field := huh.NewSelect[string]().Title(title).Options(huhOptions(opts, p.labelWidth(selectPrefix))...).Value(&value)
	// A list that shows every option keeps its natural height; a scrolling
	// one needs an explicit height, which counts the title rows too.
	cols, termRows := p.termSize()
	titleRows := textRows(title, cols)
	if rows := visibleRows(len(opts), termRows, titleRows); rows < len(opts) {
		field.Height(rows + titleRows)
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
	cols, termRows := p.termSize()
	field, ticked := multiSelectField(title, huhOptions(opts, p.labelWidth(multiSelectPrefix)), &values, cols, termRows)
	if _, err := p.run(field, nil, ticked, true); err != nil {
		return nil, err
	}
	return orderValues(opts, values), nil
}

const (
	tickHint     = "Tick with space, then press enter."
	tickReminder = "Nothing ticked: press space on a row first."
)

// multiSelectField builds the multi-select field for a terminal of cols by
// termRows, and the check run before Enter confirms. Enter on an unticked
// list is nearly always a slip (the highlighted row is not selected): the
// check then fails and the description says what to do.
func multiSelectField(title string, opts []huh.Option[string], values *[]string, cols, termRows int) (*huh.MultiSelect[string], func() bool) {
	field := huh.NewMultiSelect[string]().Title(title).Options(opts...).Value(values)
	// The height counts the title and description rows too, however many
	// rows they wrap to; without an explicit one short lists are cut off.
	// The option rows are sized for the longer description, so that showing
	// it never hides an option.
	titleRows := textRows(title, cols)
	rows := visibleRows(len(opts), termRows, titleRows+max(textRows(tickHint, cols), textRows(tickReminder, cols)))
	describe := func(text string) {
		field.Description(text)
		field.Height(rows + titleRows + textRows(text, cols))
	}
	describe(tickHint)
	ticked := func() bool {
		if v, ok := field.GetValue().([]string); ok && len(v) > 0 {
			describe(tickHint)
			return true
		}
		describe(tickReminder)
		return false
	}
	return field, ticked
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
