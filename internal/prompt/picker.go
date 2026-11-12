package prompt

import (
	"errors"
	"io"
	"os"
	"sort"
	"sync"
	"sync/atomic"

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
	return &terminalPicker{in: in, out: errw, dropTypeAhead: IsTerminal(in)}
}

type terminalPicker struct {
	in  io.Reader
	out io.Writer
	// dropTypeAhead says that keys pressed before a yes/no question is on
	// screen are not answers to it. Only a terminal has such input to drop;
	// a pipe keeps every byte.
	dropTypeAhead bool
}

// drawGate tells when a prompt is on screen. The program draws a frame some
// milliseconds after it starts reading keys (it enters raw mode first, and
// frames are written on a timer), so a key can arrive before the question it
// would answer is visible.
type drawGate struct {
	// viewed is set once the program asked the field for its view: the next
	// write to the terminal carries the frame, or directly precedes it.
	viewed atomic.Bool
	once   sync.Once
	// drawn is closed when that write was made.
	drawn chan struct{}
	// done is closed when the prompt ended.
	done chan struct{}
	// flush drops the keys the terminal still holds at that moment.
	flush func()
}

// drawnMsg follows the keys that were read before the prompt was drawn.
type drawnMsg struct{}

func newDrawGate(in io.Reader) *drawGate {
	g := &drawGate{drawn: make(chan struct{}), done: make(chan struct{}), flush: func() {}}
	if f, ok := in.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		g.flush = func() { discardInput(f) }
	}
	return g
}

// wrote is called after every write to the terminal.
func (g *drawGate) wrote() {
	if !g.viewed.Load() {
		return
	}
	g.once.Do(func() {
		g.flush()
		close(g.drawn)
	})
}

// wait is a command that reports the first frame. Its message is queued
// behind the keys read until then, so those are told apart from the keys
// pressed with the question in view.
func (g *drawGate) wait() tea.Msg {
	select {
	case <-g.drawn:
		return drawnMsg{}
	case <-g.done:
		return nil
	}
}

// output returns w with every write reported to the gate. A file stays a
// file to the program, which asks it for the terminal's size and colours.
func (g *drawGate) output(w io.Writer) io.Writer {
	if f, ok := w.(*os.File); ok {
		return gatedFile{File: f, gate: g}
	}
	return gatedWriter{Writer: w, gate: g}
}

type gatedWriter struct {
	io.Writer
	gate *drawGate
}

func (w gatedWriter) Write(b []byte) (int, error) {
	n, err := w.Writer.Write(b)
	w.gate.wrote()
	return n, err
}

type gatedFile struct {
	*os.File
	gate *drawGate
}

func (w gatedFile) Write(b []byte) (int, error) {
	n, err := w.File.Write(b)
	w.gate.wrote()
	return n, err
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
	// gate, when not nil, is told that the field was drawn.
	gate    *drawGate
	waiting bool
}

// Update keeps the wrapper in the form: the form stores the model a field
// returns. The first update of a gated field also starts the wait for its
// first frame.
func (h *hinted) Update(msg tea.Msg) (huh.Model, tea.Cmd) {
	_, cmd := h.Field.Update(msg)
	if h.gate != nil && !h.waiting {
		h.waiting = true
		cmd = tea.Batch(cmd, h.gate.wait)
	}
	return h, cmd
}

func (h *hinted) View() string {
	if h.gate != nil {
		h.gate.viewed.Store(true)
	}
	return h.Field.View()
}

func (h *hinted) WithWidth(width int) huh.Field {
	h.width = width
	h.Field.WithWidth(width)
	return h
}

// KeyBinds leaves out the keys that do something else in the field's current
// state. In the filter input space and ctrl+a go to the text; while the text
// matches no option there is nothing to confirm or to move to, and run drops
// those keys.
func (h *hinted) KeyBinds() []key.Binding {
	binds := h.Field.KeyBinds()
	if f, ok := h.Field.(filterer); ok && f.GetFiltering() {
		noMatch := false
		if hv, ok := h.Field.(hoverer); ok {
			_, any := hv.Hovered()
			noMatch = !any
		}
		kept := make([]key.Binding, 0, len(binds))
		for _, b := range binds {
			switch b.Help().Key {
			case "space", "ctrl+a":
				continue
			case "enter", "↑", "↓":
				if noMatch {
					continue
				}
			}
			kept = append(kept, b)
		}
		binds = kept
	}
	return fitHints(orderHints(binds), h.width)
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

// selectUpKeys are the keys that move up in a select outside its filter
// input (the library's defaults).
var selectUpKeys = huh.NewDefaultKeyMap().Select.Up.Keys()

const (
	leaveHint  = "confirm • esc cancel"
	filterHint = "confirm" // Esc belongs to the filter: the library's own hint says how
)

// syncFilterHint rewrites the Enter hint of a list field for the filter
// state the key being handled leads to: while a filter is typed or applied
// Esc acts on the filter, so "esc cancel" must not be shown. Applying a key
// map resets the bindings the field switches on and off by itself, so they
// are set to the field's current state (filtering, applied) first.
//
// editing says that the key opens the filter input. The keys that edit its
// text must not move the list as well: the half-page keys (ctrl+u and ctrl+d
// delete text there) are switched off and ctrl+k (delete to the end of the
// line) no longer moves up, until the input is closed again.
func syncFilterHint(field huh.Field, km *huh.KeyMap, filtering, applied, escLeaves, editing bool) {
	hint := filterHint
	if escLeaves {
		hint = leaveHint
	}
	s, m := &km.Select, &km.MultiSelect
	for _, b := range []*key.Binding{&s.HalfPageUp, &s.HalfPageDown, &m.HalfPageUp, &m.HalfPageDown} {
		b.SetEnabled(!editing)
	}
	if editing {
		s.Up.SetKeys("up", "ctrl+p")
	} else {
		s.Up.SetKeys(selectUpKeys...)
	}
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
// prompt with that value, which is returned as the first result. ticks, when
// not nil (multi-select), is asked before Enter confirms; when it refuses the
// key is dropped and the prompt stays open. enterSetsFilter says that Enter
// in the filter input only applies the filter (multi-select); in a select it
// also confirms the highlighted match. gate, when not nil, makes the prompt
// drop the keys pressed before it was drawn (Ctrl-C still leaves it).
func (p *terminalPicker) run(field huh.Field, shortcuts map[string]string, ticks *tickGuard, enterSetsFilter bool, gate *drawGate) (string, error) {
	km := keyMap()
	out := p.out
	// unseen is set until the prompt is on screen.
	unseen := gate != nil
	if gate != nil {
		out = gate.output(out)
		defer close(gate.done)
	}
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
		syncFilterHint(field, km, false, filtered, !filtered, false)
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
	// tickOr handles a key that ticks rows while the reminder that nothing
	// is ticked is on screen: the field gets the key at once, so that the
	// reminder goes away with the first tick and not on a later key. The
	// size message that replaces the key makes the form draw the new state.
	// Any other time the key is passed on.
	tickOr := func(k tea.KeyPressMsg) tea.Msg {
		if ticks == nil || !ticks.reminding {
			return shortcutOr(k, false)
		}
		field.Update(k)
		ticks.refresh()
		return p.sizeMsg()
	}
	form := newGatedForm(field, km, gate).
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
			if _, ok := msg.(drawnMsg); ok {
				unseen = false
				return nil
			}
			k, isKey := msg.(tea.KeyPressMsg)
			if !isKey {
				return msg
			}
			if viaShortcut {
				return nil
			}
			if unseen {
				// Pressed before the question could be read: not an answer
				// to it.
				if k.String() == "ctrl+c" {
					return msg
				}
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
			case "up", "down", "ctrl+p", "ctrl+n", "ctrl+j":
				if noMatch {
					// With nothing to move to, the lists put their cursor
					// before the first row: a multi-select then panics on
					// the next toggle, a select confirms a stale value.
					return nil
				}
			case "ctrl+a":
				if filtering {
					// Start of the line in the filter text. A multi-select
					// would tick every match as well; Home is the same
					// editing key without that second meaning.
					return tea.KeyPressMsg{Code: tea.KeyHome}
				}
				return tickOr(k)
			case "space", "x":
				if filtering {
					return msg // typed into the filter
				}
				return tickOr(k)
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
				if !filtering && ticks != nil && !ticks.confirm() {
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
					syncFilterHint(field, km, false, true, true, false)
					filtered = false
					return msg
				}
				return tea.InterruptMsg{}
			case "/":
				if canFilter && !filtering {
					syncFilterHint(field, km, false, filtered, false, true)
				}
			default:
				return shortcutOr(k, filtering)
			}
			return msg
		})).
		WithInput(p.in).
		WithOutput(out)
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
	return newGatedForm(field, km, nil)
}

// newGatedForm is newForm with a gate that is told when the field is drawn
// (nil for none).
func newGatedForm(field huh.Field, km *huh.KeyMap, gate *drawGate) *huh.Form {
	return huh.NewForm(huh.NewGroup(&hinted{Field: field, gate: gate})).WithTheme(huh.ThemeFunc(theme)).WithKeyMap(km)
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
	picked, err := p.run(field, shortcuts, nil, false, nil)
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
	field, ticks := multiSelectField(title, huhOptions(opts, p.labelWidth(multiSelectPrefix)), &values, cols, termRows)
	if _, err := p.run(field, nil, ticks, true, nil); err != nil {
		return nil, err
	}
	return orderValues(opts, values), nil
}

const (
	tickHint     = "Tick with space, then press enter."
	tickReminder = "Nothing ticked: press space on a row first."
)

// tickGuard keeps a multi-select from being confirmed with nothing ticked.
// Enter on an unticked list is nearly always a slip (the highlighted row is
// not selected): the description then says what to do, until a row is ticked.
type tickGuard struct {
	// reminding is set while the description shows tickReminder.
	reminding bool
	ticked    func() bool
	describe  func(text string)
}

// confirm reports whether Enter may confirm the list, and shows the
// reminder when it may not.
func (g *tickGuard) confirm() bool {
	if g.ticked() {
		g.remind(false)
		return true
	}
	g.remind(true)
	return false
}

// refresh withdraws the reminder once a row is ticked: it would state
// something false next to the tick.
func (g *tickGuard) refresh() {
	if g.reminding && g.ticked() {
		g.remind(false)
	}
}

func (g *tickGuard) remind(on bool) {
	g.reminding = on
	if on {
		g.describe(tickReminder)
	} else {
		g.describe(tickHint)
	}
}

// multiSelectField builds the multi-select field for a terminal of cols by
// termRows, and the guard asked before Enter confirms.
func multiSelectField(title string, opts []huh.Option[string], values *[]string, cols, termRows int) (*huh.MultiSelect[string], *tickGuard) {
	field := huh.NewMultiSelect[string]().Title(title).Options(opts...).Value(values)
	// The height counts the title and description rows too, however many
	// rows they wrap to; without an explicit one short lists are cut off.
	// The option rows are sized for the longer description, so that showing
	// it never hides an option.
	titleRows := textRows(title, cols)
	rows := visibleRows(len(opts), termRows, titleRows+max(textRows(tickHint, cols), textRows(tickReminder, cols)))
	guard := &tickGuard{
		ticked: func() bool {
			v, ok := field.GetValue().([]string)
			return ok && len(v) > 0
		},
		describe: func(text string) {
			field.Description(text)
			field.Height(rows + titleRows + textRows(text, cols))
		},
	}
	guard.remind(false)
	return field, guard
}

func (p *terminalPicker) Confirm(title string, def bool) (bool, error) {
	value := def
	// What was typed before the question appeared is not an answer to it: a
	// "y" and Enter typed ahead would confirm it unseen. The keys are dropped
	// up to the moment the question is drawn, not only up to the start of
	// the prompt: drawing takes long enough for pasted or scripted input to
	// arrive in between.
	var gate *drawGate
	if p.dropTypeAhead {
		gate = newDrawGate(p.in)
	}
	if _, err := p.run(huh.NewConfirm().Title(title).Value(&value), nil, nil, false, gate); err != nil {
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
	if _, err := p.run(field, nil, nil, false, nil); err != nil {
		return "", err
	}
	return value, nil
}
