package prompt

import (
	"bytes"
	"errors"
	"io"
	"os"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
)

var abc = []Option{{Label: "Alpha", Value: "a"}, {Label: "Beta", Value: "b"}, {Label: "Gamma", Value: "c"}}

func TestDefaultValue(t *testing.T) {
	for _, tc := range []struct {
		opts []Option
		def  string
		want string
	}{
		{abc, "b", "b"},
		{abc, "", "a"},
		{abc, "missing", "a"},
		{nil, "x", ""},
	} {
		if got := defaultValue(tc.opts, tc.def); got != tc.want {
			t.Errorf("defaultValue(%d options, %q) = %q, want %q", len(tc.opts), tc.def, got, tc.want)
		}
	}
}

func TestOrderValues(t *testing.T) {
	got := orderValues(abc, []string{"c", "a", "unknown", "c"})
	if want := []string{"a", "c"}; !reflect.DeepEqual(got, want) {
		t.Errorf("orderValues = %v, want %v", got, want)
	}
	if got := orderValues(abc, nil); len(got) != 0 {
		t.Errorf("orderValues with nothing chosen = %v", got)
	}
}

func TestVisibleRows(t *testing.T) {
	for _, c := range []struct{ n, termRows, headRows, want int }{
		{3, 24, 1, 3},   // a short list is shown whole
		{40, 24, 1, 12}, // a long list is capped
		{40, 14, 2, 9},  // head, options, blank row, hints and cursor row fit 14 rows
		{10, 10, 1, 6},  // a short terminal makes a short list scroll too
		{40, 4, 2, 3},   // never fewer than three rows
		{2, 4, 2, 2},    // nor more rows than options
	} {
		if got := visibleRows(c.n, c.termRows, c.headRows); got != c.want {
			t.Errorf("visibleRows(%d, %d, %d) = %d, want %d", c.n, c.termRows, c.headRows, got, c.want)
		}
	}
}

func TestTextRows(t *testing.T) {
	const text = "Nothing ticked: press space on a row first."
	if got := textRows(text, 80); got != 1 {
		t.Errorf("textRows on 80 columns = %d, want 1", got)
	}
	if got := textRows(text, 30); got != 2 {
		t.Errorf("textRows on 30 columns = %d, want 2", got)
	}
}

func TestMapAbort(t *testing.T) {
	if err := mapAbort(nil); err != nil {
		t.Errorf("mapAbort(nil) = %v", err)
	}
	if err := mapAbort(huh.ErrUserAborted); !errors.Is(err, ErrAborted) {
		t.Errorf("mapAbort(ErrUserAborted) = %v, want ErrAborted", err)
	}
	other := errors.New("boom")
	if err := mapAbort(other); err != other {
		t.Errorf("mapAbort must pass other errors through, got %v", err)
	}
}

func TestIsTerminal(t *testing.T) {
	if IsTerminal(strings.NewReader("")) || IsTerminal(&bytes.Buffer{}) || IsTerminal(nil) {
		t.Error("readers and buffers are not terminals")
	}
	f, err := os.Open(os.DevNull)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	if IsTerminal(f) {
		t.Error("the null device is not a terminal")
	}
}

func TestEmptyOptionLists(t *testing.T) {
	p := NewPicker(strings.NewReader(""), io.Discard)
	if _, err := p.Select("t", nil, ""); err == nil {
		t.Error("Select without options must fail")
	}
	if _, err := p.MultiSelect("t", nil); err == nil {
		t.Error("MultiSelect without options must fail")
	}
}

// syncBuffer is a bytes.Buffer safe for the renderer goroutine.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

// drive runs fn against a picker whose keyboard is fed with keys, one group
// at a time, and fails the test when the prompt does not finish.
func drive[T any](t *testing.T, keys []string, fn func(Picker) (T, error)) (T, error) {
	t.Helper()
	pr, pw := io.Pipe()
	out := &syncBuffer{}
	type result struct {
		v   T
		err error
	}
	done := make(chan result, 1)
	go func() {
		v, err := fn(NewPicker(pr, out))
		done <- result{v, err}
	}()
	go func() {
		for _, k := range keys {
			time.Sleep(60 * time.Millisecond)
			if _, err := io.WriteString(pw, k); err != nil {
				return
			}
			if k == "\x1b" {
				// A lone Esc is told apart from an escape sequence by the
				// pause that follows it.
				time.Sleep(250 * time.Millisecond)
			}
		}
	}()
	select {
	case r := <-done:
		pw.Close()
		return r.v, r.err
	case <-time.After(10 * time.Second):
		pw.Close()
		t.Fatal("the prompt did not finish")
		panic("unreachable")
	}
}

const (
	keyDown  = "\x1b[B"
	keyUp    = "\x1b[A"
	keyEnter = "\r"
	keyCtrlC = "\x03"
)

func TestPickerSelect(t *testing.T) {
	got, err := drive(t, []string{keyDown, keyEnter}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if err != nil || got != "b" {
		t.Errorf("down+enter = %q, %v; want b", got, err)
	}
	got, err = drive(t, []string{keyEnter}, func(p Picker) (string, error) { return p.Select("Pick", abc, "c") })
	if err != nil || got != "c" {
		t.Errorf("enter on the default = %q, %v; want c", got, err)
	}
	got, err = drive(t, []string{"k", keyEnter}, func(p Picker) (string, error) { return p.Select("Pick", abc, "c") })
	if err != nil || got != "b" {
		t.Errorf("k+enter from c = %q, %v; want b", got, err)
	}
	_, err = drive(t, []string{keyCtrlC}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("ctrl-c = %v, want ErrAborted", err)
	}
}

func TestPickerMultiSelect(t *testing.T) {
	got, err := drive(t, []string{keyDown, keyDown, " ", keyUp, keyUp, " ", keyEnter}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if want := []string{"a", "c"}; err != nil || !reflect.DeepEqual(got, want) {
		t.Errorf("MultiSelect = %v, %v; want %v", got, err, want)
	}
	_, err = drive(t, []string{keyCtrlC}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("ctrl-c = %v, want ErrAborted", err)
	}
}

func TestPickerConfirm(t *testing.T) {
	for _, tc := range []struct {
		keys []string
		def  bool
		want bool
	}{
		{[]string{keyEnter}, false, false},
		{[]string{keyEnter}, true, true},
		// y and n select an answer; only Enter confirms it.
		{[]string{"y", keyEnter}, false, true},
		{[]string{"n", keyEnter}, true, false},
		{[]string{"y", "n", keyEnter}, false, false},
		{[]string{"y", "y", keyEnter}, false, true},
		{[]string{"N", "Y", keyEnter}, false, true},
	} {
		got, err := drive(t, tc.keys, func(p Picker) (bool, error) { return p.Confirm("Sure?", tc.def) })
		if err != nil || got != tc.want {
			t.Errorf("Confirm(def %v) with %q = %v, %v; want %v", tc.def, tc.keys, got, err, tc.want)
		}
	}
	// A key typed right after Enter must not change the confirmed answer.
	if got, err := drive(t, []string{keyEnter + "y"}, func(p Picker) (bool, error) { return p.Confirm("Sure?", false) }); err != nil || got {
		t.Errorf("Confirm with enter then y = %v, %v; want false", got, err)
	}
	_, err := drive(t, []string{keyCtrlC}, func(p Picker) (bool, error) { return p.Confirm("Sure?", true) })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("ctrl-c = %v, want ErrAborted", err)
	}
	// y alone does not finish the prompt, so the Enter that habitually
	// follows it cannot land in the next prompt.
	_, err = drive(t, []string{"y", keyCtrlC}, func(p Picker) (bool, error) { return p.Confirm("Sure?", false) })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("y then ctrl-c = %v, want ErrAborted: y must not answer the prompt", err)
	}
}

func TestPickerInput(t *testing.T) {
	got, err := drive(t, []string{"new", keyEnter}, func(p Picker) (string, error) { return p.Input("Name", "", nil) })
	if err != nil || got != "new" {
		t.Errorf("Input = %q, %v; want new", got, err)
	}
	got, err = drive(t, []string{keyEnter}, func(p Picker) (string, error) { return p.Input("Name", "kept", nil) })
	if err != nil || got != "kept" {
		t.Errorf("Input with a default = %q, %v; want kept", got, err)
	}
	// A rejected value keeps the prompt open until it is corrected.
	noSpaces := func(s string) error {
		if s == "" || strings.Contains(s, " ") {
			return errors.New("invalid")
		}
		return nil
	}
	got, err = drive(t, []string{"a b", keyEnter, "\x7f\x7f", "x", keyEnter}, func(p Picker) (string, error) { return p.Input("Name", "", noSpaces) })
	if err != nil || got != "ax" {
		t.Errorf("Input after a correction = %q, %v; want ax", got, err)
	}
}

func TestPickerEsc(t *testing.T) {
	const keyEsc = "\x1b"
	_, err := drive(t, []string{keyEsc}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("esc on a list = %v, want ErrAborted", err)
	}
	_, err = drive(t, []string{"x", keyEsc}, func(p Picker) (string, error) { return p.Input("Name", "", nil) })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("esc in an input = %v, want ErrAborted", err)
	}
	// While the filter is being typed Esc only leaves the filter input.
	got, err := drive(t, []string{"/", "be", keyEsc, keyEnter}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if err != nil || got != "b" {
		t.Errorf("filter, esc, enter = %q, %v; want b", got, err)
	}
}

// The drive-based tests below cover what the key filter does end to end.

func TestPickerShortcutKey(t *testing.T) {
	opts := []Option{{Label: "Alpha", Value: "a"}, {Label: "Quit", Value: "quit", Key: "q"}}
	got, err := drive(t, []string{"q"}, func(p Picker) (string, error) { return p.Select("Pick", opts, "") })
	if err != nil || got != "quit" {
		t.Errorf("shortcut key = %q, %v; want quit", got, err)
	}
	// While typing a filter the key is text, not a shortcut.
	got, err = drive(t, []string{"/", "q", keyEnter, keyEnter}, func(p Picker) (string, error) { return p.Select("Pick", opts, "") })
	if err != nil || got != "quit" {
		t.Errorf("q typed into the filter then enter = %q, %v; want the filtered option", got, err)
	}
}

func TestPickerEscClearsAppliedFilterFirst(t *testing.T) {
	const keyEsc = "\x1b"
	// "/be" then Esc leaves the filter input with the filter applied; the
	// next Esc clears the filter and the prompt stays open, so Enter still
	// answers it.
	got, err := drive(t, []string{"/", "be", keyEsc, keyEsc, keyEnter}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if err != nil || got == "" {
		t.Errorf("Esc on an applied filter ended the prompt: %q, %v", got, err)
	}
	// With the filter cleared, one more Esc leaves the prompt.
	_, err = drive(t, []string{"/", "be", keyEsc, keyEsc, keyEsc}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("third Esc = %v, want ErrAborted", err)
	}
}

func TestPickerMultiSelectNeedsATick(t *testing.T) {
	// Enter with nothing ticked keeps the prompt open; ticking then works.
	got, err := drive(t, []string{keyEnter, " ", keyEnter}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if err != nil || !reflect.DeepEqual(got, []string{"a"}) {
		t.Errorf("MultiSelect after an empty enter = %v, %v; want [a]", got, err)
	}
	_, err = drive(t, []string{keyEnter, "\x1b"}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("Esc after an empty enter = %v, want ErrAborted", err)
	}
}

func TestKeyMapHints(t *testing.T) {
	km := keyMap()
	for name, h := range map[string]string{
		"select":      km.Select.Submit.Help().Desc,
		"multiselect": km.MultiSelect.Submit.Help().Desc,
		"confirm":     km.Confirm.Submit.Help().Desc,
		"input":       km.Input.Submit.Help().Desc,
	} {
		if !strings.Contains(h, "esc cancel") {
			t.Errorf("%s hint %q does not say how to leave", name, h)
		}
	}
	if k := km.MultiSelect.Toggle.Help().Key; k != "space" {
		t.Errorf("toggle hint key = %q, want space", k)
	}
}

// In a multi-select Enter in the filter input only applies the filter: the
// prompt stays open, rows can still be ticked, and Esc clears the filter
// before it leaves.
func TestPickerMultiSelectFilter(t *testing.T) {
	const keyEsc = "\x1b"
	got, err := drive(t, []string{"/", "be", keyEnter, " ", keyEnter}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if err != nil || !reflect.DeepEqual(got, []string{"b"}) {
		t.Errorf("filter, enter, tick, enter = %v, %v; want [b]", got, err)
	}
	got, err = drive(t, []string{"/", "be", keyEnter, keyEsc, " ", keyEnter}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if err != nil || len(got) != 1 {
		t.Errorf("filter, enter, esc (clear), tick, enter = %v, %v; want one value", got, err)
	}
	_, err = drive(t, []string{"/", "be", keyEnter, keyEsc, keyEsc}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("esc after clearing the filter = %v, want ErrAborted", err)
	}
}

func TestSyncFilterHint(t *testing.T) {
	km := keyMap()
	field := huh.NewSelect[string]().Options(huhOptions(abc, 80)...)
	syncFilterHint(field, km, false, false, false, false)
	if h := km.Select.Submit.Help().Desc; strings.Contains(h, "esc") {
		t.Errorf("hint while a filter is in use = %q, must not mention esc", h)
	}
	syncFilterHint(field, km, false, true, true, false)
	if h := km.Select.Submit.Help().Desc; !strings.Contains(h, "esc cancel") {
		t.Errorf("hint after the filter was cleared = %q", h)
	}
	if !km.Select.ClearFilter.Enabled() || km.Select.SetFilter.Enabled() || !km.Select.Filter.Enabled() {
		t.Error("bindings must mirror the state the field is in: filter applied, not being typed")
	}
}

// Leaving the filter input without a filter in effect (nothing typed, text
// deleted again, or no match, which resets the filter) leaves nothing for
// Esc to clear: the next Esc must end the prompt.
func TestPickerEscAfterEmptyFilter(t *testing.T) {
	const keyEsc, keyBackspace = "\x1b", "\x7f"
	_, err := drive(t, []string{"/", keyEsc, keyEsc}, func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if !errors.Is(err, ErrAborted) {
		t.Errorf("select: /, esc, esc = %v, want ErrAborted", err)
	}
	for _, keys := range [][]string{
		{"/", keyEsc, keyEsc},
		{"/", "0", keyBackspace, keyEnter, keyEsc},
		{"/", "zzz", keyEnter, keyEsc},
	} {
		_, err := drive(t, keys, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
		if !errors.Is(err, ErrAborted) {
			t.Errorf("multi-select: keys %q = %v, want ErrAborted", keys, err)
		}
	}
}

// Enter in a filter that matches nothing is not a submission: the prompt
// must keep reading keys instead of dropping every later one.
func TestPickerEnterOnEmptyFilterKeepsPromptAlive(t *testing.T) {
	const keyEsc, keyBackspace = "\x1b", "\x7f"
	sel := func(p Picker) (string, error) { return p.Select("Pick", abc, "") }
	_, err := drive(t, []string{"/", "zzz", keyEnter, keyCtrlC}, sel)
	if !errors.Is(err, ErrAborted) {
		t.Errorf("ctrl-c after enter on an empty filter = %v, want ErrAborted", err)
	}
	// The first Esc closes the filter input, the next one leaves.
	_, err = drive(t, []string{"/", "zzz", keyEnter, keyEsc, keyEsc}, sel)
	if !errors.Is(err, ErrAborted) {
		t.Errorf("esc, esc after enter on an empty filter = %v, want ErrAborted", err)
	}
	got, err := drive(t, []string{"/", "zzz", keyEnter, keyBackspace, keyBackspace, keyBackspace, "be", keyEnter}, sel)
	if err != nil || got != "b" {
		t.Errorf("corrected filter then enter = %q, %v; want b", got, err)
	}
}

// While the filter matches nothing there is no row to move to. The library
// would put the cursor before the first row: a multi-select then panics on
// the next toggle and a select confirms a value that is not highlighted.
func TestPickerMoveKeysOnEmptyFilter(t *testing.T) {
	const keyEsc, keyCtrlD, keyBackspace = "\x1b", "\x04", "\x7f"
	multi := func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) }
	for _, tc := range []struct {
		keys []string
		want []string
	}{
		{[]string{"/", "zzz", keyDown, keyEnter, " ", keyEnter}, []string{"a"}},
		{[]string{"/", "zzz", keyCtrlD, keyEsc, keyDown, " ", keyEnter}, []string{"b"}},
		// With a match the cursor still moves inside the filter input.
		{[]string{"/", "a", keyDown, keyEnter, " ", keyEnter}, []string{"b"}},
	} {
		got, err := drive(t, tc.keys, multi)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("multi-select keys %q = %v, %v; want %v", tc.keys, got, err, tc.want)
		}
	}
	got, err := drive(t, []string{"/", "zzz", keyUp, keyCtrlD, keyBackspace, keyBackspace, keyBackspace, "ga", keyEnter},
		func(p Picker) (string, error) { return p.Select("Pick", abc, "") })
	if err != nil || got != "c" {
		t.Errorf("select: move keys on an empty filter, then a match = %q, %v; want c", got, err)
	}
}

func TestKnownSize(t *testing.T) {
	for _, c := range []struct{ w, h, wantW, wantH int }{
		{0, 0, 80, 24},
		{120, 0, 120, 24},
		{0, 40, 80, 40},
		{100, 30, 100, 30},
	} {
		got := knownSize(tea.WindowSizeMsg{Width: c.w, Height: c.h})
		if got.Width != c.wantW || got.Height != c.wantH {
			t.Errorf("knownSize(%dx%d) = %dx%d, want %dx%d", c.w, c.h, got.Width, got.Height, c.wantW, c.wantH)
		}
	}
}

// Tab must not confirm a multi-select, with a filter applied either: it
// would skip the check for a ticked row. The prompt stays open until it is
// left.
func TestPickerMultiSelectTabDoesNotConfirm(t *testing.T) {
	const keyEsc = "\x1b"
	for name, keys := range map[string][]string{
		"no filter":               {"\t", keyCtrlC},
		"filter applied by enter": {"/", "a", keyEnter, "\t", keyCtrlC},
		"filter applied by esc":   {"/", "a", keyEsc, "\t", keyCtrlC},
		"ticked, filter applied":  {" ", "/", "a", keyEnter, "\t", keyCtrlC},
	} {
		got, err := drive(t, keys, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
		if !errors.Is(err, ErrAborted) {
			t.Errorf("%s: MultiSelect = %v, %v; want ErrAborted", name, got, err)
		}
	}
}

// The keys that edit the filter text must not move the list as well:
// ctrl+u, ctrl+d and ctrl+k are editing keys there, and ctrl+a is the start
// of the line, not "tick all".
func TestPickerFilterEditingKeysDoNotMoveTheList(t *testing.T) {
	const keyCtrlA, keyCtrlD, keyCtrlK, keyCtrlU = "\x01", "\x04", "\x0b", "\x15"
	var many []Option
	for i := 0; i < 30; i++ {
		many = append(many, Option{Label: "option-" + string(rune('A'+i)), Value: string(rune('A' + i))})
	}
	tenDown := strings.Repeat(keyDown, 10)
	sel := func(p Picker) (string, error) { return p.Select("Pick", many, "") }
	for name, tc := range map[string]struct {
		keys []string
		want string
	}{
		// The cursor is on the eleventh row (K) and must stay there.
		"ctrl+u deletes the text":            {[]string{tenDown, "/", "option", keyCtrlU, keyEnter}, "K"},
		"ctrl+d at the end of the text":      {[]string{tenDown, "/", "option", keyCtrlD, keyEnter}, "K"},
		"ctrl+k at the end of the text":      {[]string{tenDown, "/", "option", keyCtrlK, keyEnter}, "K"},
		"ctrl+u on a filter without a match": {[]string{"/", "zzz", keyCtrlU, "option-c", keyEnter}, "C"},
		// Outside the filter input they move as before.
		"ctrl+k outside the filter": {[]string{keyDown + keyDown, keyCtrlK, keyEnter}, "B"},
		"ctrl+k after the filter":   {[]string{"/", "option", "\x1b", keyDown + keyDown, keyCtrlK, keyEnter}, "B"},
	} {
		got, err := drive(t, tc.keys, sel)
		if err != nil || got != tc.want {
			t.Errorf("select, %s: keys %q = %q, %v; want %q", name, tc.keys, got, err, tc.want)
		}
	}
	// Every label holds an "a". Ctrl+a in the filter input ticks nothing, so
	// the space that follows ticks the first row; outside it still ticks
	// all, and the space then unticks the first row.
	multi := func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) }
	for name, tc := range map[string]struct {
		keys []string
		want []string
	}{
		"ctrl+a in the filter input":  {[]string{"/", "a", keyCtrlA, keyEnter, " ", keyEnter}, []string{"a"}},
		"ctrl+a outside it":           {[]string{keyCtrlA, " ", keyEnter}, []string{"b", "c"}},
		"ctrl+a on an applied filter": {[]string{"/", "a", keyEnter, keyCtrlA, " ", keyEnter}, []string{"b", "c"}},
		"ctrl+a after the reminder":   {[]string{keyEnter, keyCtrlA, keyEnter}, []string{"a", "b", "c"}},
		"space after the reminder":    {[]string{keyEnter, keyDown, " ", keyEnter}, []string{"b"}},
	} {
		got, err := drive(t, tc.keys, multi)
		if err != nil || !reflect.DeepEqual(got, tc.want) {
			t.Errorf("multi-select, %s: keys %q = %v, %v; want %v", name, tc.keys, got, err, tc.want)
		}
	}
}

// heldOutput is a terminal that shows nothing until release is closed: its
// first write blocks, as the first frame of a prompt does for the time the
// program needs to start.
type heldOutput struct {
	syncBuffer
	once    sync.Once
	reached chan struct{} // closed when the first write arrived
	release chan struct{}
}

func (h *heldOutput) Write(p []byte) (int, error) {
	h.once.Do(func() { close(h.reached) })
	<-h.release
	return h.syncBuffer.Write(p)
}

func (h *heldOutput) shows(text string) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return strings.Contains(h.b.String(), text)
}

// A yes/no question on a terminal takes no key pressed before it is drawn:
// "y" then Enter sent while the program starts would confirm it unseen. Keys
// pressed once it is on screen answer it as usual.
func TestPickerConfirmDropsKeysPressedBeforeItIsDrawn(t *testing.T) {
	for _, tc := range []struct {
		name          string
		ahead, after  string
		dropTypeAhead bool
		want          bool
	}{
		{"typed ahead", "y" + keyEnter, keyEnter, true, false},
		{"typed ahead, then answered", "y" + keyEnter, "y" + keyEnter, true, true},
		{"typed ahead, then declined", keyEnter, "n" + keyEnter, true, false},
		// Not a terminal: every byte of the input counts.
		{"piped", "y", keyEnter, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pr, pw := io.Pipe()
			defer pw.Close()
			out := &heldOutput{reached: make(chan struct{}), release: make(chan struct{})}
			type result struct {
				v   bool
				err error
			}
			done := make(chan result, 1)
			go func() {
				p := &terminalPicker{in: pr, out: out, dropTypeAhead: tc.dropTypeAhead}
				v, err := p.Confirm("Sure?", false)
				done <- result{v, err}
			}()
			select {
			case <-out.reached:
			case <-time.After(10 * time.Second):
				close(out.release)
				t.Fatal("the prompt never drew anything")
			}
			// The program is running and nothing is on screen yet.
			if _, err := io.WriteString(pw, tc.ahead); err != nil {
				t.Fatal(err)
			}
			time.Sleep(150 * time.Millisecond)
			select {
			case r := <-done:
				close(out.release)
				t.Fatalf("answered before the question was drawn: %v, %v", r.v, r.err)
			default:
			}
			close(out.release)
			deadline := time.Now().Add(10 * time.Second)
			for !out.shows("Sure?") {
				if time.Now().After(deadline) {
					t.Fatal("the question was never drawn")
				}
				time.Sleep(10 * time.Millisecond)
			}
			time.Sleep(60 * time.Millisecond)
			if _, err := io.WriteString(pw, tc.after); err != nil {
				t.Fatal(err)
			}
			select {
			case r := <-done:
				if r.err != nil || r.v != tc.want {
					t.Errorf("Confirm = %v, %v; want %v", r.v, r.err, tc.want)
				}
			case <-time.After(10 * time.Second):
				t.Fatal("the prompt did not finish")
			}
		})
	}
}

// Ctrl-C leaves a yes/no question even before it is drawn.
func TestPickerConfirmCtrlCBeforeItIsDrawn(t *testing.T) {
	pr, pw := io.Pipe()
	defer pw.Close()
	out := &heldOutput{reached: make(chan struct{}), release: make(chan struct{})}
	done := make(chan error, 1)
	go func() {
		p := &terminalPicker{in: pr, out: out, dropTypeAhead: true}
		_, err := p.Confirm("Sure?", true)
		done <- err
	}()
	select {
	case <-out.reached:
	case <-time.After(10 * time.Second):
		close(out.release)
		t.Fatal("the prompt never drew anything")
	}
	if _, err := io.WriteString(pw, keyCtrlC); err != nil {
		t.Fatal(err)
	}
	time.Sleep(100 * time.Millisecond)
	close(out.release)
	select {
	case err := <-done:
		if !errors.Is(err, ErrAborted) {
			t.Errorf("ctrl-c = %v, want ErrAborted", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the prompt did not finish")
	}
}
