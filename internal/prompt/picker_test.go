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

func TestListHeight(t *testing.T) {
	if got := listHeight(3); got != 0 {
		t.Errorf("a short list must keep its natural height, got %d", got)
	}
	if got := listHeight(40); got <= 0 || got >= 40 {
		t.Errorf("a long list must be capped, got %d", got)
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

type fakeField struct {
	huh.Field
	filtering bool
}

func (f fakeField) GetFiltering() bool { return f.filtering }

func TestEscAborts(t *testing.T) {
	esc := tea.KeyPressMsg{Code: tea.KeyEscape}
	if esc.String() != "esc" {
		t.Fatalf("escape key renders as %q", esc.String())
	}
	if _, ok := escAborts(fakeField{}, esc).(tea.InterruptMsg); !ok {
		t.Error("Esc outside a filter must interrupt the prompt")
	}
	if _, ok := escAborts(fakeField{filtering: true}, esc).(tea.KeyPressMsg); !ok {
		t.Error("Esc while typing a filter must reach the field")
	}
	if _, ok := escAborts(huh.NewConfirm(), esc).(tea.InterruptMsg); !ok {
		t.Error("Esc on a field without a filter must interrupt the prompt")
	}
	down := tea.KeyPressMsg{Code: tea.KeyDown}
	if got := escAborts(fakeField{}, down); !reflect.DeepEqual(got, down) {
		t.Errorf("other keys must pass through, got %#v", got)
	}
	if got := escAborts(fakeField{}, tea.QuitMsg{}); !reflect.DeepEqual(got, tea.QuitMsg{}) {
		t.Errorf("other messages must pass through, got %#v", got)
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
	got, err = drive(t, []string{keyEnter}, func(p Picker) ([]string, error) { return p.MultiSelect("Pick", abc) })
	if err != nil || len(got) != 0 {
		t.Errorf("enter without a choice = %v, %v; want nothing", got, err)
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
		{[]string{"y"}, false, true},
		{[]string{"n"}, true, false},
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
