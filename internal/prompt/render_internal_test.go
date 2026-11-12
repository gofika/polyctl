package prompt

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	tea "charm.land/bubbletea/v2"
	"charm.land/huh/v2"
	"github.com/charmbracelet/colorprofile"
	"github.com/charmbracelet/x/ansi"
)

func numbered(n int) []Option {
	var opts []Option
	for i := 0; i < n; i++ {
		opts = append(opts, Option{Label: fmt.Sprintf("option-%d.", i), Value: fmt.Sprint(i)})
	}
	return opts
}

// Every option of a short multi-select must be visible, on a narrow terminal
// too and also after Enter on an unticked list replaced the description: the
// explicit height has to leave room for the title and description rows,
// however many rows they wrap to.
func TestMultiSelectShowsEveryOption(t *testing.T) {
	for _, cols := range []int{80, 40, 30, 24} {
		for n := 1; n <= 5; n++ {
			opts := numbered(n)
			var values []string
			field, ticked := multiSelectField("Pick the rows to delete", huhOptions(opts, 80), &values, cols, 24)
			form := huh.NewForm(huh.NewGroup(field))
			form.Init()
			for _, reminded := range []bool{false, true} {
				if reminded && ticked() {
					t.Fatal("an unticked list must not confirm")
				}
				form.Update(tea.WindowSizeMsg{Width: cols, Height: 24})
				view := form.View()
				for _, o := range opts {
					if !strings.Contains(view, o.Label) {
						t.Errorf("%d columns, %d options, reminded=%v: %q is not rendered:\n%s", cols, n, reminded, o.Label, view)
					}
				}
				if want := map[bool]string{false: "then", true: "Nothing"}[reminded]; !strings.Contains(view, want) {
					t.Errorf("%d columns, reminded=%v: description is missing:\n%s", cols, reminded, view)
				}
			}
		}
	}
}

// A prompt must not be taller than the terminal: the rows that do not fit
// scroll off at the top, and the first row is the title and filter input.
func TestLongListsFitShortTerminals(t *testing.T) {
	opts := numbered(40)
	for _, termRows := range []int{24, 14, 10, 8} {
		var values []string
		multi, ticked := multiSelectField("Pick many", huhOptions(opts, 80), &values, 80, termRows)
		ticked()

		var value string
		single := huh.NewSelect[string]().Title("Pick one").Options(huhOptions(opts, 80)...).Value(&value)
		if rows := visibleRows(len(opts), termRows, 1); rows < len(opts) {
			single.Height(rows + 1)
		}

		for name, field := range map[string]huh.Field{"multi-select": multi, "select": single} {
			form := huh.NewForm(huh.NewGroup(field))
			form.Init()
			form.Update(tea.WindowSizeMsg{Width: 80, Height: termRows})
			view := form.View()
			if got := strings.Count(view, "\n") + 1; got >= termRows {
				t.Errorf("%s on %d rows takes %d rows:\n%s", name, termRows, got, view)
			}
			if !strings.Contains(view, "Pick") {
				t.Errorf("%s on %d rows: the title is not rendered:\n%s", name, termRows, view)
			}
		}
	}
}

func TestTruncate(t *testing.T) {
	if got := truncate("short", 10); got != "short" {
		t.Errorf("truncate = %q", got)
	}
	if got := truncate("abcdefghij", 5); got != "abcd…" {
		t.Errorf("truncate = %q", got)
	}
	// Wide characters take two columns each: the limit is columns, not runes.
	wide := strings.Repeat("示例科技有限公司", 10)
	for _, n := range []int{20, 5, 4} {
		got := truncate(wide, n)
		if w := ansi.StringWidth(got); w > n || !strings.HasSuffix(got, "…") {
			t.Errorf("truncate(wide, %d) = %q (%d columns), want at most %d columns ending in an ellipsis", n, got, w, n)
		}
	}
}

// A label cut to labelWidth must stay on one row, with wide characters and on
// a narrow terminal too: a wrapped row pushes other options out of the list.
func TestLabelsStayOnOneRow(t *testing.T) {
	long := strings.Repeat("示例科技有限公司", 12)
	for _, cols := range []int{80, 26, 22, 12} {
		opts := []Option{{Label: long + "1", Value: "1"}, {Label: long + "2", Value: "2"}, {Label: strings.Repeat("x", 200), Value: "3"}}
		var value string
		var values []string
		single := huh.NewSelect[string]().Title("One").Options(huhOptions(opts, max(cols-selectPrefix-1, 4))...).Value(&value)
		multi, _ := multiSelectField("Many", huhOptions(opts, max(cols-multiSelectPrefix-1, 4)), &values, cols, 40)
		for name, field := range map[string]huh.Field{"select": single, "multi-select": multi} {
			form := huh.NewForm(huh.NewGroup(field))
			form.Init()
			form.Update(tea.WindowSizeMsg{Width: cols, Height: 40})
			view := form.View()
			// The field's rows start with its border; the key hints below
			// are not part of it.
			cut := 0
			for _, line := range strings.Split(view, "\n") {
				if !strings.Contains(line, "┃") {
					continue
				}
				if strings.Contains(line, "…") {
					cut++
				}
				if w := ansi.StringWidth(line); w > cols {
					t.Errorf("%s on %d columns: a row takes %d columns: %q", name, cols, w, line)
				}
			}
			if cut != len(opts) {
				t.Errorf("%s on %d columns: %d of %d options are on one row with an ellipsis:\n%s", name, cols, cut, len(opts), view)
			}
		}
	}
}

// press sends a key to the form the way the picker's key filter leaves it:
// the keys that close the filter input go through leaveFilterInput's path.
func press(form *huh.Form, cols int, keys ...tea.KeyPressMsg) string {
	for _, k := range keys {
		form.Update(k)
	}
	form.Update(tea.WindowSizeMsg{Width: cols, Height: 24})
	return ansi.Strip(form.View())
}

// hintLine is the row of key hints: the last row of the view.
func hintLine(view string) string {
	lines := strings.Split(strings.TrimRight(view, "\n"), "\n")
	return lines[len(lines)-1]
}

func runeKey(r rune) tea.KeyPressMsg { return tea.KeyPressMsg{Code: r, Text: string(r)} }

// The hint line must say how to confirm and how to leave on a narrow
// terminal too, and must never be wider than the terminal.
func TestHintsFitNarrowTerminals(t *testing.T) {
	for _, cols := range []int{120, 80, 60, 40, 30} {
		fields := map[string]func() huh.Field{
			"select": func() huh.Field {
				var v string
				return huh.NewSelect[string]().Title("One").Options(huhOptions(abc, 20)...).Value(&v)
			},
			"multi-select": func() huh.Field {
				var v []string
				f, _ := multiSelectField("Many", huhOptions(abc, 20), &v, cols, 24)
				return f
			},
			"confirm": func() huh.Field {
				var v bool
				return huh.NewConfirm().Title("Sure?").Value(&v)
			},
			"input": func() huh.Field {
				var v string
				return huh.NewInput().Title("Name").Value(&v)
			},
		}
		for name, build := range fields {
			field := build()
			km := keyMap()
			form := newForm(field, km)
			form.Init()
			hint := hintLine(press(form, cols))
			if w := ansi.StringWidth(hint); w >= cols {
				t.Errorf("%s on %d columns: the hint line takes %d columns: %q", name, cols, w, hint)
			}
			for _, want := range []string{"enter confirm", "esc cancel"} {
				if !strings.Contains(hint, want) {
					t.Errorf("%s on %d columns: hint lacks %q: %q", name, cols, want, hint)
				}
			}
			if cols >= 80 && strings.Contains(hint, "…") {
				t.Errorf("%s on %d columns: the hint line is cut: %q", name, cols, hint)
			}
			if _, ok := field.(filterer); !ok {
				continue
			}
			// While the filter is typed Esc belongs to it.
			syncFilterHint(field, km, false, false, false)
			hint = hintLine(press(form, cols, runeKey('/'), runeKey('a')))
			if w := ansi.StringWidth(hint); w >= cols {
				t.Errorf("%s on %d columns, filtering: the hint line takes %d columns: %q", name, cols, w, hint)
			}
			// Below 40 columns not even the two filter hints of a select fit.
			if cols >= 40 && !strings.Contains(hint, "esc set filter") || strings.Contains(hint, "esc cancel") {
				t.Errorf("%s on %d columns, filtering: hint = %q", name, cols, hint)
			}
		}
	}
}

// With a filter applied to a multi-select the hints are those of the list
// again: Enter confirms, Esc clears the filter, and the keys that move
// between the fields of a form stay off (Tab would confirm the list without
// the check for a ticked row).
func TestHintsAfterApplyingAFilter(t *testing.T) {
	for _, closing := range []tea.KeyPressMsg{{Code: tea.KeyEnter}, {Code: tea.KeyEscape}} {
		var v []string
		field, _ := multiSelectField("Many", huhOptions(abc, 20), &v, 80, 24)
		km := keyMap()
		form := newForm(field, km)
		form.Init()
		syncFilterHint(field, km, false, false, false)
		press(form, 80, runeKey('/'), runeKey('a'))
		// What leaveFilterInput does with the key that closes the input.
		field.Update(closing)
		if !filterApplied(field, km) {
			t.Fatalf("%s: the filter is not applied", closing)
		}
		syncFilterHint(field, km, false, true, false)
		hint := hintLine(press(form, 80))
		for _, want := range []string{"enter confirm", "esc clear filter"} {
			if !strings.Contains(hint, want) {
				t.Errorf("%s: hint lacks %q: %q", closing, want, hint)
			}
		}
		for _, bad := range []string{"shift+tab", "esc cancel"} {
			if strings.Contains(hint, bad) {
				t.Errorf("%s: hint shows %q: %q", closing, bad, hint)
			}
		}
	}
}

// The selected answer of a yes/no question must be told apart without
// colours: Yes-selected and No-selected have to differ once a terminal
// profile without colours has dropped them.
func TestConfirmSelectionVisibleWithoutColour(t *testing.T) {
	views := map[bool]string{}
	for _, yes := range []bool{true, false} {
		v := yes
		form := newForm(huh.NewConfirm().Title("Sure?").Value(&v), keyMap())
		form.Init()
		form.Update(tea.WindowSizeMsg{Width: 80, Height: 24})
		var out bytes.Buffer
		w := colorprofile.Writer{Forward: &out, Profile: colorprofile.Ascii}
		if _, err := w.WriteString(form.View()); err != nil {
			t.Fatal(err)
		}
		views[yes] = out.String()
		if strings.Contains(views[yes], "[38;") || strings.Contains(views[yes], "[48;") {
			t.Fatalf("colours survived the Ascii profile: %q", views[yes])
		}
	}
	if views[true] == views[false] {
		t.Errorf("Yes-selected and No-selected look the same without colours: %q", views[true])
	}
	if !strings.Contains(views[true], "\x1b[4") {
		t.Errorf("the selected button is not underlined: %q", views[true])
	}
}
