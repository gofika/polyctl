package prompt

import (
	"fmt"
	"strings"
	"testing"

	"charm.land/huh/v2"
)

// Every option of a short multi-select must be visible: the explicit height
// has to leave room for the title and description rows.
func TestMultiSelectShowsEveryOption(t *testing.T) {
	for n := 1; n <= 4; n++ {
		var opts []Option
		for i := 0; i < n; i++ {
			opts = append(opts, Option{Label: fmt.Sprintf("option-%d", i), Value: fmt.Sprint(i)})
		}
		var values []string
		field := huh.NewMultiSelect[string]().Title("Pick").
			Description("space toggles, enter confirms, esc cancels").
			Options(huhOptions(opts, 80)...).Value(&values)
		field.Height(n + 2)
		form := huh.NewForm(huh.NewGroup(field)).WithWidth(80)
		form.Init()
		view := form.View()
		for _, o := range opts {
			if !strings.Contains(view, o.Label) {
				t.Errorf("%d options: %q is not rendered:\n%s", n, o.Label, view)
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
}
