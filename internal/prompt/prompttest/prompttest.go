// Package prompttest provides a scripted prompt.Picker for tests of the
// interactive flow: it answers every question from a fixed list, records
// what was asked (title, options, default) so tests can assert the offered
// candidates (x86 only, available only, the "Create a new ..." entry), and
// fails the test on an unexpected question or an answer that is not offered.
package prompttest

import (
	"fmt"
	"strings"
	"testing"

	"github.com/gofika/polyctl/internal/prompt"
)

// Abort is a scripted answer: the user leaves the prompt with Esc or Ctrl-C.
type Abort struct{}

// Then is a scripted answer that first runs Do, while the prompt is open,
// and then answers with Answer: what happens while the user looks at a menu.
type Then struct {
	Do     func()
	Answer any
}

// KeepDefault is a scripted answer to Input: the user accepts the default.
type KeepDefault struct{}

// Label is a scripted answer to Select that names the option by a part of
// its label instead of its value (for sentinel values such as the "Create a
// new ..." entry).
type Label string

// Asked records one prompt shown by the picker.
type Asked struct {
	Kind    string // select, multi, confirm or input
	Title   string
	Options []prompt.Option
	Default string
}

// Picker answers prompts from Answers, in order: a string (a value) or a
// Label for Select, a string for Input (re-asked while the validator
// rejects it, the next answer being the correction), a []string for
// MultiSelect, a bool for Confirm, Abort{} for any of them.
type Picker struct {
	T       testing.TB
	Answers []any
	Asked   []Asked
}

// New returns a Picker with the given answers.
func New(t testing.TB, answers ...any) *Picker { return &Picker{T: t, Answers: answers} }

func (p *Picker) next(a Asked) (any, error) {
	p.T.Helper()
	p.Asked = append(p.Asked, a)
	if len(p.Answers) == 0 {
		p.T.Errorf("unexpected %s prompt %q: no scripted answer left", a.Kind, a.Title)
		return nil, prompt.ErrAborted
	}
	v := p.Answers[0]
	p.Answers = p.Answers[1:]
	if th, ok := v.(Then); ok {
		th.Do()
		v = th.Answer
	}
	if _, ok := v.(Abort); ok {
		return nil, prompt.ErrAborted
	}
	return v, nil
}

// HasValue reports whether v is the value of one of opts.
func HasValue(opts []prompt.Option, v string) bool {
	for _, o := range opts {
		if o.Value == v {
			return true
		}
	}
	return false
}

// Select answers with a value of opts, or the first option whose label
// contains a Label answer.
func (p *Picker) Select(title string, opts []prompt.Option, def string) (string, error) {
	p.T.Helper()
	v, err := p.next(Asked{Kind: "select", Title: title, Options: opts, Default: def})
	if err != nil {
		return "", err
	}
	if l, ok := v.(Label); ok {
		for _, o := range opts {
			if strings.Contains(o.Label, string(l)) {
				return o.Value, nil
			}
		}
		p.T.Errorf("select %q: no option label contains %q (options %v)", title, l, opts)
		return "", prompt.ErrAborted
	}
	s, ok := v.(string)
	if !ok || !HasValue(opts, s) {
		p.T.Errorf("select %q: scripted answer %#v is not one of the options %v", title, v, opts)
		return "", prompt.ErrAborted
	}
	return s, nil
}

// MultiSelect answers with values of opts.
func (p *Picker) MultiSelect(title string, opts []prompt.Option) ([]string, error) {
	p.T.Helper()
	v, err := p.next(Asked{Kind: "multi", Title: title, Options: opts})
	if err != nil {
		return nil, err
	}
	vs, ok := v.([]string)
	if !ok {
		p.T.Errorf("multi-select %q: scripted answer %#v is not a []string", title, v)
		return nil, prompt.ErrAborted
	}
	for _, s := range vs {
		if !HasValue(opts, s) {
			p.T.Errorf("multi-select %q: %q is not one of the options %v", title, s, opts)
		}
	}
	return vs, nil
}

// Confirm answers with a bool.
func (p *Picker) Confirm(title string, def bool) (bool, error) {
	p.T.Helper()
	v, err := p.next(Asked{Kind: "confirm", Title: title, Default: fmt.Sprint(def)})
	if err != nil {
		return false, err
	}
	b, ok := v.(bool)
	if !ok {
		p.T.Errorf("confirm %q: scripted answer %#v is not a bool", title, v)
		return false, prompt.ErrAborted
	}
	return b, nil
}

// Input behaves like the terminal: a value the validator rejects keeps the
// prompt open, and the next scripted answer is the user's correction.
func (p *Picker) Input(title, def string, validate func(string) error) (string, error) {
	p.T.Helper()
	for {
		v, err := p.next(Asked{Kind: "input", Title: title, Default: def})
		if err != nil {
			return "", err
		}
		s, ok := v.(string)
		if _, keep := v.(KeepDefault); keep {
			s, ok = def, true
		}
		if !ok {
			p.T.Errorf("input %q: scripted answer %#v is not a string", title, v)
			return "", prompt.ErrAborted
		}
		if validate == nil || validate(s) == nil {
			return s, nil
		}
	}
}

// Find returns the first recorded prompt with the given title.
func (p *Picker) Find(title string) *Asked {
	p.T.Helper()
	for i := range p.Asked {
		if p.Asked[i].Title == title {
			return &p.Asked[i]
		}
	}
	p.T.Errorf("no prompt titled %q was shown; prompts: %v", title, p.Titles())
	return &Asked{}
}

// Titles lists the prompts shown, as "kind:title".
func (p *Picker) Titles() []string {
	var out []string
	for _, a := range p.Asked {
		out = append(out, a.Kind+":"+a.Title)
	}
	return out
}

// Done fails the test when scripted answers were never asked for.
func (p *Picker) Done() {
	p.T.Helper()
	if len(p.Answers) != 0 {
		p.T.Errorf("%d scripted answer(s) were never asked for: %#v (prompts: %v)", len(p.Answers), p.Answers, p.Titles())
	}
}

// Values joins the values of opts with spaces, for assertions.
func Values(opts []prompt.Option) string {
	var out []string
	for _, o := range opts {
		out = append(out, o.Value)
	}
	return strings.Join(out, " ")
}

// Labels joins the labels of opts with newlines, for assertions.
func Labels(opts []prompt.Option) string {
	var out []string
	for _, o := range opts {
		out = append(out, o.Label)
	}
	return strings.Join(out, "\n")
}
