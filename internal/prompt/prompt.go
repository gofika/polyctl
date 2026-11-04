// Package prompt implements the small amount of interactive input polyctl needs.
package prompt

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"golang.org/x/term"
)

// ErrNotInteractive is returned when input is required but stdin is not a terminal.
var ErrNotInteractive = errors.New("interactive input required (stdin closed or not a terminal); pass the value with --set or on stdin")

// IO bundles the streams used by prompts.
type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	reader *bufio.Reader
}

// New returns an IO using the given streams (nil means os.Std*).
func New(in io.Reader, out, errw io.Writer) *IO {
	if in == nil {
		in = os.Stdin
	}
	if out == nil {
		out = os.Stdout
	}
	if errw == nil {
		errw = os.Stderr
	}
	return &IO{In: in, Out: out, Err: errw, reader: bufio.NewReader(in)}
}

// IsTerminal reports whether the input is an interactive terminal.
func (p *IO) IsTerminal() bool {
	f, ok := p.In.(*os.File)
	return ok && term.IsTerminal(int(f.Fd()))
}

// Line prompts for a line of text. def is used when the user enters nothing.
func (p *IO) Line(label, def string) (string, error) {
	if def != "" {
		fmt.Fprintf(p.Err, "%s [%s]: ", label, def)
	} else {
		fmt.Fprintf(p.Err, "%s: ", label)
	}
	s, err := p.reader.ReadString('\n')
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		// Terminate the label line so the caller's error message does not
		// share it.
		fmt.Fprintln(p.Err)
		if errors.Is(err, io.EOF) {
			return "", ErrNotInteractive
		}
		return "", err
	}
	s = strings.TrimSpace(s)
	if s == "" {
		return def, nil
	}
	return s, nil
}

// Required prompts until a non-empty value is given.
func (p *IO) Required(label string) (string, error) {
	for {
		s, err := p.Line(label, "")
		if err != nil {
			return "", err
		}
		if s != "" {
			return s, nil
		}
		fmt.Fprintln(p.Err, "a value is required")
	}
}

// Secret prompts without echo when possible.
func (p *IO) Secret(label string) (string, error) {
	f, ok := p.In.(*os.File)
	if ok && term.IsTerminal(int(f.Fd())) {
		fmt.Fprintf(p.Err, "%s: ", label)
		b, err := term.ReadPassword(int(f.Fd()))
		fmt.Fprintln(p.Err)
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(b)), nil
	}
	return p.Line(label, "")
}

// RequiredSecret prompts until a non-empty secret is given.
func (p *IO) RequiredSecret(label string) (string, error) {
	for {
		s, err := p.Secret(label)
		if err != nil {
			return "", err
		}
		if s != "" {
			return s, nil
		}
		fmt.Fprintln(p.Err, "a value is required")
	}
}

// Confirm asks a yes/no question.
func (p *IO) Confirm(label string, def bool) (bool, error) {
	hint := "y/N"
	if def {
		hint = "Y/n"
	}
	s, err := p.Line(fmt.Sprintf("%s (%s)", label, hint), "")
	if err != nil {
		return false, err
	}
	switch strings.ToLower(s) {
	case "":
		return def, nil
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

// Choose asks the user to pick one of options (by number or value).
func (p *IO) Choose(label string, options []string, def string) (string, error) {
	for i, o := range options {
		marker := " "
		if o == def {
			marker = "*"
		}
		fmt.Fprintf(p.Err, " %s %d) %s\n", marker, i+1, o)
	}
	for {
		s, err := p.Line(label, def)
		if err != nil {
			return "", err
		}
		for i, o := range options {
			if s == o || s == fmt.Sprint(i+1) {
				return o, nil
			}
		}
		fmt.Fprintf(p.Err, "choose one of 1-%d\n", len(options))
	}
}
