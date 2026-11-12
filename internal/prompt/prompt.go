// Package prompt implements the small amount of interactive input polyctl needs.
package prompt

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"runtime"
	"strings"

	"golang.org/x/term"
)

// ErrNotInteractive is returned when a question would have to be asked in the
// non-interactive flow, where nothing is ever asked. It is a usage error:
// the caller left out a value it has to pass. Leaving a prompt in the
// interactive flow is ErrAborted instead.
var ErrNotInteractive = errors.New("input required, but polyctl is not running interactively (no terminal, --no-input or POLYCTL_NO_INPUT)")

// ErrNoValue is returned by ReadValue when stdin holds no value: it ended,
// or its first line is empty.
var ErrNoValue = errors.New("no value on stdin")

// ErrStdinTerminal is returned by ReadValue when stdin is a terminal: the
// non-interactive flow reads piped data only, never what a person types.
var ErrStdinTerminal = errors.New("stdin is a terminal; the value has to be piped")

// IO bundles the streams used by prompts.
type IO struct {
	In  io.Reader
	Out io.Writer
	Err io.Writer

	reader *bufio.Reader
	// interactive is the flow the command runs in, decided by the caller
	// (app.Runtime.Interactive) and never by looking at the streams here.
	interactive bool
	// ctx ends a prompt that is waiting for input (see WithContext).
	ctx context.Context
	// editor reads lines from a terminal in raw mode. It is kept between
	// prompts because it holds the input read past the end of a line.
	editor *term.Terminal
}

// New returns an IO using the given streams (nil means os.Std*). It is in
// the non-interactive flow, where every question fails with
// ErrNotInteractive without printing or reading anything, until
// WithInteractive says otherwise.
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

// WithContext makes the prompts of p end with ErrAborted once ctx is done
// (the command was interrupted), instead of waiting for a line that will
// never be used. It returns p.
func (p *IO) WithContext(ctx context.Context) *IO {
	p.ctx = ctx
	return p
}

// WithInteractive sets the flow of p: true lets its questions be asked,
// false makes them fail with ErrNotInteractive. It returns p.
func (p *IO) WithInteractive(interactive bool) *IO {
	p.interactive = interactive
	return p
}

// Interactive reports the flow handed to WithInteractive.
func (p *IO) Interactive() bool { return p.interactive }

// refuse is the error of a question that cannot be asked.
func refuse(label string) error {
	label = strings.TrimSuffix(strings.TrimSpace(label), ":")
	return fmt.Errorf("%w: cannot ask for %q", ErrNotInteractive, label)
}

// ReadValue reads one value from stdin for the non-interactive flow: a
// single line, trimmed, without printing a label. Several calls read
// successive lines. A stdin that is a terminal is not read (ErrStdinTerminal)
// and one without a value is ErrNoValue.
func (p *IO) ReadValue() (string, error) {
	if p.ctx != nil && p.ctx.Err() != nil {
		return "", p.ctx.Err()
	}
	if IsTerminal(p.In) {
		return "", ErrStdinTerminal
	}
	s, err := p.readString()
	if errors.Is(err, ErrAborted) {
		// Nothing was asked, so nothing was left: the command was interrupted.
		return "", context.Cause(p.ctx)
	}
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	if s = strings.TrimSpace(s); s == "" {
		return "", ErrNoValue
	}
	return s, nil
}

// done is closed when the prompt's context is; it is nil without one.
func (p *IO) done() <-chan struct{} {
	if p.ctx == nil {
		return nil
	}
	return p.ctx.Done()
}

// rawLineEditor says whether lines typed on a terminal are read in raw mode,
// where Ctrl-C and Ctrl-D are keys that leave the prompt. On Windows the
// console keeps its line mode: there Ctrl-C interrupts the command, which
// ends the prompt through the context.
const rawLineEditor = runtime.GOOS != "windows"

// read prints label and reads one line: without echo when secret is set and
// the input is a terminal. Leaving the prompt (Ctrl-C, Ctrl-D on an empty
// line, an interrupted command, input that ends) is ErrAborted. In the
// non-interactive flow nothing is printed or read: it is ErrNotInteractive.
func (p *IO) read(label string, secret bool) (string, error) {
	if !p.interactive {
		return "", refuse(label)
	}
	if p.ctx != nil && p.ctx.Err() != nil {
		return "", ErrAborted
	}
	// The flow is interactive; what follows only picks the way to read: a
	// terminal is read in raw mode, anything else (scripted input in tests)
	// line by line.
	f, _ := p.In.(*os.File)
	onTerminal := IsTerminal(p.In)
	if onTerminal && rawLineEditor && (secret || IsTerminal(p.Err)) {
		// A visible line is echoed by the editor, on Err: when that is not
		// the terminal the line mode below echoes instead.
		if s, err, ok := p.readRaw(f, label, secret); ok {
			return s, err
		}
	}
	if onTerminal && secret {
		return p.readPassword(f, label)
	}
	fmt.Fprint(p.Err, label)
	s, err := p.readString()
	if err != nil && (s == "" || !errors.Is(err, io.EOF)) {
		// Terminate the label line so the caller's error message does not
		// share it.
		fmt.Fprintln(p.Err)
		if errors.Is(err, ErrAborted) || errors.Is(err, io.EOF) {
			return "", ErrAborted // Ctrl-D, or the input ended
		}
		return "", err
	}
	return s, nil
}

type lineResult struct {
	s   string
	err error
}

// readString reads up to the next newline of the buffered input. The read
// runs aside when a context can end the prompt first.
func (p *IO) readString() (string, error) {
	done := p.done()
	if done == nil {
		return p.reader.ReadString('\n')
	}
	ch := make(chan lineResult, 1)
	go func() {
		s, err := p.reader.ReadString('\n')
		ch <- lineResult{s, err}
	}()
	select {
	case r := <-ch:
		return r.s, r.err
	case <-done:
		// The read stays blocked; every later prompt of p fails at once, so
		// nothing else reads the input meanwhile.
		return "", ErrAborted
	}
}

// readRaw reads a line from the terminal f in raw mode, where the terminal
// neither echoes nor turns Ctrl-C into a signal: the line editor sees the
// key and ends the prompt. ok is false when the terminal could not be put
// in raw mode and nothing was printed or read.
func (p *IO) readRaw(f *os.File, label string, secret bool) (s string, err error, ok bool) {
	fd := int(f.Fd())
	state, rawErr := term.MakeRaw(fd)
	if rawErr != nil {
		return "", nil, false
	}
	restored := false
	restore := func() {
		if !restored {
			restored = true
			_ = term.Restore(fd, state)
		}
	}
	defer restore()
	if p.editor == nil {
		p.editor = term.NewTerminal(struct {
			io.Reader
			io.Writer
		}{f, p.Err}, "")
	}
	ed := p.editor
	if out, isFile := p.Err.(*os.File); isFile {
		if w, h, err := term.GetSize(int(out.Fd())); err == nil && w > 0 && h > 0 {
			_ = ed.SetSize(w, h)
		}
	}
	ch := make(chan lineResult, 1)
	go func() {
		var r lineResult
		if secret {
			r.s, r.err = ed.ReadPassword(label)
		} else {
			ed.SetPrompt(label)
			r.s, r.err = ed.ReadLine()
		}
		ch <- r
	}()
	select {
	case r := <-ch:
		if r.err == nil {
			return r.s, nil, true
		}
		// The editor reports Ctrl-C, Ctrl-D on an empty line and a closed
		// terminal alike as the end of the input.
		restore()
		fmt.Fprintln(p.Err)
		if errors.Is(r.err, io.EOF) {
			return "", ErrAborted, true
		}
		return "", r.err, true
	case <-p.done():
		// Interrupted from outside (SIGINT, SIGTERM). The editor stays
		// blocked in its read and is not used again.
		p.editor = nil
		restore()
		fmt.Fprintln(p.Err)
		return "", ErrAborted, true
	}
}

// readPassword reads a line without echo in the terminal's line mode. The
// read cannot be stopped, so on an interrupted command it is left behind
// and the terminal is given its echo back.
func (p *IO) readPassword(f *os.File, label string) (string, error) {
	fd := int(f.Fd())
	state, stateErr := term.GetState(fd)
	fmt.Fprint(p.Err, label)
	ch := make(chan lineResult, 1)
	go func() {
		b, err := term.ReadPassword(fd)
		ch <- lineResult{string(b), err}
	}()
	select {
	case r := <-ch:
		fmt.Fprintln(p.Err)
		if errors.Is(r.err, io.EOF) {
			return "", ErrAborted
		}
		return r.s, r.err
	case <-p.done():
		if stateErr == nil {
			_ = term.Restore(fd, state)
		}
		fmt.Fprintln(p.Err)
		return "", ErrAborted
	}
}

// Line prompts for a line of text. def is used when the user enters nothing.
func (p *IO) Line(label, def string) (string, error) {
	if def != "" {
		label = fmt.Sprintf("%s [%s]", label, def)
	}
	s, err := p.read(label+": ", false)
	if err != nil {
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
	s, err := p.read(label+": ", true)
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(s), nil
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
	if !p.interactive {
		return false, refuse(label)
	}
	// What was typed before the question appeared is not an answer to it
	// (only a terminal holds such input; for anything else this is a no-op).
	if f, ok := p.In.(*os.File); ok {
		discardInput(f)
		p.editor = nil // with what it had read ahead
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
	if !p.interactive {
		return "", refuse(label)
	}
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
