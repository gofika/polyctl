package prompt

import (
	"bytes"
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"
)

func TestLinePrompts(t *testing.T) {
	var errw bytes.Buffer
	p := New(strings.NewReader("  one  \n\n\ntwo\nsecret\nlast"), io.Discard, &errw).WithInteractive(true)
	if s, err := p.Line("Name", ""); err != nil || s != "one" {
		t.Errorf("Line = %q, %v; want one", s, err)
	}
	if s, err := p.Line("Region", "eu"); err != nil || s != "eu" {
		t.Errorf("Line with a default on an empty line = %q, %v; want eu", s, err)
	}
	if s, err := p.Required("Key"); err != nil || s != "two" {
		t.Errorf("Required = %q, %v; want two", s, err)
	}
	if s, err := p.RequiredSecret("Token"); err != nil || s != "secret" {
		t.Errorf("RequiredSecret = %q, %v; want secret", s, err)
	}
	// A last line without a newline still counts.
	if s, err := p.Line("Last", ""); err != nil || s != "last" {
		t.Errorf("Line at the end of the input = %q, %v; want last", s, err)
	}
	for _, want := range []string{"Name: ", "Region [eu]: ", "a value is required", "Token: "} {
		if !strings.Contains(errw.String(), want) {
			t.Errorf("prompts lack %q: %q", want, errw.String())
		}
	}
}

// Input that ends where a value is required must end the prompt, also the
// ones that ask again on an empty value: the question was left.
func TestPromptsEndWithTheInput(t *testing.T) {
	for name, ask := range map[string]func(*IO) error{
		"Line":           func(p *IO) error { _, err := p.Line("x", ""); return err },
		"Required":       func(p *IO) error { _, err := p.Required("x"); return err },
		"Secret":         func(p *IO) error { _, err := p.Secret("x"); return err },
		"RequiredSecret": func(p *IO) error { _, err := p.RequiredSecret("x"); return err },
		"Confirm":        func(p *IO) error { _, err := p.Confirm("x", false); return err },
		"Choose":         func(p *IO) error { _, err := p.Choose("x", []string{"a", "b"}, ""); return err },
	} {
		for _, input := range []string{"", "\n\n"} {
			err := ask(New(strings.NewReader(input), io.Discard, io.Discard).WithInteractive(true).WithContext(context.Background()))
			if input == "" && !errors.Is(err, ErrAborted) {
				t.Errorf("%s on empty input = %v, want ErrAborted", name, err)
			}
			if strings.HasPrefix(name, "Required") && !errors.Is(err, ErrAborted) {
				t.Errorf("%s on input %q = %v, want ErrAborted", name, input, err)
			}
		}
	}
}

// An interrupted command must end a prompt that waits for input, and every
// prompt after it: the read itself cannot be stopped.
func TestPromptsEndWithTheContext(t *testing.T) {
	for name, ask := range map[string]func(*IO) error{
		"Line":           func(p *IO) error { _, err := p.Line("x", ""); return err },
		"Required":       func(p *IO) error { _, err := p.Required("x"); return err },
		"Secret":         func(p *IO) error { _, err := p.Secret("x"); return err },
		"RequiredSecret": func(p *IO) error { _, err := p.RequiredSecret("x"); return err },
		"Confirm":        func(p *IO) error { _, err := p.Confirm("x", true); return err },
		"Choose":         func(p *IO) error { _, err := p.Choose("x", []string{"a", "b"}, "a"); return err },
	} {
		pr, pw := io.Pipe() // never written: the read blocks
		ctx, cancel := context.WithCancel(context.Background())
		p := New(pr, io.Discard, io.Discard).WithInteractive(true).WithContext(ctx)
		done := make(chan error, 1)
		go func() { done <- ask(p) }()
		time.AfterFunc(20*time.Millisecond, cancel)
		select {
		case err := <-done:
			if !errors.Is(err, ErrAborted) {
				t.Errorf("%s after the context ended = %v, want ErrAborted", name, err)
			}
		case <-time.After(5 * time.Second):
			t.Errorf("%s still waits after the context ended", name)
		}
		if err := ask(p); !errors.Is(err, ErrAborted) {
			t.Errorf("%s on an ended context = %v, want ErrAborted", name, err)
		}
		cancel()
		pw.Close()
	}
}

// Input from a pipe is an answer wherever it was written: nothing of it is
// discarded before a yes/no question.
func TestConfirmKeepsPipedInput(t *testing.T) {
	p := New(strings.NewReader("y\nno\n\n"), io.Discard, io.Discard).WithInteractive(true)
	for i, want := range []bool{true, false, true} {
		if got, err := p.Confirm("Sure", true); err != nil || got != want {
			t.Errorf("answer %d = %v, %v; want %v", i, got, err, want)
		}
	}
}

// countingReader fails the test when it is read.
type countingReader struct {
	t     *testing.T
	reads int
}

func (r *countingReader) Read([]byte) (int, error) {
	r.reads++
	r.t.Error("stdin was read in the non-interactive flow")
	return 0, io.EOF
}

// In the non-interactive flow, which is the one New starts in, no question
// prints a label or reads anything: each is ErrNotInteractive at once.
func TestNonInteractiveAsksNothing(t *testing.T) {
	for name, ask := range map[string]func(*IO) error{
		"Line":           func(p *IO) error { _, err := p.Line("x", "def"); return err },
		"Required":       func(p *IO) error { _, err := p.Required("x"); return err },
		"Secret":         func(p *IO) error { _, err := p.Secret("x"); return err },
		"RequiredSecret": func(p *IO) error { _, err := p.RequiredSecret("x"); return err },
		"Confirm":        func(p *IO) error { _, err := p.Confirm("x", true); return err },
		"Choose":         func(p *IO) error { _, err := p.Choose("x", []string{"a", "b"}, "a"); return err },
	} {
		for _, switchedOff := range []bool{false, true} {
			in := &countingReader{t: t}
			var out, errw bytes.Buffer
			p := New(in, &out, &errw)
			if switchedOff {
				p = p.WithInteractive(true).WithInteractive(false)
			}
			if p.Interactive() {
				t.Fatalf("%s: the IO must not be interactive", name)
			}
			err := ask(p.WithContext(context.Background()))
			if !errors.Is(err, ErrNotInteractive) || !strings.Contains(err.Error(), `"x`) {
				t.Errorf("%s = %v, want ErrNotInteractive naming the question", name, err)
			}
			if in.reads != 0 || out.Len() != 0 || errw.Len() != 0 {
				t.Errorf("%s: %d reads, stdout %q, stderr %q; want nothing", name, in.reads, out.String(), errw.String())
			}
		}
	}
}

// ReadValue is the one read of the non-interactive flow: a line per call,
// trimmed, no label; one reader, so nothing buffered is lost.
func TestReadValue(t *testing.T) {
	var out, errw bytes.Buffer
	p := New(strings.NewReader("  one \r\ntwo\n\nlast"), &out, &errw)
	for _, want := range []string{"one", "two"} {
		if got, err := p.ReadValue(); err != nil || got != want {
			t.Errorf("ReadValue = %q, %v; want %q", got, err, want)
		}
	}
	if _, err := p.ReadValue(); !errors.Is(err, ErrNoValue) {
		t.Errorf("ReadValue on an empty line = %v, want ErrNoValue", err)
	}
	if got, err := p.ReadValue(); err != nil || got != "last" {
		t.Errorf("ReadValue on a last line without newline = %q, %v", got, err)
	}
	if _, err := p.ReadValue(); !errors.Is(err, ErrNoValue) {
		t.Errorf("ReadValue at the end of the input = %v, want ErrNoValue", err)
	}
	if out.Len() != 0 || errw.Len() != 0 {
		t.Errorf("ReadValue printed: stdout %q, stderr %q", out.String(), errw.String())
	}

	// An interrupted command ends the read with the context's error, never
	// with ErrAborted: no prompt was left.
	pr, pw := io.Pipe()
	defer pw.Close()
	ctx, cancel := context.WithCancel(context.Background())
	p = New(pr, io.Discard, io.Discard).WithContext(ctx)
	done := make(chan error, 1)
	go func() { _, err := p.ReadValue(); done <- err }()
	time.AfterFunc(20*time.Millisecond, cancel)
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) || errors.Is(err, ErrAborted) {
			t.Errorf("ReadValue after the context ended = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Error("ReadValue still waits after the context ended")
	}
	if _, err := p.ReadValue(); !errors.Is(err, context.Canceled) {
		t.Errorf("ReadValue on an ended context = %v, want context.Canceled", err)
	}
}
