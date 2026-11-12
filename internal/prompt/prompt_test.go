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
	p := New(strings.NewReader("  one  \n\n\ntwo\nsecret\nlast"), io.Discard, &errw)
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
// ones that ask again on an empty value.
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
			err := ask(New(strings.NewReader(input), io.Discard, io.Discard).WithContext(context.Background()))
			if input == "" && !errors.Is(err, ErrNotInteractive) {
				t.Errorf("%s on empty input = %v, want ErrNotInteractive", name, err)
			}
			if strings.HasPrefix(name, "Required") && !errors.Is(err, ErrNotInteractive) {
				t.Errorf("%s on input %q = %v, want ErrNotInteractive", name, input, err)
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
		p := New(pr, io.Discard, io.Discard).WithContext(ctx)
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
	p := New(strings.NewReader("y\nno\n\n"), io.Discard, io.Discard)
	for i, want := range []bool{true, false, true} {
		if got, err := p.Confirm("Sure", true); err != nil || got != want {
			t.Errorf("answer %d = %v, %v; want %v", i, got, err, want)
		}
	}
}
