package fsutil

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

var errBusy = errors.New("busy")

func TestRetryUntilTheTargetIsFree(t *testing.T) {
	calls, slept := 0, time.Duration(0)
	err := retry(func() error {
		calls++
		if calls < 3 {
			return errBusy
		}
		return nil
	}, func(err error) bool { return errors.Is(err, errBusy) }, func(d time.Duration) { slept += d })
	if err != nil || calls != 3 {
		t.Fatalf("retry = %v after %d calls", err, calls)
	}
	if slept != retryFirst*3 {
		t.Errorf("waited %v, want %v", slept, retryFirst*3)
	}
}

func TestRetryGivesUp(t *testing.T) {
	calls, slept := 0, time.Duration(0)
	err := retry(func() error { calls++; return errBusy },
		func(err error) bool { return true }, func(d time.Duration) { slept += d })
	if !errors.Is(err, errBusy) {
		t.Fatalf("retry = %v", err)
	}
	if slept < retryFor || slept > 3*retryFor {
		t.Errorf("waited %v before giving up, want about %v", slept, retryFor)
	}
	other := errors.New("other")
	calls = 0
	if err := retry(func() error { calls++; return other }, func(err error) bool { return errors.Is(err, errBusy) }, func(time.Duration) {}); err != other || calls != 1 {
		t.Errorf("a permanent error was retried: %v after %d calls", err, calls)
	}
}

// On Windows, the target held open by a reader (as another polyctl process
// reading credentials.json does) is replaced once the reader closes it.
func TestRenameWhileTheTargetIsOpen(t *testing.T) {
	dir := t.TempDir()
	target, tmp := filepath.Join(dir, "f"), filepath.Join(dir, "f.tmp")
	if err := os.WriteFile(target, []byte("old"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(tmp, []byte("new"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(target)
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		time.Sleep(50 * time.Millisecond)
		f.Close()
	}()
	if err := Rename(tmp, target); err != nil {
		t.Fatalf("Rename = %v", err)
	}
	if b, _ := os.ReadFile(target); string(b) != "new" {
		t.Errorf("target = %q", b)
	}
}
