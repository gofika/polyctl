package app

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A hook whose program path has spaces and is quoted runs, and gets the
// event on stdin and in the environment.
func TestQuotedHookRunsOnWindows(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "dir with spaces")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	script := filepath.Join(dir, "hook.cmd")
	out := filepath.Join(dir, "out.txt")
	body := "@echo off\r\necho %POLYCTL_EVENT%> \"" + out + "\"\r\nfindstr \"^\" >> \"" + out + "\"\r\n"
	if err := os.WriteFile(script, []byte(body), 0o700); err != nil {
		t.Fatal(err)
	}
	rt, errb := hookRuntime(t, `"`+script+`" arg`)
	rt.NotifyFailure(context.Background(), Failure{Event: "x.failed", Error: "boom"})
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatalf("the hook did not run: %v (stderr %q)", err, errb.String())
	}
	if !strings.Contains(string(b), "x.failed") || !strings.Contains(string(b), `"error":"boom"`) {
		t.Errorf("hook output = %q", b)
	}
}
