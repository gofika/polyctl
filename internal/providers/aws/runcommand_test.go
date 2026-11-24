package aws

import (
	"errors"
	"strings"
	"testing"

	ssmtypes "github.com/aws/aws-sdk-go-v2/service/ssm/types"

	"github.com/gofika/polyctl/internal/platform"
)

// runCommandClient is a client whose Systems Manager calls go to the fake
// Run Command state f.
func runCommandClient(t *testing.T, f fakeRunCommand) (*client, *fakeEC2s) {
	t.Helper()
	useFakeClock(t)
	st := &fakeEC2s{run: f}
	return &client{ssmFor: func(r string) ssmAPI { return &fakeSSM{shared: st, region: r} }}, st
}

// Output that may have been cut, on standard output (characters, not
// bytes) or standard error, is refused as not supported (exit code 7, the
// code of an incomplete listing), whichever stream reaches its limit.
func TestRunShellCommandCutOutput(t *testing.T) {
	cases := []struct {
		name           string
		stdout, stderr string
		cut            string
	}{
		{"short multibyte stdout", strings.Repeat("鍵", ssmStdoutLimit/3), "", ""},
		{"stdout", strings.Repeat("x", ssmStdoutLimit), "", "standard output"},
		{"stderr", "", strings.Repeat("e", ssmStderrLimit), "standard error"},
	}
	for _, c := range cases {
		cl, st := runCommandClient(t, fakeRunCommand{})
		f := &st.run
		f.manage("i-1", ssmtypes.PingStatusOnline)
		f.exec = func(string, string) (string, string, int) { return c.stdout, c.stderr, 0 }
		so, _, _, err := cl.runShellCommand(t.Context(), "r", "i-1", "true")
		if c.cut == "" {
			if err != nil || string(so) != c.stdout {
				t.Errorf("%s: %v", c.name, err)
			}
			continue
		}
		if !errors.Is(err, platform.ErrNotSupported) || !strings.Contains(err.Error(), "the "+c.cut) || !strings.Contains(err.Error(), "may be cut") {
			t.Errorf("%s: %v", c.name, err)
		}
	}
}
