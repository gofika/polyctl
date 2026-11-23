package platform

import (
	"errors"
	"strings"
	"testing"
)

// Every parser of command-line values reports a malformed value as
// ErrInvalidInput, so that a command forwarding the error exits with the
// usage code (2) and not the general one.
func TestParseErrorsAreUsageErrors(t *testing.T) {
	check := func(what string, err error) {
		t.Helper()
		if !errors.Is(err, ErrInvalidInput) {
			t.Errorf("%s: %v does not wrap ErrInvalidInput", what, err)
		}
	}
	_, err := ParseIngressRule("tcp:99999:0.0.0.0/0")
	check("rule", err)
	_, _, err = ParseRuleSource("nonsense")
	check("source", err)
	_, err = ParseListener("ftp:21")
	check("listener", err)
	_, err = ParseRecordSpec("www:A:not-an-ip")
	check("record spec", err)
	check("record validate", RecordSpec{Name: "www", Type: "A", Value: "x"}.Validate())
	_, err = ParseRecordFile(strings.NewReader("records:\n  - name: www\n    typo: A\n"))
	check("records file", err)
	_, err = RecordSpec{Name: "www.other.org."}.FQDN("example.com")
	check("record fqdn", err)
	// One prefix only, not one per layer.
	if _, err := ParseRecordSpec("www:A:not-an-ip"); strings.Count(err.Error(), ErrInvalidInput.Error()) != 1 {
		t.Errorf("message = %q", err)
	}
}
