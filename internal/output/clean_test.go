package output

import (
	"bytes"
	"strings"
	"testing"
)

func TestClean(t *testing.T) {
	for in, want := range map[string]string{
		"plain text":                      "plain text",
		"multi\nline\tok":                 "multi\nline\tok",
		"日本語 ü":                           "日本語 ü",
		"x\x1b]52;c;aGk=\x07\x1b[2Kweb-1": `x\x1b]52;c;aGk=\x07\x1b[2Kweb-1`,
		"back\rspace\b del\x7f":           `back\x0dspace\x08 del\x7f`,
		"c1 \u009b31m csi":                `c1 \u009b31m csi`,
		"bad \xff utf8":                   `bad \xff utf8`,
	} {
		if got := Clean(in); got != want {
			t.Errorf("Clean(%q) = %q, want %q", in, got, want)
		}
	}
}

// A cell holding escape sequences (a key comment from an instance) is
// printed escaped, not executed by the terminal.
func TestRenderGridEscapesControls(t *testing.T) {
	var b bytes.Buffer
	err := RenderGrid(&b, Grid{Headers: []string{"NAME", "COMMENT"}, Rows: [][]string{{"web\r\x1b[K", "a\x1b]52;c;eA==\x07"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.ContainsAny(b.String(), "\x1b\x07\r") || !strings.Contains(b.String(), `web\x0d\x1b[K`) {
		t.Errorf("grid %q", b.String())
	}
	b.Reset()
	_ = RenderGrid(&b, Grid{Empty: "no \x1b[31mkeys"})
	if strings.Contains(b.String(), "\x1b") {
		t.Errorf("empty %q", b.String())
	}
}
