package output

import (
	"fmt"
	"strings"
	"unicode/utf8"
)

// Clean returns s for a terminal: every control character (C0 but newline
// and tab, DEL, C1) is written as a visible escape (\x1b, \u009b), and
// bytes that are not UTF-8 as \xNN, so text from an instance, an API or a
// file (a key comment, a Name tag, remote stderr) cannot move the cursor,
// erase a line, set the clipboard or otherwise change what the terminal
// shows. Text without control characters is returned as is.
func Clean(s string) string {
	if !needsClean(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && n == 1:
			fmt.Fprintf(&b, `\x%02x`, s[i])
		case r == '\n' || r == '\t':
			b.WriteRune(r)
		case r < 0x20 || r == 0x7f:
			fmt.Fprintf(&b, `\x%02x`, r)
		case r >= 0x80 && r < 0xa0:
			fmt.Fprintf(&b, `\u%04x`, r)
		default:
			b.WriteString(s[i : i+n])
		}
		i += n
	}
	return b.String()
}

func needsClean(s string) bool {
	for i := 0; i < len(s); {
		r, n := utf8.DecodeRuneInString(s[i:])
		if r == utf8.RuneError && n == 1 || r < 0x20 && r != '\n' && r != '\t' || r == 0x7f || r >= 0x80 && r < 0xa0 {
			return true
		}
		i += n
	}
	return false
}
