package shellquote

import "testing"

func TestQuoteAndArg(t *testing.T) {
	for in, want := range map[string]string{
		"":                  "''",
		"www":               "www",
		"@":                 "@",
		"203.0.113.10":      "203.0.113.10",
		"2001:db8::1":       "2001:db8::1",
		"10 mx.example.com": "'10 mx.example.com'",
		`"v=spf1 -all"`:     `'"v=spf1 -all"'`,
		"it's":              `'it'\''s'`,
		"$HOME":             "'$HOME'",
		"*.example.com":     "'*.example.com'",
	} {
		if got := Arg(in); got != want {
			t.Errorf("Arg(%q) = %s, want %s", in, got, want)
		}
	}
	if got := Quote("a b"); got != "'a b'" {
		t.Errorf("Quote = %s", got)
	}
	if got := Join("polyctl", "dns", "add", "example.com", "@", "TXT", "v=spf1 -all"); got != "polyctl dns add example.com @ TXT 'v=spf1 -all'" {
		t.Errorf("Join = %s", got)
	}
}
