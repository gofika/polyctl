package godaddy

import (
	"errors"
	"strings"
	"testing"
)

func TestRecordIDRoundTrip(t *testing.T) {
	cases := []struct{ typ, name, data string }{
		{"A", "@", "1.2.3.4"},
		{"a", "www", "1.2.3.4"},
		{"TXT", "@", "v=spf1 include:_spf.example.com ~all"},
		{"TXT", "_dmarc", `v=DMARC1; p=none; rua=mailto:a@b.c`},
		{"CNAME", "*", "target.example.net"},
		{"TXT", "weird", "pipe|inside|data"},
		{"TXT", "pct", "100% sure"},
		{"MX", "@", "mail.example.com"},
	}
	for _, c := range cases {
		id := EncodeRecordID(c.typ, c.name, c.data)
		if strings.Count(id, "|") != 2 {
			t.Errorf("%q: id %q must contain exactly two separators", c.data, id)
		}
		if strings.ContainsAny(id, " \t\n\"'") {
			t.Errorf("id %q contains unsafe characters", id)
		}
		typ, name, data, err := DecodeRecordID(id)
		if err != nil {
			t.Fatalf("decode %q: %v", id, err)
		}
		if typ != strings.ToUpper(c.typ) || name != c.name || data != c.data {
			t.Errorf("round trip of %+v gave %q %q %q (id %q)", c, typ, name, data, id)
		}
	}
	if got := EncodeRecordID("A", "", "1.1.1.1"); got != "A|@|1.1.1.1" {
		t.Errorf("empty name should become @, got %q", got)
	}
}

func TestDecodeRecordIDErrors(t *testing.T) {
	for _, bad := range []string{"", "A", "A|www", "|www|data", "A||data", "A|%zz|data"} {
		if _, _, _, err := DecodeRecordID(bad); !errors.Is(err, ErrBadRecordID) {
			t.Errorf("%q: expected ErrBadRecordID, got %v", bad, err)
		}
	}
}
