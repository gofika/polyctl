package platform

import (
	"errors"
	"testing"
)

func TestParseTypeShorthand(t *testing.T) {
	for _, tc := range []struct {
		in      string
		ok      bool
		invalid bool
		cores   int
		mem     float64
		memory  string
		mib     int
	}{
		{in: "2H4G", ok: true, cores: 2, mem: 4, memory: "4", mib: 4096},
		{in: "2h2g", ok: true, cores: 2, mem: 2, memory: "2", mib: 2048},
		{in: "4H8G", ok: true, cores: 4, mem: 8, memory: "8", mib: 8192},
		{in: "1H0.5G", ok: true, cores: 1, mem: 0.5, memory: "0.5", mib: 512},
		{in: "16H3.75G", ok: true, cores: 16, mem: 3.75, memory: "3.75", mib: 3840},
		{in: "02H04.0G", ok: true, cores: 2, mem: 4, memory: "4", mib: 4096},
		// Exact type ids and other text: not a shorthand.
		{in: "ecs.u1-c1m1.large"},
		{in: "e2-small"},
		{in: "t3.micro"},
		{in: ""},
		{in: "2H4"},
		{in: "H4G"},
		{in: "2HG"},
		{in: "2H4GB"},
		{in: " 2H4G"},
		{in: "2.5H4G"},
		{in: "2H.5G"},
		{in: "-2H4G"},
		{in: "2X4G"},
		// The shape of a shorthand, but no size.
		{in: "0H2G", ok: true, invalid: true},
		{in: "2H0G", ok: true, invalid: true},
		{in: "2H0.0G", ok: true, invalid: true},
		{in: "99999999999999999999H2G", ok: true, invalid: true},
	} {
		s, ok, err := ParseTypeShorthand(tc.in)
		if ok != tc.ok {
			t.Errorf("%q: ok = %v, want %v", tc.in, ok, tc.ok)
			continue
		}
		if tc.invalid {
			if !errors.Is(err, ErrInvalidInput) {
				t.Errorf("%q: err = %v, want ErrInvalidInput", tc.in, err)
			}
			continue
		}
		if err != nil {
			t.Errorf("%q: err = %v", tc.in, err)
			continue
		}
		if !ok {
			continue
		}
		if s.Text != tc.in || s.String() != tc.in || s.Cores != tc.cores || s.MemoryGiB != tc.mem || s.Memory() != tc.memory || s.MemoryMiB() != tc.mib {
			t.Errorf("%q: got %+v (memory %s, %d MiB)", tc.in, s, s.Memory(), s.MemoryMiB())
		}
		if !s.Matches(tc.cores, tc.mib) || s.Matches(tc.cores+1, tc.mib) || s.Matches(tc.cores, tc.mib+1) {
			t.Errorf("%q: Matches is wrong", tc.in)
		}
	}
}
