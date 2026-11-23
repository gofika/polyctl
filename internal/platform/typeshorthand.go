package platform

import (
	"fmt"
	"math"
	"regexp"
	"strconv"
)

// typeShorthandRE matches the "<cores>H<memory>G" way of writing an
// instance size (2H4G, 1h0.5g).
var typeShorthandRE = regexp.MustCompile(`^(\d+)[Hh](\d+(?:\.\d+)?)[Gg]$`)

// TypeShorthand is an instance size written as "<cores>H<memory>G": the
// --type of the instance commands takes it in place of a type id, and each
// platform resolves it to a type of its own when the command runs.
type TypeShorthand struct {
	// Text is the value as it was written.
	Text string
	// Cores is the number of vCPUs (at least 1).
	Cores int
	// MemoryGiB is the memory in GiB (more than 0).
	MemoryGiB float64
}

// String returns the value as it was written.
func (s TypeShorthand) String() string { return s.Text }

// Memory returns the memory without trailing zeros ("4", "0.5").
func (s TypeShorthand) Memory() string {
	return strconv.FormatFloat(s.MemoryGiB, 'f', -1, 64)
}

// MemoryMiB returns the memory in MiB, rounded to the nearest MiB.
func (s TypeShorthand) MemoryMiB() int {
	return int(math.Round(s.MemoryGiB * 1024))
}

// Matches reports whether an instance of cores vCPUs and memMiB MiB of
// memory has exactly the size of the shorthand.
func (s TypeShorthand) Matches(cores, memMiB int) bool {
	return cores == s.Cores && memMiB == s.MemoryMiB()
}

// ParseTypeShorthand reads an instance type written as "<cores>H<memory>G".
// ok is false for anything else: that is an exact type id, used as it is.
// A value of that shape that cannot be a size (0 cores, 0 GiB, a number
// too large) is ok with an ErrInvalidInput error (exit code 2).
func ParseTypeShorthand(v string) (s TypeShorthand, ok bool, err error) {
	m := typeShorthandRE.FindStringSubmatch(v)
	if m == nil {
		return TypeShorthand{}, false, nil
	}
	cores, cerr := strconv.Atoi(m[1])
	mem, merr := strconv.ParseFloat(m[2], 64)
	switch {
	case cerr != nil || cores > math.MaxInt32:
		return TypeShorthand{}, true, fmt.Errorf("%w: instance size %q: %s vCPUs is not a usable number", ErrInvalidInput, v, m[1])
	case cores < 1:
		return TypeShorthand{}, true, fmt.Errorf("%w: instance size %q: the number of vCPUs must be at least 1 (write <cores>H<memory>G, such as 2H4G)", ErrInvalidInput, v)
	case merr != nil || math.IsInf(mem, 0):
		return TypeShorthand{}, true, fmt.Errorf("%w: instance size %q: %s GiB is not a usable amount of memory", ErrInvalidInput, v, m[2])
	case mem <= 0:
		return TypeShorthand{}, true, fmt.Errorf("%w: instance size %q: the memory must be more than 0 GiB (write <cores>H<memory>G, such as 2H4G)", ErrInvalidInput, v)
	}
	return TypeShorthand{Text: v, Cores: cores, MemoryGiB: mem}, true, nil
}
