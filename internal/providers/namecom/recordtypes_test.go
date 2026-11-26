package namecom

import (
	"slices"
	"testing"
)

// name.com writes exactly the types of its record API: SRV and ANAME, and
// no CAA.
func TestRecordTypes(t *testing.T) {
	types := (&provider{}).RecordTypes()
	if !slices.Equal(types, []string{"A", "AAAA", "CNAME", "ANAME", "MX", "NS", "TXT", "SRV"}) {
		t.Errorf("RecordTypes = %v", types)
	}
}
