package godaddy

import (
	"slices"
	"testing"
)

// GoDaddy writes the types of its record API but SOA: SRV included (its
// value is split into the fields GoDaddy keeps apart).
func TestRecordTypes(t *testing.T) {
	types := (&provider{}).RecordTypes()
	if !slices.Equal(types, []string{"A", "AAAA", "CNAME", "MX", "NS", "TXT", "SRV", "CAA"}) {
		t.Errorf("RecordTypes = %v", types)
	}
}
