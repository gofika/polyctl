package namecom

import (
	"slices"
	"testing"
)

// SRV values given as text cannot be written to this platform's separate
// fields, so dns ensure refuses them up front (exit code 7).
func TestRecordTypesLeaveOutSRV(t *testing.T) {
	types := (&provider{}).RecordTypes()
	if slices.Contains(types, "SRV") || !slices.Contains(types, "MX") {
		t.Errorf("RecordTypes = %v", types)
	}
}
