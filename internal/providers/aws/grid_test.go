package aws

import (
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestRecordGridShowsAliasInsteadOfZeroTTL(t *testing.T) {
	g := recordGrid([]platform.Record{
		{ID: "a", Name: "example.com", Type: "A", Value: "d111.cloudfront.net", Extra: map[string]any{"alias": true}},
		{ID: "b", Name: "www.example.com", Type: "A", Value: "192.0.2.1", TTL: 300},
		// Route 53 accepts a real TTL of 0 seconds on ordinary records.
		{ID: "c", Name: "zero.example.com", Type: "A", Value: "192.0.2.2", TTL: 0},
	})
	if g.Headers[3] != "TTL" {
		t.Fatalf("headers: %v", g.Headers)
	}
	got := []string{g.Rows[0][3], g.Rows[1][3], g.Rows[2][3]}
	if got[0] != "alias" || got[1] != "300" || got[2] != "0" {
		t.Fatalf("TTL column: %v", got)
	}
}
