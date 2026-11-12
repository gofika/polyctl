package godaddy

import (
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestRecordGridShowsDefaultInsteadOfZeroTTL(t *testing.T) {
	g := recordGrid([]platform.Record{
		{ID: "a", Name: "example.com", Type: "A", Value: "192.0.2.1"},
		{ID: "b", Name: "www.example.com", Type: "A", Value: "192.0.2.2", TTL: 600},
	})
	if g.Headers[3] != "TTL" {
		t.Fatalf("headers: %v", g.Headers)
	}
	if g.Rows[0][3] != "default" || g.Rows[1][3] != "600" {
		t.Fatalf("TTL column: %q, %q", g.Rows[0][3], g.Rows[1][3])
	}
}
