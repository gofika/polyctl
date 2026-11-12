package cli

import (
	"reflect"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func TestRecordGridTTLAndProxiedColumns(t *testing.T) {
	yes := true
	recs := []platform.Record{
		{ID: "r1", Name: "example.com", Type: "A", Value: "192.0.2.1", TTL: 1, Proxied: &yes},
		{ID: "r2", Name: "www.example.com", Type: "A", Value: "192.0.2.2", TTL: 300},
	}
	g := recordGrid(recs, platform.Cloudflare)
	if want := []string{"NAME", "TYPE", "VALUE", "TTL", "PROXIED", "ID"}; !reflect.DeepEqual(g.Headers, want) {
		t.Fatalf("cloudflare headers: %v", g.Headers)
	}
	if g.Rows[0][3] != "auto" || g.Rows[1][3] != "300" {
		t.Fatalf("cloudflare TTL column: %q, %q", g.Rows[0][3], g.Rows[1][3])
	}

	// The same value is a real one-second TTL elsewhere, and there is no
	// PROXIED column.
	g = recordGrid(recs, platform.GCP)
	if want := []string{"NAME", "TYPE", "VALUE", "TTL", "ID"}; !reflect.DeepEqual(g.Headers, want) {
		t.Fatalf("gcp headers: %v", g.Headers)
	}
	if g.Rows[0][3] != "1" {
		t.Fatalf("gcp TTL column: %q", g.Rows[0][3])
	}

	alias := []platform.Record{{ID: "a", Name: "example.com", Type: "A", Value: "d111.cloudfront.net", Extra: map[string]any{"alias": true}}}
	if got := recordGrid(alias, platform.AWS).Rows[0][3]; got != "alias" {
		t.Fatalf("aws alias TTL column: %q", got)
	}
	if got := recordGrid([]platform.Record{{ID: "g", Name: "example.com", Type: "A", Value: "192.0.2.3"}}, platform.GoDaddy).Rows[0][3]; got != "default" {
		t.Fatalf("godaddy default TTL column: %q", got)
	}
}
