package cloudflare

import (
	"strings"
	"testing"
)

func TestCacheDisplayHelpers(t *testing.T) {
	p := map[string]any{"edge_ttl": map[string]any{"mode": "override_origin", "default": int64(0), "status_code_ttl": []any{
		map[string]any{"status_code_range": map[string]any{"from": int64(200), "to": int64(299)}, "value": int64(60)},
		map[string]any{"status_code_range": map[string]any{"from": int64(400)}, "value": int64(0)},
		map[string]any{"status_code_range": map[string]any{"to": int64(199)}, "value": int64(5)},
		map[string]any{"status_code": int64(404), "value": int64(1)},
		map[string]any{"value": int64(2)},
	}}}
	if got := statusTTLText(p); got != "200-299:60, 400+:0, <=199:5, 404:1, unknown:2" {
		t.Errorf("status ttl = %q", got)
	}
	if got := ttlText(p, "edge_ttl"); got != "override 0s (no cache)" {
		t.Errorf("edge ttl = %q", got)
	}
	if got := ttlText(map[string]any{"edge_ttl": map[string]any{"mode": "bypass_by_default"}}, "edge_ttl"); got != "bypass by default" {
		t.Errorf("bypass = %q", got)
	}
	if got := ttlText(nil, "edge_ttl"); got != "-" {
		t.Errorf("no parameters = %q", got)
	}
	if got := secondsText(int64(2678400)); got != "2678400s (31d)" {
		t.Errorf("seconds = %q", got)
	}
	if got := cutExpression(strings.Repeat("x", 50), false); len(got) != expressionWidth || !strings.HasSuffix(got, "...") {
		t.Errorf("cut = %q", got)
	}
}
