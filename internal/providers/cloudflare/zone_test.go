package cloudflare

import (
	"errors"
	"fmt"
	"reflect"
	"testing"

	"github.com/gofika/polyctl/internal/platform"
)

func cfErr(status, code int, msg string) error {
	return fmt.Errorf("wrapped: %w", newError(status, "GET", "/zones/x", []message{{Code: code, Message: msg}}))
}

func TestZoneGone(t *testing.T) {
	for _, tc := range []struct {
		err  error
		gone bool
	}{
		{cfErr(400, 1001, "Invalid zone identifier"), true},
		{cfErr(403, 9109, "Invalid zone identifier"), true},
		{cfErr(404, 7003, "Could not route to /zones/x, perhaps your object identifier is invalid?"), true},
		// 9109 is also an invalid token, and 1001 a malformed body.
		{cfErr(403, 9109, "Invalid access token"), false},
		{cfErr(400, 1001, "Request body is invalid."), false},
		{cfErr(403, 10000, "Authentication error"), false},
		{errors.New("plain"), false},
		{nil, false},
	} {
		if got := zoneGone(tc.err); got != tc.gone {
			t.Errorf("zoneGone(%v) = %v", tc.err, got)
		}
	}
}

func TestFoundationUnsupported(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want bool
	}{
		{cfErr(400, 1003, "Foundation DNS is not available"), true},
		{cfErr(403, 1003, "x"), true},
		{cfErr(403, 10000, "Authentication error"), true},
		{cfErr(400, 1001, "Request body is invalid."), false},
		{cfErr(500, 10001, "internal"), false},
	} {
		if got := foundationUnsupported(tc.err); got != tc.want {
			t.Errorf("foundationUnsupported(%v) = %v", tc.err, got)
		}
	}
}

func TestSettingError(t *testing.T) {
	if err := settingError(cfErr(400, 1003, "Undefined zone setting"), "nope", ""); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("1003 = %v", err)
	}
	if err := settingError(cfErr(400, 1006, "Unrecognized zone setting name"), "nope", ""); !errors.Is(err, platform.ErrNotFound) {
		t.Errorf("1006 = %v", err)
	}
	if err := settingError(cfErr(400, 1015, "Not allowed to edit zone setting"), "response_buffering", "free"); !errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("1015 = %v", err)
	}
	if err := settingError(cfErr(400, 1007, "Invalid value"), "ssl", ""); errors.Is(err, platform.ErrNotFound) || errors.Is(err, platform.ErrNotSupported) {
		t.Errorf("1007 = %v", err)
	}
	// A zone that is gone stays recognizable.
	if err := settingError(cfErr(400, 1001, "Invalid zone identifier"), "ssl", ""); !zoneGone(err) {
		t.Errorf("gone = %v", err)
	}
}

func TestSettingValue(t *testing.T) {
	for _, tc := range []struct {
		name, given string
		current     any
		want        any
		bad         bool
	}{
		{"always_use_https", "true", "off", "on", false},
		{"always_use_https", "OFF", "on", "off", false},
		{"ssl", "strict", "full", "strict", false},
		{"browser_cache_ttl", "7200", float64(14400), float64(7200), false},
		{"browser_cache_ttl", "soon", float64(14400), "soon", false},
		{"security_header", `{"enabled":true}`, map[string]any{}, map[string]any{"enabled": true}, false},
		{"some_bool", "on", false, true, false},
		{settingArgo, "true", nil, "on", false},
		{settingArgo, "maybe", nil, nil, true},
		{settingFoundationDNS, "on", nil, true, false},
		{settingFoundationDNS, "false", nil, false, false},
		{settingFoundationDNS, "yes", nil, nil, true},
	} {
		got, err := settingValue(tc.name, tc.given, tc.current)
		if (err != nil) != tc.bad || (err != nil && !errors.Is(err, errBadSettingValue)) {
			t.Errorf("%s %q: err %v", tc.name, tc.given, err)
			continue
		}
		if !tc.bad && !reflect.DeepEqual(got, tc.want) {
			t.Errorf("%s %q = %#v, want %#v", tc.name, tc.given, got, tc.want)
		}
	}
}

func TestSettingText(t *testing.T) {
	for v, want := range map[any]string{"on": "on", true: "true", float64(14400): "14400", 1.5: "1.5", nil: ""} {
		if got := settingText(v); got != want {
			t.Errorf("settingText(%v) = %q", v, got)
		}
	}
	if got := settingText(map[string]any{"a": 1}); got != `{"a":1}` {
		t.Errorf("object = %q", got)
	}
}

func TestZoneDomainArg(t *testing.T) {
	if d, err := zoneDomainArg("Example.COM."); err != nil || d != "example.com" {
		t.Errorf("= %q, %v", d, err)
	}
	for _, bad := range []string{"", "nodot", "http://example.com", "example.com/x", "a b.com", "192.0.2.1", ".example.com", "a..com", "*.example.com"} {
		if _, err := zoneDomainArg(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestErrorRayID(t *testing.T) {
	e := newError(503, "GET", "/zones", []message{{Code: 10001, Message: "service unavailable"}})
	e.RayID = "abc-NRT"
	if got := e.Error(); got != "cloudflare: GET /zones: HTTP 503: service unavailable (code 10001) (cf-ray abc-NRT)" {
		t.Errorf("Error() = %q", got)
	}
	e = newError(400, "GET", "/zones", []message{{Code: 1001, Message: "x"}})
	e.RayID = "abc-NRT"
	if got := e.Error(); got != "cloudflare: GET /zones: HTTP 400: x (code 1001)" {
		t.Errorf("a client error quotes no ray id: %q", got)
	}
}
