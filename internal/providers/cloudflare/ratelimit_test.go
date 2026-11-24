package cloudflare

import (
	"testing"

	"github.com/gofika/polyctl/internal/httpx"
)

// Cloudflare refuses requests for the rest of its 5-minute window once the
// account limit is hit; the client must wait for Retry-After.
func TestAPIHonoursRetryAfter(t *testing.T) {
	for name, a := range map[string]*api{
		"token": newAPI("https://api.example", "tok", "acc"),
		"oauth": newOAuthAPI("https://api.example", &oauthSession{}, "acc"),
	} {
		if _, ok := a.http.HTTP.Transport.(*httpx.RateLimitTransport); !ok {
			t.Errorf("%s: transport = %T, want *httpx.RateLimitTransport", name, a.http.HTTP.Transport)
		}
	}
}
