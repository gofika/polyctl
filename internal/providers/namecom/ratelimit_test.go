package namecom

import (
	"testing"

	"github.com/gofika/polyctl/internal/httpx"
)

func TestClientHonoursRetryAfter(t *testing.T) {
	c := newClient("https://api.example", envTest, testUser, testToken)
	if _, ok := c.api.HTTP.Transport.(*httpx.RateLimitTransport); !ok {
		t.Errorf("transport = %T, want *httpx.RateLimitTransport", c.api.HTTP.Transport)
	}
}
