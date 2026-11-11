package cloudflare

import (
	"os"
	"testing"
)

// TestMain clears the ambient API token so tests never pick up (or send to a
// fake server) a real credential from the developer's environment.
func TestMain(m *testing.M) {
	os.Unsetenv(tokenEnv)
	os.Exit(m.Run())
}
