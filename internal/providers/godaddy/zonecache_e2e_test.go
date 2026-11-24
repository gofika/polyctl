package godaddy_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/gofika/polyctl/internal/cli"
	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

// Moving the nameservers of a domain away from GoDaddy drops its zone from
// the inventory, so neutral dns commands no longer route to GoDaddy.
func TestNameserversElsewhereForgetTheZone(t *testing.T) {
	e := newDeleteEnv(t)
	zones := func() int {
		t.Helper()
		db, err := inventory.Open(filepath.Join(e.dir, "inventory.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer db.Close()
		rows, err := db.List(context.Background(), inventory.Query{Platform: platform.GoDaddy, Type: platform.ResZone})
		if err != nil {
			t.Fatal(err)
		}
		return len(rows)
	}
	if code, _, stderr := e.run(nil, "", "godaddy", "domain", "get", "example.com", "--refresh"); code != cli.ExitOK || zones() != 1 {
		t.Fatalf("domain get: exit %d, %d zones, %s", code, zones(), stderr)
	}
	if code, _, stderr := e.run(nil, "", "godaddy", "domain", "ns", "set", "example.com", "ada.ns.cloudflare.com", "bob.ns.cloudflare.com", "--yes"); code != cli.ExitOK || zones() != 0 {
		t.Fatalf("ns set: exit %d, %d zones, %s", code, zones(), stderr)
	}
}
