package cli

import (
	"context"
	"testing"

	"github.com/gofika/polyctl/internal/inventory"
)

// A logout detaches the stored Windows passwords of the account, also with
// --keep-inventory: the next account logged in under the same name is not
// handed them by name.
func TestAuthLogoutDetachesInstanceSecrets(t *testing.T) {
	for _, keep := range []bool{false, true} {
		dir, cfgPath := setupMulti(t)
		db, err := inventory.Open(openInventoryPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		ctx := context.Background()
		row := inventory.SecretRow{SecretKey: inventory.SecretKey{Platform: fakePlatform, Profile: "a", Location: "r1", InstanceID: "i-1"},
			Name: "win", User: "Administrator", Nonce: []byte("n"), Sealed: []byte("s")}
		if err := db.PutSecret(ctx, row); err != nil {
			t.Fatal(err)
		}
		db.Close()
		args := []string{"auth", "logout", string(fakePlatform), "--profile", "a"}
		if keep {
			args = append(args, "--keep-inventory")
		}
		if code, _, stderr := mainRun(cfgPath, args...); code != ExitOK {
			t.Fatalf("logout (keep %v): exit %d (stderr %q)", keep, code, stderr)
		}
		db, err = inventory.Open(openInventoryPath(dir))
		if err != nil {
			t.Fatal(err)
		}
		if rows, _ := db.ListSecrets(ctx, fakePlatform, "a", ""); len(rows) != 0 {
			t.Errorf("keep %v: rows still under the profile: %+v", keep, rows)
		}
		if rows, _ := db.FindDetachedSecret(ctx, fakePlatform, "a", "", "i-1"); len(rows) != 1 {
			t.Errorf("keep %v: detached rows = %+v", keep, rows)
		}
		db.Close()
	}
}
