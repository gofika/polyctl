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

// auth rename run again after an interruption that left the inventory
// renamed and the config not: the instance secrets it moved stay with the
// profile, and the finished rename leaves no record behind.
func TestAuthRenameRerunAfterInterruptionKeepsSecrets(t *testing.T) {
	dir, cfgPath := setupMulti(t)
	ctx := context.Background()
	db, err := inventory.Open(openInventoryPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	row := inventory.SecretRow{SecretKey: inventory.SecretKey{Platform: fakePlatform, Profile: "a", Location: "r1", InstanceID: "i-1"},
		Name: "win", User: "Administrator", Nonce: []byte("n"), Sealed: []byte("s")}
	if err := db.PutSecret(ctx, row); err != nil {
		t.Fatal(err)
	}
	// The interrupted run: the inventory moved, the config was not saved.
	if err := db.RenameProfile(ctx, fakePlatform, "a", "acme"); err != nil {
		t.Fatal(err)
	}
	db.Close()
	if code, _, stderr := mainRun(cfgPath, "auth", "rename", "a", "acme"); code != ExitOK {
		t.Fatalf("rename: exit %d (stderr %q)", code, stderr)
	}
	db, err = inventory.Open(openInventoryPath(dir))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if rows, _ := db.ListSecrets(ctx, fakePlatform, "acme", ""); len(rows) != 1 {
		t.Errorf("rows under acme = %+v, want i-1", rows)
	}
	// A later rename onto acme's old leftovers detaches them again.
	if err := db.PutSecret(ctx, inventory.SecretRow{SecretKey: inventory.SecretKey{Platform: fakePlatform, Profile: "a", Location: "r1", InstanceID: "i-2"},
		Name: "w2", User: "Administrator", Nonce: []byte("n"), Sealed: []byte("s")}); err != nil {
		t.Fatal(err)
	}
	if err := db.RenameProfile(ctx, fakePlatform, "a", "acme"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.FindDetachedSecret(ctx, fakePlatform, "acme", "", "i-1"); len(rows) != 1 {
		t.Errorf("the record of the finished rename was left behind: %+v", rows)
	}
}
