package inventory_test

import (
	"context"
	"testing"

	"github.com/gofika/polyctl/internal/inventory"
	"github.com/gofika/polyctl/internal/platform"
)

func putSecret(t *testing.T, db *inventory.DB, profile, id, name string) {
	t.Helper()
	err := db.PutSecret(context.Background(), inventory.SecretRow{SecretKey: inventory.SecretKey{Platform: platform.AWS, Profile: profile, Location: "us-east-1", InstanceID: id},
		Name: name, User: "Administrator", Nonce: []byte("n"), Sealed: []byte("s")})
	if err != nil {
		t.Fatal(err)
	}
}

// A logout detaches the secrets: a later account under the same name does
// not find them by name or in its list, only by instance id, marked as
// detached.
func TestDetachSecrets(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	putSecret(t, db, "p", "i-1", "win")
	putSecret(t, db, "q", "i-9", "win")
	if err := db.DetachSecrets(ctx, platform.AWS, "p"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.FindSecrets(ctx, platform.AWS, "p", "", "win"); len(rows) != 0 {
		t.Errorf("a detached row matches by name: %+v", rows)
	}
	if rows, _ := db.ListSecrets(ctx, platform.AWS, "p", ""); len(rows) != 0 {
		t.Errorf("a detached row is listed: %+v", rows)
	}
	if rows, _ := db.FindDetachedSecret(ctx, platform.AWS, "p", "", "i-1"); len(rows) != 1 {
		t.Errorf("FindDetachedSecret(i-1) = %+v", rows)
	}
	if rows, _ := db.FindDetachedSecret(ctx, platform.AWS, "p", "", "win"); len(rows) != 0 {
		t.Errorf("FindDetachedSecret matched a name: %+v", rows)
	}
	if rows, _ := db.ListSecrets(ctx, platform.AWS, "q", ""); len(rows) != 1 {
		t.Errorf("another profile's rows were detached: %+v", rows)
	}
	if n, _ := db.CountSecrets(ctx); n != 2 {
		t.Errorf("rows = %d, want 2 (nothing deleted)", n)
	}
}

// Leftover rows under the target name of a rename are detached, not merged
// into the renamed account, so renaming back (the undo of a failed rename)
// moves only the rows the rename moved.
func TestRenameProfileDetachesLeftoversAtTheTarget(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	putSecret(t, db, "old", "i-1", "mine")
	putSecret(t, db, "new", "i-2", "leftover")
	if err := db.RenameProfile(ctx, platform.AWS, "old", "new"); err != nil {
		t.Fatal(err)
	}
	rows, _ := db.ListSecrets(ctx, platform.AWS, "new", "")
	if len(rows) != 1 || rows[0].InstanceID != "i-1" {
		t.Errorf("rows under new = %+v, want only i-1", rows)
	}
	if err := db.RenameProfile(ctx, platform.AWS, "new", "old"); err != nil {
		t.Fatal(err)
	}
	rows, _ = db.ListSecrets(ctx, platform.AWS, "old", "")
	if len(rows) != 1 || rows[0].InstanceID != "i-1" {
		t.Errorf("rows under old after the undo = %+v, want only i-1", rows)
	}
	if rows, _ := db.FindDetachedSecret(ctx, platform.AWS, "new", "", "i-2"); len(rows) != 1 {
		t.Errorf("the leftover is not kept detached: %+v", rows)
	}
}

// A rename interrupted after the inventory moved (before the config was
// saved) is run again: the rows it moved stay with the account instead of
// being detached as leftovers of a logged-out one, and its cached rows stay
// too. Once the rename is recorded as done, leftovers are detached again.
func TestRenameProfileResumedAfterAnInterruption(t *testing.T) {
	ctx := context.Background()
	db, _ := openDB(t)
	putSecret(t, db, "old", "i-1", "mine")
	if err := db.RenameProfile(ctx, platform.AWS, "old", "new"); err != nil {
		t.Fatal(err)
	}
	// Interrupted here; the same rename runs again.
	if err := db.RenameProfile(ctx, platform.AWS, "old", "new"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.ListSecrets(ctx, platform.AWS, "new", ""); len(rows) != 1 || rows[0].InstanceID != "i-1" {
		t.Errorf("rows under new after the rerun = %+v, want i-1", rows)
	}
	if err := db.EndRename(ctx, "old", "new"); err != nil {
		t.Fatal(err)
	}
	putSecret(t, db, "old", "i-2", "other")
	if err := db.RenameProfile(ctx, platform.AWS, "old", "new"); err != nil {
		t.Fatal(err)
	}
	if rows, _ := db.FindDetachedSecret(ctx, platform.AWS, "new", "", "i-1"); len(rows) != 1 {
		t.Errorf("a leftover of a finished rename is not detached: %+v", rows)
	}
}
