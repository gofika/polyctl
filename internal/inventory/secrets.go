package inventory

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/gofika/polyctl/internal/platform"
)

// secretSchema is the table of instance login secrets (the Windows user
// name and password of the instances polyctl creates). The secret itself
// is never stored in plain text: secret holds an AES-256-GCM ciphertext
// sealed by internal/secrets with the nonce next to it. Rows are not part
// of any synced set: a sync, Replace or Purge leaves them alone.
const secretSchema = `
CREATE TABLE IF NOT EXISTS instance_secrets (
  platform     TEXT    NOT NULL,
  profile      TEXT    NOT NULL,
  location     TEXT    NOT NULL,
  instance_id  TEXT    NOT NULL,
  name         TEXT    NOT NULL,
  user         TEXT    NOT NULL,
  nonce        BLOB    NOT NULL,
  secret       BLOB    NOT NULL,
  created_at   INTEGER NOT NULL,
  updated_at   INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, location, instance_id)
);
CREATE INDEX IF NOT EXISTS instance_secrets_name ON instance_secrets (platform, profile, name);
`

// SecretKey identifies the stored secret of one instance.
type SecretKey struct {
	Platform platform.ID
	Profile  string
	// Location is the region (or the zone, where instances live in one).
	Location   string
	InstanceID string
}

// SecretRow is a stored instance secret, still sealed.
type SecretRow struct {
	SecretKey
	Name string
	User string
	// Nonce and Sealed are the AES-GCM nonce and ciphertext.
	Nonce, Sealed []byte
	CreatedAt     time.Time
	UpdatedAt     time.Time
}

// PutSecret stores (or replaces) the sealed secret of an instance. A
// replaced row keeps its creation time.
func (d *DB) PutSecret(ctx context.Context, r SecretRow) error {
	now := d.now().Unix()
	_, err := d.sql.ExecContext(ctx, `
INSERT INTO instance_secrets (platform, profile, location, instance_id, name, user, nonce, secret, created_at, updated_at)
VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
ON CONFLICT (platform, profile, location, instance_id) DO UPDATE SET
  name = excluded.name, user = excluded.user, nonce = excluded.nonce, secret = excluded.secret, updated_at = excluded.updated_at`,
		string(r.Platform), r.Profile, r.Location, r.InstanceID, r.Name, r.User, r.Nonce, r.Sealed, now, now)
	return err
}

// GetSecret returns the stored secret of an instance, nil when there is none.
func (d *DB) GetSecret(ctx context.Context, k SecretKey) (*SecretRow, error) {
	rows, err := d.querySecrets(ctx, `platform=? AND profile=? AND location=? AND instance_id=?`,
		string(k.Platform), k.Profile, k.Location, k.InstanceID)
	if err != nil || len(rows) == 0 {
		return nil, err
	}
	return &rows[0], nil
}

// FindSecrets returns the stored secrets of a profile's instances whose id
// or name is ref, in location ("" matches every location).
func (d *DB) FindSecrets(ctx context.Context, p platform.ID, profile, location, ref string) ([]SecretRow, error) {
	where := `platform=? AND profile=? AND (instance_id=? OR name=?)`
	args := []any{string(p), profile, ref, ref}
	if location != "" {
		where += ` AND location=?`
		args = append(args, location)
	}
	return d.querySecrets(ctx, where, args...)
}

// ListSecrets returns the stored secrets of a profile's instances in
// location ("" matches every location).
func (d *DB) ListSecrets(ctx context.Context, p platform.ID, profile, location string) ([]SecretRow, error) {
	where := `platform=? AND profile=?`
	args := []any{string(p), profile}
	if location != "" {
		where += ` AND location=?`
		args = append(args, location)
	}
	return d.querySecrets(ctx, where, args...)
}

// DeleteSecret removes the stored secret of an instance; a missing one is
// not an error.
func (d *DB) DeleteSecret(ctx context.Context, k SecretKey) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM instance_secrets WHERE platform=? AND profile=? AND location=? AND instance_id=?`,
		string(k.Platform), k.Profile, k.Location, k.InstanceID)
	return err
}

// CountSecrets returns the number of stored instance secrets.
func (d *DB) CountSecrets(ctx context.Context) (int, error) {
	var n int
	err := d.sql.QueryRowContext(ctx, `SELECT COUNT(*) FROM instance_secrets`).Scan(&n)
	return n, err
}

func (d *DB) querySecrets(ctx context.Context, where string, args ...any) ([]SecretRow, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT platform, profile, location, instance_id, name, user, nonce, secret, created_at, updated_at
FROM instance_secrets WHERE `+where+` ORDER BY location, instance_id`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []SecretRow
	for rows.Next() {
		var r SecretRow
		var p string
		var created, updated int64
		if err := rows.Scan(&p, &r.Profile, &r.Location, &r.InstanceID, &r.Name, &r.User, &r.Nonce, &r.Sealed, &created, &updated); err != nil {
			return nil, err
		}
		r.Platform = platform.ID(p)
		r.CreatedAt, r.UpdatedAt = time.Unix(created, 0), time.Unix(updated, 0)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return nil, err
	}
	return out, nil
}
