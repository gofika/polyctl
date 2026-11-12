// Package inventory is the local SQLite cache of platform resources
// (~/.config/polyctl/inventory.db).
package inventory

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "modernc.org/sqlite"

	"github.com/gofika/polyctl/internal/platform"
)

// ErrNeverSynced is returned by reads when the requested set has never been fetched.
var ErrNeverSynced = errors.New("never synced")

const schema = `
PRAGMA journal_mode = WAL;
PRAGMA foreign_keys = ON;
CREATE TABLE IF NOT EXISTS resources (
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,
  resource_id   TEXT    NOT NULL,
  name          TEXT    NOT NULL,
  parent_id     TEXT    NOT NULL DEFAULT '',
  domain        TEXT    NOT NULL DEFAULT '',
  data          TEXT    NOT NULL,
  updated_at    INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, resource_type, resource_id)
);
CREATE INDEX IF NOT EXISTS resources_type_name ON resources (resource_type, name);
CREATE INDEX IF NOT EXISTS resources_parent ON resources (platform, profile, resource_type, parent_id);
CREATE TABLE IF NOT EXISTS domain_index (
  domain        TEXT NOT NULL,
  platform      TEXT NOT NULL,
  profile       TEXT NOT NULL,
  resource_type TEXT NOT NULL,
  resource_id   TEXT NOT NULL,
  updated_at    INTEGER NOT NULL,
  PRIMARY KEY (domain, platform, profile, resource_type, resource_id)
);
CREATE TABLE IF NOT EXISTS sync_state (
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,
  scope         TEXT    NOT NULL DEFAULT '',
  synced_at     INTEGER NOT NULL,
  expires_at    INTEGER NOT NULL,
  PRIMARY KEY (platform, profile, resource_type, scope)
);
`

// DB wraps the SQLite connection.
type DB struct {
	sql *sql.DB
	now func() time.Time
}

// Open opens (and migrates) the inventory database at path.
func Open(path string) (*DB, error) {
	dsn := path + "?_pragma=busy_timeout(5000)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	if _, err := db.Exec(schema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate inventory db: %w", err)
	}
	return &DB{sql: db, now: time.Now}, nil
}

// Close closes the database.
func (d *DB) Close() error { return d.sql.Close() }

// Resource is a stored row.
type Resource struct {
	Platform  platform.ID           `json:"platform" yaml:"platform"`
	Profile   string                `json:"profile" yaml:"profile"`
	Type      platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	ID        string                `json:"resource_id" yaml:"resource_id"`
	Name      string                `json:"name" yaml:"name"`
	ParentID  string                `json:"parent_id,omitempty" yaml:"parent_id,omitempty"`
	Domain    string                `json:"domain,omitempty" yaml:"domain,omitempty"`
	Data      json.RawMessage       `json:"data" yaml:"-"`
	UpdatedAt time.Time             `json:"updated_at" yaml:"updated_at"`
	ExpiresAt time.Time             `json:"expires_at" yaml:"expires_at"`
}

// Decode unmarshals Data into v.
func (r Resource) Decode(v any) error { return json.Unmarshal(r.Data, v) }

// Set identifies a synced set of resources: all resources of one type for a
// profile, optionally restricted to a scope (the zone id for dns_record).
type Set struct {
	Platform platform.ID
	Profile  string
	Type     platform.ResourceType
	Scope    string
}

// State is the freshness of a Set.
type State struct {
	SyncedAt  time.Time
	ExpiresAt time.Time
}

// Fresh reports whether the set exists and has not expired.
func (s *State) Fresh(now time.Time) bool { return s != nil && now.Before(s.ExpiresAt) }

// GetState returns the sync state of a set, nil if never synced.
func (d *DB) GetState(ctx context.Context, s Set) (*State, error) {
	row := d.sql.QueryRowContext(ctx, `SELECT synced_at, expires_at FROM sync_state WHERE platform=? AND profile=? AND resource_type=? AND scope=?`,
		string(s.Platform), s.Profile, string(s.Type), s.Scope)
	var syncedAt, expiresAt int64
	if err := row.Scan(&syncedAt, &expiresAt); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, nil
		}
		return nil, err
	}
	return &State{SyncedAt: time.Unix(syncedAt, 0), ExpiresAt: time.Unix(expiresAt, 0)}, nil
}

// Replace atomically replaces the contents of a set with resources, records
// the sync time, and rebuilds the domain index for the set. For an
// unscoped dns_record set it also clears every per-zone scope of the profile.
func (d *DB) Replace(ctx context.Context, s Set, resources []platform.Resource, ttl time.Duration) error {
	now := d.now()
	exp := now.Add(ttl)
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	if s.Scope == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE platform=? AND profile=? AND resource_type=?`, string(s.Platform), s.Profile, string(s.Type)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM domain_index WHERE platform=? AND profile=? AND resource_type=?`, string(s.Platform), s.Profile, string(s.Type)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM sync_state WHERE platform=? AND profile=? AND resource_type=?`, string(s.Platform), s.Profile, string(s.Type)); err != nil {
			return err
		}
	} else {
		// The index rows are found through the resources they belong to, so
		// they must go before the resources themselves.
		if _, err := tx.ExecContext(ctx, `DELETE FROM domain_index WHERE platform=? AND profile=? AND resource_type=? AND resource_id IN (SELECT resource_id FROM resources WHERE platform=? AND profile=? AND resource_type=? AND parent_id=?)`,
			string(s.Platform), s.Profile, string(s.Type), string(s.Platform), s.Profile, string(s.Type), s.Scope); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE platform=? AND profile=? AND resource_type=? AND parent_id=?`, string(s.Platform), s.Profile, string(s.Type), s.Scope); err != nil {
			return err
		}
	}

	ins, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO resources (platform, profile, resource_type, resource_id, name, parent_id, domain, data, updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer ins.Close()
	idx, err := tx.PrepareContext(ctx, `INSERT OR REPLACE INTO domain_index (domain, platform, profile, resource_type, resource_id, updated_at) VALUES (?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer idx.Close()

	for _, r := range resources {
		b, err := json.Marshal(r.Data)
		if err != nil {
			return fmt.Errorf("encode %s %s: %w", r.Type, r.ID, err)
		}
		dom := platform.NormalizeDomain(r.Domain)
		if _, err := ins.ExecContext(ctx, string(s.Platform), s.Profile, string(r.Type), r.ID, r.Name, r.ParentID, dom, string(b), now.Unix(), exp.Unix()); err != nil {
			return err
		}
		if dom != "" && r.Type != platform.ResDNSRecord {
			if _, err := idx.ExecContext(ctx, dom, string(s.Platform), s.Profile, string(r.Type), r.ID, now.Unix()); err != nil {
				return err
			}
		}
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO sync_state (platform, profile, resource_type, scope, synced_at, expires_at) VALUES (?,?,?,?,?,?)`,
		string(s.Platform), s.Profile, string(s.Type), s.Scope, now.Unix(), exp.Unix()); err != nil {
		return err
	}
	// An unscoped sync also refreshes every per-parent scope it covered, so a
	// later scoped read (e.g. records of one zone) is served from the cache.
	if s.Scope == "" {
		seen := map[string]bool{}
		for _, r := range resources {
			if r.ParentID == "" || seen[r.ParentID] {
				continue
			}
			seen[r.ParentID] = true
			if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO sync_state (platform, profile, resource_type, scope, synced_at, expires_at) VALUES (?,?,?,?,?,?)`,
				string(s.Platform), s.Profile, string(s.Type), r.ParentID, now.Unix(), exp.Unix()); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

// Upsert inserts or updates a single resource without touching sync state.
func (d *DB) Upsert(ctx context.Context, s Set, r platform.Resource, ttl time.Duration) error {
	now := d.now()
	b, err := json.Marshal(r.Data)
	if err != nil {
		return err
	}
	dom := platform.NormalizeDomain(r.Domain)
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO resources (platform, profile, resource_type, resource_id, name, parent_id, domain, data, updated_at, expires_at) VALUES (?,?,?,?,?,?,?,?,?,?)`,
		string(s.Platform), s.Profile, string(r.Type), r.ID, r.Name, r.ParentID, dom, string(b), now.Unix(), now.Add(ttl).Unix()); err != nil {
		return err
	}
	if dom != "" && r.Type != platform.ResDNSRecord {
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO domain_index (domain, platform, profile, resource_type, resource_id, updated_at) VALUES (?,?,?,?,?,?)`,
			dom, string(s.Platform), s.Profile, string(r.Type), r.ID, now.Unix()); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Delete removes a single resource (and its index entries).
func (d *DB) Delete(ctx context.Context, s Set, resourceType platform.ResourceType, id string) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE platform=? AND profile=? AND resource_type=? AND resource_id=?`, string(s.Platform), s.Profile, string(resourceType), id); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM domain_index WHERE platform=? AND profile=? AND resource_type=? AND resource_id=?`, string(s.Platform), s.Profile, string(resourceType), id); err != nil {
		return err
	}
	return tx.Commit()
}

// Query filters resource listings. Zero values mean "any".
type Query struct {
	Platform platform.ID
	Profile  string
	Type     platform.ResourceType
	ParentID string
	Domain   string
	Name     string
}

// List returns matching resources ordered by platform, profile, type, name.
func (d *DB) List(ctx context.Context, q Query) ([]Resource, error) {
	var where []string
	var args []any
	add := func(col string, v string) {
		if v != "" {
			where = append(where, col+"=?")
			args = append(args, v)
		}
	}
	add("platform", string(q.Platform))
	add("profile", q.Profile)
	add("resource_type", string(q.Type))
	add("parent_id", q.ParentID)
	add("domain", platform.NormalizeDomain(q.Domain))
	add("name", q.Name)
	sqlq := `SELECT platform, profile, resource_type, resource_id, name, parent_id, domain, data, updated_at, expires_at FROM resources`
	if len(where) > 0 {
		sqlq += " WHERE " + strings.Join(where, " AND ")
	}
	sqlq += " ORDER BY platform, profile, resource_type, name, resource_id"
	rows, err := d.sql.QueryContext(ctx, sqlq, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Resource
	for rows.Next() {
		var r Resource
		var p, t, data string
		var upd, exp int64
		if err := rows.Scan(&p, &r.Profile, &t, &r.ID, &r.Name, &r.ParentID, &r.Domain, &data, &upd, &exp); err != nil {
			return nil, err
		}
		r.Platform, r.Type = platform.ID(p), platform.ResourceType(t)
		r.Data = json.RawMessage(data)
		r.UpdatedAt, r.ExpiresAt = time.Unix(upd, 0), time.Unix(exp, 0)
		out = append(out, r)
	}
	return out, rows.Err()
}

// Get returns one resource.
func (d *DB) Get(ctx context.Context, s Set, resourceType platform.ResourceType, id string) (*Resource, error) {
	rs, err := d.List(ctx, Query{Platform: s.Platform, Profile: s.Profile, Type: resourceType})
	if err != nil {
		return nil, err
	}
	for i := range rs {
		if rs[i].ID == id {
			return &rs[i], nil
		}
	}
	return nil, platform.ErrNotFound
}

// IndexEntry is a row of domain_index.
type IndexEntry struct {
	Domain     string                `json:"domain" yaml:"domain"`
	Platform   platform.ID           `json:"platform" yaml:"platform"`
	Profile    string                `json:"profile" yaml:"profile"`
	Type       platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	ResourceID string                `json:"resource_id" yaml:"resource_id"`
	UpdatedAt  time.Time             `json:"updated_at" yaml:"updated_at"`
}

// LookupDomain returns index entries for any of the given domains (exact
// matches), optionally filtered by resource type. Results are ordered with
// the longest domain first, so callers can take the most specific match.
func (d *DB) LookupDomain(ctx context.Context, domains []string, rt platform.ResourceType) ([]IndexEntry, error) {
	if len(domains) == 0 {
		return nil, nil
	}
	ph := make([]string, len(domains))
	args := make([]any, 0, len(domains)+1)
	for i, dm := range domains {
		ph[i] = "?"
		args = append(args, platform.NormalizeDomain(dm))
	}
	q := `SELECT domain, platform, profile, resource_type, resource_id, updated_at FROM domain_index WHERE domain IN (` + strings.Join(ph, ",") + `)`
	if rt != "" {
		q += ` AND resource_type=?`
		args = append(args, string(rt))
	}
	q += ` ORDER BY length(domain) DESC, platform, profile, resource_type, resource_id`
	rows, err := d.sql.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IndexEntry
	for rows.Next() {
		var e IndexEntry
		var p, t string
		var upd int64
		if err := rows.Scan(&e.Domain, &p, &e.Profile, &t, &e.ResourceID, &upd); err != nil {
			return nil, err
		}
		e.Platform, e.Type = platform.ID(p), platform.ResourceType(t)
		e.UpdatedAt = time.Unix(upd, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// IndexEntries lists the entire domain index.
func (d *DB) IndexEntries(ctx context.Context) ([]IndexEntry, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT domain, platform, profile, resource_type, resource_id, updated_at FROM domain_index ORDER BY domain, platform, profile, resource_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []IndexEntry
	for rows.Next() {
		var e IndexEntry
		var p, t string
		var upd int64
		if err := rows.Scan(&e.Domain, &p, &e.Profile, &t, &e.ResourceID, &upd); err != nil {
			return nil, err
		}
		e.Platform, e.Type = platform.ID(p), platform.ResourceType(t)
		e.UpdatedAt = time.Unix(upd, 0)
		out = append(out, e)
	}
	return out, rows.Err()
}

// Purge removes everything stored for a profile (used by logout).
func (d *DB) Purge(ctx context.Context, p platform.ID, profile string) error {
	for _, t := range []string{"resources", "domain_index", "sync_state"} {
		if _, err := d.sql.ExecContext(ctx, `DELETE FROM `+t+` WHERE platform=? AND profile=?`, string(p), profile); err != nil {
			return err
		}
	}
	return nil
}

// RenameProfile moves everything stored for an account from one profile name
// to another, in one transaction. Rows already stored under the new name for
// that platform are stale leftovers and are removed first.
func (d *DB) RenameProfile(ctx context.Context, p platform.ID, oldName, newName string) error {
	if oldName == newName {
		return nil
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for _, t := range []string{"resources", "domain_index", "sync_state"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE platform=? AND profile=?`, string(p), newName); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `UPDATE `+t+` SET profile=? WHERE platform=? AND profile=?`, newName, string(p), oldName); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// Stats summarises the inventory per profile and type.
type Stat struct {
	Platform  platform.ID           `json:"platform" yaml:"platform"`
	Profile   string                `json:"profile" yaml:"profile"`
	Type      platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	Count     int                   `json:"count" yaml:"count"`
	SyncedAt  time.Time             `json:"synced_at" yaml:"synced_at"`
	ExpiresAt time.Time             `json:"expires_at" yaml:"expires_at"`
}

// Stats returns counts and freshness for each synced set (unscoped scopes only).
func (d *DB) Stats(ctx context.Context) ([]Stat, error) {
	rows, err := d.sql.QueryContext(ctx, `
SELECT s.platform, s.profile, s.resource_type, s.synced_at, s.expires_at,
  (SELECT COUNT(*) FROM resources r WHERE r.platform=s.platform AND r.profile=s.profile AND r.resource_type=s.resource_type)
FROM sync_state s WHERE s.scope='' ORDER BY s.platform, s.profile, s.resource_type`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Stat
	for rows.Next() {
		var st Stat
		var p, t string
		var syncedAt, expiresAt int64
		if err := rows.Scan(&p, &st.Profile, &t, &syncedAt, &expiresAt, &st.Count); err != nil {
			return nil, err
		}
		st.Platform, st.Type = platform.ID(p), platform.ResourceType(t)
		st.SyncedAt, st.ExpiresAt = time.Unix(syncedAt, 0), time.Unix(expiresAt, 0)
		out = append(out, st)
	}
	return out, rows.Err()
}
