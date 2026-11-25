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
	if _, err := db.Exec(schema + ipIndexSchema + secretSchema + renameSchema); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate inventory db: %w", err)
	}
	if err := migrateData(db); err != nil {
		db.Close()
		return nil, fmt.Errorf("migrate inventory db: %w", err)
	}
	return &DB{sql: db, now: time.Now}, nil
}

// dataVersion is the version of the stored data, kept in PRAGMA
// user_version. Version 1 names a DNS record's data "value"; polyctl 0.1.x
// wrote it as "content". Version 2 drops the cached GoDaddy DNS records,
// whose ids did not carry the zone before (see forgetGoDaddyRecords).
// Version 3 drops everything cached for Google Cloud, whose rows did not
// carry their project before (see forgetGCPRows). Version 4 makes the sets
// cached for Google Cloud due, whose accounts cover every project their
// credentials see since then (see expireGCPSets). Version 5 does the same
// for Cloudflare, whose logins cover every account their credentials see
// since then (see expireCloudflareSets).
const dataVersion = 5

// expireCloudflareSets makes every set cached for Cloudflare due, keeping
// its rows: a login used to cover the accounts selected for it and covers
// every account its credentials see now, so a set that is still fresh would
// hide the accounts that were not selected. The next read of a set syncs
// it; until then, and with --offline, its rows are served.
const expireCloudflareSets = `UPDATE sync_state SET expires_at = 0 WHERE platform = 'cloudflare'`

// expireGCPSets makes every set cached for Google Cloud due, keeping its
// rows: an account used to cover the projects selected for it and covers
// every project its credentials see now, so a set that is still fresh
// would hide the projects that were not selected. The next read of a set
// syncs it; until then, and with --offline, its rows are served.
const expireGCPSets = `UPDATE sync_state SET expires_at = 0 WHERE platform = 'gcp'`

// forgetGCPRows drops the rows cached for Google Cloud before an account
// could hold several projects: zone, record and certificate ids and the
// parents of every row now start with the project, so the old rows would
// neither be found nor be replaced by a sync. The sets are synced again on
// their next use. Instance secrets are not cached data and stay.
var forgetGCPRows = []string{
	`DELETE FROM resources WHERE platform = 'gcp'`,
	`DELETE FROM domain_index WHERE platform = 'gcp'`,
	`DELETE FROM ip_index WHERE platform = 'gcp'`,
	`DELETE FROM sync_state WHERE platform = 'gcp'`,
}

// forgetGoDaddyRecords drops the GoDaddy DNS records cached before their
// ids carried the zone: the same record in two domains of one account
// shared one row, so the cache of one of them missed it. The sets are
// synced again on their next use.
var forgetGoDaddyRecords = []string{
	`DELETE FROM resources WHERE platform = 'godaddy' AND resource_type = 'dns_record'`,
	`DELETE FROM domain_index WHERE platform = 'godaddy' AND resource_type = 'dns_record'`,
	`DELETE FROM ip_index WHERE platform = 'godaddy' AND resource_type = 'dns_record'`,
	`DELETE FROM sync_state WHERE platform = 'godaddy' AND resource_type = 'dns_record'`,
}

// renameRecordContent rewrites the DNS records cached by polyctl 0.1.x,
// whose data was stored under "content", to the "value" field read today.
// platform.Record reads either key, so the rewrite is about what is shown
// as stored (inventory list -o json) and about one format on disk.
const renameRecordContent = `
UPDATE resources
   SET data = json_remove(json_set(data, '$.value', json_extract(data, '$.content')), '$.content')
 WHERE resource_type = 'dns_record'
   AND json_valid(data)
   AND json_type(data, '$.content') IS NOT NULL
   AND json_type(data, '$.value') IS NULL`

// hasRecordContent finds out, without writing, whether renameRecordContent
// has anything to do.
const hasRecordContent = `
SELECT EXISTS (SELECT 1 FROM resources
 WHERE resource_type = 'dns_record'
   AND json_valid(data)
   AND json_type(data, '$.content') IS NOT NULL
   AND json_type(data, '$.value') IS NULL)`

// migrateData brings the stored JSON up to dataVersion.
//
// The rewrite of DNS records is not tied to the version alone: a polyctl
// 0.1.x that shares the config directory (both versions installed, a
// rollback, a synced home directory) keeps writing "content" rows into a
// database that is already at version 1. So every Open looks for such rows,
// which is a read, and rewrites them when there are any. The version is
// kept for format changes that cannot be detected this way.
func migrateData(db *sql.DB) error {
	var v int
	if err := db.QueryRow(`PRAGMA user_version`).Scan(&v); err != nil {
		return err
	}
	var stale bool
	if err := db.QueryRow(hasRecordContent).Scan(&stale); err != nil {
		return err
	}
	if v >= dataVersion && !stale {
		return nil
	}
	tx, err := db.Begin()
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.Exec(renameRecordContent); err != nil {
		return err
	}
	if v < 2 {
		for _, q := range forgetGoDaddyRecords {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
	}
	if v < 3 {
		for _, q := range forgetGCPRows {
			if _, err := tx.Exec(q); err != nil {
				return err
			}
		}
	}
	if v < 4 {
		if _, err := tx.Exec(expireGCPSets); err != nil {
			return err
		}
	}
	if v < 5 {
		if _, err := tx.Exec(expireCloudflareSets); err != nil {
			return err
		}
	}
	if v < dataVersion {
		if _, err := tx.Exec(fmt.Sprintf(`PRAGMA user_version = %d`, dataVersion)); err != nil {
			return err
		}
	}
	return tx.Commit()
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
// the sync time, and rebuilds the domain index and the IP index for the set. For an
// unscoped dns_record set it also clears every per-zone scope of the profile.
func (d *DB) Replace(ctx context.Context, s Set, resources []platform.Resource, ttl time.Duration) error {
	return d.ReplaceKeeping(ctx, s, resources, ttl, nil)
}

// ReplaceKeeping is Replace for a sync that could not read some parents of
// an unscoped set (the regions of a multi-region sync that failed): the
// stored rows whose ParentID is in keep stay, with their index entries,
// unless resources holds a row of the same id, and the set expires at once
// so the next read retries the failed parents. A scoped set ignores keep.
func (d *DB) ReplaceKeeping(ctx context.Context, s Set, resources []platform.Resource, ttl time.Duration, keep []string) error {
	return d.ReplaceKeepingTrees(ctx, s, resources, ttl, keep, nil)
}

// ReplaceKeepingTrees is ReplaceKeeping with whole trees of parents kept
// as well: a tree t keeps the rows whose ParentID is t or starts with
// t + "/" (a Google Cloud project that failed, whose rows have the parent
// "<project>" or "<project>/<zone or region>"), and the rows whose
// ParentID is the id of a stored row of the tree, of any type of the same
// profile (a Cloudflare account that failed: its zone rows have the parent
// "<account>", and its record rows the id of their zone).
func (d *DB) ReplaceKeepingTrees(ctx context.Context, s Set, resources []platform.Resource, ttl time.Duration, keep, trees []string) error {
	if s.Scope != "" {
		keep, trees = nil, nil
	}
	return d.replace(ctx, s, resources, ttl, keep, trees)
}

// keptCond is the SQL condition of the rows a partial sync keeps, with its
// arguments: parent_id in keep, or in one of trees, or the id of a row of
// one of trees (collectTreeRows must have run in the transaction).
func keptCond(keep, trees []string) (string, []any) {
	var parts []string
	var args []any
	if len(keep) > 0 {
		parts = append(parts, `parent_id IN (`+strings.TrimSuffix(strings.Repeat("?,", len(keep)), ",")+`)`)
		for _, k := range keep {
			args = append(args, k)
		}
	}
	for _, t := range trees {
		parts = append(parts, treeCond)
		args = append(args, t, t, t)
	}
	if len(trees) > 0 {
		parts = append(parts, treeChildCond)
	}
	return `(` + strings.Join(parts, " OR ") + `)`, args
}

// treeCond matches the rows of one tree of parents (three arguments, the
// tree each time).
const treeCond = `(parent_id = ? OR substr(parent_id, 1, length(?) + 1) = ? || '/')`

// treeChildCond matches the rows whose parent is a row of the trees that
// collectTreeRows gathered (no argument).
const treeChildCond = `parent_id IN (SELECT id FROM temp.tree_rows)`

// collectTreeRows gathers, in a temporary table of the transaction, the
// ids of the stored rows of the trees of a profile, whatever their type:
// the parents treeChildCond matches. The table is read instead of the
// resources themselves, so that a statement deleting resources does not
// search the rows it deletes. dropTreeRows removes it.
func collectTreeRows(ctx context.Context, tx *sql.Tx, p platform.ID, profile string, trees []string) error {
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS tree_rows (id TEXT PRIMARY KEY)`); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM temp.tree_rows`); err != nil {
		return err
	}
	for _, t := range trees {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO temp.tree_rows SELECT resource_id FROM resources WHERE platform=? AND profile=? AND `+treeCond,
			string(p), profile, t, t, t); err != nil {
			return err
		}
	}
	return nil
}

func dropTreeRows(ctx context.Context, tx *sql.Tx) error {
	_, err := tx.ExecContext(ctx, `DROP TABLE IF EXISTS temp.tree_rows`)
	return err
}

func (d *DB) replace(ctx context.Context, s Set, resources []platform.Resource, ttl time.Duration, keep, trees []string) error {
	now := d.now()
	exp := now.Add(ttl)
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()

	kept := len(keep)+len(trees) > 0
	if s.Scope == "" && kept {
		// Only the rows outside the kept parents go, and their index
		// entries before them.
		if len(trees) > 0 {
			if err := collectTreeRows(ctx, tx, s.Platform, s.Profile, trees); err != nil {
				return err
			}
		}
		cond, condArgs := keptCond(keep, trees)
		args := append([]any{string(s.Platform), s.Profile, string(s.Type)}, condArgs...)
		dropped := `SELECT resource_id FROM resources WHERE platform=? AND profile=? AND resource_type=? AND NOT ` + cond
		for _, t := range []string{"domain_index", "ip_index"} {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE platform=? AND profile=? AND resource_type=? AND resource_id IN (`+dropped+`)`,
				append([]any{string(s.Platform), s.Profile, string(s.Type)}, args...)...); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE platform=? AND profile=? AND resource_type=? AND NOT `+cond, args...); err != nil {
			return err
		}
		// The state of the scopes of the kept parents stays with their
		// rows: a read of one of them that cannot go online is still
		// answered from what is stored.
		if _, err := tx.ExecContext(ctx, `DELETE FROM sync_state WHERE platform=? AND profile=? AND resource_type=? AND NOT `+strings.ReplaceAll(cond, "parent_id", "scope"), args...); err != nil {
			return err
		}
		if len(trees) > 0 {
			if err := dropTreeRows(ctx, tx); err != nil {
				return err
			}
		}
	} else if s.Scope == "" {
		if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE platform=? AND profile=? AND resource_type=?`, string(s.Platform), s.Profile, string(s.Type)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM domain_index WHERE platform=? AND profile=? AND resource_type=?`, string(s.Platform), s.Profile, string(s.Type)); err != nil {
			return err
		}
		if _, err := tx.ExecContext(ctx, `DELETE FROM ip_index WHERE platform=? AND profile=? AND resource_type=?`, string(s.Platform), s.Profile, string(s.Type)); err != nil {
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
		if _, err := tx.ExecContext(ctx, `DELETE FROM ip_index WHERE platform=? AND profile=? AND resource_type=? AND resource_id IN (SELECT resource_id FROM resources WHERE platform=? AND profile=? AND resource_type=? AND parent_id=?)`,
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
		if kept {
			// The row may replace a kept one: its old domain goes.
			if _, err := tx.ExecContext(ctx, `DELETE FROM domain_index WHERE platform=? AND profile=? AND resource_type=? AND resource_id=?`, string(s.Platform), s.Profile, string(r.Type), r.ID); err != nil {
				return err
			}
		}
		if _, err := ins.ExecContext(ctx, string(s.Platform), s.Profile, string(r.Type), r.ID, r.Name, r.ParentID, dom, string(b), now.Unix(), exp.Unix()); err != nil {
			return err
		}
		if dom != "" && r.Type != platform.ResDNSRecord {
			if _, err := idx.ExecContext(ctx, dom, string(s.Platform), s.Profile, string(r.Type), r.ID, now.Unix()); err != nil {
				return err
			}
		}
		if err := writeIPs(ctx, tx, s.Platform, s.Profile, r); err != nil {
			return err
		}
	}
	// A set with kept parents holds old rows of the parents that failed:
	// it expires now, so the next read syncs again (and find reports it
	// stale) instead of serving them as fresh for a whole TTL.
	setExp := exp
	if s.Scope == "" && kept {
		setExp = now
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO sync_state (platform, profile, resource_type, scope, synced_at, expires_at) VALUES (?,?,?,?,?,?)`,
		string(s.Platform), s.Profile, string(s.Type), s.Scope, now.Unix(), setExp.Unix()); err != nil {
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
	if err := writeIPs(ctx, tx, s.Platform, s.Profile, r); err != nil {
		return err
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
	if _, err := tx.ExecContext(ctx, `DELETE FROM ip_index WHERE platform=? AND profile=? AND resource_type=? AND resource_id=?`, string(s.Platform), s.Profile, string(resourceType), id); err != nil {
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

// Purge removes everything cached for a profile (used by logout). The
// instance secrets stay, as they cannot be fetched again; logout detaches
// them (DetachSecrets).
func (d *DB) Purge(ctx context.Context, p platform.ID, profile string) error {
	for _, t := range []string{"resources", "domain_index", "ip_index", "sync_state"} {
		if _, err := d.sql.ExecContext(ctx, `DELETE FROM `+t+` WHERE platform=? AND profile=?`, string(p), profile); err != nil {
			return err
		}
	}
	return nil
}

// PurgeTree removes what is cached for one tree of parents of a profile
// (see ReplaceKeepingTrees): the rows of a Google Cloud project that was
// disabled, or those of a Cloudflare account that left the selection
// (its zone rows, and the record rows under the ids of those zones), with
// their index entries and the sync state of the scopes among them.
// Instance secrets stay.
func (d *DB) PurgeTree(ctx context.Context, p platform.ID, profile, tree string) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := collectTreeRows(ctx, tx, p, profile, []string{tree}); err != nil {
		return err
	}
	cond := `(` + treeCond + ` OR ` + treeChildCond + `)`
	rows := `SELECT resource_type || char(0) || resource_id FROM resources WHERE platform=? AND profile=? AND ` + cond
	args := []any{string(p), profile, string(p), profile, tree, tree, tree}
	for _, t := range []string{"domain_index", "ip_index"} {
		if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE platform=? AND profile=? AND resource_type || char(0) || resource_id IN (`+rows+`)`, args...); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM resources WHERE platform=? AND profile=? AND `+cond, string(p), profile, tree, tree, tree); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM sync_state WHERE platform=? AND profile=? AND `+strings.ReplaceAll(cond, "parent_id", "scope"), string(p), profile, tree, tree, tree); err != nil {
		return err
	}
	if err := dropTreeRows(ctx, tx); err != nil {
		return err
	}
	return tx.Commit()
}

// Expire marks every synced set of a profile as due: the rows stay, and the
// next read that may go online syncs again (what the account covers
// changed).
func (d *DB) Expire(ctx context.Context, p platform.ID, profile string) error {
	_, err := d.sql.ExecContext(ctx, `UPDATE sync_state SET expires_at = 0 WHERE platform=? AND profile=?`, string(p), profile)
	return err
}

// renameSchema records the renames of profiles under way: RenameProfile
// adds a row in the transaction that moves an account's rows, and EndRename
// removes it once the config names the profile anew (or the rename was
// undone). A row left by an interrupted rename tells the rerun that the rows
// already under the new name are the ones it moved.
const renameSchema = `
CREATE TABLE IF NOT EXISTS profile_renames (
  platform  TEXT NOT NULL,
  old       TEXT NOT NULL,
  new       TEXT NOT NULL,
  PRIMARY KEY (platform, old, new)
);
`

// RenameProfile moves everything stored for an account from one profile name
// to another, instance secrets included, in one transaction. Rows already
// stored under the new name for that platform are stale leftovers: cached
// rows are removed first, instance secrets are detached. When an earlier
// run of the same rename was interrupted after moving the rows (its record
// is still there, see EndRename), the rows under the new name are the ones
// it moved and are kept as they are.
func (d *DB) RenameProfile(ctx context.Context, p platform.ID, oldName, newName string) error {
	if oldName == newName {
		return nil
	}
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var resumed int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM profile_renames WHERE platform=? AND old=? AND new=?`, string(p), oldName, newName).Scan(&resumed); err != nil {
		return err
	}
	for _, t := range []string{"resources", "domain_index", "ip_index", "sync_state"} {
		if resumed == 0 {
			if _, err := tx.ExecContext(ctx, `DELETE FROM `+t+` WHERE platform=? AND profile=?`, string(p), newName); err != nil {
				return err
			}
		}
		if _, err := tx.ExecContext(ctx, `UPDATE OR REPLACE `+t+` SET profile=? WHERE platform=? AND profile=?`, newName, string(p), oldName); err != nil {
			return err
		}
	}
	// Instance secrets cannot be fetched again. Rows already under the new
	// name belong to an account that was logged out there (left by a
	// release that kept them in place): they are detached, not merged into
	// the renamed account, and a rename undone by renaming back moves only
	// the rows this one moved.
	if resumed == 0 {
		if err := detachSecrets(ctx, tx, p, newName); err != nil {
			return err
		}
	}
	if _, err := tx.ExecContext(ctx, `UPDATE OR REPLACE instance_secrets SET profile=? WHERE platform=? AND profile=?`, newName, string(p), oldName); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO profile_renames (platform, old, new) VALUES (?, ?, ?)`, string(p), oldName, newName); err != nil {
		return err
	}
	return tx.Commit()
}

// EndRename removes the records of a rename of profile oldName to newName
// (and of its undo), once the config was saved with the new name or the
// rename was undone.
func (d *DB) EndRename(ctx context.Context, oldName, newName string) error {
	_, err := d.sql.ExecContext(ctx, `DELETE FROM profile_renames WHERE (old=? AND new=?) OR (old=? AND new=?)`, oldName, newName, newName, oldName)
	return err
}

// DetachedSuffix is appended to the profile of the instance secrets of an
// account that was logged out. Profile names cannot contain a slash, so a
// detached row never matches a profile.
const DetachedSuffix = "/detached"

// DetachedProfile is the profile column of the detached instance secrets of
// profile.
func DetachedProfile(profile string) string { return profile + DetachedSuffix }

// DetachSecrets moves the instance secrets of an account (used by logout)
// out of the profile: an account logged in later under the same name, which
// may be another one, does not see them as its own. They stay readable by
// instance id (FindDetachedSecret). A row of the same instance detached
// before is replaced.
func (d *DB) DetachSecrets(ctx context.Context, p platform.ID, profile string) error {
	tx, err := d.sql.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err := detachSecrets(ctx, tx, p, profile); err != nil {
		return err
	}
	return tx.Commit()
}

func detachSecrets(ctx context.Context, tx *sql.Tx, p platform.ID, profile string) error {
	_, err := tx.ExecContext(ctx, `UPDATE OR REPLACE instance_secrets SET profile=? WHERE platform=? AND profile=?`, DetachedProfile(profile), string(p), profile)
	return err
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
