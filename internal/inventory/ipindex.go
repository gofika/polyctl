package inventory

import (
	"context"
	"database/sql"
	"net/netip"
	"strings"

	"github.com/gofika/polyctl/internal/platform"
)

// ipIndexSchema is the IP index: every address, prefix and DNS name of the
// resources that carry them (Resource.IPs), written with the resource and
// rebuilt with its set. prefix_bits is 0 for an address or a DNS name and
// the prefix length for a prefix ("10.1.2.0/24" has 24), which is matched
// by containment.
const ipIndexSchema = `
CREATE TABLE IF NOT EXISTS ip_index (
  platform      TEXT    NOT NULL,
  profile       TEXT    NOT NULL,
  resource_type TEXT    NOT NULL,
  resource_id   TEXT    NOT NULL,
  ip            TEXT    NOT NULL,
  kind          TEXT    NOT NULL,
  prefix_bits   INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (platform, profile, resource_type, resource_id, ip, kind)
);
CREATE INDEX IF NOT EXISTS ip_index_ip ON ip_index (ip);
CREATE INDEX IF NOT EXISTS ip_index_prefix ON ip_index (prefix_bits) WHERE prefix_bits > 0;
`

// execer is what a transaction and the database have in common.
type execer interface {
	ExecContext(ctx context.Context, query string, args ...any) (sql.Result, error)
}

// prefixBits returns the prefix length of an index value, 0 for an
// address or a DNS name.
func prefixBits(r platform.IPRef) int {
	if r.Kind == platform.IPDNS || !strings.Contains(r.Value, "/") {
		return 0
	}
	p, err := netip.ParsePrefix(r.Value)
	if err != nil {
		return 0
	}
	return p.Bits()
}

// writeIPs replaces the index rows of one resource with its IPs.
func writeIPs(ctx context.Context, tx execer, p platform.ID, profile string, r platform.Resource) error {
	if _, err := tx.ExecContext(ctx, `DELETE FROM ip_index WHERE platform=? AND profile=? AND resource_type=? AND resource_id=?`,
		string(p), profile, string(r.Type), r.ID); err != nil {
		return err
	}
	for _, ip := range r.IPs {
		if ip.Value == "" {
			continue
		}
		bits := prefixBits(ip)
		if bits == 0 && strings.Contains(ip.Value, "/") {
			continue // an invalid prefix is never matched
		}
		if _, err := tx.ExecContext(ctx, `INSERT OR REPLACE INTO ip_index (platform, profile, resource_type, resource_id, ip, kind, prefix_bits) VALUES (?,?,?,?,?,?,?)`,
			string(p), profile, string(r.Type), r.ID, ip.Value, string(ip.Kind), bits); err != nil {
			return err
		}
	}
	return nil
}

// IPHit is a row of the IP index that matched a query.
type IPHit struct {
	Platform   platform.ID           `json:"platform" yaml:"platform"`
	Profile    string                `json:"profile" yaml:"profile"`
	Type       platform.ResourceType `json:"resource_type" yaml:"resource_type"`
	ResourceID string                `json:"resource_id" yaml:"resource_id"`
	// IP is the indexed value that matched: the address, the prefix that
	// contains it, or the DNS name.
	IP   string          `json:"ip" yaml:"ip"`
	Kind platform.IPKind `json:"kind" yaml:"kind"`
}

func scanHits(rows *sql.Rows) ([]IPHit, error) {
	defer rows.Close()
	var out []IPHit
	for rows.Next() {
		var h IPHit
		var p, t, k string
		if err := rows.Scan(&p, &h.Profile, &t, &h.ResourceID, &h.IP, &k); err != nil {
			return nil, err
		}
		h.Platform, h.Type, h.Kind = platform.ID(p), platform.ResourceType(t), platform.IPKind(k)
		out = append(out, h)
	}
	return out, rows.Err()
}

const hitColumns = `platform, profile, resource_type, resource_id, ip, kind`

// LookupIP returns the index rows holding addr: the rows of that exact
// address, and the prefixes that contain it (GCP alias ranges, IPv6
// prefixes). The address is compared in its canonical form, so the spelling
// of an IPv6 address or an IPv4-mapped form makes no difference.
func (d *DB) LookupIP(ctx context.Context, addr netip.Addr) ([]IPHit, error) {
	addr = addr.WithZone("").Unmap()
	rows, err := d.sql.QueryContext(ctx, `SELECT `+hitColumns+` FROM ip_index WHERE ip=? AND kind<>? AND prefix_bits=0
ORDER BY platform, profile, resource_type, resource_id, kind`, addr.String(), string(platform.IPDNS))
	if err != nil {
		return nil, err
	}
	out, err := scanHits(rows)
	if err != nil {
		return nil, err
	}
	rows, err = d.sql.QueryContext(ctx, `SELECT `+hitColumns+` FROM ip_index WHERE prefix_bits > 0
ORDER BY platform, profile, resource_type, resource_id, kind`)
	if err != nil {
		return nil, err
	}
	prefixes, err := scanHits(rows)
	if err != nil {
		return nil, err
	}
	for _, h := range prefixes {
		if p, err := netip.ParsePrefix(h.IP); err == nil && p.Contains(addr) {
			out = append(out, h)
		}
	}
	return out, nil
}

// LookupDNS returns the index rows of a DNS name (compared without case
// and trailing dot).
func (d *DB) LookupDNS(ctx context.Context, name string) ([]IPHit, error) {
	rows, err := d.sql.QueryContext(ctx, `SELECT `+hitColumns+` FROM ip_index WHERE ip=? AND kind=?
ORDER BY platform, profile, resource_type, resource_id`, platform.NormalizeDomain(name), string(platform.IPDNS))
	if err != nil {
		return nil, err
	}
	return scanHits(rows)
}
