// Package repodb binds repo.Store to TimescaleDB via *store.Store. Tenant-scoped
// calls run in a tenant transaction (RLS); the audit writer, the challenge
// sweeper listing, tenant enumeration and the platform-scope server
// configuration run under the system-scope pin; the overlap question and the
// reconciler's zone names go through the narrow SECURITY DEFINER functions
// dns_zone_conflict() and dns_zone_names(). Unique violations map to
// repo.ErrConflict, foreign-key violations on writes (a missing or cross-tenant
// zone — the composite (tenant_id, id) key) and malformed ids to
// repo.ErrNotFound.
package repodb

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"regexp"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

// DB implements repo.Store over *store.Store.
type DB struct{ St *store.Store }

var _ repo.Store = (*DB)(nil)

// New wraps the store.
func New(st *store.Store) *DB { return &DB{St: st} }

// Close releases the underlying pool.
func (d *DB) Close() { d.St.Close() }

func (d *DB) tenant(ctx context.Context, tid string, fn func(tx pgx.Tx) error) error {
	if !isUUID(tid) {
		return repo.ErrNotFound
	}
	return d.St.Tx(ctx, store.Scope{TenantID: tid}, fn)
}

func (d *DB) system(ctx context.Context, fn func(tx pgx.Tx) error) error {
	return d.St.Tx(ctx, store.Scope{System: true}, fn)
}

type scanner interface{ Scan(dest ...any) error }

// mapErr maps store errors: no row / malformed id → ErrNotFound, unique
// violation → ErrConflict, foreign-key violation → ErrNotFound (the referenced
// zone is missing or belongs to another tenant).
func mapErr(err error) error {
	if err == nil {
		return nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return repo.ErrNotFound
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		switch pg.Code {
		case "23505":
			return repo.ErrConflict
		case "23503", "22P02": // foreign_key_violation, invalid_text_representation
			return repo.ErrNotFound
		}
	}
	return err
}

func affected(tag pgconn.CommandTag, err error) error {
	if err != nil {
		return mapErr(err)
	}
	if tag.RowsAffected() == 0 {
		return repo.ErrNotFound
	}
	return nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

func orNow(t time.Time) time.Time {
	if t.IsZero() {
		return time.Now().UTC()
	}
	return t
}

func strs(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// likePattern escapes LIKE metacharacters so user input matches literally.
func likePattern(q string) string {
	r := strings.NewReplacer(`\`, `\\`, `%`, `\%`, `_`, `\_`)
	return "%" + r.Replace(strings.ToLower(strings.TrimSpace(q))) + "%"
}

// canonIP renders an IP literal as the inet column does ("" when invalid).
func canonIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// ---------------------------------------------------------------- zones

const zoneCols = `id, tenant_id, name, pdns_id, kind, masters, dnssec, description, template_id, origin,
 nameservers, created_by, created_at, updated_at`

func scanZone(sc scanner) (store.Zone, error) {
	var z store.Zone
	var tpl *string
	err := sc.Scan(&z.ID, &z.TenantID, &z.Name, &z.PDNSID, &z.Kind, &z.Masters, &z.DNSSEC, &z.Description, &tpl, &z.Origin,
		&z.Nameservers, &z.CreatedBy, &z.CreatedAt, &z.UpdatedAt)
	z.TemplateID = deref(tpl)
	z.Masters, z.Nameservers = strs(z.Masters), strs(z.Nameservers)
	return z, err
}

// CreateZone implements repo.Zones.
func (d *DB) CreateZone(ctx context.Context, z store.Zone) error {
	if z.Kind == "" {
		z.Kind = store.KindNative
	}
	if z.Origin == "" {
		z.Origin = store.OriginManual
	}
	var tpl *string
	if isUUID(z.TemplateID) {
		tpl = &z.TemplateID
	}
	created := orNow(z.CreatedAt)
	updated := z.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	return d.tenant(ctx, z.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_zones (`+zoneCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14)`,
			z.ID, z.TenantID, z.Name, z.PDNSID, z.Kind, strs(z.Masters), z.DNSSEC, z.Description, tpl, z.Origin,
			strs(z.Nameservers), z.CreatedBy, created, updated)
		return mapErr(err)
	})
}

// GetZone implements repo.Zones.
func (d *DB) GetZone(ctx context.Context, tenantID, id string) (store.Zone, error) {
	if !isUUID(id) {
		return store.Zone{}, repo.ErrNotFound
	}
	var z store.Zone
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		z, err = scanZone(tx.QueryRow(ctx, `SELECT `+zoneCols+` FROM dns_zones WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return mapErr(err)
	})
	return z, err
}

// GetZoneByName implements repo.Zones.
func (d *DB) GetZoneByName(ctx context.Context, tenantID, name string) (store.Zone, error) {
	var z store.Zone
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		z, err = scanZone(tx.QueryRow(ctx, `SELECT `+zoneCols+` FROM dns_zones WHERE tenant_id = $1 AND name = $2`, tenantID, name))
		return mapErr(err)
	})
	return z, err
}

func collectZones(rows pgx.Rows) ([]store.Zone, error) {
	defer rows.Close()
	out := []store.Zone{}
	for rows.Next() {
		z, err := scanZone(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, z)
	}
	return out, rows.Err()
}

// ListZones implements repo.Zones.
func (d *DB) ListZones(ctx context.Context, tenantID string, f store.ZoneFilter) ([]store.Zone, int64, error) {
	f = f.Normalized(0)
	var items []store.Zone
	var total int64
	q := ""
	if strings.TrimSpace(f.Query) != "" {
		q = likePattern(f.Query)
	}
	where := ` WHERE tenant_id = $1 AND ($2 = '' OR kind = $2) AND ($3 = '' OR origin = $3) AND ($4 = '' OR name LIKE $4 ESCAPE '\')`
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		if err := tx.QueryRow(ctx, `SELECT count(*) FROM dns_zones`+where, tenantID, f.Kind, f.Origin, q).Scan(&total); err != nil {
			return mapErr(err)
		}
		rows, err := tx.Query(ctx, `SELECT `+zoneCols+` FROM dns_zones`+where+` ORDER BY name COLLATE "C" LIMIT $5 OFFSET $6`,
			tenantID, f.Kind, f.Origin, q, f.PageSize, f.Offset())
		if err != nil {
			return mapErr(err)
		}
		items, err = collectZones(rows)
		return err
	})
	if err != nil {
		return nil, 0, err
	}
	return items, total, nil
}

// UpdateZone implements repo.Zones.
func (d *DB) UpdateZone(ctx context.Context, z store.Zone) (store.Zone, error) {
	if !isUUID(z.ID) {
		return store.Zone{}, repo.ErrNotFound
	}
	var out store.Zone
	err := d.tenant(ctx, z.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanZone(tx.QueryRow(ctx, `UPDATE dns_zones SET kind = $3, masters = $4, dnssec = $5, description = $6, updated_at = $7
 WHERE tenant_id = $1 AND id = $2 RETURNING `+zoneCols, z.TenantID, z.ID, z.Kind, strs(z.Masters), z.DNSSEC, z.Description, orNow(z.UpdatedAt)))
		return mapErr(err)
	})
	return out, err
}

// DeleteZone implements repo.Zones (challenges cascade).
func (d *DB) DeleteZone(ctx context.Context, tenantID, id string) error {
	if !isUUID(id) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM dns_zones WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	})
}

// ZoneConflict implements repo.Zones through dns_zone_conflict() (boolean only).
func (d *DB) ZoneConflict(ctx context.Context, tenantID, name string) (bool, error) {
	var conflict bool
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return mapErr(tx.QueryRow(ctx, `SELECT dns_zone_conflict($1, $2::uuid)`, strings.ToLower(name), tenantID).Scan(&conflict))
	})
	return conflict, err
}

// AllZoneNames implements repo.Zones through dns_zone_names() (names only).
func (d *DB) AllZoneNames(ctx context.Context) ([]string, error) {
	out := []string{}
	err := d.St.Tx(ctx, store.Scope{}, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT n FROM dns_zone_names() AS n ORDER BY n COLLATE "C"`)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var n string
			if err := rows.Scan(&n); err != nil {
				return err
			}
			out = append(out, n)
		}
		return rows.Err()
	})
	return out, err
}

// ZonesForTenant implements repo.Zones.
func (d *DB) ZonesForTenant(ctx context.Context, tenantID string) ([]store.Zone, error) {
	var out []store.Zone
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+zoneCols+` FROM dns_zones WHERE tenant_id = $1 ORDER BY name COLLATE "C"`, tenantID)
		if err != nil {
			return mapErr(err)
		}
		out, err = collectZones(rows)
		return err
	})
	return out, err
}

// ---------------------------------------------------------------- templates

const templateCols = `id, tenant_id, name, description, records, created_at, updated_at`

func scanTemplate(sc scanner) (store.Template, error) {
	var t store.Template
	var raw []byte
	if err := sc.Scan(&t.ID, &t.TenantID, &t.Name, &t.Description, &raw, &t.CreatedAt, &t.UpdatedAt); err != nil {
		return t, err
	}
	t.Records = []store.TemplateRecord{}
	if len(raw) > 0 {
		if err := json.Unmarshal(raw, &t.Records); err != nil {
			return t, err
		}
	}
	return t, nil
}

func recordsJSON(r []store.TemplateRecord) []byte {
	if r == nil {
		r = []store.TemplateRecord{}
	}
	b, _ := json.Marshal(r) // plain structs: marshalling cannot fail
	return b
}

// CreateTemplate implements repo.Templates.
func (d *DB) CreateTemplate(ctx context.Context, t store.Template) error {
	created := orNow(t.CreatedAt)
	updated := t.UpdatedAt
	if updated.IsZero() {
		updated = created
	}
	return d.tenant(ctx, t.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_zone_templates (`+templateCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			t.ID, t.TenantID, t.Name, t.Description, recordsJSON(t.Records), created, updated)
		return mapErr(err)
	})
}

// GetTemplate implements repo.Templates.
func (d *DB) GetTemplate(ctx context.Context, tenantID, id string) (store.Template, error) {
	if !isUUID(id) {
		return store.Template{}, repo.ErrNotFound
	}
	var t store.Template
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		t, err = scanTemplate(tx.QueryRow(ctx, `SELECT `+templateCols+` FROM dns_zone_templates WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return mapErr(err)
	})
	return t, err
}

// ListTemplates implements repo.Templates.
func (d *DB) ListTemplates(ctx context.Context, tenantID string) ([]store.Template, error) {
	out := []store.Template{}
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+templateCols+` FROM dns_zone_templates WHERE tenant_id = $1 ORDER BY lower(name) COLLATE "C", id`, tenantID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			t, err := scanTemplate(rows)
			if err != nil {
				return err
			}
			out = append(out, t)
		}
		return rows.Err()
	})
	return out, err
}

// UpdateTemplate implements repo.Templates.
func (d *DB) UpdateTemplate(ctx context.Context, t store.Template) (store.Template, error) {
	if !isUUID(t.ID) {
		return store.Template{}, repo.ErrNotFound
	}
	var out store.Template
	err := d.tenant(ctx, t.TenantID, func(tx pgx.Tx) error {
		var err error
		out, err = scanTemplate(tx.QueryRow(ctx, `UPDATE dns_zone_templates SET name = $3, description = $4, records = $5, updated_at = $6
 WHERE tenant_id = $1 AND id = $2 RETURNING `+templateCols, t.TenantID, t.ID, t.Name, t.Description, recordsJSON(t.Records), orNow(t.UpdatedAt)))
		return mapErr(err)
	})
	return out, err
}

// DeleteTemplate implements repo.Templates.
func (d *DB) DeleteTemplate(ctx context.Context, tenantID, id string) error {
	if !isUUID(id) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM dns_zone_templates WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	})
}

// ---------------------------------------------------------------- supermasters

const smCols = `id, tenant_id, host(ip), nameserver, created_by, created_at`

func scanSupermaster(sc scanner) (store.Supermaster, error) {
	var s store.Supermaster
	err := sc.Scan(&s.ID, &s.TenantID, &s.IP, &s.Nameserver, &s.CreatedBy, &s.CreatedAt)
	return s, err
}

// CreateSupermaster implements repo.Supermasters.
func (d *DB) CreateSupermaster(ctx context.Context, s store.Supermaster) error {
	ip := canonIP(s.IP)
	if ip == "" {
		return repo.ErrConflict // mirrors memstore; callers validate first
	}
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_supermasters (id, tenant_id, ip, nameserver, created_by, created_at) VALUES ($1,$2,$3::inet,$4,$5,$6)`,
			s.ID, s.TenantID, ip, s.Nameserver, s.CreatedBy, orNow(s.CreatedAt))
		return mapErr(err)
	})
}

// GetSupermaster implements repo.Supermasters.
func (d *DB) GetSupermaster(ctx context.Context, tenantID, id string) (store.Supermaster, error) {
	if !isUUID(id) {
		return store.Supermaster{}, repo.ErrNotFound
	}
	var s store.Supermaster
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var err error
		s, err = scanSupermaster(tx.QueryRow(ctx, `SELECT `+smCols+` FROM dns_supermasters WHERE tenant_id = $1 AND id = $2`, tenantID, id))
		return mapErr(err)
	})
	return s, err
}

// ListSupermasters implements repo.Supermasters.
func (d *DB) ListSupermasters(ctx context.Context, tenantID string) ([]store.Supermaster, error) {
	out := []store.Supermaster{}
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+smCols+` FROM dns_supermasters WHERE tenant_id = $1 ORDER BY ip, nameserver COLLATE "C"`, tenantID)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			s, err := scanSupermaster(rows)
			if err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	return out, err
}

// DeleteSupermaster implements repo.Supermasters.
func (d *DB) DeleteSupermaster(ctx context.Context, tenantID, id string) error {
	if !isUUID(id) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM dns_supermasters WHERE tenant_id = $1 AND id = $2`, tenantID, id))
	})
}

// ---------------------------------------------------------------- server config

func jsonOr(raw json.RawMessage) []byte {
	if len(raw) == 0 {
		return []byte("{}")
	}
	return raw
}

// GetServerConfig implements repo.ServerConfig.
func (d *DB) GetServerConfig(ctx context.Context) (store.ServerConfig, error) {
	var c store.ServerConfig
	err := d.system(ctx, func(tx pgx.Tx) error {
		var rec, auth []byte
		err := tx.QueryRow(ctx, `SELECT recursor, authoritative, recursor_hash, auth_hash, updated_by, updated_at FROM dns_server_config WHERE id = 1`).
			Scan(&rec, &auth, &c.RecursorHash, &c.AuthHash, &c.UpdatedBy, &c.UpdatedAt)
		c.Recursor, c.Authoritative = rec, auth
		return mapErr(err)
	})
	return c, err
}

// SaveServerConfig implements repo.ServerConfig (hashes are kept).
func (d *DB) SaveServerConfig(ctx context.Context, c store.ServerConfig) error {
	return d.system(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_server_config (id, recursor, authoritative, updated_by, updated_at) VALUES (1, $1, $2, $3, $4)
 ON CONFLICT (id) DO UPDATE SET recursor = EXCLUDED.recursor, authoritative = EXCLUDED.authoritative,
 updated_by = EXCLUDED.updated_by, updated_at = EXCLUDED.updated_at`,
			jsonOr(c.Recursor), jsonOr(c.Authoritative), c.UpdatedBy, orNow(c.UpdatedAt))
		return mapErr(err)
	})
}

// SetConfigHashes implements repo.ServerConfig.
func (d *DB) SetConfigHashes(ctx context.Context, recursorHash, authHash string, at time.Time) error {
	return d.system(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_server_config (id, recursor_hash, auth_hash, updated_at) VALUES (1, $1, $2, $3)
 ON CONFLICT (id) DO UPDATE SET recursor_hash = EXCLUDED.recursor_hash, auth_hash = EXCLUDED.auth_hash`,
			recursorHash, authHash, orNow(at))
		return mapErr(err)
	})
}

// ---------------------------------------------------------------- ipam sync

const syncCols = `tenant_id, ip_address_id, host(address), hostname, forward_zone_id, forward_name, forward_type,
 reverse_zone_id, reverse_name, last_event, updated_at`

// GetIPAMSync implements repo.IPAMSync.
func (d *DB) GetIPAMSync(ctx context.Context, tenantID, ipAddressID string) (store.IPAMSync, error) {
	var s store.IPAMSync
	err := d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		var fz, rz *string
		err := tx.QueryRow(ctx, `SELECT `+syncCols+` FROM dns_ipam_sync WHERE tenant_id = $1 AND ip_address_id = $2`, tenantID, ipAddressID).
			Scan(&s.TenantID, &s.IPAddressID, &s.Address, &s.Hostname, &fz, &s.ForwardName, &s.ForwardType, &rz, &s.ReverseName, &s.LastEvent, &s.UpdatedAt)
		s.ForwardZoneID, s.ReverseZoneID = deref(fz), deref(rz)
		return mapErr(err)
	})
	return s, err
}

func nullUUID(s string) *string {
	if !isUUID(s) {
		return nil
	}
	return &s
}

// UpsertIPAMSync implements repo.IPAMSync.
func (d *DB) UpsertIPAMSync(ctx context.Context, s store.IPAMSync) error {
	ip := canonIP(s.Address)
	if ip == "" || s.IPAddressID == "" {
		return repo.ErrConflict // mirrors memstore; callers validate first
	}
	if s.LastEvent == "" {
		s.LastEvent = store.SyncCreated
	}
	return d.tenant(ctx, s.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_ipam_sync (tenant_id, ip_address_id, address, hostname, forward_zone_id, forward_name, forward_type,
 reverse_zone_id, reverse_name, last_event, updated_at) VALUES ($1,$2,$3::inet,$4,$5,$6,$7,$8,$9,$10,$11)
 ON CONFLICT (tenant_id, ip_address_id) DO UPDATE SET address = EXCLUDED.address, hostname = EXCLUDED.hostname,
 forward_zone_id = EXCLUDED.forward_zone_id, forward_name = EXCLUDED.forward_name, forward_type = EXCLUDED.forward_type,
 reverse_zone_id = EXCLUDED.reverse_zone_id, reverse_name = EXCLUDED.reverse_name, last_event = EXCLUDED.last_event,
 updated_at = EXCLUDED.updated_at`,
			s.TenantID, s.IPAddressID, ip, s.Hostname, nullUUID(s.ForwardZoneID), s.ForwardName, s.ForwardType,
			nullUUID(s.ReverseZoneID), s.ReverseName, s.LastEvent, orNow(s.UpdatedAt))
		return mapErr(err)
	})
}

// DeleteIPAMSync implements repo.IPAMSync.
func (d *DB) DeleteIPAMSync(ctx context.Context, tenantID, ipAddressID string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM dns_ipam_sync WHERE tenant_id = $1 AND ip_address_id = $2`, tenantID, ipAddressID))
	})
}

// ClearSyncZone implements repo.IPAMSync.
func (d *DB) ClearSyncZone(ctx context.Context, tenantID, zoneID string) error {
	if !isUUID(zoneID) {
		return nil
	}
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		if _, err := tx.Exec(ctx, `UPDATE dns_ipam_sync SET forward_zone_id = NULL, forward_name = '', forward_type = ''
 WHERE tenant_id = $1 AND forward_zone_id = $2`, tenantID, zoneID); err != nil {
			return mapErr(err)
		}
		_, err := tx.Exec(ctx, `UPDATE dns_ipam_sync SET reverse_zone_id = NULL, reverse_name = ''
 WHERE tenant_id = $1 AND reverse_zone_id = $2`, tenantID, zoneID)
		return mapErr(err)
	})
}

// ---------------------------------------------------------------- challenges

const challengeCols = `id, tenant_id, zone_id, fqdn, value, requested_by, created_at`

// InsertChallenge implements repo.Challenges.
func (d *DB) InsertChallenge(ctx context.Context, c store.Challenge) error {
	if !isUUID(c.ZoneID) {
		return repo.ErrNotFound
	}
	return d.tenant(ctx, c.TenantID, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_acme_challenges (`+challengeCols+`) VALUES ($1,$2,$3,$4,$5,$6,$7)`,
			c.ID, c.TenantID, c.ZoneID, c.FQDN, c.Value, c.RequestedBy, orNow(c.CreatedAt))
		return mapErr(err)
	})
}

// DeleteChallenge implements repo.Challenges.
func (d *DB) DeleteChallenge(ctx context.Context, tenantID, fqdn, value string) error {
	return d.tenant(ctx, tenantID, func(tx pgx.Tx) error {
		return affected(tx.Exec(ctx, `DELETE FROM dns_acme_challenges WHERE tenant_id = $1 AND fqdn = $2 AND value = $3`, tenantID, fqdn, value))
	})
}

// ChallengesOlderThan implements repo.Challenges (system scope: the sweeper).
func (d *DB) ChallengesOlderThan(ctx context.Context, before time.Time, limit int) ([]store.Challenge, error) {
	if limit <= 0 {
		limit = 1000
	}
	out := []store.Challenge{}
	err := d.system(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT `+challengeCols+` FROM dns_acme_challenges WHERE created_at < $1 ORDER BY created_at, id LIMIT $2`, before, limit)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var c store.Challenge
			if err := rows.Scan(&c.ID, &c.TenantID, &c.ZoneID, &c.FQDN, &c.Value, &c.RequestedBy, &c.CreatedAt); err != nil {
				return err
			}
			out = append(out, c)
		}
		return rows.Err()
	})
	return out, err
}

// ---------------------------------------------------------------- backup + audit

// AllTemplates implements repo.Backup.
func (d *DB) AllTemplates(ctx context.Context, tenantID string) ([]store.Template, error) {
	return d.ListTemplates(ctx, tenantID)
}

// AllSupermasters implements repo.Backup.
func (d *DB) AllSupermasters(ctx context.Context, tenantID string) ([]store.Supermaster, error) {
	return d.ListSupermasters(ctx, tenantID)
}

// TenantIDs implements repo.Backup (system scope).
func (d *DB) TenantIDs(ctx context.Context) ([]string, error) {
	out := []string{}
	err := d.system(ctx, func(tx pgx.Tx) error {
		rows, err := tx.Query(ctx, `SELECT DISTINCT t::text FROM (
 SELECT tenant_id AS t FROM dns_zones UNION SELECT tenant_id FROM dns_zone_templates UNION SELECT tenant_id FROM dns_supermasters) s ORDER BY 1`)
		if err != nil {
			return mapErr(err)
		}
		defer rows.Close()
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				return err
			}
			out = append(out, id)
		}
		return rows.Err()
	})
	return out, err
}

// AppendAudit implements repo.Store (system scope; platform events use the nil tenant).
func (d *DB) AppendAudit(ctx context.Context, row store.AuditRow) error {
	var detail []byte
	if row.Detail != nil {
		detail, _ = json.Marshal(row.Detail) // redacted plain values: marshalling cannot fail
	}
	tenant := row.TenantID
	if tenant == "" {
		tenant = store.NilTenant
	}
	return d.system(ctx, func(tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `INSERT INTO dns_audit_events (id, tenant_id, at, actor_kind, actor_id, action, subject_kind, subject_id, outcome, reason, detail)
 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
			row.ID, tenant, orNow(row.At), row.ActorKind, row.ActorID, row.Action, row.SubjectKind, row.SubjectID, row.Outcome, row.Reason, detail)
		return mapErr(err)
	})
}
