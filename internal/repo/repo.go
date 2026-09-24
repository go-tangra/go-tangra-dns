// Package repo defines the storage contract of the DNS module. Every
// tenant-scoped method runs under the tenant's RLS scope; the only cross-tenant
// operations are ZoneConflict and AllZoneNames (narrow SECURITY DEFINER
// functions returning a boolean / names only), the challenge sweeper listing,
// backup tenant enumeration, the platform-scope server configuration and audit
// appends.
package repo

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

// Sentinel errors every implementation maps its failures to.
var (
	ErrNotFound = errors.New("not found")
	ErrConflict = errors.New("conflict")
)

// Zones is the zone-ownership surface.
type Zones interface {
	// CreateZone inserts z; ErrConflict when the name or PowerDNS id is taken by
	// ANY tenant (global unique indexes).
	CreateZone(ctx context.Context, z store.Zone) error
	GetZone(ctx context.Context, tenantID, id string) (store.Zone, error)
	// GetZoneByName resolves a canonical zone name within the tenant.
	GetZoneByName(ctx context.Context, tenantID, name string) (store.Zone, error)
	// ListZones returns one page (name order) plus the total match count.
	ListZones(ctx context.Context, tenantID string, f store.ZoneFilter) ([]store.Zone, int64, error)
	// UpdateZone writes kind, masters, dnssec and description (and updated_at);
	// the stored zone is returned.
	UpdateZone(ctx context.Context, z store.Zone) (store.Zone, error)
	// DeleteZone removes the zone (its challenges cascade).
	DeleteZone(ctx context.Context, tenantID, id string) error
	// ZoneConflict reports whether a zone of ANOTHER tenant is equal to, an
	// ancestor of, or a descendant of name (boolean only — the owner is never
	// revealed). Same-tenant nesting is not a conflict.
	ZoneConflict(ctx context.Context, tenantID, name string) (bool, error)
	// AllZoneNames lists every managed zone name across tenants (recursor
	// reconciler; names only).
	AllZoneNames(ctx context.Context) ([]string, error)
	// ZonesForTenant lists all of the tenant's zones by name (longest-suffix
	// matching for IPAM sync and ACME challenges).
	ZonesForTenant(ctx context.Context, tenantID string) ([]store.Zone, error)
}

// Templates is the zone-template surface.
type Templates interface {
	// CreateTemplate inserts t; ErrConflict on (tenant, lower(name)).
	CreateTemplate(ctx context.Context, t store.Template) error
	GetTemplate(ctx context.Context, tenantID, id string) (store.Template, error)
	// ListTemplates lists the tenant's templates by name.
	ListTemplates(ctx context.Context, tenantID string) ([]store.Template, error)
	// UpdateTemplate writes name, description and records (replacing the list).
	UpdateTemplate(ctx context.Context, t store.Template) (store.Template, error)
	DeleteTemplate(ctx context.Context, tenantID, id string) error
}

// Supermasters is the supermaster surface (no update: delete and re-create).
type Supermasters interface {
	// CreateSupermaster inserts s; ErrConflict when (ip, nameserver) exists for
	// ANY tenant.
	CreateSupermaster(ctx context.Context, s store.Supermaster) error
	GetSupermaster(ctx context.Context, tenantID, id string) (store.Supermaster, error)
	// ListSupermasters lists the tenant's rows by (ip, nameserver).
	ListSupermasters(ctx context.Context, tenantID string) ([]store.Supermaster, error)
	DeleteSupermaster(ctx context.Context, tenantID, id string) error
}

// ServerConfig is the platform-scope configuration surface. Callers MUST have
// verified platform-admin authority (or run as the system scope).
type ServerConfig interface {
	// GetServerConfig returns the stored row; ErrNotFound when none was saved
	// (the defaults apply).
	GetServerConfig(ctx context.Context) (store.ServerConfig, error)
	// SaveServerConfig upserts the sections (hashes are kept).
	SaveServerConfig(ctx context.Context, c store.ServerConfig) error
	// SetConfigHashes records the hashes of the files last written successfully.
	SetConfigHashes(ctx context.Context, recursorHash, authHash string, at time.Time) error
}

// IPAMSync is the IPAM sync-state surface.
type IPAMSync interface {
	GetIPAMSync(ctx context.Context, tenantID, ipAddressID string) (store.IPAMSync, error)
	// UpsertIPAMSync inserts or replaces the row keyed by (tenant, address id).
	UpsertIPAMSync(ctx context.Context, s store.IPAMSync) error
	DeleteIPAMSync(ctx context.Context, tenantID, ipAddressID string) error
	// ClearSyncZone nulls every forward/reverse reference to a deleted zone
	// (the zone-delete path; zone deletion is never blocked by sync rows).
	ClearSyncZone(ctx context.Context, tenantID, zoneID string) error
}

// Challenges is the ACME DNS-01 bookkeeping surface.
type Challenges interface {
	// InsertChallenge records a presented value; ErrConflict on a duplicate
	// (tenant, fqdn, value); ErrNotFound when the zone is missing in the tenant.
	InsertChallenge(ctx context.Context, c store.Challenge) error
	// DeleteChallenge removes the (fqdn, value) row; ErrNotFound when absent.
	DeleteChallenge(ctx context.Context, tenantID, fqdn, value string) error
	// ChallengesOlderThan lists at most limit rows across tenants created
	// before the cut-off, oldest first (system scope: the sweeper).
	ChallengesOlderThan(ctx context.Context, before time.Time, limit int) ([]store.Challenge, error)
}

// Backup is the export iteration surface.
type Backup interface {
	AllTemplates(ctx context.Context, tenantID string) ([]store.Template, error)
	AllSupermasters(ctx context.Context, tenantID string) ([]store.Supermaster, error)
	// TenantIDs enumerates tenants holding DNS data (system scope; platform-admin backup).
	TenantIDs(ctx context.Context) ([]string, error)
}

// Store is the full DNS persistence contract.
type Store interface {
	Zones
	Templates
	Supermasters
	ServerConfig
	IPAMSync
	Challenges
	Backup
	// AppendAudit persists an audit row (system scope).
	AppendAudit(ctx context.Context, row store.AuditRow) error
}
