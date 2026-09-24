// Package store holds the DNS module's domain types, the embedded migrations
// and the pgx pool with tenant-scoped transactions. Record sets are not stored
// locally: PowerDNS is their source of truth (data-model.md).
package store

import (
	"encoding/json"
	"strings"
	"time"
)

// Zone kinds (PowerDNS Native|Master|Slave|Producer|Consumer, lower-cased).
const (
	KindNative   = "native"
	KindMaster   = "master"
	KindSlave    = "slave"
	KindProducer = "producer"
	KindConsumer = "consumer"
)

// Zone origins.
const (
	OriginManual = "manual"
	OriginIPAM   = "ipam"
)

// CreatedByIPAMSync is the created_by value of zones the IPAM sync creates.
const CreatedByIPAMSync = "ipam-sync"

// Sync events (dns_ipam_sync.last_event).
const (
	SyncCreated    = "created"
	SyncUpdated    = "updated"
	SyncScanned    = "scanned"
	SyncDeleted    = "deleted"
	SyncReconciled = "reconciled"
)

// Kinds lists every zone kind.
var Kinds = []string{KindNative, KindMaster, KindSlave, KindProducer, KindConsumer}

// ValidKind reports whether k is a known zone kind.
func ValidKind(k string) bool { return contains(Kinds, k) }

// ValidOrigin reports whether o is a known zone origin.
func ValidOrigin(o string) bool { return o == OriginManual || o == OriginIPAM }

// ValidSyncEvent reports whether e is a known sync event.
func ValidSyncEvent(e string) bool {
	return contains([]string{SyncCreated, SyncUpdated, SyncScanned, SyncDeleted, SyncReconciled}, e)
}

// NeedsMasters reports whether a zone of kind k takes its data from primaries
// (slave/consumer) and therefore requires masters.
func NeedsMasters(k string) bool { return k == KindSlave || k == KindConsumer }

// PDNSKind maps a kind to PowerDNS's capitalised spelling ("" for unknown).
func PDNSKind(k string) string {
	if !ValidKind(k) {
		return ""
	}
	return strings.ToUpper(k[:1]) + k[1:]
}

// KindFromPDNS maps PowerDNS's spelling back to a kind ("" for unknown).
func KindFromPDNS(k string) string {
	k = strings.ToLower(k)
	if !ValidKind(k) {
		return ""
	}
	return k
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if x == v {
			return true
		}
	}
	return false
}

// Zone is a tenant-owned zone on the shared PowerDNS Authoritative server.
// Name is canonical (lower-case, trailing dot, A-labels) and globally unique;
// PDNSID is the PowerDNS zone id used for every API call (never a
// caller-supplied name).
type Zone struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	Name        string    `json:"name"`
	PDNSID      string    `json:"-"`
	Kind        string    `json:"kind"`
	Masters     []string  `json:"masters"`
	DNSSEC      bool      `json:"dnssec"`
	Description string    `json:"description,omitempty"`
	TemplateID  string    `json:"template_id,omitempty"`
	Origin      string    `json:"origin"`
	Nameservers []string  `json:"nameservers"`
	CreatedBy   string    `json:"created_by,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// ZoneFilter selects a page of zones (name order). Query matches the name
// case-insensitively as a substring.
type ZoneFilter struct {
	Query    string
	Kind     string
	Origin   string
	Page     int // 1-based; <=0 means 1
	PageSize int // <=0 means 25
}

// Normalized returns the filter with paging defaults applied and the page size
// capped at max.
func (f ZoneFilter) Normalized(max int) ZoneFilter {
	f.Page, f.PageSize = normPage(f.Page, f.PageSize, max)
	return f
}

// Offset is the row offset of the page.
func (f ZoneFilter) Offset() int { return (f.Page - 1) * f.PageSize }

func normPage(page, size, max int) (int, int) {
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = 25
	}
	if max > 0 && size > max {
		size = max
	}
	return page, size
}

// Matches reports whether z passes the filter's query/kind/origin predicates.
func (f ZoneFilter) Matches(z Zone) bool {
	if f.Kind != "" && z.Kind != f.Kind {
		return false
	}
	if f.Origin != "" && z.Origin != f.Origin {
		return false
	}
	if q := strings.ToLower(strings.TrimSpace(f.Query)); q != "" && !strings.Contains(z.Name, q) {
		return false
	}
	return true
}

// InZone reports whether the canonical name equals zone or lies inside it.
func InZone(name, zone string) bool {
	return name == zone || strings.HasSuffix(name, "."+zone)
}

// LongestZone returns the longest zone of zones that equals or contains the
// canonical fqdn (ok=false when none does).
func LongestZone(zones []Zone, fqdn string) (Zone, bool) {
	var best Zone
	found := false
	for _, z := range zones {
		if InZone(fqdn, z.Name) && (!found || len(z.Name) > len(best.Name)) {
			best, found = z, true
		}
	}
	return best, found
}

// TemplateRecord is one record row of a zone template. Name and Content may
// carry the [ZONE] placeholder; Priority applies to MX/SRV.
type TemplateRecord struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      int    `json:"ttl"`
	Content  string `json:"content"`
	Priority int    `json:"priority,omitempty"`
}

// MaxTemplateRecords bounds a template's record list.
const MaxTemplateRecords = 200

// Template is a reusable record set for new zones. Name is unique per tenant
// (case-insensitive).
type Template struct {
	ID          string           `json:"id"`
	TenantID    string           `json:"tenant_id"`
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Records     []TemplateRecord `json:"records"`
	CreatedAt   time.Time        `json:"created_at"`
	UpdatedAt   time.Time        `json:"updated_at"`
}

// Supermaster is a primary allowed to auto-provision zones on the shared
// PowerDNS. (IP, Nameserver) is globally unique; the PowerDNS account is the
// tenant id.
type Supermaster struct {
	ID         string    `json:"id"`
	TenantID   string    `json:"tenant_id"`
	IP         string    `json:"ip"`
	Nameserver string    `json:"nameserver"`
	CreatedBy  string    `json:"created_by,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
}

// ServerConfig is the platform-scope single row: the typed configuration
// sections as JSON (the dnsconf model owns their shape) and the hashes of the
// last rendered files successfully written.
type ServerConfig struct {
	Recursor      json.RawMessage `json:"recursor"`
	Authoritative json.RawMessage `json:"authoritative"`
	RecursorHash  string          `json:"-"`
	AuthHash      string          `json:"-"`
	UpdatedBy     string          `json:"updated_by,omitempty"`
	UpdatedAt     time.Time       `json:"updated_at"`
}

// IPAMSync is what the IPAM sync last wrote for one IPAM address.
type IPAMSync struct {
	TenantID      string    `json:"tenant_id"`
	IPAddressID   string    `json:"ip_address_id"`
	Address       string    `json:"address"`
	Hostname      string    `json:"hostname"`
	ForwardZoneID string    `json:"forward_zone_id,omitempty"`
	ForwardName   string    `json:"forward_name,omitempty"`
	ForwardType   string    `json:"forward_type,omitempty"` // A | AAAA | ""
	ReverseZoneID string    `json:"reverse_zone_id,omitempty"`
	ReverseName   string    `json:"reverse_name,omitempty"`
	LastEvent     string    `json:"last_event"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// Challenge records one presented ACME DNS-01 TXT value (the token is public).
type Challenge struct {
	ID          string    `json:"id"`
	TenantID    string    `json:"tenant_id"`
	ZoneID      string    `json:"zone_id"`
	FQDN        string    `json:"fqdn"`
	Value       string    `json:"value"`
	RequestedBy string    `json:"requested_by"`
	CreatedAt   time.Time `json:"created_at"`
}

// AuditRow is an append-only audit event.
type AuditRow struct {
	ID          string
	TenantID    string
	At          time.Time
	ActorKind   string
	ActorID     string
	Action      string
	SubjectKind string
	SubjectID   string
	Outcome     string
	Reason      string
	Detail      map[string]any
}

// NilTenant is the tenant recorded for platform-scope audit events.
const NilTenant = "00000000-0000-0000-0000-000000000000"
