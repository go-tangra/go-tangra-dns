// Package memstore is an in-memory repo.Store for the DNS module, used by
// offline tests and local development. It filters by tenant (mirroring RLS),
// enforces every unique guard of the schema — GLOBAL zone name and PowerDNS id,
// GLOBAL supermaster (ip, nameserver), per-tenant case-insensitive template
// name, per-tenant (fqdn, value) challenges — answers the overlap question with
// the same semantics as the dns_zone_conflict SQL function, cascades challenge
// rows on zone delete, and offers per-method error injection via FailNext.
package memstore

import (
	"context"
	"encoding/json"
	"net/netip"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/store"
)

// injectedErr is the error FailNext arms for a given method.
type injectedErr struct{ method string }

func (e injectedErr) Error() string { return "memstore: injected failure in " + e.method }

// Mem is an in-memory store. It is safe for concurrent use.
type Mem struct {
	mu sync.Mutex

	zones        map[string]store.Zone
	templates    map[string]store.Template
	supermasters map[string]store.Supermaster
	config       *store.ServerConfig
	sync         map[string]store.IPAMSync // tenant|address id
	challenges   map[string]store.Challenge
	audit        []store.AuditRow

	failNext map[string]bool
	// Now is the clock used for defaults (overridable in tests).
	Now func() time.Time
}

var _ repo.Store = (*Mem)(nil)

// New builds an empty store.
func New() *Mem {
	return &Mem{
		zones:        map[string]store.Zone{},
		templates:    map[string]store.Template{},
		supermasters: map[string]store.Supermaster{},
		sync:         map[string]store.IPAMSync{},
		challenges:   map[string]store.Challenge{},
		failNext:     map[string]bool{},
		Now:          func() time.Time { return time.Now().UTC() },
	}
}

// FailNext arms the next call to the named method to return an injected error.
func (m *Mem) FailNext(method string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.failNext[method] = true
}

// fail reports (and disarms) an injected failure for method. Callers hold mu.
func (m *Mem) fail(method string) error {
	if m.failNext[method] {
		delete(m.failNext, method)
		return injectedErr{method}
	}
	return nil
}

// Audit returns a copy of the appended audit rows (tests).
func (m *Mem) Audit() []store.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.AuditRow(nil), m.audit...)
}

// Close is a no-op for the in-memory store.
func (m *Mem) Close() {}

func orNow(t, now time.Time) time.Time {
	if t.IsZero() {
		return now
	}
	return t
}

func strs(v []string) []string {
	out := make([]string, len(v))
	copy(out, v)
	return out
}

func cloneZone(z store.Zone) store.Zone {
	z.Masters = strs(z.Masters)
	z.Nameservers = strs(z.Nameservers)
	return z
}

// ---------------------------------------------------------------- zones

// CreateZone implements repo.Zones.
func (m *Mem) CreateZone(_ context.Context, z store.Zone) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateZone"); err != nil {
		return err
	}
	if _, dup := m.zones[z.ID]; dup {
		return repo.ErrConflict
	}
	for _, x := range m.zones {
		if x.Name == z.Name || x.PDNSID == z.PDNSID {
			return repo.ErrConflict
		}
	}
	now := m.Now()
	z.CreatedAt = orNow(z.CreatedAt, now)
	z.UpdatedAt = orNow(z.UpdatedAt, z.CreatedAt)
	if z.Kind == "" {
		z.Kind = store.KindNative
	}
	if z.Origin == "" {
		z.Origin = store.OriginManual
	}
	m.zones[z.ID] = cloneZone(z)
	return nil
}

func (m *Mem) zone(tenantID, id string) (store.Zone, error) {
	z, ok := m.zones[id]
	if !ok || z.TenantID != tenantID {
		return store.Zone{}, repo.ErrNotFound
	}
	return z, nil
}

// GetZone implements repo.Zones.
func (m *Mem) GetZone(_ context.Context, tenantID, id string) (store.Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetZone"); err != nil {
		return store.Zone{}, err
	}
	z, err := m.zone(tenantID, id)
	return cloneZone(z), err
}

// GetZoneByName implements repo.Zones.
func (m *Mem) GetZoneByName(_ context.Context, tenantID, name string) (store.Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetZoneByName"); err != nil {
		return store.Zone{}, err
	}
	for _, z := range m.zones {
		if z.TenantID == tenantID && z.Name == name {
			return cloneZone(z), nil
		}
	}
	return store.Zone{}, repo.ErrNotFound
}

func (m *Mem) tenantZones(tenantID string) []store.Zone {
	var out []store.Zone
	for _, z := range m.zones {
		if z.TenantID == tenantID {
			out = append(out, cloneZone(z))
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// ListZones implements repo.Zones.
func (m *Mem) ListZones(_ context.Context, tenantID string, f store.ZoneFilter) ([]store.Zone, int64, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListZones"); err != nil {
		return nil, 0, err
	}
	f = f.Normalized(0)
	matched := []store.Zone{}
	for _, z := range m.tenantZones(tenantID) {
		if f.Matches(z) {
			matched = append(matched, z)
		}
	}
	total := int64(len(matched))
	lo := min(f.Offset(), len(matched))
	hi := min(lo+f.PageSize, len(matched))
	return matched[lo:hi], total, nil
}

// UpdateZone implements repo.Zones.
func (m *Mem) UpdateZone(_ context.Context, z store.Zone) (store.Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateZone"); err != nil {
		return store.Zone{}, err
	}
	cur, err := m.zone(z.TenantID, z.ID)
	if err != nil {
		return store.Zone{}, err
	}
	cur.Kind, cur.Masters, cur.DNSSEC, cur.Description = z.Kind, strs(z.Masters), z.DNSSEC, z.Description
	cur.UpdatedAt = orNow(z.UpdatedAt, m.Now())
	m.zones[cur.ID] = cur
	return cloneZone(cur), nil
}

// DeleteZone implements repo.Zones.
func (m *Mem) DeleteZone(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteZone"); err != nil {
		return err
	}
	if _, err := m.zone(tenantID, id); err != nil {
		return err
	}
	delete(m.zones, id)
	for k, c := range m.challenges { // ON DELETE CASCADE
		if c.TenantID == tenantID && c.ZoneID == id {
			delete(m.challenges, k)
		}
	}
	return nil
}

// Overlaps reports whether canonical names a and b are equal or one contains
// the other (the dns_zone_conflict predicate).
func Overlaps(a, b string) bool {
	return a == b || strings.HasSuffix(a, "."+b) || strings.HasSuffix(b, "."+a)
}

// ZoneConflict implements repo.Zones.
func (m *Mem) ZoneConflict(_ context.Context, tenantID, name string) (bool, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ZoneConflict"); err != nil {
		return false, err
	}
	name = strings.ToLower(name)
	for _, z := range m.zones {
		if z.TenantID != tenantID && Overlaps(name, z.Name) {
			return true, nil
		}
	}
	return false, nil
}

// AllZoneNames implements repo.Zones.
func (m *Mem) AllZoneNames(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AllZoneNames"); err != nil {
		return nil, err
	}
	out := []string{}
	for _, z := range m.zones {
		out = append(out, z.Name)
	}
	sort.Strings(out)
	return out, nil
}

// ZonesForTenant implements repo.Zones.
func (m *Mem) ZonesForTenant(_ context.Context, tenantID string) ([]store.Zone, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ZonesForTenant"); err != nil {
		return nil, err
	}
	out := m.tenantZones(tenantID)
	if out == nil {
		out = []store.Zone{}
	}
	return out, nil
}

// ---------------------------------------------------------------- templates

func cloneTemplate(t store.Template) store.Template {
	recs := make([]store.TemplateRecord, len(t.Records))
	copy(recs, t.Records)
	t.Records = recs
	return t
}

func (m *Mem) templateNameTaken(t store.Template) bool {
	for _, x := range m.templates {
		if x.TenantID == t.TenantID && x.ID != t.ID && strings.EqualFold(x.Name, t.Name) {
			return true
		}
	}
	return false
}

// CreateTemplate implements repo.Templates.
func (m *Mem) CreateTemplate(_ context.Context, t store.Template) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateTemplate"); err != nil {
		return err
	}
	if _, dup := m.templates[t.ID]; dup || m.templateNameTaken(t) {
		return repo.ErrConflict
	}
	now := m.Now()
	t.CreatedAt = orNow(t.CreatedAt, now)
	t.UpdatedAt = orNow(t.UpdatedAt, t.CreatedAt)
	m.templates[t.ID] = cloneTemplate(t)
	return nil
}

func (m *Mem) template(tenantID, id string) (store.Template, error) {
	t, ok := m.templates[id]
	if !ok || t.TenantID != tenantID {
		return store.Template{}, repo.ErrNotFound
	}
	return t, nil
}

// GetTemplate implements repo.Templates.
func (m *Mem) GetTemplate(_ context.Context, tenantID, id string) (store.Template, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetTemplate"); err != nil {
		return store.Template{}, err
	}
	t, err := m.template(tenantID, id)
	return cloneTemplate(t), err
}

func (m *Mem) tenantTemplates(tenantID string) []store.Template {
	out := []store.Template{}
	for _, t := range m.templates {
		if t.TenantID == tenantID {
			out = append(out, cloneTemplate(t))
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := strings.ToLower(out[i].Name), strings.ToLower(out[j].Name)
		if a != b {
			return a < b
		}
		return out[i].ID < out[j].ID
	})
	return out
}

// ListTemplates implements repo.Templates.
func (m *Mem) ListTemplates(_ context.Context, tenantID string) ([]store.Template, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListTemplates"); err != nil {
		return nil, err
	}
	return m.tenantTemplates(tenantID), nil
}

// UpdateTemplate implements repo.Templates.
func (m *Mem) UpdateTemplate(_ context.Context, t store.Template) (store.Template, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpdateTemplate"); err != nil {
		return store.Template{}, err
	}
	cur, err := m.template(t.TenantID, t.ID)
	if err != nil {
		return store.Template{}, err
	}
	if m.templateNameTaken(t) {
		return store.Template{}, repo.ErrConflict
	}
	cur.Name, cur.Description, cur.Records = t.Name, t.Description, t.Records
	cur.UpdatedAt = orNow(t.UpdatedAt, m.Now())
	cur = cloneTemplate(cur)
	m.templates[cur.ID] = cur
	return cloneTemplate(cur), nil
}

// DeleteTemplate implements repo.Templates.
func (m *Mem) DeleteTemplate(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteTemplate"); err != nil {
		return err
	}
	if _, err := m.template(tenantID, id); err != nil {
		return err
	}
	delete(m.templates, id)
	return nil
}

// ---------------------------------------------------------------- supermasters

// canonIP renders an IP literal the way the inet column does ("" when invalid).
func canonIP(s string) string {
	a, err := netip.ParseAddr(s)
	if err != nil {
		return ""
	}
	return a.Unmap().String()
}

// CreateSupermaster implements repo.Supermasters.
func (m *Mem) CreateSupermaster(_ context.Context, s store.Supermaster) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("CreateSupermaster"); err != nil {
		return err
	}
	ip := canonIP(s.IP)
	if ip == "" {
		return repo.ErrConflict // the inet column refuses it; callers validate first
	}
	if _, dup := m.supermasters[s.ID]; dup {
		return repo.ErrConflict
	}
	for _, x := range m.supermasters {
		if x.IP == ip && x.Nameserver == s.Nameserver {
			return repo.ErrConflict
		}
	}
	s.IP = ip
	s.CreatedAt = orNow(s.CreatedAt, m.Now())
	m.supermasters[s.ID] = s
	return nil
}

// GetSupermaster implements repo.Supermasters.
func (m *Mem) GetSupermaster(_ context.Context, tenantID, id string) (store.Supermaster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetSupermaster"); err != nil {
		return store.Supermaster{}, err
	}
	s, ok := m.supermasters[id]
	if !ok || s.TenantID != tenantID {
		return store.Supermaster{}, repo.ErrNotFound
	}
	return s, nil
}

func (m *Mem) tenantSupermasters(tenantID string) []store.Supermaster {
	out := []store.Supermaster{}
	for _, s := range m.supermasters {
		if s.TenantID == tenantID {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool { // inet order, then name (the SQL ORDER BY)
		a, b := netip.MustParseAddr(out[i].IP), netip.MustParseAddr(out[j].IP)
		if c := a.Compare(b); c != 0 {
			return c < 0
		}
		return out[i].Nameserver < out[j].Nameserver
	})
	return out
}

// ListSupermasters implements repo.Supermasters.
func (m *Mem) ListSupermasters(_ context.Context, tenantID string) ([]store.Supermaster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ListSupermasters"); err != nil {
		return nil, err
	}
	return m.tenantSupermasters(tenantID), nil
}

// DeleteSupermaster implements repo.Supermasters.
func (m *Mem) DeleteSupermaster(_ context.Context, tenantID, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteSupermaster"); err != nil {
		return err
	}
	s, ok := m.supermasters[id]
	if !ok || s.TenantID != tenantID {
		return repo.ErrNotFound
	}
	delete(m.supermasters, id)
	return nil
}

// ---------------------------------------------------------------- server config

func jsonOr(raw json.RawMessage) json.RawMessage {
	if len(raw) == 0 {
		return json.RawMessage("{}")
	}
	return append(json.RawMessage(nil), raw...)
}

// GetServerConfig implements repo.ServerConfig.
func (m *Mem) GetServerConfig(_ context.Context) (store.ServerConfig, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetServerConfig"); err != nil {
		return store.ServerConfig{}, err
	}
	if m.config == nil {
		return store.ServerConfig{}, repo.ErrNotFound
	}
	c := *m.config
	c.Recursor, c.Authoritative = jsonOr(c.Recursor), jsonOr(c.Authoritative)
	return c, nil
}

// SaveServerConfig implements repo.ServerConfig.
func (m *Mem) SaveServerConfig(_ context.Context, c store.ServerConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("SaveServerConfig"); err != nil {
		return err
	}
	next := store.ServerConfig{Recursor: jsonOr(c.Recursor), Authoritative: jsonOr(c.Authoritative),
		UpdatedBy: c.UpdatedBy, UpdatedAt: orNow(c.UpdatedAt, m.Now())}
	if m.config != nil {
		next.RecursorHash, next.AuthHash = m.config.RecursorHash, m.config.AuthHash
	}
	m.config = &next
	return nil
}

// SetConfigHashes implements repo.ServerConfig.
func (m *Mem) SetConfigHashes(_ context.Context, recursorHash, authHash string, at time.Time) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("SetConfigHashes"); err != nil {
		return err
	}
	if m.config == nil {
		m.config = &store.ServerConfig{Recursor: jsonOr(nil), Authoritative: jsonOr(nil), UpdatedAt: orNow(at, m.Now())}
	}
	m.config.RecursorHash, m.config.AuthHash = recursorHash, authHash
	return nil
}

// ---------------------------------------------------------------- ipam sync

func syncKey(tenantID, id string) string { return tenantID + "|" + id }

// GetIPAMSync implements repo.IPAMSync.
func (m *Mem) GetIPAMSync(_ context.Context, tenantID, ipAddressID string) (store.IPAMSync, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("GetIPAMSync"); err != nil {
		return store.IPAMSync{}, err
	}
	s, ok := m.sync[syncKey(tenantID, ipAddressID)]
	if !ok {
		return store.IPAMSync{}, repo.ErrNotFound
	}
	return s, nil
}

// UpsertIPAMSync implements repo.IPAMSync.
func (m *Mem) UpsertIPAMSync(_ context.Context, s store.IPAMSync) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("UpsertIPAMSync"); err != nil {
		return err
	}
	ip := canonIP(s.Address)
	if ip == "" || s.IPAddressID == "" {
		return repo.ErrConflict // the schema refuses it; callers validate first
	}
	s.Address = ip
	if s.LastEvent == "" {
		s.LastEvent = store.SyncCreated
	}
	s.UpdatedAt = orNow(s.UpdatedAt, m.Now())
	m.sync[syncKey(s.TenantID, s.IPAddressID)] = s
	return nil
}

// DeleteIPAMSync implements repo.IPAMSync.
func (m *Mem) DeleteIPAMSync(_ context.Context, tenantID, ipAddressID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteIPAMSync"); err != nil {
		return err
	}
	k := syncKey(tenantID, ipAddressID)
	if _, ok := m.sync[k]; !ok {
		return repo.ErrNotFound
	}
	delete(m.sync, k)
	return nil
}

// ClearSyncZone implements repo.IPAMSync.
func (m *Mem) ClearSyncZone(_ context.Context, tenantID, zoneID string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ClearSyncZone"); err != nil {
		return err
	}
	for k, s := range m.sync {
		if s.TenantID != tenantID {
			continue
		}
		if s.ForwardZoneID == zoneID {
			s.ForwardZoneID, s.ForwardName, s.ForwardType = "", "", ""
		}
		if s.ReverseZoneID == zoneID {
			s.ReverseZoneID, s.ReverseName = "", ""
		}
		m.sync[k] = s
	}
	return nil
}

// ---------------------------------------------------------------- challenges

// InsertChallenge implements repo.Challenges.
func (m *Mem) InsertChallenge(_ context.Context, c store.Challenge) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("InsertChallenge"); err != nil {
		return err
	}
	if _, err := m.zone(c.TenantID, c.ZoneID); err != nil {
		return repo.ErrNotFound // composite FK: the zone must exist in the tenant
	}
	if _, dup := m.challenges[c.ID]; dup {
		return repo.ErrConflict
	}
	for _, x := range m.challenges {
		if x.TenantID == c.TenantID && x.FQDN == c.FQDN && x.Value == c.Value {
			return repo.ErrConflict
		}
	}
	c.CreatedAt = orNow(c.CreatedAt, m.Now())
	m.challenges[c.ID] = c
	return nil
}

// DeleteChallenge implements repo.Challenges.
func (m *Mem) DeleteChallenge(_ context.Context, tenantID, fqdn, value string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("DeleteChallenge"); err != nil {
		return err
	}
	for k, c := range m.challenges {
		if c.TenantID == tenantID && c.FQDN == fqdn && c.Value == value {
			delete(m.challenges, k)
			return nil
		}
	}
	return repo.ErrNotFound
}

// ChallengesOlderThan implements repo.Challenges.
func (m *Mem) ChallengesOlderThan(_ context.Context, before time.Time, limit int) ([]store.Challenge, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("ChallengesOlderThan"); err != nil {
		return nil, err
	}
	out := []store.Challenge{}
	for _, c := range m.challenges {
		if c.CreatedAt.Before(before) {
			out = append(out, c)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].CreatedAt.Before(out[j].CreatedAt)
		}
		return out[i].ID < out[j].ID
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// ---------------------------------------------------------------- backup + audit

// AllTemplates implements repo.Backup.
func (m *Mem) AllTemplates(_ context.Context, tenantID string) ([]store.Template, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AllTemplates"); err != nil {
		return nil, err
	}
	return m.tenantTemplates(tenantID), nil
}

// AllSupermasters implements repo.Backup.
func (m *Mem) AllSupermasters(_ context.Context, tenantID string) ([]store.Supermaster, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AllSupermasters"); err != nil {
		return nil, err
	}
	return m.tenantSupermasters(tenantID), nil
}

// TenantIDs implements repo.Backup.
func (m *Mem) TenantIDs(_ context.Context) ([]string, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("TenantIDs"); err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	for _, z := range m.zones {
		seen[z.TenantID] = true
	}
	for _, t := range m.templates {
		seen[t.TenantID] = true
	}
	for _, s := range m.supermasters {
		seen[s.TenantID] = true
	}
	out := []string{}
	for t := range seen {
		out = append(out, t)
	}
	sort.Strings(out)
	return out, nil
}

// AppendAudit implements repo.Store.
func (m *Mem) AppendAudit(_ context.Context, row store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if err := m.fail("AppendAudit"); err != nil {
		return err
	}
	m.audit = append(m.audit, row)
	return nil
}
