package event

import (
	"context"
	"fmt"
	"net"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/internal/data"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	entZone "github.com/go-tangra/go-tangra-dns/internal/data/ent/zone"
	"github.com/go-tangra/go-tangra-dns/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/internal/recursor"
)

const defaultRecordTTL = 3600

// Handler reacts to IPAM events by maintaining DNS zones/records.
type Handler struct {
	log         *log.Helper
	zoneRepo    *data.ZoneRepo
	pdnsCli     *pdns.Client
	recursorCli *recursor.Client
}

// NewHandler builds the event handler.
func NewHandler(ctx *bootstrap.Context, zoneRepo *data.ZoneRepo, pdnsCli *pdns.Client, recursorCli *recursor.Client) *Handler {
	return &Handler{
		log:         ctx.NewLoggerHelper("dns/event/handler"),
		zoneRepo:    zoneRepo,
		pdnsCli:     pdnsCli,
		recursorCli: recursorCli,
	}
}

// HandleIPAddressCreated ensures a zone exists for the IP's hostname and
// upserts a forward A record plus a reverse PTR record. No-op when the IP
// has no hostname or the address is not a valid IPv4.
func (h *Handler) HandleIPAddressCreated(ctx context.Context, d *IPAddressData) error {
	host := canonHost(d.Hostname)
	if host == "" {
		return nil // gating: only act when a hostname is present
	}

	parsed := net.ParseIP(d.Address)
	if parsed == nil || parsed.To4() == nil {
		h.log.Infof("skipping %s: %q is not an IPv4 address (A records only)", host, d.Address)
		return nil
	}
	ipv4 := parsed.To4().String()

	// Forward: ensure zone + A record.
	zone, err := h.findOrCreateZone(ctx, d.TenantID, host)
	if err != nil {
		return fmt.Errorf("ensure zone for %s: %w", host, err)
	}
	aRR := pdns.RRset{
		Name:       host + ".",
		Type:       "A",
		TTL:        defaultRecordTTL,
		ChangeType: "REPLACE",
		Records:    []pdns.RRsetRecord{{Content: ipv4}},
	}
	if err := h.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{aRR}); err != nil {
		return fmt.Errorf("upsert A %s -> %s in zone %s: %w", host, ipv4, zone.Name, err)
	}
	h.log.Infof("auto-created A record %s -> %s in zone %s (tenant %d)", host, ipv4, zone.Name, d.TenantID)

	// Reverse: ensure the /24 in-addr.arpa zone + PTR record. Best-effort —
	// a reverse failure must not undo the forward record.
	h.upsertPTR(ctx, d.TenantID, ipv4, host)
	return nil
}

// HandleIPAddressDeleted removes the forward A record and reverse PTR record
// that HandleIPAddressCreated would have created. Best-effort: missing zones
// or records are ignored, and zones themselves are never deleted.
func (h *Handler) HandleIPAddressDeleted(ctx context.Context, d *IPAddressData) error {
	host := canonHost(d.Hostname)
	parsed := net.ParseIP(d.Address)
	var ipv4 string
	if parsed != nil && parsed.To4() != nil {
		ipv4 = parsed.To4().String()
	}

	// Forward: delete the A record from the owning zone (if any).
	if host != "" {
		if zone, err := h.findZone(ctx, d.TenantID, host); err != nil {
			h.log.Warnf("lookup zone for %s: %v", host, err)
		} else if zone != nil {
			rr := pdns.RRset{Name: host + ".", Type: "A", ChangeType: "DELETE"}
			if err := h.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{rr}); err != nil {
				h.log.Warnf("delete A %s in zone %s: %v", host, zone.Name, err)
			} else {
				h.log.Infof("removed A record %s from zone %s (tenant %d)", host, zone.Name, d.TenantID)
			}
		}
	}

	// Reverse: delete the PTR record from the in-addr.arpa zone (if any).
	if ipv4 != "" {
		revZone := reverseZoneName(ipv4)
		if zone, err := h.findZone(ctx, d.TenantID, strings.TrimSuffix(revZone, ".")); err != nil {
			h.log.Warnf("lookup reverse zone %s: %v", revZone, err)
		} else if zone != nil {
			rr := pdns.RRset{Name: reverseName(ipv4), Type: "PTR", ChangeType: "DELETE"}
			if err := h.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{rr}); err != nil {
				h.log.Warnf("delete PTR %s in zone %s: %v", reverseName(ipv4), zone.Name, err)
			} else {
				h.log.Infof("removed PTR record %s from zone %s (tenant %d)", reverseName(ipv4), zone.Name, d.TenantID)
			}
		}
	}
	return nil
}

// upsertPTR ensures the reverse /24 zone exists and upserts a PTR record.
func (h *Handler) upsertPTR(ctx context.Context, tenantID uint32, ipv4, host string) {
	revZone := reverseZoneName(ipv4)
	zone, err := h.ensureZone(ctx, tenantID, revZone)
	if err != nil {
		h.log.Warnf("ensure reverse zone %s: %v", revZone, err)
		return
	}
	rr := pdns.RRset{
		Name:       reverseName(ipv4),
		Type:       "PTR",
		TTL:        defaultRecordTTL,
		ChangeType: "REPLACE",
		Records:    []pdns.RRsetRecord{{Content: host + "."}},
	}
	if err := h.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{rr}); err != nil {
		h.log.Warnf("upsert PTR %s -> %s in zone %s: %v", reverseName(ipv4), host, zone.Name, err)
		return
	}
	h.log.Infof("auto-created PTR record %s -> %s in zone %s (tenant %d)", reverseName(ipv4), host, zone.Name, tenantID)
}

// findZone returns the longest existing managed zone (for the tenant) that
// is a suffix of host, or nil if none matches.
func (h *Handler) findZone(ctx context.Context, tenantID uint32, host string) (*ent.Zone, error) {
	zones, _, err := h.zoneRepo.List(ctx, tenantID, 0, 1000, "")
	if err != nil {
		return nil, fmt.Errorf("list zones: %w", err)
	}
	var best *ent.Zone
	bestLen := -1
	for _, z := range zones {
		zn := strings.ToLower(strings.TrimSuffix(z.Name, "."))
		if host == zn || strings.HasSuffix(host, "."+zn) {
			if len(zn) > bestLen {
				best, bestLen = z, len(zn)
			}
		}
	}
	return best, nil
}

// findOrCreateZone resolves the zone a host belongs to. It first reuses the
// longest existing managed zone that is a suffix of host (so for
// test.infra.verax.net it prefers infra.verax.net, then verax.net). If none
// exists, it creates the registrable domain — the last two labels, e.g.
// test.infra.verax.net -> verax.net — and uses that.
func (h *Handler) findOrCreateZone(ctx context.Context, tenantID uint32, host string) (*ent.Zone, error) {
	zone, err := h.findZone(ctx, tenantID, host)
	if err != nil {
		return nil, err
	}
	if zone != nil {
		return zone, nil
	}

	// No managed zone matches — create the registrable domain (eTLD+1),
	// i.e. the last two labels.
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return nil, fmt.Errorf("hostname %q has no parent domain", host)
	}
	zoneName := strings.Join(labels[len(labels)-2:], ".") + "."
	return h.ensureZone(ctx, tenantID, zoneName)
}

// canonHost lowercases and strips the trailing dot from a hostname.
func canonHost(h string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimSpace(h), "."))
}

// reverseName returns the in-addr.arpa PTR owner name for an IPv4 address,
// e.g. 10.77.88.99 -> "99.88.77.10.in-addr.arpa.".
func reverseName(ipv4 string) string {
	o := strings.Split(ipv4, ".")
	if len(o) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.%s.in-addr.arpa.", o[3], o[2], o[1], o[0])
}

// reverseZoneName returns the /24 reverse zone for an IPv4 address,
// e.g. 10.77.88.99 -> "88.77.10.in-addr.arpa.".
func reverseZoneName(ipv4 string) string {
	o := strings.Split(ipv4, ".")
	if len(o) != 4 {
		return ""
	}
	return fmt.Sprintf("%s.%s.%s.in-addr.arpa.", o[2], o[1], o[0])
}

// ensureZone creates the zone in PowerDNS (tolerating an already-existing
// zone) and persists the local metadata row.
func (h *Handler) ensureZone(ctx context.Context, tenantID uint32, zoneName string) (*ent.Zone, error) {
	created, err := h.pdnsCli.CreateZone(ctx, &pdns.Zone{Name: zoneName, Kind: "Native"})
	if err != nil {
		// The zone may already exist in PowerDNS (created out-of-band or a
		// previous partial run). Fall back to fetching it.
		existing, getErr := h.pdnsCli.GetZone(ctx, zoneName)
		if getErr != nil {
			return nil, fmt.Errorf("powerdns create zone %s: %w", zoneName, err)
		}
		created = existing
	}

	pdnsID := created.ID
	if pdnsID == "" {
		pdnsID = zoneName
	}

	// Reuse an existing local row if one already maps to this pdns zone.
	if existing, _ := h.zoneRepo.GetByPdnsID(ctx, tenantID, pdnsID); existing != nil {
		h.syncRecursor(ctx, zoneName)
		return existing, nil
	}

	row := &ent.Zone{
		ID:          uuid.NewString(),
		TenantID:    &tenantID,
		PdnsID:      pdnsID,
		Name:        zoneName,
		Kind:        entZone.KindNATIVE,
		Description: "auto-created from IPAM ip_address.created event",
	}
	saved, err := h.zoneRepo.Create(ctx, row)
	if err != nil {
		return nil, fmt.Errorf("persist zone %s: %w", zoneName, err)
	}
	h.log.Infof("auto-created zone %s (tenant %d)", zoneName, tenantID)
	h.syncRecursor(ctx, zoneName)
	return saved, nil
}

// syncRecursor points the recursor's forward entry for zoneName at the
// authoritative server. Best-effort — failures are logged, not fatal.
func (h *Handler) syncRecursor(ctx context.Context, zoneName string) {
	if h.recursorCli == nil {
		return
	}
	if err := h.recursorCli.SyncForwardZone(ctx, zoneName); err != nil {
		h.log.Warnf("recursor forward sync failed for %s: %v", zoneName, err)
	}
}
