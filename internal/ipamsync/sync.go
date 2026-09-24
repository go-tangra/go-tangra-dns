package ipamsync

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/events"
	"github.com/go-tangra/go-tangra-dns/v4/internal/metrics"
	"github.com/go-tangra/go-tangra-dns/v4/internal/records"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

// ErrNotFound is IPAM's "no such address in this tenant" (treated as deleted).
var ErrNotFound = errors.New("ipamsync: address not found in IPAM")

// Address is IPAM's current state of one address (the only input the sync
// writes from).
type Address struct {
	ID       string
	Address  string
	SubnetID string
	Hostname string
}

// Subnet is the part of an IPAM subnet the reverse sizing needs.
type Subnet struct {
	ID   string
	CIDR string
}

// IPAM reads addresses and subnets of a tenant over SPIFFE mTLS
// (contracts §D; the ipamclient adapter satisfies it).
type IPAM interface {
	// GetAddress returns ErrNotFound when the address does not exist in the tenant.
	GetAddress(ctx context.Context, tenantID, id string) (Address, error)
	GetSubnet(ctx context.Context, tenantID, id string) (Subnet, error)
}

// Comment marks record sets written by the sync (the UI shows an "IPAM" hint).
const Comment = "managed by IPAM sync"

// Deps wire the syncer; every field but Audit, Metrics, Log and Now is required.
type Deps struct {
	Store   repo.Store
	Zones   *zones.Service
	Records *records.Service
	IPAM    IPAM
	Audit   audit.Recorder
	Metrics *metrics.Metrics
	TTL     int // record TTL (config ipam_sync.default_ttl)
	Log     *slog.Logger
	Now     func() time.Time
}

// Syncer applies IPAM address events to DNS.
type Syncer struct{ d Deps }

// New builds the syncer.
func New(d Deps) *Syncer {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.TTL <= 0 {
		d.TTL = 3600
	}
	return &Syncer{d: d}
}

func lastEvent(typ string) string {
	switch typ {
	case TypeUpdated:
		return store.SyncUpdated
	case TypeScanned:
		return store.SyncScanned
	case TypeDeleted:
		return store.SyncDeleted
	}
	return store.SyncCreated
}

// Handle re-reads the event's address from IPAM (the payload is never used
// for writes) and converges the tenant's DNS to it: upsert forward + PTR for
// an address with a host name, remove them when the host name was cleared or
// the address is gone. Only the event's tenant is touched.
func (s *Syncer) Handle(ctx context.Context, tenantID string, ev Event) error {
	if tenantID == "" || ev.ID == "" {
		return fmt.Errorf("%w: tenant and address id required", ErrMalformed)
	}
	subj := authz.SystemFor(tenantID)
	prev, err := s.d.Store.GetIPAMSync(ctx, tenantID, ev.ID)
	has := err == nil
	if err != nil && !errors.Is(err, repo.ErrNotFound) {
		return fmt.Errorf("ipam sync: state: %w", err)
	}
	addr, err := s.d.IPAM.GetAddress(ctx, tenantID, ev.ID)
	if errors.Is(err, ErrNotFound) {
		if !has {
			return nil // unknown or already removed: nothing of ours exists
		}
		return s.release(ctx, subj, prev)
	}
	if err != nil {
		s.d.Metrics.IPAMSync("read", metrics.ResultUnavailable)
		return fmt.Errorf("ipam sync: read address: %w", err)
	}
	ip, err := netip.ParseAddr(strings.TrimSpace(addr.Address))
	if err != nil || ip.Zone() != "" || addr.ID != ev.ID {
		s.d.Metrics.IPAMSync("read", metrics.ResultRefused)
		return fmt.Errorf("%w: IPAM returned an unusable address", ErrMalformed)
	}
	ip = ip.Unmap()
	host, ok := CanonicalHost(addr.Hostname)
	if !ok {
		if !has {
			s.d.Metrics.IPAMSync("skip", metrics.ResultSkipped)
			return nil // events without (usable) host names are ignored
		}
		return s.clear(ctx, subj, prev, lastEvent(ev.Type))
	}
	if !has {
		prev = store.IPAMSync{TenantID: tenantID, IPAddressID: ev.ID}
	}
	return s.upsert(ctx, subj, prev, ip, host, addr.SubnetID, lastEvent(ev.Type))
}

// upsert converges forward + reverse to (ip, host). Each side is recorded in
// the sync state only on success; a reverse failure never undoes the forward.
func (s *Syncer) upsert(ctx context.Context, subj authz.Subjects, prev store.IPAMSync, ip netip.Addr, host, subnetID, last string) error {
	all, err := s.d.Store.ZonesForTenant(ctx, subj.TenantID)
	if err != nil {
		return fmt.Errorf("ipam sync: zones: %w", err)
	}
	next := store.IPAMSync{TenantID: subj.TenantID, IPAddressID: prev.IPAddressID, Address: ip.String(), Hostname: host, LastEvent: last, UpdatedAt: s.d.Now()}
	var firstErr error
	note := func(err error) {
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}

	// Forward (A/AAAA): the address merged into the host's set.
	fw, ferr := PlanForward(all, host, ip)
	var fz store.Zone
	if ferr == nil {
		fz, ferr = s.zone(ctx, subj, fw.Existing, fw.ZoneID, fw.Zone)
	}
	moved := prev.ForwardName != "" && (ferr != nil || prev.ForwardZoneID != fz.ID || prev.ForwardName != fw.Name ||
		prev.ForwardType != fw.Type || prev.Address != next.Address)
	keep, ferr := s.side(ferr, moved, func() error {
		return s.removeValue(ctx, subj, prev.ForwardZoneID, prev.ForwardName, prev.ForwardType, prev.Address)
	}, func() error { return s.addValue(ctx, subj, fz, fw.Name, fw.Type, next.Address) }, note)
	switch {
	case ferr == nil:
		next.ForwardZoneID, next.ForwardName, next.ForwardType = fz.ID, fw.Name, fw.Type
	case keep:
		next.ForwardZoneID, next.ForwardName, next.ForwardType = prev.ForwardZoneID, prev.ForwardName, prev.ForwardType
	}
	if ferr != nil {
		s.outcome(ctx, subj, prev.IPAddressID, fw.Zone, host, fw.Type, ferr)
	}

	// Reverse (PTR): the subnet-sized reverse zone, or an existing one.
	prefix := -1
	if subnetID != "" {
		if sn, err := s.d.IPAM.GetSubnet(ctx, subj.TenantID, subnetID); err == nil {
			prefix = PrefixOf(sn.CIDR)
		} else {
			s.d.Log.WarnContext(ctx, "ipam sync: subnet lookup failed; default reverse size", "err", err)
		}
	}
	rv, rerr := PlanReverse(all, ip, prefix)
	var rz store.Zone
	if rerr == nil {
		rz, rerr = s.zone(ctx, subj, rv.Existing, rv.ZoneID, rv.Zone)
	}
	moved = prev.ReverseName != "" && (rerr != nil || prev.ReverseZoneID != rz.ID || prev.ReverseName != rv.Owner)
	keep, rerr = s.side(rerr, moved, func() error {
		return s.removeSet(ctx, subj, prev.ReverseZoneID, prev.ReverseName, "PTR")
	}, func() error { return s.setPTR(ctx, subj, rz, rv.Owner, host) }, note)
	switch {
	case rerr == nil:
		next.ReverseZoneID, next.ReverseName = rz.ID, rv.Owner
	case keep:
		next.ReverseZoneID, next.ReverseName = prev.ReverseZoneID, prev.ReverseName
	}
	if rerr != nil {
		s.outcome(ctx, subj, prev.IPAddressID, rv.Zone, rv.Owner, "PTR", rerr)
	}

	if err := s.d.Store.UpsertIPAMSync(ctx, next); err != nil {
		return fmt.Errorf("ipam sync: save state: %w", err)
	}
	if ferr == nil || rerr == nil {
		s.auditEvent(ctx, subj, audit.SyncUpsert, prev.IPAddressID, audit.OutcomeOK, "", next.ForwardName, next.ReverseName)
		s.d.Metrics.IPAMSync("upsert", metrics.ResultOK)
	}
	return firstErr
}

// permanent reports whether a planning/zone error means the address can no
// longer be written where it was (host unmanaged, zone of another tenant,
// secondary zone, invalid name) rather than a transient failure.
func permanent(err error) bool {
	return errors.Is(err, ErrSkip) || errors.Is(err, zones.ErrDuplicate) || errors.Is(err, zones.ErrInvalidKind) ||
		errors.Is(err, validate.ErrName) || errors.Is(err, validate.ErrRecord) || errors.Is(err, validate.ErrPublicSuffix)
}

// side runs one side's transition: when the record moved, the previous one
// is removed first — unless the new target failed transiently (the previous
// record stays and is kept in the state, keep=true) — and a failed removal
// also keeps it (retried on the next event) instead of writing the new one.
// keep is only meaningful when prev had a record on this side.
func (s *Syncer) side(planErr error, moved bool, remove, write func() error, note func(error)) (keep bool, err error) {
	if moved {
		if planErr != nil && !permanent(planErr) {
			return true, planErr
		}
		if rerr := remove(); rerr != nil {
			note(rerr)
			return true, rerr
		}
	}
	if planErr != nil {
		return false, planErr
	}
	// A transient write failure keeps the previous references: the record may
	// still exist and must stay reachable for the next event.
	err = write()
	return err != nil && !permanent(err), err
}

// clear removes both records of an address whose host name was cleared; the
// state row is kept with empty references until the address is deleted.
func (s *Syncer) clear(ctx context.Context, subj authz.Subjects, prev store.IPAMSync, last string) error {
	err := s.drop(ctx, subj, prev)
	next := store.IPAMSync{TenantID: prev.TenantID, IPAddressID: prev.IPAddressID, Address: prev.Address, LastEvent: last, UpdatedAt: s.d.Now()}
	if err != nil {
		next.ForwardZoneID, next.ForwardName, next.ForwardType = prev.ForwardZoneID, prev.ForwardName, prev.ForwardType
		next.ReverseZoneID, next.ReverseName = prev.ReverseZoneID, prev.ReverseName
	}
	if serr := s.d.Store.UpsertIPAMSync(ctx, next); serr != nil {
		return fmt.Errorf("ipam sync: save state: %w", serr)
	}
	return err
}

// release removes both records of a deleted address and its state row.
func (s *Syncer) release(ctx context.Context, subj authz.Subjects, prev store.IPAMSync) error {
	if err := s.drop(ctx, subj, prev); err != nil {
		return err
	}
	if err := s.d.Store.DeleteIPAMSync(ctx, prev.TenantID, prev.IPAddressID); err != nil && !errors.Is(err, repo.ErrNotFound) {
		return fmt.Errorf("ipam sync: delete state: %w", err)
	}
	return nil
}

// drop removes the forward value and the PTR recorded in prev (zones kept).
func (s *Syncer) drop(ctx context.Context, subj authz.Subjects, prev store.IPAMSync) error {
	var first error
	if prev.ForwardName != "" {
		first = s.removeValue(ctx, subj, prev.ForwardZoneID, prev.ForwardName, prev.ForwardType, prev.Address)
	}
	if prev.ReverseName != "" {
		if err := s.removeSet(ctx, subj, prev.ReverseZoneID, prev.ReverseName, "PTR"); err != nil && first == nil {
			first = err
		}
	}
	if first != nil {
		s.auditEvent(ctx, subj, audit.SyncDelete, prev.IPAddressID, audit.OutcomeError, "error", prev.ForwardName, prev.ReverseName)
		s.d.Metrics.IPAMSync("delete", metrics.ResultError)
		return first
	}
	if prev.ForwardName != "" || prev.ReverseName != "" {
		s.auditEvent(ctx, subj, audit.SyncDelete, prev.IPAddressID, audit.OutcomeOK, "", prev.ForwardName, prev.ReverseName)
		s.d.Metrics.IPAMSync("delete", metrics.ResultOK)
	}
	return nil
}

// zone loads an existing zone of the tenant or creates it (native, origin
// ipam). A name owned by / overlapping another tenant is zones.ErrDuplicate.
func (s *Syncer) zone(ctx context.Context, subj authz.Subjects, existing bool, id, name string) (store.Zone, error) {
	if existing {
		return s.d.Zones.Owned(ctx, subj, id)
	}
	z, err := s.d.Zones.Create(ctx, subj, zones.CreateInput{Name: name, Kind: store.KindNative, Origin: store.OriginIPAM})
	if errors.Is(err, zones.ErrDuplicate) {
		if own, e := s.d.Zones.ByName(ctx, subj, name); e == nil {
			return own, nil // created meanwhile in this tenant
		}
	}
	return z, err
}

func (s *Syncer) lookup(ctx context.Context, subj authz.Subjects, z store.Zone, name, typ string) (records.RecordSet, bool, error) {
	cur, err := s.d.Records.Lookup(ctx, subj, z, records.Key{Name: name, Type: typ})
	if errors.Is(err, records.ErrNotFound) {
		return records.RecordSet{}, false, nil
	}
	return cur, err == nil, err
}

func input(name, typ string, ttl uint32, values []string) validate.RecordSetInput {
	in := validate.RecordSetInput{Name: name, Type: typ, TTL: int(ttl), Comment: Comment}
	for _, v := range values {
		in.Values = append(in.Values, validate.RecordValue{Content: v})
	}
	return in
}

func contents(r records.RecordSet) []string {
	out := make([]string, 0, len(r.Values))
	for _, v := range r.Values {
		out = append(out, v.Content)
	}
	return out
}

// addValue merges value into the (name, typ) set (other addresses sharing
// the host name are kept); a set already holding it is left untouched.
func (s *Syncer) addValue(ctx context.Context, subj authz.Subjects, z store.Zone, name, typ, value string) error {
	cur, ok, err := s.lookup(ctx, subj, z, name, typ)
	if err != nil {
		return err
	}
	ttl := uint32(s.d.TTL) // #nosec G115 -- bounded by config validation
	vals := []string{}
	if ok {
		if slices.Contains(contents(cur), value) {
			return nil
		}
		ttl, vals = cur.TTL, contents(cur)
	}
	_, err = s.d.Records.Apply(ctx, subj, z, input(name, typ, ttl, append(vals, value)), events.SourceIPAM)
	return err
}

// removeValue takes value out of the (name, typ) set of zone id, deleting
// the set when it was the last value. A zone or set that no longer exists is
// fine.
func (s *Syncer) removeValue(ctx context.Context, subj authz.Subjects, zoneID, name, typ, value string) error {
	z, err := s.d.Zones.Owned(ctx, subj, zoneID)
	if errors.Is(err, zones.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	cur, ok, err := s.lookup(ctx, subj, z, name, typ)
	if err != nil || !ok {
		return err
	}
	rest := slices.DeleteFunc(contents(cur), func(v string) bool { return v == value })
	if len(rest) == len(cur.Values) {
		return nil
	}
	if len(rest) == 0 {
		return s.d.Records.Remove(ctx, subj, z, records.Key{Name: name, Type: typ}, events.SourceIPAM)
	}
	in := input(name, typ, cur.TTL, rest)
	in.Comment = cur.Comment
	_, err = s.d.Records.Apply(ctx, subj, z, in, events.SourceIPAM)
	return err
}

// removeSet deletes the (name, typ) set of zone id (PTR owners are per address).
func (s *Syncer) removeSet(ctx context.Context, subj authz.Subjects, zoneID, name, typ string) error {
	z, err := s.d.Zones.Owned(ctx, subj, zoneID)
	if errors.Is(err, zones.ErrNotFound) {
		return nil
	}
	if err != nil {
		return err
	}
	return s.d.Records.Remove(ctx, subj, z, records.Key{Name: name, Type: typ}, events.SourceIPAM)
}

// setPTR points owner at host (a set already doing so is left untouched).
func (s *Syncer) setPTR(ctx context.Context, subj authz.Subjects, z store.Zone, owner, host string) error {
	cur, ok, err := s.lookup(ctx, subj, z, owner, "PTR")
	if err != nil {
		return err
	}
	if ok && slices.Equal(contents(cur), []string{host}) {
		return nil
	}
	_, err = s.d.Records.Apply(ctx, subj, z, input(owner, "PTR", uint32(s.d.TTL), []string{host}), events.SourceIPAM) // #nosec G115 -- bounded by config validation
	return err
}

// outcome audits and counts one side that could not be written: a zone of
// another tenant (or a non-writable/invalid target) is a skip, anything else
// an error.
func (s *Syncer) outcome(ctx context.Context, subj authz.Subjects, id, zone, name, typ string, err error) {
	reason := "error"
	switch {
	case errors.Is(err, ErrSkip):
		s.d.Metrics.IPAMSync("skip", metrics.ResultSkipped)
		return // unmanaged host: nothing to audit
	case errors.Is(err, zones.ErrDuplicate):
		reason = "zone_conflict"
	case errors.Is(err, zones.ErrInvalidKind):
		reason = "invalid_kind"
	case errors.Is(err, validate.ErrName), errors.Is(err, validate.ErrRecord), errors.Is(err, validate.ErrPublicSuffix):
		reason = "invalid_name"
	}
	if reason != "error" {
		s.d.Log.InfoContext(ctx, "ipam sync: record skipped", "zone", zone, "name", name, "type", typ, "reason", reason)
		s.auditDetail(ctx, subj, audit.SyncSkip, id, audit.OutcomeRefused, reason, map[string]any{"zone": zone, "name": name, "type": typ})
		s.d.Metrics.IPAMSync("skip", metrics.ResultRefused)
		return
	}
	s.d.Log.WarnContext(ctx, "ipam sync: record write failed", "zone", zone, "name", name, "type", typ, "err", err)
	s.auditDetail(ctx, subj, audit.SyncUpsert, id, audit.OutcomeError, "error", map[string]any{"zone": zone, "name": name, "type": typ})
	s.d.Metrics.IPAMSync("upsert", metrics.ResultError)
}

func (s *Syncer) auditEvent(ctx context.Context, subj authz.Subjects, t audit.EventType, id, outcome, reason, forward, reverse string) {
	s.auditDetail(ctx, subj, t, id, outcome, reason, map[string]any{"forward": forward, "reverse": reverse})
}

func (s *Syncer) auditDetail(ctx context.Context, subj authz.Subjects, t audit.EventType, id, outcome, reason string, details map[string]any) {
	audit.Emit(ctx, s.d.Audit, audit.Event{TenantID: subj.TenantID, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectSync, SubjectID: id, Outcome: outcome, Reason: reason, Details: details})
}
