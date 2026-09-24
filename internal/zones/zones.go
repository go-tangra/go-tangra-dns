// Package zones is the zone lifecycle of the DNS module (US1, research D1/D2):
// tenant-owned zones on the shared PowerDNS Authoritative server with global
// name uniqueness and overlap refusal, PowerDNS-first writes with compensation
// so neither store keeps a half-created zone, resolver forward sync, events,
// audit and metrics.
//
// Every PowerDNS operation on an existing zone first loads it under the
// caller's tenant (ownership, SR-001) and uses the stored PowerDNS id — never a
// caller-supplied name. Route permissions of signed-in users are enforced by
// the HTTP layer (from the OpenAPI document); non-human actors (mesh modules,
// the IPAM sync) are checked here against their fixed allow-lists, and a wired
// Checker is consulted for users too.
package zones

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/miekg/dns"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/events"
	"github.com/go-tangra/go-tangra-dns/v4/internal/metrics"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/recursor"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
)

// Errors (the HTTP layer maps them to the contract reasons).
var (
	ErrNotFound         = errors.New("zones: zone not found")           // zone_not_found
	ErrDuplicate        = errors.New("zones: duplicate zone")           // duplicate (owner never revealed)
	ErrInvalidKind      = errors.New("zones: invalid kind")             // invalid_kind
	ErrInvalid          = errors.New("zones: invalid input")            // bad_request
	ErrRejected         = errors.New("zones: refused by PowerDNS")      // bad_request
	ErrTemplateNotFound = errors.New("zones: template not found")       // template_not_found
	ErrExportTooLarge   = errors.New("zones: zone too large to export") // bad_request
)

// Limits.
const (
	MaxDescription = 1000
	MaxNameservers = 16
	MaxPageSize    = 100
)

// TemplateExpander expands a zone template into initial rrsets for a new
// zone (US3). It returns ErrTemplateNotFound for an unknown template.
type TemplateExpander interface {
	Expand(ctx context.Context, tenantID, templateID, zone string) ([]pdns.RRset, error)
}

// Deps wire the service. Store and PDNS are required; the rest is optional.
type Deps struct {
	Store     repo.Store
	PDNS      pdns.Client
	Recursor  recursor.Client
	Events    events.Publisher
	Audit     audit.Recorder
	Metrics   *metrics.Metrics
	Checker   authz.Checker
	Templates TemplateExpander
	// MaxExportBytes caps a BIND export (config limits_dns.max_export_bytes;
	// 0 = 32 MiB).
	MaxExportBytes int64
	Log            *slog.Logger
	Now            func() time.Time
	NewID          func() string
}

// Service manages zones.
type Service struct{ d Deps }

// New builds the service.
func New(d Deps) *Service {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.NewID == nil {
		d.NewID = store.NewID
	}
	if d.MaxExportBytes <= 0 {
		d.MaxExportBytes = 32 << 20
	}
	return &Service{d: d}
}

// CreateInput is a new zone. Origin and RRsets are set by internal callers
// only (the IPAM sync); they are not part of the browser contract.
type CreateInput struct {
	Name        string   `json:"name"`
	Kind        string   `json:"kind"`
	Masters     []string `json:"masters,omitempty"`
	Nameservers []string `json:"nameservers,omitempty"`
	DNSSEC      bool     `json:"dnssec,omitempty"`
	Description string   `json:"description,omitempty"`
	TemplateID  string   `json:"template_id,omitempty"`

	Origin string       `json:"-"`
	RRsets []pdns.RRset `json:"-"`
}

// UpdateInput changes zone metadata; nil fields are kept.
type UpdateInput struct {
	Kind        *string   `json:"kind,omitempty"`
	Masters     *[]string `json:"masters,omitempty"`
	DNSSEC      *bool     `json:"dnssec,omitempty"`
	Description *string   `json:"description,omitempty"`
}

// Detail is a zone with its PowerDNS serials (absent when PowerDNS could not
// be read).
type Detail struct {
	store.Zone
	Serial         *uint32 `json:"serial,omitempty"`
	NotifiedSerial *uint32 `json:"notified_serial,omitempty"`
}

// guard checks the caller may use perm within its tenant (see package doc).
func (s *Service) guard(ctx context.Context, subj authz.Subjects, perm string) error {
	if subj.TenantID == "" {
		return fmt.Errorf("%w: tenant required", authz.ErrForbidden)
	}
	if subj.ActorKind == authz.ActorUser && s.d.Checker == nil {
		return nil // the HTTP layer enforced the route permission
	}
	return authz.Require(ctx, s.d.Checker, subj, perm)
}

// Result maps a PowerDNS/recursor call outcome to the metrics vocabulary.
func Result(err error) string {
	switch {
	case err == nil:
		return metrics.ResultOK
	case errors.Is(err, pdns.ErrNotFound):
		return metrics.ResultNotFound
	case errors.Is(err, pdns.ErrConflict):
		return metrics.ResultConflict
	case errors.Is(err, pdns.ErrUnavailable), errors.Is(err, recursor.ErrUnavailable):
		return metrics.ResultUnavailable
	}
	return metrics.ResultError
}

// Call runs one PowerDNS call and records its latency and outcome.
func (s *Service) Call(op string, f func() error) error {
	start := time.Now()
	err := f()
	s.d.Metrics.PDNSCall(op, Result(err), time.Since(start))
	return err
}

// mapPDNS turns a PowerDNS 4xx refusal (other than 404/409) into ErrRejected;
// sentinel-carrying errors pass through (the message stays server-side).
func mapPDNS(err error) error {
	var ae *pdns.APIError
	if err != nil && errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 &&
		!errors.Is(err, pdns.ErrNotFound) && !errors.Is(err, pdns.ErrConflict) {
		return fmt.Errorf("%w (status %d)", ErrRejected, ae.Status)
	}
	return err
}

// MapPDNS is mapPDNS for sibling services (records).
func MapPDNS(err error) error { return mapPDNS(err) }

func (s *Service) audit(ctx context.Context, subj authz.Subjects, t audit.EventType, id, name, outcome string, err error) {
	e := audit.Event{TenantID: subj.TenantID, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectZone, SubjectID: id, Outcome: outcome, Details: map[string]any{"zone": name}}
	if err != nil {
		e.Reason = reasonOf(err)
	}
	audit.Emit(ctx, s.d.Audit, e)
}

// reasonOf is a stable, content-free reason for the audit log.
func reasonOf(err error) string {
	for _, c := range []struct {
		err    error
		reason string
	}{
		{ErrDuplicate, "duplicate"}, {ErrInvalidKind, "invalid_kind"}, {ErrInvalid, "bad_request"},
		{ErrRejected, "bad_request"}, {ErrTemplateNotFound, "template_not_found"}, {validate.ErrName, "invalid_name"},
		{validate.ErrMasters, "bad_request"}, {pdns.ErrUnavailable, "pdns_unavailable"}, {ErrExportTooLarge, "bad_request"},
		{ErrNotFound, "zone_not_found"},
	} {
		if errors.Is(err, c.err) {
			return c.reason
		}
	}
	return "error"
}

// outcomeOf classifies an error for the audit log.
func outcomeOf(err error) string {
	if reasonOf(err) == "error" || errors.Is(err, pdns.ErrUnavailable) {
		return audit.OutcomeError
	}
	return audit.OutcomeRefused
}

func nonNil(v []string) []string {
	if v == nil {
		return []string{}
	}
	return v
}

// view normalises a zone for responses (arrays are never null).
func view(z store.Zone) store.Zone {
	z.Masters = nonNil(z.Masters)
	z.Nameservers = nonNil(z.Nameservers)
	return z
}

func checkDescription(d string) error {
	if utf8.RuneCountInString(d) > MaxDescription {
		return fmt.Errorf("%w: the description is longer than %d characters", ErrInvalid, MaxDescription)
	}
	return nil
}

// kindMasters validates a kind and its primaries: slave/consumer need at
// least one, every other kind takes none.
func kindMasters(kind string, masters []string) ([]string, error) {
	if !store.ValidKind(kind) {
		return nil, fmt.Errorf("%w: unknown zone kind", ErrInvalidKind)
	}
	m, err := validate.Masters(masters)
	if err != nil {
		return nil, err
	}
	if store.NeedsMasters(kind) && len(m) == 0 {
		return nil, fmt.Errorf("%w: %s zones need at least one primary", ErrInvalidKind, kind)
	}
	if !store.NeedsMasters(kind) && len(m) > 0 {
		return nil, fmt.Errorf("%w: primaries apply to slave and consumer zones only", validate.ErrMasters)
	}
	return m, nil
}

func nameservers(kind string, in []string) ([]string, error) {
	out := []string{}
	if store.NeedsMasters(kind) {
		return out, nil // secondaries take their NS set from the primary
	}
	if len(in) > MaxNameservers {
		return nil, fmt.Errorf("%w: at most %d nameservers", ErrInvalid, MaxNameservers)
	}
	seen := map[string]bool{}
	for _, n := range in {
		h, err := validate.Hostname(n)
		if err != nil {
			return nil, err
		}
		if !seen[h] {
			seen[h] = true
			out = append(out, h)
		}
	}
	return out, nil
}

// Create validates the zone, refuses names taken or overlapping another
// tenant's zone or already present in PowerDNS (never adopted), creates it in
// PowerDNS (with template rrsets) and then locally — deleting the PowerDNS
// zone again if the local insert fails — then syncs the resolver forward.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, in CreateInput) (store.Zone, error) {
	if err := s.guard(ctx, subj, authz.ZonesManage); err != nil {
		return store.Zone{}, err
	}
	z, err := s.create(ctx, subj, in)
	if err != nil {
		s.audit(ctx, subj, audit.ZoneCreate, z.ID, z.Name, outcomeOf(err), err)
		return store.Zone{}, err
	}
	s.audit(ctx, subj, audit.ZoneCreate, z.ID, z.Name, audit.OutcomeOK, nil)
	events.EmitZone(ctx, s.d.Events, events.ZoneCreated, z, subj.ActorKind)
	s.syncForward(ctx, z.Name)
	return view(z), nil
}

func (s *Service) prepare(subj authz.Subjects, in CreateInput) (store.Zone, error) {
	name, err := validate.ZoneName(in.Name)
	if err != nil {
		return store.Zone{}, err
	}
	z := store.Zone{ID: s.d.NewID(), TenantID: subj.TenantID, Name: name, PDNSID: name, Kind: strings.ToLower(strings.TrimSpace(in.Kind)),
		DNSSEC: in.DNSSEC, Description: strings.TrimSpace(in.Description), TemplateID: in.TemplateID, Origin: store.OriginManual,
		CreatedBy: subj.ActorID()}
	if z.Masters, err = kindMasters(z.Kind, in.Masters); err != nil {
		return z, err
	}
	if z.Nameservers, err = nameservers(z.Kind, in.Nameservers); err != nil {
		return z, err
	}
	if err := checkDescription(z.Description); err != nil {
		return z, err
	}
	switch in.Origin {
	case "", store.OriginManual:
	case store.OriginIPAM:
		if subj.IsHuman() {
			return z, fmt.Errorf("%w: the ipam origin is reserved for the IPAM sync", ErrInvalid)
		}
		z.Origin = store.OriginIPAM
	default:
		return z, fmt.Errorf("%w: unknown origin", ErrInvalid)
	}
	return z, nil
}

func (s *Service) create(ctx context.Context, subj authz.Subjects, in CreateInput) (store.Zone, error) {
	z, err := s.prepare(subj, in)
	if err != nil {
		return z, err
	}
	rrsets := in.RRsets
	if z.TemplateID != "" {
		if store.NeedsMasters(z.Kind) {
			return z, fmt.Errorf("%w: templates apply to native, master and producer zones", ErrInvalidKind)
		}
		if s.d.Templates == nil {
			return z, ErrTemplateNotFound
		}
		tpl, err := s.d.Templates.Expand(ctx, z.TenantID, z.TemplateID, z.Name)
		if err != nil {
			return z, err
		}
		rrsets = append(append([]pdns.RRset(nil), rrsets...), tpl...)
	}
	// Ownership rules (research D1): same tenant, other tenants (overlap), PowerDNS.
	if _, err := s.d.Store.GetZoneByName(ctx, z.TenantID, z.Name); err == nil {
		return z, ErrDuplicate
	} else if !errors.Is(err, repo.ErrNotFound) {
		return z, err
	}
	if taken, err := s.d.Store.ZoneConflict(ctx, z.TenantID, z.Name); err != nil {
		return z, err
	} else if taken {
		return z, ErrDuplicate
	}
	err = s.Call("GetZone", func() error { _, e := s.d.PDNS.GetZone(ctx, z.Name); return e })
	switch {
	case err == nil:
		return z, fmt.Errorf("%w: the zone exists on the DNS server", ErrDuplicate)
	case !errors.Is(err, pdns.ErrNotFound):
		return z, mapPDNS(err)
	}
	rrsets, ns := mergeApexNS(z.Name, rrsets, z.Nameservers)
	var created pdns.Zone
	err = s.Call("CreateZone", func() error {
		var e error
		created, e = s.d.PDNS.CreateZone(ctx, pdns.Zone{Name: z.Name, Kind: store.PDNSKind(z.Kind), Masters: z.Masters, DNSSEC: z.DNSSEC,
			Nameservers: ns, Account: z.TenantID, RRsets: rrsets})
		return e
	})
	if errors.Is(err, pdns.ErrConflict) {
		return z, ErrDuplicate
	}
	if err != nil {
		return z, mapPDNS(err)
	}
	if created.ID != "" {
		z.PDNSID = created.ID
	}
	now := s.d.Now()
	z.CreatedAt, z.UpdatedAt = now, now
	if err := s.d.Store.CreateZone(ctx, z); err != nil {
		if derr := s.Call("DeleteZone", func() error { return s.d.PDNS.DeleteZone(ctx, z.PDNSID) }); derr != nil && !errors.Is(derr, pdns.ErrNotFound) {
			s.d.Log.ErrorContext(ctx, "zone create: compensating PowerDNS delete failed", "zone_id", z.ID, "err", derr)
		}
		if errors.Is(err, repo.ErrConflict) {
			return z, ErrDuplicate
		}
		return z, err
	}
	return z, nil
}

// mergeApexNS folds the requested nameservers into an apex NS rrset of the
// initial rrsets (a template's): PowerDNS refuses a nameservers list together
// with zone-level NS rrsets. The input slices are not modified.
func mergeApexNS(zone string, rrsets []pdns.RRset, nameservers []string) ([]pdns.RRset, []string) {
	idx := -1
	for i, r := range rrsets {
		if r.Name == zone && strings.EqualFold(r.Type, "NS") {
			idx = i
		}
	}
	if idx < 0 || len(nameservers) == 0 {
		return rrsets, nameservers
	}
	out := append([]pdns.RRset(nil), rrsets...)
	ns := out[idx]
	ns.Records = append([]pdns.Record(nil), ns.Records...)
	seen := map[string]bool{}
	for _, r := range ns.Records {
		seen[strings.ToLower(r.Content)] = true
	}
	for _, n := range nameservers {
		if !seen[n] {
			seen[n] = true
			ns.Records = append(ns.Records, pdns.Record{Content: n})
		}
	}
	out[idx] = ns
	return out, nil
}

func (s *Service) syncForward(ctx context.Context, name string) {
	if s.d.Recursor == nil {
		return
	}
	err := s.d.Recursor.SyncForward(ctx, name)
	s.d.Metrics.RecursorSync(Result(err))
	if err != nil {
		s.d.Log.WarnContext(ctx, "recursor forward sync failed (the reconciler retries)", "err", err)
	}
}

func (s *Service) removeForward(ctx context.Context, name string) {
	if s.d.Recursor == nil {
		return
	}
	err := s.d.Recursor.RemoveForward(ctx, name)
	s.d.Metrics.RecursorSync(Result(err))
	if err != nil {
		s.d.Log.WarnContext(ctx, "recursor forward removal failed (the reconciler retries)", "err", err)
	}
}

// Owned loads a zone of the caller's tenant (the ownership check preceding
// every PowerDNS operation). A zone of another tenant is ErrNotFound.
func (s *Service) Owned(ctx context.Context, subj authz.Subjects, id string) (store.Zone, error) {
	if err := s.guard(ctx, subj, authz.ZonesRead); err != nil {
		return store.Zone{}, err
	}
	return s.owned(ctx, subj, id)
}

func (s *Service) owned(ctx context.Context, subj authz.Subjects, id string) (store.Zone, error) {
	z, err := s.d.Store.GetZone(ctx, subj.TenantID, id)
	if errors.Is(err, repo.ErrNotFound) {
		return store.Zone{}, ErrNotFound
	}
	if err != nil {
		return store.Zone{}, err
	}
	return view(z), nil
}

// Get returns a zone with its PowerDNS serials; when PowerDNS cannot be read
// the zone is returned without them.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, id string) (Detail, error) {
	z, err := s.Owned(ctx, subj, id)
	if err != nil {
		return Detail{}, err
	}
	d := Detail{Zone: z}
	var pz pdns.Zone
	if err := s.Call("GetZone", func() error { var e error; pz, e = s.d.PDNS.GetZone(ctx, z.PDNSID); return e }); err != nil {
		s.d.Log.WarnContext(ctx, "zone detail: PowerDNS serial unavailable", "zone_id", z.ID, "err", err)
		return d, nil
	}
	d.Serial, d.NotifiedSerial = &pz.Serial, &pz.NotifiedSerial
	return d, nil
}

// List pages the tenant's zones (name order) with the total match count.
func (s *Service) List(ctx context.Context, subj authz.Subjects, f store.ZoneFilter) ([]store.Zone, int64, error) {
	if err := s.guard(ctx, subj, authz.ZonesRead); err != nil {
		return nil, 0, err
	}
	items, total, err := s.d.Store.ListZones(ctx, subj.TenantID, f.Normalized(MaxPageSize))
	if err != nil {
		return nil, 0, err
	}
	out := make([]store.Zone, 0, len(items))
	for _, z := range items {
		out = append(out, view(z))
	}
	return out, total, nil
}

// canonicalFQDN lower-cases s and adds the trailing dot; ok=false for names
// that are not domain names.
func canonicalFQDN(s string) (string, bool) {
	n := dns.Fqdn(strings.ToLower(strings.TrimSpace(s)))
	_, ok := dns.IsDomainName(n)
	return n, ok && n != "." && !strings.Contains(n, "..")
}

// ByName resolves a zone of the caller's tenant by its name.
func (s *Service) ByName(ctx context.Context, subj authz.Subjects, name string) (store.Zone, error) {
	if err := s.guard(ctx, subj, authz.ZonesRead); err != nil {
		return store.Zone{}, err
	}
	n, ok := canonicalFQDN(name)
	if !ok {
		return store.Zone{}, ErrNotFound
	}
	z, err := s.d.Store.GetZoneByName(ctx, subj.TenantID, n)
	if errors.Is(err, repo.ErrNotFound) {
		return store.Zone{}, ErrNotFound
	}
	if err != nil {
		return store.Zone{}, err
	}
	return view(z), nil
}

// FindForName returns the tenant's longest managed zone equal to or
// containing the FQDN (IPAM sync, ACME challenges, module lookups).
func (s *Service) FindForName(ctx context.Context, subj authz.Subjects, fqdn string) (store.Zone, error) {
	if err := s.guard(ctx, subj, authz.ZonesRead); err != nil {
		return store.Zone{}, err
	}
	n, ok := canonicalFQDN(fqdn)
	if !ok {
		return store.Zone{}, ErrNotFound
	}
	all, err := s.d.Store.ZonesForTenant(ctx, subj.TenantID)
	if err != nil {
		return store.Zone{}, err
	}
	z, found := store.LongestZone(all, n)
	if !found {
		return store.Zone{}, ErrNotFound
	}
	return view(z), nil
}

// Update changes kind, masters, DNSSEC and description: PowerDNS metadata
// first (only when it changes), then the local row; if the local write fails
// the previous metadata is PUT back.
func (s *Service) Update(ctx context.Context, subj authz.Subjects, id string, in UpdateInput) (store.Zone, error) {
	if err := s.guard(ctx, subj, authz.ZonesManage); err != nil {
		return store.Zone{}, err
	}
	prev, err := s.owned(ctx, subj, id)
	if err != nil {
		return store.Zone{}, err
	}
	next, err := s.update(ctx, prev, in)
	if err != nil {
		s.audit(ctx, subj, audit.ZoneUpdate, prev.ID, prev.Name, outcomeOf(err), err)
		return store.Zone{}, err
	}
	s.audit(ctx, subj, audit.ZoneUpdate, next.ID, next.Name, audit.OutcomeOK, nil)
	events.EmitZone(ctx, s.d.Events, events.ZoneUpdated, next, subj.ActorKind)
	return view(next), nil
}

func sameStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func metadata(z store.Zone) pdns.Zone {
	return pdns.Zone{Name: z.Name, Kind: store.PDNSKind(z.Kind), Masters: nonNil(z.Masters), DNSSEC: z.DNSSEC, Account: z.TenantID}
}

func (s *Service) update(ctx context.Context, prev store.Zone, in UpdateInput) (store.Zone, error) {
	next := prev
	if in.Kind != nil {
		next.Kind = strings.ToLower(strings.TrimSpace(*in.Kind))
	}
	masters := prev.Masters
	if in.Masters != nil {
		masters = *in.Masters
	} else if !store.NeedsMasters(next.Kind) {
		masters = nil // leaving slave/consumer clears the primaries
	}
	var err error
	if next.Masters, err = kindMasters(next.Kind, masters); err != nil {
		return prev, err
	}
	if in.DNSSEC != nil {
		next.DNSSEC = *in.DNSSEC
	}
	if in.Description != nil {
		next.Description = strings.TrimSpace(*in.Description)
		if err := checkDescription(next.Description); err != nil {
			return prev, err
		}
	}
	metaChanged := next.Kind != prev.Kind || next.DNSSEC != prev.DNSSEC || !sameStrings(next.Masters, nonNil(prev.Masters))
	if metaChanged {
		if err := s.Call("UpdateZoneMetadata", func() error { return s.d.PDNS.UpdateZoneMetadata(ctx, prev.PDNSID, metadata(next)) }); err != nil {
			return prev, mapPDNS(err)
		}
	}
	next.UpdatedAt = s.d.Now()
	saved, err := s.d.Store.UpdateZone(ctx, next)
	if err != nil {
		if metaChanged {
			if rerr := s.Call("UpdateZoneMetadata", func() error { return s.d.PDNS.UpdateZoneMetadata(ctx, prev.PDNSID, metadata(prev)) }); rerr != nil {
				s.d.Log.ErrorContext(ctx, "zone update: restoring PowerDNS metadata failed", "zone_id", prev.ID, "err", rerr)
			}
		}
		return prev, err
	}
	return saved, nil
}

// Delete removes the zone from PowerDNS (a zone PowerDNS no longer has is
// fine), the resolver forward (best effort), the IPAM sync references and
// the local row.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string) error {
	if err := s.guard(ctx, subj, authz.ZonesManage); err != nil {
		return err
	}
	z, err := s.owned(ctx, subj, id)
	if err != nil {
		return err
	}
	if err := s.delete(ctx, z); err != nil {
		s.audit(ctx, subj, audit.ZoneDelete, z.ID, z.Name, outcomeOf(err), err)
		return err
	}
	s.audit(ctx, subj, audit.ZoneDelete, z.ID, z.Name, audit.OutcomeOK, nil)
	events.EmitZone(ctx, s.d.Events, events.ZoneDeleted, z, subj.ActorKind)
	return nil
}

func (s *Service) delete(ctx context.Context, z store.Zone) error {
	err := s.Call("DeleteZone", func() error { return s.d.PDNS.DeleteZone(ctx, z.PDNSID) })
	if err != nil && !errors.Is(err, pdns.ErrNotFound) {
		return mapPDNS(err)
	}
	s.removeForward(ctx, z.Name)
	if err := s.d.Store.ClearSyncZone(ctx, z.TenantID, z.ID); err != nil {
		return err
	}
	return s.d.Store.DeleteZone(ctx, z.TenantID, z.ID)
}

// Export is a zone's BIND text.
type Export struct {
	Zone string `json:"zone"`
	Text string `json:"text"`
}

// Export returns the zone's BIND text from PowerDNS (size-capped).
func (s *Service) Export(ctx context.Context, subj authz.Subjects, id string) (Export, error) {
	if err := s.guard(ctx, subj, authz.ZonesManage); err != nil {
		return Export{}, err
	}
	z, err := s.owned(ctx, subj, id)
	if err != nil {
		return Export{}, err
	}
	var text string
	err = s.Call("ExportZone", func() error { var e error; text, e = s.d.PDNS.ExportZone(ctx, z.PDNSID); return e })
	if err == nil && int64(len(text)) > s.d.MaxExportBytes {
		err = fmt.Errorf("%w: more than %d bytes", ErrExportTooLarge, s.d.MaxExportBytes)
	}
	if err != nil {
		err = mapPDNS(err)
		s.audit(ctx, subj, audit.ZoneExport, z.ID, z.Name, outcomeOf(err), err)
		return Export{}, err
	}
	s.audit(ctx, subj, audit.ZoneExport, z.ID, z.Name, audit.OutcomeOK, nil)
	return Export{Zone: z.Name, Text: text}, nil
}

// Notify asks PowerDNS to send NOTIFY for a master or producer zone; any
// other kind is ErrInvalidKind (refused before PowerDNS).
func (s *Service) Notify(ctx context.Context, subj authz.Subjects, id string) error {
	if err := s.guard(ctx, subj, authz.ZonesManage); err != nil {
		return err
	}
	z, err := s.owned(ctx, subj, id)
	if err != nil {
		return err
	}
	if z.Kind != store.KindMaster && z.Kind != store.KindProducer {
		err = fmt.Errorf("%w: NOTIFY applies to master and producer zones", ErrInvalidKind)
	} else {
		err = mapPDNS(s.Call("NotifyZone", func() error { return s.d.PDNS.NotifyZone(ctx, z.PDNSID) }))
	}
	if err != nil {
		s.audit(ctx, subj, audit.ZoneNotify, z.ID, z.Name, outcomeOf(err), err)
		return err
	}
	s.audit(ctx, subj, audit.ZoneNotify, z.ID, z.Name, audit.OutcomeOK, nil)
	return nil
}
