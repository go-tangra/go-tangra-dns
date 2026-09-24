// Package records manages the record sets of a tenant's zone (US1, research
// D5/D6). PowerDNS is the source of truth: a list is one GET of the zone
// filtered, sorted and paged in memory; every change is validated per type
// (validate.RecordSet — CNAME exclusivity against the zone's current rrsets,
// SOA read-only) and applied as a single PATCH so it is atomic in PowerDNS.
// The zone is always loaded under the caller's tenant first and addressed by
// its stored PowerDNS id.
package records

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/events"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

// Errors (mapped to record_not_found / conflict by the HTTP layer).
var (
	ErrNotFound = errors.New("records: record set not found")
	ErrConflict = errors.New("records: a record set with that name and type exists")
)

// Paging bounds.
const (
	DefaultPageSize = 100
	MaxPageSize     = 500
)

// Deps wire the service; Zones and PDNS are required.
type Deps struct {
	Zones  *zones.Service
	PDNS   pdns.Client
	Events events.Publisher
	Audit  audit.Recorder
	Limits validate.Limits // zero value = validate.DefaultLimits
	Log    *slog.Logger
}

// Service manages record sets.
type Service struct{ d Deps }

// New builds the service.
func New(d Deps) *Service {
	if d.Limits == (validate.Limits{}) {
		d.Limits = validate.DefaultLimits
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	return &Service{d: d}
}

// Value is one record of a set.
type Value struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

// RecordSet is the API view of a PowerDNS rrset; SOA (and any type the module
// does not edit) is read-only.
type RecordSet struct {
	Name     string  `json:"name"`
	Type     string  `json:"type"`
	TTL      uint32  `json:"ttl"`
	Values   []Value `json:"values"`
	Comment  string  `json:"comment,omitempty"`
	ReadOnly bool    `json:"read_only"`
}

// Key identifies a record set (name "@", relative or absolute; type).
type Key struct {
	Name string `json:"name"`
	Type string `json:"type"`
}

// Filter selects a page of record sets: Type exact (any case), Query a
// case-insensitive substring of the qualified name.
type Filter struct {
	Type     string
	Query    string
	Page     int
	PageSize int
}

func toView(r pdns.RRset) RecordSet {
	v := RecordSet{Name: r.Name, Type: strings.ToUpper(r.Type), TTL: r.TTL, Values: make([]Value, 0, len(r.Records))}
	v.ReadOnly = !validate.Editable(v.Type)
	for _, rec := range r.Records {
		v.Values = append(v.Values, Value{Content: rec.Content, Disabled: rec.Disabled})
	}
	if len(r.Comments) > 0 {
		v.Comment = r.Comments[0].Content
	}
	return v
}

// reversed returns the labels of a name from the root down (DNS canonical order).
func reversed(name string) []string {
	l := strings.Split(strings.TrimSuffix(strings.ToLower(name), "."), ".")
	for i, j := 0, len(l)-1; i < j; i, j = i+1, j-1 {
		l[i], l[j] = l[j], l[i]
	}
	return l
}

func typeRank(t string) string {
	if t == "SOA" {
		return ""
	}
	return t
}

// sortSets orders sets in DNS canonical name order (apex first), then by type
// with SOA leading.
func sortSets(sets []RecordSet) {
	keys := make(map[string][]string, len(sets))
	for _, s := range sets {
		keys[s.Name] = reversed(s.Name)
	}
	sort.SliceStable(sets, func(i, j int) bool {
		a, b := keys[sets[i].Name], keys[sets[j].Name]
		for k := 0; k < len(a) && k < len(b); k++ {
			if a[k] != b[k] {
				return a[k] < b[k]
			}
		}
		if len(a) != len(b) {
			return len(a) < len(b)
		}
		return typeRank(sets[i].Type) < typeRank(sets[j].Type)
	})
}

func (s *Service) audit(ctx context.Context, subj authz.Subjects, t audit.EventType, z store.Zone, name, typ string, err error) {
	e := audit.Event{TenantID: subj.TenantID, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectRecord, SubjectID: z.ID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"zone": z.Name, "name": name, "type": typ}}
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeError, "error"
		switch {
		case errors.Is(err, validate.ErrRecord):
			e.Outcome, e.Reason = audit.OutcomeRefused, "invalid_record"
		case errors.Is(err, validate.ErrName):
			e.Outcome, e.Reason = audit.OutcomeRefused, "invalid_name"
		case errors.Is(err, ErrNotFound):
			e.Outcome, e.Reason = audit.OutcomeRefused, "record_not_found"
		case errors.Is(err, ErrConflict):
			e.Outcome, e.Reason = audit.OutcomeRefused, "conflict"
		case errors.Is(err, zones.ErrInvalidKind):
			e.Outcome, e.Reason = audit.OutcomeRefused, "invalid_kind"
		case errors.Is(err, pdns.ErrUnavailable):
			e.Reason = "pdns_unavailable"
		}
	}
	audit.Emit(ctx, s.d.Audit, e)
}

// load is the ownership check: the zone of the caller's tenant.
func (s *Service) load(ctx context.Context, subj authz.Subjects, zoneID string, perm string) (store.Zone, error) {
	if perm == authz.ZonesManage && !subj.IsHuman() {
		if err := authz.Require(ctx, nil, subj, perm); err != nil {
			return store.Zone{}, err
		}
	}
	return s.d.Zones.Owned(ctx, subj, zoneID)
}

func (s *Service) rrsets(ctx context.Context, z store.Zone) ([]pdns.RRset, error) {
	var pz pdns.Zone
	err := s.d.Zones.Call("GetZone", func() error { var e error; pz, e = s.d.PDNS.GetZone(ctx, z.PDNSID); return e })
	if err != nil {
		return nil, zones.MapPDNS(err)
	}
	return pz.RRsets, nil
}

func (s *Service) patch(ctx context.Context, z store.Zone, changes []pdns.RRset) error {
	return zones.MapPDNS(s.d.Zones.Call("PatchRRsets", func() error { return s.d.PDNS.PatchRRsets(ctx, z.PDNSID, changes) }))
}

// List returns one page of the zone's record sets and the total match count.
func (s *Service) List(ctx context.Context, subj authz.Subjects, zoneID string, f Filter) ([]RecordSet, int, error) {
	z, err := s.load(ctx, subj, zoneID, authz.ZonesRead)
	if err != nil {
		return nil, 0, err
	}
	sets, err := s.rrsets(ctx, z)
	if err != nil {
		return nil, 0, err
	}
	typ := strings.ToUpper(strings.TrimSpace(f.Type))
	q := strings.ToLower(strings.TrimSpace(f.Query))
	matched := make([]RecordSet, 0, len(sets))
	for _, r := range sets {
		if (typ != "" && !strings.EqualFold(r.Type, typ)) || (q != "" && !strings.Contains(strings.ToLower(r.Name), q)) {
			continue
		}
		matched = append(matched, toView(r))
	}
	sortSets(matched)
	page, size := f.Page, f.PageSize
	if page <= 0 {
		page = 1
	}
	if size <= 0 {
		size = DefaultPageSize
	}
	size = min(size, MaxPageSize)
	lo := min((page-1)*size, len(matched))
	hi := min(lo+size, len(matched))
	return matched[lo:hi], len(matched), nil
}

// writable refuses record writes on secondaries (their data comes from the
// primary by zone transfer).
func writable(z store.Zone) error {
	if store.NeedsMasters(z.Kind) {
		return fmt.Errorf("%w: records of %s zones come from their primaries", zones.ErrInvalidKind, z.Kind)
	}
	return nil
}

// Upsert creates or replaces the (name, type) record set (source api).
func (s *Service) Upsert(ctx context.Context, subj authz.Subjects, zoneID string, in validate.RecordSetInput) (RecordSet, error) {
	z, err := s.load(ctx, subj, zoneID, authz.ZonesManage)
	if err != nil {
		return RecordSet{}, err
	}
	return s.Apply(ctx, subj, z, in, events.SourceAPI)
}

// Apply upserts a record set into a zone the caller already loaded under its
// tenant (Owned) — the entry point of the IPAM sync and ACME challenges.
func (s *Service) Apply(ctx context.Context, subj authz.Subjects, z store.Zone, in validate.RecordSetInput, source string) (RecordSet, error) {
	if err := authz.Require(ctx, nil, withoutUser(subj), authz.ZonesManage); err != nil {
		return RecordSet{}, err
	}
	rr, err := s.apply(ctx, z, in)
	name, typ := rr.Name, rr.Type
	if err != nil {
		s.audit(ctx, subj, audit.RecordUpsert, z, in.Name, strings.ToUpper(in.Type), err)
		return RecordSet{}, err
	}
	s.audit(ctx, subj, audit.RecordUpsert, z, name, typ, nil)
	events.EmitRecord(ctx, s.d.Events, z, name, typ, events.ActionUpserted, source)
	return toView(rr), nil
}

// withoutUser lets a signed-in user through the actor allow-list check (the
// HTTP layer enforced the route permission); other actors are checked.
func withoutUser(subj authz.Subjects) authz.Subjects {
	if subj.IsHuman() {
		return authz.Internal(subj.TenantID)
	}
	return subj
}

func (s *Service) apply(ctx context.Context, z store.Zone, in validate.RecordSetInput) (pdns.RRset, error) {
	if err := writable(z); err != nil {
		return pdns.RRset{}, err
	}
	cur, err := s.rrsets(ctx, z)
	if err != nil {
		return pdns.RRset{}, err
	}
	rr, err := s.d.Limits.RecordSet(z.Name, in, cur)
	if err != nil {
		return pdns.RRset{}, err
	}
	return rr, s.patch(ctx, z, []pdns.RRset{rr})
}

// Lookup returns the (name, type) record set of a zone the caller already
// loaded under its tenant (ErrNotFound when absent) — the IPAM sync merges
// its address into existing sets with it.
func (s *Service) Lookup(ctx context.Context, subj authz.Subjects, z store.Zone, k Key) (RecordSet, error) {
	if err := authz.Require(ctx, nil, withoutUser(subj), authz.ZonesRead); err != nil {
		return RecordSet{}, err
	}
	name, err := validate.RecordName(z.Name, k.Name)
	if err != nil {
		return RecordSet{}, err
	}
	typ := strings.ToUpper(strings.TrimSpace(k.Type))
	cur, err := s.rrsets(ctx, z)
	if err != nil {
		return RecordSet{}, err
	}
	for _, r := range cur {
		if strings.EqualFold(r.Name, name) && strings.EqualFold(r.Type, typ) {
			return toView(r), nil
		}
	}
	return RecordSet{}, ErrNotFound
}

// key canonicalises a record set key within zone z.
func key(z store.Zone, k Key) (string, string, error) {
	name, err := validate.RecordName(z.Name, k.Name)
	if err != nil {
		return "", "", err
	}
	t := strings.ToUpper(strings.TrimSpace(k.Type))
	if !validate.Editable(t) {
		return "", "", &validate.RecordError{Field: "type", Msg: "this record type is read-only"}
	}
	return name, t, nil
}

func find(sets []pdns.RRset, name, typ string) bool {
	for _, r := range sets {
		if strings.EqualFold(r.Name, name) && strings.EqualFold(r.Type, typ) {
			return true
		}
	}
	return false
}

// Update replaces the record set identified by original with in; a rename (or
// type change) is REPLACE new + DELETE old in one PATCH and refuses to
// overwrite another existing set.
func (s *Service) Update(ctx context.Context, subj authz.Subjects, zoneID string, original Key, in validate.RecordSetInput) (RecordSet, error) {
	z, err := s.load(ctx, subj, zoneID, authz.ZonesManage)
	if err != nil {
		return RecordSet{}, err
	}
	rr, oldName, oldType, err := s.update(ctx, z, original, in)
	if err != nil {
		s.audit(ctx, subj, audit.RecordUpsert, z, in.Name, strings.ToUpper(in.Type), err)
		return RecordSet{}, err
	}
	s.audit(ctx, subj, audit.RecordUpsert, z, rr.Name, rr.Type, nil)
	events.EmitRecord(ctx, s.d.Events, z, rr.Name, rr.Type, events.ActionUpserted, events.SourceAPI)
	if oldName != rr.Name || oldType != rr.Type {
		s.audit(ctx, subj, audit.RecordDelete, z, oldName, oldType, nil)
		events.EmitRecord(ctx, s.d.Events, z, oldName, oldType, events.ActionDeleted, events.SourceAPI)
	}
	return toView(rr), nil
}

func (s *Service) update(ctx context.Context, z store.Zone, original Key, in validate.RecordSetInput) (pdns.RRset, string, string, error) {
	if err := writable(z); err != nil {
		return pdns.RRset{}, "", "", err
	}
	oldName, oldType, err := key(z, original)
	if err != nil {
		return pdns.RRset{}, "", "", err
	}
	cur, err := s.rrsets(ctx, z)
	if err != nil {
		return pdns.RRset{}, "", "", err
	}
	if !find(cur, oldName, oldType) {
		return pdns.RRset{}, "", "", ErrNotFound
	}
	others := make([]pdns.RRset, 0, len(cur))
	for _, r := range cur {
		if !(strings.EqualFold(r.Name, oldName) && strings.EqualFold(r.Type, oldType)) {
			others = append(others, r)
		}
	}
	rr, err := s.d.Limits.RecordSet(z.Name, in, others)
	if err != nil {
		return pdns.RRset{}, "", "", err
	}
	changes := []pdns.RRset{rr}
	if rr.Name != oldName || rr.Type != oldType {
		if find(others, rr.Name, rr.Type) {
			return pdns.RRset{}, "", "", ErrConflict
		}
		changes = append(changes, pdns.RRset{Name: oldName, Type: oldType, ChangeType: pdns.ChangeDelete})
	}
	return rr, oldName, oldType, s.patch(ctx, z, changes)
}

// Delete removes the (name, type) record set; ErrNotFound when absent.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, zoneID string, k Key) error {
	z, err := s.load(ctx, subj, zoneID, authz.ZonesManage)
	if err != nil {
		return err
	}
	name, typ, err := s.remove(ctx, z, k)
	if err != nil {
		s.audit(ctx, subj, audit.RecordDelete, z, k.Name, strings.ToUpper(k.Type), err)
		return err
	}
	s.audit(ctx, subj, audit.RecordDelete, z, name, typ, nil)
	events.EmitRecord(ctx, s.d.Events, z, name, typ, events.ActionDeleted, events.SourceAPI)
	return nil
}

// Remove deletes the (name, type) record set of an already-loaded zone if it
// exists (idempotent: absent is success) — for the IPAM sync and ACME.
func (s *Service) Remove(ctx context.Context, subj authz.Subjects, z store.Zone, k Key, source string) error {
	if err := authz.Require(ctx, nil, withoutUser(subj), authz.ZonesManage); err != nil {
		return err
	}
	name, typ, err := s.remove(ctx, z, k)
	if errors.Is(err, ErrNotFound) {
		return nil
	}
	if err != nil {
		s.audit(ctx, subj, audit.RecordDelete, z, k.Name, strings.ToUpper(k.Type), err)
		return err
	}
	s.audit(ctx, subj, audit.RecordDelete, z, name, typ, nil)
	events.EmitRecord(ctx, s.d.Events, z, name, typ, events.ActionDeleted, source)
	return nil
}

func (s *Service) remove(ctx context.Context, z store.Zone, k Key) (string, string, error) {
	if err := writable(z); err != nil {
		return "", "", err
	}
	name, typ, err := key(z, k)
	if err != nil {
		return "", "", err
	}
	cur, err := s.rrsets(ctx, z)
	if err != nil {
		return "", "", err
	}
	if !find(cur, name, typ) {
		return name, typ, ErrNotFound
	}
	return name, typ, s.patch(ctx, z, []pdns.RRset{{Name: name, Type: typ, ChangeType: pdns.ChangeDelete}})
}
