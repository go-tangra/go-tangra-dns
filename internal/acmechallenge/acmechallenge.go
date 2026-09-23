// Package acmechallenge publishes and removes ACME DNS-01 challenge values for
// the certificate service (lcm) — US4, research D12, SR-005.
//
// Rules: only the configured caller identity (the verified lcm SPIFFE ID) is
// served; fqdn must be "_acme-challenge." + the certificate domain without a
// leading "*."; the name must lie inside one of the TENANT's zones (the
// longest match is used; otherwise nothing is written); a CNAME at the name
// refuses; the value is a 43-char base64url digest. Present adds the value to
// the TXT rrset at the name keeping every other value (and the comment);
// CleanUp removes only that value and deletes the rrset when it becomes empty.
// Both are idempotent. Operations on one name are serialised in-process (an
// apex and its wildcard share "_acme-challenge.<domain>"). Every presented
// value is recorded so the sweeper can remove it when CleanUp never arrives.
package acmechallenge

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"log/slog"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/miekg/dns"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/metrics"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

// Errors (the gRPC layer maps them: InvalidArgument, NotFound,
// FailedPrecondition).
var (
	ErrInvalid      = errors.New("acmechallenge: invalid challenge")
	ErrNotFound     = errors.New("acmechallenge: no zone of the tenant contains the name")
	ErrPrecondition = errors.New("acmechallenge: the name cannot hold a challenge value")
)

// Prefix is the DNS-01 owner-name label.
const Prefix = "_acme-challenge."

// DefaultTTL is the TTL of a challenge rrset (research D12).
const DefaultTTL = 60

var valueRE = regexp.MustCompile(`^[A-Za-z0-9_-]{43}$`)

// Request is one challenge operation for the caller's tenant.
type Request struct {
	Domain string // the certificate identifier (may start with "*.")
	FQDN   string // "_acme-challenge." + Domain without "*."
	Value  string // 43-char base64url key-authorization digest
}

// Deps wire the service. Zones, Records and Store are required.
type Deps struct {
	Zones   *zones.Service
	Records *records.Service
	Store   repo.Challenges
	Audit   audit.Recorder
	Metrics *metrics.Metrics
	// AllowedCaller is the exact SPIFFE ID served (config acme.allowed_caller).
	AllowedCaller string
	TTL           int
	Log           *slog.Logger
	Now           func() time.Time
	NewID         func() string
}

const stripes = 64

// Service implements the challenge operations.
type Service struct {
	d     Deps
	locks [stripes]sync.Mutex
}

// New builds the service.
func New(d Deps) *Service {
	if d.TTL <= 0 {
		d.TTL = DefaultTTL
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.NewID == nil {
		d.NewID = store.NewID
	}
	return &Service{d: d}
}

// lock serialises operations on one (tenant, name).
func (s *Service) lock(tenantID, fqdn string) func() {
	h := fnv.New32a()
	_, _ = h.Write([]byte(tenantID + "|" + fqdn))
	m := &s.locks[h.Sum32()%stripes]
	m.Lock()
	return m.Unlock
}

// canonical returns the lower-cased FQDN (trailing dot) or false.
func canonical(name string) (string, bool) {
	n := dns.Fqdn(strings.ToLower(strings.TrimSpace(name)))
	if n == "." || strings.Contains(n, "..") || strings.ContainsAny(n, " *\\\"") {
		return "", false
	}
	_, ok := dns.IsDomainName(n)
	return n, ok
}

// check validates the request and returns the canonical owner name.
func check(r Request) (string, error) {
	if !valueRE.MatchString(r.Value) {
		return "", fmt.Errorf("%w: value must be a 43-character base64url string", ErrInvalid)
	}
	domain, ok := canonical(strings.TrimPrefix(strings.TrimSpace(r.Domain), "*."))
	if !ok {
		return "", fmt.Errorf("%w: domain is not a DNS name", ErrInvalid)
	}
	fqdn, ok := canonical(r.FQDN)
	if !ok || fqdn != Prefix+domain {
		return "", fmt.Errorf("%w: fqdn must be %s<domain>", ErrInvalid, Prefix)
	}
	return fqdn, nil
}

// quoted is the canonical TXT content of a challenge value.
func quoted(v string) string { return `"` + v + `"` }

func reasonOf(err error) string {
	switch {
	case errors.Is(err, authz.ErrForbidden):
		return "forbidden"
	case errors.Is(err, ErrInvalid):
		return "invalid_challenge"
	case errors.Is(err, ErrNotFound):
		return "zone_not_found"
	case errors.Is(err, ErrPrecondition):
		return "precondition"
	case errors.Is(err, pdns.ErrUnavailable):
		return "pdns_unavailable"
	}
	return "error"
}

func resultOf(err error) string {
	switch {
	case err == nil:
		return metrics.ResultOK
	case errors.Is(err, pdns.ErrUnavailable):
		return metrics.ResultUnavailable
	case errors.Is(err, ErrNotFound):
		return metrics.ResultNotFound
	case errors.Is(err, authz.ErrForbidden), errors.Is(err, ErrInvalid), errors.Is(err, ErrPrecondition):
		return metrics.ResultRefused
	}
	return metrics.ResultError
}

func (s *Service) audit(ctx context.Context, subj authz.Subjects, t audit.EventType, zone, fqdn string, err error) {
	tenant := subj.TenantID
	if tenant == "" {
		tenant = audit.NilTenant
	}
	e := audit.Event{TenantID: tenant, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectChallenge, SubjectID: fqdn, Outcome: audit.OutcomeOK, Details: map[string]any{"zone": zone, "name": fqdn}}
	if err != nil {
		e.EventType, e.Outcome, e.Reason = audit.ChallengeRefused, audit.OutcomeRefused, reasonOf(err)
		if e.Reason == "error" || e.Reason == "pdns_unavailable" {
			e.EventType, e.Outcome = t, audit.OutcomeError
		}
		e.Details["op"] = string(t)
	}
	audit.Emit(ctx, s.d.Audit, e)
}

// Refused records a challenge call refused before reaching the service (a
// peer other than the allowed caller). tenantID may be anything the caller
// sent; it is recorded only when it names a tenant.
func (s *Service) Refused(ctx context.Context, peer, tenantID string) {
	if !uuidRE.MatchString(tenantID) {
		tenantID = audit.NilTenant
	}
	actor := peer
	if actor == "" {
		actor = "unknown"
	}
	audit.Emit(ctx, s.d.Audit, audit.Event{TenantID: tenantID, EventType: audit.ChallengeRefused, ActorKind: audit.ActorModule, ActorID: actor,
		SubjectKind: audit.SubjectChallenge, Outcome: audit.OutcomeRefused, Reason: "forbidden"})
	s.d.Metrics.Challenge("refused", metrics.ResultRefused)
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

// resolve admits the caller and finds the tenant zone for the request.
func (s *Service) resolve(ctx context.Context, subj authz.Subjects, r Request) (authz.Subjects, store.Zone, string, error) {
	w, err := authz.Challenger(subj, s.d.AllowedCaller)
	if err != nil {
		return subj, store.Zone{}, "", err
	}
	fqdn, err := check(r)
	if err != nil {
		return w, store.Zone{}, "", err
	}
	z, err := s.d.Zones.FindForName(ctx, w, fqdn)
	if errors.Is(err, zones.ErrNotFound) {
		return w, store.Zone{}, fqdn, ErrNotFound
	}
	if err != nil {
		return w, store.Zone{}, fqdn, err
	}
	if store.NeedsMasters(z.Kind) {
		return w, z, fqdn, fmt.Errorf("%w: %s zones take their records from their primaries", ErrPrecondition, z.Kind)
	}
	return w, z, fqdn, nil
}

// current returns the TXT rrset at fqdn (ok=false when absent) after refusing
// a CNAME at the name.
func (s *Service) current(ctx context.Context, w authz.Subjects, z store.Zone, fqdn string) (records.RecordSet, bool, error) {
	if _, err := s.d.Records.Lookup(ctx, w, z, records.Key{Name: fqdn, Type: "CNAME"}); err == nil {
		return records.RecordSet{}, false, fmt.Errorf("%w: a CNAME exists at %s", ErrPrecondition, fqdn)
	} else if !errors.Is(err, records.ErrNotFound) {
		return records.RecordSet{}, false, err
	}
	rs, err := s.d.Records.Lookup(ctx, w, z, records.Key{Name: fqdn, Type: "TXT"})
	if errors.Is(err, records.ErrNotFound) {
		return records.RecordSet{}, false, nil
	}
	return rs, err == nil, err
}

func mapWrite(err error) error {
	if errors.Is(err, validate.ErrRecord) || errors.Is(err, zones.ErrInvalidKind) {
		return fmt.Errorf("%w: %w", ErrPrecondition, err)
	}
	return err
}

// Present adds the value to the TXT rrset at fqdn (idempotent) and returns the
// zone written.
func (s *Service) Present(ctx context.Context, subj authz.Subjects, r Request) (string, error) {
	w, z, fqdn, err := s.resolve(ctx, subj, r)
	if err == nil {
		err = s.present(ctx, w, z, fqdn, r.Value)
	}
	s.audit(ctx, w, audit.ChallengePresent, z.Name, fqdn, err)
	s.d.Metrics.Challenge("present", resultOf(err))
	if err != nil {
		return "", err
	}
	return z.Name, nil
}

func (s *Service) present(ctx context.Context, w authz.Subjects, z store.Zone, fqdn, value string) error {
	unlock := s.lock(z.TenantID, fqdn)
	defer unlock()
	rs, _, err := s.current(ctx, w, z, fqdn)
	if err != nil {
		return err
	}
	in := validate.RecordSetInput{Name: fqdn, Type: "TXT", TTL: s.d.TTL, Comment: rs.Comment}
	for _, v := range rs.Values {
		if v.Content == quoted(value) {
			return s.record(ctx, w, z, fqdn, value) // already present
		}
		in.Values = append(in.Values, validate.RecordValue{Content: v.Content, Disabled: v.Disabled})
	}
	in.Values = append(in.Values, validate.RecordValue{Content: quoted(value)})
	if _, err := s.d.Records.Apply(ctx, w, z, in, events.SourceACME); err != nil {
		return mapWrite(err)
	}
	return s.record(ctx, w, z, fqdn, value)
}

// record books the presented value for the sweeper; a bookkeeping failure is
// logged, never failing the challenge (the value is already published).
func (s *Service) record(ctx context.Context, w authz.Subjects, z store.Zone, fqdn, value string) error {
	c := store.Challenge{ID: s.d.NewID(), TenantID: z.TenantID, ZoneID: z.ID, FQDN: fqdn, Value: value, RequestedBy: w.PeerSPIFFE, CreatedAt: s.d.Now()}
	if err := s.d.Store.InsertChallenge(ctx, c); err != nil && !errors.Is(err, repo.ErrConflict) {
		s.d.Log.WarnContext(ctx, "challenge bookkeeping failed (the value may outlive a lost clean-up)", "zone", z.Name, "err", err)
	}
	return nil
}

// CleanUp removes the value from the TXT rrset at fqdn (absent = OK) and
// returns the zone cleaned.
func (s *Service) CleanUp(ctx context.Context, subj authz.Subjects, r Request) (string, error) {
	w, z, fqdn, err := s.resolve(ctx, subj, r)
	if err == nil {
		err = s.remove(ctx, w, z, fqdn, r.Value)
	}
	s.audit(ctx, w, audit.ChallengeCleanup, z.Name, fqdn, err)
	s.d.Metrics.Challenge("cleanup", resultOf(err))
	if err != nil {
		return "", err
	}
	return z.Name, nil
}

func (s *Service) remove(ctx context.Context, w authz.Subjects, z store.Zone, fqdn, value string) error {
	unlock := s.lock(z.TenantID, fqdn)
	defer unlock()
	rs, found, err := s.current(ctx, w, z, fqdn)
	if err != nil {
		return err
	}
	if found {
		if err := s.drop(ctx, w, z, rs, fqdn, value); err != nil {
			return err
		}
	}
	if err := s.d.Store.DeleteChallenge(ctx, z.TenantID, fqdn, value); err != nil && !errors.Is(err, repo.ErrNotFound) {
		s.d.Log.WarnContext(ctx, "challenge bookkeeping delete failed", "zone", z.Name, "err", err)
	}
	return nil
}

// drop rewrites rs without value (deleting the rrset when nothing is left).
func (s *Service) drop(ctx context.Context, w authz.Subjects, z store.Zone, rs records.RecordSet, fqdn, value string) error {
	in := validate.RecordSetInput{Name: fqdn, Type: "TXT", TTL: int(rs.TTL), Comment: rs.Comment}
	hit := false
	for _, v := range rs.Values {
		if v.Content == quoted(value) {
			hit = true
			continue
		}
		in.Values = append(in.Values, validate.RecordValue{Content: v.Content, Disabled: v.Disabled})
	}
	switch {
	case !hit:
		return nil
	case len(in.Values) == 0:
		return mapWrite(s.d.Records.Remove(ctx, w, z, records.Key{Name: fqdn, Type: "TXT"}, events.SourceACME))
	}
	_, err := s.d.Records.Apply(ctx, w, z, in, events.SourceACME)
	return mapWrite(err)
}
