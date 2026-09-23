// Package supermasters manages the PowerDNS supermasters (autoprimaries) of
// the shared server (US3, FR-007, research D15). A supermaster may
// auto-provision ANY zone name on the shared server, so creating or deleting
// one requires platform-administrator authority on top of
// supermasters:manage; tenants only list and view their own rows. The
// PowerDNS account is forced to the tenant, (ip, nameserver) is globally
// unique, the IP passes the SSRF guard and every change is PowerDNS-first
// with a compensating reversal when the local write fails. There is no
// update: delete and re-create.
package supermasters

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/metrics"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

// Errors (not_found, conflict, bad_request).
var (
	ErrNotFound  = errors.New("supermasters: supermaster not found")
	ErrDuplicate = errors.New("supermasters: that ip and nameserver pair exists")
	ErrRejected  = errors.New("supermasters: refused by PowerDNS")
)

// Deps wire the service; Store and PDNS are required.
type Deps struct {
	Store   repo.Store
	PDNS    pdns.Client
	Audit   audit.Recorder
	Checker authz.Checker
	Metrics *metrics.Metrics
	Log     *slog.Logger
	Now     func() time.Time
	NewID   func() string
}

// Service manages supermasters.
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
	return &Service{d: d}
}

// Input is a new supermaster (the account is always the caller's tenant).
type Input struct {
	IP         string `json:"ip"`
	Nameserver string `json:"nameserver"`
}

func (s *Service) guard(ctx context.Context, subj authz.Subjects) error {
	if subj.TenantID == "" {
		return fmt.Errorf("%w: tenant required", authz.ErrForbidden)
	}
	if subj.IsHuman() && s.d.Checker == nil {
		return nil // the HTTP layer enforced the route permission
	}
	return authz.Require(ctx, s.d.Checker, subj, authz.SupermastersManage)
}

func (s *Service) guardAdmin(ctx context.Context, subj authz.Subjects) error {
	if err := authz.RequirePlatformAdmin(subj); err != nil {
		return err
	}
	return s.guard(ctx, subj)
}

func (s *Service) call(op string, f func() error) error {
	start := time.Now()
	err := f()
	result := metrics.ResultOK
	switch {
	case err == nil:
	case errors.Is(err, pdns.ErrNotFound):
		result = metrics.ResultNotFound
	case errors.Is(err, pdns.ErrConflict):
		result = metrics.ResultConflict
	case errors.Is(err, pdns.ErrUnavailable):
		result = metrics.ResultUnavailable
	default:
		result = metrics.ResultError
	}
	s.d.Metrics.PDNSCall(op, result, time.Since(start))
	return err
}

// mapPDNS: 409 → ErrDuplicate, other 4xx → ErrRejected (message server-side).
func mapPDNS(err error) error {
	var ae *pdns.APIError
	switch {
	case err == nil:
		return nil
	case errors.Is(err, pdns.ErrConflict):
		return ErrDuplicate
	case errors.As(err, &ae) && ae.Status >= 400 && ae.Status < 500 && !errors.Is(err, pdns.ErrNotFound):
		return fmt.Errorf("%w (status %d)", ErrRejected, ae.Status)
	}
	return err
}

// pdnsName is the nameserver as PowerDNS stores it (no trailing dot).
func pdnsName(ns string) string { return strings.TrimSuffix(ns, ".") }

func (s *Service) audit(ctx context.Context, subj authz.Subjects, t audit.EventType, sm store.Supermaster, err error) {
	e := audit.Event{TenantID: subj.TenantID, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectSupermaster, SubjectID: sm.ID, Outcome: audit.OutcomeOK,
		Details: map[string]any{"ip": sm.IP, "nameserver": sm.Nameserver}}
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeRefused, "bad_request"
		switch {
		case errors.Is(err, authz.ErrForbidden):
			e.Reason = "forbidden"
		case errors.Is(err, ErrDuplicate):
			e.Reason = "conflict"
		case errors.Is(err, ErrNotFound):
			e.Reason = "not_found"
		case errors.Is(err, ErrRejected), errors.Is(err, validate.ErrMasters), errors.Is(err, validate.ErrName):
		case errors.Is(err, pdns.ErrUnavailable):
			e.Outcome, e.Reason = audit.OutcomeError, "pdns_unavailable"
		default:
			e.Outcome, e.Reason = audit.OutcomeError, "error"
		}
	}
	audit.Emit(ctx, s.d.Audit, e)
}

// List returns the tenant's supermasters.
func (s *Service) List(ctx context.Context, subj authz.Subjects) ([]store.Supermaster, error) {
	if err := s.guard(ctx, subj); err != nil {
		return nil, err
	}
	return s.d.Store.ListSupermasters(ctx, subj.TenantID)
}

// Get returns one of the tenant's supermasters.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, id string) (store.Supermaster, error) {
	if err := s.guard(ctx, subj); err != nil {
		return store.Supermaster{}, err
	}
	return s.get(ctx, subj, id)
}

func (s *Service) get(ctx context.Context, subj authz.Subjects, id string) (store.Supermaster, error) {
	sm, err := s.d.Store.GetSupermaster(ctx, subj.TenantID, id)
	if errors.Is(err, repo.ErrNotFound) {
		return store.Supermaster{}, ErrNotFound
	}
	return sm, err
}

// Create registers a supermaster: PowerDNS first (account = tenant), then
// locally — removing the PowerDNS entry again when the local insert fails.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, in Input) (store.Supermaster, error) {
	sm := store.Supermaster{ID: s.d.NewID(), TenantID: subj.TenantID, CreatedBy: subj.ActorID(), CreatedAt: s.d.Now()}
	err := s.create(ctx, subj, in, &sm)
	s.audit(ctx, subj, audit.SupermasterCreate, sm, err)
	if err != nil {
		return store.Supermaster{}, err
	}
	return sm, nil
}

func (s *Service) create(ctx context.Context, subj authz.Subjects, in Input, sm *store.Supermaster) error {
	if err := s.guardAdmin(ctx, subj); err != nil {
		return err
	}
	ip, err := validate.IPGuard(in.IP)
	if err != nil {
		return err
	}
	ns, err := validate.Hostname(in.Nameserver)
	if err != nil {
		return err
	}
	sm.IP, sm.Nameserver = ip.String(), ns
	entry := pdns.Supermaster{IP: sm.IP, Nameserver: pdnsName(ns), Account: subj.TenantID}
	if err := mapPDNS(s.call("CreateSupermaster", func() error { return s.d.PDNS.CreateSupermaster(ctx, entry) })); err != nil {
		return err
	}
	if err := s.d.Store.CreateSupermaster(ctx, *sm); err != nil {
		if derr := s.call("DeleteSupermaster", func() error { return s.d.PDNS.DeleteSupermaster(ctx, entry.IP, entry.Nameserver) }); derr != nil && !errors.Is(derr, pdns.ErrNotFound) {
			s.d.Log.ErrorContext(ctx, "supermaster create: compensating PowerDNS delete failed", "supermaster_id", sm.ID, "err", derr)
		}
		if errors.Is(err, repo.ErrConflict) {
			return ErrDuplicate
		}
		return err
	}
	return nil
}

// Delete removes a supermaster: PowerDNS first (an entry PowerDNS no longer
// has is fine), then locally — re-creating the PowerDNS entry when the local
// delete fails.
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string) error {
	sm, err := s.delete(ctx, subj, id)
	if sm.ID == "" {
		sm.ID = id
	}
	s.audit(ctx, subj, audit.SupermasterDelete, sm, err)
	return err
}

func (s *Service) delete(ctx context.Context, subj authz.Subjects, id string) (store.Supermaster, error) {
	if err := s.guardAdmin(ctx, subj); err != nil {
		return store.Supermaster{}, err
	}
	sm, err := s.get(ctx, subj, id)
	if err != nil {
		return store.Supermaster{}, err
	}
	entry := pdns.Supermaster{IP: sm.IP, Nameserver: pdnsName(sm.Nameserver), Account: sm.TenantID}
	err = s.call("DeleteSupermaster", func() error { return s.d.PDNS.DeleteSupermaster(ctx, entry.IP, entry.Nameserver) })
	gone := errors.Is(err, pdns.ErrNotFound)
	if err != nil && !gone {
		return sm, mapPDNS(err)
	}
	if err := s.d.Store.DeleteSupermaster(ctx, sm.TenantID, sm.ID); err != nil {
		if !gone {
			if cerr := s.call("CreateSupermaster", func() error { return s.d.PDNS.CreateSupermaster(ctx, entry) }); cerr != nil {
				s.d.Log.ErrorContext(ctx, "supermaster delete: restoring the PowerDNS entry failed", "supermaster_id", sm.ID, "err", cerr)
			}
		}
		if errors.Is(err, repo.ErrNotFound) {
			return sm, ErrNotFound
		}
		return sm, err
	}
	return sm, nil
}
