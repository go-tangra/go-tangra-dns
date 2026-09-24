package acmechallenge

import (
	"context"
	"errors"
	"time"

	"github.com/go-tangra/go-tangra-dns/v4/internal/audit"
	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

// sweepBatch bounds one sweep pass.
const sweepBatch = 100

// Sweep removes challenge values presented more than maxAge ago whose CleanUp
// never arrived (SC-005) and returns how many were removed. It runs in the
// system scope of each challenge's tenant; a challenge whose zone is gone is
// just forgotten.
func (s *Service) Sweep(ctx context.Context, maxAge time.Duration) (int, error) {
	rows, err := s.d.Store.ChallengesOlderThan(ctx, s.d.Now().Add(-maxAge), sweepBatch)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, c := range rows {
		sys := authz.Internal(c.TenantID)
		z, err := s.d.Zones.Owned(ctx, sys, c.ZoneID)
		if errors.Is(err, zones.ErrNotFound) {
			if derr := s.d.Store.DeleteChallenge(ctx, c.TenantID, c.FQDN, c.Value); derr != nil && !errors.Is(derr, repo.ErrNotFound) {
				s.d.Log.WarnContext(ctx, "challenge sweep: bookkeeping delete failed", "err", derr)
			}
			continue
		}
		if err == nil {
			err = s.remove(ctx, sys, z, c.FQDN, c.Value)
		}
		e := audit.Event{TenantID: c.TenantID, EventType: audit.ChallengeSwept, ActorKind: audit.ActorSystem, ActorID: authz.ActorSystem,
			SubjectKind: audit.SubjectChallenge, SubjectID: c.FQDN, Outcome: audit.OutcomeOK, Details: map[string]any{"zone": z.Name, "name": c.FQDN}}
		if err != nil {
			e.Outcome, e.Reason = audit.OutcomeError, reasonOf(err)
			s.d.Log.WarnContext(ctx, "challenge sweep failed (retried next pass)", "zone", z.Name, "err", err)
		} else {
			n++
		}
		audit.Emit(ctx, s.d.Audit, e)
		s.d.Metrics.Challenge("sweep", resultOf(err))
	}
	return n, nil
}

// Sweeper periodically removes stale challenge values (an app worker).
type Sweeper struct {
	Service  *Service
	MaxAge   time.Duration // config acme.max_age_seconds
	Interval time.Duration // default 1 minute
}

// Run sweeps every Interval until ctx is done.
func (w *Sweeper) Run(ctx context.Context) {
	iv := w.Interval
	if iv <= 0 {
		iv = time.Minute
	}
	t := time.NewTicker(iv)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := w.Service.Sweep(ctx, w.MaxAge); err != nil && ctx.Err() == nil {
				w.Service.d.Log.WarnContext(ctx, "challenge sweep", "err", err)
			}
		}
	}
}
