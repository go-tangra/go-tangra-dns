package recursor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Reconciler keeps the recursor's forward zones equal to the managed zones
// (research D10, FR-008): every managed zone is (re)pointed at the
// authoritative server and forwards for zones no longer managed are removed —
// except the root and the configured static forwards. It runs at start-up and
// on an interval, and on demand after a configuration restart (ReconcileNow,
// which first polls the recursor for readiness, bounded). A disabled client
// makes every pass a no-op. Failures are logged and retried on the next pass;
// they never block zone management.
type Reconciler struct {
	Client Client
	// Names lists every managed zone name (repo AllZoneNames, system scope).
	Names func(ctx context.Context) ([]string, error)
	// Static forwards are never removed (config recursor.static_forwards).
	Static []string
	// Interval between passes (default 5 minutes).
	Interval time.Duration
	// After is the clock (default time.After; injected in tests).
	After func(time.Duration) <-chan time.Time
	// ReadyAttempts/ReadyDelay bound ReconcileNow's readiness polling
	// (defaults 30 × 1 s).
	ReadyAttempts int
	ReadyDelay    time.Duration
	Log           *slog.Logger
	// OnResult receives the metrics result of every sync/removal.
	OnResult func(result string)
	// PDNSNames lists the zones PowerDNS serves; with OnUnowned set, every
	// pass reports how many have no local owner (created outside the
	// platform or auto-provisioned by a supermaster). They are never adopted.
	// This check runs even when the resolver is disabled.
	PDNSNames func(ctx context.Context) ([]string, error)
	OnUnowned func(n int64)
}

func (r *Reconciler) interval() time.Duration {
	if r.Interval > 0 {
		return r.Interval
	}
	return 5 * time.Minute
}

func (r *Reconciler) after(d time.Duration) <-chan time.Time {
	if r.After != nil {
		return r.After(d)
	}
	return time.After(d)
}

func (r *Reconciler) readyAttempts() int {
	if r.ReadyAttempts > 0 {
		return r.ReadyAttempts
	}
	return 30
}

func (r *Reconciler) readyDelay() time.Duration {
	if r.ReadyDelay > 0 {
		return r.ReadyDelay
	}
	return time.Second
}

func (r *Reconciler) log() *slog.Logger {
	if r.Log != nil {
		return r.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (r *Reconciler) result(err error) {
	if r.OnResult == nil {
		return
	}
	switch {
	case err == nil:
		r.OnResult("ok")
	case errors.Is(err, ErrUnavailable):
		r.OnResult("unavailable")
	default:
		r.OnResult("error")
	}
}

func (r *Reconciler) enabled() bool { return r != nil && r.Client != nil && r.Client.Enabled() }

func (r *Reconciler) counting() bool { return r != nil && r.PDNSNames != nil && r.OnUnowned != nil }

// Run reconciles immediately and then every Interval until ctx is done.
func (r *Reconciler) Run(ctx context.Context) {
	if !r.enabled() && !r.counting() {
		return
	}
	for {
		if err := r.Reconcile(ctx); err != nil {
			r.log().WarnContext(ctx, "recursor reconcile", "err", err)
		}
		select {
		case <-ctx.Done():
			return
		case <-r.after(r.interval()):
		}
	}
}

func canonicalForward(z string) string {
	z = strings.ToLower(strings.TrimSpace(z))
	if !strings.HasSuffix(z, ".") {
		z += "."
	}
	return z
}

// Reconcile runs one pass; it returns the first error after trying every
// zone (the pass never stops half-way on one failure).
func (r *Reconciler) Reconcile(ctx context.Context) error {
	if !r.enabled() && !r.counting() {
		return nil
	}
	managed, err := r.Names(ctx)
	if err != nil {
		return fmt.Errorf("recursor reconcile: zone names: %w", err)
	}
	var unownedErr error
	if r.counting() {
		unownedErr = r.countUnowned(ctx, managed)
	}
	if !r.enabled() {
		return unownedErr
	}
	keep := map[string]bool{".": true}
	for _, s := range r.Static {
		keep[canonicalForward(s)] = true
	}
	var first error
	note := func(err error) {
		r.result(err)
		if err != nil && first == nil {
			first = err
		}
	}
	for _, z := range managed {
		keep[canonicalForward(z)] = true
		note(r.Client.SyncForward(ctx, z))
	}
	current, err := r.Client.ListForwards(ctx)
	if err != nil {
		return fmt.Errorf("recursor reconcile: list forwards: %w", err)
	}
	for _, z := range current {
		if !keep[canonicalForward(z)] {
			note(r.Client.RemoveForward(ctx, z))
		}
	}
	if first == nil {
		first = unownedErr
	}
	return first
}

// countUnowned reports the PowerDNS zones no tenant owns.
func (r *Reconciler) countUnowned(ctx context.Context, managed []string) error {
	served, err := r.PDNSNames(ctx)
	if err != nil {
		return fmt.Errorf("recursor reconcile: PowerDNS zones: %w", err)
	}
	owned := make(map[string]bool, len(managed))
	for _, z := range managed {
		owned[canonicalForward(z)] = true
	}
	var n int64
	for _, z := range served {
		if !owned[canonicalForward(z)] {
			n++
		}
	}
	if n > 0 {
		r.log().WarnContext(ctx, "PowerDNS serves zones with no local owner (not adopted)", "count", n)
	}
	r.OnUnowned(n)
	return nil
}

// ReconcileNow waits (bounded) until the recursor answers — e.g. after its
// container was restarted by a configuration change — and runs one pass.
func (r *Reconciler) ReconcileNow(ctx context.Context) error {
	if !r.enabled() {
		return nil
	}
	var err error
	for i := 0; i < r.readyAttempts(); i++ {
		if err = r.Client.Ready(ctx); err == nil {
			return r.Reconcile(ctx)
		}
		if i == r.readyAttempts()-1 {
			break
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.after(r.readyDelay()):
		}
	}
	return err
}
