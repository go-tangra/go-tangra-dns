package recursor

import (
	"context"
	"os"
	"strconv"
	"sync"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	appViewer "github.com/go-tangra/go-tangra-common/viewer"
	"github.com/go-tangra/go-tangra-dns/internal/data"
)

const defaultReconcileInterval = 5 * time.Minute

// Reconciler periodically (and at startup) re-pushes every managed zone's
// forward entry to the recursor. This populates the recursor on first boot,
// recovers from drift, and re-points entries after the authoritative
// server's IP changes.
type Reconciler struct {
	log      *log.Helper
	client   *Client
	zoneRepo *data.ZoneRepo
	interval time.Duration

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	running bool
	mu      sync.Mutex
}

// NewReconciler builds the reconciler.
func NewReconciler(ctx *bootstrap.Context, client *Client, zoneRepo *data.ZoneRepo) *Reconciler {
	interval := defaultReconcileInterval
	if v := os.Getenv("RECURSOR_RECONCILE_INTERVAL_SECONDS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			interval = time.Duration(n) * time.Second
		}
	}
	return &Reconciler{
		log:      ctx.NewLoggerHelper("dns/recursor/reconciler"),
		client:   client,
		zoneRepo: zoneRepo,
		interval: interval,
	}
}

// Start runs an initial reconcile and then a periodic one. No-op when the
// recursor integration is disabled.
func (r *Reconciler) Start() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.running {
		return nil
	}
	if !r.client.Enabled() {
		r.log.Info("recursor integration disabled, reconciler not started")
		return nil
	}

	base := appViewer.NewSystemViewerContext(context.Background())
	r.ctx, r.cancel = context.WithCancel(base)
	r.running = true

	r.wg.Add(1)
	go r.loop()
	return nil
}

// Stop halts the reconciler.
func (r *Reconciler) Stop() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.running {
		return nil
	}
	r.cancel()
	r.wg.Wait()
	r.running = false
	return nil
}

func (r *Reconciler) loop() {
	defer r.wg.Done()
	// Initial reconcile shortly after boot (give the recursor a moment).
	timer := time.NewTimer(3 * time.Second)
	defer timer.Stop()
	ticker := time.NewTicker(r.interval)
	defer ticker.Stop()

	for {
		select {
		case <-r.ctx.Done():
			return
		case <-timer.C:
			r.reconcileOnce(r.ctx)
		case <-ticker.C:
			r.reconcileOnce(r.ctx)
		}
	}
}

// ReconcileNow runs a one-off reconcile with a fresh context. Used to
// re-point forward zones immediately after the authoritative container
// restarts (and may have changed IP).
func (r *Reconciler) ReconcileNow() {
	if !r.client.Enabled() {
		return
	}
	ctx := appViewer.NewSystemViewerContext(context.Background())
	r.reconcileOnce(ctx)
}

func (r *Reconciler) reconcileOnce(ctx context.Context) {
	names, err := r.zoneRepo.AllZoneNames(ctx)
	if err != nil {
		r.log.Warnf("reconcile: list zones: %v", err)
		return
	}
	var synced, failed int
	for _, name := range names {
		if err := r.client.SyncForwardZone(ctx, name); err != nil {
			r.log.Warnf("reconcile: sync %s: %v", name, err)
			failed++
			continue
		}
		synced++
	}
	if synced > 0 || failed > 0 {
		r.log.Infof("recursor reconcile complete: %d synced, %d failed", synced, failed)
	}
}
