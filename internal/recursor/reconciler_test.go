package recursor

import (
	"context"
	"errors"
	"sort"
	"sync"
	"testing"
	"time"
)

type names struct {
	mu   sync.Mutex
	list []string
	err  error
}

func (n *names) get(context.Context) ([]string, error) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.list...), n.err
}

func forwardNames(f *Fake) []string {
	out := []string{}
	for z := range f.Forwards() {
		out = append(out, z)
	}
	sort.Strings(out)
	return out
}

func TestReconcilePushesManagedAndRemovesUnmanaged(t *testing.T) {
	f := NewFake()
	f.Seed("stale.test.", "1.2.3.4:53")
	f.Seed(".", "9.9.9.9:53")
	f.Seed("corp.static.", "10.0.0.53:53")
	n := &names{list: []string{"a.test.", "b.test."}}
	var results []string
	r := &Reconciler{Client: f, Names: n.get, Static: []string{"CORP.static"}, OnResult: func(res string) { results = append(results, res) }}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	got := forwardNames(f)
	want := []string{".", "a.test.", "b.test.", "corp.static."}
	if len(got) != len(want) {
		t.Fatalf("forwards = %v", got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("forwards = %v", got)
		}
	}
	if len(results) != 3 { // 2 syncs + 1 removal
		t.Fatalf("results = %v", results)
	}
	// failures are counted and reported, the pass continues
	f.FailNext("SyncForward", ErrUnavailable)
	f.Seed("stale2.test.", "x")
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("sync failure not reported")
	}
	if _, ok := f.Forwards()["stale2.test."]; ok {
		t.Fatal("pass stopped at the first failure")
	}
	f.FailNext("RemoveForward", ErrUnavailable)
	f.Seed("stale3.test.", "x")
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("removal failure not reported")
	}
	f.FailNext("ListForwards", ErrUnavailable)
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("list failure not reported")
	}
	n.err = errors.New("db down")
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("names failure not reported")
	}
}

func TestReconcileDisabledIsNoop(t *testing.T) {
	f := &Fake{}
	r := &Reconciler{Client: f, Names: func(context.Context) ([]string, error) { t.Fatal("names read"); return nil, nil }}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := r.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.Run(ctx)
	var nilRec *Reconciler
	if err := nilRec.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestRunReconcilesAtStartAndOnInterval(t *testing.T) {
	f := NewFake()
	n := &names{list: []string{"a.test."}}
	ticks := make(chan time.Time)
	var gotInterval time.Duration
	r := &Reconciler{Client: f, Names: n.get, Interval: 42 * time.Second,
		After: func(d time.Duration) <-chan time.Time { gotInterval = d; return ticks }}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	waitFor(t, func() bool { _, ok := f.Forwards()["a.test."]; return ok })
	n.mu.Lock()
	n.list = []string{"b.test."}
	n.mu.Unlock()
	ticks <- time.Now()
	waitFor(t, func() bool { _, ok := f.Forwards()["b.test."]; _, old := f.Forwards()["a.test."]; return ok && !old })
	cancel()
	<-done
	if gotInterval != 42*time.Second {
		t.Fatalf("interval = %v", gotInterval)
	}
	// defaults: 5 minutes and time.After
	d := &Reconciler{}
	if d.interval() != 5*time.Minute || d.after(time.Nanosecond) == nil {
		t.Fatal("defaults")
	}
}

func TestReconcileNowWaitsForReadiness(t *testing.T) {
	f := NewFake()
	f.SetReady(false)
	n := &names{list: []string{"a.test."}}
	polls := 0
	r := &Reconciler{Client: f, Names: n.get, ReadyAttempts: 5, ReadyDelay: time.Millisecond,
		After: func(time.Duration) <-chan time.Time {
			polls++
			if polls == 2 {
				f.SetReady(true)
			}
			c := make(chan time.Time, 1)
			c <- time.Now()
			return c
		}}
	if err := r.ReconcileNow(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Forwards()["a.test."]; !ok || polls != 2 {
		t.Fatalf("polls = %d forwards = %v", polls, f.Forwards())
	}
	// never ready: bounded, then an error
	f.SetReady(false)
	polls = 0
	r.After = func(time.Duration) <-chan time.Time {
		polls++
		c := make(chan time.Time, 1)
		c <- time.Now()
		return c
	}
	if err := r.ReconcileNow(context.Background()); !errors.Is(err, ErrUnavailable) || polls != 4 {
		t.Fatalf("never ready = %v polls %d", err, polls)
	}
	// cancelled while waiting
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r.After = func(time.Duration) <-chan time.Time { return make(chan time.Time) }
	if err := r.ReconcileNow(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled = %v", err)
	}
	// defaults
	d := &Reconciler{}
	if d.readyAttempts() != 30 || d.readyDelay() != time.Second {
		t.Fatal("ready defaults")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met")
		}
		time.Sleep(time.Millisecond)
	}
}

// T063: PowerDNS zones with no local owner (created outside the platform or
// auto-provisioned by a supermaster) are counted — never adopted — even when
// the resolver is disabled.
func TestReconcileCountsUnownedZones(t *testing.T) {
	n := &names{list: []string{"a.test.", "B.test"}}
	pd := &names{list: []string{"a.test.", "b.test.", "outside.test.", "auto.test"}}
	var mu sync.Mutex
	var got []int64
	count := func() int { mu.Lock(); defer mu.Unlock(); return len(got) }
	r := &Reconciler{Client: &Fake{}, Names: n.get, PDNSNames: pd.get, OnUnowned: func(c int64) { mu.Lock(); got = append(got, c); mu.Unlock() }}
	if err := r.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != 2 {
		t.Fatalf("unowned = %v", got)
	}
	pd.mu.Lock()
	pd.err = errors.New("pdns down")
	pd.mu.Unlock()
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("PowerDNS listing failure not reported")
	}
	n.mu.Lock()
	n.err = errors.New("db down")
	n.mu.Unlock()
	pd.mu.Lock()
	pd.err = nil
	pd.mu.Unlock()
	if err := r.Reconcile(context.Background()); err == nil {
		t.Fatal("names failure not reported")
	}
	// Run works with only the unowned check (resolver disabled)
	n.mu.Lock()
	n.err = nil
	n.mu.Unlock()
	ctx, cancel := context.WithCancel(context.Background())
	ticks := make(chan time.Time)
	r.After = func(time.Duration) <-chan time.Time { return ticks }
	done := make(chan struct{})
	go func() { r.Run(ctx); close(done) }()
	waitFor(t, func() bool { return count() >= 2 })
	cancel()
	<-done
	// the recursor part still runs when enabled
	f := NewFake()
	r2 := &Reconciler{Client: f, Names: n.get, PDNSNames: pd.get, OnUnowned: func(int64) {}}
	if err := r2.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, ok := f.Forwards()["a.test."]; !ok {
		t.Fatal("recursor part skipped")
	}
}
