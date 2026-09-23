package ipamsync

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/go-freya/freya/services/dns/internal/stream"
)

const (
	tenantA = "11111111-1111-7111-8111-111111111111"
	tenantB = "22222222-2222-7222-8222-222222222222"
	tenantC = "33333333-3333-7333-8333-333333333333"
)

type handled struct {
	mu   sync.Mutex
	list []string // tenant/id
}

func (h *handled) add(tenant, id string) {
	h.mu.Lock()
	h.list = append(h.list, tenant+"/"+id)
	h.mu.Unlock()
}

func (h *handled) snapshot() []string {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]string(nil), h.list...)
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func addEvent(t *testing.T, m *stream.Memory, tenant, typ, data string) {
	t.Helper()
	if _, err := m.XAdd(context.Background(), stream.Key(tenant), map[string]string{"type": typ, "data": data, "to": "*", "at": "1"}, 0); err != nil {
		t.Fatal(err)
	}
}

func ev(id string) string {
	return `{"action":"created","id":"` + id + `","address":"192.0.2.10","hostname":"web.example.com"}`
}

// T049: start after the current tail per tenant, read every configured tenant,
// ignore own dns.* and foreign types, count malformed entries, keep going on
// handler errors, stop on cancel.
func TestConsumerRun(t *testing.T) {
	m := stream.NewMemory()
	addEvent(t, m, tenantA, TypeCreated, ev("old-a")) // before start: never replayed
	h := &handled{}
	var drops []string
	var dmu sync.Mutex
	c := &Consumer{Reader: m, Tenants: []string{tenantA, tenantB}, Block: 5 * time.Millisecond, RetryDelay: time.Millisecond,
		Handle: func(_ context.Context, tenant string, e Event) error {
			h.add(tenant, e.ID)
			if e.ID == "fail" {
				return errors.New("boom")
			}
			return nil
		},
		OnDrop: func(reason string) { dmu.Lock(); drops = append(drops, reason); dmu.Unlock() },
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { c.Run(ctx); close(done) }()
	waitFor(t, c.Started)

	addEvent(t, m, tenantA, "dns.record.changed", `{"zone":"example.com."}`)
	addEvent(t, m, tenantA, TypeCreated, `{bad`)
	addEvent(t, m, tenantA, TypeCreated, ev("fail"))
	addEvent(t, m, tenantA, TypeUpdated, ev("a-1"))
	addEvent(t, m, tenantB, TypeDeleted, ev("b-1"))
	addEvent(t, m, tenantC, TypeCreated, ev("c-1")) // not configured
	waitFor(t, func() bool { return len(h.snapshot()) >= 3 })
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop on cancel")
	}
	got := h.snapshot()
	want := map[string]bool{tenantA + "/fail": true, tenantA + "/a-1": true, tenantB + "/b-1": true}
	if len(got) != 3 {
		t.Fatalf("handled = %v", got)
	}
	for _, g := range got {
		if !want[g] {
			t.Fatalf("unexpected %q in %v", g, got)
		}
	}
	dmu.Lock()
	defer dmu.Unlock()
	if len(drops) != 1 || drops[0] != "malformed" {
		t.Fatalf("drops = %v", drops)
	}
}

// failingReader fails XLast/XRead a few times before delegating.
type failingReader struct {
	*stream.Memory
	mu        sync.Mutex
	lastFails int
	readFails int
}

func (f *failingReader) XLast(ctx context.Context, key string) (string, error) {
	f.mu.Lock()
	if f.lastFails > 0 {
		f.lastFails--
		f.mu.Unlock()
		return "", errors.New("down")
	}
	f.mu.Unlock()
	return f.Memory.XLast(ctx, key)
}

func (f *failingReader) XRead(ctx context.Context, key, after string, block time.Duration, count int64) ([]stream.Entry, error) {
	f.mu.Lock()
	if f.readFails > 0 {
		f.readFails--
		f.mu.Unlock()
		return nil, errors.New("down")
	}
	f.mu.Unlock()
	return f.Memory.XRead(ctx, key, after, block, count)
}

// The start position is retried until the bus answers (no replay of the whole
// stream), and read failures back off and recover.
func TestConsumerRetriesStartAndReads(t *testing.T) {
	m := stream.NewMemory()
	addEvent(t, m, tenantA, TypeCreated, ev("old"))
	r := &failingReader{Memory: m, lastFails: 2, readFails: 2}
	h := &handled{}
	c := &Consumer{Reader: r, Tenants: []string{tenantA}, Block: 5 * time.Millisecond, RetryDelay: time.Millisecond,
		Handle: func(_ context.Context, tenant string, e Event) error { h.add(tenant, e.ID); return nil }}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go c.Run(ctx)
	waitFor(t, c.Started)
	addEvent(t, m, tenantA, TypeCreated, ev("new"))
	waitFor(t, func() bool { return len(h.snapshot()) == 1 })
	if got := h.snapshot(); got[0] != tenantA+"/new" {
		t.Fatalf("handled = %v", got)
	}
}

func TestConsumerNoTenantsReturns(t *testing.T) {
	c := &Consumer{Reader: stream.NewMemory(), Handle: func(context.Context, string, Event) error { return nil }}
	done := make(chan struct{})
	go func() { c.Run(context.Background()); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Run without tenants must return")
	}
}
