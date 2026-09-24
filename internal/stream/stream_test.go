package stream

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	tA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"
	uA = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c77"
	uB = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c88"
)

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(2 * time.Millisecond)
	}
}

func recv(t *testing.T, s *Subscription) Event {
	t.Helper()
	select {
	case ev, ok := <-s.Events():
		if !ok {
			t.Fatal("subscription closed")
		}
		return ev
	case <-time.After(3 * time.Second):
		t.Fatal("no event")
	}
	return Event{}
}

func TestIDs(t *testing.T) {
	at := time.UnixMilli(1_700_000_000_123)
	id := ID(at, 7)
	ms, seq, ok := ParseID(id)
	if !ok || ms != 1_700_000_000_123 || seq != 7 {
		t.Fatalf("parse %s → %d %d %v", id, ms, seq, ok)
	}
	for _, bad := range []string{"", "1", "a-b", "1-b"} {
		if _, _, ok := ParseID(bad); ok {
			t.Errorf("%q parsed", bad)
		}
	}
	if !Less("1-0", "2-0") || !Less("1-0", "1-1") || Less("1-1", "1-0") || Less("2-0", "1-5") {
		t.Fatal("Less")
	}
	if Key(tA) != "platform:events:"+tA {
		t.Fatal("key")
	}
}

func TestMemoryClient(t *testing.T) {
	m := NewMemory()
	ctx := context.Background()
	if _, err := m.XRead(ctx, "k", "", 0, 10); err != nil {
		t.Fatal(err)
	}
	id1, _ := m.XAdd(ctx, "k", map[string]string{"a": "1"}, 0)
	id2, _ := m.XAdd(ctx, "k", map[string]string{"a": "2"}, 0)
	// $ / "" read the tail: nothing yet, then a blocking read wakes on XAdd.
	if out, _ := m.XRead(ctx, "k", "$", 0, 10); len(out) != 0 {
		t.Fatalf("tail read %v", out)
	}
	done := make(chan []Entry, 1)
	go func() { out, _ := m.XRead(ctx, "k", "", time.Second, 10); done <- out }()
	time.Sleep(10 * time.Millisecond)
	id3, _ := m.XAdd(ctx, "k", map[string]string{"a": "3"}, 0)
	if out := <-done; len(out) != 1 || out[0].ID != id3 {
		t.Fatalf("woken read %v", out)
	}
	if out, _ := m.XRead(ctx, "k", id1, 0, 1); len(out) != 1 || out[0].ID != id2 {
		t.Fatalf("after read %v", out)
	}
	if out, _ := m.XRange(ctx, "k", "", 10); len(out) != 3 {
		t.Fatalf("range %v", out)
	}
	if out, _ := m.XRange(ctx, "k", id2, 10); len(out) != 1 {
		t.Fatalf("range after %v", out)
	}
	// Blocking read: timeout and cancelled context.
	if out, err := m.XRead(ctx, "k", id3, 10*time.Millisecond, 10); err != nil || len(out) != 0 {
		t.Fatalf("timeout read %v %v", out, err)
	}
	cctx, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := m.XRead(cctx, "k", id3, time.Second, 10); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancelled read %v", err)
	}
	// MaxLen trims the head; XTrimMinID drops old ids.
	for i := 0; i < 5; i++ {
		_, _ = m.XAdd(ctx, "k", nil, 4)
	}
	if m.Len("k") != 4 {
		t.Fatalf("maxlen %d", m.Len("k"))
	}
	if err := m.XTrimMinID(ctx, "k", ID(time.Now().Add(time.Hour), 0)); err != nil || m.Len("k") != 0 {
		t.Fatalf("trim %v %d", err, m.Len("k"))
	}
	// Counters expire.
	now := time.Unix(1_700_000_000, 0)
	m.Now = func() time.Time { return now }
	n1, _ := m.Incr(ctx, "c", time.Minute)
	n2, _ := m.Incr(ctx, "c", time.Minute)
	now = now.Add(2 * time.Minute)
	n3, _ := m.Incr(ctx, "c", time.Minute)
	n4, _ := m.Incr(ctx, "c", 0)
	if n1 != 1 || n2 != 2 || n3 != 1 || n4 != 2 {
		t.Fatalf("incr %d %d %d %d", n1, n2, n3, n4)
	}
	if err := m.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	m.Close()
	if m.Len("k") != 0 {
		t.Fatal("close must drop streams")
	}
	// Outage: every call fails, including a blocked read that wakes to an error.
	boom := errors.New("down")
	m.SetErr(boom)
	for _, err := range []error{
		func() error { _, err := m.XAdd(ctx, "k", nil, 0); return err }(),
		func() error { _, err := m.XRead(ctx, "k", "", 0, 1); return err }(),
		func() error { _, err := m.XRange(ctx, "k", "", 1); return err }(),
		m.XTrimMinID(ctx, "k", "0-0"),
		func() error { _, err := m.XLast(ctx, "k"); return err }(),
		func() error { _, err := m.Incr(ctx, "c", 0); return err }(),
		m.Ping(ctx),
	} {
		if !errors.Is(err, boom) {
			t.Fatalf("outage: %v", err)
		}
	}
	m.SetErr(nil)
	if last, err := m.XLast(ctx, "k"); err != nil || last != "" {
		t.Fatalf("xlast empty: %q %v", last, err)
	}
	idL, _ := m.XAdd(ctx, "k", nil, 0)
	if last, _ := m.XLast(ctx, "k"); last != idL {
		t.Fatalf("xlast %q", last)
	}
	errs := make(chan error, 1)
	go func() { _, err := m.XRead(ctx, "k", "", time.Second, 1); errs <- err }()
	time.Sleep(10 * time.Millisecond)
	m.mu.Lock()
	m.Err = boom // already under the lock
	ch := m.notify
	m.notify = make(chan struct{})
	m.mu.Unlock()
	close(ch)
	if err := <-errs; !errors.Is(err, boom) {
		t.Fatalf("woken outage: %v", err)
	}
}

func TestLimiter(t *testing.T) {
	m := NewMemory()
	l := NewLimiter(m)
	ctx := context.Background()
	at := time.Unix(1_700_000_000, 0)
	if lim, err := l.Limited(ctx, "tenant", tA, 0, at); lim || err != nil {
		t.Fatal("zero limit must never limit")
	}
	for i := 0; i < 2; i++ {
		if lim, _ := l.Limited(ctx, "tenant", tA, 2, at); lim {
			t.Fatalf("call %d limited", i)
		}
	}
	if lim, _ := l.Limited(ctx, "tenant", tA, 2, at); !lim {
		t.Fatal("third call not limited")
	}
	if lim, _ := l.Limited(ctx, "tenant", tA, 2, at.Add(time.Minute)); lim {
		t.Fatal("next window limited")
	}
	m.SetErr(errors.New("down"))
	if lim, err := l.Limited(ctx, "tenant", tA, 2, at); !lim || err == nil {
		t.Fatal("outage must fail closed")
	}
	if RateKey("sender", uA, at) != "dns:rl:sender:"+uA+":28333333" {
		t.Fatal(RateKey("sender", uA, at))
	}
}

func TestValidateAndPublish(t *testing.T) {
	m := NewMemory()
	h := NewHub(m, Config{}, nil)
	defer h.Close()
	ctx := context.Background()
	if h.cfg.StreamsPerUser != 5 || h.cfg.StreamsPerTenant != 2000 || h.cfg.ReplayWindow != 5*time.Minute || h.cfg.MaxLen != DefaultMaxLen {
		t.Fatalf("defaults %+v", h.cfg)
	}
	for _, tc := range []struct {
		typ    string
		module bool
		err    error
	}{
		{"issued", false, nil},
		{"issued", true, ErrReserved},
		{"warden.secret-rotated", true, nil},
		{"Bad", true, ErrType},
		{"", true, ErrType},
		{strings.Repeat("a", 65), true, ErrType},
	} {
		if err := ValidateType(tc.typ, tc.module); !errors.Is(err, tc.err) {
			t.Errorf("%q/%v: %v", tc.typ, tc.module, err)
		}
	}
	// Targets and payloads.
	if _, err := h.PublishID(ctx, tA, nil, false, "x", nil, false); !errors.Is(err, ErrTargets) {
		t.Fatalf("no targets: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{uA}, true, "x", nil, false); !errors.Is(err, ErrTargets) {
		t.Fatalf("both: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, make([]string, MaxTargets+1), false, "x", nil, false); !errors.Is(err, ErrTargets) {
		t.Fatalf("too many: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{"a,b"}, false, "x", nil, false); !errors.Is(err, ErrTargets) {
		t.Fatalf("comma: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{uA}, false, "x", make(chan int), false); !errors.Is(err, ErrPayload) {
		t.Fatalf("unmarshalable: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{uA}, false, "x", "not json", false); !errors.Is(err, ErrPayload) {
		t.Fatalf("invalid json: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{uA}, false, "x", "{\n}", false); !errors.Is(err, ErrPayload) {
		t.Fatalf("newline: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{uA}, false, "x", strings.Repeat("1", MaxPayload+1), false); !errors.Is(err, ErrPayload) {
		t.Fatalf("large: %v", err)
	}
	if _, err := h.PublishID(ctx, tA, []string{uA}, false, "bad type", nil, false); !errors.Is(err, ErrType) {
		t.Fatalf("type: %v", err)
	}
	// Every accepted shape lands in the tenant stream.
	for _, data := range []any{nil, []byte(`{"a":1}`), json.RawMessage(`[1]`), `"s"`, map[string]int{"n": 1}} {
		if _, err := h.PublishID(ctx, tA, []string{uA, uB}, false, "x", data, false); err != nil {
			t.Fatalf("%T: %v", data, err)
		}
	}
	if err := h.Publish(ctx, tA, nil, true, "x", nil); err != nil {
		t.Fatal(err)
	}
	if m.Len(Key(tA)) != 6 {
		t.Fatalf("entries %d", m.Len(Key(tA)))
	}
	entries, _ := m.XRange(ctx, Key(tA), "", 10)
	if entries[0].Fields["to"] != uA+","+uB || entries[0].Fields["data"] != "{}" || entries[5].Fields["to"] != "*" || entries[5].Fields["at"] == "" {
		t.Fatalf("fields %v", entries)
	}
	m.SetErr(errors.New("down"))
	if _, err := h.PublishID(ctx, tA, []string{uA}, false, "x", nil, false); err == nil {
		t.Fatal("outage")
	}
}

func TestSubscribeFanoutReplayAndLimits(t *testing.T) {
	m := NewMemory()
	var clockMu sync.Mutex
	now := time.Now()
	clock := func() time.Time { clockMu.Lock(); defer clockMu.Unlock(); return now }
	m.Now = clock
	h := NewHub(m, Config{StreamsPerUser: 2, StreamsPerTenant: 3, ReplayWindow: time.Minute, ReadBlock: 20 * time.Millisecond, TrimInterval: 30 * time.Millisecond, RetryDelay: 10 * time.Millisecond}, nil)
	h.SetClock(clock)
	ctx := context.Background()
	a, err := h.Subscribe(ctx, tA, uA, "")
	if err != nil {
		t.Fatal(err)
	}
	b, _ := h.Subscribe(ctx, tA, uB, "")
	if h.OpenStreams() != 2 {
		t.Fatal("open")
	}
	// Live fan-out honours targets.
	_, _ = h.PublishID(ctx, tA, []string{uA}, false, "one", `{"n":1}`, false)
	_, _ = h.PublishID(ctx, tA, nil, true, "all", `{"n":2}`, false)
	if ev := recv(t, a); ev.Type != "one" || ev.Data != `{"n":1}` || ev.ID == "" {
		t.Fatalf("a1 %+v", ev)
	}
	if ev := recv(t, a); ev.Type != "all" {
		t.Fatalf("a2 %+v", ev)
	}
	ev := recv(t, b)
	if ev.Type != "all" {
		t.Fatalf("b %+v", ev)
	}
	lastB := ev.ID
	// Reconnect with Last-Event-ID replays what B missed and dedupes overlap.
	_, _ = h.PublishID(ctx, tA, []string{uB}, false, "missed", `{}`, false)
	if ev := recv(t, b); ev.Type != "missed" {
		t.Fatalf("live missed %+v", ev)
	}
	b.Close()
	b2, err := h.Subscribe(ctx, tA, uB, lastB)
	if err != nil {
		t.Fatal(err)
	}
	if ev := recv(t, b2); ev.Type != "missed" {
		t.Fatalf("replay %+v", ev)
	}
	_, _ = h.PublishID(ctx, tA, []string{uB}, false, "after", `{}`, false)
	if ev := recv(t, b2); ev.Type != "after" {
		t.Fatalf("after replay %+v", ev)
	}
	// Stale or malformed Last-Event-ID → reset; replay outage → reset too.
	for _, last := range []string{"garbage", ID(now.Add(-2*time.Minute), 0)} {
		s, _ := h.Subscribe(ctx, tA, uB, last)
		if ev := recv(t, s); ev.Type != "reset" || !strings.Contains(ev.Data, "replay_window") {
			t.Fatalf("%s: %+v", last, ev)
		}
		s.Close()
	}
	m.SetErr(errors.New("down"))
	s, _ := h.Subscribe(ctx, tA, uB, ID(now, 0))
	if ev := recv(t, s); ev.Type != "reset" || !strings.Contains(ev.Data, "replay_unavailable") {
		t.Fatalf("outage replay %+v", ev)
	}
	s.Close()
	m.SetErr(nil)
	// Limits per user and per tenant.
	c1, _ := h.Subscribe(ctx, tA, "u3", "")
	if _, err := h.Subscribe(ctx, tA, "u4", ""); !errors.Is(err, ErrTooMany) {
		t.Fatalf("tenant limit: %v", err)
	}
	c1.Close()
	c2, _ := h.Subscribe(ctx, tA, uA, "")
	if _, err := h.Subscribe(ctx, tA, uA, ""); !errors.Is(err, ErrTooMany) {
		t.Fatalf("user limit: %v", err)
	}
	c2.Close()
	c2.Close() // idempotent
	// The trim ticker drops entries older than the window.
	before := m.Len(Key(tA))
	clockMu.Lock()
	now = now.Add(2 * time.Minute)
	clockMu.Unlock()
	waitFor(t, func() bool { return m.Len(Key(tA)) < before })
	// A stalled reader is dropped once its buffer fills.
	for i := 0; i < connBuffer+5; i++ {
		_, _ = h.PublishID(ctx, tA, []string{uA}, false, "flood", `{}`, false)
	}
	waitFor(t, func() bool { _, open := <-a.Events(); return !open })
	// Read failures are logged and retried; a subscribe during the outage is refused.
	m.SetErr(errors.New("down"))
	if _, err := h.Subscribe(ctx, "other-tenant", uA, ""); err == nil {
		t.Fatal("subscribe during outage")
	}
	d, _ := h.Subscribe(ctx, tA, uA, "")
	time.Sleep(30 * time.Millisecond)
	m.SetErr(nil)
	_, _ = h.PublishID(ctx, tA, []string{uA}, false, "back", `{}`, false)
	if ev := recv(t, d); ev.Type != "back" {
		t.Fatalf("after outage %+v", ev)
	}
	// Close ends every subscription and refuses new ones.
	h.Close()
	if _, open := <-d.Events(); open {
		t.Fatal("still open after Close")
	}
	if _, err := h.Subscribe(ctx, tA, uA, ""); err == nil {
		t.Fatal("subscribe after close")
	}
	if h.OpenStreams() != 0 {
		t.Fatal("streams after close")
	}
}

func TestSubscriptionPushDedupes(t *testing.T) {
	m := NewMemory()
	h := NewHub(m, Config{RetryDelay: time.Millisecond}, nil)
	defer h.Close()
	s, _ := h.Subscribe(context.Background(), tA, uA, "")
	if !s.push(Event{ID: "5-0", Type: "a"}) || !s.push(Event{ID: "4-0", Type: "old"}) || !s.push(Event{Type: "no-id"}) {
		t.Fatal("push")
	}
	if ev := recv(t, s); ev.Type != "a" {
		t.Fatal(ev)
	}
	if ev := recv(t, s); ev.Type != "no-id" {
		t.Fatalf("older id must be dropped, got %+v", ev)
	}
	s.Close()
	if !s.push(Event{ID: "9-0"}) {
		t.Fatal("push after close must be a no-op")
	}
}

type noFlush struct{ http.ResponseWriter }

func TestServeSSE(t *testing.T) {
	m := NewMemory()
	h := NewHub(m, Config{ReadBlock: 10 * time.Millisecond}, nil)
	defer h.Close()
	ctx := context.Background()
	if Frame(Event{ID: "1-0", Type: "x", Data: "{\"a\":\n1}\r"}) != "id: 1-0\nevent: x\ndata: {\"a\":1}\n\n" {
		t.Fatal(Frame(Event{ID: "1-0", Type: "x", Data: "{}"}))
	}
	// Live event, heartbeat and the age limit.
	sub, _ := h.Subscribe(ctx, tA, uA, "")
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "/stream", nil)
	go func() {
		time.Sleep(20 * time.Millisecond)
		_, _ = h.PublishID(ctx, tA, []string{uA}, false, "hello", `{"x":1}`, false)
	}()
	ServeSSE(w, r, sub, "inst-1", 15*time.Millisecond, 150*time.Millisecond)
	body := w.Body.String()
	if w.Code != 200 || w.Header().Get("Content-Type") != "text/event-stream" || !strings.HasPrefix(body, "retry: 3000\n: connected inst-1\n\n") || !strings.Contains(body, "event: hello\ndata: {\"x\":1}\n\n") || !strings.Contains(body, ": ping\n\n") || !strings.HasSuffix(body, "event: bye\ndata: {}\n\n") {
		t.Fatalf("%d %q", w.Code, body)
	}
	// Client leaves: the handler returns and the subscription closes.
	sub2, _ := h.Subscribe(ctx, tA, uA, "")
	cctx, cancel := context.WithCancel(ctx)
	w2 := httptest.NewRecorder()
	done := make(chan struct{})
	go func() { ServeSSE(w2, r.WithContext(cctx), sub2, "i", 0, 0); close(done) }()
	time.Sleep(10 * time.Millisecond)
	cancel()
	<-done
	if _, open := <-sub2.Events(); open {
		t.Fatal("subscription open after client left")
	}
	// Subscription closed by the hub ends the response.
	sub3, _ := h.Subscribe(ctx, tA, uA, "")
	w3 := httptest.NewRecorder()
	done = make(chan struct{})
	go func() { ServeSSE(w3, r, sub3, "i", time.Second, time.Second); close(done) }()
	time.Sleep(10 * time.Millisecond)
	sub3.Close()
	<-done
	// A writer that cannot flush is refused.
	sub4, _ := h.Subscribe(ctx, tA, uA, "")
	w4 := httptest.NewRecorder()
	ServeSSE(noFlush{w4}, r, sub4, "i", 0, 0)
	if w4.Code != 500 {
		t.Fatalf("no flusher: %d", w4.Code)
	}
	sub4.Close()
}

func TestCloseDuringOutage(t *testing.T) {
	m := NewMemory()
	h := NewHub(m, Config{ReadBlock: 5 * time.Millisecond, RetryDelay: time.Minute}, nil)
	s, err := h.Subscribe(context.Background(), tA, uA, "")
	if err != nil {
		t.Fatal(err)
	}
	m.SetErr(errors.New("down"))
	time.Sleep(30 * time.Millisecond) // the loop is now waiting to retry
	done := make(chan struct{})
	go func() { h.Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Close blocked on the retry wait")
	}
	if _, open := <-s.Events(); open {
		t.Fatal("subscription open")
	}
}
