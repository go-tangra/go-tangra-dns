package audit

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/go-freya/freya/services/dns/internal/store"
)

const tn = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

type memStore struct {
	mu   sync.Mutex
	rows []store.AuditRow
	err  error
}

func (m *memStore) AppendAudit(_ context.Context, r store.AuditRow) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.err != nil {
		return m.err
	}
	m.rows = append(m.rows, r)
	return nil
}

func (m *memStore) all() []store.AuditRow {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]store.AuditRow(nil), m.rows...)
}

func ok(t EventType) Event {
	return Event{TenantID: tn, EventType: t, ActorKind: ActorUser, ActorID: "u1", SubjectKind: SubjectZone, SubjectID: "z1", Outcome: OutcomeOK}
}

func TestVocabulary(t *testing.T) {
	for _, want := range []string{"zone.create", "zone.update", "zone.delete", "zone.export", "zone.notify",
		"record.upsert", "record.delete", "template.create", "template.update", "template.delete",
		"supermaster.create", "supermaster.delete", "config.update", "config.apply", "config.restart",
		"sync.upsert", "sync.delete", "sync.skip", "challenge.present", "challenge.cleanup", "challenge.refused", "challenge.swept",
		"backup.export", "backup.import", "access.refused"} {
		if !Known(want) {
			t.Errorf("vocabulary lacks %s", want)
		}
	}
	if Known("zone.explode") || len(Vocabulary) != 25 {
		t.Fatalf("vocabulary = %d", len(Vocabulary))
	}
}

func TestValidate(t *testing.T) {
	if err := Validate(ok(ZoneCreate)); err != nil {
		t.Fatal(err)
	}
	bad := []func(*Event){
		func(e *Event) { e.EventType = "nope" },
		func(e *Event) { e.TenantID = "" },
		func(e *Event) { e.ActorKind = "robot" },
		func(e *Event) { e.SubjectKind = "planet" },
		func(e *Event) { e.Outcome = "maybe" },
	}
	for i, mut := range bad {
		e := ok(ZoneCreate)
		mut(&e)
		if Validate(e) == nil {
			t.Errorf("case %d accepted", i)
		}
	}
	for _, k := range []string{ActorModule, ActorIPAMSync, ActorSystem} {
		for _, sk := range []string{SubjectRecord, SubjectTemplate, SubjectSupermaster, SubjectConfig, SubjectContainer, SubjectSync, SubjectChallenge, SubjectBackup, SubjectSystem} {
			e := ok(SyncUpsert)
			e.ActorKind, e.SubjectKind = k, sk
			if err := Validate(e); err != nil {
				t.Errorf("actor %s subject %s: %v", k, sk, err)
			}
		}
	}
	for _, o := range []string{OutcomeRefused, OutcomeError} {
		e := ok(ChallengeRefused)
		e.Outcome = o
		if err := Validate(e); err != nil {
			t.Errorf("outcome %s: %v", o, err)
		}
	}
	platform := ok(ConfigApply)
	platform.TenantID, platform.SubjectKind = NilTenant, SubjectConfig
	if err := Validate(platform); err != nil {
		t.Fatalf("platform-scope event: %v", err)
	}
}

func TestRedaction(t *testing.T) {
	d := Redact(map[string]any{
		"api_key": "k1", "X-API-Key": "k2", "pdns_apikey": "k3", "smtp_password": "pw", "relay_token": "tok", "client_secret": "s",
		"credentials": "c", "Authorization": "Bearer x", "content": "1.2.3.4", "values": []any{"v"}, "value": "txt",
		"rdata": "r", "record_data": "d", "file_body": "listen=...", "rendered": "x", "file": "/etc/x", "body": "b",
		"zone": "example.com.", "name": "www.example.com.", "type": "A", "long": strings.Repeat("x", 400),
		"nested": map[string]any{"api_key": "t", "keep": "v", "list": []any{map[string]any{"password": "p", "n": 1}, "s"}},
	})
	for _, k := range []string{"api_key", "X-API-Key", "pdns_apikey", "smtp_password", "relay_token", "client_secret", "credentials",
		"Authorization", "content", "values", "value", "rdata", "record_data", "file_body", "rendered", "file", "body"} {
		if _, found := d[k]; found {
			t.Errorf("%s leaked", k)
		}
	}
	if d["zone"] != "example.com." || d["name"] != "www.example.com." || d["type"] != "A" || len(d["long"].(string)) != 256 {
		t.Fatalf("kept values: %+v", d)
	}
	nested := d["nested"].(map[string]any)
	if _, found := nested["api_key"]; found || nested["keep"] != "v" {
		t.Fatalf("nested: %+v", nested)
	}
	item := nested["list"].([]any)[0].(map[string]any)
	if _, found := item["password"]; found || item["n"] != 1 {
		t.Fatalf("list item: %+v", item)
	}
}

func TestWriterRecordsAndFlushes(t *testing.T) {
	st := &memStore{}
	w := NewWriter(st, nil)
	e := ok(RecordUpsert)
	e.Reason = strings.Repeat("r", 300)
	e.Details = map[string]any{"name": "www.example.com.", "type": "A", "content": "never"}
	if err := w.Record(context.Background(), e); err != nil {
		t.Fatal(err)
	}
	if err := w.Record(context.Background(), Event{EventType: "bogus"}); err == nil {
		t.Fatal("invalid event queued")
	}
	w.Flush(context.Background())
	rows := st.all()
	if len(rows) != 1 {
		t.Fatalf("rows = %d", len(rows))
	}
	r := rows[0]
	if r.Action != "record.upsert" || r.ID == "" || r.At.IsZero() || len(r.Reason) != 256 || r.Detail["type"] != "A" {
		t.Fatalf("row = %+v", r)
	}
	if _, found := r.Detail["content"]; found {
		t.Fatal("record content in audit detail")
	}
	w.Close()
	w.Close() // idempotent
	if err := w.Record(context.Background(), ok(ZoneCreate)); err == nil {
		t.Fatal("record after close")
	}
	w.Flush(context.Background()) // no-op after close
	if w.Dropped() != 1 {
		t.Fatalf("dropped = %d", w.Dropped())
	}
}

func TestWriterErrorsAndBackpressure(t *testing.T) {
	st := &memStore{err: errors.New("db down")}
	var mu sync.Mutex
	var errs []error
	w := newWriter(st, func(err error) { mu.Lock(); errs = append(errs, err); mu.Unlock() }, 1)
	// not started: the second record overflows the queue of 1
	_ = w.Record(context.Background(), ok(ZoneCreate))
	_ = w.Record(context.Background(), ok(ZoneCreate))
	if w.Dropped() != 1 {
		t.Fatalf("dropped = %d", w.Dropped())
	}
	w.tick = time.Millisecond
	w.start()
	w.Flush(context.Background())
	time.Sleep(5 * time.Millisecond)
	w.Close()
	mu.Lock()
	defer mu.Unlock()
	if len(errs) < 2 {
		t.Fatalf("errors = %v", errs)
	}
	nw := newWriter(st, nil, 1)
	nw.onError(errors.New("ignored")) // default handler is a no-op
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	nw.Flush(ctx) // not started + cancelled: returns
}

type recorder struct{ got []Event }

func (r *recorder) Record(_ context.Context, e Event) error { r.got = append(r.got, e); return nil }

func TestEmitAndActorOf(t *testing.T) {
	Emit(context.Background(), nil, ok(ZoneCreate)) // nil recorder: no-op
	r := &recorder{}
	Emit(context.Background(), r, ok(ZoneCreate))
	if len(r.got) != 1 {
		t.Fatal("emit")
	}
	for in, want := range map[string]string{"user": ActorUser, "module": ActorModule, "ipam-sync": ActorIPAMSync, "system": ActorSystem, "": ActorUser} {
		if ActorOf(in) != want {
			t.Errorf("ActorOf(%q) = %q", in, ActorOf(in))
		}
	}
}
