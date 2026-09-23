package events

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/stream"
)

const tn = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

func sample() store.Zone {
	return store.Zone{ID: "z1", TenantID: tn, Name: "example.com.", PDNSID: "SECRET-PDNS-ID=2F", Kind: store.KindMaster,
		Masters: []string{"192.0.2.53"}, Description: "SECRET-DESCRIPTION", Origin: store.OriginManual, Nameservers: []string{"ns1.example.com."}}
}

// Payloads never carry record values, API keys, PowerDNS ids or free text.
func TestPayloadsAreContentSafe(t *testing.T) {
	zraw, _ := json.Marshal(ZoneOf(sample(), "user"))
	rraw, _ := json.Marshal(RecordOf(sample(), "www.example.com.", "A", ActionUpserted, SourceAPI))
	for _, raw := range [][]byte{zraw, rraw} {
		s := string(raw)
		for _, leak := range []string{"SECRET", "192.0.2.53", "api_key", "content", "records", "values", "pdns", "masters", "description"} {
			if strings.Contains(s, leak) {
				t.Errorf("payload leaks %q: %s", leak, s)
			}
		}
	}
	var z map[string]any
	_ = json.Unmarshal(zraw, &z)
	for _, k := range []string{"zone_id", "zone", "kind", "origin", "actor_kind"} {
		if _, ok := z[k]; !ok {
			t.Errorf("zone payload lacks %s", k)
		}
	}
	var r map[string]any
	_ = json.Unmarshal(rraw, &r)
	if r["name"] != "www.example.com." || r["type"] != "A" || r["action"] != "upserted" || r["source"] != "api" || len(r) != 6 {
		t.Fatalf("record payload = %v", r)
	}
}

func TestEmitAndRecorder(t *testing.T) {
	EmitZone(context.Background(), nil, ZoneCreated, sample(), "user") // nil publisher: no-op
	EmitRecord(context.Background(), nil, sample(), "a.", "A", ActionDeleted, SourceIPAM)
	r := &Recorder{}
	EmitZone(context.Background(), r, ZoneDeleted, sample(), "ipam-sync")
	EmitRecord(context.Background(), r, sample(), "_acme-challenge.example.com.", "TXT", ActionUpserted, SourceACME)
	if len(r.Events) != 2 || r.Events[0].Type != ZoneDeleted || r.Events[0].TenantID != tn || r.Events[1].Type != RecordChanged {
		t.Fatalf("recorded = %+v", r.Events)
	}
	if p := r.Events[1].Payload.(RecordPayload); p.Source != SourceACME {
		t.Fatal("source")
	}
	for _, typ := range Types {
		if err := stream.ValidateType(typ, true); err != nil {
			t.Errorf("event type %s invalid for the hub: %v", typ, err)
		}
	}
}

func TestHubPublisherRelaysToSubscribers(t *testing.T) {
	HubPublisher{}.Publish(context.Background(), tn, ZoneCreated, ZonePayload{}) // nil hub: no-op
	hub := stream.NewHub(stream.NewMemory(), stream.Config{}, nil)
	defer hub.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	sub, err := hub.Subscribe(ctx, tn, "u1", "")
	if err != nil {
		t.Fatal(err)
	}
	defer sub.Close()
	time.Sleep(50 * time.Millisecond)
	HubPublisher{Hub: hub}.Publish(ctx, tn, RecordChanged, RecordOf(sample(), "www.example.com.", "A", ActionUpserted, SourceAPI))
	select {
	case ev := <-sub.Events():
		if ev.Type != RecordChanged || strings.Contains(ev.Data, "SECRET") || !strings.Contains(ev.Data, "www.example.com.") {
			t.Fatalf("event = %+v", ev)
		}
	case <-ctx.Done():
		t.Fatal("no event relayed")
	}
}
