// Package events publishes DNS lifecycle events to the shared platform event
// bus (platform:events:<tenant>, FR-013, contracts §C): other modules and the
// module's own SSE stream react to zone and record changes. Payloads carry ids,
// names and types only — never record values, API keys or configuration.
package events

import (
	"context"

	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
	"github.com/go-tangra/go-tangra-dns/v4/internal/stream"
)

// Event types published to platform:events:<tenant>.
const (
	ZoneCreated   = "dns.zone.created"
	ZoneUpdated   = "dns.zone.updated"
	ZoneDeleted   = "dns.zone.deleted"
	RecordChanged = "dns.record.changed"
)

// Types lists every event type the module publishes.
var Types = []string{ZoneCreated, ZoneUpdated, ZoneDeleted, RecordChanged}

// Record change actions and sources.
const (
	ActionUpserted = "upserted"
	ActionDeleted  = "deleted"

	SourceAPI  = "api"
	SourceIPAM = "ipam"
	SourceACME = "acme"
)

// ZonePayload is the content-safe body of dns.zone.* events.
type ZonePayload struct {
	ZoneID    string `json:"zone_id"`
	Zone      string `json:"zone"`
	Kind      string `json:"kind"`
	Origin    string `json:"origin"`
	ActorKind string `json:"actor_kind"`
}

// RecordPayload is the content-safe body of dns.record.changed: the owner name
// and type of the rrset, never its values.
type RecordPayload struct {
	ZoneID string `json:"zone_id"`
	Zone   string `json:"zone"`
	Name   string `json:"name"`
	Type   string `json:"type"`
	Action string `json:"action"` // upserted | deleted
	Source string `json:"source"` // api | ipam | acme
}

// ZoneOf builds the payload of z.
func ZoneOf(z store.Zone, actorKind string) ZonePayload {
	return ZonePayload{ZoneID: z.ID, Zone: z.Name, Kind: z.Kind, Origin: z.Origin, ActorKind: actorKind}
}

// RecordOf builds the payload of a change to the (name, type) rrset of z.
func RecordOf(z store.Zone, name, rtype, action, source string) RecordPayload {
	return RecordPayload{ZoneID: z.ID, Zone: z.Name, Name: name, Type: rtype, Action: action, Source: source}
}

// Publisher emits a realtime event to all of a tenant's subscribers. The
// payload is a ZonePayload or RecordPayload.
type Publisher interface {
	Publish(ctx context.Context, tenantID, eventType string, payload any)
}

// HubPublisher publishes through the stream hub (nil hub is a no-op).
type HubPublisher struct{ Hub *stream.Hub }

// Publish broadcasts eventType to every subscriber of tenantID; publishing is
// best effort and never fails the caller's operation.
func (p HubPublisher) Publish(ctx context.Context, tenantID, eventType string, payload any) {
	if p.Hub == nil {
		return
	}
	_, _ = p.Hub.PublishID(ctx, tenantID, nil, true, eventType, payload, true)
}

// EmitZone publishes a dns.zone.* event through pub when it is non-nil.
func EmitZone(ctx context.Context, pub Publisher, eventType string, z store.Zone, actorKind string) {
	if pub == nil {
		return
	}
	pub.Publish(ctx, z.TenantID, eventType, ZoneOf(z, actorKind))
}

// EmitRecord publishes dns.record.changed through pub when it is non-nil.
func EmitRecord(ctx context.Context, pub Publisher, z store.Zone, name, rtype, action, source string) {
	if pub == nil {
		return
	}
	pub.Publish(ctx, z.TenantID, RecordChanged, RecordOf(z, name, rtype, action, source))
}

// Recorded is one captured event (Recorder).
type Recorded struct {
	TenantID string
	Type     string
	Payload  any
}

// Recorder is an in-memory Publisher for tests.
type Recorder struct{ Events []Recorded }

// Publish implements Publisher.
func (r *Recorder) Publish(_ context.Context, tenantID, eventType string, p any) {
	r.Events = append(r.Events, Recorded{TenantID: tenantID, Type: eventType, Payload: p})
}

var (
	_ Publisher = HubPublisher{}
	_ Publisher = (*Recorder)(nil)
)
