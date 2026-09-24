package ipamsync

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"regexp"
)

// IPAM address event types consumed from platform:events:<tenant>.
const (
	TypeCreated = "ipam.ip_address.created"
	TypeUpdated = "ipam.ip_address.updated"
	TypeDeleted = "ipam.ip_address.deleted"
	TypeScanned = "ipam.ip_address.scanned"
)

// Decoder bounds.
const (
	MaxPayload  = 4 << 10 // bytes of the data field
	MaxID       = 64
	MaxHostname = 253
)

// Decoding outcomes: ErrIgnored for entries of other types (including the
// module's own dns.* events), ErrMalformed for address events that fail the
// shape rules (dropped and counted).
var (
	ErrIgnored   = errors.New("ipamsync: event ignored")
	ErrMalformed = errors.New("ipamsync: malformed event")
)

// Event is a decoded IPAM address event — an untrusted trigger: only ID
// (which address to re-read from IPAM) is acted on; the rest is logged at most.
type Event struct {
	Type     string
	Action   string
	ID       string
	Address  string
	SubnetID string
	Hostname string
}

var idRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

type payload struct {
	Action   string `json:"action"`
	ID       string `json:"id"`
	Address  string `json:"address"`
	SubnetID string `json:"subnet_id"`
	Hostname string `json:"hostname"`
}

// Decode validates one stream entry's fields {type, data, to, at}: the type
// must be one of the four address types, data a JSON object of at most
// MaxPayload bytes with a bounded id and an IP literal address (unknown
// fields are ignored, trailing data refused).
func Decode(fields map[string]string) (Event, error) {
	typ := fields["type"]
	switch typ {
	case TypeCreated, TypeUpdated, TypeDeleted, TypeScanned:
	default:
		return Event{}, ErrIgnored
	}
	data := fields["data"]
	if len(data) == 0 || len(data) > MaxPayload {
		return Event{}, ErrMalformed
	}
	dec := json.NewDecoder(bytes.NewReader([]byte(data)))
	var p *payload
	if err := dec.Decode(&p); err != nil || p == nil {
		return Event{}, ErrMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return Event{}, ErrMalformed
	}
	if !idRE.MatchString(p.ID) || len(p.SubnetID) > MaxID || len(p.Hostname) > MaxHostname || len(p.Action) > 16 {
		return Event{}, ErrMalformed
	}
	a, err := netip.ParseAddr(p.Address)
	if err != nil || a.Zone() != "" {
		return Event{}, ErrMalformed
	}
	return Event{Type: typ, Action: p.Action, ID: p.ID, Address: p.Address, SubnetID: p.SubnetID, Hostname: p.Hostname}, nil
}
