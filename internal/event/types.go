// Package event consumes cross-service domain events from Redis pub/sub.
// It subscribes to IPAM's ip_address.created events and, when the new IP
// carries a hostname, ensures a DNS zone exists and upserts an A record —
// mirroring the subscriber pattern used by go-tangra-deployer.
package event

import (
	"encoding/json"
	"time"
)

// IPAM event channel namespace. Full channels: "ipam.ip_address.created",
// "ipam.ip_address.deleted".
const (
	IPAMTopicPrefix      = "ipam"
	IPAMIPAddressCreated = "ip_address.created"
	IPAMIPAddressDeleted = "ip_address.deleted"
)

// Envelope is the common wrapper IPAM (and LCM) publish to Redis. Data is
// kept raw so each topic can decode its own payload type.
type Envelope struct {
	ID        string          `json:"id"`
	Type      string          `json:"type"`
	Source    string          `json:"source"`
	Timestamp time.Time       `json:"timestamp"`
	TenantID  uint32          `json:"tenant_id"`
	Data      json.RawMessage `json:"data"`
}

// IPAddressData is the payload of ipam.ip_address.* events.
type IPAddressData struct {
	IPAddressID string `json:"ip_address_id"`
	TenantID    uint32 `json:"tenant_id"`
	Address     string `json:"address"`
	Hostname    string `json:"hostname"`
	SubnetID    string `json:"subnet_id"`
	MACAddress  string `json:"mac_address"`
}
