// Package recursor keeps the PowerDNS Recursor's forward-zone list in sync
// with the platform-managed zones. When a zone is created/deleted in the
// authoritative server, the recursor must forward (or stop forwarding)
// queries for that zone to the auth server. The recursor REST API requires
// IP forward targets, so we resolve the auth host at sync time.
package recursor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
)

// Client talks to the pdns-recursor REST API.
type Client struct {
	log         *log.Helper
	apiURL      string
	apiKey      string
	forwardHost string
	forwardPort string
	http        *http.Client
}

// NewClient builds a recursor client from the environment. When
// RECURSOR_API_URL / RECURSOR_API_KEY are unset, every method is a no-op.
func NewClient(ctx *bootstrap.Context) *Client {
	return &Client{
		log:         ctx.NewLoggerHelper("dns/recursor"),
		apiURL:      strings.TrimRight(os.Getenv("RECURSOR_API_URL"), "/"),
		apiKey:      os.Getenv("RECURSOR_API_KEY"),
		forwardHost: getEnv("PDNS_FORWARD_HOST", "powerdns"),
		forwardPort: getEnv("PDNS_FORWARD_PORT", "53"),
		http:        &http.Client{Timeout: 10 * time.Second},
	}
}

// Enabled reports whether the recursor integration is configured.
func (c *Client) Enabled() bool { return c.apiURL != "" && c.apiKey != "" }

// canon lowercases and ensures a single trailing dot.
func canon(zone string) string {
	z := strings.ToLower(strings.TrimSpace(zone))
	if z == "" {
		return z
	}
	if !strings.HasSuffix(z, ".") {
		z += "."
	}
	return z
}

// resolveTarget resolves the authoritative host to an "ip:port" string.
// The recursor forward-zones API rejects hostnames, so we must pass an IP.
func (c *Client) resolveTarget(ctx context.Context) (string, error) {
	// If the configured host is already an IP, use it directly.
	if net.ParseIP(c.forwardHost) != nil {
		return net.JoinHostPort(c.forwardHost, c.forwardPort), nil
	}
	addrs, err := net.DefaultResolver.LookupIPAddr(ctx, c.forwardHost)
	if err != nil {
		return "", fmt.Errorf("resolve %s: %w", c.forwardHost, err)
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), c.forwardPort), nil
		}
	}
	if len(addrs) > 0 {
		return net.JoinHostPort(addrs[0].IP.String(), c.forwardPort), nil
	}
	return "", fmt.Errorf("no addresses for %s", c.forwardHost)
}

type zonePayload struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	Servers          []string `json:"servers"`
	RecursionDesired bool     `json:"recursion_desired"`
}

// SyncForwardZone (idempotently) points the recursor's forward entry for
// zoneName at the current authoritative server IP. Safe to call repeatedly.
func (c *Client) SyncForwardZone(ctx context.Context, zoneName string) error {
	if !c.Enabled() {
		return nil
	}
	name := canon(zoneName)
	target, err := c.resolveTarget(ctx)
	if err != nil {
		return err
	}
	body := zonePayload{Name: name, Kind: "Forwarded", Servers: []string{target}, RecursionDesired: false}

	// Delete-then-create is deterministic: it always (re)points the zone at
	// the current target IP, regardless of whether it already existed.
	_, _, _ = c.do(ctx, http.MethodDelete, "/api/v1/servers/localhost/zones/"+name, nil)
	status, resp, err := c.do(ctx, http.MethodPost, "/api/v1/servers/localhost/zones", body)
	if err != nil {
		return err
	}
	if status == http.StatusCreated || status == http.StatusOK {
		c.log.Infof("recursor: forwarding %s -> %s", name, target)
		return nil
	}
	return fmt.Errorf("recursor sync %s: status %d (%s)", name, status, resp)
}

// RemoveForwardZone removes the recursor's forward entry for zoneName.
// A missing entry (404) is treated as success.
func (c *Client) RemoveForwardZone(ctx context.Context, zoneName string) error {
	if !c.Enabled() {
		return nil
	}
	name := canon(zoneName)
	status, resp, err := c.do(ctx, http.MethodDelete, "/api/v1/servers/localhost/zones/"+name, nil)
	if err != nil {
		return err
	}
	// 404/422 mean the forward entry was already absent — treat as success
	// (this recursor returns 422 when deleting a non-existent zone).
	if status == http.StatusNoContent || status == http.StatusOK ||
		status == http.StatusNotFound || status == http.StatusUnprocessableEntity {
		c.log.Infof("recursor: stopped forwarding %s", name)
		return nil
	}
	return fmt.Errorf("recursor remove %s: status %d (%s)", name, status, resp)
}

func (c *Client) do(ctx context.Context, method, path string, body any) (int, string, error) {
	var reader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return 0, "", err
		}
		reader = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.apiURL+path, reader)
	if err != nil {
		return 0, "", err
	}
	req.Header.Set("X-API-Key", c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return 0, "", err
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, strings.TrimSpace(string(out)), nil
}

func getEnv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
