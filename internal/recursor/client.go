// Package recursor keeps the PowerDNS Recursor forwarding every managed zone to
// the authoritative server (research D10; ported from go-tangra-dns
// internal/recursor onto typed config and secret references). The recursor's
// forward-zone API rejects host names, so the authoritative host is resolved
// to an IP at sync time. An unconfigured client (no API URL) is disabled and
// every method is a no-op: the recursor being absent or down never blocks zone
// management. The API key is read per call and never appears in an error.
package recursor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// ErrUnavailable marks transport failures, missing keys, unresolvable forward
// targets and 5xx replies.
var ErrUnavailable = errors.New("recursor: unavailable")

// Defaults.
const (
	DefaultTimeout = 10 * time.Second
	maxBody        = 4 << 20
	maxMessage     = 200
)

// Client is the recursor surface the module uses (contracts §D).
type Client interface {
	// Enabled reports whether resolver forwarding is configured.
	Enabled() bool
	// SyncForward (idempotently) points the forward entry for zone at the
	// authoritative server's current IP:port.
	SyncForward(ctx context.Context, zone string) error
	// RemoveForward removes the forward entry (absent = success).
	RemoveForward(ctx context.Context, zone string) error
	// ListForwards lists the names of the recursor's Forwarded zones.
	ListForwards(ctx context.Context) ([]string, error)
	// Ready checks the recursor API answers (post-restart readiness).
	Ready(ctx context.Context) error
}

// KeyFunc yields the API key for one call (secrets.Source.RecursorAPIKey).
type KeyFunc func(ctx context.Context) (string, error)

// Resolver resolves the authoritative host (net.DefaultResolver in production).
type Resolver interface {
	LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error)
}

// Config configures the HTTP client. An empty BaseURL disables it.
type Config struct {
	BaseURL     string
	ServerID    string // default "localhost"
	Key         KeyFunc
	ForwardHost string // authoritative DNS host (default "pdns-auth")
	ForwardPort int    // default 53
	Timeout     time.Duration
	Resolver    Resolver
	HTTP        *http.Client
}

// HTTPClient talks to the PowerDNS Recursor API.
type HTTPClient struct {
	enabled  bool
	base     string
	serverID string
	key      KeyFunc
	fwdHost  string
	fwdPort  int
	timeout  time.Duration
	resolver Resolver
	hc       *http.Client
}

var (
	_          Client = (*HTTPClient)(nil)
	serverIDRE        = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
	hostRE            = regexp.MustCompile(`^[a-zA-Z0-9]([a-zA-Z0-9.:-]{0,251}[a-zA-Z0-9])?$`)
)

// New validates the configuration and builds the client (disabled when
// BaseURL is empty).
func New(cfg Config) (*HTTPClient, error) {
	if strings.TrimSpace(cfg.BaseURL) == "" {
		return &HTTPClient{}, nil
	}
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("recursor: base URL must be an http(s) URL without credentials")
	}
	if cfg.Key == nil {
		return nil, errors.New("recursor: an API key source is required")
	}
	c := &HTTPClient{enabled: true, base: strings.TrimRight(u.String(), "/"), serverID: cfg.ServerID, key: cfg.Key,
		fwdHost: cfg.ForwardHost, fwdPort: cfg.ForwardPort, timeout: cfg.Timeout, resolver: cfg.Resolver, hc: cfg.HTTP}
	if c.serverID == "" {
		c.serverID = "localhost"
	}
	if c.fwdHost == "" {
		c.fwdHost = "pdns-auth"
	}
	if c.fwdPort == 0 {
		c.fwdPort = 53
	}
	if !serverIDRE.MatchString(c.serverID) || !hostRE.MatchString(c.fwdHost) || c.fwdPort < 1 || c.fwdPort > 65535 {
		return nil, errors.New("recursor: invalid server id or forward target")
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.resolver == nil {
		c.resolver = net.DefaultResolver
	}
	if c.hc == nil {
		c.hc = &http.Client{}
	}
	return c, nil
}

// Enabled implements Client.
func (c *HTTPClient) Enabled() bool { return c.enabled }

// StatusError is a non-2xx recursor reply (sanitised, key-free message).
type StatusError struct {
	Status  int
	Message string
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("recursor: status %d: %s", e.Status, e.Message)
}

// Unwrap maps 5xx to ErrUnavailable.
func (e *StatusError) Unwrap() error {
	if e.Status >= 500 {
		return ErrUnavailable
	}
	return nil
}

func sanitize(msg, key string) string {
	if key != "" {
		msg = strings.ReplaceAll(msg, key, "[redacted]")
	}
	msg = strings.Join(strings.Fields(strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)), " ")
	if len(msg) > maxMessage {
		msg = msg[:maxMessage]
	}
	return msg
}

// canon lower-cases the zone and ensures one trailing dot; the root and empty
// names are refused (never managed through this client).
func canon(zone string) (string, error) {
	z := strings.ToLower(strings.TrimSpace(zone))
	z = strings.TrimSuffix(z, ".")
	if z == "" {
		return "", errors.New("recursor: zone name required")
	}
	return z + ".", nil
}

func (c *HTTPClient) zonesPath() string {
	return "/api/v1/servers/" + url.PathEscape(c.serverID) + "/zones"
}

// do performs one call and returns the status and body (any status).
func (c *HTTPClient) do(ctx context.Context, method, path string, in any) (int, []byte, error) {
	key, err := c.key(ctx)
	if err != nil || key == "" {
		return 0, nil, fmt.Errorf("%w: API key unavailable", ErrUnavailable)
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return 0, nil, fmt.Errorf("recursor: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return 0, nil, fmt.Errorf("recursor: build request: %w", err)
	}
	req.Header.Set("X-API-Key", key)
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return 0, nil, fmt.Errorf("%w: %s request failed", ErrUnavailable, method)
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp.StatusCode, nil, &StatusError{Status: resp.StatusCode, Message: sanitize(string(raw), key)}
	}
	return resp.StatusCode, raw, nil
}

// target resolves the authoritative host to "ip:port" (IPv4 preferred, as the
// source did).
func (c *HTTPClient) target(ctx context.Context) (string, error) {
	port := strconv.Itoa(c.fwdPort)
	if a, err := netip.ParseAddr(c.fwdHost); err == nil {
		return net.JoinHostPort(a.String(), port), nil
	}
	addrs, err := c.resolver.LookupIPAddr(ctx, c.fwdHost)
	if err != nil || len(addrs) == 0 {
		return "", fmt.Errorf("%w: cannot resolve the authoritative host", ErrUnavailable)
	}
	for _, a := range addrs {
		if v4 := a.IP.To4(); v4 != nil {
			return net.JoinHostPort(v4.String(), port), nil
		}
	}
	return net.JoinHostPort(addrs[0].IP.String(), port), nil
}

type zonePayload struct {
	Name             string   `json:"name"`
	Kind             string   `json:"kind"`
	Servers          []string `json:"servers"`
	RecursionDesired bool     `json:"recursion_desired"`
}

// SyncForward implements Client: delete-then-create always re-points the zone
// at the current target, whether or not it existed.
func (c *HTTPClient) SyncForward(ctx context.Context, zone string) error {
	if !c.enabled {
		return nil
	}
	name, err := canon(zone)
	if err != nil {
		return err
	}
	target, err := c.target(ctx)
	if err != nil {
		return err
	}
	_, _, _ = c.do(ctx, http.MethodDelete, c.zonesPath()+"/"+url.PathEscape(name), nil)
	_, _, err = c.do(ctx, http.MethodPost, c.zonesPath(), zonePayload{Name: name, Kind: "Forwarded", Servers: []string{target}})
	return err
}

// RemoveForward implements Client (404/422 mean already absent).
func (c *HTTPClient) RemoveForward(ctx context.Context, zone string) error {
	if !c.enabled {
		return nil
	}
	name, err := canon(zone)
	if err != nil {
		return err
	}
	status, _, err := c.do(ctx, http.MethodDelete, c.zonesPath()+"/"+url.PathEscape(name), nil)
	if status == http.StatusNotFound || status == http.StatusUnprocessableEntity {
		return nil
	}
	return err
}

// ListForwards implements Client.
func (c *HTTPClient) ListForwards(ctx context.Context) ([]string, error) {
	if !c.enabled {
		return nil, nil
	}
	_, raw, err := c.do(ctx, http.MethodGet, c.zonesPath(), nil)
	if err != nil {
		return nil, err
	}
	var zones []struct {
		Name string `json:"name"`
		Kind string `json:"kind"`
	}
	if err := json.Unmarshal(raw, &zones); err != nil {
		return nil, fmt.Errorf("recursor: decode zones: %w", err)
	}
	out := []string{}
	for _, z := range zones {
		if strings.EqualFold(z.Kind, "Forwarded") {
			out = append(out, z.Name)
		}
	}
	return out, nil
}

// Ready implements Client.
func (c *HTTPClient) Ready(ctx context.Context) error {
	if !c.enabled {
		return nil
	}
	_, _, err := c.do(ctx, http.MethodGet, "/api/v1/servers/"+url.PathEscape(c.serverID), nil)
	return err
}
