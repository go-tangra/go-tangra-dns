// Package pdns is the typed client of the PowerDNS Authoritative HTTP API
// (research D3; ported from go-tangra-dns internal/pdns). It is reached on the
// internal network only; the X-API-Key is read from the secret source on every
// call (rotation without restart) and never appears in an error: errors carry
// the status plus a truncated, sanitised PowerDNS message. Response bodies are
// size-capped and decoded into typed structs; zone ids are path-escaped.
//
// API reference: https://doc.powerdns.com/authoritative/http-api/
package pdns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// Sentinel errors (errors.Is).
var (
	ErrNotFound    = errors.New("pdns: not found")
	ErrConflict    = errors.New("pdns: already exists")
	ErrUnavailable = errors.New("pdns: unavailable")
	ErrTooLarge    = errors.New("pdns: response too large")
)

// Defaults.
const (
	DefaultTimeout     = 10 * time.Second
	DefaultMaxResponse = 32 << 20 // GET zone / export
	SmallResponse      = 64 << 10 // every other call
	MaxErrorMessage    = 200
	apiHeader          = "X-API-Key"
)

// Client is the PowerDNS Authoritative API surface the module uses (contracts
// §D). HTTPClient implements it against PowerDNS; Fake in memory.
type Client interface {
	// Ping checks the API is reachable and the key accepted.
	Ping(ctx context.Context) error
	// ListZoneNames lists every zone name on the server (reconciliation).
	ListZoneNames(ctx context.Context) ([]string, error)
	// GetZone returns a zone with its rrsets.
	GetZone(ctx context.Context, id string) (Zone, error)
	// CreateZone creates a zone (optionally with initial rrsets).
	CreateZone(ctx context.Context, z Zone) (Zone, error)
	// UpdateZoneMetadata PUTs kind, masters, dnssec and account.
	UpdateZoneMetadata(ctx context.Context, id string, z Zone) error
	DeleteZone(ctx context.Context, id string) error
	// PatchRRsets applies REPLACE/DELETE changes atomically.
	PatchRRsets(ctx context.Context, id string, rrsets []RRset) error
	// NotifyZone sends NOTIFY to the zone's secondaries (master/producer only).
	NotifyZone(ctx context.Context, id string) error
	// ExportZone returns the zone in BIND text form (size-capped).
	ExportZone(ctx context.Context, id string) (string, error)
	ListSupermasters(ctx context.Context) ([]Supermaster, error)
	CreateSupermaster(ctx context.Context, s Supermaster) error
	DeleteSupermaster(ctx context.Context, ip, nameserver string) error
}

// KeyFunc yields the API key for one call (secrets.Source.PDNSAPIKey).
type KeyFunc func(ctx context.Context) (string, error)

// Config configures the HTTP client.
type Config struct {
	BaseURL          string // e.g. http://pdns-auth:8081
	ServerID         string // default "localhost"
	Key              KeyFunc
	Timeout          time.Duration // per call; default 10 s
	MaxResponseBytes int64         // GET zone / export cap; default 32 MiB
	HTTP             *http.Client  // optional transport override
}

// HTTPClient talks to the PowerDNS Authoritative API.
type HTTPClient struct {
	base     string
	serverID string
	key      KeyFunc
	timeout  time.Duration
	maxLarge int64
	hc       *http.Client
}

var (
	_          Client = (*HTTPClient)(nil)
	serverIDRE        = regexp.MustCompile(`^[a-zA-Z0-9._-]{1,64}$`)
)

// New validates the configuration and builds the client.
func New(cfg Config) (*HTTPClient, error) {
	u, err := url.Parse(strings.TrimSpace(cfg.BaseURL))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil {
		return nil, errors.New("pdns: base URL must be an http(s) URL without credentials")
	}
	if cfg.Key == nil {
		return nil, errors.New("pdns: an API key source is required")
	}
	c := &HTTPClient{base: strings.TrimRight(u.String(), "/"), serverID: cfg.ServerID, key: cfg.Key,
		timeout: cfg.Timeout, maxLarge: cfg.MaxResponseBytes, hc: cfg.HTTP}
	if c.serverID == "" {
		c.serverID = "localhost"
	}
	if !serverIDRE.MatchString(c.serverID) {
		return nil, errors.New("pdns: invalid server id")
	}
	if c.timeout <= 0 {
		c.timeout = DefaultTimeout
	}
	if c.maxLarge <= 0 {
		c.maxLarge = DefaultMaxResponse
	}
	if c.hc == nil {
		c.hc = &http.Client{}
	}
	return c, nil
}

// APIError is a non-2xx PowerDNS reply: the status and a sanitised, truncated
// message. It unwraps to ErrNotFound (404), ErrConflict (409, or 422 "already
// exists"), ErrUnavailable (5xx) or nothing.
type APIError struct {
	Status  int
	Message string
	kind    error
}

func (e *APIError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("pdns: status %d", e.Status)
	}
	return fmt.Sprintf("pdns: status %d: %s", e.Status, e.Message)
}

// Unwrap exposes the sentinel of the status class.
func (e *APIError) Unwrap() error { return e.kind }

// sanitize makes a PowerDNS message safe to log/return: the key is redacted,
// control characters dropped, and the text truncated.
func sanitize(msg, key string) string {
	if key != "" {
		msg = strings.ReplaceAll(msg, key, "[redacted]")
	}
	msg = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return ' '
		}
		return r
	}, msg)
	msg = strings.Join(strings.Fields(msg), " ")
	if len(msg) > MaxErrorMessage {
		msg = msg[:MaxErrorMessage]
	}
	if key != "" { // truncation may have cut a partial key: redact any remaining prefix of it
		for n := len(key) - 1; n >= 4; n-- {
			if strings.HasSuffix(msg, key[:n]) {
				msg = strings.TrimSuffix(msg, key[:n]) + "[redacted]"
				break
			}
		}
	}
	return msg
}

// apiError builds the typed error of a non-2xx reply.
func apiError(status int, body []byte, key string) *APIError {
	var env struct {
		Error  string   `json:"error"`
		Errors []string `json:"errors"`
	}
	msg := string(body)
	if json.Unmarshal(body, &env) == nil && (env.Error != "" || len(env.Errors) > 0) {
		msg = strings.TrimSpace(env.Error + " " + strings.Join(env.Errors, "; "))
	}
	e := &APIError{Status: status, Message: sanitize(msg, key)}
	switch {
	case status == http.StatusNotFound:
		e.kind = ErrNotFound
	case status == http.StatusConflict,
		status == http.StatusUnprocessableEntity && strings.Contains(strings.ToLower(msg), "already exists"):
		e.kind = ErrConflict
	case status >= 500:
		e.kind = ErrUnavailable
	}
	return e
}

// zonePath is the escaped path of one zone. Ids that could address anything
// but a zone ("", ".", "..") are refused as not found.
func (c *HTTPClient) zonePath(id string) (string, error) {
	if id == "" || id == "." || id == ".." {
		return "", ErrNotFound
	}
	return c.zonesPath() + "/" + url.PathEscape(id), nil
}

func (c *HTTPClient) serverPath() string { return "/api/v1/servers/" + url.PathEscape(c.serverID) }
func (c *HTTPClient) zonesPath() string  { return c.serverPath() + "/zones" }
func (c *HTTPClient) smPath() string     { return c.serverPath() + "/autoprimaries" } // PowerDNS >= 4.7 (formerly "supermasters")

// do performs one call: key from the source, per-call timeout, capped body.
// It returns the raw body of a 2xx reply.
func (c *HTTPClient) do(ctx context.Context, method, path string, in any, limit int64) ([]byte, error) {
	key, err := c.key(ctx)
	if err != nil || key == "" {
		return nil, fmt.Errorf("%w: API key unavailable", ErrUnavailable)
	}
	var body io.Reader
	if in != nil {
		raw, err := json.Marshal(in)
		if err != nil {
			return nil, fmt.Errorf("pdns: encode request: %w", err)
		}
		body = bytes.NewReader(raw)
	}
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, method, c.base+path, body)
	if err != nil {
		return nil, fmt.Errorf("pdns: build request: %w", err)
	}
	req.Header.Set(apiHeader, key)
	req.Header.Set("Accept", "application/json, text/plain")
	if in != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		// Transport errors carry the URL (never the key); keep only the class.
		return nil, fmt.Errorf("%w: %s %s: request failed", ErrUnavailable, method, strings.SplitN(path, "?", 2)[0])
	}
	defer func() { _ = resp.Body.Close() }()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, fmt.Errorf("%w: reading response", ErrUnavailable)
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		if int64(len(raw)) > limit {
			raw = raw[:limit]
		}
		return nil, apiError(resp.StatusCode, raw, key)
	}
	if int64(len(raw)) > limit {
		return nil, fmt.Errorf("%w: exceeds %d bytes", ErrTooLarge, limit)
	}
	return raw, nil
}

func decode(raw []byte, out any) error {
	if err := json.Unmarshal(raw, out); err != nil {
		return fmt.Errorf("pdns: decode response: %w", err)
	}
	return nil
}

// Ping implements Client.
func (c *HTTPClient) Ping(ctx context.Context) error {
	_, err := c.do(ctx, http.MethodGet, c.serverPath(), nil, SmallResponse)
	return err
}

// ListZoneNames implements Client.
func (c *HTTPClient) ListZoneNames(ctx context.Context) ([]string, error) {
	raw, err := c.do(ctx, http.MethodGet, c.zonesPath()+"?dnssec=false", nil, c.maxLarge)
	if err != nil {
		return nil, err
	}
	var refs []zoneRef
	if err := decode(raw, &refs); err != nil {
		return nil, err
	}
	out := make([]string, 0, len(refs))
	for _, r := range refs {
		out = append(out, r.Name)
	}
	return out, nil
}

// GetZone implements Client.
func (c *HTTPClient) GetZone(ctx context.Context, id string) (Zone, error) {
	p, err := c.zonePath(id)
	if err != nil {
		return Zone{}, err
	}
	raw, err := c.do(ctx, http.MethodGet, p, nil, c.maxLarge)
	if err != nil {
		return Zone{}, err
	}
	var z Zone
	return z, decode(raw, &z)
}

// CreateZone implements Client.
func (c *HTTPClient) CreateZone(ctx context.Context, z Zone) (Zone, error) {
	in := createBody{Name: z.Name, Kind: z.Kind, Masters: z.Masters, DNSSEC: z.DNSSEC, Nameservers: z.Nameservers,
		Account: z.Account, RRsets: z.RRsets}
	if in.Nameservers == nil {
		in.Nameservers = []string{}
	}
	raw, err := c.do(ctx, http.MethodPost, c.zonesPath(), in, c.maxLarge)
	if err != nil {
		return Zone{}, err
	}
	var out Zone
	return out, decode(raw, &out)
}

// UpdateZoneMetadata implements Client.
func (c *HTTPClient) UpdateZoneMetadata(ctx context.Context, id string, z Zone) error {
	p, err := c.zonePath(id)
	if err != nil {
		return err
	}
	in := metadataBody{Kind: z.Kind, Masters: z.Masters, DNSSEC: z.DNSSEC, Account: z.Account}
	if in.Masters == nil {
		in.Masters = []string{}
	}
	_, err = c.do(ctx, http.MethodPut, p, in, SmallResponse)
	return err
}

// DeleteZone implements Client.
func (c *HTTPClient) DeleteZone(ctx context.Context, id string) error {
	p, err := c.zonePath(id)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodDelete, p, nil, SmallResponse)
	return err
}

// PatchRRsets implements Client.
func (c *HTTPClient) PatchRRsets(ctx context.Context, id string, rrsets []RRset) error {
	p, err := c.zonePath(id)
	if err != nil {
		return err
	}
	if rrsets == nil {
		rrsets = []RRset{}
	}
	_, err = c.do(ctx, http.MethodPatch, p, patchBody{RRsets: rrsets}, SmallResponse)
	return err
}

// NotifyZone implements Client.
func (c *HTTPClient) NotifyZone(ctx context.Context, id string) error {
	p, err := c.zonePath(id)
	if err != nil {
		return err
	}
	_, err = c.do(ctx, http.MethodPut, p+"/notify", nil, SmallResponse)
	return err
}

// ExportZone implements Client.
func (c *HTTPClient) ExportZone(ctx context.Context, id string) (string, error) {
	p, err := c.zonePath(id)
	if err != nil {
		return "", err
	}
	raw, err := c.do(ctx, http.MethodGet, p+"/export", nil, c.maxLarge)
	if err != nil {
		return "", err
	}
	// PowerDNS answers {"zone": "<BIND text>"} when JSON is acceptable (our
	// Accept header) and the bare text otherwise; accept both.
	if t := bytes.TrimSpace(raw); len(t) > 0 && t[0] == '{' {
		var wrapped struct {
			Zone *string `json:"zone"`
		}
		if json.Unmarshal(t, &wrapped) == nil && wrapped.Zone != nil {
			return *wrapped.Zone, nil
		}
	}
	return string(raw), nil
}

// ListSupermasters implements Client.
func (c *HTTPClient) ListSupermasters(ctx context.Context) ([]Supermaster, error) {
	raw, err := c.do(ctx, http.MethodGet, c.smPath(), nil, SmallResponse)
	if err != nil {
		return nil, err
	}
	var out []Supermaster
	return out, decode(raw, &out)
}

// CreateSupermaster implements Client.
func (c *HTTPClient) CreateSupermaster(ctx context.Context, s Supermaster) error {
	_, err := c.do(ctx, http.MethodPost, c.smPath(), s, SmallResponse)
	return err
}

// DeleteSupermaster implements Client.
func (c *HTTPClient) DeleteSupermaster(ctx context.Context, ip, nameserver string) error {
	_, err := c.do(ctx, http.MethodDelete, c.smPath()+"/"+url.PathEscape(ip)+"/"+url.PathEscape(nameserver), nil, SmallResponse)
	return err
}
