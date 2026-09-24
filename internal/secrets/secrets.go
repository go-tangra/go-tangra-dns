// Package secrets resolves the DNS module's two credentials — the PowerDNS
// Authoritative API key and the PowerDNS Recursor API key — from secret
// references (research D14; adapted from services/ticket). Config holds only
// references; the values are fetched at use time over the Freya SPIFFE channel
// (warden.v1.Secrets/GetPassword, authorised by the module's platform token) or,
// in development, read from a file, cached for a bounded refresh interval and
// re-read after it so rotations take effect without a restart. Values are never
// logged, never returned by the API and never appear in errors.
//
// Known platform gap (feature 014 T069): warden authorises only a user platform
// token and modules have no long-lived service-principal token, so the dev stack
// uses file: references; production keeps the warden path.
//
// Reference forms:
//
//	warden:<secret-id>   a warden secret (production)
//	<secret-id>          shorthand for warden:<secret-id>
//	file:<path>          a local file (development only; config warns)
package secrets

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"

	wardenv1 "github.com/go-tangra/go-tangra-warden/sdk/v4/api/proto/warden/v1"
)

// Errors (never carry secret material).
var (
	ErrNotConfigured = errors.New("secrets: reference not configured")
	ErrUnavailable   = errors.New("secrets: secret source unavailable")
	ErrEmpty         = errors.New("secrets: secret is empty")
)

// Source yields the module's credentials.
type Source interface {
	// PDNSAPIKey is the PowerDNS Authoritative API key (X-API-Key).
	PDNSAPIKey(ctx context.Context) (string, error)
	// RecursorAPIKey is the PowerDNS Recursor API key ("" with
	// ErrNotConfigured when no reference is configured).
	RecursorAPIKey(ctx context.Context) (string, error)
}

// Fetcher resolves one reference to its value.
type Fetcher interface {
	Fetch(ctx context.Context, ref string) (string, error)
}

// FetcherFunc adapts a function to Fetcher.
type FetcherFunc func(ctx context.Context, ref string) (string, error)

// Fetch implements Fetcher.
func (f FetcherFunc) Fetch(ctx context.Context, ref string) (string, error) { return f(ctx, ref) }

// ---- warden

// TokenFunc yields the module's platform token for warden calls.
type TokenFunc func(ctx context.Context) (string, error)

// FileToken reads the platform token from a file on every call (rotation).
func FileToken(path string) TokenFunc {
	return func(context.Context) (string, error) {
		raw, err := os.ReadFile(path) // #nosec G304 -- operator-configured token path
		if err != nil {
			return "", fmt.Errorf("%w: platform token unreadable", ErrUnavailable)
		}
		tok := strings.TrimSpace(string(raw))
		if tok == "" {
			return "", fmt.Errorf("%w: platform token empty", ErrUnavailable)
		}
		return tok, nil
	}
}

// Warden fetches warden references over the mesh.
type Warden struct {
	Client wardenv1.SecretsClient
	Token  TokenFunc
	// Timeout bounds one fetch (default 5 s).
	Timeout time.Duration
}

// NewWarden builds a warden fetcher over a mesh connection to the warden module.
func NewWarden(cc grpc.ClientConnInterface, token TokenFunc) *Warden {
	return &Warden{Client: wardenv1.NewSecretsClient(cc), Token: token}
}

// Fetch implements Fetcher for a warden secret id.
func (w *Warden) Fetch(ctx context.Context, id string) (string, error) {
	if w == nil || w.Client == nil || w.Token == nil {
		return "", ErrUnavailable
	}
	tok, err := w.Token(ctx)
	if err != nil {
		return "", err
	}
	timeout := w.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "authorization", "Bearer "+tok)
	res, err := w.Client.GetPassword(ctx, &wardenv1.GetPasswordRequest{Id: id})
	if err != nil {
		// Keep only the status code: nothing of the call leaks into logs.
		return "", fmt.Errorf("%w: warden: %s", ErrUnavailable, status.Code(err))
	}
	return res.GetPassword(), nil
}

// ---- resolver

// Resolver dispatches a reference by its scheme.
type Resolver struct {
	Warden Fetcher // nil refuses warden references
	// AllowFile permits file: references (development only).
	AllowFile bool
}

// Fetch implements Fetcher.
func (r Resolver) Fetch(ctx context.Context, ref string) (string, error) {
	ref = strings.TrimSpace(ref)
	switch {
	case ref == "":
		return "", ErrNotConfigured
	case strings.HasPrefix(ref, "file:"):
		if !r.AllowFile {
			return "", fmt.Errorf("%w: file references are disabled", ErrUnavailable)
		}
		raw, err := os.ReadFile(strings.TrimPrefix(ref, "file:")) // #nosec G304 -- operator-configured dev reference
		if err != nil {
			return "", fmt.Errorf("%w: file reference unreadable", ErrUnavailable)
		}
		return strings.TrimSpace(string(raw)), nil
	default:
		id := strings.TrimPrefix(ref, "warden:")
		if id == "" {
			return "", ErrNotConfigured
		}
		if r.Warden == nil {
			return "", fmt.Errorf("%w: warden not wired", ErrUnavailable)
		}
		return r.Warden.Fetch(ctx, id)
	}
}

// ---- cached source

type entry struct {
	val string
	at  time.Time
}

// Cached is the Source used by the service: it resolves the two configured
// references through a Fetcher, caches each value for Refresh and re-reads it
// after that (rotation). When a re-read fails the last good value keeps being
// served for up to MaxStale (default 10×Refresh) so a warden blip does not cut
// the module off PowerDNS; after that — or for a value never fetched — it is an
// error.
type Cached struct {
	Fetcher     Fetcher
	PDNSRef     string
	RecursorRef string
	Refresh     time.Duration
	MaxStale    time.Duration
	Now         func() time.Time

	mu    sync.Mutex
	cache map[string]entry
}

// NewCached builds the cached source.
func NewCached(f Fetcher, pdnsRef, recursorRef string, refresh time.Duration) *Cached {
	return &Cached{Fetcher: f, PDNSRef: pdnsRef, RecursorRef: recursorRef, Refresh: refresh}
}

func (c *Cached) now() time.Time {
	if c.Now != nil {
		return c.Now()
	}
	return time.Now()
}

func (c *Cached) get(ctx context.Context, ref string) (string, error) {
	if strings.TrimSpace(ref) == "" {
		return "", ErrNotConfigured
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.cache == nil {
		c.cache = map[string]entry{}
	}
	e, have := c.cache[ref]
	if have && c.now().Sub(e.at) < c.Refresh {
		return e.val, nil
	}
	if c.Fetcher == nil {
		return "", ErrUnavailable
	}
	v, err := c.Fetcher.Fetch(ctx, ref)
	if err == nil && v == "" {
		err = ErrEmpty
	}
	if err != nil {
		maxStale := c.MaxStale
		if maxStale <= 0 {
			maxStale = 10 * c.Refresh
		}
		if have && c.now().Sub(e.at) < maxStale {
			return e.val, nil
		}
		return "", err
	}
	c.cache[ref] = entry{val: v, at: c.now()}
	return v, nil
}

// PDNSAPIKey implements Source.
func (c *Cached) PDNSAPIKey(ctx context.Context) (string, error) { return c.get(ctx, c.PDNSRef) }

// RecursorAPIKey implements Source.
func (c *Cached) RecursorAPIKey(ctx context.Context) (string, error) {
	return c.get(ctx, c.RecursorRef)
}

// Invalidate drops cached values so the next use re-reads them.
func (c *Cached) Invalidate() {
	c.mu.Lock()
	c.cache = nil
	c.mu.Unlock()
}

// String never prints values.
func (c *Cached) String() string { return "secrets.Cached{pdns_ref, recursor_ref}" }

// ---- fake

// Fake is an in-memory Source for tests.
type Fake struct {
	mu       sync.Mutex
	PDNS     string
	Recursor string
	Err      error
	PDNSHit  int
}

// PDNSAPIKey implements Source.
func (f *Fake) PDNSAPIKey(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.PDNSHit++
	if f.Err != nil {
		return "", f.Err
	}
	if f.PDNS == "" {
		return "", ErrNotConfigured
	}
	return f.PDNS, nil
}

// RecursorAPIKey implements Source.
func (f *Fake) RecursorAPIKey(context.Context) (string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.Err != nil {
		return "", f.Err
	}
	if f.Recursor == "" {
		return "", ErrNotConfigured
	}
	return f.Recursor, nil
}

// SetPDNS rotates the fake PowerDNS key.
func (f *Fake) SetPDNS(v string) {
	f.mu.Lock()
	f.PDNS = v
	f.mu.Unlock()
}

// SetErr sets (or with nil clears) the fake's failure.
func (f *Fake) SetErr(err error) {
	f.mu.Lock()
	f.Err = err
	f.mu.Unlock()
}

var (
	_ Source  = (*Cached)(nil)
	_ Source  = (*Fake)(nil)
	_ Fetcher = (*Warden)(nil)
	_ Fetcher = Resolver{}
)
