package ipamsync

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	"github.com/go-freya/freya/services/dns/internal/stream"
)

// Reader is the subset of the event-bus client the consumer needs
// (stream.Client satisfies it).
type Reader interface {
	XRead(ctx context.Context, key, afterID string, block time.Duration, count int64) ([]stream.Entry, error)
	XLast(ctx context.Context, key string) (string, error)
}

// Consumer reads platform:events:<tenant> for the configured tenants (the
// deployer consumer pattern, research D8): it starts after each stream's
// current tail (a restart never replays history), decodes entries with the
// bounded decoder and hands address events to Handle. Everything else —
// other types, the module's own dns.* events — is skipped; malformed address
// events are dropped and reported through OnDrop. Handler failures are
// logged and never stop the loop.
type Consumer struct {
	Reader  Reader
	Tenants []string
	Handle  func(ctx context.Context, tenantID string, ev Event) error
	// Key names a tenant's stream (default stream.Key).
	Key func(tenantID string) string
	// Block is the per-tenant read block (default 2 s); RetryDelay the pause
	// after a bus failure (default 1 s).
	Block      time.Duration
	RetryDelay time.Duration
	Log        *slog.Logger
	// OnDrop receives "malformed" for every dropped address event.
	OnDrop func(reason string)

	started atomic.Bool
}

// Started reports whether every tenant's start position is known (tests).
func (c *Consumer) Started() bool { return c.started.Load() }

func (c *Consumer) key(t string) string {
	if c.Key != nil {
		return c.Key(t)
	}
	return stream.Key(t)
}

func (c *Consumer) log() *slog.Logger {
	if c.Log != nil {
		return c.Log
	}
	return slog.New(slog.DiscardHandler)
}

func (c *Consumer) pause(ctx context.Context) {
	d := c.RetryDelay
	if d <= 0 {
		d = time.Second
	}
	select {
	case <-ctx.Done():
	case <-time.After(d):
	}
}

// Run consumes until ctx is done.
func (c *Consumer) Run(ctx context.Context) {
	if len(c.Tenants) == 0 || c.Handle == nil {
		return
	}
	block := c.Block
	if block <= 0 {
		block = 2 * time.Second
	}
	last := map[string]string{}
	for ctx.Err() == nil {
		progressed := false
		for _, t := range c.Tenants {
			if _, ok := last[t]; !ok {
				id, err := c.Reader.XLast(ctx, c.key(t))
				if err != nil {
					continue // retried on the next pass; never replay the whole stream
				}
				if id == "" {
					id = "0-0"
				}
				last[t] = id
			}
		}
		if len(last) < len(c.Tenants) {
			c.pause(ctx)
			continue
		}
		c.started.Store(true)
		for _, t := range c.Tenants {
			entries, err := c.Reader.XRead(ctx, c.key(t), last[t], block, 100)
			if err != nil {
				if ctx.Err() != nil {
					return
				}
				c.log().WarnContext(ctx, "ipam sync: event bus read failed", "tenant", t, "err", err)
				continue
			}
			progressed = true
			for _, e := range entries {
				last[t] = e.ID
				c.dispatch(ctx, t, e)
			}
		}
		if !progressed {
			c.pause(ctx)
		}
	}
}

func (c *Consumer) dispatch(ctx context.Context, tenant string, e stream.Entry) {
	ev, err := Decode(e.Fields)
	switch {
	case errors.Is(err, ErrIgnored):
		return
	case err != nil:
		c.log().WarnContext(ctx, "ipam sync: malformed address event dropped", "tenant", tenant, "entry", e.ID)
		if c.OnDrop != nil {
			c.OnDrop("malformed")
		}
		return
	}
	if herr := c.Handle(ctx, tenant, ev); herr != nil {
		c.log().WarnContext(ctx, "ipam sync: event handling failed", "tenant", tenant, "entry", e.ID, "err", herr)
	}
}
