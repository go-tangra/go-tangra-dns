package recursor

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Fake is an in-memory recursor for offline tests: a set of forward zones, a
// call log, failure injection and a readiness switch. A zero Fake is disabled;
// NewFake returns an enabled one. It is safe for concurrent use.
type Fake struct {
	mu       sync.Mutex
	enabled  bool
	forwards map[string]string // zone -> target
	failNext map[string]error
	// Target is what SyncForward records as the forward server.
	Target string
	// Down makes every call fail with ErrUnavailable.
	Down bool
	// NotReady makes Ready fail (post-restart polling tests).
	NotReady bool
	// Calls logs "Op zone" for every call.
	Calls []string
}

var _ Client = (*Fake)(nil)

// NewFake builds an enabled fake recursor.
func NewFake() *Fake {
	return &Fake{enabled: true, forwards: map[string]string{}, failNext: map[string]error{}, Target: "172.20.0.5:53"}
}

// FailNext makes the next call of op (e.g. "SyncForward") return err.
func (f *Fake) FailNext(op string, err error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.failNext[op] = err
}

// SetDown toggles the unreachable state.
func (f *Fake) SetDown(down bool) {
	f.mu.Lock()
	f.Down = down
	f.mu.Unlock()
}

// SetReady toggles readiness.
func (f *Fake) SetReady(ready bool) {
	f.mu.Lock()
	f.NotReady = !ready
	f.mu.Unlock()
}

// Seed adds a forward entry directly (e.g. a stale, unmanaged forward).
func (f *Fake) Seed(zone, target string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.forwards[strings.ToLower(zone)] = target
}

// Forwards returns the current forward entries (zone -> target).
func (f *Fake) Forwards() map[string]string {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make(map[string]string, len(f.forwards))
	for k, v := range f.forwards {
		out[k] = v
	}
	return out
}

// CallLog returns a copy of the call log.
func (f *Fake) CallLog() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.Calls...)
}

func (f *Fake) begin(op, zone string) error {
	f.Calls = append(f.Calls, strings.TrimSpace(op+" "+zone))
	if f.Down {
		return fmt.Errorf("%w: fake is down", ErrUnavailable)
	}
	if err, ok := f.failNext[op]; ok {
		delete(f.failNext, op)
		return err
	}
	return nil
}

// Enabled implements Client.
func (f *Fake) Enabled() bool { return f.enabled }

// SyncForward implements Client.
func (f *Fake) SyncForward(_ context.Context, zone string) error {
	if !f.enabled {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name, err := canon(zone)
	if err != nil {
		return err
	}
	if err := f.begin("SyncForward", name); err != nil {
		return err
	}
	f.forwards[name] = f.Target
	return nil
}

// RemoveForward implements Client (absent = success).
func (f *Fake) RemoveForward(_ context.Context, zone string) error {
	if !f.enabled {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	name, err := canon(zone)
	if err != nil {
		return err
	}
	if err := f.begin("RemoveForward", name); err != nil {
		return err
	}
	delete(f.forwards, name)
	return nil
}

// ListForwards implements Client.
func (f *Fake) ListForwards(context.Context) ([]string, error) {
	if !f.enabled {
		return nil, nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("ListForwards", ""); err != nil {
		return nil, err
	}
	out := []string{}
	for z := range f.forwards {
		out = append(out, z)
	}
	sort.Strings(out)
	return out, nil
}

// Ready implements Client.
func (f *Fake) Ready(context.Context) error {
	if !f.enabled {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.begin("Ready", ""); err != nil {
		return err
	}
	if f.NotReady {
		return fmt.Errorf("%w: not ready", ErrUnavailable)
	}
	return nil
}
