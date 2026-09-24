package dnsconf

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"path/filepath"
	"regexp"
	"sync"
	"time"
)

// Target selects which of the two configured DNS containers to restart. No
// request field ever carries a container name: callers name a Target and the
// restarter maps it to the configured name.
type Target string

// Targets (closed set).
const (
	TargetAuth     Target = "auth"
	TargetRecursor Target = "recursor"
)

// Restarter errors.
var (
	ErrUnknownTarget = errors.New("dnsconf: unknown restart target")
	ErrDisabled      = errors.New("dnsconf: container restarts are disabled")
	ErrNoContainer   = errors.New("dnsconf: container not found")
	ErrRestart       = errors.New("dnsconf: container restart failed")
)

// Restarter restarts the DNS containers.
type Restarter interface {
	Enabled() bool
	// Containers maps each target to its configured container name.
	Containers() map[Target]string
	// Restart restarts the container of target and returns its name.
	Restart(ctx context.Context, target Target) (string, error)
}

// ContainerNameRE is the Docker container-name grammar accepted for the two
// configured names.
var ContainerNameRE = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.-]{0,127}$`)

// DockerConfig configures the restart-only Docker Engine client.
type DockerConfig struct {
	Enabled           bool
	Socket            string // absolute unix socket path
	AuthContainer     string
	RecursorContainer string
	Timeout           time.Duration
}

// Docker is a restart-only client of the Docker Engine API over the unix
// socket. It issues exactly two requests: POST /containers/{name}/restart for
// one of the two configured names, and GET /_ping. It is not a general Docker
// client and never dials while disabled.
type Docker struct {
	enabled bool
	names   map[Target]string
	http    *http.Client
}

var _ Restarter = (*Docker)(nil)

// NewDocker validates the configuration (when enabled) and builds the client.
func NewDocker(c DockerConfig) (*Docker, error) {
	d := &Docker{enabled: c.Enabled, names: map[Target]string{TargetAuth: c.AuthContainer, TargetRecursor: c.RecursorContainer}}
	if !c.Enabled {
		return d, nil
	}
	if !filepath.IsAbs(c.Socket) || filepath.Clean(c.Socket) != c.Socket {
		return nil, errors.New("dnsconf: docker socket must be an absolute, clean path")
	}
	for _, n := range []string{c.AuthContainer, c.RecursorContainer} {
		if !ContainerNameRE.MatchString(n) {
			return nil, fmt.Errorf("dnsconf: container name must match %s", ContainerNameRE)
		}
	}
	if c.AuthContainer == c.RecursorContainer {
		return nil, errors.New("dnsconf: the two container names must differ")
	}
	timeout := c.Timeout
	if timeout <= 0 {
		timeout = 60 * time.Second
	}
	socket := c.Socket
	d.http = &http.Client{Timeout: timeout, Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			var dl net.Dialer
			return dl.DialContext(ctx, "unix", socket)
		},
		DisableKeepAlives: true,
	}}
	return d, nil
}

// Enabled reports whether restarts are performed.
func (d *Docker) Enabled() bool { return d.enabled }

// Containers maps each target to its configured name.
func (d *Docker) Containers() map[Target]string {
	return map[Target]string{TargetAuth: d.names[TargetAuth], TargetRecursor: d.names[TargetRecursor]}
}

// name resolves a target to its configured container name.
func (d *Docker) name(t Target) (string, bool) {
	if t != TargetAuth && t != TargetRecursor {
		return "", false
	}
	n := d.names[t]
	return n, ContainerNameRE.MatchString(n)
}

// restartPath is the escaped request path for a (validated) name.
func restartPath(name string) string { return "/containers/" + url.PathEscape(name) + "/restart" }

func (d *Docker) do(ctx context.Context, method, path string) (int, error) {
	req, err := http.NewRequestWithContext(ctx, method, "http://docker"+path, nil)
	if err != nil {
		return 0, err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10))
	return resp.StatusCode, nil
}

// Ping checks the Docker Engine answers on the socket.
func (d *Docker) Ping(ctx context.Context) error {
	if !d.enabled {
		return ErrDisabled
	}
	code, err := d.do(ctx, http.MethodGet, "/_ping")
	if err != nil {
		return fmt.Errorf("dnsconf: docker ping: %w", err)
	}
	if code != http.StatusOK {
		return fmt.Errorf("dnsconf: docker ping: status %d", code)
	}
	return nil
}

// Restart restarts the configured container of target. The daemon's error
// text is never returned (only the status).
func (d *Docker) Restart(ctx context.Context, t Target) (string, error) {
	name, ok := d.name(t)
	if !ok {
		return "", ErrUnknownTarget
	}
	if !d.enabled {
		return name, ErrDisabled
	}
	code, err := d.do(ctx, http.MethodPost, restartPath(name))
	switch {
	case err != nil:
		return name, fmt.Errorf("%w: %s: unreachable", ErrRestart, name)
	case code == http.StatusNoContent:
		return name, nil
	case code == http.StatusNotFound:
		return name, fmt.Errorf("%w: %s", ErrNoContainer, name)
	}
	return name, fmt.Errorf("%w: %s: status %d", ErrRestart, name, code)
}

// Fake is an in-memory Restarter for tests (default names
// freya-pdns-auth/freya-pdns-recursor).
type Fake struct {
	mu       sync.Mutex
	enabled  bool
	restarts []string
	failNext error
}

var _ Restarter = (*Fake)(nil)

// NewFake builds a fake restarter.
func NewFake(enabled bool) *Fake { return &Fake{enabled: enabled} }

// Enabled implements Restarter.
func (f *Fake) Enabled() bool { return f.enabled }

// Containers implements Restarter.
func (f *Fake) Containers() map[Target]string {
	return map[Target]string{TargetAuth: "freya-pdns-auth", TargetRecursor: "freya-pdns-recursor"}
}

// FailNext makes the next Restart return err.
func (f *Fake) FailNext(err error) {
	f.mu.Lock()
	f.failNext = err
	f.mu.Unlock()
}

// Restart implements Restarter.
func (f *Fake) Restart(_ context.Context, t Target) (string, error) {
	name, ok := f.Containers()[t]
	if !ok {
		return "", ErrUnknownTarget
	}
	if !f.enabled {
		return name, ErrDisabled
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.failNext; err != nil {
		f.failNext = nil
		return name, err
	}
	f.restarts = append(f.restarts, name)
	return name, nil
}

// Restarts lists the containers restarted so far.
func (f *Fake) Restarts() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.restarts...)
}
