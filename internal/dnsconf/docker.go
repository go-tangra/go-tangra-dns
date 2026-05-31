package dnsconf

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"time"
)

// Docker is a minimal client for the Docker Engine API over the unix socket.
// It only implements what we need: restarting a container by name.
type Docker struct {
	socket string
	http   *http.Client
}

// NewDocker builds a Docker client bound to the given unix socket path.
func NewDocker(socket string) *Docker {
	if socket == "" {
		socket = "/var/run/docker.sock"
	}
	return &Docker{
		socket: socket,
		http: &http.Client{
			Timeout: 60 * time.Second,
			Transport: &http.Transport{
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
					var d net.Dialer
					return d.DialContext(ctx, "unix", socket)
				},
			},
		},
	}
}

// Available reports whether the Docker socket appears usable.
func (d *Docker) Available(ctx context.Context) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://docker/_ping", nil)
	if err != nil {
		return false
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return false
	}
	_ = resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}

// RestartContainer restarts a container by name or id. A 404 (no such
// container) is returned as an error so callers can log it.
func (d *Docker) RestartContainer(ctx context.Context, name string) error {
	if name == "" {
		return fmt.Errorf("empty container name")
	}
	url := fmt.Sprintf("http://docker/containers/%s/restart", name)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	if err != nil {
		return err
	}
	resp, err := d.http.Do(req)
	if err != nil {
		return fmt.Errorf("restart %s: %w", name, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil
	}
	body, _ := io.ReadAll(resp.Body)
	return fmt.Errorf("restart %s: status %d: %s", name, resp.StatusCode, string(body))
}
