package dnsconf

// T079: the restart-only Docker Engine client over a unix socket. Only
// "POST /containers/{name}/restart" (name = one of the two configured
// containers, selected by the Target enum) and "GET /_ping" are ever sent;
// names are validated and path-escaped; 404/500 become errors; a disabled
// restarter never dials; any Target outside the enum is refused.

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

type dockerd struct {
	mu   sync.Mutex
	reqs []string
	code map[string]int
}

func (d *dockerd) seen() []string {
	d.mu.Lock()
	defer d.mu.Unlock()
	return append([]string(nil), d.reqs...)
}

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "docker", name)) // #nosec G304 -- test fixture
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// startDockerd serves a fake Docker Engine API on a temp unix socket.
func startDockerd(t *testing.T) (string, *dockerd) {
	t.Helper()
	dir, err := os.MkdirTemp("", "dk")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	sock := filepath.Join(dir, "d.sock")
	lis, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	d := &dockerd{code: map[string]int{}}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		d.mu.Lock()
		d.reqs = append(d.reqs, r.Method+" "+r.URL.EscapedPath())
		code := d.code[r.URL.Path]
		d.mu.Unlock()
		switch {
		case code == http.StatusNotFound:
			w.WriteHeader(code)
			_, _ = w.Write(fixture(t, "restart_404.json"))
		case code == http.StatusInternalServerError:
			w.WriteHeader(code)
			_, _ = w.Write(fixture(t, "restart_500.json"))
		case r.Method == http.MethodGet && r.URL.Path == "/_ping":
			_, _ = w.Write(fixture(t, "ping.txt"))
		case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/restart"):
			w.WriteHeader(http.StatusNoContent)
		default:
			w.WriteHeader(http.StatusTeapot)
		}
	}))
	srv.Listener = lis
	srv.Start()
	t.Cleanup(srv.Close)
	return sock, d
}

func dockerCfg(sock string) DockerConfig {
	return DockerConfig{Enabled: true, Socket: sock, AuthContainer: "freya-pdns-auth", RecursorContainer: "freya-pdns-recursor", Timeout: 5 * time.Second}
}

func TestDockerRestartOnlyTheConfiguredNames(t *testing.T) {
	sock, d := startDockerd(t)
	dk, err := NewDocker(dockerCfg(sock))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	if !dk.Enabled() || dk.Containers()[TargetAuth] != "freya-pdns-auth" || dk.Containers()[TargetRecursor] != "freya-pdns-recursor" {
		t.Fatalf("containers = %v", dk.Containers())
	}
	if err := dk.Ping(ctx); err != nil {
		t.Fatal(err)
	}
	name, err := dk.Restart(ctx, TargetRecursor)
	if err != nil || name != "freya-pdns-recursor" {
		t.Fatalf("restart = %q %v", name, err)
	}
	if name, err = dk.Restart(ctx, TargetAuth); err != nil || name != "freya-pdns-auth" {
		t.Fatalf("restart auth = %q %v", name, err)
	}
	for _, bad := range []Target{"", "db", "auth ", "../auth", "freya-pdns-auth"} {
		if _, err := dk.Restart(ctx, bad); !errors.Is(err, ErrUnknownTarget) {
			t.Errorf("target %q = %v", bad, err)
		}
	}
	want := []string{"GET /_ping", "POST /containers/freya-pdns-recursor/restart", "POST /containers/freya-pdns-auth/restart"}
	got := d.seen()
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("requests = %v", got)
	}
}

func TestDockerErrors(t *testing.T) {
	sock, d := startDockerd(t)
	dk, err := NewDocker(dockerCfg(sock))
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	d.code["/containers/freya-pdns-auth/restart"] = http.StatusNotFound
	if _, err := dk.Restart(ctx, TargetAuth); !errors.Is(err, ErrNoContainer) {
		t.Fatalf("404 = %v", err)
	}
	d.code["/containers/freya-pdns-recursor/restart"] = http.StatusInternalServerError
	_, err = dk.Restart(ctx, TargetRecursor)
	if !errors.Is(err, ErrRestart) || strings.Contains(err.Error(), "driver failed") {
		t.Fatalf("500 = %v", err)
	}
	d.code["/_ping"] = 0
	// Unreachable socket.
	dead, _ := NewDocker(dockerCfg(filepath.Join(filepath.Dir(sock), "missing.sock")))
	if _, err := dead.Restart(ctx, TargetAuth); !errors.Is(err, ErrRestart) {
		t.Fatalf("dead socket = %v", err)
	}
	if err := dead.Ping(ctx); err == nil {
		t.Fatal("ping of a dead socket")
	}
}

func TestDockerPingStatus(t *testing.T) {
	sock, d := startDockerd(t)
	dk, _ := NewDocker(dockerCfg(sock))
	d.code["/_ping"] = http.StatusInternalServerError
	if err := dk.Ping(context.Background()); err == nil {
		t.Fatal("ping 500 accepted")
	}
}

func TestDockerNamesValidatedAndEscaped(t *testing.T) {
	for _, c := range []DockerConfig{
		{Enabled: true, Socket: "/var/run/docker.sock", AuthContainer: "../etc", RecursorContainer: "r"},
		{Enabled: true, Socket: "/var/run/docker.sock", AuthContainer: "a", RecursorContainer: "r/x"},
		{Enabled: true, Socket: "/var/run/docker.sock", AuthContainer: "same", RecursorContainer: "same"},
		{Enabled: true, Socket: "relative.sock", AuthContainer: "a", RecursorContainer: "r"},
		{Enabled: true, Socket: "/var/run/docker.sock", AuthContainer: "", RecursorContainer: "r"},
	} {
		if _, err := NewDocker(c); err == nil {
			t.Errorf("accepted %+v", c)
		}
	}
	if got := restartPath("a.b_c-1"); got != "/containers/a.b_c-1/restart" {
		t.Fatalf("path = %q", got)
	}
}

func TestDisabledNeverDials(t *testing.T) {
	sock, d := startDockerd(t)
	c := dockerCfg(sock)
	c.Enabled = false
	dk, err := NewDocker(c)
	if err != nil {
		t.Fatal(err)
	}
	if dk.Enabled() {
		t.Fatal("enabled")
	}
	if _, err := dk.Restart(context.Background(), TargetAuth); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled restart = %v", err)
	}
	if err := dk.Ping(context.Background()); !errors.Is(err, ErrDisabled) {
		t.Fatalf("disabled ping = %v", err)
	}
	if len(d.seen()) != 0 {
		t.Fatalf("a disabled restarter dialled: %v", d.seen())
	}
	// A disabled restarter accepts empty/invalid names (they are never used).
	if _, err := NewDocker(DockerConfig{}); err != nil {
		t.Fatal(err)
	}
}

func TestFakeRestarter(t *testing.T) {
	f := NewFake(true)
	name, err := f.Restart(context.Background(), TargetAuth)
	if err != nil || name != "freya-pdns-auth" || strings.Join(f.Restarts(), ",") != "freya-pdns-auth" {
		t.Fatalf("fake = %q %v %v", name, err, f.Restarts())
	}
	f.FailNext(errors.New("boom"))
	if _, err := f.Restart(context.Background(), TargetRecursor); err == nil {
		t.Fatal("fail next")
	}
	if _, err := f.Restart(context.Background(), "x"); !errors.Is(err, ErrUnknownTarget) {
		t.Fatal("fake accepts unknown target")
	}
	off := NewFake(false)
	if off.Enabled() || off.Containers()[TargetRecursor] != "freya-pdns-recursor" {
		t.Fatal("disabled fake")
	}
	if _, err := off.Restart(context.Background(), TargetAuth); !errors.Is(err, ErrDisabled) {
		t.Fatal("disabled fake restarts")
	}
}

func FuzzRestartTarget(f *testing.F) {
	for _, s := range []string{"auth", "recursor", "", "AUTH", "auth/../x", "freya-pdns-auth", "recursor\n"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, s string) {
		dk, err := NewDocker(DockerConfig{Enabled: true, Socket: "/nonexistent/docker.sock", AuthContainer: "freya-pdns-auth", RecursorContainer: "freya-pdns-recursor", Timeout: 50 * time.Millisecond})
		if err != nil {
			t.Fatal(err)
		}
		name, ok := dk.name(Target(s))
		switch s {
		case "auth":
			if !ok || name != "freya-pdns-auth" {
				t.Fatal("auth")
			}
		case "recursor":
			if !ok || name != "freya-pdns-recursor" {
				t.Fatal("recursor")
			}
		default:
			if ok {
				t.Fatalf("target %q resolved to %q", s, name)
			}
			if _, err := dk.Restart(context.Background(), Target(s)); !errors.Is(err, ErrUnknownTarget) {
				t.Fatalf("target %q = %v", s, err)
			}
		}
	})
}
