package app

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"

	authv1 "github.com/go-tangra/go-tangra-auth/sdk/v4/api/proto/auth/v1"
)

// fakeAuth answers auth.v1.Authorization/RegisterPermissions in memory; the
// first `failures` calls fail.
type fakeAuth struct {
	mu       sync.Mutex
	failures int
	calls    int
	method   string
	got      *authv1.RegisterPermissionsRequest
}

func (f *fakeAuth) Invoke(_ context.Context, method string, args, _ any, _ ...grpc.CallOption) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	f.method = method
	f.got = proto.Clone(args.(*authv1.RegisterPermissionsRequest)).(*authv1.RegisterPermissionsRequest)
	if f.calls <= f.failures {
		return errors.New("auth unavailable")
	}
	return nil
}

func (f *fakeAuth) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, errors.New("no streams")
}

func (f *fakeAuth) count() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

func TestRegisterPermissionsSendsRoles(t *testing.T) {
	auth := &fakeAuth{}
	if err := registerPermissions(context.Background(), auth, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatal(err)
	}
	req := auth.got
	if auth.method != authv1.Authorization_RegisterPermissions_FullMethodName {
		t.Fatalf("method %q", auth.method)
	}
	if req.GetModule() != "dns" || req.GetModuleDisplayName() != "DNS" || !req.GetDeclaresRoles() {
		t.Fatalf("module %q display %q declares_roles %v", req.GetModule(), req.GetModuleDisplayName(), req.GetDeclaresRoles())
	}
	roles := map[string]*authv1.ModuleRoleDef{}
	for _, r := range req.GetRoles() {
		roles[r.GetSlug()] = r
	}
	if len(roles) != 2 || roles["administrator"].GetDisplayName() != "DNS administrator" ||
		len(roles["administrator"].GetPermissions()) != 6 ||
		len(roles["viewer"].GetPermissions()) != 2 {
		t.Fatalf("roles %v", req.GetRoles())
	}
	grants := map[string]int{}
	for _, g := range req.GetBuiltinGrants() {
		grants[g.GetRole()] = len(g.GetPermissions())
	}
	want := map[string]int{"owner": 6, "admin": 6, "operator": 2, "member": 2, "auditor": 2}
	for role, n := range want {
		if grants[role] != n {
			t.Errorf("builtin grant %s: %d permissions, want %d", role, grants[role], n)
		}
	}
	// Transport errors are reported.
	if err := registerPermissions(context.Background(), &fakeAuth{failures: 1}, nil); err == nil {
		t.Fatal("error swallowed")
	}
}

// TestRegistrationLoopRetriesThenRepeats: failures are retried until the
// registration succeeds; afterwards it repeats every period.
func TestRegistrationLoopRetriesThenRepeats(t *testing.T) {
	auth := &fakeAuth{failures: 2}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		registrationLoop(ctx, slog.New(slog.DiscardHandler), func(ctx context.Context) error {
			return registerPermissions(ctx, auth, nil)
		}, time.Millisecond, 5*time.Millisecond)
	}()
	deadline := time.Now().Add(5 * time.Second)
	for auth.count() < 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	cancel()
	<-done
	if n := auth.count(); n < 5 {
		t.Fatalf("%d registration calls, want ≥ 5 (2 failures, success, periodic)", n)
	}
}

func TestRegistrationLoopStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	calls := 0
	registrationLoop(ctx, slog.New(slog.DiscardHandler), func(context.Context) error { calls++; return errors.New("x") }, time.Hour, time.Hour)
	if calls != 0 {
		t.Fatalf("%d calls after cancel", calls)
	}
}
