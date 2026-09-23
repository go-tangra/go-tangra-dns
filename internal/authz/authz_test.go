package authz

import (
	"context"
	"errors"
	"testing"
)

const tn = "0190f7c2-6a3e-7c1a-9b2e-2f6f9d1b4c55"

const lcm = "spiffe://example.org/svc/lcm"

var ctx = context.Background()

func TestRequireUser(t *testing.T) {
	c := Static{"viewer": {ZonesRead, DashboardRead}, "admin": {ZonesRead, ZonesManage, TemplatesManage, SupermastersManage, DashboardRead, BackupManage}}
	viewer := User(tn, "viewer", nil)
	admin := User(tn, "admin", []string{"owner", "admin"})
	if err := Require(ctx, c, viewer, ZonesRead); err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ZonesManage, TemplatesManage, SupermastersManage, BackupManage, ConfigManage} {
		if err := Require(ctx, c, viewer, p); !errors.Is(err, ErrForbidden) {
			t.Fatalf("viewer %s: %v", p, err)
		}
	}
	if !Allowed(ctx, c, admin, TemplatesManage) || Allowed(ctx, c, admin, ConfigManage) {
		t.Fatal("admin grants")
	}
	if Allowed(ctx, nil, admin, ZonesRead) {
		t.Fatal("nil checker must refuse")
	}
	if Allowed(ctx, c, Subjects{TenantID: tn, ActorKind: ActorUser}, ZonesRead) {
		t.Fatal("user without user id")
	}
	if Allowed(ctx, c, Subjects{UserID: "admin", ActorKind: ActorUser}, ZonesRead) {
		t.Fatal("no tenant")
	}
	if Allowed(ctx, c, admin, "zones:fly") {
		t.Fatal("unknown permission")
	}
	if Allowed(ctx, c, Subjects{TenantID: tn, UserID: "admin", ActorKind: "robot"}, ZonesRead) {
		t.Fatal("unknown actor kind")
	}
	called := false
	fn := CheckerFunc(func(_ context.Context, tenant, user, perm string) bool {
		called = true
		return tenant == tn && user == "admin" && perm == DashboardRead
	})
	if !Allowed(ctx, fn, admin, DashboardRead) || !called {
		t.Fatal("checker func")
	}
}

func TestRequireNonHuman(t *testing.T) {
	sync := SystemFor(tn)
	if sync.TenantID != tn || sync.UserID != IPAMSyncActorID || sync.ActorKind != ActorIPAMSync || sync.IsHuman() || sync.IsPlatformAdmin() {
		t.Fatalf("SystemFor = %+v", sync)
	}
	for _, p := range []string{ZonesRead, ZonesManage} {
		if err := Require(ctx, nil, sync, p); err != nil {
			t.Fatalf("sync %s: %v", p, err)
		}
	}
	for _, p := range []string{TemplatesManage, SupermastersManage, DashboardRead, BackupManage, ConfigManage} {
		if Allowed(ctx, nil, sync, p) {
			t.Fatalf("sync must not hold %s", p)
		}
	}
	if Allowed(ctx, nil, SystemFor(""), ZonesRead) {
		t.Fatal("sync without tenant")
	}
	mod := Module(tn, "spiffe://example.org/svc/deployer")
	if !Allowed(ctx, nil, mod, ZonesRead) || Allowed(ctx, nil, mod, ZonesManage) || mod.IsPlatformAdmin() {
		t.Fatal("module grants")
	}
	if Allowed(ctx, nil, Subjects{TenantID: tn, UserID: "x", ActorKind: ActorModule}, ZonesRead) {
		t.Fatal("module without verified peer")
	}
	sys := Internal(tn)
	for _, p := range Permissions {
		if !Allowed(ctx, nil, sys, p) {
			t.Fatalf("system %s", p)
		}
	}
}

// Tenant owners/admins are NOT platform administrators; only the
// platform-admin role on a signed-in user, or the system scope, is.
func TestPlatformAdminIsStrict(t *testing.T) {
	c := Static{"owner": Permissions, "pa": Permissions}
	owner := User(tn, "owner", []string{"owner", "admin"})
	pa := User(tn, "pa", []string{RolePlatformAdmin})
	if owner.IsPlatformAdmin() {
		t.Fatal("tenant owner treated as platform admin")
	}
	if err := RequireAdmin(ctx, c, owner, ConfigManage); !errors.Is(err, ErrForbidden) {
		t.Fatalf("owner config: %v", err)
	}
	if err := RequireAdmin(ctx, c, pa, ConfigManage); err != nil {
		t.Fatalf("platform admin config: %v", err)
	}
	if err := RequireAdmin(ctx, Static{}, pa, ConfigManage); !errors.Is(err, ErrForbidden) {
		t.Fatal("platform admin still needs the permission")
	}
	if err := RequireAdmin(ctx, nil, Internal(""), ConfigManage); !errors.Is(err, ErrForbidden) {
		t.Fatal("system scope still needs a tenant for Require")
	}
	if err := RequireAdmin(ctx, nil, Internal(tn), ConfigManage); err != nil {
		t.Fatalf("system: %v", err)
	}
	// forged: a module or the sync carrying the role is not an admin
	forged := Module(tn, lcm)
	forged.Roles = []string{RolePlatformAdmin}
	syncForged := SystemFor(tn)
	syncForged.Roles = []string{RolePlatformAdmin}
	noID := Subjects{TenantID: tn, Roles: []string{RolePlatformAdmin}, ActorKind: ActorUser}
	for _, s := range []Subjects{forged, syncForged, noID} {
		if s.IsPlatformAdmin() || RequirePlatformAdmin(s) == nil {
			t.Fatalf("forged platform admin %+v", s)
		}
	}
}

func TestCallerIs(t *testing.T) {
	if err := CallerIs(Module(tn, lcm), lcm); err != nil {
		t.Fatal(err)
	}
	for _, s := range []Subjects{
		Module(tn, "spiffe://example.org/svc/deployer"),
		Module(tn, lcm+"/x"),
		Module(tn, "spiffe://example.org/svc/LCM"),
		{TenantID: tn, UserID: lcm, ActorKind: ActorModule}, // user id is not the verified peer
		{TenantID: tn, UserID: "u", ActorKind: ActorUser, PeerSPIFFE: lcm},
		Internal(tn),
		SystemFor(tn),
	} {
		if err := CallerIs(s, lcm); !errors.Is(err, ErrForbidden) {
			t.Fatalf("forged caller %+v accepted", s)
		}
	}
	if CallerIs(Module(tn, lcm), "") == nil {
		t.Fatal("empty expected id")
	}
	if CallerIs(Module(tn, "spiffe://example.org/svc/*"), "spiffe://example.org/svc/*") == nil {
		t.Fatal("wildcard honoured")
	}
}

func TestSubjectsHelpers(t *testing.T) {
	roles := []string{"member", RolePlatformAdmin}
	a := User(tn, "u", roles)
	roles[0] = "mutated"
	if !a.HasRole("member") || a.HasRole("owner") || !a.IsPlatformAdmin() || !a.IsHuman() || a.ActorID() != "u" {
		t.Fatal("helpers")
	}
	if (Subjects{ActorKind: ActorSystem}).ActorID() != ActorSystem {
		t.Fatal("actor id fallback")
	}
	if err := RequirePlatformAdmin(a); err != nil {
		t.Fatal(err)
	}
	if err := RequireTenant(a, tn); err != nil {
		t.Fatal(err)
	}
	if !errors.Is(RequireTenant(a, "other"), ErrForbidden) || !errors.Is(RequireTenant(a, ""), ErrForbidden) {
		t.Fatal("tenant mismatch")
	}
	if !Known(ConfigManage) || Known("x:y") {
		t.Fatal("known")
	}
	if r, act, ok := Split(ZonesManage); !ok || r != "zones" || act != "manage" {
		t.Fatal("split")
	}
	for _, bad := range []string{"zones", ":read", "zones:"} {
		if _, _, ok := Split(bad); ok {
			t.Fatalf("split %q", bad)
		}
	}
	if len(Permissions) != 7 {
		t.Fatalf("permissions = %d", len(Permissions))
	}
}

func TestChallenger(t *testing.T) {
	ctx := context.Background()
	// A plain module may only read zones.
	if Require(ctx, nil, Module(tn, lcm), ZonesManage) == nil {
		t.Fatal("a module must not manage zones")
	}
	c, err := Challenger(Module(tn, lcm), lcm)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{ZonesRead, ZonesManage} {
		if err := Require(ctx, nil, c, p); err != nil {
			t.Errorf("challenger %s: %v", p, err)
		}
	}
	for _, p := range []string{TemplatesManage, ConfigManage, BackupManage} {
		if Require(ctx, nil, c, p) == nil {
			t.Errorf("challenger must not hold %s", p)
		}
	}
	if c.IsPlatformAdmin() || c.ActorKind != ActorModule || c.PeerSPIFFE != lcm {
		t.Fatalf("challenger = %+v", c)
	}
	for _, s := range []Subjects{Module(tn, "spiffe://example.org/svc/deployer"), User(tn, "u", []string{RolePlatformAdmin}), Internal(tn), {}} {
		if _, err := Challenger(s, lcm); !errors.Is(err, ErrForbidden) {
			t.Errorf("Challenger(%+v) = %v", s, err)
		}
	}
}
