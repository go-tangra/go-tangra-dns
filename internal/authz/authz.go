// Package authz is the DNS module's access model (research D16). Every browser
// route declares one API permission (x-freya-permission); the module enforces
// it itself (defence in depth behind the gateway) by asking the auth service
// through a Checker. Callers are scoped to exactly one tenant.
//
// Non-human actors never go through the Checker:
//   - the IPAM sync worker acts as SystemFor(tenant): a subject pinned to the
//     tenant whose event stream it consumes, allowed only what the sync needs
//     (read/manage zones and records) — never a bypass, never platform admin;
//   - mesh modules (gRPC, SPIFFE-authenticated and policy allow-listed) may
//     only read zones of the tenant named in the request; privileged module
//     operations (ACME challenges) additionally require CallerIs(<exact ID>);
//   - the system scope (start-up re-apply, reconcilers) may do everything.
//
// Platform administration (server configuration, supermaster create/delete,
// cross-tenant restore) is strict: only the platform-admin role or the system
// scope. A tenant owner/admin is NOT a platform administrator.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// ErrForbidden is returned when a caller lacks the required permission or scope.
var ErrForbidden = errors.New("authz: forbidden")

// Actor kinds (closed set).
const (
	ActorUser     = "user"      // a signed-in platform user (via the gateway)
	ActorModule   = "module"    // a mesh peer (SPIFFE) acting for a tenant
	ActorIPAMSync = "ipam-sync" // the IPAM sync worker, pinned to one tenant
	ActorSystem   = "system"    // trusted internal maintenance
)

// IPAMSyncActorID is the actor id recorded for IPAM sync writes.
const IPAMSyncActorID = "ipam-sync"

// API permissions (resource:action).
const (
	ZonesRead          = "zones:read"
	ZonesManage        = "zones:manage"
	TemplatesManage    = "templates:manage"
	SupermastersManage = "supermasters:manage"
	DashboardRead      = "dashboard:read"
	BackupManage       = "backup:manage"
	ConfigManage       = "config:manage"
)

// Permissions lists every module permission.
var Permissions = []string{ZonesRead, ZonesManage, TemplatesManage, SupermastersManage, DashboardRead, BackupManage, ConfigManage}

// RolePlatformAdmin confers platform administration (configuration,
// supermasters, cross-tenant restore).
const RolePlatformAdmin = "platform-admin"

// syncAllowed is what the IPAM sync worker may do within its tenant.
var syncAllowed = map[string]bool{ZonesRead: true, ZonesManage: true}

// moduleAllowed is what a mesh peer may do (contracts §B: Zones read-only).
var moduleAllowed = map[string]bool{ZonesRead: true}

// challengeAllowed is what the verified ACME caller (lcm) may do once
// Challenger admitted it: read zones and write the challenge TXT values.
var challengeAllowed = map[string]bool{ZonesRead: true, ZonesManage: true}

// Subjects is the authenticated caller.
type Subjects struct {
	TenantID   string
	UserID     string
	Roles      []string
	ActorKind  string // user | module | ipam-sync | system
	PeerSPIFFE string // the verified SPIFFE ID of a module caller

	// acme marks a module subject admitted by Challenger (unexported: only
	// this package can confer it).
	acme bool
}

// Checker answers "does this user hold this API permission in this tenant"
// (the auth service's Authorization/Check; a map in tests). A failed lookup is
// a "no".
type Checker interface {
	Has(ctx context.Context, tenantID, userID, permission string) bool
}

// CheckerFunc adapts a function to Checker.
type CheckerFunc func(ctx context.Context, tenantID, userID, permission string) bool

// Has implements Checker.
func (f CheckerFunc) Has(ctx context.Context, tenantID, userID, permission string) bool {
	return f(ctx, tenantID, userID, permission)
}

// Static is a Checker over a fixed user → permissions map (tests, dev).
type Static map[string][]string

// Has implements Checker.
func (s Static) Has(_ context.Context, _, userID, permission string) bool {
	for _, p := range s[userID] {
		if p == permission {
			return true
		}
	}
	return false
}

// User returns the subject of a signed-in user.
func User(tenantID, userID string, roles []string) Subjects {
	return Subjects{TenantID: tenantID, UserID: userID, Roles: append([]string(nil), roles...), ActorKind: ActorUser}
}

// SystemFor returns the scoped subject the IPAM sync writes under: pinned to
// the tenant whose stream it consumes, recorded as "ipam-sync".
func SystemFor(tenantID string) Subjects {
	return Subjects{TenantID: tenantID, UserID: IPAMSyncActorID, ActorKind: ActorIPAMSync}
}

// Internal returns the trusted system subject for one tenant ("" = platform scope).
func Internal(tenantID string) Subjects {
	return Subjects{TenantID: tenantID, UserID: ActorSystem, ActorKind: ActorSystem}
}

// Module returns the subject of a mesh peer acting for tenantID.
func Module(tenantID, spiffeID string) Subjects {
	return Subjects{TenantID: tenantID, UserID: spiffeID, ActorKind: ActorModule, PeerSPIFFE: spiffeID}
}

// HasRole reports whether the caller carries role.
func (s Subjects) HasRole(role string) bool {
	for _, r := range s.Roles {
		if r == role {
			return true
		}
	}
	return false
}

// IsPlatformAdmin reports whether the caller may administer the platform-wide
// DNS servers: ONLY a signed-in user holding the platform-admin role, or the
// system scope. Tenant owners/admins, modules and the IPAM sync never are.
func (s Subjects) IsPlatformAdmin() bool {
	switch s.ActorKind {
	case ActorSystem:
		return true
	case ActorUser:
		return s.UserID != "" && s.HasRole(RolePlatformAdmin)
	}
	return false
}

// ActorID is the user id (or SPIFFE ID), falling back to the actor kind.
func (s Subjects) ActorID() string {
	if s.UserID != "" {
		return s.UserID
	}
	return s.ActorKind
}

// IsHuman reports whether the caller is a signed-in user.
func (s Subjects) IsHuman() bool { return s.ActorKind == ActorUser }

// Known reports whether perm is a module permission.
func Known(perm string) bool {
	for _, p := range Permissions {
		if p == perm {
			return true
		}
	}
	return false
}

// Require checks that the caller holds perm within its own tenant. Users are
// checked through c (nil c refuses); the IPAM sync and module actors are
// limited to their fixed allow-lists; the system scope is allowed everything.
func Require(ctx context.Context, c Checker, s Subjects, perm string) error {
	if s.TenantID == "" {
		return fmt.Errorf("%w: tenant required", ErrForbidden)
	}
	if !Known(perm) {
		return fmt.Errorf("%w: unknown permission %q", ErrForbidden, perm)
	}
	switch s.ActorKind {
	case ActorSystem:
		return nil
	case ActorIPAMSync:
		if syncAllowed[perm] {
			return nil
		}
	case ActorModule:
		if s.PeerSPIFFE != "" && (moduleAllowed[perm] || (s.acme && challengeAllowed[perm])) {
			return nil
		}
	case ActorUser:
		if c != nil && s.UserID != "" && c.Has(ctx, s.TenantID, s.UserID, perm) {
			return nil
		}
	}
	return fmt.Errorf("%w: %s required", ErrForbidden, perm)
}

// Allowed is Require as a boolean.
func Allowed(ctx context.Context, c Checker, s Subjects, perm string) bool {
	return Require(ctx, c, s, perm) == nil
}

// RequireAdmin is Require(perm) AND platform-admin authority (server
// configuration, supermaster create/delete).
func RequireAdmin(ctx context.Context, c Checker, s Subjects, perm string) error {
	if err := RequirePlatformAdmin(s); err != nil {
		return err
	}
	return Require(ctx, c, s, perm)
}

// RequireTenant ensures the caller acts within tenantID (its own tenant only;
// there is no cross-tenant actor on the request paths).
func RequireTenant(s Subjects, tenantID string) error {
	if tenantID == "" || s.TenantID != tenantID {
		return fmt.Errorf("%w: tenant mismatch", ErrForbidden)
	}
	return nil
}

// RequirePlatformAdmin permits only platform admins (or the system scope).
func RequirePlatformAdmin(s Subjects) error {
	if s.IsPlatformAdmin() {
		return nil
	}
	return fmt.Errorf("%w: platform-admin required", ErrForbidden)
}

// CallerIs permits only a module caller whose verified peer SPIFFE ID equals
// spiffeID exactly (e.g. the lcm identity for ACME challenges). The ID is the
// transport-verified peer, never a request field; no wildcard is honoured.
func CallerIs(s Subjects, spiffeID string) error {
	if s.ActorKind != ActorModule || spiffeID == "" || s.PeerSPIFFE == "" || s.PeerSPIFFE != spiffeID || strings.Contains(spiffeID, "*") {
		return fmt.Errorf("%w: caller not allowed", ErrForbidden)
	}
	return nil
}

// Split returns the resource and action of a "resource:action" permission.
func Split(perm string) (resource, action string, ok bool) {
	resource, action, ok = strings.Cut(perm, ":")
	return resource, action, ok && resource != "" && action != ""
}

// Challenger admits the ACME challenge caller: the subject must pass
// CallerIs(allowed) and is then allowed to write zone records within its
// tenant (the challenge service restricts it to _acme-challenge TXT values).
// It is never a platform administrator.
func Challenger(s Subjects, allowed string) (Subjects, error) {
	if err := CallerIs(s, allowed); err != nil {
		return Subjects{}, err
	}
	s.acme = true
	return s, nil
}
