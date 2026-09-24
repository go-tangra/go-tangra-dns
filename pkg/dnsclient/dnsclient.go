// Package dnsclient is a thin, typed Go client for the dns.v1
// service-to-service gRPC API (contracts §B), for other Freya modules: the
// certificate service (lcm) publishes and removes ACME DNS-01 challenge values
// (Present/CleanUp — the DNS module serves them to the lcm identity only), and
// any module may read a tenant's managed zones. The caller supplies a
// connected SPIFFE-mTLS *grpc.ClientConn (e.g. from freya.App.Client(ctx,
// "dns")); this package does not dial. Errors are typed sentinels; the
// server's status message is never surfaced.
package dnsclient

import (
	"context"
	"errors"
	"fmt"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	dnsv1 "github.com/go-tangra/go-tangra-dns/v4/api/proto/dns/v1"
)

// Typed errors (mapped from the gRPC status code only).
var (
	ErrNotFound         = errors.New("dnsclient: not found")           // no zone of the tenant contains the name
	ErrPermissionDenied = errors.New("dnsclient: permission denied")   // the caller identity is not allowed
	ErrInvalid          = errors.New("dnsclient: invalid request")     // malformed name/value/tenant
	ErrPrecondition     = errors.New("dnsclient: precondition failed") // e.g. a CNAME at the challenge name
	ErrUnavailable      = errors.New("dnsclient: dns unavailable")     // DNS module or PowerDNS down
	ErrFailed           = errors.New("dnsclient: request failed")      // anything else
)

// Zone is a managed zone of a tenant.
type Zone struct {
	ID          string
	Name        string // canonical, trailing dot
	Kind        string
	DNSSEC      bool
	Origin      string
	Description string
	Masters     []string
	CreatedAt   time.Time
	UpdatedAt   time.Time
}

// Client calls dns.v1 over a caller-provided connection.
type Client struct {
	challenges dnsv1.ChallengesClient
	zones      dnsv1.ZonesClient
}

// New builds a client from a connected (SPIFFE-mTLS) gRPC connection.
func New(conn grpc.ClientConnInterface) *Client {
	return &Client{challenges: dnsv1.NewChallengesClient(conn), zones: dnsv1.NewZonesClient(conn)}
}

func mapErr(err error) error {
	if err == nil {
		return nil
	}
	var sentinel error
	switch status.Code(err) {
	case codes.NotFound:
		sentinel = ErrNotFound
	case codes.PermissionDenied, codes.Unauthenticated:
		sentinel = ErrPermissionDenied
	case codes.InvalidArgument:
		sentinel = ErrInvalid
	case codes.FailedPrecondition:
		sentinel = ErrPrecondition
	case codes.Unavailable, codes.DeadlineExceeded:
		sentinel = ErrUnavailable
	default:
		sentinel = ErrFailed
	}
	return fmt.Errorf("%w (%s)", sentinel, status.Code(err))
}

// Present publishes an ACME DNS-01 value at fqdn in the tenant's zone.
func (c *Client) Present(ctx context.Context, tenantID, domain, fqdn, value string) error {
	_, err := c.challenges.Present(ctx, &dnsv1.ChallengeRequest{TenantId: tenantID, Domain: domain, Fqdn: fqdn, Value: value})
	return mapErr(err)
}

// CleanUp removes an ACME DNS-01 value from fqdn (absent = success).
func (c *Client) CleanUp(ctx context.Context, tenantID, domain, fqdn, value string) error {
	_, err := c.challenges.CleanUp(ctx, &dnsv1.ChallengeRequest{TenantId: tenantID, Domain: domain, Fqdn: fqdn, Value: value})
	return mapErr(err)
}

func toTime(t *dnsv1.Timestamp) time.Time {
	if t == nil || t.GetUnix() == 0 {
		return time.Time{}
	}
	return time.Unix(t.GetUnix(), 0).UTC()
}

func toZone(z *dnsv1.Zone) Zone {
	return Zone{ID: z.GetId(), Name: z.GetName(), Kind: z.GetKind(), DNSSEC: z.GetDnssec(), Origin: z.GetOrigin(),
		Description: z.GetDescription(), Masters: append([]string(nil), z.GetMasters()...),
		CreatedAt: toTime(z.GetCreatedAt()), UpdatedAt: toTime(z.GetUpdatedAt())}
}

// ListZones pages the tenant's zones (name substring query; page is 1-based,
// pageSize <= 100) and returns the total match count.
func (c *Client) ListZones(ctx context.Context, tenantID, query string, page, pageSize int32) ([]Zone, int64, error) {
	resp, err := c.zones.List(ctx, &dnsv1.ListZonesRequest{TenantId: tenantID, Query: query, Page: page, PageSize: pageSize})
	if err != nil {
		return nil, 0, mapErr(err)
	}
	out := make([]Zone, 0, len(resp.GetItems()))
	for _, z := range resp.GetItems() {
		out = append(out, toZone(z))
	}
	return out, resp.GetTotal(), nil
}

// GetZone returns one zone of the tenant by id.
func (c *Client) GetZone(ctx context.Context, tenantID, id string) (Zone, error) {
	z, err := c.zones.Get(ctx, &dnsv1.GetZoneRequest{TenantId: tenantID, Id: id})
	if err != nil {
		return Zone{}, mapErr(err)
	}
	return toZone(z), nil
}

// GetZoneByName returns one zone of the tenant by its name.
func (c *Client) GetZoneByName(ctx context.Context, tenantID, name string) (Zone, error) {
	z, err := c.zones.Get(ctx, &dnsv1.GetZoneRequest{TenantId: tenantID, Name: name})
	if err != nil {
		return Zone{}, mapErr(err)
	}
	return toZone(z), nil
}

// FindForName returns the tenant's longest managed zone containing name.
func (c *Client) FindForName(ctx context.Context, tenantID, name string) (Zone, error) {
	z, err := c.zones.FindForName(ctx, &dnsv1.FindForNameRequest{TenantId: tenantID, Name: name})
	if err != nil {
		return Zone{}, mapErr(err)
	}
	return toZone(z), nil
}
