package service

import (
	"context"
	"errors"
	"strings"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/data"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	entZone "github.com/go-tangra/go-tangra-dns/internal/data/ent/zone"
	"github.com/go-tangra/go-tangra-dns/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/internal/recursor"
)

type ZoneService struct {
	dnsV1.UnimplementedDnsZoneServiceServer

	log         *log.Helper
	repo        *data.ZoneRepo
	tplRepo     *data.ZoneTemplateRepo
	pdnsCli     *pdns.Client
	recursorCli *recursor.Client
}

func NewZoneService(
	ctx *bootstrap.Context,
	repo *data.ZoneRepo,
	tplRepo *data.ZoneTemplateRepo,
	pdnsCli *pdns.Client,
	recursorCli *recursor.Client,
) *ZoneService {
	return &ZoneService{
		log:         ctx.NewLoggerHelper("dns/service/zone"),
		repo:        repo,
		tplRepo:     tplRepo,
		pdnsCli:     pdnsCli,
		recursorCli: recursorCli,
	}
}

func (s *ZoneService) CreateZone(ctx context.Context, req *dnsV1.CreateZoneRequest) (*dnsV1.CreateZoneResponse, error) {
	tenantID := getTenantID(ctx)
	name := canonicalName(req.GetName())
	entKind, pdnsKind := kindFromProto(req.GetKind())

	// Build the PowerDNS create request.
	pdnsZone := &pdns.Zone{
		Name:        name,
		Kind:        pdnsKind,
		Nameservers: req.GetNameservers(),
		DNSSEC:      req.GetDnssecEnabled(),
	}
	if req.GetMasters() != "" {
		pdnsZone.Masters = splitCSV(req.GetMasters())
	}

	// Apply template records if requested.
	if tplID := req.GetTemplateId(); tplID != "" {
		tpl, err := s.tplRepo.Get(ctx, tenantID, tplID)
		if err != nil {
			return nil, status.Errorf(codes.NotFound, "template not found: %v", err)
		}
		pdnsZone.RRsets = expandTemplate(tpl, name)
	}

	createdPdns, err := s.pdnsCli.CreateZone(ctx, pdnsZone)
	if err != nil {
		s.log.WithContext(ctx).Errorf("powerdns create zone failed: %v", err)
		return nil, status.Errorf(codes.Unavailable, "powerdns create zone failed: %v", err)
	}

	// Persist local row.
	row := &ent.Zone{
		ID:            uuid.NewString(),
		TenantID:      &tenantID,
		PdnsID:        createdPdns.ID,
		Name:          name,
		Kind:          entKind,
		Masters:       req.GetMasters(),
		DnssecEnabled: req.GetDnssecEnabled(),
		Description:   req.GetDescription(),
		TemplateID:    req.GetTemplateId(),
	}
	saved, err := s.repo.Create(ctx, row)
	if err != nil {
		s.log.WithContext(ctx).Errorf("persist zone failed: %v", err)
		// Roll back PowerDNS create — leave best-effort.
		_ = s.pdnsCli.DeleteZone(ctx, createdPdns.ID)
		return nil, status.Errorf(codes.Internal, "persist zone: %v", err)
	}

	// Point the recursor's forward entry for this zone at the auth server,
	// so client queries for it resolve through the recursor. Best-effort.
	if s.recursorCli != nil {
		if err := s.recursorCli.SyncForwardZone(ctx, name); err != nil {
			s.log.WithContext(ctx).Warnf("recursor forward sync failed for %s: %v", name, err)
		}
	}

	return &dnsV1.CreateZoneResponse{Zone: zoneToProto(saved, createdPdns.Serial)}, nil
}

func (s *ZoneService) GetZone(ctx context.Context, req *dnsV1.GetZoneRequest) (*dnsV1.GetZoneResponse, error) {
	tenantID := getTenantID(ctx)
	z, err := s.repo.Get(ctx, tenantID, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}
	var serial uint32
	if pz, err := s.pdnsCli.GetZone(ctx, z.PdnsID); err == nil {
		serial = pz.Serial
	}
	return &dnsV1.GetZoneResponse{Zone: zoneToProto(z, serial)}, nil
}

func (s *ZoneService) ListZones(ctx context.Context, req *dnsV1.ListZonesRequest) (*dnsV1.ListZonesResponse, error) {
	tenantID := getTenantID(ctx)
	page, pageSize := normalizePaging(req.GetPage(), req.GetPageSize())
	offset := (page - 1) * pageSize

	zones, total, err := s.repo.List(ctx, tenantID, offset, pageSize, req.GetSearch())
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list zones: %v", err)
	}

	out := &dnsV1.ListZonesResponse{Total: int32(total)}
	for _, z := range zones {
		// Filter by kind if requested.
		if req.GetKind() != dnsV1.ZoneKind_ZONE_KIND_UNSPECIFIED &&
			kindToProto(z.Kind) != req.GetKind() {
			continue
		}
		out.Zones = append(out.Zones, zoneToProto(z, 0))
	}
	return out, nil
}

func (s *ZoneService) UpdateZone(ctx context.Context, req *dnsV1.UpdateZoneRequest) (*dnsV1.UpdateZoneResponse, error) {
	tenantID := getTenantID(ctx)

	zone, err := s.repo.Get(ctx, tenantID, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}

	// Build PowerDNS metadata patch.
	pdnsPatch := &pdns.Zone{Name: zone.Name}
	if req.Kind != nil {
		_, pdnsKind := kindFromProto(req.GetKind())
		pdnsPatch.Kind = pdnsKind
	}
	if req.Masters != nil {
		pdnsPatch.Masters = splitCSV(req.GetMasters())
	}
	if req.DnssecEnabled != nil {
		pdnsPatch.DNSSEC = req.GetDnssecEnabled()
	}
	if err := s.pdnsCli.UpdateZoneMetadata(ctx, zone.PdnsID, pdnsPatch); err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns update: %v", err)
	}

	updated, err := s.repo.Update(ctx, tenantID, req.GetId(), func(u *ent.ZoneUpdateOne) {
		if req.Kind != nil {
			entKind, _ := kindFromProto(req.GetKind())
			u.SetKind(entKind)
		}
		if req.Masters != nil {
			u.SetMasters(req.GetMasters())
		}
		if req.Description != nil {
			u.SetDescription(req.GetDescription())
		}
		if req.DnssecEnabled != nil {
			u.SetDnssecEnabled(req.GetDnssecEnabled())
		}
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "persist update: %v", err)
	}
	return &dnsV1.UpdateZoneResponse{Zone: zoneToProto(updated, 0)}, nil
}

func (s *ZoneService) DeleteZone(ctx context.Context, req *dnsV1.DeleteZoneRequest) (*emptypb.Empty, error) {
	tenantID := getTenantID(ctx)
	zone, err := s.repo.Get(ctx, tenantID, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}
	if err := s.pdnsCli.DeleteZone(ctx, zone.PdnsID); err != nil && !errors.Is(err, pdns.ErrNotFound) {
		return nil, status.Errorf(codes.Unavailable, "powerdns delete: %v", err)
	}
	if err := s.repo.Delete(ctx, tenantID, req.GetId()); err != nil {
		return nil, status.Errorf(codes.Internal, "persist delete: %v", err)
	}

	// Remove the recursor's forward entry for this zone. Best-effort.
	if s.recursorCli != nil {
		if err := s.recursorCli.RemoveForwardZone(ctx, zone.Name); err != nil {
			s.log.WithContext(ctx).Warnf("recursor forward removal failed for %s: %v", zone.Name, err)
		}
	}

	return &emptypb.Empty{}, nil
}

func (s *ZoneService) ExportZone(ctx context.Context, req *dnsV1.ExportZoneRequest) (*dnsV1.ExportZoneResponse, error) {
	tenantID := getTenantID(ctx)
	zone, err := s.repo.Get(ctx, tenantID, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}
	bind, err := s.pdnsCli.ExportZone(ctx, zone.PdnsID)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns export: %v", err)
	}
	return &dnsV1.ExportZoneResponse{BindZone: bind}, nil
}

func (s *ZoneService) NotifyZone(ctx context.Context, req *dnsV1.NotifyZoneRequest) (*emptypb.Empty, error) {
	tenantID := getTenantID(ctx)
	zone, err := s.repo.Get(ctx, tenantID, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}
	if zone.Kind != entZone.KindMASTER {
		return nil, status.Error(codes.FailedPrecondition, "notify only allowed for MASTER zones")
	}
	if err := s.pdnsCli.NotifyZone(ctx, zone.PdnsID); err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns notify: %v", err)
	}
	return &emptypb.Empty{}, nil
}

// expandTemplate produces PowerDNS RRsets from a stored template by
// expanding the [ZONE] placeholder.
func expandTemplate(tpl *ent.ZoneTemplate, zoneName string) []pdns.RRset {
	zone := zoneName
	if len(zone) > 0 && zone[len(zone)-1] == '.' {
		zone = zone[:len(zone)-1]
	}
	out := make([]pdns.RRset, 0, len(tpl.Records))
	for _, r := range tpl.Records {
		name := r.Name
		content := r.Content
		name = replacePlaceholder(name, zone)
		content = replacePlaceholder(content, zone)
		if name == "" || name == "@" {
			name = zoneName
		} else if name[len(name)-1] != '.' {
			name = name + "." + zoneName
		}
		out = append(out, pdns.RRset{
			Name:       name,
			Type:       r.Type,
			TTL:        r.TTL,
			ChangeType: "REPLACE",
			Records:    []pdns.RRsetRecord{{Content: content}},
		})
	}
	return out
}

func replacePlaceholder(s, zone string) string {
	return strings.ReplaceAll(s, "[ZONE]", zone)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

func normalizePaging(page, pageSize int32) (int, int) {
	if page <= 0 {
		page = 1
	}
	if pageSize <= 0 || pageSize > 200 {
		pageSize = 50
	}
	return int(page), int(pageSize)
}
