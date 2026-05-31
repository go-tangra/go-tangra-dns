package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/google/uuid"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/data"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent/schema"
)

// ZoneTemplateService manages reusable zone templates. Templates are purely
// module-local metadata (PowerDNS has no template concept), so there is no
// PowerDNS interaction here.
type ZoneTemplateService struct {
	dnsV1.UnimplementedDnsZoneTemplateServiceServer

	log  *log.Helper
	repo *data.ZoneTemplateRepo
}

func NewZoneTemplateService(
	ctx *bootstrap.Context,
	repo *data.ZoneTemplateRepo,
) *ZoneTemplateService {
	return &ZoneTemplateService{
		log:  ctx.NewLoggerHelper("dns/service/zone_template"),
		repo: repo,
	}
}

func (s *ZoneTemplateService) CreateZoneTemplate(ctx context.Context, req *dnsV1.CreateZoneTemplateRequest) (*dnsV1.CreateZoneTemplateResponse, error) {
	tenantID := getTenantID(ctx)

	saved, err := s.repo.Create(ctx, &ent.ZoneTemplate{
		ID:          uuid.NewString(),
		TenantID:    &tenantID,
		Name:        req.GetName(),
		Description: req.GetDescription(),
		Records:     zoneTemplateStanzasFromProto(req.GetRecords()),
	})
	if err != nil {
		return nil, status.Errorf(codes.Internal, "persist zone template: %v", err)
	}
	return &dnsV1.CreateZoneTemplateResponse{Template: zoneTemplateToProto(saved)}, nil
}

func (s *ZoneTemplateService) GetZoneTemplate(ctx context.Context, req *dnsV1.GetZoneTemplateRequest) (*dnsV1.GetZoneTemplateResponse, error) {
	tpl, err := s.repo.Get(ctx, getTenantID(ctx), req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone template not found: %v", err)
	}
	return &dnsV1.GetZoneTemplateResponse{Template: zoneTemplateToProto(tpl)}, nil
}

func (s *ZoneTemplateService) ListZoneTemplates(ctx context.Context, req *dnsV1.ListZoneTemplatesRequest) (*dnsV1.ListZoneTemplatesResponse, error) {
	tenantID := getTenantID(ctx)
	page, pageSize := normalizePaging(req.GetPage(), req.GetPageSize())
	items, total, err := s.repo.List(ctx, tenantID, (page-1)*pageSize, pageSize)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list zone templates: %v", err)
	}
	out := &dnsV1.ListZoneTemplatesResponse{Total: int32(total)}
	for _, tpl := range items {
		out.Templates = append(out.Templates, zoneTemplateToProto(tpl))
	}
	return out, nil
}

func (s *ZoneTemplateService) UpdateZoneTemplate(ctx context.Context, req *dnsV1.UpdateZoneTemplateRequest) (*dnsV1.UpdateZoneTemplateResponse, error) {
	tenantID := getTenantID(ctx)

	var records []schema.TemplateRecordStanza
	if req.GetRecords() != nil {
		records = zoneTemplateStanzasFromProto(req.GetRecords())
	}

	updated, err := s.repo.Update(ctx, tenantID, req.GetId(), req.Name, req.Description, records)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "update zone template: %v", err)
	}
	return &dnsV1.UpdateZoneTemplateResponse{Template: zoneTemplateToProto(updated)}, nil
}

func (s *ZoneTemplateService) DeleteZoneTemplate(ctx context.Context, req *dnsV1.DeleteZoneTemplateRequest) (*emptypb.Empty, error) {
	if err := s.repo.Delete(ctx, getTenantID(ctx), req.GetId()); err != nil {
		return nil, status.Errorf(codes.Internal, "delete zone template: %v", err)
	}
	return &emptypb.Empty{}, nil
}
