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
	"github.com/go-tangra/go-tangra-dns/internal/pdns"
)

type SupermasterService struct {
	dnsV1.UnimplementedDnsSupermasterServiceServer

	log     *log.Helper
	repo    *data.SupermasterRepo
	pdnsCli *pdns.Client
}

func NewSupermasterService(
	ctx *bootstrap.Context,
	repo *data.SupermasterRepo,
	pdnsCli *pdns.Client,
) *SupermasterService {
	return &SupermasterService{
		log:     ctx.NewLoggerHelper("dns/service/supermaster"),
		repo:    repo,
		pdnsCli: pdnsCli,
	}
}

func (s *SupermasterService) CreateSupermaster(ctx context.Context, req *dnsV1.CreateSupermasterRequest) (*dnsV1.CreateSupermasterResponse, error) {
	tenantID := getTenantID(ctx)

	if err := s.pdnsCli.CreateSupermaster(ctx, &pdns.Supermaster{
		IP:         req.GetIp(),
		Nameserver: req.GetNameserver(),
		Account:    req.GetAccount(),
	}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns create supermaster: %v", err)
	}

	saved, err := s.repo.Create(ctx, &ent.Supermaster{
		ID:         uuid.NewString(),
		TenantID:   &tenantID,
		IP:         req.GetIp(),
		Nameserver: req.GetNameserver(),
		Account:    req.GetAccount(),
	})
	if err != nil {
		// best-effort rollback
		_ = s.pdnsCli.DeleteSupermaster(ctx, req.GetIp(), req.GetNameserver())
		return nil, status.Errorf(codes.Internal, "persist supermaster: %v", err)
	}
	return &dnsV1.CreateSupermasterResponse{Supermaster: supermasterToProto(saved)}, nil
}

func (s *SupermasterService) GetSupermaster(ctx context.Context, req *dnsV1.GetSupermasterRequest) (*dnsV1.GetSupermasterResponse, error) {
	sm, err := s.repo.Get(ctx, getTenantID(ctx), req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "supermaster not found: %v", err)
	}
	return &dnsV1.GetSupermasterResponse{Supermaster: supermasterToProto(sm)}, nil
}

func (s *SupermasterService) ListSupermasters(ctx context.Context, req *dnsV1.ListSupermastersRequest) (*dnsV1.ListSupermastersResponse, error) {
	tenantID := getTenantID(ctx)
	page, pageSize := normalizePaging(req.GetPage(), req.GetPageSize())
	items, total, err := s.repo.List(ctx, tenantID, (page-1)*pageSize, pageSize)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list supermasters: %v", err)
	}
	out := &dnsV1.ListSupermastersResponse{Total: int32(total)}
	for _, sm := range items {
		out.Supermasters = append(out.Supermasters, supermasterToProto(sm))
	}
	return out, nil
}

func (s *SupermasterService) DeleteSupermaster(ctx context.Context, req *dnsV1.DeleteSupermasterRequest) (*emptypb.Empty, error) {
	tenantID := getTenantID(ctx)
	sm, err := s.repo.Get(ctx, tenantID, req.GetId())
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "supermaster not found: %v", err)
	}
	if err := s.pdnsCli.DeleteSupermaster(ctx, sm.IP, sm.Nameserver); err != nil {
		s.log.WithContext(ctx).Warnf("powerdns delete supermaster failed: %v", err)
	}
	if err := s.repo.Delete(ctx, tenantID, req.GetId()); err != nil {
		return nil, status.Errorf(codes.Internal, "persist delete: %v", err)
	}
	return &emptypb.Empty{}, nil
}
