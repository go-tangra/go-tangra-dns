package service

import (
	"context"

	"github.com/go-kratos/kratos/v2/log"
	"github.com/tx7do/kratos-bootstrap/bootstrap"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/data"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	"github.com/go-tangra/go-tangra-dns/internal/pdns"
)

type RecordService struct {
	dnsV1.UnimplementedDnsRecordServiceServer

	log      *log.Helper
	zoneRepo *data.ZoneRepo
	pdnsCli  *pdns.Client
}

func NewRecordService(
	ctx *bootstrap.Context,
	zoneRepo *data.ZoneRepo,
	pdnsCli *pdns.Client,
) *RecordService {
	return &RecordService{
		log:      ctx.NewLoggerHelper("dns/service/record"),
		zoneRepo: zoneRepo,
		pdnsCli:  pdnsCli,
	}
}

func (s *RecordService) ListRecords(ctx context.Context, req *dnsV1.ListRecordsRequest) (*dnsV1.ListRecordsResponse, error) {
	zone, err := s.resolveZone(ctx, req.GetZoneId())
	if err != nil {
		return nil, err
	}
	pz, err := s.pdnsCli.GetZone(ctx, zone.PdnsID)
	if err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns get zone: %v", err)
	}

	out := &dnsV1.ListRecordsResponse{}
	filter := recordTypeString(req.GetType())
	for _, rr := range pz.RRsets {
		if filter != "" && filter != "UNSPECIFIED" && rr.Type != filter {
			continue
		}
		out.Records = append(out.Records, rrsetToProto(rr))
	}
	out.Total = int32(len(out.Records))
	return out, nil
}

func (s *RecordService) CreateRecord(ctx context.Context, req *dnsV1.CreateRecordRequest) (*dnsV1.CreateRecordResponse, error) {
	zone, err := s.resolveZone(ctx, req.GetZoneId())
	if err != nil {
		return nil, err
	}
	rrset := buildRRset(req.GetName(), recordTypeString(req.GetType()), req.GetTtl(), req.GetContents(), req.GetComment())
	rrset.ChangeType = "REPLACE"

	if err := s.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{rrset}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns patch: %v", err)
	}
	return &dnsV1.CreateRecordResponse{Record: rrsetToProto(rrset)}, nil
}

func (s *RecordService) UpdateRecord(ctx context.Context, req *dnsV1.UpdateRecordRequest) (*dnsV1.UpdateRecordResponse, error) {
	zone, err := s.resolveZone(ctx, req.GetZoneId())
	if err != nil {
		return nil, err
	}
	rrset := buildRRset(req.GetName(), req.GetType(), req.GetTtl(), req.GetContents(), req.GetComment())
	rrset.ChangeType = "REPLACE"

	if err := s.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{rrset}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns patch: %v", err)
	}
	return &dnsV1.UpdateRecordResponse{Record: rrsetToProto(rrset)}, nil
}

func (s *RecordService) DeleteRecord(ctx context.Context, req *dnsV1.DeleteRecordRequest) (*emptypb.Empty, error) {
	zone, err := s.resolveZone(ctx, req.GetZoneId())
	if err != nil {
		return nil, err
	}
	rrset := pdns.RRset{
		Name:       canonicalName(req.GetName()),
		Type:       req.GetType(),
		ChangeType: "DELETE",
	}
	if err := s.pdnsCli.PatchRRsets(ctx, zone.PdnsID, []pdns.RRset{rrset}); err != nil {
		return nil, status.Errorf(codes.Unavailable, "powerdns patch: %v", err)
	}
	return &emptypb.Empty{}, nil
}

func (s *RecordService) resolveZone(ctx context.Context, zoneID string) (*ent.Zone, error) {
	z, err := s.zoneRepo.Get(ctx, getTenantID(ctx), zoneID)
	if err != nil {
		return nil, status.Errorf(codes.NotFound, "zone not found: %v", err)
	}
	return z, nil
}

func buildRRset(name, rrType string, ttl uint32, contents []*dnsV1.RecordContent, comment string) pdns.RRset {
	rrs := make([]pdns.RRsetRecord, 0, len(contents))
	for _, c := range contents {
		rrs = append(rrs, pdns.RRsetRecord{Content: c.GetContent(), Disabled: c.GetDisabled()})
	}
	out := pdns.RRset{
		Name:    canonicalName(name),
		Type:    rrType,
		TTL:     ttl,
		Records: rrs,
	}
	if comment != "" {
		out.Comments = []pdns.RRsetComment{{Content: comment}}
	}
	return out
}
