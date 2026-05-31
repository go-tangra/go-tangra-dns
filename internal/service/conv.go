package service

import (
	"strings"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	dnsV1 "github.com/go-tangra/go-tangra-dns/gen/go/dns/service/v1"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	entZone "github.com/go-tangra/go-tangra-dns/internal/data/ent/zone"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent/schema"
	"github.com/go-tangra/go-tangra-dns/internal/pdns"
)

// kindToProto maps the Ent string enum onto the proto enum.
func kindToProto(k entZone.Kind) dnsV1.ZoneKind {
	switch k {
	case entZone.KindNATIVE:
		return dnsV1.ZoneKind_ZONE_KIND_NATIVE
	case entZone.KindMASTER:
		return dnsV1.ZoneKind_ZONE_KIND_MASTER
	case entZone.KindSLAVE:
		return dnsV1.ZoneKind_ZONE_KIND_SLAVE
	case entZone.KindPRODUCER:
		return dnsV1.ZoneKind_ZONE_KIND_PRODUCER
	case entZone.KindCONSUMER:
		return dnsV1.ZoneKind_ZONE_KIND_CONSUMER
	default:
		return dnsV1.ZoneKind_ZONE_KIND_UNSPECIFIED
	}
}

// kindFromProto maps the proto enum to the Ent enum and to the PowerDNS string.
func kindFromProto(k dnsV1.ZoneKind) (entZone.Kind, string) {
	switch k {
	case dnsV1.ZoneKind_ZONE_KIND_MASTER:
		return entZone.KindMASTER, "Master"
	case dnsV1.ZoneKind_ZONE_KIND_SLAVE:
		return entZone.KindSLAVE, "Slave"
	case dnsV1.ZoneKind_ZONE_KIND_PRODUCER:
		return entZone.KindPRODUCER, "Producer"
	case dnsV1.ZoneKind_ZONE_KIND_CONSUMER:
		return entZone.KindCONSUMER, "Consumer"
	default:
		return entZone.KindNATIVE, "Native"
	}
}

// derefU32 safely dereferences an optional *uint32 ent field.
func derefU32(v *uint32) uint32 {
	if v == nil {
		return 0
	}
	return *v
}

// pbTime converts an optional *time.Time ent field to a proto timestamp.
func pbTime(t *time.Time) *timestamppb.Timestamp {
	if t == nil {
		return nil
	}
	return timestamppb.New(*t)
}

func zoneToProto(z *ent.Zone, serial uint32) *dnsV1.Zone {
	return &dnsV1.Zone{
		Id:            z.ID,
		TenantId:      derefU32(z.TenantID),
		PdnsId:        z.PdnsID,
		Name:          z.Name,
		Kind:          kindToProto(z.Kind),
		Masters:       z.Masters,
		Serial:        serial,
		DnssecEnabled: z.DnssecEnabled,
		Description:   z.Description,
		TemplateId:    z.TemplateID,
		CreateTime:    pbTime(z.CreateTime),
		UpdateTime:    pbTime(z.UpdateTime),
	}
}

func supermasterToProto(sm *ent.Supermaster) *dnsV1.Supermaster {
	return &dnsV1.Supermaster{
		Id:         sm.ID,
		TenantId:   derefU32(sm.TenantID),
		Ip:         sm.IP,
		Nameserver: sm.Nameserver,
		Account:    sm.Account,
		CreateTime: pbTime(sm.CreateTime),
	}
}

func zoneTemplateToProto(tpl *ent.ZoneTemplate) *dnsV1.ZoneTemplate {
	out := &dnsV1.ZoneTemplate{
		Id:          tpl.ID,
		TenantId:    derefU32(tpl.TenantID),
		Name:        tpl.Name,
		Description: tpl.Description,
		CreateTime:  pbTime(tpl.CreateTime),
		UpdateTime:  pbTime(tpl.UpdateTime),
	}
	for _, r := range tpl.Records {
		out.Records = append(out.Records, &dnsV1.TemplateRecord{
			Name:     r.Name,
			Type:     r.Type,
			Ttl:      r.TTL,
			Content:  r.Content,
			Priority: r.Priority,
		})
	}
	return out
}

func zoneTemplateStanzasFromProto(in []*dnsV1.TemplateRecord) []schema.TemplateRecordStanza {
	out := make([]schema.TemplateRecordStanza, 0, len(in))
	for _, r := range in {
		out = append(out, schema.TemplateRecordStanza{
			Name:     r.GetName(),
			Type:     r.GetType(),
			TTL:      r.GetTtl(),
			Content:  r.GetContent(),
			Priority: r.GetPriority(),
		})
	}
	return out
}

// recordTypeString converts the proto enum to the canonical PowerDNS string.
func recordTypeString(t dnsV1.RecordType) string {
	name := t.String()
	// e.g. "RECORD_TYPE_A" -> "A"
	return strings.TrimPrefix(name, "RECORD_TYPE_")
}

// recordTypeFromString parses "A", "AAAA", ... into the proto enum.
func recordTypeFromString(s string) dnsV1.RecordType {
	if v, ok := dnsV1.RecordType_value["RECORD_TYPE_"+strings.ToUpper(s)]; ok {
		return dnsV1.RecordType(v)
	}
	return dnsV1.RecordType_RECORD_TYPE_UNSPECIFIED
}

func rrsetToProto(r pdns.RRset) *dnsV1.Record {
	out := &dnsV1.Record{
		Name: r.Name,
		Type: recordTypeFromString(r.Type),
		Ttl:  r.TTL,
	}
	for _, c := range r.Records {
		out.Contents = append(out.Contents, &dnsV1.RecordContent{
			Content:  c.Content,
			Disabled: c.Disabled,
		})
	}
	if len(r.Comments) > 0 {
		out.Comment = r.Comments[0].Content
	}
	return out
}

// canonicalName ensures the name ends with a single trailing dot.
func canonicalName(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return s
	}
	if !strings.HasSuffix(s, ".") {
		s += "."
	}
	return s
}
