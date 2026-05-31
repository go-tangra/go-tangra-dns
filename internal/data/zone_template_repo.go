package data

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	"github.com/go-tangra/go-tangra-dns/internal/data/ent/schema"
	entTpl "github.com/go-tangra/go-tangra-dns/internal/data/ent/zonetemplate"
)

type ZoneTemplateRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewZoneTemplateRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *ZoneTemplateRepo {
	return &ZoneTemplateRepo{
		log:       ctx.NewLoggerHelper("dns/repo/zone_template"),
		entClient: entClient,
	}
}

func (r *ZoneTemplateRepo) client() *ent.Client {
	return r.entClient.Client()
}

func (r *ZoneTemplateRepo) Create(ctx context.Context, tpl *ent.ZoneTemplate) (*ent.ZoneTemplate, error) {
	created, err := r.client().ZoneTemplate.Create().
		SetID(tpl.ID).
		SetNillableTenantID(tpl.TenantID).
		SetName(tpl.Name).
		SetDescription(tpl.Description).
		SetRecords(tpl.Records).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create zone_template: %w", err)
	}
	return created, nil
}

func (r *ZoneTemplateRepo) Get(ctx context.Context, tenantID uint32, id string) (*ent.ZoneTemplate, error) {
	tpl, err := r.client().ZoneTemplate.Query().
		Where(entTpl.TenantID(tenantID), entTpl.ID(id)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("get zone_template: %w", err)
	}
	return tpl, nil
}

func (r *ZoneTemplateRepo) List(ctx context.Context, tenantID uint32, offset, limit int) ([]*ent.ZoneTemplate, int, error) {
	q := r.client().ZoneTemplate.Query().Where(entTpl.TenantID(tenantID))
	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count zone_templates: %w", err)
	}
	items, err := q.Order(ent.Desc(entTpl.FieldCreateTime)).Offset(offset).Limit(limit).All(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list zone_templates: %w", err)
	}
	return items, total, nil
}

func (r *ZoneTemplateRepo) Update(
	ctx context.Context, tenantID uint32, id string,
	name *string, description *string, records []schema.TemplateRecordStanza,
) (*ent.ZoneTemplate, error) {
	tpl, err := r.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	upd := r.client().ZoneTemplate.UpdateOne(tpl)
	if name != nil {
		upd = upd.SetName(*name)
	}
	if description != nil {
		upd = upd.SetDescription(*description)
	}
	if records != nil {
		upd = upd.SetRecords(records)
	}
	updated, err := upd.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("update zone_template: %w", err)
	}
	return updated, nil
}

func (r *ZoneTemplateRepo) Delete(ctx context.Context, tenantID uint32, id string) error {
	tpl, err := r.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := r.client().ZoneTemplate.DeleteOne(tpl).Exec(ctx); err != nil {
		return fmt.Errorf("delete zone_template: %w", err)
	}
	return nil
}
