package data

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	entZone "github.com/go-tangra/go-tangra-dns/internal/data/ent/zone"
)

type ZoneRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewZoneRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *ZoneRepo {
	return &ZoneRepo{
		log:       ctx.NewLoggerHelper("dns/repo/zone"),
		entClient: entClient,
	}
}

func (r *ZoneRepo) client() *ent.Client {
	return r.entClient.Client()
}

func (r *ZoneRepo) Create(ctx context.Context, z *ent.Zone) (*ent.Zone, error) {
	cli := r.client()
	created, err := cli.Zone.Create().
		SetID(z.ID).
		SetNillableTenantID(z.TenantID).
		SetPdnsID(z.PdnsID).
		SetName(z.Name).
		SetKind(z.Kind).
		SetMasters(z.Masters).
		SetDnssecEnabled(z.DnssecEnabled).
		SetDescription(z.Description).
		SetTemplateID(z.TemplateID).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create zone: %w", err)
	}
	return created, nil
}

func (r *ZoneRepo) Get(ctx context.Context, tenantID uint32, id string) (*ent.Zone, error) {
	z, err := r.client().Zone.Query().
		Where(entZone.TenantID(tenantID), entZone.ID(id)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("get zone: %w", err)
	}
	return z, nil
}

func (r *ZoneRepo) GetByPdnsID(ctx context.Context, tenantID uint32, pdnsID string) (*ent.Zone, error) {
	z, err := r.client().Zone.Query().
		Where(entZone.TenantID(tenantID), entZone.PdnsID(pdnsID)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("get zone by pdns_id: %w", err)
	}
	return z, nil
}

// AllZoneNames returns the distinct names of every managed zone across all
// tenants. Used by the recursor reconciler (forward zones are keyed by name,
// not by tenant). Requires a system-viewer context to bypass tenant privacy.
func (r *ZoneRepo) AllZoneNames(ctx context.Context) ([]string, error) {
	names, err := r.client().Zone.Query().
		Unique(true).
		Select(entZone.FieldName).
		Strings(ctx)
	if err != nil {
		return nil, fmt.Errorf("list all zone names: %w", err)
	}
	return names, nil
}

func (r *ZoneRepo) List(ctx context.Context, tenantID uint32, offset, limit int, search string) ([]*ent.Zone, int, error) {
	q := r.client().Zone.Query().Where(entZone.TenantID(tenantID))
	if search != "" {
		q = q.Where(entZone.NameContains(search))
	}
	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count zones: %w", err)
	}
	zones, err := q.Order(ent.Desc(entZone.FieldCreateTime)).Offset(offset).Limit(limit).All(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list zones: %w", err)
	}
	return zones, total, nil
}

func (r *ZoneRepo) Update(ctx context.Context, tenantID uint32, id string, fn func(*ent.ZoneUpdateOne)) (*ent.Zone, error) {
	zone, err := r.Get(ctx, tenantID, id)
	if err != nil {
		return nil, err
	}
	upd := r.client().Zone.UpdateOne(zone)
	fn(upd)
	updated, err := upd.Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("update zone: %w", err)
	}
	return updated, nil
}

func (r *ZoneRepo) Delete(ctx context.Context, tenantID uint32, id string) error {
	z, err := r.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := r.client().Zone.DeleteOne(z).Exec(ctx); err != nil {
		return fmt.Errorf("delete zone: %w", err)
	}
	return nil
}
