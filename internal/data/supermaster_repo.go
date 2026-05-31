package data

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	entSm "github.com/go-tangra/go-tangra-dns/internal/data/ent/supermaster"
)

type SupermasterRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewSupermasterRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *SupermasterRepo {
	return &SupermasterRepo{
		log:       ctx.NewLoggerHelper("dns/repo/supermaster"),
		entClient: entClient,
	}
}

func (r *SupermasterRepo) client() *ent.Client {
	return r.entClient.Client()
}

func (r *SupermasterRepo) Create(ctx context.Context, sm *ent.Supermaster) (*ent.Supermaster, error) {
	created, err := r.client().Supermaster.Create().
		SetID(sm.ID).
		SetNillableTenantID(sm.TenantID).
		SetIP(sm.IP).
		SetNameserver(sm.Nameserver).
		SetAccount(sm.Account).
		Save(ctx)
	if err != nil {
		return nil, fmt.Errorf("create supermaster: %w", err)
	}
	return created, nil
}

func (r *SupermasterRepo) Get(ctx context.Context, tenantID uint32, id string) (*ent.Supermaster, error) {
	sm, err := r.client().Supermaster.Query().
		Where(entSm.TenantID(tenantID), entSm.ID(id)).
		Only(ctx)
	if err != nil {
		return nil, fmt.Errorf("get supermaster: %w", err)
	}
	return sm, nil
}

func (r *SupermasterRepo) List(ctx context.Context, tenantID uint32, offset, limit int) ([]*ent.Supermaster, int, error) {
	q := r.client().Supermaster.Query().Where(entSm.TenantID(tenantID))
	total, err := q.Count(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("count supermasters: %w", err)
	}
	items, err := q.Order(ent.Desc(entSm.FieldCreateTime)).Offset(offset).Limit(limit).All(ctx)
	if err != nil {
		return nil, 0, fmt.Errorf("list supermasters: %w", err)
	}
	return items, total, nil
}

func (r *SupermasterRepo) Delete(ctx context.Context, tenantID uint32, id string) error {
	sm, err := r.Get(ctx, tenantID, id)
	if err != nil {
		return err
	}
	if err := r.client().Supermaster.DeleteOne(sm).Exec(ctx); err != nil {
		return fmt.Errorf("delete supermaster: %w", err)
	}
	return nil
}
