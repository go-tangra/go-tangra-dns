package data

import (
	"context"
	"fmt"

	"github.com/go-kratos/kratos/v2/log"
	entCrud "github.com/tx7do/go-crud/entgo"
	"github.com/tx7do/kratos-bootstrap/bootstrap"

	"github.com/go-tangra/go-tangra-dns/internal/data/ent"
	entDnsConfig "github.com/go-tangra/go-tangra-dns/internal/data/ent/dnsconfig"
)

// dnsConfigID is the fixed primary key for the singleton config row.
const dnsConfigID = "global"

// DnsConfigRepo persists the platform DNS configuration JSON blob.
type DnsConfigRepo struct {
	entClient *entCrud.EntClient[*ent.Client]
	log       *log.Helper
}

func NewDnsConfigRepo(ctx *bootstrap.Context, entClient *entCrud.EntClient[*ent.Client]) *DnsConfigRepo {
	return &DnsConfigRepo{
		log:       ctx.NewLoggerHelper("dns/repo/config"),
		entClient: entClient,
	}
}

func (r *DnsConfigRepo) client() *ent.Client {
	return r.entClient.Client()
}

// Get returns the stored config JSON, or "" when no config has been saved yet.
func (r *DnsConfigRepo) Get(ctx context.Context) (string, error) {
	c, err := r.client().DnsConfig.Get(ctx, dnsConfigID)
	if ent.IsNotFound(err) {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("get dns config: %w", err)
	}
	return c.Data, nil
}

// Save upserts the singleton config row.
func (r *DnsConfigRepo) Save(ctx context.Context, data string) error {
	err := r.client().DnsConfig.Create().
		SetID(dnsConfigID).
		SetData(data).
		OnConflictColumns(entDnsConfig.FieldID).
		UpdateNewValues().
		Exec(ctx)
	if err != nil {
		return fmt.Errorf("save dns config: %w", err)
	}
	return nil
}
