package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// Supermaster is a (ip, nameserver) pair that PowerDNS trusts
// to send NOTIFY messages and auto-provision SLAVE zones.
type Supermaster struct {
	ent.Schema
}

func (Supermaster) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "dns_supermasters"},
		entsql.WithComments(true),
	}
}

func (Supermaster) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("ip").
			NotEmpty().
			MaxLen(64).
			Comment("Master IPv4/IPv6 address"),

		field.String("nameserver").
			NotEmpty().
			MaxLen(255).
			Comment("Nameserver hostname (must match SOA of incoming zones)"),

		field.String("account").
			Optional().
			MaxLen(64).
			Comment("Optional 'account' tag for grouping"),
	}
}

func (Supermaster) Edges() []ent.Edge {
	return nil
}

func (Supermaster) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (Supermaster) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "ip", "nameserver").Unique(),
	}
}
