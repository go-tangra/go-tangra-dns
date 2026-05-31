package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// Zone tracks a zone managed by the dns module.
// Authoritative DNS data lives in PowerDNS; this row stores
// multi-tenant scoping and module-level metadata.
type Zone struct {
	ent.Schema
}

func (Zone) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "dns_zones"},
		entsql.WithComments(true),
	}
}

func (Zone) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("pdns_id").
			NotEmpty().
			MaxLen(255).
			Comment("PowerDNS zone id (canonical, trailing dot)"),

		field.String("name").
			NotEmpty().
			MaxLen(255).
			Comment("Zone name (canonical)"),

		field.Enum("kind").
			Values("NATIVE", "MASTER", "SLAVE", "PRODUCER", "CONSUMER").
			Default("NATIVE").
			Comment("PowerDNS zone kind"),

		field.String("masters").
			Optional().
			MaxLen(1024).
			Comment("Comma-separated master IPs for SLAVE zones"),

		field.Bool("dnssec_enabled").
			Default(false).
			Comment("Whether DNSSEC is enabled for this zone"),

		field.String("description").
			Optional().
			MaxLen(1024).
			Comment("Local description / notes"),

		field.String("template_id").
			Optional().
			MaxLen(36).
			Comment("Optional reference to the ZoneTemplate used at creation"),
	}
}

func (Zone) Edges() []ent.Edge {
	return nil
}

func (Zone) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (Zone) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "name").Unique(),
		index.Fields("pdns_id"),
		index.Fields("kind"),
	}
}
