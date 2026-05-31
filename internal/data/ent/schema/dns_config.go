package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// DnsConfig stores platform-level PowerDNS configuration (recursor +
// authoritative). It is a global singleton keyed by a fixed id, holding the
// settings as a JSON blob. Not tenant-scoped — server config is platform-wide.
type DnsConfig struct {
	ent.Schema
}

func (DnsConfig) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "dns_config"},
		entsql.WithComments(true),
	}
}

func (DnsConfig) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("Fixed config key (global)"),

		field.Text("data").
			Optional().
			Comment("JSON-encoded {recursor, authoritative} configuration"),
	}
}

func (DnsConfig) Edges() []ent.Edge {
	return nil
}

func (DnsConfig) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.Time{},
	}
}
