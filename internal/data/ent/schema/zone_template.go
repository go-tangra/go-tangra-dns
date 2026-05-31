package schema

import (
	"entgo.io/ent"
	"entgo.io/ent/dialect/entsql"
	"entgo.io/ent/schema"
	"entgo.io/ent/schema/field"
	"entgo.io/ent/schema/index"
	"github.com/tx7do/go-crud/entgo/mixin"
)

// ZoneTemplate is a Poweradmin-style reusable template
// that defines a set of record stanzas applied when creating a zone.
type ZoneTemplate struct {
	ent.Schema
}

func (ZoneTemplate) Annotations() []schema.Annotation {
	return []schema.Annotation{
		entsql.Annotation{Table: "dns_zone_templates"},
		entsql.WithComments(true),
	}
}

func (ZoneTemplate) Fields() []ent.Field {
	return []ent.Field{
		field.String("id").
			NotEmpty().
			Unique().
			Comment("UUID primary key"),

		field.String("name").
			NotEmpty().
			MaxLen(128).
			Comment("Template name (unique per tenant)"),

		field.String("description").
			Optional().
			MaxLen(1024).
			Comment("Template description"),

		// Stored as JSON for flexibility; records are not relational.
		field.JSON("records", []TemplateRecordStanza{}).
			Optional().
			Comment("Record stanzas applied on zone creation"),
	}
}

func (ZoneTemplate) Edges() []ent.Edge {
	return nil
}

func (ZoneTemplate) Mixin() []ent.Mixin {
	return []ent.Mixin{
		mixin.CreateBy{},
		mixin.Time{},
		mixin.TenantID[uint32]{},
	}
}

func (ZoneTemplate) Indexes() []ent.Index {
	return []ent.Index{
		index.Fields("tenant_id"),
		index.Fields("tenant_id", "name").Unique(),
	}
}

// TemplateRecordStanza is the JSON-stored shape of a template record.
// "[ZONE]" placeholders in name/content are replaced with the zone name.
type TemplateRecordStanza struct {
	Name     string `json:"name"`
	Type     string `json:"type"`
	TTL      uint32 `json:"ttl"`
	Content  string `json:"content"`
	Priority uint32 `json:"priority,omitempty"`
}
