package store

import "github.com/go-tangra/go-tangra/v4/listquery"

// List definitions of the DNS tables (specs/032-server-side-tables in
// go-tangra). Sort fields map to constant expressions only; nothing from a
// request ever reaches SQL. NotNull marks the SQL fields over NOT NULL
// columns: their ORDER BY carries no NULLS LAST, so btree indexes serve both
// directions.
var (
	// ZoneList pages dns_zones in SQL. Names are stored lower-case, so the
	// byte-wise "C" collation keeps the module's established name order.
	// The PowerDNS serial is not a column and is therefore not sortable.
	ZoneList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name":       {Expr: `name COLLATE "C"`, NotNull: true},
			"kind":       {Expr: `kind COLLATE "C"`, NotNull: true},
			"updated_at": {Expr: "updated_at", DefaultDir: listquery.Desc, NotNull: true},
		},
		Default: "name", TieBreak: "id",
	}
	// RecordList pages a zone's PowerDNS rrsets in memory (records package):
	// "name" is DNS canonical order (labels compared from the root down, apex
	// first), ties broken by type with SOA leading.
	RecordList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name": {Expr: "name"},
			"type": {Expr: "type"},
			"ttl":  {Expr: "ttl"},
		},
		Default: "name", TieBreak: "name,type", DefaultSize: 100, MaxSize: 200,
	}
	// TemplateList pages dns_zone_templates in SQL (case-insensitive name).
	TemplateList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"name": {Expr: `lower(name) COLLATE "C"`, NotNull: true},
		},
		Default: "name", TieBreak: "id",
	}
	// SupermasterList pages dns_supermasters in SQL (inet order for ip).
	SupermasterList = listquery.Spec{
		Fields: map[string]listquery.Field{
			"ip":         {Expr: "ip", NotNull: true},
			"nameserver": {Expr: `nameserver COLLATE "C"`, NotNull: true},
		},
		Default: "ip", TieBreak: "id",
	}
)
