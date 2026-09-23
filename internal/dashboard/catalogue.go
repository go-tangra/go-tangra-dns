// Package dashboard serves the curated DNS health dashboard (US6, research
// D13, SR-006): a FIXED catalogue of resolver and authoritative panels (the
// PromQL of the reference dashboard, go-tangra-dns frontend/src/views/
// dashboard) is run server-side over a bounded window and step. No query
// text is ever accepted from a caller; without a metrics URL the dashboard
// reports itself unavailable.
package dashboard

// Kind is how a panel is drawn.
type Kind string

// Panel kinds.
const (
	KindStat   Kind = "stat"   // one instant value
	KindSeries Kind = "series" // range series over the window
)

// Query is one catalogue expression; Label names its series in the panel.
type Query struct {
	Label string
	Expr  string
}

// Panel is one catalogue entry.
type Panel struct {
	ID      string
	Kind    Kind
	Unit    string
	Queries []Query
}

// catalogue is the only PromQL the module ever sends.
var catalogue = []Panel{
	// Resolver (pdns_recursor_*).
	{ID: "recursor_qps", Kind: KindStat, Unit: "qps", Queries: []Query{{"questions", `sum(rate(pdns_recursor_questions[5m]))`}}},
	{ID: "recursor_cache_hit", Kind: KindStat, Unit: "%", Queries: []Query{{"cache_hit",
		`100 * sum(pdns_recursor_cache_hits) / clamp_min(sum(pdns_recursor_cache_hits + pdns_recursor_cache_misses), 1)`}}},
	{ID: "recursor_concurrent", Kind: KindStat, Unit: "queries", Queries: []Query{{"concurrent", `sum(pdns_recursor_concurrent_queries)`}}},
	{ID: "recursor_uptime", Kind: KindStat, Unit: "s", Queries: []Query{{"uptime", `max(pdns_recursor_uptime)`}}},
	{ID: "recursor_latency", Kind: KindSeries, Unit: "qps", Queries: []Query{
		{"0-1ms", `sum(rate(pdns_recursor_answers0_1[5m]))`},
		{"1-10ms", `sum(rate(pdns_recursor_answers1_10[5m]))`},
		{"10-100ms", `sum(rate(pdns_recursor_answers10_100[5m]))`},
		{"100-1000ms", `sum(rate(pdns_recursor_answers100_1000[5m]))`},
	}},
	{ID: "recursor_answers", Kind: KindSeries, Unit: "qps", Queries: []Query{
		{"noerror", `sum(rate(pdns_recursor_noerror_answers[5m]))`},
		{"nxdomain", `sum(rate(pdns_recursor_nxdomain_answers[5m]))`},
		{"servfail", `sum(rate(pdns_recursor_servfail_answers[5m]))`},
	}},
	{ID: "recursor_questions_outqueries", Kind: KindSeries, Unit: "qps", Queries: []Query{
		{"questions", `sum(rate(pdns_recursor_questions[5m]))`},
		{"outqueries", `sum(rate(pdns_recursor_all_outqueries[5m]))`},
	}},
	// Authoritative (pdns_auth_*).
	{ID: "auth_qps", Kind: KindStat, Unit: "qps", Queries: []Query{{"queries", `sum(rate(pdns_auth_backend_queries[5m]))`}}},
	{ID: "auth_packetcache_hit", Kind: KindStat, Unit: "%", Queries: []Query{{"packetcache_hit",
		`100 * sum(pdns_auth_packetcache_hit) / clamp_min(sum(pdns_auth_packetcache_hit + pdns_auth_packetcache_miss), 1)`}}},
	{ID: "auth_querycache_hit", Kind: KindStat, Unit: "%", Queries: []Query{{"querycache_hit",
		`100 * sum(pdns_auth_query_cache_hit) / clamp_min(sum(pdns_auth_query_cache_hit + pdns_auth_query_cache_miss), 1)`}}},
	{ID: "auth_queries", Kind: KindSeries, Unit: "qps", Queries: []Query{{"queries", `sum(rate(pdns_auth_backend_queries[5m]))`}}},
	{ID: "auth_errors", Kind: KindSeries, Unit: "pps", Queries: []Query{
		{"servfail", `sum(rate(pdns_auth_servfail_packets[5m]))`},
		{"nxdomain", `sum(rate(pdns_auth_nxdomain_packets[5m]))`},
	}},
}

// Catalogue returns a copy of the fixed panel set.
func Catalogue() []Panel {
	out := make([]Panel, len(catalogue))
	for i, p := range catalogue {
		p.Queries = append([]Query(nil), p.Queries...)
		out[i] = p
	}
	return out
}
