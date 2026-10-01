package contract

// Feature 032 (go-tangra specs/032-server-side-tables): every DNS list answers
// page/page_size/sort/order with {items,total,page,page_size,sort,order},
// pages each row exactly once under every sort and direction, clamps a page
// beyond the last, and refuses invalid values with validation_failed naming
// the parameter (never echoing its value).

import (
	"fmt"
	"strings"
	"testing"
)

type listPage[T any] struct {
	Items    []T    `json:"items"`
	Total    int    `json:"total"`
	Page     int    `json:"page"`
	PageSize int    `json:"page_size"`
	Sort     string `json:"sort"`
	Order    string `json:"order"`
}

// walk pages path (which already carries its query) with size until the
// server stops returning the requested page, and returns the keys seen.
func walk[T any](t *testing.T, h *harness, tok, path string, size int, key func(T) string) ([]string, int) {
	t.Helper()
	sep := "?"
	if strings.Contains(path, "?") {
		sep = "&"
	}
	var keys []string
	total := -1
	for pg := 1; pg < 100; pg++ {
		w := h.do("GET", fmt.Sprintf("%s%spage=%d&page_size=%d", path, sep, pg, size), tok, "")
		if w.Code != 200 {
			t.Fatalf("%s page %d = %d %s", path, pg, w.Code, w.Body)
		}
		lp := decode[listPage[T]](t, w)
		if total >= 0 && lp.Total != total {
			t.Fatalf("%s: total changed %d → %d", path, total, lp.Total)
		}
		total = lp.Total
		if lp.Page != pg {
			break
		}
		for _, it := range lp.Items {
			keys = append(keys, key(it))
		}
		if pg*size >= total {
			break
		}
	}
	return keys, total
}

func onceEach(t *testing.T, label string, keys []string, total int) {
	t.Helper()
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Fatalf("%s: %s twice", label, k)
		}
		seen[k] = true
	}
	if len(seen) != total {
		t.Fatalf("%s: %d of %d", label, len(seen), total)
	}
}

func TestZoneListContract(t *testing.T) {
	h := newHarness(t)
	for i, n := range []string{"b.test", "a.test", "c.example", "x.example", "m.test", "d.example", "k.test"} {
		kind := []string{"native", "master"}[i%2]
		h.createZone("admin-a", `{"name":"`+n+`","kind":"`+kind+`"}`)
	}
	h.createZone("admin-b", `{"name":"other.test","kind":"native"}`)

	w := h.do("GET", p+"/zones", "viewer-a", "")
	lp := decode[listPage[zoneJSON]](t, w)
	if lp.Total != 7 || lp.Page != 1 || lp.PageSize != 25 || lp.Sort != "name" || lp.Order != "asc" || lp.Items[0].Name != "a.test." {
		t.Fatalf("defaults = %+v", lp)
	}
	if lp := decode[listPage[zoneJSON]](t, h.do("GET", p+"/zones?sort=updated_at", "viewer-a", "")); lp.Order != "desc" {
		t.Fatalf("updated_at default direction = %s", lp.Order)
	}
	for _, sort := range []string{"name", "kind", "updated_at"} {
		for _, order := range []string{"asc", "desc"} {
			keys, total := walk(t, h, "viewer-a", p+"/zones?sort="+sort+"&order="+order, 2, func(z zoneJSON) string { return z.ID })
			if total != 7 {
				t.Fatalf("%s %s total %d (tenant isolation)", sort, order, total)
			}
			onceEach(t, "zones "+sort+" "+order, keys, total)
		}
	}
	desc := decode[listPage[zoneJSON]](t, h.do("GET", p+"/zones?sort=name&order=desc&page_size=1", "viewer-a", ""))
	if desc.Items[0].Name != "x.example." {
		t.Fatalf("name desc first = %s", desc.Items[0].Name)
	}
	// filters keep their totals; beyond the last page → the last page
	beyond := decode[listPage[zoneJSON]](t, h.do("GET", p+"/zones?kind=master&page=9&page_size=2", "viewer-a", ""))
	if beyond.Total != 3 || beyond.Page != 2 || len(beyond.Items) != 1 {
		t.Fatalf("clamp = %+v", beyond)
	}
	if other := decode[listPage[zoneJSON]](t, h.do("GET", p+"/zones", "admin-b", "")); other.Total != 1 {
		t.Fatalf("tenant B total = %d", other.Total)
	}
}

func TestRecordListContract(t *testing.T) {
	h := newHarness(t)
	z := h.createZone("admin-a", `{"name":"example.test","kind":"native","nameservers":["ns1.example.test."]}`)
	rp := p + "/zones/" + z.ID + "/records"
	for i, n := range []string{"www", "mail", "a.b", "b", "api", "zz"} {
		b := fmt.Sprintf(`{"name":"%s","type":"A","ttl":%d,"values":[{"content":"192.0.2.%d"}]}`, n, 300+60*(i%3), i+1)
		if w := h.do("POST", rp, "admin-a", b); w.Code != 200 {
			t.Fatalf("upsert %s = %d %s", n, w.Code, w.Body)
		}
	}
	lp := decode[listPage[recordJSON]](t, h.do("GET", rp, "viewer-a", ""))
	if lp.Total != 8 || lp.PageSize != 100 || lp.Sort != "name" || lp.Order != "asc" || lp.Items[0].Type != "SOA" {
		t.Fatalf("defaults = %+v", lp)
	}
	// DNS canonical order: a.b.example.test. sorts under b.example.test.
	names := []string{}
	for _, r := range lp.Items {
		names = append(names, r.Name)
	}
	if got := strings.Join(names, " "); !strings.Contains(got, "b.example.test. a.b.example.test.") {
		t.Fatalf("canonical order = %s", got)
	}
	for _, sort := range []string{"name", "type", "ttl"} {
		for _, order := range []string{"asc", "desc"} {
			keys, total := walk(t, h, "viewer-a", rp+"?sort="+sort+"&order="+order, 3, func(r recordJSON) string { return r.Name + "|" + r.Type })
			onceEach(t, "records "+sort+" "+order, keys, total)
		}
	}
	if lp := decode[listPage[recordJSON]](t, h.do("GET", rp+"?sort=ttl&order=desc&page_size=1", "viewer-a", "")); lp.Items[0].TTL != 3600 {
		t.Fatalf("ttl desc first = %+v", lp.Items[0])
	}
	if w := h.do("GET", rp+"?page_size=200", "viewer-a", ""); w.Code != 200 {
		t.Fatalf("page_size 200 = %d", w.Code)
	}
}

func TestTemplateAndSupermasterListContract(t *testing.T) {
	h := newUS3Harness(t)
	for _, n := range []string{"Web", "mail", "Alpha", "beta", "web2"} {
		if w := h.do("POST", p+"/templates", "admin-a", `{"name":"`+n+`","records":[]}`); w.Code != 201 {
			t.Fatalf("template %s = %d %s", n, w.Code, w.Body)
		}
	}
	for _, order := range []string{"asc", "desc"} {
		keys, total := walk(t, h, "viewer-a", p+"/templates?sort=name&order="+order, 2, func(x templateJSON) string { return x.Name })
		onceEach(t, "templates "+order, keys, total)
		want := "Alpha beta mail Web web2"
		if order == "desc" {
			want = "web2 Web mail beta Alpha"
		}
		if got := strings.Join(keys, " "); got != want {
			t.Fatalf("templates %s = %s", order, got)
		}
	}
	for _, sm := range [][2]string{{"192.0.2.10", "ns2.primary.example"}, {"192.0.2.9", "ns1.primary.example"}, {"198.51.100.7", "ns3.primary.example"}} {
		if w := h.do("POST", p+"/supermasters", "platform-a", `{"ip":"`+sm[0]+`","nameserver":"`+sm[1]+`"}`); w.Code != 201 {
			t.Fatalf("supermaster %v = %d %s", sm, w.Code, w.Body)
		}
	}
	lp := decode[listPage[supermasterJSON]](t, h.do("GET", p+"/supermasters", "admin-a", ""))
	if lp.Total != 3 || lp.Sort != "ip" || lp.Items[0].IP != "192.0.2.9" || lp.Items[1].IP != "192.0.2.10" {
		t.Fatalf("inet order = %+v", lp)
	}
	for _, sort := range []string{"ip", "nameserver"} {
		for _, order := range []string{"asc", "desc"} {
			keys, total := walk(t, h, "admin-a", p+"/supermasters?sort="+sort+"&order="+order, 2, func(x supermasterJSON) string { return x.ID })
			onceEach(t, "supermasters "+sort+" "+order, keys, total)
		}
	}
}

func TestListRefusals(t *testing.T) {
	h := newUS3Harness(t)
	z := h.createZone("admin-a", `{"name":"example.test","kind":"native"}`)
	lists := []string{p + "/zones", p + "/zones/" + z.ID + "/records", p + "/templates", p + "/supermasters"}
	cases := []struct{ query, param string }{
		{"sort=bogus", "sort"},
		{"sort=id", "sort"},
		{"order=up", "order"},
		{"page_size=201", "page_size"},
		{"page_size=0", "page_size"},
		{"page_size=abc", "page_size"},
		{"page=0", "page"},
		{"page=-1", "page"},
		{"page=abc", "page"},
	}
	for _, path := range lists {
		for _, c := range cases {
			w := h.do("GET", path+"?"+c.query, "admin-a", "")
			e := decode[errJSON](t, w)
			if w.Code != 422 || e.Reason != "validation_failed" || e.Detail["param"] != c.param {
				t.Errorf("%s?%s = %d %s", path, c.query, w.Code, w.Body)
			}
			if v := strings.SplitN(c.query, "=", 2)[1]; strings.Contains(w.Body.String(), `"`+v+`"`) {
				t.Errorf("%s?%s echoes the value: %s", path, c.query, w.Body)
			}
		}
	}
}
