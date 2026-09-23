package contract

// T030: the record-set surface of contracts §A: list with type filter, name
// search and paging (correct total, SOA read_only), create/replace, update
// and rename, delete, invalid content → invalid_record with a reason, and
// zones:manage required on every write.

import (
	"net/url"
	"strings"
	"testing"
)

type valueJSON struct {
	Content  string `json:"content"`
	Disabled bool   `json:"disabled"`
}

type recordJSON struct {
	Name     string      `json:"name"`
	Type     string      `json:"type"`
	TTL      int         `json:"ttl"`
	Values   []valueJSON `json:"values"`
	Comment  string      `json:"comment"`
	ReadOnly bool        `json:"read_only"`
}

func TestRecordShapesAndList(t *testing.T) {
	h := newHarness(t)
	z := h.createZone("admin-a", `{"name":"example.test","kind":"native","nameservers":["ns1.example.test."]}`)
	rp := p + "/zones/" + z.ID + "/records"
	for _, b := range []string{
		`{"name":"www","type":"A","ttl":300,"values":[{"content":"192.0.2.10"},{"content":"192.0.2.11","disabled":true}],"comment":"web"}`,
		`{"name":"www","type":"AAAA","ttl":300,"values":[{"content":"2001:db8::10"}]}`,
		`{"name":"@","type":"MX","ttl":3600,"values":[{"content":"10 mail.example.test."}]}`,
		`{"name":"@","type":"TXT","ttl":3600,"values":[{"content":"v=spf1 -all"}]}`,
		`{"name":"@","type":"CAA","ttl":3600,"values":[{"content":"0 issue \"letsencrypt.org\""}]}`,
	} {
		w := h.do("POST", rp, "admin-a", b)
		if w.Code != 200 {
			t.Fatalf("upsert %s = %d %s", b, w.Code, w.Body)
		}
	}
	w := h.do("POST", rp, "admin-a", `{"name":"api","type":"txt","ttl":300,"values":[{"content":"hello world"}]}`)
	if w.Code != 422 { // the type enum is upper-case
		t.Fatalf("lower-case type = %d", w.Code)
	}
	all := decode[page[recordJSON]](t, h.do("GET", rp, "viewer-a", ""))
	if all.Total != 7 || len(all.Items) != 7 || all.Items[0].Type != "SOA" || !all.Items[0].ReadOnly {
		t.Fatalf("list = %+v", all)
	}
	var txt recordJSON
	for _, r := range all.Items {
		if r.Type == "TXT" {
			txt = r
		}
		if r.Type != "SOA" && r.ReadOnly {
			t.Errorf("%s read-only", r.Type)
		}
	}
	if len(txt.Values) != 1 || txt.Values[0].Content != `"v=spf1 -all"` {
		t.Fatalf("txt canonical = %+v", txt)
	}
	pg := decode[page[recordJSON]](t, h.do("GET", rp+"?type=A&query=ww", "viewer-a", ""))
	if pg.Total != 1 || pg.Items[0].Name != "www.example.test." || len(pg.Items[0].Values) != 2 || !pg.Items[0].Values[1].Disabled || pg.Items[0].Comment != "web" {
		t.Fatalf("filtered = %+v", pg)
	}
	pg = decode[page[recordJSON]](t, h.do("GET", rp+"?page=2&page_size=5", "viewer-a", ""))
	if pg.Total != 7 || len(pg.Items) != 2 {
		t.Fatalf("paging = %+v", pg)
	}
	if w := h.do("GET", rp+"?page_size=501", "viewer-a", ""); w.Code != 422 {
		t.Fatalf("page_size cap = %d", w.Code)
	}

	// update in place, then rename
	w = h.do("PUT", rp, "admin-a", `{"original":{"name":"www","type":"A"},"record":{"name":"www","type":"A","ttl":600,"values":[{"content":"192.0.2.10"}]}}`)
	if w.Code != 200 || decode[recordJSON](t, w).TTL != 600 {
		t.Fatalf("update = %d %s", w.Code, w.Body)
	}
	w = h.do("PUT", rp, "admin-a", `{"original":{"name":"www.example.test.","type":"A"},"record":{"name":"web","type":"A","ttl":600,"values":[{"content":"192.0.2.10"}]}}`)
	if w.Code != 200 || decode[recordJSON](t, w).Name != "web.example.test." {
		t.Fatalf("rename = %d %s", w.Code, w.Body)
	}
	if pg := decode[page[recordJSON]](t, h.do("GET", rp+"?type=A&query=www", "admin-a", "")); pg.Total != 0 {
		t.Fatalf("old name kept: %+v", pg)
	}
	w = h.do("PUT", rp, "admin-a", `{"original":{"name":"gone","type":"A"},"record":{"name":"gone","type":"A","ttl":600,"values":[{"content":"192.0.2.10"}]}}`)
	if w.Code != 404 || reason(t, w) != "record_not_found" {
		t.Fatalf("update missing = %d %s", w.Code, w.Body)
	}
	w = h.do("PUT", rp, "admin-a", `{"original":{"name":"web","type":"A"},"record":{"name":"www","type":"AAAA","ttl":600,"values":[{"content":"2001:db8::1"}]}}`)
	if w.Code != 409 || reason(t, w) != "conflict" {
		t.Fatalf("rename onto existing = %d %s", w.Code, w.Body)
	}
	// delete
	if w := h.do("DELETE", rp+"?name=web&type=A", "admin-a", ""); w.Code != 204 {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if w := h.do("DELETE", rp+"?name=web&type=A", "admin-a", ""); w.Code != 404 || reason(t, w) != "record_not_found" {
		t.Fatalf("delete again = %d %s", w.Code, w.Body)
	}
	if w := h.do("DELETE", rp+"?name=%40&type=SOA", "admin-a", ""); w.Code != 422 {
		t.Fatalf("delete SOA = %d", w.Code)
	}
}

func TestRecordRefusals(t *testing.T) {
	h := newHarness(t)
	z := h.createZone("admin-a", `{"name":"example.test","kind":"native"}`)
	rp := p + "/zones/" + z.ID + "/records"
	if w := h.do("POST", rp, "admin-a", `{"name":"www","type":"A","ttl":300,"values":[{"content":"192.0.2.1"}]}`); w.Code != 200 {
		t.Fatal(w.Body)
	}
	before := len(h.pd.CallLog())
	cases := []struct {
		body, reason, field string
	}{
		{`{"name":"x","type":"A","ttl":300,"values":[{"content":"999.1.1.1"}]}`, "invalid_record", "values[0].content"},
		{`{"name":"@","type":"MX","ttl":300,"values":[{"content":"mail.example.test."}]}`, "invalid_record", "values[0].content"},
		{`{"name":"@","type":"CNAME","ttl":300,"values":[{"content":"x.example.net."}]}`, "invalid_record", "type"},
		{`{"name":"www","type":"CNAME","ttl":300,"values":[{"content":"x.example.net."}]}`, "invalid_record", "type"},
		{`{"name":"x","type":"A","ttl":30,"values":[{"content":"192.0.2.1"}]}`, "invalid_record", "ttl"},
		{`{"name":"x","type":"TXT","ttl":300,"values":[{"content":"a\nb"}]}`, "invalid_record", "values[0].content"},
		{`{"name":"foo.other.test.","type":"A","ttl":300,"values":[{"content":"192.0.2.1"}]}`, "invalid_name", ""},
	}
	for _, c := range cases {
		w := h.do("POST", rp, "admin-a", c.body)
		if w.Code != 422 || reason(t, w) != c.reason {
			t.Errorf("%s = %d %s", c.body, w.Code, w.Body)
			continue
		}
		detail := decode[errJSON](t, w).Detail
		if msg, _ := detail["message"].(string); msg == "" || strings.Contains(msg, "validate:") {
			t.Errorf("%s: detail = %v", c.body, detail)
		}
		if c.field != "" && detail["field"] != c.field {
			t.Errorf("%s: field = %v", c.body, detail["field"])
		}
	}
	// SOA is not an editable type (contract enum)
	if w := h.do("POST", rp, "admin-a", `{"name":"@","type":"SOA","ttl":300,"values":[{"content":"x"}]}`); w.Code != 422 {
		t.Fatalf("soa = %d", w.Code)
	}
	for _, c := range h.pd.CallLog()[before:] {
		if strings.HasPrefix(c, "PatchRRsets") {
			t.Fatalf("an invalid record reached PowerDNS: %v", c)
		}
	}
	// PowerDNS down
	h.pd.SetDown(true)
	if w := h.do("GET", rp, "admin-a", ""); w.Code != 503 || reason(t, w) != "pdns_unavailable" {
		t.Fatalf("list down = %d %s", w.Code, w.Body)
	}
	h.pd.SetDown(false)
	// unknown zone
	if w := h.do("GET", p+"/zones/nope/records", "admin-a", ""); w.Code != 404 || reason(t, w) != "zone_not_found" {
		t.Fatalf("unknown zone = %d %s", w.Code, w.Body)
	}
	if w := h.do("DELETE", rp+"?"+url.Values{"name": {"x"}}.Encode(), "admin-a", ""); w.Code != 422 {
		t.Fatalf("delete without type = %d", w.Code)
	}
}
