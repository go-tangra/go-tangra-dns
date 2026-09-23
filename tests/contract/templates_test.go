package contract

// T059: the US3 surface of contracts §A over the full HTTP chain: template
// CRUD shapes and refusals, zone creation from a template, supermaster routes
// (no PUT; create/delete platform-admin only), zone export text and NOTIFY
// (202 for master, invalid_kind for native), permissions per route.

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-freya/freya/internal/testrt"
	"github.com/go-freya/freya/internal/testutil"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/events"
	"github.com/go-freya/freya/services/dns/internal/httpapi"
	"github.com/go-freya/freya/services/dns/internal/memstore"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/recursor"
	"github.com/go-freya/freya/services/dns/internal/supermasters"
	"github.com/go-freya/freya/services/dns/internal/templates"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

const platformA = "66666666-6666-7666-8666-666666666666"

func newUS3Harness(t *testing.T) *harness {
	t.Helper()
	rt := testrt.New(t, testutil.MustCA("example.org"), "dns")
	v := verifier{
		"admin-a":    {UserID: adminA, TenantID: tenantA, Roles: []string{"owner", "admin"}},
		"viewer-a":   {UserID: viewerA, TenantID: tenantA},
		"admin-b":    {UserID: adminB, TenantID: tenantB},
		"platform-a": {UserID: platformA, TenantID: tenantA, Roles: []string{authz.RolePlatformAdmin}},
	}
	all := []string{authz.ZonesRead, authz.ZonesManage, authz.TemplatesManage, authz.SupermastersManage}
	checker := authz.Static{adminA: all, adminB: all, platformA: all, viewerA: {authz.ZonesRead}}
	s, err := httpapi.NewHandler(rt, httpapi.WithVerifier(v), httpapi.WithChecker(checker))
	if err != nil {
		t.Fatal(err)
	}
	h := newHarness(t)
	h.s = s
	h.st, h.pd, h.rec, h.pub = memstore.New(), pdns.NewFake(), recursor.NewFake(), &events.Recorder{}
	ts := templates.New(templates.Deps{Store: h.st})
	zs := zones.New(zones.Deps{Store: h.st, PDNS: h.pd, Recursor: h.rec, Events: h.pub, Templates: ts})
	rs := records.New(records.Deps{Zones: zs, PDNS: h.pd, Events: h.pub})
	sm := supermasters.New(supermasters.Deps{Store: h.st, PDNS: h.pd})
	s.Register(httpapi.Deps{Zones: zs, Records: rs, Templates: ts, Supermasters: sm})
	return h
}

type templateJSON struct {
	ID      string `json:"id"`
	Name    string `json:"name"`
	Records []struct {
		Name     string `json:"name"`
		Type     string `json:"type"`
		TTL      int    `json:"ttl"`
		Content  string `json:"content"`
		Priority int    `json:"priority"`
	} `json:"records"`
}

const stdTemplate = `{"name":"Standard","description":"mail","records":[
 {"name":"@","type":"NS","ttl":3600,"content":"ns1.[ZONE]."},
 {"name":"@","type":"MX","ttl":3600,"content":"mail.[ZONE].","priority":10},
 {"name":"www","type":"CNAME","ttl":300,"content":"[ZONE]."}]}`

func TestTemplateShapes(t *testing.T) {
	h := newUS3Harness(t)
	w := h.do("POST", p+"/templates", "admin-a", stdTemplate)
	if w.Code != 201 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	tpl := decode[templateJSON](t, w)
	if tpl.ID == "" || tpl.Name != "Standard" || len(tpl.Records) != 3 || tpl.Records[1].Priority != 10 {
		t.Fatalf("template = %+v", tpl)
	}
	if w := h.do("GET", p+"/templates", "viewer-a", ""); w.Code != 200 || len(decode[page[templateJSON]](t, w).Items) != 1 {
		t.Fatalf("list = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/templates", "admin-b", ""); w.Code != 200 || len(decode[page[templateJSON]](t, w).Items) != 0 {
		t.Fatalf("other tenant list = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/templates/"+tpl.ID, "viewer-a", ""); w.Code != 200 {
		t.Fatalf("get = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/templates/"+tpl.ID, "admin-b", ""); w.Code != 404 || reason(t, w) != "template_not_found" {
		t.Fatalf("cross-tenant get = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/templates", "admin-a", `{"name":"STANDARD","records":[]}`); w.Code != 409 || reason(t, w) != "conflict" {
		t.Fatalf("duplicate = %d %s", w.Code, w.Body)
	}
	w = h.do("POST", p+"/templates", "admin-a", `{"name":"Bad","records":[{"name":"@","type":"A","ttl":3600,"content":"nope"}]}`)
	if w.Code != 422 || reason(t, w) != "invalid_record" || decode[errJSON](t, w).Detail["field"] != "records[0].content" {
		t.Fatalf("invalid record = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/templates", "admin-a", `{"name":"  ","records":[]}`); w.Code != 400 || reason(t, w) != "bad_request" {
		t.Fatalf("blank name = %d %s", w.Code, w.Body)
	}
	// zone from template
	z := h.createZone("admin-a", `{"name":"tpl.test","kind":"native","template_id":"`+tpl.ID+`"}`)
	w = h.do("GET", p+"/zones/"+z.ID+"/records?type=MX", "viewer-a", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), `"10 mail.tpl.test."`) {
		t.Fatalf("expanded MX = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/zones", "admin-a", `{"name":"tpl2.test","kind":"native","template_id":"missing"}`); w.Code != 404 || reason(t, w) != "template_not_found" {
		t.Fatalf("missing template = %d %s", w.Code, w.Body)
	}
	// update replaces the list; delete keeps zones
	w = h.do("PUT", p+"/templates/"+tpl.ID, "admin-a", `{"name":"Renamed","records":[{"name":"@","type":"TXT","ttl":300,"content":"hi"}]}`)
	if w.Code != 200 || len(decode[templateJSON](t, w).Records) != 1 {
		t.Fatalf("update = %d %s", w.Code, w.Body)
	}
	for _, c := range []struct{ method, path, body string }{
		{"POST", "/templates", stdTemplate},
		{"PUT", "/templates/" + tpl.ID, stdTemplate},
		{"DELETE", "/templates/" + tpl.ID, ""},
	} {
		if w := h.do(c.method, p+c.path, "viewer-a", c.body); w.Code != 403 {
			t.Errorf("viewer %s %s = %d", c.method, c.path, w.Code)
		}
	}
	if w := h.do("DELETE", p+"/templates/"+tpl.ID, "admin-a", ""); w.Code != 204 {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if w := h.do("DELETE", p+"/templates/"+tpl.ID, "admin-a", ""); w.Code != 404 || reason(t, w) != "template_not_found" {
		t.Fatalf("delete twice = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/zones/"+z.ID, "viewer-a", ""); w.Code != 200 {
		t.Fatal("zone removed with its template")
	}
}

type supermasterJSON struct {
	ID         string `json:"id"`
	IP         string `json:"ip"`
	Nameserver string `json:"nameserver"`
	TenantID   string `json:"tenant_id"`
}

func TestSupermasterRoutes(t *testing.T) {
	h := newUS3Harness(t)
	body := `{"ip":"192.0.2.53","nameserver":"ns1.primary.example"}`
	if w := h.do("POST", p+"/supermasters", "admin-a", body); w.Code != 403 || reason(t, w) != "forbidden" {
		t.Fatalf("tenant admin create = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/supermasters", "viewer-a", body); w.Code != 403 {
		t.Fatalf("viewer create = %d", w.Code)
	}
	w := h.do("POST", p+"/supermasters", "platform-a", body)
	if w.Code != 201 {
		t.Fatalf("create = %d %s", w.Code, w.Body)
	}
	sm := decode[supermasterJSON](t, w)
	if sm.ID == "" || sm.IP != "192.0.2.53" || sm.Nameserver != "ns1.primary.example." {
		t.Fatalf("supermaster = %+v", sm)
	}
	if w := h.do("POST", p+"/supermasters", "platform-a", body); w.Code != 409 || reason(t, w) != "conflict" {
		t.Fatalf("duplicate = %d %s", w.Code, w.Body)
	}
	w = h.do("POST", p+"/supermasters", "platform-a", `{"ip":"127.0.0.1","nameserver":"ns1.primary.example"}`)
	if w.Code != 400 || reason(t, w) != "bad_request" || decode[errJSON](t, w).Detail["field"] != "ip" {
		t.Fatalf("loopback = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/supermasters", "platform-a", `{"ip":"192.0.2.9","nameserver":"x"}`); w.Code != 422 || reason(t, w) != "invalid_name" {
		t.Fatalf("bad nameserver = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/supermasters", "admin-a", ""); w.Code != 200 || len(decode[page[supermasterJSON]](t, w).Items) != 1 {
		t.Fatalf("list = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/supermasters", "viewer-a", ""); w.Code != 403 {
		t.Fatalf("viewer list = %d", w.Code)
	}
	if w := h.do("GET", p+"/supermasters/"+sm.ID, "admin-a", ""); w.Code != 200 {
		t.Fatalf("get = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/supermasters/"+sm.ID, "admin-b", ""); w.Code != 404 || reason(t, w) != "not_found" {
		t.Fatalf("cross-tenant get = %d %s", w.Code, w.Body)
	}
	// no update route
	r := h.s.Handler()
	req := newReq(http.MethodPut, p+"/supermasters/"+sm.ID, "platform-a", body)
	rw := httptest.NewRecorder()
	r.ServeHTTP(rw, req)
	if rw.Code == 200 || rw.Code == 201 || rw.Code == 204 {
		t.Fatalf("PUT supermaster = %d", rw.Code)
	}
	if w := h.do("DELETE", p+"/supermasters/"+sm.ID, "admin-a", ""); w.Code != 403 {
		t.Fatalf("tenant admin delete = %d", w.Code)
	}
	if w := h.do("DELETE", p+"/supermasters/"+sm.ID, "platform-a", ""); w.Code != 204 {
		t.Fatalf("delete = %d %s", w.Code, w.Body)
	}
	if l, _ := h.pd.ListSupermasters(t.Context()); len(l) != 0 {
		t.Fatalf("PowerDNS rows = %+v", l)
	}
}

func TestExportAndNotifyRoutes(t *testing.T) {
	h := newUS3Harness(t)
	native := h.createZone("admin-a", `{"name":"exp.test","kind":"native","nameservers":["ns1.exp.test"]}`)
	master := h.createZone("admin-a", `{"name":"m.test","kind":"master","nameservers":["ns1.m.test"]}`)
	w := h.do("GET", p+"/zones/"+native.ID+"/export", "admin-a", "")
	ex := decode[struct {
		Zone string `json:"zone"`
		Text string `json:"text"`
	}](t, w)
	if w.Code != 200 || ex.Zone != "exp.test." || !strings.Contains(ex.Text, "exp.test.\t3600\tIN\tSOA") {
		t.Fatalf("export = %d %s", w.Code, w.Body)
	}
	if w := h.do("GET", p+"/zones/"+native.ID+"/export", "viewer-a", ""); w.Code != 403 {
		t.Fatalf("viewer export = %d", w.Code)
	}
	if w := h.do("GET", p+"/zones/"+native.ID+"/export", "admin-b", ""); w.Code != 404 || reason(t, w) != "zone_not_found" {
		t.Fatalf("cross-tenant export = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/zones/"+master.ID+"/notify", "admin-a", ""); w.Code != 202 {
		t.Fatalf("master notify = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/zones/"+native.ID+"/notify", "admin-a", ""); w.Code != 422 || reason(t, w) != "invalid_kind" {
		t.Fatalf("native notify = %d %s", w.Code, w.Body)
	}
	if w := h.do("POST", p+"/zones/"+master.ID+"/notify", "viewer-a", ""); w.Code != 403 {
		t.Fatalf("viewer notify = %d", w.Code)
	}
	h.pd.SetDown(true)
	if w := h.do("GET", p+"/zones/"+native.ID+"/export", "admin-a", ""); w.Code != 503 || reason(t, w) != "pdns_unavailable" {
		t.Fatalf("down export = %d %s", w.Code, w.Body)
	}
}

func newReq(method, path, tok, body string) *http.Request {
	r := httptest.NewRequest(method, path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Authorization", "Bearer "+tok)
	r.Header.Set("X-CSRF-Token", "csrf")
	return r
}
