package httpapi

import (
	"encoding/json"
	"net/http/httptest"
	"testing"

	"github.com/go-tangra/go-tangra-dns/v4/internal/store"
)

// parseList is the handlers' defence in depth behind the OpenAPI validator:
// the same refusals, naming only the parameter.
func TestParseList(t *testing.T) {
	cases := map[string]string{
		"sort=bogus":           "sort",
		"order=up":             "order",
		"page_size=201":        "page_size",
		"page=0":               "page",
		"page=x":               "page",
		"cursor=abc&page=2":    "cursor",
		"sort=name&order=desc": "",
		"page=3&page_size=200": "",
		"":                     "",
	}
	for q, param := range cases {
		w := httptest.NewRecorder()
		req, ok := parseList(w, httptest.NewRequest("GET", "/x?"+q, nil), store.ZoneList)
		if param == "" {
			if !ok || w.Body.Len() != 0 || req.Sort == "" {
				t.Errorf("%q refused: %s", q, w.Body)
			}
			continue
		}
		var body struct {
			Reason string            `json:"reason"`
			Detail map[string]string `json:"detail"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		if ok || w.Code != 422 || body.Reason != "validation_failed" || body.Detail["param"] != param {
			t.Errorf("%q = %v %d %s", q, ok, w.Code, w.Body)
		}
	}
	// records allow at most 200 per page as well
	if _, ok := parseList(httptest.NewRecorder(), httptest.NewRequest("GET", "/x?page_size=201", nil), store.RecordList); ok {
		t.Error("records page_size 201 accepted")
	}
}
