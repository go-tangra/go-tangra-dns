package dashboard

// T088: the stdlib Prometheus HTTP API client — query / query_range
// parameters, vector/matrix/scalar decoding, error and status handling, and
// the response size cap.

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

type promSrv struct {
	last url.Values
	path string
	code int
	body string
}

func (p *promSrv) start(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.last, p.path = r.URL.Query(), r.URL.Path
		if r.Method != http.MethodGet {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if p.code != 0 {
			w.WriteHeader(p.code)
		}
		_, _ = w.Write([]byte(p.body))
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestPromQuery(t *testing.T) {
	ps := &promSrv{body: `{"status":"success","data":{"resultType":"vector","result":[{"metric":{"instance":"rec:8082"},"value":[1758628800.5,"12.25"]},{"metric":{},"value":[1758628800.5,"NaN"]}]}}`}
	srv := ps.start(t)
	c, err := NewProm(PromConfig{BaseURL: srv.URL + "/prom/", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	at := time.Unix(1758628800, 0)
	got, err := c.Query(context.Background(), "sum(rate(pdns_recursor_questions[5m]))", at)
	if err != nil {
		t.Fatal(err)
	}
	if ps.path != "/prom/api/v1/query" || ps.last.Get("query") != "sum(rate(pdns_recursor_questions[5m]))" || ps.last.Get("time") != "1758628800" {
		t.Fatalf("request = %s %v", ps.path, ps.last)
	}
	if len(got) != 1 || got[0].Value != 12.25 || got[0].Labels["instance"] != "rec:8082" {
		t.Fatalf("samples = %+v", got)
	}
	ps.body = `{"status":"success","data":{"resultType":"scalar","result":[1758628800,"3"]}}`
	if got, err = c.Query(context.Background(), "x", at); err != nil || len(got) != 1 || got[0].Value != 3 {
		t.Fatalf("scalar = %+v %v", got, err)
	}
}

func TestPromQueryRange(t *testing.T) {
	ps := &promSrv{body: `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{"job":"pdns"},"values":[[1000,"1"],[1060,"2.5"],[1120,"+Inf"]]}]}}`}
	srv := ps.start(t)
	c, _ := NewProm(PromConfig{BaseURL: srv.URL})
	got, err := c.QueryRange(context.Background(), "rate(pdns_auth_backend_queries[5m])", time.Unix(1000, 0), time.Unix(4600, 0), time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ps.path != "/api/v1/query_range" || ps.last.Get("start") != "1000" || ps.last.Get("end") != "4600" || ps.last.Get("step") != "60" {
		t.Fatalf("request = %s %v", ps.path, ps.last)
	}
	if len(got) != 1 || got[0].Labels["job"] != "pdns" || len(got[0].Points) != 2 || got[0].Points[1] != [2]float64{1060, 2.5} {
		t.Fatalf("series = %+v", got)
	}
}

func TestPromErrors(t *testing.T) {
	ps := &promSrv{}
	srv := ps.start(t)
	c, _ := NewProm(PromConfig{BaseURL: srv.URL, MaxBytes: 256})
	ctx := context.Background()
	cases := []struct {
		code int
		body string
		want error
	}{
		{400, `{"status":"error","errorType":"bad_data","error":"parse error at char 3"}`, ErrQuery},
		{503, `oops`, ErrQuery},
		{200, `{"status":"error","error":"x"}`, ErrQuery},
		{200, `not json`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"string","result":[1,"x"]}}`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1,"abc"]}]}}`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":[1]}]}}`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"vector","result":[{"metric":{},"value":["x","1"]}]}}`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"matrix","result":[{"metric":{},"values":[[1,"zz"]]}]}}`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"scalar","result":[1]}}`, ErrQuery},
		{200, `{"status":"success","data":{"resultType":"vector","result":[` + strings.Repeat(`{"metric":{},"value":[1,"1"]},`, 20) + `{}]}}`, ErrTooLarge},
	}
	for i, c2 := range cases {
		ps.code, ps.body = c2.code, c2.body
		_, err1 := c.Query(ctx, "q", time.Unix(1, 0))
		_, err2 := c.QueryRange(ctx, "q", time.Unix(1, 0), time.Unix(2, 0), time.Second)
		if !errors.Is(err1, c2.want) || !errors.Is(err2, c2.want) {
			t.Errorf("case %d: %v / %v", i, err1, err2)
		}
		if err1 != nil && strings.Contains(err1.Error(), "parse error") {
			t.Errorf("case %d: server text surfaced: %v", i, err1)
		}
	}
	srv.Close()
	if _, err := c.Query(ctx, "q", time.Unix(1, 0)); !errors.Is(err, ErrUnreachable) {
		t.Fatalf("closed = %v", err)
	}
	for _, bad := range []string{"", "ftp://x", "http://", "http://u:p@h", "http://h/?q=1", "http://h/#f", "::"} {
		if _, err := NewProm(PromConfig{BaseURL: bad}); err == nil {
			t.Errorf("base %q accepted", bad)
		}
	}
}

func TestFake(t *testing.T) {
	f := NewFake()
	f.Instant["a"] = []Sample{{Value: 1}}
	if s, err := f.Query(context.Background(), "a", time.Now()); err != nil || len(s) != 1 {
		t.Fatal("instant")
	}
	f.Err["b"] = errors.New("x")
	if _, err := f.QueryRange(context.Background(), "b", time.Now(), time.Now(), time.Second); err == nil {
		t.Fatal("err")
	}
	f.Hook = func(context.Context) error { return errors.New("hook") }
	if _, err := f.Query(context.Background(), "a", time.Now()); err == nil {
		t.Fatal("hook")
	}
	if len(f.Exprs()) != 3 || len(f.Ranges()) != 1 {
		t.Fatalf("calls = %v %v", f.Exprs(), f.Ranges())
	}
}
