package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dashboard"
)

// registerDashboard mounts the curated dashboard (US6). Only the window is
// accepted; any other query parameter (e.g. a PromQL "query") is refused.
func (s *Server) registerDashboard(svc *dashboard.Service) {
	s.withSubject("GET", Prefix+"/dashboard", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		q := r.URL.Query()
		for k := range q {
			if k != "window" {
				WriteDetail(w, ErrBadRequest, map[string]any{"message": "only the window parameter is accepted"})
				return
			}
		}
		if len(q["window"]) > 1 {
			WriteError(w, ErrBadRequest.Status, ErrBadRequest.Reason)
			return
		}
		res, err := svc.Get(r.Context(), subj, q.Get("window"))
		if errors.Is(err, dashboard.ErrWindow) {
			WriteDetail(w, ErrBadRequest, map[string]any{"message": err.Error()})
			return
		}
		if err != nil {
			Fail(w, r, s.log, err)
			return
		}
		WriteJSON(w, http.StatusOK, res)
	})
}
