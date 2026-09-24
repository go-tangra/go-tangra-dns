package httpapi

import (
	"errors"
	"net/http"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dnsconf"
)

// registerConfig mounts the server-configuration routes (US5; config:manage
// from the route AND platform-admin enforced by the service).
func (s *Server) registerConfig(svc *dnsconf.Service) {
	s.withSubject("GET", Prefix+"/config", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		v, err := svc.Get(r.Context(), subj)
		if err != nil {
			s.failConfig(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, v)
	})
	s.withSubject("PUT", Prefix+"/config", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in dnsconf.Model
		if err := DecodeJSON(r, &in, 0); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		res, err := svc.Update(r.Context(), subj, in)
		if err != nil {
			s.failConfig(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, res)
	})
}

func (s *Server) failConfig(w http.ResponseWriter, r *http.Request, err error) {
	var fe *dnsconf.FieldError
	if errors.As(err, &fe) {
		WriteDetail(w, ErrInvalidConfig, map[string]any{"field": fe.Field, "message": fe.Msg})
		return
	}
	Fail(w, r, s.log, err)
}
