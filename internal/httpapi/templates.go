package httpapi

import (
	"net/http"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/supermasters"
	"github.com/go-freya/freya/services/dns/internal/templates"
)

// registerTemplates mounts the zone-template routes (US3).
func (s *Server) registerTemplates(svc *templates.Service) {
	s.withSubject("GET", Prefix+"/templates", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		items, err := svc.List(r.Context(), subj)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.withSubject("POST", Prefix+"/templates", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in templates.Input
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		t, err := svc.Create(r.Context(), subj, in)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, t)
	})
	s.withSubject("GET", Prefix+"/templates/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		t, err := svc.Get(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, t)
	})
	s.withSubject("PUT", Prefix+"/templates/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in templates.Input
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		t, err := svc.Update(r.Context(), subj, r.PathValue("id"), in)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, t)
	})
	s.withSubject("DELETE", Prefix+"/templates/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		if err := svc.Delete(r.Context(), subj, r.PathValue("id")); err != nil {
			s.failDNS(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}

// registerSupermasters mounts the supermaster routes (US3; no update route).
func (s *Server) registerSupermasters(svc *supermasters.Service) {
	s.withSubject("GET", Prefix+"/supermasters", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		items, err := svc.List(r.Context(), subj)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items})
	})
	s.withSubject("POST", Prefix+"/supermasters", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in supermasters.Input
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		sm, err := svc.Create(r.Context(), subj, in)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, sm)
	})
	s.withSubject("GET", Prefix+"/supermasters/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		sm, err := svc.Get(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, sm)
	})
	s.withSubject("DELETE", Prefix+"/supermasters/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		if err := svc.Delete(r.Context(), subj, r.PathValue("id")); err != nil {
			s.failDNS(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
