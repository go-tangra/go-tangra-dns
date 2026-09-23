package httpapi

import (
	"net/http"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

// recordUpdate is the PUT body: the original (name, type) and the new set.
type recordUpdate struct {
	Original records.Key             `json:"original"`
	Record   validate.RecordSetInput `json:"record"`
}

// registerRecords mounts the record-set routes of a zone (US1).
func (s *Server) registerRecords(svc *records.Service) {
	s.withSubject("GET", Prefix+"/zones/{id}/records", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		q := r.URL.Query()
		items, total, err := svc.List(r.Context(), subj, r.PathValue("id"), records.Filter{Type: q.Get("type"), Query: q.Get("query"),
			Page: queryInt(r, "page"), PageSize: queryInt(r, "page_size")})
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
	})
	s.withSubject("POST", Prefix+"/zones/{id}/records", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in validate.RecordSetInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		out, err := svc.Upsert(r.Context(), subj, r.PathValue("id"), in)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.withSubject("PUT", Prefix+"/zones/{id}/records", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in recordUpdate
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		out, err := svc.Update(r.Context(), subj, r.PathValue("id"), in.Original, in.Record)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, out)
	})
	s.withSubject("DELETE", Prefix+"/zones/{id}/records", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		q := r.URL.Query()
		if err := svc.Delete(r.Context(), subj, r.PathValue("id"), records.Key{Name: q.Get("name"), Type: q.Get("type")}); err != nil {
			s.failDNS(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
}
