package httpapi

import (
	"errors"
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/records"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/supermasters"
	"github.com/go-freya/freya/services/dns/internal/templates"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

// domainError maps the zones/records services' sentinels to contract reasons.
func domainError(err error) error {
	switch {
	case errors.Is(err, zones.ErrNotFound):
		return ErrZoneNotFound
	case errors.Is(err, zones.ErrDuplicate):
		return ErrDuplicate
	case errors.Is(err, zones.ErrInvalidKind):
		return ErrInvalidKind
	case errors.Is(err, zones.ErrInvalid), errors.Is(err, zones.ErrRejected), errors.Is(err, zones.ErrExportTooLarge),
		errors.Is(err, templates.ErrInvalid), errors.Is(err, supermasters.ErrRejected):
		return ErrBadRequest
	case errors.Is(err, templates.ErrDuplicate), errors.Is(err, supermasters.ErrDuplicate):
		return ErrConflict
	case errors.Is(err, supermasters.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, zones.ErrTemplateNotFound):
		return ErrTemplateNotFound
	case errors.Is(err, records.ErrNotFound):
		return ErrRecordNotFound
	case errors.Is(err, records.ErrConflict):
		return ErrConflict
	}
	return err
}

// message strips the package prefix of a validation error: what remains was
// written by the validator about the caller's own input.
func message(err error) string {
	return validatePrefix.ReplaceAllString(err.Error(), "")
}

var validatePrefix = regexp.MustCompile(`^(?:[a-z ]+: )*validate: [a-z ]+: (?:validate: [a-z ]+: )*`)

// failDNS writes a DNS-domain refusal: record/name/primary refusals carry a
// detail (field + message) so the UI can show the reason inline.
func (s *Server) failDNS(w http.ResponseWriter, r *http.Request, err error) {
	var re *validate.RecordError
	switch {
	case errors.As(err, &re):
		WriteDetail(w, ErrInvalidRecord, map[string]any{"field": re.Field, "message": re.Msg})
	case errors.Is(err, validate.ErrName):
		WriteDetail(w, ErrInvalidName, map[string]any{"message": message(err)})
	case errors.Is(err, validate.ErrMasters):
		WriteDetail(w, ErrBadRequest, map[string]any{"field": s.mastersField(r), "message": message(err)})
	case errors.Is(err, zones.ErrInvalid), errors.Is(err, templates.ErrInvalid):
		WriteDetail(w, ErrBadRequest, map[string]any{"message": message(err)})
	default:
		Fail(w, r, s.log, domainError(err))
	}
}

// mastersField names the field an IP-guard refusal is about.
func (s *Server) mastersField(r *http.Request) string {
	if strings.Contains(r.URL.Path, "/supermasters") {
		return "ip"
	}
	return "masters"
}

// withSubject wraps a handler needing the verified caller. Route permissions
// are enforced by the authorize middleware from the OpenAPI document.
func (s *Server) withSubject(method, path string, fn func(w http.ResponseWriter, r *http.Request, subj authz.Subjects)) {
	s.MustHandle(method, path, func(w http.ResponseWriter, r *http.Request) {
		subj, err := Subjects(r)
		if err != nil {
			Fail(w, r, s.log, err)
			return
		}
		fn(w, r, subj)
	})
}

func queryInt(r *http.Request, name string) int {
	n, err := strconv.Atoi(r.URL.Query().Get(name))
	if err != nil {
		return 0
	}
	return n
}

// registerZones mounts the zone routes (US1).
func (s *Server) registerZones(svc *zones.Service) {
	s.withSubject("GET", Prefix+"/zones", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		q := r.URL.Query()
		items, total, err := svc.List(r.Context(), subj, store.ZoneFilter{Query: q.Get("query"), Kind: q.Get("kind"), Origin: q.Get("origin"),
			Page: queryInt(r, "page"), PageSize: queryInt(r, "page_size")})
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, map[string]any{"items": items, "total": total})
	})
	s.withSubject("POST", Prefix+"/zones", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in zones.CreateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		z, err := svc.Create(r.Context(), subj, in)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusCreated, z)
	})
	s.withSubject("GET", Prefix+"/zones/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		d, err := svc.Get(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, d)
	})
	s.withSubject("PUT", Prefix+"/zones/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in zones.UpdateInput
		if err := DecodeJSON(r, &in, 0); err != nil {
			s.failDNS(w, r, err)
			return
		}
		z, err := svc.Update(r.Context(), subj, r.PathValue("id"), in)
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, z)
	})
	s.withSubject("DELETE", Prefix+"/zones/{id}", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		if err := svc.Delete(r.Context(), subj, r.PathValue("id")); err != nil {
			s.failDNS(w, r, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	})
	// US3: BIND export and NOTIFY.
	s.withSubject("GET", Prefix+"/zones/{id}/export", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		ex, err := svc.Export(r.Context(), subj, r.PathValue("id"))
		if err != nil {
			s.failDNS(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, ex)
	})
	s.withSubject("POST", Prefix+"/zones/{id}/notify", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		if err := svc.Notify(r.Context(), subj, r.PathValue("id")); err != nil {
			s.failDNS(w, r, err)
			return
		}
		w.WriteHeader(http.StatusAccepted)
	})
}
