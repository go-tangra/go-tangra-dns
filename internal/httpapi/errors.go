package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/pdns"
	"github.com/go-tangra/go-tangra-dns/v4/internal/repo"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
)

// Error is a refusal with a stable reason from the closed vocabulary of
// contracts §A (plus the platform envelope reasons).
type Error struct {
	Status int
	Reason string
}

func (e *Error) Error() string { return e.Reason }

// Refusals.
var (
	ErrUnauthenticated = &Error{http.StatusUnauthorized, "unauthenticated"}
	ErrForbidden       = &Error{http.StatusForbidden, "forbidden"}
	ErrNotFound        = &Error{http.StatusNotFound, "not_found"}
	ErrMalformed       = &Error{http.StatusBadRequest, "malformed_body"}
	ErrBadRequest      = &Error{http.StatusBadRequest, "bad_request"}
	ErrValidation      = &Error{http.StatusUnprocessableEntity, "validation_failed"}
	ErrConflict        = &Error{http.StatusConflict, "conflict"}
	ErrBodyTooLarge    = &Error{http.StatusRequestEntityTooLarge, "body_too_large"}
	ErrRateLimited     = &Error{http.StatusTooManyRequests, "rate_limited"}
	ErrUnavailable     = &Error{http.StatusServiceUnavailable, "temporarily_unavailable"}
	ErrNotImplemented  = &Error{http.StatusNotImplemented, "not_implemented"}

	// DNS-domain reasons (contracts §A).
	ErrInvalidName        = &Error{http.StatusUnprocessableEntity, "invalid_name"}
	ErrInvalidRecord      = &Error{http.StatusUnprocessableEntity, "invalid_record"}
	ErrInvalidKind        = &Error{http.StatusUnprocessableEntity, "invalid_kind"}
	ErrInvalidConfig      = &Error{http.StatusUnprocessableEntity, "invalid_config"}
	ErrZoneNotFound       = &Error{http.StatusNotFound, "zone_not_found"}
	ErrRecordNotFound     = &Error{http.StatusNotFound, "record_not_found"}
	ErrTemplateNotFound   = &Error{http.StatusNotFound, "template_not_found"}
	ErrDuplicate          = &Error{http.StatusConflict, "duplicate"}
	ErrPDNSUnavailable    = &Error{http.StatusServiceUnavailable, "pdns_unavailable"}
	ErrMetricsUnavailable = &Error{http.StatusServiceUnavailable, "metrics_unavailable"}
)

// MaxBodyBytes bounds JSON bodies of ordinary operations (a record set of 100
// long TXT values or a 200-row template fits).
const MaxBodyBytes = 512 << 10

// WriteJSON encodes v with status; API responses are never cached.
func WriteJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// WriteError emits {"reason": ...} and nothing else.
func WriteError(w http.ResponseWriter, status int, reason string) {
	WriteJSON(w, status, map[string]string{"reason": reason})
}

// WriteDetail emits {"reason": ..., "detail": {...}}; detail values are never secrets.
func WriteDetail(w http.ResponseWriter, e *Error, detail map[string]any) {
	WriteJSON(w, e.Status, map[string]any{"reason": e.Reason, "detail": detail})
}

// Fail maps err to a response: *Error verbatim, store/authz/validation/PowerDNS
// sentinels to their reasons, oversized bodies to 413, anything else to 503
// (details logged only, never returned — PowerDNS messages stay server-side).
func Fail(w http.ResponseWriter, r *http.Request, log *slog.Logger, err error) {
	status, reason := Status(err)
	if status >= 500 && log != nil {
		log.ErrorContext(r.Context(), "request failed", "path", r.URL.Path, "request_id", RequestID(r), "err", err)
	}
	WriteError(w, status, reason)
}

// Status maps an error to its status and reason.
func Status(err error) (int, string) {
	var e *Error
	var mbe *http.MaxBytesError
	switch {
	case errors.As(err, &e):
		return e.Status, e.Reason
	case errors.As(err, &mbe):
		return ErrBodyTooLarge.Status, ErrBodyTooLarge.Reason
	case errors.Is(err, authz.ErrForbidden):
		return ErrForbidden.Status, ErrForbidden.Reason
	case errors.Is(err, validate.ErrName):
		return ErrInvalidName.Status, ErrInvalidName.Reason
	case errors.Is(err, validate.ErrMasters):
		return ErrBadRequest.Status, ErrBadRequest.Reason
	case errors.Is(err, repo.ErrNotFound):
		return ErrNotFound.Status, ErrNotFound.Reason
	case errors.Is(err, repo.ErrConflict):
		return ErrConflict.Status, ErrConflict.Reason
	case errors.Is(err, pdns.ErrUnavailable):
		return ErrPDNSUnavailable.Status, ErrPDNSUnavailable.Reason
	}
	return ErrUnavailable.Status, ErrUnavailable.Reason
}

// DecodeJSON reads a bounded JSON body into v, refusing unknown fields and
// trailing data. limit <= 0 means MaxBodyBytes.
func DecodeJSON(r *http.Request, v any, limit int64) error {
	if limit <= 0 {
		limit = MaxBodyBytes
	}
	body := http.MaxBytesReader(nil, r.Body, limit)
	dec := json.NewDecoder(body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		var mbe *http.MaxBytesError
		if errors.As(err, &mbe) {
			return ErrBodyTooLarge
		}
		return ErrMalformed
	}
	if _, err := dec.Token(); err != io.EOF {
		return ErrMalformed
	}
	return nil
}
