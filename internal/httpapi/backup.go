package httpapi

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"

	"github.com/go-tangra/go-tangra-dns/v4/internal/authz"
	"github.com/go-tangra/go-tangra-dns/v4/internal/backup"
)

// MaxImportBytes bounds a backup import body (x-freya-max-body-bytes).
const MaxImportBytes = 64 << 20

type exportRequest struct {
	TenantID string `json:"tenant_id,omitempty"`
}

type importRequest struct {
	Mode     string          `json:"mode,omitempty"`
	TenantID string          `json:"tenant_id,omitempty"`
	Full     bool            `json:"full,omitempty"`
	Backup   json.RawMessage `json:"backup"`
}

// registerBackup mounts the tenant export/import routes (FR-017).
func (s *Server) registerBackup(svc *backup.Service, parse func([]byte) (backup.Backup, error)) {
	s.withSubject("POST", Prefix+"/backup/export", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in exportRequest
		if err := decodeOptional(r, &in); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		b, err := svc.Export(r.Context(), subj, in.TenantID)
		if err != nil {
			s.failBackup(w, r, err)
			return
		}
		w.Header().Set("Content-Disposition", `attachment; filename="dns-backup.json"`)
		WriteJSON(w, http.StatusOK, b)
	})
	s.withSubject("POST", Prefix+"/backup/import", func(w http.ResponseWriter, r *http.Request, subj authz.Subjects) {
		var in importRequest
		if err := DecodeJSON(r, &in, MaxImportBytes); err != nil {
			Fail(w, r, s.log, err)
			return
		}
		if in.Mode != "" && in.Mode != backup.ModeSkip && in.Mode != backup.ModeOverwrite {
			WriteDetail(w, ErrValidation, map[string]any{"field": "mode"})
			return
		}
		doc, err := parse(in.Backup)
		if err != nil {
			s.failBackup(w, r, err)
			return
		}
		res, err := svc.Import(r.Context(), subj, doc, backup.Options{Mode: in.Mode, TenantID: in.TenantID, Full: in.Full})
		if err != nil {
			s.failBackup(w, r, err)
			return
		}
		WriteJSON(w, http.StatusOK, res)
	})
}

func (s *Server) failBackup(w http.ResponseWriter, r *http.Request, err error) {
	if errors.Is(err, backup.ErrBadSchema) || errors.Is(err, backup.ErrTooLarge) {
		WriteDetail(w, ErrValidation, map[string]any{"message": "the backup document is invalid"})
		return
	}
	s.failDNS(w, r, err)
}

// decodeOptional decodes a bounded JSON body that may be absent.
func decodeOptional(r *http.Request, v any) error {
	if r.Body == nil || r.ContentLength == 0 {
		return nil
	}
	raw, err := io.ReadAll(http.MaxBytesReader(nil, r.Body, MaxBodyBytes))
	if err != nil {
		return ErrBodyTooLarge
	}
	if len(raw) == 0 {
		return nil
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil || dec.More() {
		return ErrMalformed
	}
	return nil
}
