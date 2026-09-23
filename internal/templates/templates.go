// Package templates manages reusable zone templates (US3, FR-006): per-tenant
// named record lists with a [ZONE] placeholder, validated when saved against a
// placeholder zone and expanded — and re-validated — against the real zone
// when a zone is created from them (zones.TemplateExpander).
package templates

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/validate"
	"github.com/go-freya/freya/services/dns/internal/zones"
)

// Errors (template_not_found, conflict, bad_request).
var (
	ErrNotFound  = zones.ErrTemplateNotFound
	ErrDuplicate = errors.New("templates: a template with that name exists")
	ErrInvalid   = errors.New("templates: invalid template")
)

// Limits.
const (
	MaxName        = 100
	MaxDescription = 1000
)

// Deps wire the service; Store is required.
type Deps struct {
	Store   repo.Store
	Audit   audit.Recorder
	Checker authz.Checker
	Limits  validate.Limits // zero value = validate.DefaultLimits
	Log     *slog.Logger
	Now     func() time.Time
	NewID   func() string
}

// Service manages templates.
type Service struct{ d Deps }

var _ zones.TemplateExpander = (*Service)(nil)

// New builds the service.
func New(d Deps) *Service {
	if d.Limits == (validate.Limits{}) {
		d.Limits = validate.DefaultLimits
	}
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.NewID == nil {
		d.NewID = store.NewID
	}
	return &Service{d: d}
}

// Input is a template as submitted (PUT replaces the record list).
type Input struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	Records     []store.TemplateRecord `json:"records"`
}

// guard checks perm for the caller's tenant: signed-in users through the
// Checker when one is wired (else the HTTP layer enforced the route
// permission); other actors through their allow-lists.
func (s *Service) guard(ctx context.Context, subj authz.Subjects, perm string) error {
	if subj.TenantID == "" {
		return fmt.Errorf("%w: tenant required", authz.ErrForbidden)
	}
	if subj.IsHuman() && s.d.Checker == nil {
		return nil
	}
	return authz.Require(ctx, s.d.Checker, subj, perm)
}

func view(t store.Template) store.Template {
	if t.Records == nil {
		t.Records = []store.TemplateRecord{}
	}
	return t
}

func hasControl(s string) bool {
	return strings.IndexFunc(s, unicode.IsControl) >= 0
}

// normalize validates the input and returns its stored form: trimmed name
// and description, upper-case types, trimmed names/contents, every record
// valid against a placeholder zone.
func (s *Service) normalize(in Input) (Input, error) {
	out := Input{Name: strings.TrimSpace(in.Name), Description: strings.TrimSpace(in.Description), Records: []store.TemplateRecord{}}
	if out.Name == "" || utf8.RuneCountInString(out.Name) > MaxName || hasControl(out.Name) {
		return out, fmt.Errorf("%w: the name must be 1–%d characters without control characters", ErrInvalid, MaxName)
	}
	if utf8.RuneCountInString(out.Description) > MaxDescription {
		return out, fmt.Errorf("%w: the description is longer than %d characters", ErrInvalid, MaxDescription)
	}
	for _, r := range in.Records {
		r.Name, r.Content = strings.TrimSpace(r.Name), strings.TrimSpace(r.Content)
		r.Type = strings.ToUpper(strings.TrimSpace(r.Type))
		out.Records = append(out.Records, r)
	}
	if _, err := ExpandRecords(s.d.Limits, placeholderZone, out.Records); err != nil {
		return out, err
	}
	return out, nil
}

func (s *Service) audit(ctx context.Context, subj authz.Subjects, t audit.EventType, id, name string, err error) {
	e := audit.Event{TenantID: subj.TenantID, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectTemplate, SubjectID: id, Outcome: audit.OutcomeOK, Details: map[string]any{"name": name}}
	if err != nil {
		e.Outcome, e.Reason = audit.OutcomeRefused, "bad_request"
		var re *validate.RecordError
		switch {
		case errors.Is(err, ErrNotFound):
			e.Reason = "template_not_found"
		case errors.Is(err, ErrDuplicate):
			e.Reason = "conflict"
		case errors.As(err, &re):
			e.Reason = "invalid_record"
		case errors.Is(err, ErrInvalid), errors.Is(err, validate.ErrName):
		default:
			e.Outcome, e.Reason = audit.OutcomeError, "error"
		}
	}
	audit.Emit(ctx, s.d.Audit, e)
}

func mapStore(err error) error {
	switch {
	case errors.Is(err, repo.ErrNotFound):
		return ErrNotFound
	case errors.Is(err, repo.ErrConflict):
		return ErrDuplicate
	}
	return err
}

// List returns the tenant's templates (name order).
func (s *Service) List(ctx context.Context, subj authz.Subjects) ([]store.Template, error) {
	if err := s.guard(ctx, subj, authz.ZonesRead); err != nil {
		return nil, err
	}
	items, err := s.d.Store.ListTemplates(ctx, subj.TenantID)
	if err != nil {
		return nil, err
	}
	out := make([]store.Template, 0, len(items))
	for _, t := range items {
		out = append(out, view(t))
	}
	return out, nil
}

// Get returns one template of the tenant.
func (s *Service) Get(ctx context.Context, subj authz.Subjects, id string) (store.Template, error) {
	if err := s.guard(ctx, subj, authz.ZonesRead); err != nil {
		return store.Template{}, err
	}
	t, err := s.d.Store.GetTemplate(ctx, subj.TenantID, id)
	if err != nil {
		return store.Template{}, mapStore(err)
	}
	return view(t), nil
}

// Create validates and stores a template.
func (s *Service) Create(ctx context.Context, subj authz.Subjects, in Input) (store.Template, error) {
	if err := s.guard(ctx, subj, authz.TemplatesManage); err != nil {
		return store.Template{}, err
	}
	n, err := s.normalize(in)
	if err != nil {
		s.audit(ctx, subj, audit.TemplateCreate, "", n.Name, err)
		return store.Template{}, err
	}
	now := s.d.Now()
	t := store.Template{ID: s.d.NewID(), TenantID: subj.TenantID, Name: n.Name, Description: n.Description, Records: n.Records, CreatedAt: now, UpdatedAt: now}
	if err := s.d.Store.CreateTemplate(ctx, t); err != nil {
		err = mapStore(err)
		s.audit(ctx, subj, audit.TemplateCreate, t.ID, t.Name, err)
		return store.Template{}, err
	}
	s.audit(ctx, subj, audit.TemplateCreate, t.ID, t.Name, nil)
	return view(t), nil
}

// Update replaces name, description and the record list.
func (s *Service) Update(ctx context.Context, subj authz.Subjects, id string, in Input) (store.Template, error) {
	if err := s.guard(ctx, subj, authz.TemplatesManage); err != nil {
		return store.Template{}, err
	}
	n, err := s.normalize(in)
	if err != nil {
		s.audit(ctx, subj, audit.TemplateUpdate, id, n.Name, err)
		return store.Template{}, err
	}
	t, err := s.d.Store.UpdateTemplate(ctx, store.Template{ID: id, TenantID: subj.TenantID, Name: n.Name, Description: n.Description,
		Records: n.Records, UpdatedAt: s.d.Now()})
	if err != nil {
		err = mapStore(err)
		s.audit(ctx, subj, audit.TemplateUpdate, id, n.Name, err)
		return store.Template{}, err
	}
	s.audit(ctx, subj, audit.TemplateUpdate, id, t.Name, nil)
	return view(t), nil
}

// Delete removes a template (zones created from it are kept).
func (s *Service) Delete(ctx context.Context, subj authz.Subjects, id string) error {
	if err := s.guard(ctx, subj, authz.TemplatesManage); err != nil {
		return err
	}
	if err := s.d.Store.DeleteTemplate(ctx, subj.TenantID, id); err != nil {
		err = mapStore(err)
		s.audit(ctx, subj, audit.TemplateDelete, id, "", err)
		return err
	}
	s.audit(ctx, subj, audit.TemplateDelete, id, "", nil)
	return nil
}

// Expand implements zones.TemplateExpander: the tenant's template expanded
// and re-validated for zone (ErrNotFound = zones.ErrTemplateNotFound).
func (s *Service) Expand(ctx context.Context, tenantID, templateID, zone string) ([]pdns.RRset, error) {
	t, err := s.d.Store.GetTemplate(ctx, tenantID, templateID)
	if err != nil {
		return nil, mapStore(err)
	}
	return ExpandRecords(s.d.Limits, zone, t.Records)
}
