// Package backup exports and imports a tenant's DNS metadata (FR-017, research
// D16). The export is schema-versioned and carries the tenant's zone metadata
// (with each zone's BIND text from PowerDNS for reference only), its zone
// templates and its supermaster rows. It NEVER carries API keys, the PowerDNS
// zone ids or the server configuration: those are platform secrets / platform
// state, not tenant data.
//
// Import (skip keeps existing rows, overwrite rewrites them):
//   - zones are re-linked, never re-created: a zone is imported only when it
//     exists on the PowerDNS server, is not owned by another tenant (locally or
//     through its PowerDNS account) and does not overlap another tenant's zone;
//     zones missing on the server are reported in missing_in_pdns. The BIND
//     text is not re-imported. A restore never deletes a zone.
//   - templates are upserted by id (validated like the templates API).
//   - supermasters touch the shared server, so they are restored only for a
//     platform administrator (research D15); for anyone else they are skipped.
//
// A restore into another tenant than the caller's (cross-tenant) or a full
// restore (the target's templates are wiped first) requires a platform admin;
// a cross-tenant restore mints fresh ids so primary keys never collide.
package backup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/go-freya/freya/services/dns/internal/audit"
	"github.com/go-freya/freya/services/dns/internal/authz"
	"github.com/go-freya/freya/services/dns/internal/pdns"
	"github.com/go-freya/freya/services/dns/internal/repo"
	"github.com/go-freya/freya/services/dns/internal/store"
	"github.com/go-freya/freya/services/dns/internal/templates"
	"github.com/go-freya/freya/services/dns/internal/validate"
)

// SchemaVersion is the backup document version this service reads and writes.
const SchemaVersion = 1

// Restore modes.
const (
	ModeSkip      = "skip"
	ModeOverwrite = "overwrite"
)

// Errors (bad document → 422 validation_failed).
var (
	ErrBadSchema = errors.New("backup: invalid backup document")
	ErrTooLarge  = errors.New("backup: document exceeds the row limit")
)

// Limits.
const (
	// MaxRows bounds any single collection of an import (a parser guard).
	MaxRows = 20000
	// MaxBindBytes caps the total BIND text of one export (the import body
	// limit is 64 MiB); zones past the cap are exported without text.
	MaxBindBytes = 48 << 20
	maxDesc      = 1000
)

// Collection names (Result keys).
const (
	CZones        = "zones"
	CTemplates    = "templates"
	CSupermasters = "supermasters"
)

// placeholderZone validates template rows the way the templates API does.
const placeholderZone = "placeholder.example."

// ZoneRow is a zone's metadata plus its BIND text (reference only).
type ZoneRow struct {
	store.Zone
	Bind string `json:"bind,omitempty"`
}

// Backup is the export document.
type Backup struct {
	SchemaVersion int                 `json:"schema_version"`
	ExportedAt    time.Time           `json:"exported_at"`
	TenantID      string              `json:"tenant_id"`
	Zones         []ZoneRow           `json:"zones"`
	Templates     []store.Template    `json:"templates"`
	Supermasters  []store.Supermaster `json:"supermasters"`
}

// Options control an import.
type Options struct {
	Mode     string // skip | overwrite
	TenantID string // target tenant ("" = the caller's; another one is platform-admin only)
	Full     bool   // wipe the target's templates first (platform-admin only)
}

// Result reports what an import did.
type Result struct {
	TenantID      string         `json:"tenant_id"`
	Mode          string         `json:"mode"`
	Imported      map[string]int `json:"imported"`
	Skipped       map[string]int `json:"skipped"`
	MissingInPDNS []string       `json:"missing_in_pdns"`
}

// Deps wire the service; Store and PDNS are required.
type Deps struct {
	Store   repo.Store
	PDNS    pdns.Client
	Audit   audit.Recorder
	Checker authz.Checker
	Limits  validate.Limits // zero value = validate.DefaultLimits
	Log     *slog.Logger
	Now     func() time.Time
	NewID   func() string
}

// Service exports and imports tenant DNS metadata.
type Service struct{ d Deps }

// New builds the service.
func New(d Deps) *Service {
	if d.Log == nil {
		d.Log = slog.New(slog.DiscardHandler)
	}
	if d.Now == nil {
		d.Now = func() time.Time { return time.Now().UTC() }
	}
	if d.NewID == nil {
		d.NewID = store.NewID
	}
	if d.Limits == (validate.Limits{}) {
		d.Limits = validate.DefaultLimits
	}
	return &Service{d: d}
}

// guard checks backup:manage for the caller in its own tenant (the HTTP layer
// enforces the route permission of signed-in users when no Checker is wired;
// modules and the IPAM sync never hold backup:manage).
func (s *Service) guard(ctx context.Context, subj authz.Subjects) error {
	if subj.TenantID == "" {
		return fmt.Errorf("%w: tenant required", authz.ErrForbidden)
	}
	if subj.ActorKind == authz.ActorUser && s.d.Checker == nil {
		return nil
	}
	return authz.Require(ctx, s.d.Checker, subj, authz.BackupManage)
}

// target resolves and authorises the tenant an operation acts on.
func (s *Service) target(ctx context.Context, subj authz.Subjects, tenantID string) (string, error) {
	if err := s.guard(ctx, subj); err != nil {
		return "", err
	}
	if tenantID == "" || tenantID == subj.TenantID {
		return subj.TenantID, nil
	}
	if err := authz.RequirePlatformAdmin(subj); err != nil {
		return "", err
	}
	if !isUUID(tenantID) {
		return "", bad("tenant_id")
	}
	return tenantID, nil
}

func (s *Service) emit(ctx context.Context, subj authz.Subjects, tenant string, t audit.EventType, outcome, reason string, details map[string]any) {
	if tenant == "" {
		tenant = audit.NilTenant
	}
	audit.Emit(ctx, s.d.Audit, audit.Event{TenantID: tenant, EventType: t, ActorKind: audit.ActorOf(subj.ActorKind), ActorID: subj.ActorID(),
		SubjectKind: audit.SubjectBackup, SubjectID: string(t), Outcome: outcome, Reason: reason, Details: details})
}

func (s *Service) refused(ctx context.Context, subj authz.Subjects, t audit.EventType, err error) {
	if errors.Is(err, authz.ErrForbidden) {
		s.emit(ctx, subj, subj.TenantID, t, audit.OutcomeRefused, "forbidden", nil)
	}
}

// Export builds a backup of the caller's tenant (another tenant: platform
// admin). A zone whose BIND text cannot be read (PowerDNS down, zone gone) is
// exported without it.
func (s *Service) Export(ctx context.Context, subj authz.Subjects, tenantID string) (Backup, error) {
	t, err := s.target(ctx, subj, tenantID)
	if err != nil {
		s.refused(ctx, subj, audit.BackupExport, err)
		return Backup{}, err
	}
	b := Backup{SchemaVersion: SchemaVersion, ExportedAt: s.d.Now(), TenantID: t,
		Zones: []ZoneRow{}, Templates: []store.Template{}, Supermasters: []store.Supermaster{}}
	zs, err := s.d.Store.ZonesForTenant(ctx, t)
	if err != nil {
		return Backup{}, err
	}
	budget, noText := MaxBindBytes, 0
	for _, z := range zs {
		row := ZoneRow{Zone: z}
		if row.Masters == nil {
			row.Masters = []string{}
		}
		if row.Nameservers == nil {
			row.Nameservers = []string{}
		}
		text, err := s.d.PDNS.ExportZone(ctx, z.PDNSID)
		if err == nil && len(text) <= budget {
			row.Bind = text
			budget -= len(text)
		} else {
			noText++
		}
		b.Zones = append(b.Zones, row)
	}
	tpls, err := s.d.Store.AllTemplates(ctx, t)
	if err != nil {
		return Backup{}, err
	}
	for _, tp := range tpls {
		if tp.Records == nil {
			tp.Records = []store.TemplateRecord{}
		}
		b.Templates = append(b.Templates, tp)
	}
	sms, err := s.d.Store.AllSupermasters(ctx, t)
	if err != nil {
		return Backup{}, err
	}
	b.Supermasters = append(b.Supermasters, sms...)
	s.emit(ctx, subj, t, audit.BackupExport, audit.OutcomeOK, "", map[string]any{"zones": len(b.Zones), "templates": len(b.Templates),
		"supermasters": len(b.Supermasters), "zones_without_text": noText, "cross_tenant": t != subj.TenantID})
	return b, nil
}

var uuidRE = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func isUUID(s string) bool { return uuidRE.MatchString(s) }

func bad(what string) error { return fmt.Errorf("%w: %s", ErrBadSchema, what) }

func hasControl(s string) bool { return strings.IndexFunc(s, unicode.IsControl) >= 0 }

// Parse decodes a backup document (unknown fields refused, one JSON value)
// and validates it.
func Parse(raw []byte, l validate.Limits) (Backup, error) {
	var b Backup
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&b); err != nil {
		return Backup{}, bad("malformed JSON")
	}
	if dec.More() {
		return Backup{}, bad("trailing data")
	}
	if err := Validate(b, l); err != nil {
		return Backup{}, err
	}
	return b, nil
}

// Validate checks a parsed backup document before anything is written. Zone
// names must already be canonical (as exported), kinds/origins known, masters
// guarded, template records valid, supermaster addresses/nameservers valid.
func Validate(b Backup, l validate.Limits) error {
	if l == (validate.Limits{}) {
		l = validate.DefaultLimits
	}
	if b.SchemaVersion != SchemaVersion {
		return fmt.Errorf("%w: schema version %d", ErrBadSchema, b.SchemaVersion)
	}
	for name, n := range map[string]int{CZones: len(b.Zones), CTemplates: len(b.Templates), CSupermasters: len(b.Supermasters)} {
		if n > MaxRows {
			return fmt.Errorf("%w: %s has %d rows", ErrTooLarge, name, n)
		}
	}
	if b.TenantID != "" && !isUUID(b.TenantID) {
		return bad("tenant_id")
	}
	for _, z := range b.Zones {
		if !isUUID(z.ID) || (z.TemplateID != "" && !isUUID(z.TemplateID)) {
			return bad("zone id")
		}
		if n, err := validate.ZoneName(z.Name); err != nil || n != z.Name {
			return bad("zone name")
		}
		if !store.ValidKind(z.Kind) || (z.Origin != "" && !store.ValidOrigin(z.Origin)) {
			return bad("zone kind/origin")
		}
		if _, err := validate.Masters(z.Masters); err != nil {
			return bad("zone masters")
		}
		if utf8.RuneCountInString(z.Description) > maxDesc || len(z.Nameservers) > 16 {
			return bad("zone description/nameservers")
		}
		for _, ns := range z.Nameservers {
			if _, err := validate.Hostname(ns); err != nil {
				return bad("zone nameserver")
			}
		}
	}
	for _, t := range b.Templates {
		if !isUUID(t.ID) {
			return bad("template id")
		}
		name := strings.TrimSpace(t.Name)
		if name == "" || utf8.RuneCountInString(name) > templates.MaxName || hasControl(name) || utf8.RuneCountInString(t.Description) > templates.MaxDescription {
			return bad("template name/description")
		}
		if _, err := templates.ExpandRecords(l, placeholderZone, t.Records); err != nil {
			return bad("template records")
		}
	}
	for _, sm := range b.Supermasters {
		if !isUUID(sm.ID) {
			return bad("supermaster id")
		}
		if _, err := validate.IPGuard(sm.IP); err != nil {
			return bad("supermaster ip")
		}
		if _, err := validate.Hostname(sm.Nameserver); err != nil {
			return bad("supermaster nameserver")
		}
	}
	return nil
}

// remap gives every row a fresh id (cross-tenant restore); zone template
// references follow their template or are dropped.
func (s *Service) remap(b Backup) Backup {
	tpl := map[string]string{}
	out := b
	out.Templates = make([]store.Template, len(b.Templates))
	for i, t := range b.Templates {
		nid := s.d.NewID()
		tpl[t.ID] = nid
		t.ID = nid
		out.Templates[i] = t
	}
	out.Zones = make([]ZoneRow, len(b.Zones))
	for i, z := range b.Zones {
		z.ID = s.d.NewID()
		z.TemplateID = tpl[z.TemplateID]
		out.Zones[i] = z
	}
	out.Supermasters = make([]store.Supermaster, len(b.Supermasters))
	for i, sm := range b.Supermasters {
		sm.ID = s.d.NewID()
		out.Supermasters[i] = sm
	}
	return out
}

// importer carries one import's state.
type importer struct {
	s      *Service
	ctx    context.Context
	subj   authz.Subjects
	target string
	origin string
	mode   string
	res    Result
}

func (im *importer) imported(c string) { im.res.Imported[c]++ }
func (im *importer) skipped(c string)  { im.res.Skipped[c]++ }

// Import loads a backup into the target tenant (the caller's by default).
func (s *Service) Import(ctx context.Context, subj authz.Subjects, b Backup, opts Options) (Result, error) {
	res := Result{Imported: map[string]int{}, Skipped: map[string]int{}, MissingInPDNS: []string{}}
	tgt, err := s.target(ctx, subj, opts.TenantID)
	if err == nil && opts.Full {
		err = authz.RequirePlatformAdmin(subj)
	}
	if err != nil {
		s.refused(ctx, subj, audit.BackupImport, err)
		return res, err
	}
	if err := Validate(b, s.d.Limits); err != nil {
		return res, err
	}
	res.TenantID, res.Mode = tgt, ModeSkip
	if opts.Mode == ModeOverwrite {
		res.Mode = ModeOverwrite
	}
	origin := b.TenantID
	if origin != tgt {
		b = s.remap(b)
	}
	im := &importer{s: s, ctx: ctx, subj: subj, target: tgt, origin: origin, mode: res.Mode, res: res}
	err = im.run(b, opts.Full)
	outcome, reason := audit.OutcomeOK, ""
	if err != nil {
		outcome, reason = audit.OutcomeError, "import failed"
	}
	s.emit(ctx, subj, tgt, audit.BackupImport, outcome, reason, map[string]any{"mode": im.res.Mode, "full": opts.Full,
		"cross_tenant": tgt != subj.TenantID, "zones": im.res.Imported[CZones], "templates": im.res.Imported[CTemplates],
		"supermasters": im.res.Imported[CSupermasters], "missing_in_pdns": len(im.res.MissingInPDNS)})
	return im.res, err
}

func (im *importer) run(b Backup, full bool) error {
	if full {
		if err := im.wipeTemplates(); err != nil {
			return err
		}
	}
	for _, t := range b.Templates {
		if err := im.template(t); err != nil {
			return err
		}
	}
	if len(b.Zones) > 0 {
		names, err := im.s.d.PDNS.ListZoneNames(im.ctx)
		if err != nil {
			return err
		}
		onServer := map[string]bool{}
		for _, n := range names {
			onServer[strings.ToLower(n)] = true
		}
		for _, z := range b.Zones {
			if err := im.zone(z, onServer); err != nil {
				return err
			}
		}
	}
	if len(b.Supermasters) > 0 {
		if !im.subj.IsPlatformAdmin() {
			im.res.Skipped[CSupermasters] += len(b.Supermasters)
			return nil
		}
		live, err := im.s.d.PDNS.ListSupermasters(im.ctx)
		if err != nil {
			return err
		}
		for _, sm := range b.Supermasters {
			if err := im.supermaster(sm, live); err != nil {
				return err
			}
		}
	}
	return nil
}

func (im *importer) wipeTemplates() error {
	list, err := im.s.d.Store.AllTemplates(im.ctx, im.target)
	if err != nil {
		return err
	}
	for _, t := range list {
		if err := im.s.d.Store.DeleteTemplate(im.ctx, im.target, t.ID); err != nil && !errors.Is(err, repo.ErrNotFound) {
			return err
		}
	}
	return nil
}

func (im *importer) template(t store.Template) error {
	st, ctx := im.s.d.Store, im.ctx
	t.TenantID = im.target
	t.Name, t.Description = strings.TrimSpace(t.Name), strings.TrimSpace(t.Description)
	if t.Records == nil {
		t.Records = []store.TemplateRecord{}
	}
	_, err := st.GetTemplate(ctx, im.target, t.ID)
	switch {
	case err == nil:
		if im.mode != ModeOverwrite {
			im.skipped(CTemplates)
			return nil
		}
		t.UpdatedAt = im.s.d.Now()
		_, err = st.UpdateTemplate(ctx, t)
	case errors.Is(err, repo.ErrNotFound):
		if t.CreatedAt.IsZero() {
			t.CreatedAt = im.s.d.Now()
		}
		t.UpdatedAt = im.s.d.Now()
		err = st.CreateTemplate(ctx, t)
	default:
		return err
	}
	switch {
	case err == nil:
		im.imported(CTemplates)
	case errors.Is(err, repo.ErrConflict), errors.Is(err, repo.ErrNotFound):
		im.skipped(CTemplates)
	default:
		return err
	}
	return nil
}

// ownAccount reports whether a PowerDNS account may be adopted by the target:
// unset, the target, or (a cross-tenant restore) the backup's origin tenant.
func (im *importer) ownAccount(account string) bool {
	return account == "" || account == im.target || (im.origin != "" && account == im.origin)
}

func (im *importer) zone(row ZoneRow, onServer map[string]bool) error {
	st, pd, ctx := im.s.d.Store, im.s.d.PDNS, im.ctx
	z := row.Zone
	z.TenantID = im.target
	if z.Origin == "" {
		z.Origin = store.OriginManual
	}
	local, err := st.GetZoneByName(ctx, im.target, z.Name)
	switch {
	case err == nil:
		if im.mode != ModeOverwrite {
			im.skipped(CZones)
			return nil
		}
		local.Description = z.Description
		local.UpdatedAt = im.s.d.Now()
		if _, err := st.UpdateZone(ctx, local); err != nil {
			return err
		}
		im.imported(CZones)
		return nil
	case !errors.Is(err, repo.ErrNotFound):
		return err
	}
	if !onServer[z.Name] {
		im.res.MissingInPDNS = append(im.res.MissingInPDNS, z.Name)
		return nil
	}
	if taken, err := st.ZoneConflict(ctx, im.target, z.Name); err != nil {
		return err
	} else if taken {
		im.skipped(CZones) // owned (or overlapped) by another tenant; never revealed
		return nil
	}
	live, err := pd.GetZone(ctx, z.Name)
	if errors.Is(err, pdns.ErrNotFound) {
		im.res.MissingInPDNS = append(im.res.MissingInPDNS, z.Name)
		return nil
	}
	if err != nil {
		return err
	}
	if !im.ownAccount(live.Account) {
		im.skipped(CZones)
		return nil
	}
	// The local row mirrors the live zone; the backup contributes the
	// description, template link and origin.
	z.PDNSID = z.Name
	if live.ID != "" {
		z.PDNSID = live.ID
	}
	if k := store.KindFromPDNS(live.Kind); k != "" {
		z.Kind = k
	}
	z.Masters = append([]string{}, live.Masters...)
	z.DNSSEC = live.DNSSEC
	if z.Nameservers == nil {
		z.Nameservers = []string{}
	}
	if z.CreatedAt.IsZero() {
		z.CreatedAt = im.s.d.Now()
	}
	z.UpdatedAt = im.s.d.Now()
	if z.TemplateID != "" {
		if _, err := st.GetTemplate(ctx, im.target, z.TemplateID); err != nil {
			z.TemplateID = ""
		}
	}
	if err := st.CreateZone(ctx, z); err != nil {
		if errors.Is(err, repo.ErrConflict) {
			im.skipped(CZones)
			return nil
		}
		return err
	}
	if live.Account != im.target {
		meta := pdns.Zone{Kind: live.Kind, Masters: live.Masters, DNSSEC: live.DNSSEC, Account: im.target}
		if err := pd.UpdateZoneMetadata(ctx, z.PDNSID, meta); err != nil {
			im.s.d.Log.WarnContext(ctx, "backup import: PowerDNS account update failed", "zone", z.Name, "err", err)
		}
	}
	im.imported(CZones)
	return nil
}

func (im *importer) supermaster(sm store.Supermaster, live []pdns.Supermaster) error {
	st, pd, ctx := im.s.d.Store, im.s.d.PDNS, im.ctx
	sm.TenantID = im.target
	ip, _ := validate.IPGuard(sm.IP)
	ns, _ := validate.Hostname(sm.Nameserver)
	sm.IP, sm.Nameserver = ip.String(), ns
	if sm.CreatedAt.IsZero() {
		sm.CreatedAt = im.s.d.Now()
	}
	if _, err := st.GetSupermaster(ctx, im.target, sm.ID); err == nil {
		im.skipped(CSupermasters) // no update: an entry is immutable
		return nil
	} else if !errors.Is(err, repo.ErrNotFound) {
		return err
	}
	pdnsNS := strings.TrimSuffix(ns, ".")
	onServer := false
	for _, e := range live {
		if e.IP == sm.IP && strings.TrimSuffix(e.Nameserver, ".") == pdnsNS {
			if !im.ownAccount(e.Account) {
				im.skipped(CSupermasters)
				return nil
			}
			onServer = true
		}
	}
	if !onServer {
		if err := pd.CreateSupermaster(ctx, pdns.Supermaster{IP: sm.IP, Nameserver: pdnsNS, Account: im.target}); err != nil {
			if errors.Is(err, pdns.ErrConflict) {
				im.skipped(CSupermasters)
				return nil
			}
			return err
		}
	}
	if err := st.CreateSupermaster(ctx, sm); err != nil {
		if !onServer {
			if derr := pd.DeleteSupermaster(ctx, sm.IP, pdnsNS); derr != nil && !errors.Is(derr, pdns.ErrNotFound) {
				im.s.d.Log.ErrorContext(ctx, "backup import: compensating supermaster delete failed", "err", derr)
			}
		}
		if errors.Is(err, repo.ErrConflict) {
			im.skipped(CSupermasters)
			return nil
		}
		return err
	}
	im.imported(CSupermasters)
	return nil
}
