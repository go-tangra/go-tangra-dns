package httpapi

import (
	"net/http"

	"github.com/go-tangra/go-tangra-dns/v4/internal/backup"
	"github.com/go-tangra/go-tangra-dns/v4/internal/stream"

	"github.com/go-tangra/go-tangra-dns/v4/internal/dashboard"
	"github.com/go-tangra/go-tangra-dns/v4/internal/dnsconf"
	"github.com/go-tangra/go-tangra-dns/v4/internal/records"
	"github.com/go-tangra/go-tangra-dns/v4/internal/supermasters"
	"github.com/go-tangra/go-tangra-dns/v4/internal/templates"
	"github.com/go-tangra/go-tangra-dns/v4/internal/validate"
	"github.com/go-tangra/go-tangra-dns/v4/internal/zones"
)

// Prefix of the browser API.
const Prefix = "/api/dns/v1"

// Deps wire the HTTP handlers. Every field is optional: a route whose service
// is not wired answers 501 not_implemented. The domain services of the user
// stories (zones, records, templates, supermasters, configuration, dashboard,
// backup, stream) are added here as they land.
type Deps struct {
	Health  func() map[string]string // component status for /health
	Zones   *zones.Service           // US1: zones CRUD
	Records *records.Service         // US1: record sets of a zone

	Templates    *templates.Service    // US3: zone templates
	Supermasters *supermasters.Service // US3: supermasters (create/delete platform-admin)

	Config    *dnsconf.Service   // US5: server configuration (platform-admin)
	Dashboard *dashboard.Service // US6: curated metrics dashboard

	Backup *backup.Service // tenant export/import (FR-017)
	// ParseBackup decodes and validates an import document (nil = backup.Parse
	// with the default record limits).
	ParseBackup func([]byte) (backup.Backup, error)
	Hub         *stream.Hub // SSE relay of the tenant's dns.* events
}

// Register mounts the handlers of every wired dependency.
func (s *Server) Register(d Deps) {
	s.MustHandle("GET", Prefix+"/health", func(w http.ResponseWriter, _ *http.Request) {
		out := map[string]any{"status": "ok"}
		if d.Health != nil {
			comps := d.Health()
			for _, v := range comps {
				if v != "ok" {
					out["status"] = "degraded"
				}
			}
			out["components"] = comps
		}
		WriteJSON(w, http.StatusOK, out)
	})
	if d.Zones != nil {
		s.registerZones(d.Zones)
	}
	if d.Records != nil {
		s.registerRecords(d.Records)
	}
	if d.Templates != nil {
		s.registerTemplates(d.Templates)
	}
	if d.Supermasters != nil {
		s.registerSupermasters(d.Supermasters)
	}
	if d.Config != nil {
		s.registerConfig(d.Config)
	}
	if d.Dashboard != nil {
		s.registerDashboard(d.Dashboard)
	}
	if d.Backup != nil {
		parse := d.ParseBackup
		if parse == nil {
			parse = func(raw []byte) (backup.Backup, error) { return backup.Parse(raw, validate.Limits{}) }
		}
		s.registerBackup(d.Backup, parse)
	}
	if d.Hub != nil {
		s.registerStream(d.Hub)
	}
}
