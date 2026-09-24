package httpapi

import (
	"errors"
	"net/http"
	"os"

	"github.com/go-tangra/go-tangra-dns/v4/internal/stream"
)

// registerStream mounts GET /stream: a per-signed-in-user SSE stream of the
// tenant's dns.* events relayed from the platform event bus (closed by the
// module at 290 s; the client resumes with last_id).
func (s *Server) registerStream(hub *stream.Hub) {
	instance, _ := os.Hostname()
	s.MustHandle("GET", Prefix+"/stream", func(w http.ResponseWriter, r *http.Request) {
		subj, err := Subjects(r)
		if err != nil {
			Fail(w, r, s.log, err)
			return
		}
		sub, err := hub.Subscribe(r.Context(), subj.TenantID, subj.UserID, r.URL.Query().Get("last_id"))
		if err != nil {
			if errors.Is(err, stream.ErrTooMany) {
				Fail(w, r, nil, ErrRateLimited)
				return
			}
			Fail(w, r, s.log, err)
			return
		}
		stream.ServeSSE(w, r, sub, instance, stream.Heartbeat, stream.MaxAge)
	})
}
