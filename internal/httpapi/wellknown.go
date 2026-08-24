package httpapi

import (
	"context"
	"net/http"
	"time"
)

func (s *Server) handleJWKS(w http.ResponseWriter, r *http.Request) {
	set, err := s.signer.JWKS()
	if err != nil {
		s.internal(w, r, "build jwks", err)
		return
	}
	// Keys are stable and both current and next are always published, so this
	// can be cached hard. SDKs must not block a request on fetching it.
	w.Header().Set("Cache-Control", "public, max-age=3600, stale-while-revalidate=86400")
	w.Header().Set("Content-Type", "application/jwk-set+json")
	writeJSONNoStore(w, http.StatusOK, set)
}

// handleHealth checks real database connectivity. A liveness probe that only
// proves the process is running will happily keep a broken instance in rotation.
func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Second)
	defer cancel()

	if err := s.db.Health(ctx); err != nil {
		s.log.ErrorContext(ctx, "health check failed", "err", err)
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{
			"status": "unhealthy", "database": "unreachable",
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok", "database": "ok"})
}
