package httpapi

import (
	"context"
	"crypto/subtle"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/yash-sharma-dev/authsvc/internal/store"
	"github.com/yash-sharma-dev/authsvc/internal/token"
)

type ctxKey int

const claimsKey ctxKey = iota

// ClaimsFrom returns the verified access-token claims attached by requireUser.
func ClaimsFrom(ctx context.Context) (*token.Claims, bool) {
	c, ok := ctx.Value(claimsKey).(*token.Claims)
	return c, ok
}

// requireUser verifies the bearer access token and confirms the session behind
// it is still live. Verifying the signature alone is not enough: logout and
// reuse-detection revoke sessions, and an unexpired token from a revoked session
// must stop working immediately.
func (s *Server) requireUser(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		raw := bearer(r)
		if raw == "" {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}

		claims, err := s.verifyAnyAudience(raw)
		if err != nil {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}

		if claims.SessionID != "" {
			sess, err := s.db.SessionByID(r.Context(), claims.SessionID)
			switch {
			case errors.Is(err, store.ErrNotFound):
				writeErr(w, http.StatusUnauthorized, "unauthorized", "session no longer exists")
				return
			case err != nil:
				s.internal(w, r, "session lookup", err)
				return
			case sess.RevokedAt != nil:
				writeErr(w, http.StatusUnauthorized, "session_revoked", "session has been revoked")
				return
			}
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		next(w, r.WithContext(ctx))
	}
}

// verifyAnyAudience validates the token against the audience it carries. The
// audience is bound at mint time to a registered client, so this checks the
// signature and issuer while still confirming the client exists.
func (s *Server) verifyAnyAudience(raw string) (*token.Claims, error) {
	unverified, err := token.PeekAudience(raw)
	if err != nil {
		return nil, err
	}
	return s.signer.VerifyAccess(raw, unverified)
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		key := bearer(r)
		if key == "" {
			key = r.Header.Get("X-Admin-Key")
		}
		if subtle.ConstantTimeCompare([]byte(key), []byte(s.opts.AdminAPIKey)) != 1 {
			writeErr(w, http.StatusUnauthorized, "unauthorized", "invalid admin key")
			return
		}
		next(w, r)
	}
}

func bearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

// limit applies a fixed-window rate limit and writes 429 when exceeded.
// A failure to reach the limiter must not fail open on auth endpoints.
func (s *Server) limit(w http.ResponseWriter, r *http.Request, bucket string, n int, window time.Duration) bool {
	ok, err := s.db.Allow(r.Context(), bucket, n, window)
	if err != nil {
		s.internal(w, r, "rate limiter", err)
		return false
	}
	if !ok {
		w.Header().Set("Retry-After", "60")
		writeErr(w, http.StatusTooManyRequests, "rate_limited", "too many attempts, try again later")
		return false
	}
	return true
}

func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func (s *Server) recoverer(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if v := recover(); v != nil {
				s.log.Error("panic in handler", "panic", v, "path", r.URL.Path)
				writeErr(w, http.StatusInternalServerError, "internal", "something went wrong")
			}
		}()
		next.ServeHTTP(w, r)
	})
}

type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(c int) {
	w.status = c
	w.ResponseWriter.WriteHeader(c)
}

func (s *Server) accessLog(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: 200}
		next.ServeHTTP(sw, r)
		s.log.Info("request",
			"method", r.Method, "path", r.URL.Path, "status", sw.status,
			"dur_ms", time.Since(start).Milliseconds(), "ip", clientIP(r))
	})
}
