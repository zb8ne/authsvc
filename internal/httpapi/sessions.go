package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/zb8ne/authsvc/internal/store"
)

func (s *Server) handleRefresh(w http.ResponseWriter, r *http.Request) {
	tok := s.refreshTokenFrom(r)
	if tok == "" {
		writeErr(w, http.StatusUnauthorized, "unauthorized", "no refresh token")
		return
	}
	if !s.limit(w, r, "refresh:ip:"+clientIP(r), 120, time.Hour) {
		return
	}

	iss, err := s.db.Rotate(r.Context(), tok, store.SessionMeta{
		UserAgent: r.UserAgent(), IP: clientIP(r),
	})
	switch {
	case errors.Is(err, store.ErrTokenReuse):
		// The family is already revoked by Rotate. Say so plainly: the client
		// cannot recover, and the user must log in again.
		s.log.WarnContext(r.Context(), "refresh token reuse detected, family revoked",
			"ip", clientIP(r), "ua", r.UserAgent())
		s.clearRefreshCookie(w)
		writeErr(w, http.StatusUnauthorized, "token_reuse",
			"this session has been revoked; sign in again")
		return
	case errors.Is(err, store.ErrNotFound):
		s.clearRefreshCookie(w)
		writeErr(w, http.StatusUnauthorized, "unauthorized", "refresh token is invalid or expired")
		return
	case err != nil:
		s.internal(w, r, "rotate refresh token", err)
		return
	}

	u, err := s.db.UserByID(r.Context(), iss.Session.UserID)
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	if u.DisabledAt != nil {
		_ = s.db.RevokeAllForUser(r.Context(), u.ID)
		s.clearRefreshCookie(w)
		writeErr(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}

	client, err := s.db.ClientByID(r.Context(), iss.Session.ClientID)
	if err != nil {
		s.internal(w, r, "load client", err)
		return
	}

	resp, err := s.respondWithTokens(w, u, client.Audience, iss)
	if err != nil {
		s.internal(w, r, "sign access token", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

// refreshTokenFrom prefers the httpOnly cookie and falls back to a JSON body,
// which is what server-side SDK callers use.
func (s *Server) refreshTokenFrom(r *http.Request) string {
	if c, err := r.Cookie(RefreshCookie); err == nil && c.Value != "" {
		return c.Value
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
	}
	r.Body = http.MaxBytesReader(nil, r.Body, maxBody)
	_ = decodeQuiet(r, &body)
	return body.RefreshToken
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	if claims.SessionID != "" {
		sess, err := s.db.SessionByID(r.Context(), claims.SessionID)
		if err == nil {
			// Revoke the family, not the single row: an older copy of the
			// lineage would otherwise still be able to refresh.
			if err := s.db.RevokeFamily(r.Context(), sess.FamilyID); err != nil {
				s.internal(w, r, "revoke family", err)
				return
			}
		}
	}
	s.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleLogoutAll(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	if err := s.db.RevokeAllForUser(r.Context(), claims.Subject); err != nil {
		s.internal(w, r, "revoke all", err)
		return
	}
	s.clearRefreshCookie(w)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleMe(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	u, err := s.db.UserByID(r.Context(), claims.Subject)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "user not found")
		return
	}
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	writeJSON(w, http.StatusOK, userJSON(u))
}

type sessionView struct {
	ID        string    `json:"id"`
	ClientID  string    `json:"client_id"`
	IssuedAt  time.Time `json:"issued_at"`
	ExpiresAt time.Time `json:"expires_at"`
	UserAgent string    `json:"user_agent,omitempty"`
	IP        string    `json:"ip,omitempty"`
	Current   bool      `json:"current"`
}

func (s *Server) handleListSessions(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	rows, err := s.db.ActiveSessionsForUser(r.Context(), claims.Subject)
	if err != nil {
		s.internal(w, r, "list sessions", err)
		return
	}
	out := make([]sessionView, 0, len(rows))
	for _, s2 := range rows {
		out = append(out, sessionView{
			ID: s2.ID, ClientID: s2.ClientID, IssuedAt: s2.IssuedAt, ExpiresAt: s2.ExpiresAt,
			UserAgent: s2.UserAgent, IP: s2.IP, Current: s2.ID == claims.SessionID,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"sessions": out})
}

func (s *Server) handleDeleteSession(w http.ResponseWriter, r *http.Request) {
	claims, _ := ClaimsFrom(r.Context())
	id := r.PathValue("id")

	sess, err := s.db.SessionByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusNotFound, "not_found", "no such session")
		return
	}
	if err != nil {
		s.internal(w, r, "load session", err)
		return
	}
	// Never let one user revoke another's session, and do not reveal that the
	// id exists at all.
	if sess.UserID != claims.Subject {
		writeErr(w, http.StatusNotFound, "not_found", "no such session")
		return
	}
	if err := s.db.RevokeFamily(r.Context(), sess.FamilyID); err != nil {
		s.internal(w, r, "revoke family", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
