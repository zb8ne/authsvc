package httpapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/zb8ne/authsvc/internal/notify"
	"github.com/zb8ne/authsvc/internal/password"
	"github.com/zb8ne/authsvc/internal/store"
)

// dummyHash is verified against when no user exists, so a login attempt costs
// the same whether or not the account is real. Without this, response timing
// enumerates accounts.
var dummyHash, _ = password.Hash("this password matches nothing at all")

type registerReq struct {
	ClientID string `json:"client_id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	var req registerReq
	if !decode(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if !validEmail(email) {
		writeErr(w, http.StatusBadRequest, "invalid_email", "that does not look like an email address")
		return
	}
	if len(req.Password) < MinPasswordLen {
		writeErr(w, http.StatusBadRequest, "weak_password",
			"password must be at least 10 characters")
		return
	}
	if !s.limit(w, r, "register:ip:"+clientIP(r), 10, time.Hour) {
		return
	}

	client, ok := s.lookupClient(w, r, req.ClientID)
	if !ok {
		return
	}

	hash, err := password.Hash(req.Password)
	if err != nil {
		s.internal(w, r, "hash password", err)
		return
	}

	u, err := s.db.CreateUser(r.Context(), email, &hash)
	if err != nil {
		// Do not confirm that the address is taken. Tell the existing owner
		// instead, out of band, and give the caller the same shape of answer.
		if existing, e := s.db.UserByEmail(r.Context(), email); e == nil {
			s.sendEmailVerification(r.Context(), existing)
			writeJSON(w, http.StatusAccepted, map[string]string{
				"status": "verification_sent",
			})
			return
		}
		s.internal(w, r, "create user", err)
		return
	}

	s.sendEmailVerification(r.Context(), u)

	resp, err := s.issueSession(r.Context(), r, w, u, client)
	if err != nil {
		s.internal(w, r, "issue session", err)
		return
	}
	writeJSON(w, http.StatusCreated, resp)
}

type loginReq struct {
	ClientID string `json:"client_id"`
	Email    string `json:"email"`
	Password string `json:"password"`
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	var req loginReq
	if !decode(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)

	// Per-IP catches spraying; per-identifier catches a distributed attack on
	// one account. Both are needed.
	if !s.limit(w, r, "login:ip:"+clientIP(r), 30, 15*time.Minute) {
		return
	}
	if !s.limit(w, r, "login:id:"+email, 10, 15*time.Minute) {
		return
	}

	client, ok := s.lookupClient(w, r, req.ClientID)
	if !ok {
		return
	}

	u, err := s.db.UserByEmail(r.Context(), email)
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internal(w, r, "lookup user", err)
		return
	}

	stored := dummyHash
	if u != nil && u.PasswordHash != nil {
		stored = *u.PasswordHash
	}
	match, verr := password.Verify(stored, req.Password)
	if verr != nil {
		s.internal(w, r, "verify password", verr)
		return
	}

	if u == nil || u.PasswordHash == nil || !match {
		writeErr(w, http.StatusUnauthorized, "invalid_credentials", "email or password is incorrect")
		return
	}
	if u.DisabledAt != nil {
		writeErr(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}

	resp, err := s.issueSession(r.Context(), r, w, u, client)
	if err != nil {
		s.internal(w, r, "issue session", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

type tokenOnlyReq struct {
	Token string `json:"token"`
}

func (s *Server) handleEmailVerify(w http.ResponseWriter, r *http.Request) {
	var req tokenOnlyReq
	if !decode(w, r, &req) {
		return
	}
	if !s.limit(w, r, "verify:ip:"+clientIP(r), 30, time.Hour) {
		return
	}

	userID, err := s.db.ConsumeToken(r.Context(), store.PurposeEmailVerify, req.Token)
	if errors.Is(err, store.ErrCodeInvalid) {
		writeErr(w, http.StatusBadRequest, "invalid_token", "this link is invalid or has expired")
		return
	}
	if err != nil {
		s.internal(w, r, "consume verify token", err)
		return
	}
	if err := s.db.MarkEmailVerified(r.Context(), userID); err != nil {
		s.internal(w, r, "mark verified", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"email_verified": true})
}

type forgotReq struct {
	Email string `json:"email"`
}

func (s *Server) handlePasswordForgot(w http.ResponseWriter, r *http.Request) {
	var req forgotReq
	if !decode(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)

	if !s.limit(w, r, "forgot:ip:"+clientIP(r), 10, time.Hour) {
		return
	}
	if !s.limit(w, r, "forgot:id:"+email, 3, time.Hour) {
		return
	}

	// Always answer identically, whether or not the account exists.
	defer writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent_if_registered"})

	u, err := s.db.UserByEmail(r.Context(), email)
	if err != nil {
		return
	}
	tok, err := store.NewOpaqueToken()
	if err != nil {
		s.log.ErrorContext(r.Context(), "mint reset token", "err", err)
		return
	}
	if err := s.db.IssueCode(r.Context(), u.ID, store.PurposePasswordReset, tok, PasswordResetTTL); err != nil {
		s.log.ErrorContext(r.Context(), "issue reset token", "err", err)
		return
	}
	if err := s.sender.SendCode(r.Context(), notify.Email(u.Email), notify.PurposePasswordReset, tok); err != nil {
		s.log.ErrorContext(r.Context(), "send reset email", "err", err)
	}
}

type resetReq struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

func (s *Server) handlePasswordReset(w http.ResponseWriter, r *http.Request) {
	var req resetReq
	if !decode(w, r, &req) {
		return
	}
	if len(req.NewPassword) < MinPasswordLen {
		writeErr(w, http.StatusBadRequest, "weak_password", "password must be at least 10 characters")
		return
	}
	if !s.limit(w, r, "reset:ip:"+clientIP(r), 20, time.Hour) {
		return
	}

	userID, err := s.db.ConsumeToken(r.Context(), store.PurposePasswordReset, req.Token)
	if errors.Is(err, store.ErrCodeInvalid) {
		writeErr(w, http.StatusBadRequest, "invalid_token", "this link is invalid or has expired")
		return
	}
	if err != nil {
		s.internal(w, r, "consume reset token", err)
		return
	}

	hash, err := password.Hash(req.NewPassword)
	if err != nil {
		s.internal(w, r, "hash password", err)
		return
	}
	if err := s.db.SetPasswordHash(r.Context(), userID, hash); err != nil {
		s.internal(w, r, "set password", err)
		return
	}

	// A reset is the remedy for a compromised account, so every existing
	// session must die with it — otherwise the attacker keeps their access.
	if err := s.db.RevokeAllForUser(r.Context(), userID); err != nil {
		s.internal(w, r, "revoke sessions after reset", err)
		return
	}
	s.clearRefreshCookie(w)
	writeJSON(w, http.StatusOK, map[string]bool{"password_reset": true})
}

// sendEmailVerification delivers the verification link in the background.
//
// It must not run inline: the user does not need the email to have been
// accepted by the provider before their account exists, and a slow or
// unreachable mail provider would otherwise stall — or hang — registration.
// Delivery failures are logged, not surfaced.
func (s *Server) sendEmailVerification(ctx context.Context, u *store.User) {
	if u.EmailVerified() {
		return
	}

	// Detach from the request context, which is cancelled the moment the
	// response is written, but keep a hard ceiling of our own.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), 30*time.Second)

	go func() {
		defer cancel()
		s.deliverEmailVerification(ctx, u)
	}()
}

func (s *Server) deliverEmailVerification(ctx context.Context, u *store.User) {
	tok, err := store.NewOpaqueToken()
	if err != nil {
		s.log.ErrorContext(ctx, "mint verify token", "err", err)
		return
	}
	if err := s.db.IssueCode(ctx, u.ID, store.PurposeEmailVerify, tok, EmailVerifyTTL); err != nil {
		s.log.ErrorContext(ctx, "issue verify token", "err", err)
		return
	}
	if err := s.sender.SendCode(ctx, notify.Email(u.Email), notify.PurposeEmailVerify, tok); err != nil {
		s.log.ErrorContext(ctx, "send verify email", "err", err, "user_id", u.ID)
	}
}

func (s *Server) lookupClient(w http.ResponseWriter, r *http.Request, id string) (*store.Client, bool) {
	if id == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "client_id is required")
		return nil, false
	}
	c, err := s.db.ClientByID(r.Context(), id)
	if errors.Is(err, store.ErrNotFound) {
		writeErr(w, http.StatusBadRequest, "unknown_client", "unknown client_id")
		return nil, false
	}
	if err != nil {
		s.internal(w, r, "lookup client", err)
		return nil, false
	}
	return c, true
}
