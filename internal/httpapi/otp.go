package httpapi

import (
	"errors"
	"net/http"
	"time"

	"github.com/yash-sharma-dev/authsvc/internal/notify"
	"github.com/yash-sharma-dev/authsvc/internal/store"
)

// otpIdentifier scopes a code to one client. A code issued for "dayflow" must
// not be redeemable for a token whose audience is another app.
func otpIdentifier(clientID, email string) string { return clientID + "|" + email }

type otpRequestReq struct {
	ClientID string `json:"client_id"`
	Email    string `json:"email"`
}

func (s *Server) handleOTPRequest(w http.ResponseWriter, r *http.Request) {
	var req otpRequestReq
	if !decode(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if !validEmail(email) {
		writeErr(w, http.StatusBadRequest, "invalid_email", "that does not look like an email address")
		return
	}
	if !s.limit(w, r, "otp:ip:"+clientIP(r), 20, time.Hour) {
		return
	}
	if !s.limit(w, r, "otp:id:"+email, 5, time.Hour) {
		return
	}
	client, ok := s.lookupClient(w, r, req.ClientID)
	if !ok {
		return
	}

	code, err := store.NewNumericCode(6)
	if err != nil {
		s.internal(w, r, "mint otp", err)
		return
	}
	if err := s.db.IssueCode(r.Context(), otpIdentifier(client.ID, email), store.PurposeLoginOTP, code, OTPTTL); err != nil {
		s.internal(w, r, "issue otp", err)
		return
	}
	if err := s.sender.SendCode(r.Context(), notify.Email(email), notify.PurposeLoginOTP, code); err != nil {
		s.log.ErrorContext(r.Context(), "send otp", "err", err)
		writeErr(w, http.StatusBadGateway, "delivery_failed", "could not send the code, try again")
		return
	}
	// Same answer whether or not the address has an account.
	writeJSON(w, http.StatusAccepted, map[string]string{"status": "sent"})
}

type otpVerifyReq struct {
	ClientID string `json:"client_id"`
	Email    string `json:"email"`
	Code     string `json:"code"`
}

func (s *Server) handleOTPVerify(w http.ResponseWriter, r *http.Request) {
	var req otpVerifyReq
	if !decode(w, r, &req) {
		return
	}
	email := normalizeEmail(req.Email)
	if !s.limit(w, r, "otpv:ip:"+clientIP(r), 30, time.Hour) {
		return
	}
	client, ok := s.lookupClient(w, r, req.ClientID)
	if !ok {
		return
	}

	err := s.db.ConsumeCode(r.Context(), otpIdentifier(client.ID, email), store.PurposeLoginOTP, req.Code)
	switch {
	case errors.Is(err, store.ErrCodeAttempts):
		writeErr(w, http.StatusTooManyRequests, "too_many_attempts", "too many attempts, request a new code")
		return
	case errors.Is(err, store.ErrCodeInvalid):
		writeErr(w, http.StatusUnauthorized, "invalid_code", "that code is invalid or has expired")
		return
	case err != nil:
		s.internal(w, r, "consume otp", err)
		return
	}

	// Proving control of an inbox both creates the account and verifies it.
	u, err := s.db.UserByEmail(r.Context(), email)
	if errors.Is(err, store.ErrNotFound) {
		u, err = s.db.CreateUser(r.Context(), email, nil)
	}
	if err != nil {
		s.internal(w, r, "resolve otp user", err)
		return
	}
	if !u.EmailVerified() {
		if err := s.db.MarkEmailVerified(r.Context(), u.ID); err != nil {
			s.internal(w, r, "mark verified", err)
			return
		}
		u, err = s.db.UserByID(r.Context(), u.ID)
		if err != nil {
			s.internal(w, r, "reload user", err)
			return
		}
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
