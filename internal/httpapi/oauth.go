package httpapi

import (
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/zb8ne/authsvc/internal/linking"
	"github.com/zb8ne/authsvc/internal/oauth"
	"github.com/zb8ne/authsvc/internal/password"
	"github.com/zb8ne/authsvc/internal/store"
)

// handleOAuthStart begins a login. The originating app is recorded server-side
// against a random state value; the callback recovers it from there.
func (s *Server) handleOAuthStart(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.provider(w, r)
	if !ok {
		return
	}
	if !s.limit(w, r, "oauth:ip:"+clientIP(r), 60, time.Hour) {
		return
	}

	q := r.URL.Query()
	client, ok := s.lookupClient(w, r, q.Get("client_id"))
	if !ok {
		return
	}

	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	// Exact match against the registered list. Anything looser here is an open
	// redirect that hands the auth code to whoever asked for it.
	if !client.AllowsRedirect(redirectURI) {
		writeErr(w, http.StatusBadRequest, "invalid_redirect_uri",
			"redirect_uri is not registered for this client")
		return
	}

	s.beginFlow(w, r, provider, client, redirectURI, q.Get("state"), nil)
}

// handleLinkStart begins an account-linking round trip for a signed-in user.
func (s *Server) handleLinkStart(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.provider(w, r)
	if !ok {
		return
	}
	claims, _ := ClaimsFrom(r.Context())

	q := r.URL.Query()
	client, ok := s.lookupClient(w, r, q.Get("client_id"))
	if !ok {
		return
	}
	redirectURI := q.Get("redirect_uri")
	if redirectURI == "" && len(client.RedirectURIs) == 1 {
		redirectURI = client.RedirectURIs[0]
	}
	if !client.AllowsRedirect(redirectURI) {
		writeErr(w, http.StatusBadRequest, "invalid_redirect_uri",
			"redirect_uri is not registered for this client")
		return
	}

	userID := claims.Subject
	s.beginFlow(w, r, provider, client, redirectURI, q.Get("state"), &userID)
}

func (s *Server) beginFlow(w http.ResponseWriter, r *http.Request, p oauth.Provider,
	client *store.Client, redirectURI, appState string, linkUserID *string) {

	state, err := store.NewOpaqueToken()
	if err != nil {
		s.internal(w, r, "mint state", err)
		return
	}
	verifier, err := oauth.NewVerifier()
	if err != nil {
		s.internal(w, r, "mint pkce verifier", err)
		return
	}

	if err := s.db.CreateOAuthFlow(r.Context(), state, store.OAuthFlow{
		Provider: p.Name(), ClientID: client.ID, RedirectURI: redirectURI,
		AppState: appState, CodeVerifier: verifier, LinkUserID: linkUserID,
	}); err != nil {
		s.internal(w, r, "record oauth flow", err)
		return
	}

	http.Redirect(w, r, p.AuthURL(state, oauth.Challenge(verifier)), http.StatusFound)
}

// handleOAuthCallback is the single URL registered with Google and GitHub.
//
// It cannot set a cookie for the app's own domain, so it mints a short-lived
// auth code and redirects to the app, whose backend exchanges it server-side.
func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	provider, ok := s.provider(w, r)
	if !ok {
		return
	}
	q := r.URL.Query()

	// Recover the flow first: without it we do not know where to send the user,
	// so even provider-reported errors have to be reported here.
	flow, err := s.db.ConsumeOAuthFlow(r.Context(), q.Get("state"))
	if err != nil {
		// Covers a missing, forged, expired, or replayed state.
		writeErr(w, http.StatusBadRequest, "invalid_state",
			"this sign-in link is invalid or has already been used")
		return
	}
	if flow.Provider != provider.Name() {
		writeErr(w, http.StatusBadRequest, "invalid_state", "state does not match this provider")
		return
	}

	if e := q.Get("error"); e != "" {
		// The user declined, or the provider refused. Hand it back to the app.
		s.redirectWithError(w, r, flow, e)
		return
	}
	code := q.Get("code")
	if code == "" {
		s.redirectWithError(w, r, flow, "missing_code")
		return
	}

	profile, err := provider.Exchange(r.Context(), code, flow.CodeVerifier)
	if err != nil {
		s.log.ErrorContext(r.Context(), "oauth exchange failed", "provider", provider.Name(), "err", err)
		s.redirectWithError(w, r, flow, "exchange_failed")
		return
	}
	profile.Email = normalizeEmail(profile.Email)

	var userID string
	if flow.LinkUserID != nil {
		if _, err := linking.LinkToUser(r.Context(), s.db, *flow.LinkUserID, provider.Name(), profile); err != nil {
			if errors.Is(err, linking.ErrAlreadyLinkedElsewhere) {
				s.redirectWithError(w, r, flow, "already_linked")
				return
			}
			s.log.ErrorContext(r.Context(), "link identity", "err", err)
			s.redirectWithError(w, r, flow, "link_failed")
			return
		}
		userID = *flow.LinkUserID
	} else {
		res, err := linking.Resolve(r.Context(), s.db, provider.Name(), profile)
		if err != nil {
			if errors.Is(err, linking.ErrManualLinkRequired) {
				s.log.WarnContext(r.Context(), "refused unsafe auto-link",
					"provider", provider.Name(), "provider_email_verified", profile.EmailVerified)
				s.redirectWithError(w, r, flow, "manual_link_required")
				return
			}
			s.log.ErrorContext(r.Context(), "resolve identity", "err", err)
			s.redirectWithError(w, r, flow, "login_failed")
			return
		}
		if res.User.DisabledAt != nil {
			s.redirectWithError(w, r, flow, "account_disabled")
			return
		}
		userID = res.User.ID
	}

	authCode, err := store.NewOpaqueToken()
	if err != nil {
		s.internal(w, r, "mint auth code", err)
		return
	}
	if err := s.db.CreateAuthCode(r.Context(), authCode, store.AuthCode{
		UserID: userID, ClientID: flow.ClientID, RedirectURI: flow.RedirectURI,
	}); err != nil {
		s.internal(w, r, "store auth code", err)
		return
	}

	http.Redirect(w, r, appendQuery(flow.RedirectURI, map[string]string{
		"code": authCode, "state": flow.AppState,
	}), http.StatusFound)
}

func (s *Server) redirectWithError(w http.ResponseWriter, r *http.Request, flow *store.OAuthFlow, code string) {
	http.Redirect(w, r, appendQuery(flow.RedirectURI, map[string]string{
		"error": code, "state": flow.AppState,
	}), http.StatusFound)
}

type exchangeReq struct {
	Code         string `json:"code"`
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

// handleTokenExchange is called by the app's backend, never its browser. It is
// the only place the client secret is used.
func (s *Server) handleTokenExchange(w http.ResponseWriter, r *http.Request) {
	var req exchangeReq
	if !decode(w, r, &req) {
		return
	}
	if !s.limit(w, r, "exchange:ip:"+clientIP(r), 120, time.Hour) {
		return
	}

	client, err := s.db.ClientByID(r.Context(), req.ClientID)
	if err != nil {
		writeErr(w, http.StatusUnauthorized, "invalid_client", "unknown client or bad secret")
		return
	}
	ok, err := password.Verify(client.SecretHash, req.ClientSecret)
	if err != nil || !ok {
		writeErr(w, http.StatusUnauthorized, "invalid_client", "unknown client or bad secret")
		return
	}

	ac, err := s.db.ConsumeAuthCode(r.Context(), req.Code)
	if err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_code", "this code is invalid, expired, or already used")
		return
	}
	// A code issued for one client must not be redeemable by another, even
	// with that other client's valid credentials.
	if ac.ClientID != client.ID {
		writeErr(w, http.StatusBadRequest, "invalid_code", "this code was not issued to this client")
		return
	}

	u, err := s.db.UserByID(r.Context(), ac.UserID)
	if err != nil {
		s.internal(w, r, "load user", err)
		return
	}
	if u.DisabledAt != nil {
		writeErr(w, http.StatusForbidden, "account_disabled", "this account is disabled")
		return
	}

	iss, err := s.db.CreateSession(r.Context(), u.ID, client.ID, store.SessionMeta{
		UserAgent: r.UserAgent(), IP: clientIP(r),
	})
	if err != nil {
		s.internal(w, r, "create session", err)
		return
	}
	resp, err := s.respondWithTokens(w, u, client.Audience, iss)
	if err != nil {
		s.internal(w, r, "sign access token", err)
		return
	}
	writeJSON(w, http.StatusOK, resp)
}

func (s *Server) provider(w http.ResponseWriter, r *http.Request) (oauth.Provider, bool) {
	name := strings.ToLower(r.PathValue("provider"))
	p, ok := s.providers[name]
	if !ok {
		writeErr(w, http.StatusNotFound, "unknown_provider", "no such provider")
		return nil, false
	}
	return p, true
}

func appendQuery(raw string, params map[string]string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	q := u.Query()
	for k, v := range params {
		if v != "" {
			q.Set(k, v)
		}
	}
	u.RawQuery = q.Encode()
	return u.String()
}
