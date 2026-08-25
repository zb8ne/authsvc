// Package httpapi is the HTTP surface: routing, middleware, handlers.
package httpapi

import (
	"context"
	"log/slog"
	"net/http"
	"time"

	"github.com/zb8ne/authsvc/internal/notify"
	"github.com/zb8ne/authsvc/internal/oauth"
	"github.com/zb8ne/authsvc/internal/store"
	"github.com/zb8ne/authsvc/internal/token"
)

// Cookie settings. Path is /v1/token so the refresh token is sent only to the
// refresh endpoint and never rides along on ordinary API calls.
const (
	RefreshCookie = "authsvc_refresh"
	RefreshPath   = "/v1/token"
)

// TTLs for the emailed secrets.
const (
	OTPTTL           = 10 * time.Minute
	EmailVerifyTTL   = 24 * time.Hour
	PasswordResetTTL = time.Hour
)

type Options struct {
	Issuer      string
	AdminAPIKey string
	// Secure controls the cookie Secure flag; false only for local development.
	Secure bool
	// ContactEmail is shown on the privacy and terms pages. Google requires a
	// reachable contact for a published OAuth app.
	ContactEmail string
}

type Server struct {
	db     *store.DB
	signer *token.Signer
	sender notify.Sender
	log    *slog.Logger
	opts   Options
	now    func() time.Time
	// providers is keyed by provider name; a provider absent from the map is
	// simply not configured, and its routes 404.
	providers map[string]oauth.Provider
}

// WithProviders registers the configured OAuth providers.
func (s *Server) WithProviders(ps ...oauth.Provider) *Server {
	for _, p := range ps {
		s.providers[p.Name()] = p
	}
	return s
}

func New(db *store.DB, signer *token.Signer, sender notify.Sender, log *slog.Logger, opts Options) *Server {
	if log == nil {
		log = slog.Default()
	}
	if opts.ContactEmail == "" {
		opts.ContactEmail = "See the repository at github.com/zb8ne/authsvc"
	}
	return &Server{db: db, signer: signer, sender: sender, log: log, opts: opts,
		now: time.Now, providers: map[string]oauth.Provider{}}
}

func (s *Server) Routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /.well-known/jwks.json", s.handleJWKS)
	mux.HandleFunc("GET /healthz", s.handleHealth)

	// Required by Google before an OAuth app can be published, and shown to
	// users on the consent screen.
	mux.HandleFunc("GET /", s.handleHome)
	mux.HandleFunc("GET /privacy", s.handlePrivacy)
	mux.HandleFunc("GET /terms", s.handleTerms)

	mux.HandleFunc("POST /v1/auth/register", s.handleRegister)
	mux.HandleFunc("POST /v1/auth/login", s.handleLogin)
	mux.HandleFunc("POST /v1/auth/email/verify", s.handleEmailVerify)
	mux.HandleFunc("POST /v1/auth/password/forgot", s.handlePasswordForgot)
	mux.HandleFunc("POST /v1/auth/password/reset", s.handlePasswordReset)

	mux.HandleFunc("POST /v1/auth/otp/request", s.handleOTPRequest)
	mux.HandleFunc("POST /v1/auth/otp/verify", s.handleOTPVerify)

	mux.HandleFunc("GET /v1/oauth/{provider}/start", s.handleOAuthStart)
	mux.HandleFunc("GET /v1/oauth/{provider}/callback", s.handleOAuthCallback)
	mux.HandleFunc("GET /v1/me/link/{provider}/start", s.requireUser(s.handleLinkStart))

	mux.HandleFunc("POST /v1/token/exchange", s.handleTokenExchange)
	mux.HandleFunc("POST /v1/token/refresh", s.handleRefresh)
	mux.HandleFunc("POST /v1/auth/logout", s.requireUser(s.handleLogout))
	mux.HandleFunc("POST /v1/auth/logout-all", s.requireUser(s.handleLogoutAll))

	mux.HandleFunc("GET /v1/me", s.requireUser(s.handleMe))
	mux.HandleFunc("GET /v1/sessions", s.requireUser(s.handleListSessions))
	mux.HandleFunc("DELETE /v1/sessions/{id}", s.requireUser(s.handleDeleteSession))

	mux.HandleFunc("POST /v1/admin/clients", s.requireAdmin(s.handleCreateClient))
	mux.HandleFunc("GET /v1/admin/clients", s.requireAdmin(s.handleListClients))

	return s.recoverer(s.accessLog(securityHeaders(mux)))
}

// issueSession mints an access token and a rotating refresh token, and sets the
// refresh cookie. Used by every successful authentication path.
func (s *Server) issueSession(ctx context.Context, r *http.Request, w http.ResponseWriter, u *store.User, c *store.Client) (*tokenResponse, error) {
	iss, err := s.db.CreateSession(ctx, u.ID, c.ID, store.SessionMeta{
		UserAgent: r.UserAgent(),
		IP:        clientIP(r),
	})
	if err != nil {
		return nil, err
	}
	return s.respondWithTokens(w, u, c.Audience, iss)
}

func (s *Server) respondWithTokens(w http.ResponseWriter, u *store.User, audience string, iss *store.IssuedSession) (*tokenResponse, error) {
	access, err := s.signer.SignAccess(token.Claims{
		Subject:       u.ID,
		Audience:      audience,
		SessionID:     iss.Session.ID,
		Email:         u.Email,
		EmailVerified: u.EmailVerified(),
		Roles:         []string{},
	})
	if err != nil {
		return nil, err
	}
	s.setRefreshCookie(w, iss.RefreshToken, iss.Session.ExpiresAt)
	return &tokenResponse{
		AccessToken:  access,
		RefreshToken: iss.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(s.signer.AccessTTL().Seconds()),
		User:         userJSON(u),
	}, nil
}

type tokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	User         *userView `json:"user"`
}

type userView struct {
	ID            string `json:"id"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
}

func userJSON(u *store.User) *userView {
	return &userView{ID: u.ID, Email: u.Email, EmailVerified: u.EmailVerified()}
}

func (s *Server) setRefreshCookie(w http.ResponseWriter, tok string, exp time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookie,
		Value:    tok,
		Path:     RefreshPath,
		Expires:  exp,
		HttpOnly: true,
		Secure:   s.opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearRefreshCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     RefreshCookie,
		Value:    "",
		Path:     RefreshPath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.opts.Secure,
		SameSite: http.SameSiteLaxMode,
	})
}
