package authsdk

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwt"
)

type User struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	EmailVerified bool      `json:"email_verified"`
	Roles         []string  `json:"roles,omitempty"`
	SessionID     string    `json:"-"`
	ExpiresAt     time.Time `json:"-"`
}

// HasRole reports whether the user carries the named role.
func (u User) HasRole(role string) bool {
	for _, r := range u.Roles {
		if r == role {
			return true
		}
	}
	return false
}

type ctxKey int

const userKey ctxKey = iota

// UserFrom returns the authenticated user attached by RequireUser.
func UserFrom(ctx context.Context) (User, bool) {
	u, ok := ctx.Value(userKey).(User)
	return u, ok
}

// RequireUser rejects requests without a valid access token.
//
// Verification is entirely local, against the cached JWKS. There is no network
// call here and no dependency on authsvc being reachable.
func (c *Client) RequireUser(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		raw := bearerToken(r)
		if raw == "" {
			writeAuthErr(w, http.StatusUnauthorized, "unauthorized", "missing bearer token")
			return
		}

		u, err := c.Verify(raw)
		if err != nil {
			// A missing key set is the service's problem, not the caller's;
			// saying 401 would tell the user to re-login pointlessly.
			if errorIsKeyProblem(err) {
				writeAuthErr(w, http.StatusServiceUnavailable, "keys_unavailable",
					"cannot verify tokens right now")
				return
			}
			writeAuthErr(w, http.StatusUnauthorized, "unauthorized", "invalid or expired token")
			return
		}

		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userKey, u)))
	})
}

// RequireRole requires any one of the named roles. It must be used inside
// RequireUser.
//
// Roles come from the access token, so a role change takes effect only when the
// token is next refreshed — up to the access-token TTL, one hour by default.
// For a permission that must revoke instantly, check it against your own
// database instead.
func (c *Client) RequireRole(roles ...string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			u, ok := UserFrom(r.Context())
			if !ok {
				writeAuthErr(w, http.StatusUnauthorized, "unauthorized", "not authenticated")
				return
			}
			for _, want := range roles {
				if u.HasRole(want) {
					next.ServeHTTP(w, r)
					return
				}
			}
			writeAuthErr(w, http.StatusForbidden, "forbidden", "insufficient role")
		})
	}
}

// Verify validates an access token locally and returns the user it describes.
func (c *Client) Verify(raw string) (User, error) {
	set, err := c.keys.get()
	if err != nil {
		return User{}, err
	}

	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(set),
		jwt.WithIssuer(c.cfg.Issuer),
		jwt.WithAudience(c.cfg.Audience),
		jwt.WithValidate(true),
	)
	if err != nil {
		return User{}, err
	}

	u := User{ID: tok.Subject(), ExpiresAt: tok.Expiration()}
	if v, ok := tok.Get("email"); ok {
		u.Email, _ = v.(string)
	}
	if v, ok := tok.Get("email_verified"); ok {
		u.EmailVerified, _ = v.(bool)
	}
	if v, ok := tok.Get("sid"); ok {
		u.SessionID, _ = v.(string)
	}
	if v, ok := tok.Get("roles"); ok {
		if list, ok := v.([]any); ok {
			u.Roles = make([]string, 0, len(list))
			for _, r := range list {
				if s, ok := r.(string); ok {
					u.Roles = append(u.Roles, s)
				}
			}
		}
	}
	return u, nil
}

func bearerToken(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if len(h) > 7 && strings.EqualFold(h[:7], "bearer ") {
		return strings.TrimSpace(h[7:])
	}
	return ""
}

func writeAuthErr(w http.ResponseWriter, status int, code, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]string{"code": code, "message": msg},
	})
}
