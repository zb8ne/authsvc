package httpapi

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestRefreshRotatesViaCookie(t *testing.T) {
	r := newRig(t)
	reg := r.register(r.newClient(), r.email(), goodPassword)
	c := refreshCookie(reg)

	rp := r.do("POST", "/v1/token/refresh", nil, withCookie(c))
	if rp.Status != http.StatusOK {
		t.Fatalf("refresh: %d %s", rp.Status, rp.Raw)
	}
	if rp.str("refresh_token") == c.Value {
		t.Fatal("refresh returned the same token; it must rotate")
	}
	if refreshCookie(rp) == nil {
		t.Fatal("rotated refresh cookie not set")
	}
	if rp.str("access_token") == "" {
		t.Fatal("no new access token")
	}
}

func TestRefreshAcceptsBodyToken(t *testing.T) {
	r := newRig(t)
	reg := r.register(r.newClient(), r.email(), goodPassword)

	rp := r.do("POST", "/v1/token/refresh", map[string]string{
		"refresh_token": reg.str("refresh_token"),
	})
	if rp.Status != http.StatusOK {
		t.Fatalf("server-side refresh failed: %d %s", rp.Status, rp.Raw)
	}
}

// The end-to-end version of the reuse-detection test, through HTTP.
func TestRefreshReuseRevokesTheFamily(t *testing.T) {
	r := newRig(t)
	reg := r.register(r.newClient(), r.email(), goodPassword)
	original := reg.str("refresh_token")

	second := r.do("POST", "/v1/token/refresh", map[string]string{"refresh_token": original})
	if second.Status != http.StatusOK {
		t.Fatalf("first rotation failed: %d %s", second.Status, second.Raw)
	}
	live := second.str("refresh_token")

	// Attacker replays the stolen original.
	replay := r.do("POST", "/v1/token/refresh", map[string]string{"refresh_token": original})
	if replay.errCode() != "token_reuse" {
		t.Fatalf("replay returned %q (%d), want token_reuse", replay.errCode(), replay.Status)
	}

	// The legitimate holder is now locked out too — that is the intended cost.
	after := r.do("POST", "/v1/token/refresh", map[string]string{"refresh_token": live})
	if after.Status == http.StatusOK {
		t.Fatal("the live refresh token still works after reuse was detected")
	}

	// And the reuse response must clear the cookie rather than leave a dead one.
	if c := refreshCookie(replay); c == nil || c.MaxAge >= 0 {
		t.Error("refresh cookie was not cleared on reuse detection")
	}
}

func TestRefreshRejectsGarbage(t *testing.T) {
	r := newRig(t)
	rp := r.do("POST", "/v1/token/refresh", map[string]string{"refresh_token": "not-a-token"})
	if rp.Status != http.StatusUnauthorized {
		t.Fatalf("got %d %s", rp.Status, rp.Raw)
	}
}

func TestRefreshWithNoTokenIs401(t *testing.T) {
	r := newRig(t)
	if rp := r.do("POST", "/v1/token/refresh", nil); rp.Status != http.StatusUnauthorized {
		t.Fatalf("got %d", rp.Status)
	}
}

func TestMeRequiresAuth(t *testing.T) {
	r := newRig(t)
	if rp := r.do("GET", "/v1/me", nil); rp.Status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /v1/me returned %d", rp.Status)
	}
	if rp := r.do("GET", "/v1/me", nil, withBearer("garbage")); rp.Status != http.StatusUnauthorized {
		t.Fatalf("garbage token returned %d", rp.Status)
	}
}

func TestMeReturnsTheUser(t *testing.T) {
	r := newRig(t)
	email := r.email()
	reg := r.register(r.newClient(), email, goodPassword)

	rp := r.do("GET", "/v1/me", nil, withBearer(reg.str("access_token")))
	if rp.Status != http.StatusOK {
		t.Fatalf("%d %s", rp.Status, rp.Raw)
	}
	if rp.str("email") != email {
		t.Fatalf("email = %q, want %q", rp.str("email"), email)
	}
}

func TestLogoutRevokesTheSession(t *testing.T) {
	r := newRig(t)
	reg := r.register(r.newClient(), r.email(), goodPassword)
	access := reg.str("access_token")

	if rp := r.do("POST", "/v1/auth/logout", nil, withBearer(access)); rp.Status != http.StatusNoContent {
		t.Fatalf("logout: %d %s", rp.Status, rp.Raw)
	}

	// The access token is still cryptographically valid but its session is gone.
	if rp := r.do("GET", "/v1/me", nil, withBearer(access)); rp.Status != http.StatusUnauthorized {
		t.Fatalf("access token still works after logout: %d", rp.Status)
	}
	if rp := r.do("POST", "/v1/token/refresh", map[string]string{
		"refresh_token": reg.str("refresh_token"),
	}); rp.Status == http.StatusOK {
		t.Fatal("refresh token still works after logout")
	}
}

func TestLogoutAllKillsEveryDevice(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	first := r.register(cid, email, goodPassword)
	second := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": email, "password": goodPassword,
	})

	if rp := r.do("POST", "/v1/auth/logout-all", nil, withBearer(first.str("access_token"))); rp.Status != http.StatusNoContent {
		t.Fatalf("logout-all: %d %s", rp.Status, rp.Raw)
	}
	for name, tok := range map[string]string{"first": first.str("access_token"), "second": second.str("access_token")} {
		if rp := r.do("GET", "/v1/me", nil, withBearer(tok)); rp.Status != http.StatusUnauthorized {
			t.Errorf("%s session survived logout-all: %d", name, rp.Status)
		}
	}
}

func TestListSessionsMarksCurrent(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	first := r.register(cid, email, goodPassword)
	r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": email, "password": goodPassword,
	})

	rp := r.do("GET", "/v1/sessions", nil, withBearer(first.str("access_token")))
	if rp.Status != http.StatusOK {
		t.Fatalf("%d %s", rp.Status, rp.Raw)
	}
	var out struct {
		Sessions []sessionView `json:"sessions"`
	}
	if err := json.Unmarshal(rp.Raw, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Sessions) != 2 {
		t.Fatalf("got %d sessions, want 2", len(out.Sessions))
	}
	current := 0
	for _, s := range out.Sessions {
		if s.Current {
			current++
		}
	}
	if current != 1 {
		t.Fatalf("%d sessions marked current, want exactly 1", current)
	}
}

// A user must not be able to revoke somebody else's session.
func TestDeleteSessionRejectsOtherUsers(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()

	victim := r.register(cid, r.email(), goodPassword)
	attacker := r.register(cid, r.email(), goodPassword)

	var vs struct {
		Sessions []sessionView `json:"sessions"`
	}
	list := r.do("GET", "/v1/sessions", nil, withBearer(victim.str("access_token")))
	json.Unmarshal(list.Raw, &vs)
	if len(vs.Sessions) == 0 {
		t.Fatal("victim has no sessions")
	}
	victimSession := vs.Sessions[0].ID

	rp := r.do("DELETE", "/v1/sessions/"+victimSession, nil, withBearer(attacker.str("access_token")))
	if rp.Status != http.StatusNotFound {
		t.Fatalf("cross-user delete returned %d, want 404 (and it must not reveal the id exists)", rp.Status)
	}
	if got := r.do("GET", "/v1/me", nil, withBearer(victim.str("access_token"))); got.Status != http.StatusOK {
		t.Fatal("the victim's session was actually revoked by another user")
	}
}

func TestDeleteOwnSession(t *testing.T) {
	r := newRig(t)
	reg := r.register(r.newClient(), r.email(), goodPassword)

	var out struct {
		Sessions []sessionView `json:"sessions"`
	}
	list := r.do("GET", "/v1/sessions", nil, withBearer(reg.str("access_token")))
	json.Unmarshal(list.Raw, &out)

	rp := r.do("DELETE", "/v1/sessions/"+out.Sessions[0].ID, nil, withBearer(reg.str("access_token")))
	if rp.Status != http.StatusNoContent {
		t.Fatalf("%d %s", rp.Status, rp.Raw)
	}
	if got := r.do("GET", "/v1/me", nil, withBearer(reg.str("access_token"))); got.Status != http.StatusUnauthorized {
		t.Fatal("session still valid after deleting it")
	}
}
