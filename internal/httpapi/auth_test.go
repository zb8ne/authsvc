package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/yash-sharma-dev/authsvc/internal/notify"
)

func TestRegisterIssuesTokensAndSendsVerification(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()

	rp := r.register(cid, email, goodPassword)
	if rp.Status != http.StatusCreated {
		t.Fatalf("status %d: %s", rp.Status, rp.Raw)
	}
	if rp.str("access_token") == "" || rp.str("refresh_token") == "" {
		t.Fatal("no tokens returned")
	}
	if refreshCookie(rp) == nil {
		t.Fatal("refresh cookie not set")
	}

	sent, ok := r.mail.last(notify.PurposeEmailVerify)
	if !ok {
		t.Fatal("no verification email sent")
	}
	if sent.To != email {
		t.Fatalf("verification sent to %q, want %q", sent.To, email)
	}

	u, _ := rp.Body["user"].(map[string]any)
	if u["email_verified"] != false {
		t.Fatal("a brand-new account must not start out email-verified")
	}
}

func TestRefreshCookieIsHardened(t *testing.T) {
	r := newRig(t)
	rp := r.register(r.newClient(), r.email(), goodPassword)

	c := refreshCookie(rp)
	if c == nil {
		t.Fatal("no refresh cookie")
	}
	if !c.HttpOnly {
		t.Error("refresh cookie is not HttpOnly; script can read it")
	}
	if c.SameSite != http.SameSiteLaxMode {
		t.Errorf("SameSite = %v, want Lax", c.SameSite)
	}
	if c.Path != RefreshPath {
		t.Errorf("cookie Path = %q, want %q so it is not sent on ordinary calls", c.Path, RefreshPath)
	}
}

func TestRegisterRejectsWeakAndInvalidInput(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()

	if rp := r.register(cid, r.email(), "short"); rp.errCode() != "weak_password" {
		t.Errorf("short password: got %q (%d)", rp.errCode(), rp.Status)
	}
	if rp := r.register(cid, "not-an-email", goodPassword); rp.errCode() != "invalid_email" {
		t.Errorf("bad email: got %q", rp.errCode())
	}
	if rp := r.register("no-such-client", r.email(), goodPassword); rp.errCode() != "unknown_client" {
		t.Errorf("unknown client: got %q", rp.errCode())
	}
}

// Registering an existing address must not confirm that it is taken.
func TestRegisterDoesNotLeakAccountExistence(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()

	r.register(cid, email, goodPassword)
	rp := r.register(cid, email, "a-totally-different-password")

	if rp.Status == http.StatusConflict {
		t.Fatal("duplicate registration returned 409, which confirms the address is registered")
	}
	if strings.Contains(strings.ToLower(string(rp.Raw)), "exists") {
		t.Fatalf("response body leaks existence: %s", rp.Raw)
	}
	if rp.str("access_token") != "" {
		t.Fatal("re-registering an existing email handed out a session for it")
	}
}

func TestLoginHappyPath(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	r.register(cid, email, goodPassword)

	rp := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": email, "password": goodPassword,
	})
	if rp.Status != http.StatusOK {
		t.Fatalf("status %d: %s", rp.Status, rp.Raw)
	}
	if rp.str("access_token") == "" {
		t.Fatal("no access token")
	}
}

func TestLoginIsCaseInsensitiveOnEmail(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	r.register(cid, email, goodPassword)

	rp := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": strings.ToUpper(email), "password": goodPassword,
	})
	if rp.Status != http.StatusOK {
		t.Fatalf("uppercase email failed to log in: %d %s", rp.Status, rp.Raw)
	}
}

// The same error for a wrong password and a nonexistent account.
func TestLoginDoesNotEnumerateAccounts(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	r.register(cid, email, goodPassword)

	wrongPw := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": email, "password": "wrong-password-here",
	})
	noUser := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": r.email(), "password": "wrong-password-here",
	})

	if wrongPw.Status != noUser.Status {
		t.Errorf("status differs: wrong password %d, unknown account %d", wrongPw.Status, noUser.Status)
	}
	if wrongPw.errCode() != noUser.errCode() {
		t.Errorf("error code differs: %q vs %q", wrongPw.errCode(), noUser.errCode())
	}
	if wrongPw.Status != http.StatusUnauthorized {
		t.Errorf("status = %d, want 401", wrongPw.Status)
	}
}

func TestEmailVerifyFlow(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	reg := r.register(cid, email, goodPassword)

	sent, ok := r.mail.last(notify.PurposeEmailVerify)
	if !ok {
		t.Fatal("no verification token sent")
	}

	rp := r.do("POST", "/v1/auth/email/verify", map[string]string{"token": sent.Code})
	if rp.Status != http.StatusOK {
		t.Fatalf("verify failed: %d %s", rp.Status, rp.Raw)
	}

	me := r.do("GET", "/v1/me", nil, withBearer(reg.str("access_token")))
	if me.Body["email_verified"] != true {
		t.Fatalf("email not marked verified: %s", me.Raw)
	}

	// Single use.
	again := r.do("POST", "/v1/auth/email/verify", map[string]string{"token": sent.Code})
	if again.errCode() != "invalid_token" {
		t.Fatalf("verification token was reusable: %d %s", again.Status, again.Raw)
	}
}

func TestEmailVerifyRejectsGarbage(t *testing.T) {
	r := newRig(t)
	rp := r.do("POST", "/v1/auth/email/verify", map[string]string{"token": "nope"})
	if rp.errCode() != "invalid_token" {
		t.Fatalf("got %q (%d)", rp.errCode(), rp.Status)
	}
}

func TestPasswordResetFlow(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	reg := r.register(cid, email, goodPassword)

	if rp := r.do("POST", "/v1/auth/password/forgot", map[string]string{"email": email}); rp.Status != http.StatusAccepted {
		t.Fatalf("forgot: %d %s", rp.Status, rp.Raw)
	}
	sent, ok := r.mail.last(notify.PurposePasswordReset)
	if !ok {
		t.Fatal("no reset token sent")
	}

	const newPw = "an-entirely-new-password"
	rp := r.do("POST", "/v1/auth/password/reset", map[string]string{
		"token": sent.Code, "new_password": newPw,
	})
	if rp.Status != http.StatusOK {
		t.Fatalf("reset: %d %s", rp.Status, rp.Raw)
	}

	// New password works, old one does not.
	if got := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": email, "password": newPw,
	}); got.Status != http.StatusOK {
		t.Fatalf("new password rejected: %d %s", got.Status, got.Raw)
	}
	if got := r.do("POST", "/v1/auth/login", map[string]string{
		"client_id": cid, "email": email, "password": goodPassword,
	}); got.Status == http.StatusOK {
		t.Fatal("the old password still works after a reset")
	}

	// A reset is the remedy for a compromise: pre-existing sessions must die.
	if me := r.do("GET", "/v1/me", nil, withBearer(reg.str("access_token"))); me.Status == http.StatusOK {
		t.Fatal("a session predating the password reset is still valid")
	}
}

func TestPasswordForgotDoesNotLeakExistence(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	known := r.email()
	r.register(cid, known, goodPassword)

	a := r.do("POST", "/v1/auth/password/forgot", map[string]string{"email": known}, withIP("10.0.0.1"))
	b := r.do("POST", "/v1/auth/password/forgot", map[string]string{"email": r.email()}, withIP("10.0.0.2"))

	if a.Status != b.Status || string(a.Raw) != string(b.Raw) {
		t.Fatalf("responses differ for known vs unknown address:\n known: %d %s\n unknown: %d %s",
			a.Status, a.Raw, b.Status, b.Raw)
	}
}

func TestPasswordResetTokenIsSingleUse(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()
	r.register(cid, email, goodPassword)

	r.do("POST", "/v1/auth/password/forgot", map[string]string{"email": email})
	sent, _ := r.mail.last(notify.PurposePasswordReset)

	r.do("POST", "/v1/auth/password/reset", map[string]string{"token": sent.Code, "new_password": "first-new-password"})
	again := r.do("POST", "/v1/auth/password/reset", map[string]string{"token": sent.Code, "new_password": "second-new-password"})
	if again.Status == http.StatusOK {
		t.Fatal("reset token was usable twice")
	}
}

func TestResetRejectsWeakPassword(t *testing.T) {
	r := newRig(t)
	rp := r.do("POST", "/v1/auth/password/reset", map[string]string{"token": "x", "new_password": "short"})
	if rp.errCode() != "weak_password" {
		t.Fatalf("got %q", rp.errCode())
	}
}

func TestMalformedBodyRejected(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()

	// Unknown fields must fail loudly rather than silently defaulting.
	rp := r.do("POST", "/v1/auth/login", map[string]any{
		"client_id": cid, "email": "a@b.co", "password": "x", "admin": true,
	})
	if rp.Status != http.StatusBadRequest {
		t.Fatalf("unknown field accepted: %d %s", rp.Status, rp.Raw)
	}
}
