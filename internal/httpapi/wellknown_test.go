package httpapi

import (
	"net/http"
	"strings"
	"testing"
)

func TestJWKSIsPublicAndCacheable(t *testing.T) {
	r := newRig(t)
	rp := r.do("GET", "/.well-known/jwks.json", nil)
	if rp.Status != http.StatusOK {
		t.Fatalf("%d %s", rp.Status, rp.Raw)
	}
	if !strings.Contains(rp.Header.Get("Cache-Control"), "max-age") {
		t.Errorf("JWKS is not cacheable: Cache-Control = %q", rp.Header.Get("Cache-Control"))
	}

	keys, _ := rp.Body["keys"].([]any)
	if len(keys) == 0 {
		t.Fatal("no keys published")
	}
	for _, k := range keys {
		m := k.(map[string]any)
		if m["kid"] == "" || m["kid"] == nil {
			t.Error("key published without a kid")
		}
		if m["crv"] != "Ed25519" {
			t.Errorf("crv = %v, want Ed25519", m["crv"])
		}
		if _, leaked := m["d"]; leaked {
			t.Fatal("JWKS leaks the private scalar")
		}
	}
}

func TestHealthzChecksTheDatabase(t *testing.T) {
	r := newRig(t)
	rp := r.do("GET", "/healthz", nil)
	if rp.Status != http.StatusOK {
		t.Fatalf("%d %s", rp.Status, rp.Raw)
	}
	if rp.str("database") != "ok" {
		t.Fatalf("healthz does not report database state: %s", rp.Raw)
	}
}

func TestSecurityHeadersPresent(t *testing.T) {
	r := newRig(t)
	rp := r.do("GET", "/healthz", nil)
	for k, want := range map[string]string{
		"X-Content-Type-Options": "nosniff",
		"X-Frame-Options":        "DENY",
		"Referrer-Policy":        "no-referrer",
	} {
		if got := rp.Header.Get(k); got != want {
			t.Errorf("%s = %q, want %q", k, got, want)
		}
	}
}

func TestTokenResponsesAreNotCached(t *testing.T) {
	r := newRig(t)
	reg := r.register(r.newClient(), r.email(), goodPassword)
	if got := reg.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("token response Cache-Control = %q, want no-store", got)
	}
}

// A token minted for one app must not authenticate against another's audience.
func TestAccessTokenIsBoundToItsAudience(t *testing.T) {
	r := newRig(t)
	appA := r.newClient()
	reg := r.register(appA, r.email(), goodPassword)

	claims, err := r.signer.VerifyAccess(reg.str("access_token"), appA)
	if err != nil {
		t.Fatalf("token does not verify against its own audience: %v", err)
	}
	if claims.SessionID == "" {
		t.Error("no sid claim; session revocation could not be enforced")
	}
	if claims.Roles == nil {
		t.Error("roles claim missing")
	}

	if _, err := r.signer.VerifyAccess(reg.str("access_token"), r.newClient()); err == nil {
		t.Fatal("the token verified against a different client's audience")
	}
}

// Google requires these before an OAuth app can be published, and users see
// them on the consent screen. A 404 here blocks publishing.
func TestLegalPagesAreServed(t *testing.T) {
	r := newRig(t)
	for _, path := range []string{"/", "/privacy", "/terms"} {
		rp := r.do("GET", path, nil)
		if rp.Status != http.StatusOK {
			t.Errorf("%s returned %d, want 200", path, rp.Status)
		}
		if ct := rp.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
			t.Errorf("%s Content-Type = %q", path, ct)
		}
		if len(rp.Raw) < 400 {
			t.Errorf("%s body is only %d bytes; too thin to be a real page", path, len(rp.Raw))
		}
	}
}

// The privacy page must actually describe what the service stores. If this
// drifts from reality it is worse than having no page.
func TestPrivacyPageDescribesWhatIsActuallyStored(t *testing.T) {
	r := newRig(t)
	body := strings.ToLower(string(r.do("GET", "/privacy", nil).Raw))

	for _, want := range []string{"email", "argon2id", "ip address", "user-agent", "session"} {
		if !strings.Contains(body, want) {
			t.Errorf("privacy page does not mention %q, which the service does store", want)
		}
	}
	for _, want := range []string{"resend", "railway"} {
		if !strings.Contains(body, want) {
			t.Errorf("privacy page does not disclose the %q subprocessor", want)
		}
	}
}

// An unknown path must still 404 — the root handler must not swallow everything.
func TestRootHandlerDoesNotSwallowUnknownPaths(t *testing.T) {
	r := newRig(t)
	if rp := r.do("GET", "/definitely-not-a-route", nil); rp.Status != http.StatusNotFound {
		t.Fatalf("unknown path returned %d, want 404", rp.Status)
	}
}
