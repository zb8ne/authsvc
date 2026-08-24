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
