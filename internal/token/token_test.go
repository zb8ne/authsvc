package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"testing"
	"time"
)

func newKeyB64(t *testing.T) string {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(priv.Seed())
}

func newSigner(t *testing.T) *Signer {
	t.Helper()
	s, err := NewSigner(Config{
		Issuer:     "https://auth.grindlog.lol",
		AccessTTL:  time.Hour,
		PrivateKey: newKeyB64(t),
		NextKey:    newKeyB64(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	s := newSigner(t)
	c := Claims{Subject: "u1", Audience: "dayflow", SessionID: "s1", Email: "a@b.c", EmailVerified: true, Roles: []string{"employee"}}
	tok, err := s.SignAccess(c)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.VerifyAccess(tok, "dayflow")
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "u1" || got.SessionID != "s1" || got.Email != "a@b.c" || !got.EmailVerified {
		t.Fatalf("claims round-tripped wrong: %+v", got)
	}
	if len(got.Roles) != 1 || got.Roles[0] != "employee" {
		t.Fatalf("roles round-tripped wrong: %+v", got.Roles)
	}
	if got.JTI == "" {
		t.Fatal("jti not set")
	}
}

func TestVerifyRejectsWrongAudience(t *testing.T) {
	s := newSigner(t)
	tok, _ := s.SignAccess(Claims{Subject: "u1", Audience: "dayflow"})
	if _, err := s.VerifyAccess(tok, "sih26"); err == nil {
		t.Fatal("token for a different audience verified")
	}
}

func TestVerifyRejectsExpired(t *testing.T) {
	s := newSigner(t)
	s.now = func() time.Time { return time.Now().Add(-2 * time.Hour) }
	tok, _ := s.SignAccess(Claims{Subject: "u1", Audience: "dayflow"})
	s.now = time.Now
	if _, err := s.VerifyAccess(tok, "dayflow"); err == nil {
		t.Fatal("expired token verified")
	}
}

func TestVerifyRejectsForeignKey(t *testing.T) {
	a, b := newSigner(t), newSigner(t)
	tok, _ := a.SignAccess(Claims{Subject: "u1", Audience: "dayflow"})
	if _, err := b.VerifyAccess(tok, "dayflow"); err == nil {
		t.Fatal("token signed by an unrelated key verified")
	}
}

func TestVerifyRejectsTamperedPayload(t *testing.T) {
	s := newSigner(t)
	tok, _ := s.SignAccess(Claims{Subject: "u1", Audience: "dayflow"})
	// flip a byte in the payload segment
	b := []byte(tok)
	for i := range b {
		if b[i] == '.' {
			b[i+1] ^= 0x01
			break
		}
	}
	if _, err := s.VerifyAccess(string(b), "dayflow"); err == nil {
		t.Fatal("tampered token verified")
	}
}

func TestVerifyRejectsNoneAlg(t *testing.T) {
	s := newSigner(t)
	// header {"alg":"none","typ":"JWT"} + a payload, empty signature
	e := base64.RawURLEncoding.EncodeToString
	forged := e([]byte(`{"alg":"none","typ":"JWT"}`)) + "." +
		e([]byte(`{"iss":"https://auth.grindlog.lol","sub":"u1","aud":"dayflow","exp":99999999999}`)) + "."
	if _, err := s.VerifyAccess(forged, "dayflow"); err == nil {
		t.Fatal("alg=none token verified")
	}
}

func TestJWKSPublishesBothKeys(t *testing.T) {
	s := newSigner(t)
	set, err := s.JWKS()
	if err != nil {
		t.Fatal(err)
	}
	if set.Len() != 2 {
		t.Fatalf("JWKS has %d keys, want 2 (current + next) so rotation needs no flag day", set.Len())
	}
	seen := map[string]bool{}
	for i := 0; i < set.Len(); i++ {
		k, _ := set.Key(i)
		if k.KeyID() == "" {
			t.Fatal("JWKS key has no kid")
		}
		if seen[k.KeyID()] {
			t.Fatal("duplicate kid in JWKS")
		}
		seen[k.KeyID()] = true
	}
}

func TestJWKSOmitsPrivateMaterial(t *testing.T) {
	s := newSigner(t)
	set, _ := s.JWKS()
	buf, err := set.(interface{ MarshalJSON() ([]byte, error) }).MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if contains(string(buf), `"d"`) {
		t.Fatalf("JWKS leaks the private scalar: %s", buf)
	}
}

func contains(h, n string) bool {
	for i := 0; i+len(n) <= len(h); i++ {
		if h[i:i+len(n)] == n {
			return true
		}
	}
	return false
}

func TestSignerRequiresPrivateKey(t *testing.T) {
	if _, err := NewSigner(Config{Issuer: "x", AccessTTL: time.Hour}); err == nil {
		t.Fatal("NewSigner accepted an empty private key")
	}
}

func TestNextKeyIsOptional(t *testing.T) {
	s, err := NewSigner(Config{Issuer: "x", AccessTTL: time.Hour, PrivateKey: newKeyB64(t)})
	if err != nil {
		t.Fatal(err)
	}
	set, _ := s.JWKS()
	if set.Len() != 1 {
		t.Fatalf("JWKS has %d keys, want 1", set.Len())
	}
}

func TestRefreshTokenIsRandomAndOpaque(t *testing.T) {
	a, err := NewRefreshToken()
	if err != nil {
		t.Fatal(err)
	}
	b, _ := NewRefreshToken()
	if a == b {
		t.Fatal("two refresh tokens are identical")
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(a)
	if err != nil {
		t.Fatalf("refresh token is not base64url: %v", err)
	}
	if len(raw) != 32 {
		t.Fatalf("refresh token has %d bytes of entropy, want 32", len(raw))
	}
	if contains(a, ".") {
		t.Fatal("refresh token looks like a JWT; it must be opaque")
	}
}

func TestHashRefreshIsStableSHA256(t *testing.T) {
	tok, _ := NewRefreshToken()
	h1, h2 := HashRefresh(tok), HashRefresh(tok)
	if len(h1) != 32 {
		t.Fatalf("hash is %d bytes, want 32 (sha256)", len(h1))
	}
	if string(h1) != string(h2) {
		t.Fatal("HashRefresh is not deterministic")
	}
	other, _ := NewRefreshToken()
	if string(HashRefresh(other)) == string(h1) {
		t.Fatal("distinct tokens hash equal")
	}
}

func TestEmptyRolesRoundTripsAsEmptySlice(t *testing.T) {
	s := newSigner(t)
	tok, _ := s.SignAccess(Claims{Subject: "u1", Audience: "dayflow"})
	got, err := s.VerifyAccess(tok, "dayflow")
	if err != nil {
		t.Fatal(err)
	}
	if got.Roles == nil {
		t.Fatal("roles came back nil; signing an empty slice must verify as an empty slice")
	}
	if len(got.Roles) != 0 {
		t.Fatalf("roles = %v, want empty", got.Roles)
	}
}
