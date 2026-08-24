package authsdk

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const (
	testIssuer   = "https://auth.test"
	testAudience = "dayflow"
)

// fakeAuthsvc serves a JWKS and mints tokens the way authsvc does, so the SDK
// is tested against the real token shape rather than a convenient one.
type fakeAuthsvc struct {
	srv  *httptest.Server
	key  jwk.Key
	pub  jwk.Set
	hits int64

	mu     sync.Mutex
	status int // when non-zero, JWKS returns this instead
	body   string
}

func newFakeAuthsvc(t *testing.T) *fakeAuthsvc {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := jwk.FromRaw(priv)
	if err != nil {
		t.Fatal(err)
	}
	key.Set(jwk.KeyIDKey, "test-key-1")
	key.Set(jwk.AlgorithmKey, jwa.EdDSA)

	pub, _ := key.PublicKey()
	set := jwk.NewSet()
	set.AddKey(pub)

	f := &fakeAuthsvc{key: key, pub: set}
	mux := http.NewServeMux()
	mux.HandleFunc("/.well-known/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt64(&f.hits, 1)
		f.mu.Lock()
		status, body := f.status, f.body
		f.mu.Unlock()

		if status != 0 {
			http.Error(w, body, status)
			return
		}
		w.Header().Set("Content-Type", "application/jwk-set+json")
		json.NewEncoder(w).Encode(f.pub)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeAuthsvc) breakWith(status int, body string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.status, f.body = status, body
}

func (f *fakeAuthsvc) jwksHits() int64 { return atomic.LoadInt64(&f.hits) }

type claimOpt func(*jwt.Builder) *jwt.Builder

func withRoles(roles ...string) claimOpt {
	return func(b *jwt.Builder) *jwt.Builder { return b.Claim("roles", roles) }
}
func withAudience(a string) claimOpt {
	return func(b *jwt.Builder) *jwt.Builder { return b.Audience([]string{a}) }
}
func withIssuer(i string) claimOpt {
	return func(b *jwt.Builder) *jwt.Builder { return b.Issuer(i) }
}
func expiredAt(d time.Duration) claimOpt {
	return func(b *jwt.Builder) *jwt.Builder {
		return b.IssuedAt(time.Now().Add(d - time.Hour)).Expiration(time.Now().Add(d))
	}
}

func (f *fakeAuthsvc) mint(t *testing.T, opts ...claimOpt) string {
	t.Helper()
	b := jwt.NewBuilder().
		Issuer(testIssuer).
		Subject("user-1").
		Audience([]string{testAudience}).
		JwtID("jti-1").
		IssuedAt(time.Now()).
		Expiration(time.Now().Add(time.Hour)).
		Claim("sid", "session-1").
		Claim("email", "user@example.test").
		Claim("email_verified", true).
		Claim("roles", []string{})

	for _, o := range opts {
		b = o(b)
	}
	tok, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, f.key))
	if err != nil {
		t.Fatal(err)
	}
	return string(signed)
}

func newTestClient(t *testing.T, f *fakeAuthsvc, mut ...func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		BaseURL:  f.srv.URL,
		Issuer:   testIssuer,
		ClientID: testAudience,
		Audience: testAudience,
	}
	for _, m := range mut {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(c.Close)
	return c
}

func TestNewRequiresBaseURL(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Fatal("New accepted an empty BaseURL")
	}
}

func TestAudienceDefaultsToClientID(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f, func(cfg *Config) { cfg.Audience = "" })
	if c.cfg.Audience != testAudience {
		t.Fatalf("Audience = %q, want it defaulted to ClientID", c.cfg.Audience)
	}
}

func TestVerifyAcceptsAValidToken(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)

	u, err := c.Verify(f.mint(t, withRoles("employee", "admin")))
	if err != nil {
		t.Fatal(err)
	}
	if u.ID != "user-1" || u.Email != "user@example.test" || !u.EmailVerified {
		t.Fatalf("claims wrong: %+v", u)
	}
	if u.SessionID != "session-1" {
		t.Errorf("sid = %q", u.SessionID)
	}
	if !u.HasRole("admin") || u.HasRole("nope") {
		t.Errorf("roles wrong: %v", u.Roles)
	}
}

func TestVerifyRejectsBadTokens(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)

	other := newFakeAuthsvc(t) // a different signing key entirely

	cases := map[string]string{
		"wrong audience": f.mint(t, withAudience("someone-else")),
		"wrong issuer":   f.mint(t, withIssuer("https://evil.test")),
		"expired":        f.mint(t, expiredAt(-time.Minute)),
		"foreign key":    other.mint(t),
		"garbage":        "not-a-jwt",
		"empty":          "",
	}
	for name, tok := range cases {
		if _, err := c.Verify(tok); err == nil {
			t.Errorf("%s: token was accepted", name)
		}
	}
}

// The property the whole SDK exists for.
func TestVerificationSurvivesAuthsvcOutage(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)
	tok := f.mint(t)

	if _, err := c.Verify(tok); err != nil {
		t.Fatalf("baseline verify failed: %v", err)
	}

	// authsvc falls over completely.
	f.srv.Close()

	for i := 0; i < 100; i++ {
		if _, err := c.Verify(tok); err != nil {
			t.Fatalf("verify %d failed while authsvc was down: %v", i, err)
		}
	}
}

// RequireUser must not touch the network on the request path.
func TestRequireUserMakesNoNetworkCalls(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)
	tok := f.mint(t)

	before := f.jwksHits()

	h := c.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := UserFrom(r.Context()); !ok {
			t.Error("no user in context")
		}
		w.WriteHeader(http.StatusOK)
	}))

	for i := 0; i < 50; i++ {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusOK {
			t.Fatalf("request %d: %d %s", i, rec.Code, rec.Body)
		}
	}

	if got := f.jwksHits() - before; got != 0 {
		t.Fatalf("%d JWKS fetches happened on the request path, want 0", got)
	}
}

func TestRequireUserRejectsMissingAndBadTokens(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)
	h := c.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran for an unauthenticated request")
	}))

	for name, auth := range map[string]string{
		"no header":     "",
		"not bearer":    "Basic abc",
		"garbage token": "Bearer nonsense",
	} {
		req := httptest.NewRequest("GET", "/", nil)
		if auth != "" {
			req.Header.Set("Authorization", auth)
		}
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s: status %d, want 401", name, rec.Code)
		}
	}
}

func TestRequireRole(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)

	ok := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })
	h := c.RequireUser(c.RequireRole("admin", "owner")(ok))

	call := func(tok string) int {
		req := httptest.NewRequest("GET", "/", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := call(f.mint(t, withRoles("admin"))); got != 200 {
		t.Errorf("admin got %d, want 200", got)
	}
	if got := call(f.mint(t, withRoles("owner"))); got != 200 {
		t.Errorf("owner (second listed role) got %d, want 200", got)
	}
	if got := call(f.mint(t, withRoles("employee"))); got != http.StatusForbidden {
		t.Errorf("employee got %d, want 403", got)
	}
	if got := call(f.mint(t)); got != http.StatusForbidden {
		t.Errorf("no roles got %d, want 403", got)
	}
}

// RequireRole outside RequireUser must fail closed.
func TestRequireRoleWithoutRequireUserDenies(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)

	h := c.RequireRole("admin")(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran without authentication")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+f.mint(t, withRoles("admin")))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("status %d, want 401", rec.Code)
	}
}

// A cold cache is the service's failure, not the caller's: 503, not 401.
func TestColdCacheReports503NotUnauthorized(t *testing.T) {
	f := newFakeAuthsvc(t)
	tok := f.mint(t)
	f.breakWith(http.StatusInternalServerError, "down")

	c := newTestClient(t, f)

	h := c.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran with no keys available")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503 — a missing key set is not the caller's fault", rec.Code)
	}
}

func TestFallbackURLUsedOn5xx(t *testing.T) {
	primary := newFakeAuthsvc(t)
	primary.breakWith(http.StatusBadGateway, "down")

	standby := newFakeAuthsvc(t)
	standby.key, standby.pub = primary.key, primary.pub // same keys, as a real standby would have

	c := newTestClient(t, primary, func(cfg *Config) { cfg.FallbackURL = standby.srv.URL })

	if _, err := c.Verify(primary.mint(t)); err != nil {
		t.Fatalf("fallback was not used: %v", err)
	}
	if standby.jwksHits() == 0 {
		t.Fatal("the standby was never contacted")
	}
}

func TestFallbackURLUsedOnConnectionError(t *testing.T) {
	primary := newFakeAuthsvc(t)
	standby := newFakeAuthsvc(t)
	standby.key, standby.pub = primary.key, primary.pub
	tok := primary.mint(t)

	primary.srv.Close() // connection refused

	c := newTestClient(t, primary, func(cfg *Config) { cfg.FallbackURL = standby.srv.URL })
	if _, err := c.Verify(tok); err != nil {
		t.Fatalf("fallback was not used on a connection error: %v", err)
	}
}

// A 4xx is a real answer from a healthy server, so it must not trigger failover.
func TestNoFailoverOn4xx(t *testing.T) {
	primary := newFakeAuthsvc(t)
	primary.breakWith(http.StatusNotFound, "nope")
	standby := newFakeAuthsvc(t)

	c := newTestClient(t, primary, func(cfg *Config) { cfg.FallbackURL = standby.srv.URL })
	c.keys.refresh()

	if standby.jwksHits() != 0 {
		t.Fatal("a 4xx from the primary triggered failover to the standby")
	}
}

// A broken refresh must never discard a working key set.
func TestFailedRefreshKeepsExistingKeys(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)
	tok := f.mint(t)

	if _, err := c.Verify(tok); err != nil {
		t.Fatal(err)
	}

	f.breakWith(http.StatusInternalServerError, "boom")
	c.keys.refresh()

	if _, err := c.Verify(tok); err != nil {
		t.Fatalf("a failed refresh discarded the cached keys: %v", err)
	}
}

// Nor may an empty key set replace a good one.
func TestEmptyJWKSDoesNotReplaceGoodKeys(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)
	tok := f.mint(t)
	if _, err := c.Verify(tok); err != nil {
		t.Fatal(err)
	}

	f.mu.Lock()
	f.pub = jwk.NewSet()
	f.mu.Unlock()
	c.keys.refresh()

	if _, err := c.Verify(tok); err != nil {
		t.Fatalf("an empty JWKS wiped the cache: %v", err)
	}
}

func TestOnErrorReceivesRefreshFailures(t *testing.T) {
	f := newFakeAuthsvc(t)
	f.breakWith(http.StatusInternalServerError, "boom")

	var mu sync.Mutex
	var got []error
	c := newTestClient(t, f, func(cfg *Config) {
		cfg.OnError = func(err error) {
			mu.Lock()
			defer mu.Unlock()
			got = append(got, err)
		}
	})
	c.keys.refresh()

	mu.Lock()
	defer mu.Unlock()
	if len(got) == 0 {
		t.Fatal("OnError was never called for a failing refresh")
	}
}

func TestJWKSMaxStaleRejectsAncientKeys(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f, func(cfg *Config) { cfg.JWKSMaxStale = time.Millisecond })
	tok := f.mint(t)

	f.srv.Close()
	time.Sleep(5 * time.Millisecond)

	_, err := c.Verify(tok)
	if err == nil {
		t.Fatal("keys past JWKSMaxStale were still used")
	}
	if !errors.Is(err, ErrKeysTooStale) {
		t.Fatalf("err = %v, want ErrKeysTooStale", err)
	}
}

// The bound on how long a compromised signing key stays trusted by an app that
// can no longer reach authsvc. It must be finite by default.
func TestJWKSMaxStaleDefaultsToAFiniteBound(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f, func(cfg *Config) { cfg.JWKSMaxStale = 0 })

	if c.cfg.JWKSMaxStale <= 0 {
		t.Fatal("JWKSMaxStale defaulted to unbounded; a leaked key would stay trusted forever")
	}
	if c.cfg.JWKSMaxStale != DefaultJWKSMaxStale {
		t.Fatalf("JWKSMaxStale = %v, want %v", c.cfg.JWKSMaxStale, DefaultJWKSMaxStale)
	}
	// Long enough that an ordinary outage does not break anything.
	if c.cfg.JWKSMaxStale < 24*time.Hour {
		t.Fatalf("JWKSMaxStale = %v, too short to ride out an outage", c.cfg.JWKSMaxStale)
	}
}

func TestNoMaxStaleDisablesExpiry(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f, func(cfg *Config) { cfg.JWKSMaxStale = NoMaxStale })
	tok := f.mint(t)

	f.srv.Close()
	time.Sleep(5 * time.Millisecond)

	if _, err := c.Verify(tok); err != nil {
		t.Fatalf("NoMaxStale still expired the keys: %v", err)
	}
}

// Stale keys are the service's problem, not the caller's — same as a cold cache.
func TestStaleKeysReport503NotUnauthorized(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f, func(cfg *Config) { cfg.JWKSMaxStale = time.Millisecond })
	tok := f.mint(t)

	f.srv.Close()
	time.Sleep(5 * time.Millisecond)

	h := c.RequireUser(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("handler ran with untrustworthy keys")
	}))
	req := httptest.NewRequest("GET", "/", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("status %d, want 503", rec.Code)
	}
}

func TestStartURLShape(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f)

	got := c.StartURL("google", "https://app.test/cb", "st&ate")
	for _, want := range []string{
		f.srv.URL + "/v1/oauth/google/start",
		"client_id=dayflow",
		"redirect_uri=https%3A%2F%2Fapp.test%2Fcb",
		"state=st%26ate",
	} {
		if !contains(got, want) {
			t.Errorf("StartURL missing %q: %s", want, got)
		}
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
