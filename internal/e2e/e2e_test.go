// Package e2e drives the real SDK against the real server. Everything else is
// tested in isolation; this is the only place the two halves meet, and it is
// what catches a contract drifting apart.
package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/zb8ne/authsvc/internal/httpapi"
	"github.com/zb8ne/authsvc/internal/notify"
	"github.com/zb8ne/authsvc/internal/oauth"
	"github.com/zb8ne/authsvc/internal/store"
	"github.com/zb8ne/authsvc/internal/token"
	authsdk "github.com/zb8ne/authsvc/sdk/go"
)

type nullSender struct{}

func (nullSender) SendCode(context.Context, notify.Address, notify.Purpose, string) error { return nil }

// stubProvider stands in for Google so the OAuth path can run offline.
type stubProvider struct {
	state   string
	profile *oauth.Profile
}

func (s *stubProvider) Name() string { return "google" }
func (s *stubProvider) AuthURL(state, challenge string) string {
	s.state = state
	return "https://provider.test/auth?state=" + url.QueryEscape(state)
}
func (s *stubProvider) Exchange(ctx context.Context, code, verifier string) (*oauth.Profile, error) {
	p := *s.profile
	return &p, nil
}

type env struct {
	auth     *httptest.Server
	db       *store.DB
	sdk      *authsdk.Client
	clientID string
	secret   string
	prov     *stubProvider
	// ip is this env's source address; see uniqueIP.
	ip     string
	client *http.Client
}

func setup(t *testing.T) *env {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)

	// The issuer must match the server's own URL, which is only known after
	// the test server starts — so build the handler against a placeholder and
	// re-create the signer once the address is known.
	var srv *httptest.Server
	srv = httptest.NewUnstartedServer(nil)
	issuer := "http://" + srv.Listener.Addr().String()

	signer, err := token.NewSigner(token.Config{
		Issuer: issuer, AccessTTL: time.Hour,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
	})
	if err != nil {
		t.Fatal(err)
	}

	prov := &stubProvider{profile: &oauth.Profile{
		Subject:       "sub-" + strings.ToLower(ulid.Make().String()),
		Email:         "oauth-" + strings.ToLower(ulid.Make().String()) + "@example.test",
		EmailVerified: true,
	}}

	const adminKey = "e2e-admin"
	api := httpapi.New(db, signer, nullSender{}, slog.New(slog.NewTextHandler(io.Discard, nil)),
		httpapi.Options{Issuer: issuer, AdminAPIKey: adminKey, Secure: false}).
		WithProviders(prov)

	srv.Config.Handler = api.Routes()
	srv.Start()
	t.Cleanup(srv.Close)

	ip := uniqueIP()
	client := newIPClient(ip)

	// Register the app the way an operator would: one admin call, no console.
	clientID := "e2e-" + strings.ToLower(ulid.Make().String())
	body := `{"id":"` + clientID + `","name":"E2E","redirect_uris":["https://app.test/cb"]}`
	req, _ := http.NewRequest("POST", srv.URL+"/v1/admin/clients", strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+adminKey)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("create client: %d %s", resp.StatusCode, raw)
	}
	secret := jsonField(t, raw, "client_secret")

	sdk, err := authsdk.New(authsdk.Config{
		BaseURL:      srv.URL,
		ClientID:     clientID,
		ClientSecret: secret,
		Audience:     clientID,
		Issuer:       issuer,
		HTTPClient:   client,
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(sdk.Close)

	return &env{auth: srv, db: db, sdk: sdk, clientID: clientID, secret: secret,
		prov: prov, ip: ip, client: client}
}

func jsonField(t *testing.T, raw []byte, key string) string {
	t.Helper()
	var m map[string]any
	if err := jsonUnmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	s, _ := m[key].(string)
	if s == "" {
		t.Fatalf("no %q in %s", key, raw)
	}
	return s
}

// protectedApp is a miniature consumer app guarded by the SDK.
func (e *env) protectedApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.Handle("GET /whoami", e.sdk.RequireUser(http.HandlerFunc(
		func(w http.ResponseWriter, r *http.Request) {
			u, _ := authsdk.UserFrom(r.Context())
			w.Write([]byte(u.ID + " " + u.Email))
		})))
	mux.Handle("GET /admin", e.sdk.RequireUser(e.sdk.RequireRole("admin")(
		http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte("admin ok"))
		}))))
	return httptest.NewServer(mux)
}

func TestSDKVerifiesRealServerTokens(t *testing.T) {
	e := setup(t)
	app := e.protectedApp()
	defer app.Close()

	email := "user-" + strings.ToLower(ulid.Make().String()) + "@example.test"
	reg := e.postJSON(t, e.auth.URL+"/v1/auth/register", map[string]string{
		"client_id": e.clientID, "email": email, "password": "a-good-long-password",
	})
	access := jsonField(t, reg, "access_token")

	status, body := e.get(t, app.URL+"/whoami", access)
	if status != http.StatusOK {
		t.Fatalf("protected route rejected a real token: %d %s", status, body)
	}
	if !strings.Contains(body, email) {
		t.Fatalf("app saw %q, want the user's email", body)
	}

	// No roles on the token, so the admin route must refuse.
	if status, _ := e.get(t, app.URL+"/admin", access); status != http.StatusForbidden {
		t.Fatalf("admin route returned %d for a roleless token, want 403", status)
	}
}

func TestSDKRejectsAnotherClientsToken(t *testing.T) {
	a, b := setup(t), setup(t)
	app := a.protectedApp()
	defer app.Close()

	email := "user-" + strings.ToLower(ulid.Make().String()) + "@example.test"
	reg := b.postJSON(t, b.auth.URL+"/v1/auth/register", map[string]string{
		"client_id": b.clientID, "email": email, "password": "a-good-long-password",
	})

	status, _ := a.get(t, app.URL+"/whoami", jsonField(t, reg, "access_token"))
	if status != http.StatusUnauthorized {
		t.Fatalf("app A accepted a token minted for app B: %d", status)
	}
}

// The full OAuth handoff, driven through the SDK's callback handler.
func TestSDKOAuthCallbackHandoff(t *testing.T) {
	e := setup(t)

	var got *authsdk.Session
	cb := httptest.NewServer(e.sdk.HandleCallback(
		func(w http.ResponseWriter, r *http.Request, s *authsdk.Session) {
			got = s
			w.WriteHeader(http.StatusOK)
		}))
	defer cb.Close()

	// 1. Start: the browser is sent to the provider.
	startURL := e.sdk.StartURL("google", "https://app.test/cb", "my-state")
	resp, err := newIPClientNoRedirect(e.ip).Get(startURL)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusFound {
		t.Fatalf("start returned %d", resp.StatusCode)
	}

	// 2. The provider redirects back to authsvc's callback, which issues a code.
	q := url.Values{"state": {e.prov.state}, "code": {"provider-code"}}
	resp2, err := newIPClientNoRedirect(e.ip).Get(e.auth.URL + "/v1/oauth/google/callback?" + q.Encode())
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()

	loc, _ := url.Parse(resp2.Header.Get("Location"))
	code := loc.Query().Get("code")
	if code == "" {
		t.Fatalf("no code in redirect %q", resp2.Header.Get("Location"))
	}
	if loc.Query().Get("state") != "my-state" {
		t.Errorf("state not round-tripped: %q", loc.Query().Get("state"))
	}

	// 3. The app's own callback exchanges it server-side.
	status, body := e.get(t, cb.URL+"?code="+url.QueryEscape(code)+"&state=my-state", "")
	if status != http.StatusOK {
		t.Fatalf("SDK callback: %d %s", status, body)
	}
	if got == nil || got.AccessToken == "" {
		t.Fatal("SDK produced no session")
	}
	if got.User.Email != e.prov.profile.Email {
		t.Fatalf("session user = %q, want the provider's email", got.User.Email)
	}

	// And the session it produced actually works.
	app := e.protectedApp()
	defer app.Close()
	if s, b := e.get(t, app.URL+"/whoami", got.AccessToken); s != http.StatusOK {
		t.Fatalf("SDK-produced token rejected by the app: %d %s", s, b)
	}
}

func TestSDKCallbackSurfacesRefusedLink(t *testing.T) {
	e := setup(t)

	var gotCode string
	cb := httptest.NewServer(e.sdk.HandleCallbackWithError(
		func(w http.ResponseWriter, r *http.Request, s *authsdk.Session) {
			t.Error("session handler ran for a refused login")
		},
		func(w http.ResponseWriter, r *http.Request, code authsdk.CallbackError, err error) {
			gotCode = string(code)
			w.WriteHeader(http.StatusUnauthorized)
		}))
	defer cb.Close()

	e.get(t, cb.URL+"?error=manual_link_required&state=x", "")
	if gotCode != "manual_link_required" {
		t.Fatalf("error handler saw %q, want manual_link_required", gotCode)
	}
}

func TestSDKRefreshRotates(t *testing.T) {
	e := setup(t)
	ctx := context.Background()

	email := "user-" + strings.ToLower(ulid.Make().String()) + "@example.test"
	reg := e.postJSON(t, e.auth.URL+"/v1/auth/register", map[string]string{
		"client_id": e.clientID, "email": email, "password": "a-good-long-password",
	})
	first := jsonField(t, reg, "refresh_token")

	s, err := e.sdk.Refresh(ctx, first)
	if err != nil {
		t.Fatal(err)
	}
	if s.RefreshToken == first {
		t.Fatal("refresh did not rotate the token")
	}

	// Replaying the spent token must kill the family, through the SDK too.
	if _, err := e.sdk.Refresh(ctx, first); err == nil {
		t.Fatal("a spent refresh token was accepted")
	}
	if _, err := e.sdk.Refresh(ctx, s.RefreshToken); err == nil {
		t.Fatal("the live token still works after reuse detection")
	}
}

func TestSDKLogin(t *testing.T) {
	e := setup(t)
	email := "user-" + strings.ToLower(ulid.Make().String()) + "@example.test"
	e.postJSON(t, e.auth.URL+"/v1/auth/register", map[string]string{
		"client_id": e.clientID, "email": email, "password": "a-good-long-password",
	})

	s, err := e.sdk.Login(context.Background(), email, "a-good-long-password")
	if err != nil {
		t.Fatal(err)
	}
	if s.User.Email != email {
		t.Fatalf("logged in as %q", s.User.Email)
	}
	if _, err := e.sdk.Login(context.Background(), email, "wrong-password"); err == nil {
		t.Fatal("a wrong password logged in")
	}
}

// Revoking a session server-side must stop the token at authsvc, even though
// the SDK keeps verifying it locally until it expires. This is the documented
// tradeoff of the 1h TTL and it should be visible, not surprising.
func TestRevokedSessionStillVerifiesLocallyUntilExpiry(t *testing.T) {
	e := setup(t)
	app := e.protectedApp()
	defer app.Close()

	email := "user-" + strings.ToLower(ulid.Make().String()) + "@example.test"
	reg := e.postJSON(t, e.auth.URL+"/v1/auth/register", map[string]string{
		"client_id": e.clientID, "email": email, "password": "a-good-long-password",
	})
	access := jsonField(t, reg, "access_token")

	req, _ := http.NewRequest("POST", e.auth.URL+"/v1/auth/logout", nil)
	req.Header.Set("Authorization", "Bearer "+access)
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	// authsvc itself refuses immediately.
	if s, _ := e.get(t, e.auth.URL+"/v1/me", access); s != http.StatusUnauthorized {
		t.Fatalf("authsvc still accepted a revoked session: %d", s)
	}
	// The SDK, verifying locally, does not know yet. Asserted so a future
	// change to this behaviour is a deliberate decision rather than a surprise.
	if s, _ := e.get(t, app.URL+"/whoami", access); s != http.StatusOK {
		t.Fatalf("local verification changed behaviour: got %d", s)
	}
}
