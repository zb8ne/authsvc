package httpapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/zb8ne/authsvc/internal/oauth"
	"github.com/zb8ne/authsvc/internal/store"
)

// fakeProvider stands in for Google/GitHub. It records the challenge it was
// handed at start and the verifier presented at exchange, so tests can assert
// PKCE is actually wired rather than merely present in the URL.
type fakeProvider struct {
	name string

	mu          sync.Mutex
	lastState   string
	challenge   string
	gotVerifier string

	profile *oauth.Profile
	err     error
}

func (f *fakeProvider) Name() string { return f.name }

func (f *fakeProvider) AuthURL(state, challenge string) string {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.lastState, f.challenge = state, challenge
	return "https://provider.test/authorize?state=" + url.QueryEscape(state) +
		"&code_challenge=" + url.QueryEscape(challenge) + "&code_challenge_method=S256"
}

func (f *fakeProvider) Exchange(ctx context.Context, code, verifier string) (*oauth.Profile, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.gotVerifier = verifier
	if f.err != nil {
		return nil, f.err
	}
	p := *f.profile
	return &p, nil
}

func (f *fakeProvider) state() string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.lastState
}

// oauthRig is a rig with a fake provider registered.
type oauthRig struct {
	*rig
	prov   *fakeProvider
	client string
	secret string
}

func newOAuthRig(t *testing.T) *oauthRig {
	r := newRig(t)
	prov := &fakeProvider{
		name: "google",
		profile: &oauth.Profile{
			Subject: "sub-" + strings.ToLower(ulid.Make().String()),
			Email:   r.email(), EmailVerified: true, Name: "Test User",
			Raw: json.RawMessage(`{}`),
		},
	}
	r.server.WithProviders(prov)

	// A client with a known secret, so token exchange can be exercised.
	id := "oauth-" + strings.ToLower(ulid.Make().String())
	rp := r.do("POST", "/v1/admin/clients", map[string]any{
		"id": id, "name": "OAuth App", "redirect_uris": []string{"https://app.test/cb"},
	}, withAdmin())
	if rp.Status != http.StatusCreated {
		t.Fatalf("create client: %d %s", rp.Status, rp.Raw)
	}
	return &oauthRig{rig: r, prov: prov, client: id, secret: rp.str("client_secret")}
}

// start runs the start endpoint and returns the state the provider was given.
func (o *oauthRig) start(extra map[string]string) reply {
	q := url.Values{"client_id": {o.client}, "redirect_uri": {"https://app.test/cb"}}
	for k, v := range extra {
		q.Set(k, v)
	}
	return o.do("GET", "/v1/oauth/google/start?"+q.Encode(), nil)
}

func (o *oauthRig) callback(state, code string) reply {
	q := url.Values{"state": {state}, "code": {code}}
	return o.do("GET", "/v1/oauth/google/callback?"+q.Encode(), nil)
}

// codeFrom pulls the auth code out of a callback's redirect Location.
func codeFrom(t *testing.T, rp reply) (code, appState, errCode string) {
	t.Helper()
	loc := rp.Header.Get("Location")
	if loc == "" {
		t.Fatalf("no Location header on %d: %s", rp.Status, rp.Raw)
	}
	u, err := url.Parse(loc)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	return q.Get("code"), q.Get("state"), q.Get("error")
}

func TestOAuthFullHandoff(t *testing.T) {
	o := newOAuthRig(t)

	st := o.start(map[string]string{"state": "app-state-123"})
	if st.Status != http.StatusFound {
		t.Fatalf("start: %d %s", st.Status, st.Raw)
	}
	loc, _ := url.Parse(st.Header.Get("Location"))
	if loc.Query().Get("code_challenge_method") != "S256" {
		t.Error("PKCE challenge method is not S256")
	}
	if loc.Query().Get("code_challenge") == "" {
		t.Error("no PKCE challenge sent to the provider")
	}

	cb := o.callback(o.prov.state(), "provider-code")
	if cb.Status != http.StatusFound {
		t.Fatalf("callback: %d %s", cb.Status, cb.Raw)
	}
	code, appState, errCode := codeFrom(t, cb)
	if errCode != "" {
		t.Fatalf("callback returned error %q", errCode)
	}
	if code == "" {
		t.Fatal("no auth code in the redirect")
	}
	if appState != "app-state-123" {
		t.Errorf("app state = %q, want it round-tripped", appState)
	}
	if !strings.HasPrefix(cb.Header.Get("Location"), "https://app.test/cb?") {
		t.Errorf("redirected to %q, want the app's registered URI", cb.Header.Get("Location"))
	}

	// The callback must not set a session cookie — it is on the wrong domain.
	if refreshCookie(cb) != nil {
		t.Error("callback set a refresh cookie; the handoff must go through the code exchange")
	}

	// The app's backend exchanges the code.
	ex := o.do("POST", "/v1/token/exchange", map[string]string{
		"code": code, "client_id": o.client, "client_secret": o.secret,
	})
	if ex.Status != http.StatusOK {
		t.Fatalf("exchange: %d %s", ex.Status, ex.Raw)
	}
	if ex.str("access_token") == "" || ex.str("refresh_token") == "" {
		t.Fatal("exchange returned no tokens")
	}

	me := o.do("GET", "/v1/me", nil, withBearer(ex.str("access_token")))
	if me.str("email") != o.prov.profile.Email {
		t.Fatalf("me = %s, want the provider's email", me.Raw)
	}
}

// The verifier must never leave the server; only its hash goes to the provider.
func TestPKCEVerifierMatchesChallenge(t *testing.T) {
	o := newOAuthRig(t)
	o.start(nil)

	o.prov.mu.Lock()
	challenge := o.prov.challenge
	o.prov.mu.Unlock()

	o.callback(o.prov.state(), "provider-code")

	o.prov.mu.Lock()
	verifier := o.prov.gotVerifier
	o.prov.mu.Unlock()

	if verifier == "" {
		t.Fatal("no code_verifier presented at exchange")
	}
	if oauth.Challenge(verifier) != challenge {
		t.Fatalf("verifier does not hash to the challenge sent at start")
	}
	if strings.Contains(challenge, verifier) {
		t.Fatal("the challenge contains the raw verifier")
	}
}

func TestStateIsSingleUse(t *testing.T) {
	o := newOAuthRig(t)
	o.start(nil)
	state := o.prov.state()

	if rp := o.callback(state, "code-1"); rp.Status != http.StatusFound {
		t.Fatalf("first callback: %d %s", rp.Status, rp.Raw)
	}
	replay := o.callback(state, "code-2")
	if replay.errCode() != "invalid_state" {
		t.Fatalf("replayed state accepted: %d %s", replay.Status, replay.Raw)
	}
}

func TestCallbackRejectsForgedState(t *testing.T) {
	o := newOAuthRig(t)
	o.start(nil)

	rp := o.callback("a-state-we-never-issued", "code")
	if rp.errCode() != "invalid_state" {
		t.Fatalf("forged state accepted: %d %s", rp.Status, rp.Raw)
	}
}

func TestStartRejectsUnregisteredRedirect(t *testing.T) {
	o := newOAuthRig(t)
	rp := o.start(map[string]string{"redirect_uri": "https://evil.test/steal"})
	if rp.errCode() != "invalid_redirect_uri" {
		t.Fatalf("unregistered redirect accepted: %d %s", rp.Status, rp.Raw)
	}
}

func TestStartRejectsUnknownProvider(t *testing.T) {
	o := newOAuthRig(t)
	rp := o.do("GET", "/v1/oauth/facebook/start?client_id="+o.client, nil)
	if rp.Status != http.StatusNotFound {
		t.Fatalf("unconfigured provider returned %d", rp.Status)
	}
}

func TestAuthCodeIsSingleUse(t *testing.T) {
	o := newOAuthRig(t)
	o.start(nil)
	cb := o.callback(o.prov.state(), "provider-code")
	code, _, _ := codeFrom(t, cb)

	body := map[string]string{"code": code, "client_id": o.client, "client_secret": o.secret}
	if rp := o.do("POST", "/v1/token/exchange", body); rp.Status != http.StatusOK {
		t.Fatalf("first exchange: %d %s", rp.Status, rp.Raw)
	}
	if rp := o.do("POST", "/v1/token/exchange", body); rp.Status == http.StatusOK {
		t.Fatal("auth code was redeemable twice")
	}
}

func TestExchangeRequiresCorrectClientSecret(t *testing.T) {
	o := newOAuthRig(t)
	o.start(nil)
	cb := o.callback(o.prov.state(), "provider-code")
	code, _, _ := codeFrom(t, cb)

	rp := o.do("POST", "/v1/token/exchange", map[string]string{
		"code": code, "client_id": o.client, "client_secret": "wrong-secret",
	})
	if rp.errCode() != "invalid_client" {
		t.Fatalf("bad secret accepted: %d %s", rp.Status, rp.Raw)
	}
	// And the code must survive, unredeemed, for the legitimate caller.
	if ok := o.do("POST", "/v1/token/exchange", map[string]string{
		"code": code, "client_id": o.client, "client_secret": o.secret,
	}); ok.Status != http.StatusOK {
		t.Fatalf("a failed auth attempt burned the code: %d %s", ok.Status, ok.Raw)
	}
}

// A code issued to one app must not be redeemable by another, even by an app
// presenting its own perfectly valid credentials.
func TestAuthCodeIsBoundToItsClient(t *testing.T) {
	o := newOAuthRig(t)

	otherID := "other-" + strings.ToLower(ulid.Make().String())
	other := o.do("POST", "/v1/admin/clients", map[string]any{
		"id": otherID, "name": "Other", "redirect_uris": []string{"https://other.test/cb"},
	}, withAdmin())

	o.start(nil)
	cb := o.callback(o.prov.state(), "provider-code")
	code, _, _ := codeFrom(t, cb)

	rp := o.do("POST", "/v1/token/exchange", map[string]string{
		"code": code, "client_id": otherID, "client_secret": other.str("client_secret"),
	})
	if rp.Status == http.StatusOK {
		t.Fatal("another client redeemed a code that was not issued to it")
	}
}

func TestExchangeRejectsUnknownCode(t *testing.T) {
	o := newOAuthRig(t)
	rp := o.do("POST", "/v1/token/exchange", map[string]string{
		"code": "never-issued", "client_id": o.client, "client_secret": o.secret,
	})
	if rp.errCode() != "invalid_code" {
		t.Fatalf("got %q (%d)", rp.errCode(), rp.Status)
	}
}

// A refused auto-link must come back to the app as an error, not a session.
func TestCallbackSurfacesManualLinkRequired(t *testing.T) {
	o := newOAuthRig(t)
	ctx := context.Background()

	// A verified local account already owns the address...
	victim, err := o.db.CreateUser(ctx, o.prov.profile.Email, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := o.db.MarkEmailVerified(ctx, victim.ID); err != nil {
		t.Fatal(err)
	}
	// ...and the provider will not vouch for it.
	o.prov.mu.Lock()
	o.prov.profile.EmailVerified = false
	o.prov.mu.Unlock()

	o.start(nil)
	cb := o.callback(o.prov.state(), "provider-code")
	code, _, errCode := codeFrom(t, cb)

	if errCode != "manual_link_required" {
		t.Fatalf("error = %q, want manual_link_required", errCode)
	}
	if code != "" {
		t.Fatal("an auth code was issued despite the refused link")
	}
}

func TestCallbackPropagatesProviderDenial(t *testing.T) {
	o := newOAuthRig(t)
	o.start(map[string]string{"state": "app-1"})

	q := url.Values{"state": {o.prov.state()}, "error": {"access_denied"}}
	rp := o.do("GET", "/v1/oauth/google/callback?"+q.Encode(), nil)

	_, appState, errCode := codeFrom(t, rp)
	if errCode != "access_denied" {
		t.Fatalf("error = %q, want access_denied passed through", errCode)
	}
	if appState != "app-1" {
		t.Errorf("app state = %q, want it preserved on the error path", appState)
	}
}

func TestCallbackHandlesExchangeFailure(t *testing.T) {
	o := newOAuthRig(t)
	o.prov.mu.Lock()
	o.prov.err = errString("provider is down")
	o.prov.mu.Unlock()

	o.start(nil)
	cb := o.callback(o.prov.state(), "code")
	_, _, errCode := codeFrom(t, cb)
	if errCode != "exchange_failed" {
		t.Fatalf("error = %q, want exchange_failed", errCode)
	}
}

// Signing in twice through the provider must reuse the account, not make two.
func TestRepeatOAuthLoginResolvesToSameUser(t *testing.T) {
	o := newOAuthRig(t)

	login := func() string {
		o.start(nil)
		cb := o.callback(o.prov.state(), "provider-code")
		code, _, _ := codeFrom(t, cb)
		ex := o.do("POST", "/v1/token/exchange", map[string]string{
			"code": code, "client_id": o.client, "client_secret": o.secret,
		})
		me := o.do("GET", "/v1/me", nil, withBearer(ex.str("access_token")))
		return me.str("id")
	}

	if a, b := login(), login(); a != b {
		t.Fatalf("two logins produced different users: %s and %s", a, b)
	}
}

func TestLinkFlowRequiresAuth(t *testing.T) {
	o := newOAuthRig(t)
	rp := o.do("GET", "/v1/me/link/google/start?client_id="+o.client, nil)
	if rp.Status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated link start returned %d", rp.Status)
	}
}

func TestLinkFlowAttachesIdentityToSignedInUser(t *testing.T) {
	o := newOAuthRig(t)
	reg := o.register(o.client, o.email(), goodPassword)
	access := reg.str("access_token")

	q := url.Values{"client_id": {o.client}, "redirect_uri": {"https://app.test/cb"}}
	st := o.do("GET", "/v1/me/link/google/start?"+q.Encode(), nil, withBearer(access))
	if st.Status != http.StatusFound {
		t.Fatalf("link start: %d %s", st.Status, st.Raw)
	}

	cb := o.callback(o.prov.state(), "provider-code")
	if _, _, errCode := codeFrom(t, cb); errCode != "" {
		t.Fatalf("link callback errored: %q", errCode)
	}

	me := o.do("GET", "/v1/me", nil, withBearer(access))
	ids, err := o.db.IdentitiesForUser(context.Background(), me.str("id"))
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 1 || ids[0].Provider != "google" {
		t.Fatalf("identity not linked to the signed-in user: %+v", ids)
	}
	// Linking must not silently adopt the provider's address.
	if me.str("email") == o.prov.profile.Email {
		t.Error("linking overwrote the user's own email with the provider's")
	}
}

func TestOAuthFlowExpires(t *testing.T) {
	o := newOAuthRig(t)
	o.start(nil)
	state := o.prov.state()

	// Fast-forward past the flow TTL.
	o.db.SetNow(func() time.Time { return time.Now().Add(store.OAuthFlowTTL + time.Minute) })
	defer o.db.SetNow(time.Now)

	if rp := o.callback(state, "code"); rp.errCode() != "invalid_state" {
		t.Fatalf("an expired flow was accepted: %d %s", rp.Status, rp.Raw)
	}
}
