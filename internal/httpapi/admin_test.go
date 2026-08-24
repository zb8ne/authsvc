package httpapi

import (
	"net/http"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"

	"github.com/zb8ne/authsvc/internal/password"
)

func TestCreateClientReturnsSecretOnceAndStoresOnlyAHash(t *testing.T) {
	r := newRig(t)
	id := "app-" + strings.ToLower(ulid.Make().String())

	rp := r.do("POST", "/v1/admin/clients", map[string]any{
		"id": id, "name": "Test App", "redirect_uris": []string{"https://app.test/cb"},
	}, withAdmin())
	if rp.Status != http.StatusCreated {
		t.Fatalf("%d %s", rp.Status, rp.Raw)
	}
	secret := rp.str("client_secret")
	if secret == "" {
		t.Fatal("no client_secret returned")
	}
	if rp.str("audience") != id {
		t.Errorf("audience defaulted to %q, want the client id", rp.str("audience"))
	}

	c, err := r.db.ClientByID(t.Context(), id)
	if err != nil {
		t.Fatal(err)
	}
	if c.SecretHash == secret {
		t.Fatal("the client secret is stored in plaintext")
	}
	ok, err := password.Verify(c.SecretHash, secret)
	if err != nil || !ok {
		t.Fatalf("stored hash does not verify the issued secret: ok=%v err=%v", ok, err)
	}

	// The secret must never appear again.
	list := r.do("GET", "/v1/admin/clients", nil, withAdmin())
	if strings.Contains(string(list.Raw), secret) {
		t.Fatal("the client list echoes the secret")
	}
	if strings.Contains(string(list.Raw), "secret_hash") {
		t.Fatal("the client list exposes secret_hash")
	}
}

func TestAdminRequiresKey(t *testing.T) {
	r := newRig(t)
	for _, opt := range []func(*http.Request){
		func(*http.Request) {},
		withBearer("wrong-key"),
	} {
		if rp := r.do("GET", "/v1/admin/clients", nil, opt); rp.Status != http.StatusUnauthorized {
			t.Errorf("admin endpoint returned %d without a valid key", rp.Status)
		}
	}
}

func TestCreateClientValidatesRedirectURIs(t *testing.T) {
	r := newRig(t)
	bad := []string{
		"http://evil.test/cb",      // plaintext, not localhost
		"/relative/cb",             // not absolute
		"https://app.test/cb#frag", // fragment
		"https://*.app.test/cb",    // wildcard
		"::::not a url",
	}
	for _, uri := range bad {
		rp := r.do("POST", "/v1/admin/clients", map[string]any{
			"id": "x-" + strings.ToLower(ulid.Make().String()), "name": "n",
			"redirect_uris": []string{uri},
		}, withAdmin())
		if rp.Status != http.StatusBadRequest {
			t.Errorf("redirect_uri %q was accepted (%d)", uri, rp.Status)
		}
	}

	// http on localhost is allowed, because that is where development lives.
	rp := r.do("POST", "/v1/admin/clients", map[string]any{
		"id": "local-" + strings.ToLower(ulid.Make().String()), "name": "n",
		"redirect_uris": []string{"http://localhost:3000/cb"},
	}, withAdmin())
	if rp.Status != http.StatusCreated {
		t.Errorf("http://localhost was rejected: %d %s", rp.Status, rp.Raw)
	}
}

func TestCreateClientRejectsDuplicateID(t *testing.T) {
	r := newRig(t)
	id := "dup-" + strings.ToLower(ulid.Make().String())
	body := map[string]any{"id": id, "name": "n", "redirect_uris": []string{"https://a.test/cb"}}

	if rp := r.do("POST", "/v1/admin/clients", body, withAdmin()); rp.Status != http.StatusCreated {
		t.Fatalf("first create: %d", rp.Status)
	}
	if rp := r.do("POST", "/v1/admin/clients", body, withAdmin()); rp.Status != http.StatusConflict {
		t.Fatalf("duplicate create returned %d, want 409", rp.Status)
	}
}
