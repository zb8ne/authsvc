package httpapi

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"

	"github.com/yash-sharma-dev/authsvc/internal/notify"
	"github.com/yash-sharma-dev/authsvc/internal/password"
	"github.com/yash-sharma-dev/authsvc/internal/store"
	"github.com/yash-sharma-dev/authsvc/internal/token"
)

// capture records every code the service tries to deliver, so tests can read
// the OTP or reset token the user would have received.
type capture struct {
	mu   sync.Mutex
	sent []sentCode
	fail error
}

type sentCode struct {
	To      string
	Purpose notify.Purpose
	Code    string
}

func (c *capture) SendCode(ctx context.Context, to notify.Address, p notify.Purpose, code string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.fail != nil {
		return c.fail
	}
	c.sent = append(c.sent, sentCode{to.Value, p, code})
	return nil
}

func (c *capture) last(p notify.Purpose) (sentCode, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for i := len(c.sent) - 1; i >= 0; i-- {
		if c.sent[i].Purpose == p {
			return c.sent[i], true
		}
	}
	return sentCode{}, false
}

const adminKey = "test-admin-key"

type rig struct {
	t      *testing.T
	srv    *httptest.Server
	db     *store.DB
	mail   *capture
	signer *token.Signer
	// ip is unique per rig. Rate limits are keyed on the client IP, so without
	// this every test would share one budget and later tests would 429.
	ip string
}

func newRig(t *testing.T) *rig {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)

	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer, err := token.NewSigner(token.Config{
		Issuer:     "https://auth.test",
		AccessTTL:  time.Hour,
		PrivateKey: base64.StdEncoding.EncodeToString(priv.Seed()),
	})
	if err != nil {
		t.Fatal(err)
	}

	mail := &capture{}
	s := New(db, signer, mail, slog.New(slog.NewTextHandler(io.Discard, nil)), Options{
		Issuer: "https://auth.test", AdminAPIKey: adminKey, Secure: false,
	})
	srv := httptest.NewServer(s.Routes())
	t.Cleanup(srv.Close)

	return &rig{t: t, srv: srv, db: db, mail: mail, signer: signer, ip: uniqueIP()}
}

// newClient registers an app client directly in the DB.
func (r *rig) newClient() string {
	r.t.Helper()
	id := "c-" + ulid.Make().String()
	hash, _ := password.Hash("secret")
	err := r.db.CreateClient(context.Background(), store.Client{
		ID: id, Name: "test", SecretHash: hash,
		RedirectURIs: []string{"https://app.test/cb"}, Audience: id,
	})
	if err != nil {
		r.t.Fatal(err)
	}
	return id
}

// Lowercase: the service normalizes emails, so a mixed-case fixture would make
// assertions about the delivered address fail for the wrong reason.
func (r *rig) email() string {
	return "u-" + strings.ToLower(ulid.Make().String()) + "@example.test"
}

type reply struct {
	Status  int
	Body    map[string]any
	Raw     []byte
	Cookies []*http.Cookie
	Header  http.Header
}

func (rp reply) errCode() string {
	if e, ok := rp.Body["error"].(map[string]any); ok {
		s, _ := e["code"].(string)
		return s
	}
	return ""
}

func (rp reply) str(k string) string {
	s, _ := rp.Body[k].(string)
	return s
}

// do issues a request. body may be nil, a map, or a struct.
func (r *rig) do(method, path string, body any, opts ...func(*http.Request)) reply {
	r.t.Helper()
	var buf io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			r.t.Fatal(err)
		}
		buf = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, r.srv.URL+path, buf)
	if err != nil {
		r.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	req.Header.Set("X-Forwarded-For", r.ip)
	// opts run last so a test can deliberately override the source IP.
	for _, o := range opts {
		o(req)
	}

	// No redirect following, no cookie jar: each test states its own intent.
	resp, err := (&http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}).Do(req)
	if err != nil {
		r.t.Fatal(err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	out := reply{Status: resp.StatusCode, Raw: raw, Cookies: resp.Cookies(), Header: resp.Header}
	_ = json.Unmarshal(raw, &out.Body)
	return out
}

func withBearer(tok string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("Authorization", "Bearer "+tok) }
}

func withAdmin() func(*http.Request) { return withBearer(adminKey) }

func withIP(ip string) func(*http.Request) {
	return func(r *http.Request) { r.Header.Set("X-Forwarded-For", ip) }
}

func withCookie(c *http.Cookie) func(*http.Request) {
	return func(r *http.Request) { r.AddCookie(c) }
}

func refreshCookie(rp reply) *http.Cookie {
	for _, c := range rp.Cookies {
		if c.Name == RefreshCookie {
			return c
		}
	}
	return nil
}

// register creates a verified-by-default user and returns the token reply.
func (r *rig) register(clientID, email, pw string) reply {
	return r.do("POST", "/v1/auth/register", map[string]string{
		"client_id": clientID, "email": email, "password": pw,
	})
}

const goodPassword = "correct-horse-battery"

// uniqueIP hands each rig its own source address out of 203.0.113.0/24-ish
// space, widened to a full /8 so collisions across a package run are unlikely.
func uniqueIP() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return fmt.Sprintf("198.%d.%d.%d", b[0], b[1], b[2])
}
