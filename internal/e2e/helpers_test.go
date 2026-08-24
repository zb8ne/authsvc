package e2e

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

// uniqueIP gives each test env its own source address.
//
// Rate limits are keyed on the client IP, and every request in a test binary
// otherwise arrives from 127.0.0.1 — so tests would share one budget and start
// failing with 429 once the suite had been run a few times. Real deployments
// sit behind a proxy that sets this header, so this also exercises the path
// production actually takes.
func uniqueIP() string {
	var b [3]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(err)
	}
	return fmt.Sprintf("198.%d.%d.%d", b[0], b[1], b[2])
}

// ipTransport stamps every outgoing request with a fixed source IP.
type ipTransport struct {
	ip   string
	base http.RoundTripper
}

func (t ipTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	r.Header.Set("X-Forwarded-For", t.ip)
	base := t.base
	if base == nil {
		base = http.DefaultTransport
	}
	return base.RoundTrip(r)
}

func newIPClient(ip string) *http.Client {
	return &http.Client{Transport: ipTransport{ip: ip}}
}

// noRedirect is for asserting on Location headers rather than following them.
func newIPClientNoRedirect(ip string) *http.Client {
	c := newIPClient(ip)
	c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return c
}

func (e *env) postJSON(t *testing.T, url string, body map[string]string) []byte {
	t.Helper()
	raw, _ := json.Marshal(body)
	req, err := http.NewRequest("POST", url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	out, _ := io.ReadAll(resp.Body)
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		t.Fatalf("POST %s: %d %s", url, resp.StatusCode, out)
	}
	return out
}

func (e *env) get(t *testing.T, url, bearer string) (int, string) {
	t.Helper()
	req, _ := http.NewRequest("GET", url, nil)
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b)
}
