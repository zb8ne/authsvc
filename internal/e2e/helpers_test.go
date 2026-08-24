package e2e

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"testing"
)

func jsonUnmarshal(b []byte, v any) error { return json.Unmarshal(b, v) }

func postJSON(t *testing.T, url string, body map[string]string) []byte {
	t.Helper()
	raw, _ := json.Marshal(body)
	resp, err := http.Post(url, "application/json", bytes.NewReader(raw))
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
