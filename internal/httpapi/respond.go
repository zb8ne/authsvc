package httpapi

import (
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"strings"
)

// maxBody caps request bodies. Auth payloads are tiny; anything larger is abuse.
const maxBody = 64 << 10

type errBody struct {
	Error errDetail `json:"error"`
}

type errDetail struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	if v != nil {
		_ = json.NewEncoder(w).Encode(v)
	}
}

// writeJSONNoStore writes JSON without clobbering a Cache-Control already set
// by the caller (the JWKS endpoint wants to be cached).
func writeJSONNoStore(w http.ResponseWriter, status int, v any) {
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeErr(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, errBody{errDetail{code, msg}})
}

// decode reads a JSON body with a size cap and rejects unknown fields, so a
// typo'd field name fails loudly instead of silently defaulting.
func decode(w http.ResponseWriter, r *http.Request, dst any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, maxBody)
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(dst); err != nil {
		writeErr(w, http.StatusBadRequest, "invalid_request", "malformed JSON body")
		return false
	}
	if err := dec.Decode(&struct{}{}); !errors.Is(err, io.EOF) {
		writeErr(w, http.StatusBadRequest, "invalid_request", "body must contain a single JSON object")
		return false
	}
	return true
}

func (s *Server) internal(w http.ResponseWriter, r *http.Request, msg string, err error) {
	s.log.ErrorContext(r.Context(), msg, "err", err, "path", r.URL.Path)
	writeErr(w, http.StatusInternalServerError, "internal", "something went wrong")
}

func normalizeEmail(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// validEmail is deliberately loose. Real validation is "we sent a code and you
// read it"; anything stricter mostly rejects valid addresses.
func validEmail(s string) bool {
	at := strings.IndexByte(s, '@')
	if at <= 0 || at == len(s)-1 {
		return false
	}
	if strings.ContainsAny(s, " \r\n\t") {
		return false
	}
	return strings.Contains(s[at+1:], ".")
}

// MinPasswordLen: length is the only requirement that reliably helps. Composition
// rules push users toward predictable substitutions.
const MinPasswordLen = 10

func clientIP(r *http.Request) string {
	if f := r.Header.Get("X-Forwarded-For"); f != "" {
		if i := strings.IndexByte(f, ','); i > 0 {
			return strings.TrimSpace(f[:i])
		}
		return strings.TrimSpace(f)
	}
	host := r.RemoteAddr
	if i := strings.LastIndexByte(host, ':'); i > 0 {
		return host[:i]
	}
	return host
}

func logAttrs(r *http.Request) []slog.Attr {
	return []slog.Attr{slog.String("path", r.URL.Path), slog.String("ip", clientIP(r))}
}

// decodeQuiet decodes without writing an error response; used where a missing
// or malformed body is an acceptable, non-fatal case.
func decodeQuiet(r *http.Request, dst any) error {
	return json.NewDecoder(r.Body).Decode(dst)
}
