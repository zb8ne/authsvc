package httpapi

import (
	"net/http"
	"net/url"
	"strings"

	"github.com/yash-sharma-dev/authsvc/internal/password"
	"github.com/yash-sharma-dev/authsvc/internal/store"
)

type createClientReq struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	RedirectURIs []string `json:"redirect_uris"`
	Audience     string   `json:"audience"`
}

type createClientResp struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	Audience     string   `json:"audience"`
	RedirectURIs []string `json:"redirect_uris"`
	// Secret is returned exactly once, at creation. Only its hash is stored.
	Secret string `json:"client_secret"`
}

func (s *Server) handleCreateClient(w http.ResponseWriter, r *http.Request) {
	var req createClientReq
	if !decode(w, r, &req) {
		return
	}
	if req.ID == "" || req.Name == "" {
		writeErr(w, http.StatusBadRequest, "invalid_request", "id and name are required")
		return
	}
	if req.Audience == "" {
		req.Audience = req.ID
	}
	for _, u := range req.RedirectURIs {
		if err := validRedirect(u); err != nil {
			writeErr(w, http.StatusBadRequest, "invalid_redirect_uri", err.Error())
			return
		}
	}

	secret, err := store.NewOpaqueToken()
	if err != nil {
		s.internal(w, r, "mint client secret", err)
		return
	}
	hash, err := password.Hash(secret)
	if err != nil {
		s.internal(w, r, "hash client secret", err)
		return
	}

	c := store.Client{
		ID: req.ID, Name: req.Name, SecretHash: hash,
		RedirectURIs: req.RedirectURIs, Audience: req.Audience,
	}
	if c.RedirectURIs == nil {
		c.RedirectURIs = []string{}
	}
	if err := s.db.CreateClient(r.Context(), c); err != nil {
		writeErr(w, http.StatusConflict, "client_exists", "a client with that id already exists")
		return
	}

	writeJSON(w, http.StatusCreated, createClientResp{
		ID: c.ID, Name: c.Name, Audience: c.Audience, RedirectURIs: c.RedirectURIs, Secret: secret,
	})
}

func (s *Server) handleListClients(w http.ResponseWriter, r *http.Request) {
	rows, err := s.db.ListClients(r.Context())
	if err != nil {
		s.internal(w, r, "list clients", err)
		return
	}
	out := make([]map[string]any, 0, len(rows))
	for _, c := range rows {
		// Never echo secret_hash, even to an admin.
		out = append(out, map[string]any{
			"id": c.ID, "name": c.Name, "audience": c.Audience, "redirect_uris": c.RedirectURIs,
		})
	}
	writeJSON(w, http.StatusOK, map[string]any{"clients": out})
}

// validRedirect enforces absolute https URLs without fragments. http is allowed
// only for localhost, which is where local development lives.
func validRedirect(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return errString("redirect_uri is not a valid URL")
	}
	if !u.IsAbs() || u.Host == "" {
		return errString("redirect_uri must be absolute")
	}
	if u.Fragment != "" {
		return errString("redirect_uri must not contain a fragment")
	}
	host := u.Hostname()
	isLocal := host == "localhost" || host == "127.0.0.1" || host == "::1"
	if u.Scheme != "https" && !(u.Scheme == "http" && isLocal) {
		return errString("redirect_uri must use https (http is allowed only for localhost)")
	}
	if strings.Contains(raw, "*") {
		return errString("wildcards are not allowed in redirect_uri")
	}
	return nil
}

type errString string

func (e errString) Error() string { return string(e) }
