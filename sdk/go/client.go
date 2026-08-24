package authsdk

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

const maxRespBody = 1 << 20

func (c *Client) do(req *http.Request) ([]byte, error) {
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxRespBody))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return nil, &httpStatusError{Status: resp.StatusCode, Body: string(body)}
	}
	return body, nil
}

func (c *Client) postWithFallback(ctx context.Context, path string, payload any, out any) error {
	raw, err := json.Marshal(payload)
	if err != nil {
		return err
	}

	body, err := c.postOnce(ctx, c.cfg.BaseURL+path, raw)
	if err != nil && c.cfg.FallbackURL != "" && shouldFailOver(err) {
		body, err = c.postOnce(ctx, c.cfg.FallbackURL+path, raw)
	}
	if err != nil {
		return err
	}
	if out == nil {
		return nil
	}
	return json.Unmarshal(body, out)
}

func (c *Client) postOnce(ctx context.Context, url string, raw []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

// Session is what an app receives after a successful login or refresh. The
// refresh token is the app's to store — typically in its own httpOnly cookie.
type Session struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	User         User   `json:"user"`
}

// Exchange trades an OAuth authorization code for a session. This must run on
// the app's backend: it presents the client secret.
func (c *Client) Exchange(ctx context.Context, code string) (*Session, error) {
	if c.cfg.ClientSecret == "" {
		return nil, fmt.Errorf("authsdk: ClientSecret is required to exchange a code")
	}
	var s Session
	err := c.postWithFallback(ctx, "/v1/token/exchange", map[string]string{
		"code": code, "client_id": c.cfg.ClientID, "client_secret": c.cfg.ClientSecret,
	}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Refresh rotates a refresh token. The returned token replaces the old one:
// authsvc revokes the whole session family if a spent token is presented again.
func (c *Client) Refresh(ctx context.Context, refreshToken string) (*Session, error) {
	var s Session
	err := c.postWithFallback(ctx, "/v1/token/refresh", map[string]string{
		"refresh_token": refreshToken,
	}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// Login authenticates with email and password.
func (c *Client) Login(ctx context.Context, email, password string) (*Session, error) {
	var s Session
	err := c.postWithFallback(ctx, "/v1/auth/login", map[string]string{
		"client_id": c.cfg.ClientID, "email": email, "password": password,
	}, &s)
	if err != nil {
		return nil, err
	}
	return &s, nil
}

// StartURL is where to send a browser to begin an OAuth login. state is
// returned to the callback unchanged; use it to carry the post-login
// destination and your own CSRF token.
func (c *Client) StartURL(provider, redirectURI, state string) string {
	return fmt.Sprintf("%s/v1/oauth/%s/start?client_id=%s&redirect_uri=%s&state=%s",
		c.cfg.BaseURL, urlEscape(provider), urlEscape(c.cfg.ClientID),
		urlEscape(redirectURI), urlEscape(state))
}
