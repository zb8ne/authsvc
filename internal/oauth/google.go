package oauth

import (
	"context"
	"encoding/json"
	"fmt"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
)

type Google struct {
	cfg *oauth2.Config
}

func NewGoogle(clientID, clientSecret, redirectURL string) *Google {
	return &Google{cfg: &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     google.Endpoint,
		Scopes:       []string{"openid", "email", "profile"},
	}}
}

func (g *Google) Name() string { return "google" }

func (g *Google) AuthURL(state, challenge string) string {
	return g.cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

type googleUser struct {
	Sub           string `json:"sub"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

func (g *Google) Exchange(ctx context.Context, code, verifier string) (*Profile, error) {
	tok, err := g.cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("google: exchange: %w", err)
	}

	raw, err := getJSON(ctx, g.cfg.Client(ctx, tok), "https://openidconnect.googleapis.com/v1/userinfo")
	if err != nil {
		return nil, fmt.Errorf("google: userinfo: %w", err)
	}
	var u googleUser
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, fmt.Errorf("google: decode userinfo: %w", err)
	}
	if u.Sub == "" {
		return nil, fmt.Errorf("google: userinfo has no sub")
	}

	return &Profile{
		Subject:       u.Sub,
		Email:         u.Email,
		EmailVerified: u.EmailVerified,
		Name:          u.Name,
		Avatar:        u.Picture,
		Raw:           raw,
	}, nil
}
