package oauth

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"
)

type GitHub struct {
	cfg *oauth2.Config
}

func NewGitHub(clientID, clientSecret, redirectURL string) *GitHub {
	return &GitHub{cfg: &oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     github.Endpoint,
		// user:email is required: the profile endpoint omits the address when
		// the user has set it to private, which is common.
		Scopes: []string{"read:user", "user:email"},
	}}
}

func (g *GitHub) Name() string { return "github" }

func (g *GitHub) AuthURL(state, challenge string) string {
	return g.cfg.AuthCodeURL(state,
		oauth2.SetAuthURLParam("code_challenge", challenge),
		oauth2.SetAuthURLParam("code_challenge_method", "S256"),
	)
}

type githubUser struct {
	ID        int64  `json:"id"`
	Login     string `json:"login"`
	Name      string `json:"name"`
	AvatarURL string `json:"avatar_url"`
	Email     string `json:"email"`
}

type githubEmail struct {
	Email    string `json:"email"`
	Primary  bool   `json:"primary"`
	Verified bool   `json:"verified"`
}

func (g *GitHub) Exchange(ctx context.Context, code, verifier string) (*Profile, error) {
	tok, err := g.cfg.Exchange(ctx, code, oauth2.SetAuthURLParam("code_verifier", verifier))
	if err != nil {
		return nil, fmt.Errorf("github: exchange: %w", err)
	}
	client := g.cfg.Client(ctx, tok)

	raw, err := getJSON(ctx, client, "https://api.github.com/user")
	if err != nil {
		return nil, fmt.Errorf("github: user: %w", err)
	}
	var u githubUser
	if err := json.Unmarshal(raw, &u); err != nil {
		return nil, fmt.Errorf("github: decode user: %w", err)
	}
	if u.ID == 0 {
		return nil, fmt.Errorf("github: user has no id")
	}

	// The /user payload never says whether the address is verified, so it can
	// never be trusted on its own. Only /user/emails carries that flag.
	email, verified := "", false
	if rawEmails, err := getJSON(ctx, client, "https://api.github.com/user/emails"); err == nil {
		var list []githubEmail
		if json.Unmarshal(rawEmails, &list) == nil {
			email, verified = pickEmail(list)
		}
	}
	if email == "" {
		// Fall back to the profile address, but never claim it is verified.
		email, verified = u.Email, false
	}

	return &Profile{
		Subject:       strconv.FormatInt(u.ID, 10),
		Email:         email,
		EmailVerified: verified,
		Name:          firstNonEmpty(u.Name, u.Login),
		Avatar:        u.AvatarURL,
		Raw:           raw,
	}, nil
}

// pickEmail prefers the primary verified address, then any verified address,
// then the primary. An unverified address is only ever returned with
// verified=false, which downstream refuses to auto-link on.
func pickEmail(list []githubEmail) (string, bool) {
	var anyVerified, primary string
	for _, e := range list {
		if e.Primary && e.Verified {
			return e.Email, true
		}
		if e.Verified && anyVerified == "" {
			anyVerified = e.Email
		}
		if e.Primary && primary == "" {
			primary = e.Email
		}
	}
	if anyVerified != "" {
		return anyVerified, true
	}
	return primary, false
}

func firstNonEmpty(vs ...string) string {
	for _, v := range vs {
		if v != "" {
			return v
		}
	}
	return ""
}
