package store

import (
	"context"
	"time"
)

// OAuthFlowTTL bounds how long a started login may sit unfinished.
const OAuthFlowTTL = 10 * time.Minute

type OAuthFlow struct {
	Provider     string
	ClientID     string
	RedirectURI  string
	AppState     string
	CodeVerifier string
	// LinkUserID is set when the flow is an account-linking request from an
	// already-authenticated user rather than a login.
	LinkUserID *string
}

// CreateOAuthFlow records an in-flight round trip. state is stored hashed: it
// travels through the provider and a user's browser history, so it is a secret
// on the same footing as a token.
func (db *DB) CreateOAuthFlow(ctx context.Context, state string, f OAuthFlow) error {
	now := db.now()
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO oauth_flows (state_hash, provider, client_id, redirect_uri, app_state,
		                         code_verifier, link_user_id, created_at, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		hashCode(state), f.Provider, f.ClientID, f.RedirectURI, f.AppState,
		f.CodeVerifier, f.LinkUserID, now, now.Add(OAuthFlowTTL))
	return err
}

// ConsumeOAuthFlow redeems a state value exactly once. A replayed state is
// rejected, which is what makes the CSRF protection real rather than nominal.
func (db *DB) ConsumeOAuthFlow(ctx context.Context, state string) (*OAuthFlow, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var f OAuthFlow
	var expires time.Time
	err = tx.QueryRow(ctx, `
		SELECT provider, client_id, redirect_uri, app_state, code_verifier, link_user_id, expires_at
		  FROM oauth_flows WHERE state_hash = $1 AND consumed_at IS NULL
		 FOR UPDATE`, hashCode(state)).
		Scan(&f.Provider, &f.ClientID, &f.RedirectURI, &f.AppState, &f.CodeVerifier, &f.LinkUserID, &expires)
	if err != nil {
		return nil, ErrNotFound
	}
	if db.now().After(expires) {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE oauth_flows SET consumed_at = $2 WHERE state_hash = $1`, hashCode(state), db.now()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &f, nil
}

// AuthCodeTTL is deliberately tiny: the code is handed to the app's frontend in
// a URL and is redeemed immediately by its backend.
const AuthCodeTTL = 60 * time.Second

type AuthCode struct {
	UserID      string
	ClientID    string
	RedirectURI string
}

func (db *DB) CreateAuthCode(ctx context.Context, code string, c AuthCode) error {
	now := db.now()
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO auth_codes (code_hash, user_id, client_id, redirect_uri, expires_at)
		VALUES ($1,$2,$3,$4,$5)`,
		hashCode(code), c.UserID, c.ClientID, c.RedirectURI, now.Add(AuthCodeTTL))
	return err
}

// ConsumeAuthCode redeems an authorization code exactly once.
func (db *DB) ConsumeAuthCode(ctx context.Context, code string) (*AuthCode, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var c AuthCode
	var expires time.Time
	err = tx.QueryRow(ctx, `
		SELECT user_id, client_id, redirect_uri, expires_at
		  FROM auth_codes WHERE code_hash = $1 AND consumed_at IS NULL
		 FOR UPDATE`, hashCode(code)).
		Scan(&c.UserID, &c.ClientID, &c.RedirectURI, &expires)
	if err != nil {
		return nil, ErrNotFound
	}
	if db.now().After(expires) {
		return nil, ErrNotFound
	}
	if _, err := tx.Exec(ctx,
		`UPDATE auth_codes SET consumed_at = $2 WHERE code_hash = $1`, hashCode(code), db.now()); err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return &c, nil
}

// PruneOAuth clears out spent and expired flow and code rows.
func (db *DB) PruneOAuth(ctx context.Context) error {
	cutoff := db.now().Add(-time.Hour)
	if _, err := db.Pool.Exec(ctx, `DELETE FROM oauth_flows WHERE expires_at < $1`, cutoff); err != nil {
		return err
	}
	_, err := db.Pool.Exec(ctx, `DELETE FROM auth_codes WHERE expires_at < $1`, cutoff)
	return err
}
