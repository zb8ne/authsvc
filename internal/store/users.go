package store

import (
	"context"
	"time"

	"github.com/oklog/ulid/v2"
)

type User struct {
	ID              string
	Email           string
	EmailVerifiedAt *time.Time
	PasswordHash    *string
	CreatedAt       time.Time
	DisabledAt      *time.Time
}

func (u *User) EmailVerified() bool { return u.EmailVerifiedAt != nil }

// CreateUser inserts a user. passwordHash is nil for OAuth-only accounts.
func (db *DB) CreateUser(ctx context.Context, email string, passwordHash *string) (*User, error) {
	u := User{ID: ulid.Make().String(), Email: email, PasswordHash: passwordHash, CreatedAt: db.now()}
	err := db.Pool.QueryRow(ctx, `
		INSERT INTO users (id, email, password_hash, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$4) RETURNING created_at`,
		u.ID, u.Email, u.PasswordHash, u.CreatedAt).Scan(&u.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &u, nil
}

func (db *DB) UserByEmail(ctx context.Context, email string) (*User, error) {
	return db.scanUser(ctx, `WHERE email = $1`, email)
}

func (db *DB) UserByID(ctx context.Context, id string) (*User, error) {
	return db.scanUser(ctx, `WHERE id = $1`, id)
}

func (db *DB) scanUser(ctx context.Context, where string, arg any) (*User, error) {
	var u User
	err := db.Pool.QueryRow(ctx, `
		SELECT id, email, email_verified_at, password_hash, created_at, disabled_at
		  FROM users `+where, arg).
		Scan(&u.ID, &u.Email, &u.EmailVerifiedAt, &u.PasswordHash, &u.CreatedAt, &u.DisabledAt)
	if err != nil {
		return nil, norows(err)
	}
	return &u, nil
}

func (db *DB) MarkEmailVerified(ctx context.Context, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET email_verified_at = COALESCE(email_verified_at, $2), updated_at = $2 WHERE id = $1`,
		userID, db.now())
	return err
}

func (db *DB) SetPasswordHash(ctx context.Context, userID, hash string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE users SET password_hash = $2, updated_at = $3 WHERE id = $1`, userID, hash, db.now())
	return err
}

type Client struct {
	ID           string
	Name         string
	SecretHash   string
	RedirectURIs []string
	Audience     string
}

func (db *DB) CreateClient(ctx context.Context, c Client) error {
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO app_clients (id, name, secret_hash, redirect_uris, audience)
		VALUES ($1,$2,$3,$4,$5)`, c.ID, c.Name, c.SecretHash, c.RedirectURIs, c.Audience)
	return err
}

func (db *DB) ClientByID(ctx context.Context, id string) (*Client, error) {
	var c Client
	err := db.Pool.QueryRow(ctx,
		`SELECT id, name, secret_hash, redirect_uris, audience FROM app_clients WHERE id = $1`, id).
		Scan(&c.ID, &c.Name, &c.SecretHash, &c.RedirectURIs, &c.Audience)
	if err != nil {
		return nil, norows(err)
	}
	return &c, nil
}

// AllowsRedirect reports whether uri is an exact registered redirect. Exact
// match only — prefix matching on redirect URIs is a known open-redirect hole.
func (c *Client) AllowsRedirect(uri string) bool {
	for _, u := range c.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}

func (db *DB) ListClients(ctx context.Context) ([]Client, error) {
	rows, err := db.Pool.Query(ctx,
		`SELECT id, name, secret_hash, redirect_uris, audience FROM app_clients ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Client
	for rows.Next() {
		var c Client
		if err := rows.Scan(&c.ID, &c.Name, &c.SecretHash, &c.RedirectURIs, &c.Audience); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}
