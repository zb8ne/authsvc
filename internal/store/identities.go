package store

import (
	"context"
	"encoding/json"

	"github.com/oklog/ulid/v2"
)

type Identity struct {
	ID            string
	UserID        string
	Provider      string
	Subject       string
	Email         string
	EmailVerified bool
	RawProfile    json.RawMessage
}

// IdentityBySubject looks up a linked identity by the provider's stable id.
// This is the only correct key for "have we seen this account before" — email
// is not stable and is not owned by the provider.
func (db *DB) IdentityBySubject(ctx context.Context, provider, subject string) (*Identity, error) {
	var i Identity
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, provider, subject, COALESCE(email,''), email_verified, raw_profile
		  FROM identities WHERE provider = $1 AND subject = $2`, provider, subject).
		Scan(&i.ID, &i.UserID, &i.Provider, &i.Subject, &i.Email, &i.EmailVerified, &i.RawProfile)
	if err != nil {
		return nil, norows(err)
	}
	return &i, nil
}

func (db *DB) IdentitiesForUser(ctx context.Context, userID string) ([]Identity, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, provider, subject, COALESCE(email,''), email_verified, raw_profile
		  FROM identities WHERE user_id = $1 ORDER BY provider`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Identity
	for rows.Next() {
		var i Identity
		if err := rows.Scan(&i.ID, &i.UserID, &i.Provider, &i.Subject, &i.Email, &i.EmailVerified, &i.RawProfile); err != nil {
			return nil, err
		}
		out = append(out, i)
	}
	return out, rows.Err()
}

// CreateIdentity links an auth method to a user. The unique constraint on
// (provider, subject) is what stops the same provider account being attached to
// two different users.
func (db *DB) CreateIdentity(ctx context.Context, i Identity) (*Identity, error) {
	i.ID = ulid.Make().String()
	if i.RawProfile == nil {
		i.RawProfile = json.RawMessage("{}")
	}
	_, err := db.Pool.Exec(ctx, `
		INSERT INTO identities (id, user_id, provider, subject, email, email_verified, raw_profile)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		i.ID, i.UserID, i.Provider, i.Subject, i.Email, i.EmailVerified, i.RawProfile)
	if err != nil {
		return nil, err
	}
	return &i, nil
}

// CreateUserWithIdentity creates a user and their first identity atomically, so
// a failure cannot leave an orphaned account with no way to sign in.
func (db *DB) CreateUserWithIdentity(ctx context.Context, email string, emailVerified bool, i Identity) (*User, *Identity, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, nil, err
	}
	defer tx.Rollback(ctx)

	now := db.now()
	u := User{ID: ulid.Make().String(), Email: email, CreatedAt: now}
	if emailVerified {
		u.EmailVerifiedAt = &now
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO users (id, email, email_verified_at, created_at, updated_at)
		VALUES ($1,$2,$3,$4,$4)`, u.ID, u.Email, u.EmailVerifiedAt, now); err != nil {
		return nil, nil, err
	}

	i.ID = ulid.Make().String()
	i.UserID = u.ID
	if i.RawProfile == nil {
		i.RawProfile = json.RawMessage("{}")
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO identities (id, user_id, provider, subject, email, email_verified, raw_profile)
		VALUES ($1,$2,$3,$4,$5,$6,$7)`,
		i.ID, i.UserID, i.Provider, i.Subject, i.Email, i.EmailVerified, i.RawProfile); err != nil {
		return nil, nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, nil, err
	}
	return &u, &i, nil
}
