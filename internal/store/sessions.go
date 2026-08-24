package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/oklog/ulid/v2"

	"github.com/yash-sharma-dev/authsvc/internal/token"
)

// RefreshTTL is how long a refresh token stays valid before the user must log
// in again. Rotation on every use keeps the window of any single token short.
const RefreshTTL = 30 * 24 * time.Hour

type Session struct {
	ID        string
	UserID    string
	ClientID  string
	FamilyID  string
	ParentID  *string
	IssuedAt  time.Time
	ExpiresAt time.Time
	UsedAt    *time.Time
	RevokedAt *time.Time
	UserAgent string
	IP        string
}

type SessionMeta struct {
	UserAgent string
	IP        string
}

// IssuedSession pairs the stored row with the raw refresh token, which is
// returned to the caller exactly once and never persisted.
type IssuedSession struct {
	Session      Session
	RefreshToken string
}

// CreateSession starts a brand-new refresh family — a fresh login.
func (db *DB) CreateSession(ctx context.Context, userID, clientID string, m SessionMeta) (*IssuedSession, error) {
	id := ulid.Make().String()
	return db.insertSession(ctx, db.Pool, id, userID, clientID, id, nil, m)
}

func (db *DB) insertSession(ctx context.Context, q querier, id, userID, clientID, familyID string, parentID *string, m SessionMeta) (*IssuedSession, error) {
	raw, err := token.NewRefreshToken()
	if err != nil {
		return nil, err
	}
	now := db.now()
	s := Session{
		ID: id, UserID: userID, ClientID: clientID, FamilyID: familyID, ParentID: parentID,
		IssuedAt: now, ExpiresAt: now.Add(RefreshTTL), UserAgent: m.UserAgent, IP: m.IP,
	}
	_, err = q.Exec(ctx, `
		INSERT INTO sessions (id, user_id, client_id, family_id, parent_id, token_hash,
		                      issued_at, expires_at, user_agent, ip)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10)`,
		s.ID, s.UserID, s.ClientID, s.FamilyID, s.ParentID, token.HashRefresh(raw),
		s.IssuedAt, s.ExpiresAt, s.UserAgent, s.IP)
	if err != nil {
		return nil, err
	}
	return &IssuedSession{Session: s, RefreshToken: raw}, nil
}

// querier is satisfied by both *pgxpool.Pool and pgx.Tx, so insertSession can
// run standalone or inside the rotation transaction.
type querier interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
}

// Rotate exchanges a refresh token for a new one.
//
// The whole operation runs in one transaction and locks the presented row FOR
// UPDATE, so two concurrent refreshes of the same token cannot both succeed:
// one wins, the other observes used_at and trips reuse detection.
//
// If the presented token was already spent, the entire family is revoked and
// ErrTokenReuse is returned — a spent token in the wild means it was cloned.
func (db *DB) Rotate(ctx context.Context, refreshToken string, m SessionMeta) (*IssuedSession, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback(ctx)

	var (
		id, userID, clientID, familyID string
		expiresAt                      time.Time
		usedAt, revokedAt              *time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, user_id, client_id, family_id, expires_at, used_at, revoked_at
		  FROM sessions WHERE token_hash = $1 FOR UPDATE`,
		token.HashRefresh(refreshToken)).
		Scan(&id, &userID, &clientID, &familyID, &expiresAt, &usedAt, &revokedAt)
	if err != nil {
		return nil, norows(err)
	}

	if usedAt != nil {
		// Already spent. Whoever holds this copy should not have it.
		if _, err := tx.Exec(ctx,
			`UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE family_id = $1`,
			familyID, db.now()); err != nil {
			return nil, err
		}
		if err := tx.Commit(ctx); err != nil {
			return nil, err
		}
		return nil, ErrTokenReuse
	}
	if revokedAt != nil {
		return nil, ErrNotFound
	}
	if db.now().After(expiresAt) {
		return nil, ErrNotFound
	}

	if _, err := tx.Exec(ctx, `UPDATE sessions SET used_at = $2 WHERE id = $1`, id, db.now()); err != nil {
		return nil, err
	}

	parent := id
	issued, err := db.insertSession(ctx, tx, ulid.Make().String(), userID, clientID, familyID, &parent, m)
	if err != nil {
		return nil, err
	}
	if err := tx.Commit(ctx); err != nil {
		return nil, err
	}
	return issued, nil
}

// RevokeFamily revokes every session sharing a rotation lineage.
func (db *DB) RevokeFamily(ctx context.Context, familyID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE family_id = $1`,
		familyID, db.now())
	return err
}

// RevokeAllForUser is logout-all.
func (db *DB) RevokeAllForUser(ctx context.Context, userID string) error {
	_, err := db.Pool.Exec(ctx,
		`UPDATE sessions SET revoked_at = COALESCE(revoked_at, $2) WHERE user_id = $1 AND revoked_at IS NULL`,
		userID, db.now())
	return err
}

// RevokeByToken is a single logout: it kills the family, not just the one row,
// so the refresh lineage cannot be continued from an older copy.
func (db *DB) RevokeByToken(ctx context.Context, refreshToken string) error {
	var familyID string
	err := db.Pool.QueryRow(ctx, `SELECT family_id FROM sessions WHERE token_hash = $1`,
		token.HashRefresh(refreshToken)).Scan(&familyID)
	if err != nil {
		return norows(err)
	}
	return db.RevokeFamily(ctx, familyID)
}

func (db *DB) SessionByToken(ctx context.Context, refreshToken string) (*Session, error) {
	return db.scanSession(ctx, `WHERE token_hash = $1`, token.HashRefresh(refreshToken))
}

func (db *DB) SessionByID(ctx context.Context, id string) (*Session, error) {
	return db.scanSession(ctx, `WHERE id = $1`, id)
}

func (db *DB) scanSession(ctx context.Context, where string, arg any) (*Session, error) {
	var s Session
	err := db.Pool.QueryRow(ctx, `
		SELECT id, user_id, client_id, family_id, parent_id, issued_at, expires_at,
		       used_at, revoked_at, COALESCE(user_agent,''), COALESCE(ip,'')
		  FROM sessions `+where, arg).
		Scan(&s.ID, &s.UserID, &s.ClientID, &s.FamilyID, &s.ParentID, &s.IssuedAt,
			&s.ExpiresAt, &s.UsedAt, &s.RevokedAt, &s.UserAgent, &s.IP)
	if err != nil {
		return nil, norows(err)
	}
	return &s, nil
}

// SessionsForFamily returns a lineage oldest-first, for assertions and auditing.
func (db *DB) SessionsForFamily(ctx context.Context, familyID string) ([]Session, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, client_id, family_id, parent_id, issued_at, expires_at,
		       used_at, revoked_at, COALESCE(user_agent,''), COALESCE(ip,'')
		  FROM sessions WHERE family_id = $1 ORDER BY issued_at, id`, familyID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.ClientID, &s.FamilyID, &s.ParentID,
			&s.IssuedAt, &s.ExpiresAt, &s.UsedAt, &s.RevokedAt, &s.UserAgent, &s.IP); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// ActiveSessionsForUser lists live sessions for GET /v1/sessions.
func (db *DB) ActiveSessionsForUser(ctx context.Context, userID string) ([]Session, error) {
	rows, err := db.Pool.Query(ctx, `
		SELECT id, user_id, client_id, family_id, parent_id, issued_at, expires_at,
		       used_at, revoked_at, COALESCE(user_agent,''), COALESCE(ip,'')
		  FROM sessions
		 WHERE user_id = $1 AND revoked_at IS NULL AND used_at IS NULL AND expires_at > $2
		 ORDER BY issued_at DESC`, userID, db.now())
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []Session
	for rows.Next() {
		var s Session
		if err := rows.Scan(&s.ID, &s.UserID, &s.ClientID, &s.FamilyID, &s.ParentID,
			&s.IssuedAt, &s.ExpiresAt, &s.UsedAt, &s.RevokedAt, &s.UserAgent, &s.IP); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

// PruneSessions drops rows well past expiry. Run nightly.
func (db *DB) PruneSessions(ctx context.Context, grace time.Duration) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, db.now().Add(-grace))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
