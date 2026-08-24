package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"math/big"
	"time"

	"github.com/oklog/ulid/v2"
)

// MaxOTPAttempts caps guesses against a single issued code. Without this a
// 6-digit code is brute-forceable in a few thousand requests.
const MaxOTPAttempts = 5

var (
	ErrCodeInvalid  = errors.New("store: code invalid or expired")
	ErrCodeAttempts = errors.New("store: too many attempts")
)

type Purpose string

const (
	PurposeLoginOTP      Purpose = "login_otp"
	PurposeEmailVerify   Purpose = "email_verify"
	PurposePasswordReset Purpose = "password_reset"
)

func hashCode(s string) []byte {
	sum := sha256.Sum256([]byte(s))
	return sum[:]
}

// NewNumericCode returns a uniformly random n-digit code, zero padded.
func NewNumericCode(n int) (string, error) {
	max := new(big.Int).Exp(big.NewInt(10), big.NewInt(int64(n)), nil)
	v, err := rand.Int(rand.Reader, max)
	if err != nil {
		return "", err
	}
	s := v.String()
	for len(s) < n {
		s = "0" + s
	}
	return s, nil
}

// NewOpaqueToken returns a high-entropy token for emailed links (verification,
// password reset), where the user pastes rather than types.
func NewOpaqueToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// IssueCode stores the hash of code and invalidates any outstanding code for the
// same identifier and purpose, so only the newest one can be redeemed.
func (db *DB) IssueCode(ctx context.Context, identifier string, p Purpose, code string, ttl time.Duration) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	now := db.now()
	if _, err := tx.Exec(ctx, `
		UPDATE otp_codes SET consumed_at = $3
		 WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL`,
		identifier, string(p), now); err != nil {
		return err
	}
	if _, err := tx.Exec(ctx, `
		INSERT INTO otp_codes (id, identifier, code_hash, purpose, expires_at, created_at)
		VALUES ($1,$2,$3,$4,$5,$6)`,
		ulid.Make().String(), identifier, hashCode(code), string(p), now.Add(ttl), now); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// ConsumeCode redeems a code for an identifier the caller already knows (email
// OTP: the user tells us who they are, then proves it).
//
// A failed guess increments attempts on the outstanding row; exceeding
// MaxOTPAttempts burns the code entirely.
func (db *DB) ConsumeCode(ctx context.Context, identifier string, p Purpose, code string) error {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx)

	var (
		id       string
		hash     []byte
		attempts int
		expires  time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, code_hash, attempts, expires_at
		  FROM otp_codes
		 WHERE identifier = $1 AND purpose = $2 AND consumed_at IS NULL
		 ORDER BY created_at DESC LIMIT 1
		 FOR UPDATE`, identifier, string(p)).Scan(&id, &hash, &attempts, &expires)
	if err != nil {
		return ErrCodeInvalid
	}

	if db.now().After(expires) {
		return ErrCodeInvalid
	}
	if attempts >= MaxOTPAttempts {
		return ErrCodeAttempts
	}

	if !constantTimeEqual(hash, hashCode(code)) {
		attempts++
		q := `UPDATE otp_codes SET attempts = $2 WHERE id = $1`
		if attempts >= MaxOTPAttempts {
			q = `UPDATE otp_codes SET attempts = $2, consumed_at = now() WHERE id = $1`
		}
		if _, err := tx.Exec(ctx, q, id, attempts); err != nil {
			return err
		}
		if err := tx.Commit(ctx); err != nil {
			return err
		}
		if attempts >= MaxOTPAttempts {
			return ErrCodeAttempts
		}
		return ErrCodeInvalid
	}

	if _, err := tx.Exec(ctx, `UPDATE otp_codes SET consumed_at = $2 WHERE id = $1`, id, db.now()); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return err
	}
	return nil
}

// ConsumeToken redeems an emailed token where the token itself identifies the
// row, and returns the identifier it was issued for. Single use.
func (db *DB) ConsumeToken(ctx context.Context, p Purpose, tok string) (string, error) {
	tx, err := db.Pool.Begin(ctx)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx)

	var (
		id, identifier string
		expires        time.Time
	)
	err = tx.QueryRow(ctx, `
		SELECT id, identifier, expires_at
		  FROM otp_codes
		 WHERE code_hash = $1 AND purpose = $2 AND consumed_at IS NULL
		 FOR UPDATE`, hashCode(tok), string(p)).Scan(&id, &identifier, &expires)
	if err != nil {
		return "", ErrCodeInvalid
	}
	if db.now().After(expires) {
		return "", ErrCodeInvalid
	}
	if _, err := tx.Exec(ctx, `UPDATE otp_codes SET consumed_at = $2 WHERE id = $1`, id, db.now()); err != nil {
		return "", err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", err
	}
	return identifier, nil
}

// PruneCodes drops spent and long-expired codes.
func (db *DB) PruneCodes(ctx context.Context, grace time.Duration) (int64, error) {
	tag, err := db.Pool.Exec(ctx, `DELETE FROM otp_codes WHERE expires_at < $1`, db.now().Add(-grace))
	if err != nil {
		return 0, err
	}
	return tag.RowsAffected(), nil
}
