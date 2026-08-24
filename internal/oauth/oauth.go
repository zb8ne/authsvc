// Package oauth wraps the identity providers behind one interface.
package oauth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
)

type Provider interface {
	Name() string
	AuthURL(state, codeChallenge string) string
	Exchange(ctx context.Context, code, verifier string) (*Profile, error)
}

type Profile struct {
	// Subject is the provider's stable id for this account — NOT the email.
	// Emails change and, at some providers, are user-settable.
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	Avatar        string
	Raw           json.RawMessage
}

// NewVerifier returns a PKCE code verifier (RFC 7636): 43-128 chars of
// unreserved characters, here 43 from 32 random bytes.
func NewVerifier() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// Challenge returns the S256 challenge for a verifier. Plain is never used.
func Challenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}
