// Package token mints and verifies access tokens (Ed25519 JWTs) and refresh
// tokens (opaque random bytes, stored only as a sha256 digest).
package token

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwt"
	"github.com/oklog/ulid/v2"
)

// RefreshBytes is the entropy of a refresh token before base64url encoding.
const RefreshBytes = 32

type Config struct {
	Issuer     string
	AccessTTL  time.Duration
	PrivateKey string // base64 std, ed25519 seed (32B) or full private key (64B)
	NextKey    string // optional; published in JWKS but never used to sign
}

type Claims struct {
	Subject       string
	Audience      string
	SessionID     string
	JTI           string
	Email         string
	EmailVerified bool
	Roles         []string
	IssuedAt      time.Time
	ExpiresAt     time.Time
}

type Signer struct {
	issuer  string
	ttl     time.Duration
	signKey jwk.Key // current key, with kid
	pubSet  jwk.Set // current + next, public halves only
	now     func() time.Time
}

func NewSigner(c Config) (*Signer, error) {
	if c.PrivateKey == "" {
		return nil, errors.New("token: ED25519_PRIVATE_KEY is required")
	}
	if c.AccessTTL <= 0 {
		c.AccessTTL = time.Hour
	}

	signKey, err := parseKey(c.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("token: private key: %w", err)
	}

	pubSet := jwk.NewSet()
	if err := addPublic(pubSet, signKey); err != nil {
		return nil, err
	}
	if c.NextKey != "" {
		next, err := parseKey(c.NextKey)
		if err != nil {
			return nil, fmt.Errorf("token: next key: %w", err)
		}
		if err := addPublic(pubSet, next); err != nil {
			return nil, err
		}
	}

	return &Signer{issuer: c.Issuer, ttl: c.AccessTTL, signKey: signKey, pubSet: pubSet, now: time.Now}, nil
}

// parseKey decodes a base64 ed25519 seed or private key and derives a stable kid
// from the public half, so the kid survives restarts and redeploys.
func parseKey(s string) (jwk.Key, error) {
	raw, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		raw, err = base64.RawURLEncoding.DecodeString(s)
		if err != nil {
			return nil, errors.New("not valid base64")
		}
	}

	var priv ed25519.PrivateKey
	switch len(raw) {
	case ed25519.SeedSize:
		priv = ed25519.NewKeyFromSeed(raw)
	case ed25519.PrivateKeySize:
		priv = ed25519.PrivateKey(raw)
	default:
		return nil, fmt.Errorf("want %d or %d bytes, got %d", ed25519.SeedSize, ed25519.PrivateKeySize, len(raw))
	}

	key, err := jwk.FromRaw(priv)
	if err != nil {
		return nil, err
	}
	pub := priv.Public().(ed25519.PublicKey)
	sum := sha256.Sum256(pub)
	kid := base64.RawURLEncoding.EncodeToString(sum[:8])
	if err := key.Set(jwk.KeyIDKey, kid); err != nil {
		return nil, err
	}
	if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
		return nil, err
	}
	return key, nil
}

func addPublic(set jwk.Set, priv jwk.Key) error {
	pub, err := priv.PublicKey()
	if err != nil {
		return err
	}
	if err := pub.Set(jwk.KeyUsageKey, "sig"); err != nil {
		return err
	}
	return set.AddKey(pub)
}

// JWKS returns the public key set. Both the current and the next key are always
// present so a rotation is a config change, not a flag day.
// AccessTTL is the lifetime of tokens this signer mints.
func (s *Signer) AccessTTL() time.Duration { return s.ttl }

func (s *Signer) JWKS() (jwk.Set, error) { return s.pubSet, nil }

func (s *Signer) SignAccess(c Claims) (string, error) {
	now := s.now()
	if c.JTI == "" {
		c.JTI = ulid.Make().String()
	}

	b := jwt.NewBuilder().
		Issuer(s.issuer).
		Subject(c.Subject).
		Audience([]string{c.Audience}).
		JwtID(c.JTI).
		IssuedAt(now).
		Expiration(now.Add(s.ttl)).
		Claim("sid", c.SessionID).
		Claim("email", c.Email).
		Claim("email_verified", c.EmailVerified)

	roles := c.Roles
	if roles == nil {
		roles = []string{}
	}
	b = b.Claim("roles", roles)

	tok, err := b.Build()
	if err != nil {
		return "", err
	}
	signed, err := jwt.Sign(tok, jwt.WithKey(jwa.EdDSA, s.signKey))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

// VerifyAccess checks signature, issuer, audience and expiry. It accepts any key
// currently in the JWKS, which is what makes rotation seamless.
func (s *Signer) VerifyAccess(raw, audience string) (*Claims, error) {
	tok, err := jwt.Parse([]byte(raw),
		jwt.WithKeySet(s.pubSet, jws.WithInferAlgorithmFromKey(false)),
		jwt.WithIssuer(s.issuer),
		jwt.WithAudience(audience),
		jwt.WithValidate(true),
		jwt.WithClock(clockFunc(s.now)),
	)
	if err != nil {
		return nil, err
	}

	c := &Claims{
		Subject:   tok.Subject(),
		JTI:       tok.JwtID(),
		IssuedAt:  tok.IssuedAt(),
		ExpiresAt: tok.Expiration(),
	}
	if a := tok.Audience(); len(a) > 0 {
		c.Audience = a[0]
	}
	if v, ok := tok.Get("sid"); ok {
		c.SessionID, _ = v.(string)
	}
	if v, ok := tok.Get("email"); ok {
		c.Email, _ = v.(string)
	}
	if v, ok := tok.Get("email_verified"); ok {
		c.EmailVerified, _ = v.(bool)
	}
	if v, ok := tok.Get("roles"); ok {
		if list, ok := v.([]any); ok {
			// Start non-nil so a token with no roles round-trips as an empty
			// slice rather than nil; callers range over it either way, but the
			// asymmetry is a trap worth not having.
			c.Roles = make([]string, 0, len(list))
			for _, r := range list {
				if s, ok := r.(string); ok {
					c.Roles = append(c.Roles, s)
				}
			}
		}
	}
	return c, nil
}

type clockFunc func() time.Time

func (f clockFunc) Now() time.Time { return f() }

// NewRefreshToken returns a fresh opaque refresh token. The raw value is shown
// to the caller exactly once and is never stored.
func NewRefreshToken() (string, error) {
	b := make([]byte, RefreshBytes)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

// HashRefresh returns the sha256 digest stored in sessions.token_hash.
func HashRefresh(tok string) []byte {
	sum := sha256.Sum256([]byte(tok))
	return sum[:]
}

// PeekAudience reads the audience from an *unverified* token so the caller can
// then verify against it. The returned value is attacker-controlled until
// VerifyAccess succeeds — never trust it for anything else.
func PeekAudience(raw string) (string, error) {
	tok, err := jwt.ParseInsecure([]byte(raw))
	if err != nil {
		return "", err
	}
	aud := tok.Audience()
	if len(aud) == 0 {
		return "", errors.New("token: no audience")
	}
	return aud[0], nil
}
