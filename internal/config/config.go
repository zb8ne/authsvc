// Package config loads all runtime configuration from the environment.
//
// Nothing here reads platform-specific variables (RAILWAY_*, DYNO, ...) except
// PORT, which is universal. Portability is a hard requirement: this service must
// run identically under docker compose, Railway, or anything else.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	Port      string
	Issuer    string
	DatabaseURL string

	SigningKey     string
	SigningKeyNext string

	AccessTTL time.Duration

	Google OAuthApp
	GitHub OAuthApp

	SMTP SMTP

	AdminAPIKey string

	// Dev relaxes cookie Secure and lets notify fall back to stdout.
	Dev bool
}

type OAuthApp struct {
	ClientID     string
	ClientSecret string
}

func (a OAuthApp) Configured() bool { return a.ClientID != "" && a.ClientSecret != "" }

type SMTP struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

func (s SMTP) Configured() bool { return s.Host != "" && s.From != "" }

// Load reads the environment and fails fast on anything missing that the
// service cannot start without.
func Load() (*Config, error) {
	c := &Config{
		Port:        env("PORT", "8080"),
		Issuer:      strings.TrimRight(env("ISSUER", "http://localhost:8080"), "/"),
		DatabaseURL: os.Getenv("DATABASE_URL"),

		SigningKey:     os.Getenv("ED25519_PRIVATE_KEY"),
		SigningKeyNext: os.Getenv("ED25519_PRIVATE_KEY_NEXT"),

		Google: OAuthApp{os.Getenv("GOOGLE_CLIENT_ID"), os.Getenv("GOOGLE_CLIENT_SECRET")},
		GitHub: OAuthApp{os.Getenv("GITHUB_CLIENT_ID"), os.Getenv("GITHUB_CLIENT_SECRET")},

		SMTP: SMTP{
			Host: os.Getenv("SMTP_HOST"),
			User: os.Getenv("SMTP_USER"),
			Pass: os.Getenv("SMTP_PASS"),
			From: os.Getenv("SMTP_FROM"),
		},

		AdminAPIKey: os.Getenv("ADMIN_API_KEY"),
		Dev:         env("DEV", "") != "",
	}

	ttl, err := time.ParseDuration(env("ACCESS_TTL", "1h"))
	if err != nil {
		return nil, fmt.Errorf("config: ACCESS_TTL: %w", err)
	}
	c.AccessTTL = ttl

	if p := os.Getenv("SMTP_PORT"); p != "" {
		n, err := strconv.Atoi(p)
		if err != nil {
			return nil, fmt.Errorf("config: SMTP_PORT: %w", err)
		}
		c.SMTP.Port = n
	} else {
		c.SMTP.Port = 587
	}

	var missing []string
	if c.DatabaseURL == "" {
		missing = append(missing, "DATABASE_URL")
	}
	if c.SigningKey == "" {
		missing = append(missing, "ED25519_PRIVATE_KEY")
	}
	if c.AdminAPIKey == "" {
		missing = append(missing, "ADMIN_API_KEY")
	}
	if len(missing) > 0 {
		return nil, fmt.Errorf("config: missing required env: %s", strings.Join(missing, ", "))
	}
	if !c.Dev && !strings.HasPrefix(c.Issuer, "https://") {
		return nil, errors.New("config: ISSUER must be https outside DEV")
	}
	return c, nil
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}
