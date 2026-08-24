// Package authsdk is the client for authsvc.
//
// The design goal is that verifying a request costs nothing and depends on
// nothing. RequireUser validates tokens locally against a cached JWKS and never
// makes a network call on the request path — so an authsvc outage cannot take
// down the apps that depend on it. Only the login and refresh paths, which are
// inherently interactive, talk to the service.
package authsdk

import (
	"errors"
	"net/http"
	"strings"
	"sync"
	"time"
)

type Config struct {
	// BaseURL is the authsvc origin, e.g. https://auth.zb8ne.lol.
	BaseURL string
	// FallbackURL is tried when BaseURL fails to connect or returns 5xx.
	FallbackURL string

	ClientID     string
	ClientSecret string
	// Audience defaults to ClientID. Tokens minted for any other audience are
	// rejected, which is what stops one app's token working against another.
	Audience string

	// Issuer defaults to BaseURL. It must match the `iss` claim exactly.
	Issuer string

	// HTTPClient is used for the login and refresh paths only.
	HTTPClient *http.Client

	// JWKSRefresh is how often keys are refreshed in the background.
	// Defaults to 15 minutes; keys are served from cache regardless.
	JWKSRefresh time.Duration
	// JWKSMaxStale bounds how long a cached key set may be served after
	// refreshes start failing. Defaults to DefaultJWKSMaxStale.
	//
	// This is the bound on how long a compromised signing key stays trusted by
	// an app that can no longer reach authsvc. It has to be finite: without it,
	// rotating a leaked key out would mean redeploying every dependent app.
	// Seven days is long enough that an outage serves stale keys and nothing
	// breaks, and short enough that the blast radius is bounded.
	//
	// Set to NoMaxStale to disable expiry entirely. Only do that if you would
	// rather serve indefinitely-old keys than fail closed.
	JWKSMaxStale time.Duration

	// SignInURL is your app's own sign-in page. The default callback error page
	// links to it as the way forward. Optional.
	SignInURL string

	// OnError receives background refresh failures. Optional.
	OnError func(error)
}

type Client struct {
	cfg  Config
	http *http.Client
	keys *keyCache
	stop chan struct{}
	once sync.Once
}

// DefaultJWKSMaxStale bounds how long cached keys are trusted once refreshes
// start failing. A 7-day authsvc outage is a different conversation than a
// key-rotation policy.
const DefaultJWKSMaxStale = 7 * 24 * time.Hour

// NoMaxStale disables key expiry. See Config.JWKSMaxStale before using it.
const NoMaxStale = time.Duration(-1)

var ErrNoBaseURL = errors.New("authsdk: BaseURL is required")

// ErrKeysTooStale means refreshes have been failing for longer than
// JWKSMaxStale. The SDK fails closed rather than trust keys it can no longer
// confirm.
var ErrKeysTooStale = errors.New("authsdk: cached keys are too stale to trust")

func New(cfg Config) (*Client, error) {
	if cfg.BaseURL == "" {
		return nil, ErrNoBaseURL
	}
	cfg.BaseURL = strings.TrimRight(cfg.BaseURL, "/")
	cfg.FallbackURL = strings.TrimRight(cfg.FallbackURL, "/")
	if cfg.Audience == "" {
		cfg.Audience = cfg.ClientID
	}
	if cfg.Issuer == "" {
		cfg.Issuer = cfg.BaseURL
	}
	if cfg.HTTPClient == nil {
		cfg.HTTPClient = &http.Client{Timeout: 10 * time.Second}
	}
	if cfg.JWKSRefresh <= 0 {
		cfg.JWKSRefresh = 15 * time.Minute
	}
	if cfg.JWKSMaxStale == 0 {
		cfg.JWKSMaxStale = DefaultJWKSMaxStale
	}

	c := &Client{cfg: cfg, http: cfg.HTTPClient, stop: make(chan struct{})}
	c.keys = newKeyCache(c)

	// Warm the cache once, with a short budget. A failure here is not fatal:
	// the background refresher will keep trying, and making startup depend on
	// authsvc being reachable is exactly the coupling this SDK avoids.
	c.keys.warm()
	go c.keys.run()

	return c, nil
}

// Close stops the background key refresher.
func (c *Client) Close() {
	c.once.Do(func() { close(c.stop) })
}
