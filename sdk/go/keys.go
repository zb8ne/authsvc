package authsdk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
)

// keyCache holds the JWKS and refreshes it in the background.
//
// Reads never block on the network. That is the whole point: a request being
// verified must not wait on, or fail because of, an HTTP call to authsvc.
type keyCache struct {
	c *Client

	mu        sync.RWMutex
	set       jwk.Set
	fetchedAt time.Time
	lastErr   error

	// refreshing guards against piling up concurrent refreshes when the
	// service is slow or down.
	refreshing sync.Mutex
}

func newKeyCache(c *Client) *keyCache { return &keyCache{c: c} }

var ErrNoKeys = errors.New("authsdk: no verification keys available yet")

// get returns the cached key set. It never performs a fetch; if the set is
// stale it kicks off a background refresh and returns the stale set anyway,
// because a stale key still verifies a valid token correctly.
func (k *keyCache) get() (jwk.Set, error) {
	k.mu.RLock()
	set, at, err := k.set, k.fetchedAt, k.lastErr
	k.mu.RUnlock()

	if set == nil {
		// Cold and never successfully fetched. Trigger a refresh so the next
		// request can succeed, but do not wait for it.
		go k.refresh()
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrNoKeys, err)
		}
		return nil, ErrNoKeys
	}

	age := time.Since(at)
	if age > k.c.cfg.JWKSRefresh {
		go k.refresh() // stale-while-revalidate
	}
	if max := k.c.cfg.JWKSMaxStale; max > 0 && age > max {
		return nil, fmt.Errorf("authsdk: key set is %s stale, past JWKSMaxStale", age.Round(time.Second))
	}
	return set, nil
}

// warm does one bounded, best-effort fetch at construction.
func (k *keyCache) warm() {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := k.fetch(ctx); err != nil {
		k.report(err)
	}
}

func (k *keyCache) run() {
	t := time.NewTicker(k.c.cfg.JWKSRefresh)
	defer t.Stop()
	for {
		select {
		case <-k.c.stop:
			return
		case <-t.C:
			k.refresh()
		}
	}
}

func (k *keyCache) refresh() {
	// Only one refresh at a time; the rest simply return.
	if !k.refreshing.TryLock() {
		return
	}
	defer k.refreshing.Unlock()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := k.fetch(ctx); err != nil {
		k.report(err)
	}
}

func (k *keyCache) fetch(ctx context.Context) error {
	body, err := k.c.getWithFallback(ctx, "/.well-known/jwks.json")
	if err != nil {
		k.mu.Lock()
		k.lastErr = err
		k.mu.Unlock()
		return err
	}

	set, err := jwk.Parse(body)
	if err != nil {
		k.mu.Lock()
		k.lastErr = err
		k.mu.Unlock()
		return fmt.Errorf("authsdk: parse jwks: %w", err)
	}
	if set.Len() == 0 {
		// Never replace a working key set with an empty one.
		err := errors.New("authsdk: jwks contained no keys")
		k.mu.Lock()
		k.lastErr = err
		k.mu.Unlock()
		return err
	}

	k.mu.Lock()
	k.set, k.fetchedAt, k.lastErr = set, time.Now(), nil
	k.mu.Unlock()
	return nil
}

func (k *keyCache) report(err error) {
	if k.c.cfg.OnError != nil {
		k.c.cfg.OnError(err)
	}
}

// getWithFallback tries BaseURL, then FallbackURL on a connection error or 5xx.
// A 4xx is a real answer and is not retried against the fallback.
func (c *Client) getWithFallback(ctx context.Context, path string) ([]byte, error) {
	body, err := c.getOnce(ctx, c.cfg.BaseURL+path)
	if err == nil {
		return body, nil
	}
	if c.cfg.FallbackURL == "" || !shouldFailOver(err) {
		return nil, err
	}
	body, ferr := c.getOnce(ctx, c.cfg.FallbackURL+path)
	if ferr != nil {
		return nil, fmt.Errorf("authsdk: primary failed (%v); fallback failed: %w", err, ferr)
	}
	return body, nil
}

// httpStatusError marks a non-2xx response so failover can distinguish "the
// server is broken" from "the server said no".
type httpStatusError struct {
	Status int
	Body   string
}

func (e *httpStatusError) Error() string {
	return fmt.Sprintf("authsdk: server returned %d: %s", e.Status, e.Body)
}

func shouldFailOver(err error) bool {
	var se *httpStatusError
	if errors.As(err, &se) {
		return se.Status >= 500
	}
	// Transport-level failure: connection refused, DNS, timeout.
	return true
}

func (c *Client) getOnce(ctx context.Context, url string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	return c.do(req)
}

func errorIsNoKeys(err error) bool { return errors.Is(err, ErrNoKeys) }
