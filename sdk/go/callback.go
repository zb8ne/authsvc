package authsdk

import (
	"net/http"
	"net/url"
)

// SessionHandler receives the established session. Set your own cookie and
// redirect from here — authsvc cannot set a cookie for your domain, which is
// why the code exchange exists.
type SessionHandler func(w http.ResponseWriter, r *http.Request, s *Session)

// ErrorHandler receives a failed callback. If nil, a plain 401 is written.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, code string, err error)

// HandleCallback returns the handler for your app's registered redirect_uri.
// It exchanges the one-time code server-side and hands you the session.
func (c *Client) HandleCallback(onSession SessionHandler) http.Handler {
	return c.HandleCallbackWithError(onSession, nil)
}

func (c *Client) HandleCallbackWithError(onSession SessionHandler, onError ErrorHandler) http.Handler {
	if onError == nil {
		onError = func(w http.ResponseWriter, r *http.Request, code string, err error) {
			writeAuthErr(w, http.StatusUnauthorized, code, "sign-in failed")
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// authsvc reports a refused login by redirecting here with ?error=,
		// including manual_link_required when an unsafe account link was
		// declined. Surface that to the user rather than retrying the login.
		if e := q.Get("error"); e != "" {
			onError(w, r, e, nil)
			return
		}
		code := q.Get("code")
		if code == "" {
			onError(w, r, "missing_code", nil)
			return
		}

		s, err := c.Exchange(r.Context(), code)
		if err != nil {
			onError(w, r, "exchange_failed", err)
			return
		}
		onSession(w, r, s)
	})
}

// CallbackState returns the state value authsvc echoed back, so the app can
// check it against whatever it stored before the redirect.
func CallbackState(r *http.Request) string { return r.URL.Query().Get("state") }

func urlEscape(s string) string { return url.QueryEscape(s) }
