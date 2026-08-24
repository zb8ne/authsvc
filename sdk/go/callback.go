package authsdk

import (
	"net/http"
	"net/url"
)

// SessionHandler receives the established session. Set your own cookie and
// redirect from here — authsvc cannot set a cookie for your domain, which is
// why the code exchange exists.
type SessionHandler func(w http.ResponseWriter, r *http.Request, s *Session)

// ErrorHandler receives a failed callback. code is one of the CallbackError
// constants. If nil, a human-readable page is rendered — see WriteErrorPage.
type ErrorHandler func(w http.ResponseWriter, r *http.Request, code CallbackError, err error)

// HandleCallback returns the handler for your app's registered redirect_uri.
// It exchanges the one-time code server-side and hands you the session.
func (c *Client) HandleCallback(onSession SessionHandler) http.Handler {
	return c.HandleCallbackWithError(onSession, nil)
}

func (c *Client) HandleCallbackWithError(onSession SessionHandler, onError ErrorHandler) http.Handler {
	if onError == nil {
		// A bare error code is a dead end for the person who hit it, and
		// manual_link_required is a path real users take: registered with a
		// password, later clicked "Sign in with Google".
		onError = func(w http.ResponseWriter, r *http.Request, code CallbackError, err error) {
			WriteErrorPage(w, http.StatusUnauthorized, code, c.cfg.SignInURL)
		}
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		// authsvc reports a refused login by redirecting here with ?error=,
		// including manual_link_required when an unsafe account link was
		// declined. Surface that to the user rather than retrying the login.
		if e := q.Get("error"); e != "" {
			onError(w, r, CallbackError(e), nil)
			return
		}
		code := q.Get("code")
		if code == "" {
			onError(w, r, ErrCodeMissingCode, nil)
			return
		}

		s, err := c.Exchange(r.Context(), code)
		if err != nil {
			onError(w, r, ErrCodeExchangeFailed, err)
			return
		}
		onSession(w, r, s)
	})
}

// CallbackState returns the state value authsvc echoed back, so the app can
// check it against whatever it stored before the redirect.
func CallbackState(r *http.Request) string { return r.URL.Query().Get("state") }

func urlEscape(s string) string { return url.QueryEscape(s) }
