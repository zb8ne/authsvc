package authsdk

import (
	"html"
	"net/http"
)

// CallbackError is an error code authsvc returns to the app's redirect_uri.
type CallbackError string

const (
	// ErrCodeManualLinkRequired means the email on the provider account already
	// belongs to a user, and linking automatically would not be safe. This is a
	// normal thing for a real user to hit — they registered with a password and
	// later clicked "Sign in with Google" — not an edge case.
	ErrCodeManualLinkRequired CallbackError = "manual_link_required"
	// ErrCodeAlreadyLinked means the provider account belongs to a different user.
	ErrCodeAlreadyLinked   CallbackError = "already_linked"
	ErrCodeAccessDenied    CallbackError = "access_denied"
	ErrCodeAccountDisabled CallbackError = "account_disabled"
	ErrCodeExchangeFailed  CallbackError = "exchange_failed"
	ErrCodeMissingCode     CallbackError = "missing_code"
	ErrCodeLoginFailed     CallbackError = "login_failed"
)

// Message returns wording suitable for showing to the person who hit it.
// These say what happened and what to do next, in that order.
func (c CallbackError) Message() (title, detail string) {
	switch c {
	case ErrCodeManualLinkRequired:
		return "You already have an account with this email",
			"Sign in with your password, then connect this account from your " +
				"settings. We don't link them automatically because we can't yet " +
				"confirm both accounts belong to you."
	case ErrCodeAlreadyLinked:
		return "That account is already connected to someone else",
			"This provider account is linked to a different user. Sign in with " +
				"that account, or disconnect it there first."
	case ErrCodeAccessDenied:
		return "Sign-in was cancelled",
			"You can try again, or sign in with your email and password instead."
	case ErrCodeAccountDisabled:
		return "This account is disabled",
			"Get in touch if you think that's a mistake."
	case ErrCodeMissingCode, ErrCodeExchangeFailed, ErrCodeLoginFailed:
		return "Sign-in didn't complete",
			"Something went wrong on our end. Please try again."
	}
	return "Sign-in didn't complete", "Please try again."
}

// Retryable reports whether simply trying again could plausibly work. It is
// false for manual_link_required and already_linked: retrying the same login
// will fail the same way, and looping the user through it is the dead end worth
// avoiding.
func (c CallbackError) Retryable() bool {
	switch c {
	case ErrCodeManualLinkRequired, ErrCodeAlreadyLinked, ErrCodeAccountDisabled:
		return false
	}
	return true
}

// WriteErrorPage renders a plain, self-contained HTML explanation. It exists so
// the common failure paths have a sane default instead of a bare error code;
// pass your own ErrorHandler to HandleCallbackWithError to match your design.
//
// signInURL, when non-empty, is offered as the way forward.
func WriteErrorPage(w http.ResponseWriter, status int, code CallbackError, signInURL string) {
	title, detail := code.Message()

	action := ""
	if signInURL != "" {
		label := "Try again"
		if !code.Retryable() {
			label = "Sign in another way"
		}
		action = `<p><a class="btn" href="` + html.EscapeString(signInURL) + `">` + label + `</a></p>`
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(`<!doctype html>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>` + html.EscapeString(title) + `</title>
<style>
  :root { color-scheme: light dark; }
  body { font: 16px/1.6 system-ui, sans-serif; max-width: 32rem;
         margin: 12vh auto; padding: 0 1.5rem; }
  h1 { font-size: 1.4rem; margin: 0 0 .6rem; }
  p { margin: 0 0 1rem; opacity: .85; }
  .btn { display: inline-block; padding: .55rem 1.1rem; border-radius: .4rem;
         background: #2563eb; color: #fff; text-decoration: none; }
</style>
<h1>` + html.EscapeString(title) + `</h1>
<p>` + html.EscapeString(detail) + `</p>` + action + `
`))
}
