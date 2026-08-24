package authsdk

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Every code the server can redirect with must produce wording a person can
// act on. A missing case here shows up as a bare error code in front of a user.
func TestEveryCallbackErrorHasHumanWording(t *testing.T) {
	codes := []CallbackError{
		ErrCodeManualLinkRequired, ErrCodeAlreadyLinked, ErrCodeAccessDenied,
		ErrCodeAccountDisabled, ErrCodeExchangeFailed, ErrCodeMissingCode,
		ErrCodeLoginFailed,
		"something_we_have_never_seen", // unknown codes must still be handled
	}
	for _, c := range codes {
		title, detail := c.Message()
		if title == "" || detail == "" {
			t.Errorf("%s: empty wording", c)
		}
		if strings.Contains(title, "_") || strings.Contains(detail, "_") {
			t.Errorf("%s: wording leaks a raw error code: %q / %q", c, title, detail)
		}
	}
}

// The specific dead end this exists to fix.
func TestManualLinkRequiredExplainsWhatToDo(t *testing.T) {
	title, detail := ErrCodeManualLinkRequired.Message()
	full := strings.ToLower(title + " " + detail)

	for _, want := range []string{"already have an account", "password", "settings"} {
		if !strings.Contains(full, want) {
			t.Errorf("wording does not mention %q: %s / %s", want, title, detail)
		}
	}
	if ErrCodeManualLinkRequired.Retryable() {
		t.Error("manual_link_required marked retryable; retrying fails identically")
	}
}

func TestRetryableClassification(t *testing.T) {
	for _, c := range []CallbackError{ErrCodeManualLinkRequired, ErrCodeAlreadyLinked, ErrCodeAccountDisabled} {
		if c.Retryable() {
			t.Errorf("%s should not be retryable", c)
		}
	}
	for _, c := range []CallbackError{ErrCodeAccessDenied, ErrCodeExchangeFailed} {
		if !c.Retryable() {
			t.Errorf("%s should be retryable", c)
		}
	}
}

func TestWriteErrorPageRendersHumanText(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteErrorPage(rec, http.StatusUnauthorized, ErrCodeManualLinkRequired, "https://app.test/signin")

	body := rec.Body.String()
	if !strings.Contains(body, "already have an account") {
		t.Errorf("page does not explain the problem: %s", body)
	}
	if strings.Contains(body, "manual_link_required") {
		t.Error("page shows the raw error code to the user")
	}
	if !strings.Contains(body, "https://app.test/signin") {
		t.Error("page does not offer a way forward")
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q", ct)
	}
}

// The sign-in URL is app-supplied; it must not be injectable into the page.
func TestWriteErrorPageEscapesSignInURL(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteErrorPage(rec, http.StatusUnauthorized, ErrCodeAccessDenied,
		`https://app.test/"><script>alert(1)</script>`)

	if strings.Contains(rec.Body.String(), "<script>alert(1)</script>") {
		t.Fatalf("sign-in URL was not escaped: %s", rec.Body.String())
	}
}

func TestWriteErrorPageOmitsButtonWithoutSignInURL(t *testing.T) {
	rec := httptest.NewRecorder()
	WriteErrorPage(rec, http.StatusUnauthorized, ErrCodeAccessDenied, "")
	if strings.Contains(rec.Body.String(), "<a class=\"btn\"") {
		t.Error("rendered an empty link with no sign-in URL configured")
	}
}

// The default callback handler must render the page, not a JSON error code.
func TestDefaultCallbackErrorHandlerIsHumanReadable(t *testing.T) {
	f := newFakeAuthsvc(t)
	c := newTestClient(t, f, func(cfg *Config) { cfg.SignInURL = "https://app.test/signin" })

	srv := httptest.NewServer(c.HandleCallback(
		func(w http.ResponseWriter, r *http.Request, s *Session) {
			t.Error("session handler ran for a failed callback")
		}))
	defer srv.Close()

	resp, err := http.Get(srv.URL + "?error=manual_link_required")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if !strings.Contains(body, "already have an account") {
		t.Fatalf("default handler did not explain the failure: %s", body)
	}
}
