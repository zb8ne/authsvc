package httpapi

import (
	"net/http"
	"testing"

	"github.com/zb8ne/authsvc/internal/notify"
	"github.com/zb8ne/authsvc/internal/store"
)

func TestOTPLoginCreatesAndVerifiesAccount(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()

	rp := r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": cid, "email": email})
	if rp.Status != http.StatusAccepted {
		t.Fatalf("request: %d %s", rp.Status, rp.Raw)
	}
	sent, ok := r.mail.last(notify.PurposeLoginOTP)
	if !ok {
		t.Fatal("no OTP sent")
	}
	if len(sent.Code) != 6 {
		t.Fatalf("OTP %q is not 6 digits", sent.Code)
	}

	got := r.do("POST", "/v1/auth/otp/verify", map[string]string{
		"client_id": cid, "email": email, "code": sent.Code,
	})
	if got.Status != http.StatusOK {
		t.Fatalf("verify: %d %s", got.Status, got.Raw)
	}
	if got.str("access_token") == "" {
		t.Fatal("no access token")
	}

	// Proving control of the inbox is itself verification.
	u, _ := got.Body["user"].(map[string]any)
	if u["email_verified"] != true {
		t.Fatal("OTP login did not mark the email verified")
	}
}

func TestOTPRequestDoesNotLeakExistence(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	known := r.email()
	r.register(cid, known, goodPassword)

	a := r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": cid, "email": known})
	b := r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": cid, "email": r.email()})
	if a.Status != b.Status || string(a.Raw) != string(b.Raw) {
		t.Fatalf("known vs unknown differ: %d %s / %d %s", a.Status, a.Raw, b.Status, b.Raw)
	}
}

func TestOTPIsSingleUse(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()

	r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": cid, "email": email})
	sent, _ := r.mail.last(notify.PurposeLoginOTP)

	r.do("POST", "/v1/auth/otp/verify", map[string]string{"client_id": cid, "email": email, "code": sent.Code})
	again := r.do("POST", "/v1/auth/otp/verify", map[string]string{"client_id": cid, "email": email, "code": sent.Code})
	if again.Status == http.StatusOK {
		t.Fatal("OTP was redeemable twice")
	}
}

// A code issued for one app must not buy a token for another.
func TestOTPIsScopedToTheRequestingClient(t *testing.T) {
	r := newRig(t)
	appA, appB := r.newClient(), r.newClient()
	email := r.email()

	r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": appA, "email": email})
	sent, _ := r.mail.last(notify.PurposeLoginOTP)

	cross := r.do("POST", "/v1/auth/otp/verify", map[string]string{
		"client_id": appB, "email": email, "code": sent.Code,
	})
	if cross.Status == http.StatusOK {
		t.Fatal("an OTP issued for one client was redeemed against another")
	}
}

func TestOTPWrongCodeRejectedThenBurned(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()

	r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": cid, "email": email})
	sent, _ := r.mail.last(notify.PurposeLoginOTP)

	for i := 0; i < store.MaxOTPAttempts-1; i++ {
		rp := r.do("POST", "/v1/auth/otp/verify", map[string]string{
			"client_id": cid, "email": email, "code": "000000",
		})
		if rp.errCode() != "invalid_code" {
			t.Fatalf("attempt %d: got %q (%d)", i, rp.errCode(), rp.Status)
		}
	}
	rp := r.do("POST", "/v1/auth/otp/verify", map[string]string{
		"client_id": cid, "email": email, "code": "000000",
	})
	if rp.errCode() != "too_many_attempts" {
		t.Fatalf("want too_many_attempts at the cap, got %q", rp.errCode())
	}

	// The real code is dead now too.
	real := r.do("POST", "/v1/auth/otp/verify", map[string]string{
		"client_id": cid, "email": email, "code": sent.Code,
	})
	if real.Status == http.StatusOK {
		t.Fatal("the correct OTP still worked after the attempt cap")
	}
}

func TestOTPRequestRateLimitedPerIdentifier(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	email := r.email()

	var limited bool
	for i := 0; i < 8; i++ {
		// Vary the IP so this exercises the per-identifier limit specifically.
		rp := r.do("POST", "/v1/auth/otp/request",
			map[string]string{"client_id": cid, "email": email}, withIP(uniqueIP()))
		if rp.Status == http.StatusTooManyRequests {
			limited = true
			break
		}
	}
	if !limited {
		t.Fatal("unlimited OTPs can be sent to one address from rotating IPs")
	}
}

func TestOTPDeliveryFailureIsReported(t *testing.T) {
	r := newRig(t)
	cid := r.newClient()
	r.mail.fail = errSend

	rp := r.do("POST", "/v1/auth/otp/request", map[string]string{"client_id": cid, "email": r.email()})
	if rp.Status != http.StatusBadGateway {
		t.Fatalf("want 502 when delivery fails, got %d %s", rp.Status, rp.Raw)
	}
}

var errSend = errString("smtp is down")
