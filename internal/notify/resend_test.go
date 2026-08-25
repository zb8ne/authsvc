package notify

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestResendSendsExpectedPayload(t *testing.T) {
	var got resendReq
	var auth string

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		body, _ := io.ReadAll(r.Body)
		json.Unmarshal(body, &got)
		w.WriteHeader(http.StatusOK)
		w.Write([]byte(`{"id":"abc"}`))
	}))
	defer srv.Close()

	s := ResendSender{APIKey: "re_test", From: "auth@example.test", HTTPClient: srv.Client()}
	// Point the sender at the test server.
	old := resendURL
	resendURL = srv.URL
	defer func() { resendURL = old }()

	if err := s.SendCode(context.Background(), Email("user@example.test"), PurposeLoginOTP, "123456"); err != nil {
		t.Fatal(err)
	}
	if auth != "Bearer re_test" {
		t.Errorf("Authorization = %q", auth)
	}
	if got.From != "auth@example.test" || len(got.To) != 1 || got.To[0] != "user@example.test" {
		t.Errorf("envelope wrong: %+v", got)
	}
	if !strings.Contains(got.Text, "123456") {
		t.Errorf("body omits the code: %q", got.Text)
	}
	if got.Subject == "" {
		t.Error("no subject")
	}
}

func TestResendSurfacesAPIErrors(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusUnprocessableEntity)
		w.Write([]byte(`{"message":"domain not verified"}`))
	}))
	defer srv.Close()

	old := resendURL
	resendURL = srv.URL
	defer func() { resendURL = old }()

	err := ResendSender{APIKey: "k", From: "a@b.c", HTTPClient: srv.Client()}.
		SendCode(context.Background(), Email("x@y.z"), PurposeLoginOTP, "1")
	if err == nil {
		t.Fatal("a 422 was treated as success")
	}
	if !strings.Contains(err.Error(), "domain not verified") {
		t.Errorf("error does not carry the provider's reason: %v", err)
	}
	if strings.Contains(err.Error(), "Bearer") {
		t.Error("error leaks the API key")
	}
}

// A hung provider must not hold the caller open indefinitely.
func TestResendTimesOut(t *testing.T) {
	// release lets the handler return once the assertion is done. Parking it on
	// r.Context().Done() instead would deadlock srv.Close(), which waits for
	// outstanding handlers.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-release
	}))
	defer srv.Close()
	defer close(release)

	old := resendURL
	resendURL = srv.URL
	defer func() { resendURL = old }()

	s := ResendSender{APIKey: "k", From: "a@b.c", HTTPClient: &http.Client{Timeout: 300 * time.Millisecond}}

	done := make(chan error, 1)
	go func() {
		done <- s.SendCode(context.Background(), Email("x@y.z"), PurposeLoginOTP, "1")
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("a hung provider returned success")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("SendCode did not time out")
	}
}

func TestResendRejectsHeaderInjectionAndPhone(t *testing.T) {
	s := ResendSender{APIKey: "k", From: "a@b.c"}
	if err := s.SendCode(context.Background(), Email("a@b.c\r\nBcc: evil@x.com"), PurposeLoginOTP, "1"); err == nil {
		t.Error("CRLF address accepted")
	}
	if err := s.SendCode(context.Background(), Address{KindPhone, "+911234567890"}, PurposeLoginOTP, "1"); err == nil {
		t.Error("phone address accepted")
	}
}

// net/smtp has no timeout of its own; ours must bound a black-holed port.
func TestSMTPFailsFastOnBlockedPort(t *testing.T) {
	// 198.51.100.0/24 is TEST-NET-2: routable-looking but black-holed.
	s := SMTPSender{Host: "198.51.100.1", Port: 587, From: "a@b.c", Timeout: 700 * time.Millisecond}

	start := time.Now()
	err := s.SendCode(context.Background(), Email("x@y.z"), PurposeLoginOTP, "1")
	elapsed := time.Since(start)

	if err == nil {
		t.Fatal("expected an error against a black-holed port")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("took %s to give up; SMTP sends must be bounded", elapsed)
	}
	if !strings.Contains(err.Error(), "block") {
		t.Logf("note: error was %v", err)
	}
}

var _ Sender = ResendSender{}
