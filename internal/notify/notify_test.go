package notify

import (
	"context"
	"strings"
	"testing"
)

func TestSMTPRejectsHeaderInjection(t *testing.T) {
	s := SMTPSender{Host: "localhost", Port: 25, From: "a@b.c"}
	err := s.SendCode(context.Background(), Email("victim@x.com\r\nBcc: everyone@y.com"), PurposeLoginOTP, "123456")
	if err == nil || !strings.Contains(err.Error(), "line break") {
		t.Fatalf("address with CRLF was not rejected, got %v", err)
	}
}

func TestSMTPRejectsPhone(t *testing.T) {
	s := SMTPSender{Host: "localhost", Port: 25, From: "a@b.c"}
	if err := s.SendCode(context.Background(), Address{KindPhone, "+911234567890"}, PurposeLoginOTP, "1"); err == nil {
		t.Fatal("SMTP sender accepted a phone address")
	}
}

func TestBodyIncludesCode(t *testing.T) {
	for _, p := range []Purpose{PurposeLoginOTP, PurposeEmailVerify, PurposePasswordReset} {
		if !strings.Contains(bodyFor(p, "ZZTOP"), "ZZTOP") {
			t.Errorf("body for %s omits the code", p)
		}
		if subjectFor(p) == "" {
			t.Errorf("no subject for %s", p)
		}
	}
}

var _ Sender = SMTPSender{}
var _ Sender = LogSender{}
