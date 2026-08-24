package notify

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
)

type SMTPSender struct {
	Host string
	Port int
	User string
	Pass string
	From string
}

func (s SMTPSender) SendCode(ctx context.Context, to Address, p Purpose, code string) error {
	if to.Kind != KindEmail {
		return fmt.Errorf("notify: SMTPSender cannot deliver to %s", to.Kind)
	}
	if strings.ContainsAny(to.Value, "\r\n") {
		// Never let a header be split by a crafted address.
		return errors.New("notify: address contains a line break")
	}

	msg := "From: " + s.From + "\r\n" +
		"To: " + to.Value + "\r\n" +
		"Subject: " + subjectFor(p) + "\r\n" +
		"MIME-Version: 1.0\r\n" +
		"Content-Type: text/plain; charset=utf-8\r\n" +
		"\r\n" + bodyFor(p, code) + "\r\n"

	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	var auth smtp.Auth
	if s.User != "" {
		auth = smtp.PlainAuth("", s.User, s.Pass, s.Host)
	}
	return smtp.SendMail(addr, auth, s.From, []string{to.Value}, []byte(msg))
}
