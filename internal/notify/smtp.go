package notify

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/smtp"
	"strings"
	"time"
)

// SMTPSender delivers over SMTP.
//
// Note: many PaaS providers (Railway, Fly, Heroku) block outbound SMTP ports to
// prevent spam abuse. If sends hang in production but work locally, that is
// almost certainly why — use ResendSender, which goes over HTTPS, instead.
type SMTPSender struct {
	Host string
	Port int
	User string
	Pass string
	From string
	// Timeout bounds the whole conversation. Defaults to DefaultSMTPTimeout.
	Timeout time.Duration
}

// DefaultSMTPTimeout bounds dial, TLS, auth, and send.
//
// net/smtp.SendMail has NO timeout of its own: against a black-holed port it
// blocks until the OS gives up, which can be minutes. Inside an HTTP handler
// that means a request that never returns.
const DefaultSMTPTimeout = 20 * time.Second

func (s SMTPSender) timeout() time.Duration {
	if s.Timeout > 0 {
		return s.Timeout
	}
	return DefaultSMTPTimeout
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

	ctx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()

	// Dial through a context-aware dialer so a blocked port fails fast rather
	// than hanging the caller.
	addr := net.JoinHostPort(s.Host, fmt.Sprint(s.Port))
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("notify: smtp dial %s: %w (many hosts block outbound SMTP ports)", addr, err)
	}
	defer conn.Close()

	// Deadline covers the rest of the conversation, not just the dial.
	if dl, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	c, err := smtp.NewClient(conn, s.Host)
	if err != nil {
		return fmt.Errorf("notify: smtp: %w", err)
	}
	defer c.Close()

	if ok, _ := c.Extension("STARTTLS"); ok {
		if err := c.StartTLS(&tls.Config{ServerName: s.Host}); err != nil {
			return fmt.Errorf("notify: smtp starttls: %w", err)
		}
	}
	if s.User != "" {
		if err := c.Auth(smtp.PlainAuth("", s.User, s.Pass, s.Host)); err != nil {
			return fmt.Errorf("notify: smtp auth: %w", err)
		}
	}
	if err := c.Mail(s.From); err != nil {
		return fmt.Errorf("notify: smtp from: %w", err)
	}
	if err := c.Rcpt(to.Value); err != nil {
		return fmt.Errorf("notify: smtp rcpt: %w", err)
	}
	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("notify: smtp data: %w", err)
	}
	if _, err := w.Write([]byte(msg)); err != nil {
		return err
	}
	if err := w.Close(); err != nil {
		return err
	}
	return c.Quit()
}
