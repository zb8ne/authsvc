package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ResendSender delivers over Resend's HTTPS API rather than SMTP.
//
// This exists because most PaaS providers — Railway included — block outbound
// SMTP ports (25/465/587) to prevent spam abuse. A container that can reach
// smtp.resend.com on port 587 locally will hang on it in production. Port 443
// is never blocked, so the HTTP API is the portable choice.
//
// Prefer this over SMTPSender anywhere you do not control egress rules.
type ResendSender struct {
	APIKey string
	From   string
	// HTTPClient is optional; a 15s-timeout client is used when nil.
	HTTPClient *http.Client
}

// resendURL is a var so tests can point it at a stub server.
var resendURL = "https://api.resend.com/emails"

func (s ResendSender) client() *http.Client {
	if s.HTTPClient != nil {
		return s.HTTPClient
	}
	return &http.Client{Timeout: 15 * time.Second}
}

type resendReq struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	Text    string   `json:"text"`
}

func (s ResendSender) SendCode(ctx context.Context, to Address, p Purpose, code string) error {
	if to.Kind != KindEmail {
		return fmt.Errorf("notify: ResendSender cannot deliver to %s", to.Kind)
	}
	if strings.ContainsAny(to.Value, "\r\n") {
		return fmt.Errorf("notify: address contains a line break")
	}

	body, err := json.Marshal(resendReq{
		From: s.From, To: []string{to.Value},
		Subject: subjectFor(p), Text: bodyFor(p, code),
	})
	if err != nil {
		return err
	}

	// Bound the send even if the caller's context has no deadline: a hung
	// provider must never hold an HTTP handler open.
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resendURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+s.APIKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.client().Do(req)
	if err != nil {
		return fmt.Errorf("notify: resend: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 8<<10))
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		// Never log the API key; the body is safe and usually says why.
		return fmt.Errorf("notify: resend returned %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	return nil
}
