// Package notify delivers one-time codes and links.
//
// Handlers only ever see Sender. Phone/SMS is deferred (Indian DLT registration
// is a KYC process, not a signup form); when it lands it is one new file
// implementing this same interface and nothing above it changes.
package notify

import (
	"context"
	"fmt"
)

type Kind string

const (
	KindEmail Kind = "email"
	KindPhone Kind = "phone"
)

type Address struct {
	Kind  Kind
	Value string
}

func Email(v string) Address { return Address{KindEmail, v} }

type Purpose string

const (
	PurposeLoginOTP      Purpose = "login_otp"
	PurposeEmailVerify   Purpose = "email_verify"
	PurposePasswordReset Purpose = "password_reset"
)

type Sender interface {
	SendCode(ctx context.Context, to Address, p Purpose, code string) error
}

func subjectFor(p Purpose) string {
	switch p {
	case PurposeLoginOTP:
		return "Your sign-in code"
	case PurposeEmailVerify:
		return "Verify your email"
	case PurposePasswordReset:
		return "Reset your password"
	}
	return "Your code"
}

func bodyFor(p Purpose, code string) string {
	switch p {
	case PurposeLoginOTP:
		return fmt.Sprintf("Your sign-in code is %s. It expires in 10 minutes.\n\nIf you didn't ask for this, ignore this email.", code)
	case PurposeEmailVerify:
		return fmt.Sprintf("Confirm your email address with this token:\n\n%s\n\nIt expires in 24 hours.", code)
	case PurposePasswordReset:
		return fmt.Sprintf("Use this token to reset your password:\n\n%s\n\nIt expires in 1 hour. If you didn't ask for this, ignore this email — your password has not changed.", code)
	}
	return code
}
