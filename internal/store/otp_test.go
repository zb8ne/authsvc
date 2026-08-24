package store

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/oklog/ulid/v2"
)

func ident() string { return "user-" + ulid.Make().String() + "@example.test" }

func TestConsumeCodeHappyPath(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	if err := db.IssueCode(ctx, id, PurposeLoginOTP, "123456", 10*time.Minute); err != nil {
		t.Fatal(err)
	}
	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "123456"); err != nil {
		t.Fatal(err)
	}
}

func TestCodeIsSingleUse(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	db.IssueCode(ctx, id, PurposeLoginOTP, "123456", 10*time.Minute)
	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "123456"); err != nil {
		t.Fatal(err)
	}
	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "123456"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("code was redeemable twice: %v", err)
	}
}

func TestRawCodeIsNotStored(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	db.IssueCode(ctx, id, PurposeLoginOTP, "424242", 10*time.Minute)
	var n int
	err := db.Pool.QueryRow(ctx,
		`SELECT count(*) FROM otp_codes WHERE identifier = $1 AND encode(code_hash,'escape') = '424242'`, id).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Fatal("raw OTP found in otp_codes.code_hash")
	}
}

func TestIssuingNewCodeInvalidatesTheOld(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	db.IssueCode(ctx, id, PurposeLoginOTP, "111111", 10*time.Minute)
	db.IssueCode(ctx, id, PurposeLoginOTP, "222222", 10*time.Minute)

	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "111111"); err == nil {
		t.Fatal("a superseded code was still redeemable")
	}
	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "222222"); err != nil {
		t.Fatalf("the newest code should work: %v", err)
	}
}

func TestExpiredCodeRejected(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	db.now = func() time.Time { return time.Now().Add(-time.Hour) }
	db.IssueCode(ctx, id, PurposeLoginOTP, "123456", 10*time.Minute)
	db.now = time.Now

	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "123456"); !errors.Is(err, ErrCodeInvalid) {
		t.Fatalf("expired code accepted: %v", err)
	}
}

func TestBruteForceBurnsTheCode(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	db.IssueCode(ctx, id, PurposeLoginOTP, "123456", 10*time.Minute)
	for i := 0; i < MaxOTPAttempts-1; i++ {
		if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "000000"); !errors.Is(err, ErrCodeInvalid) {
			t.Fatalf("attempt %d: got %v", i, err)
		}
	}
	// The attempt that hits the cap.
	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "000000"); !errors.Is(err, ErrCodeAttempts) {
		t.Fatalf("want ErrCodeAttempts at the cap, got %v", err)
	}
	// Even the correct code is now dead — the code is burned, not just throttled.
	if err := db.ConsumeCode(ctx, id, PurposeLoginOTP, "123456"); err == nil {
		t.Fatal("correct code still worked after the attempt cap was hit")
	}
}

func TestPurposesAreIsolated(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	db.IssueCode(ctx, id, PurposeLoginOTP, "123456", 10*time.Minute)
	if err := db.ConsumeCode(ctx, id, PurposePasswordReset, "123456"); err == nil {
		t.Fatal("a login OTP was redeemed as a password reset")
	}
}

func TestConsumeTokenReturnsIdentifier(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	id := ident()

	tok, err := NewOpaqueToken()
	if err != nil {
		t.Fatal(err)
	}
	if err := db.IssueCode(ctx, id, PurposeEmailVerify, tok, time.Hour); err != nil {
		t.Fatal(err)
	}
	got, err := db.ConsumeToken(ctx, PurposeEmailVerify, tok)
	if err != nil {
		t.Fatal(err)
	}
	if got != id {
		t.Fatalf("identifier = %q, want %q", got, id)
	}
	if _, err := db.ConsumeToken(ctx, PurposeEmailVerify, tok); !errors.Is(err, ErrCodeInvalid) {
		t.Fatal("token was redeemable twice")
	}
}

func TestConsumeTokenRejectsWrongPurpose(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	tok, _ := NewOpaqueToken()
	db.IssueCode(ctx, ident(), PurposeEmailVerify, tok, time.Hour)

	if _, err := db.ConsumeToken(ctx, PurposePasswordReset, tok); !errors.Is(err, ErrCodeInvalid) {
		t.Fatal("an email-verify token was accepted as a password reset")
	}
}

func TestNewNumericCodeShape(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 50; i++ {
		c, err := NewNumericCode(6)
		if err != nil {
			t.Fatal(err)
		}
		if len(c) != 6 {
			t.Fatalf("code %q is not 6 digits", c)
		}
		for _, r := range c {
			if r < '0' || r > '9' {
				t.Fatalf("code %q has a non-digit", c)
			}
		}
		seen[c] = true
	}
	if len(seen) < 40 {
		t.Fatalf("only %d distinct codes in 50 draws; entropy looks wrong", len(seen))
	}
}

func TestAllowFixedWindow(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	bucket := "test:" + ulid.Make().String()

	for i := 0; i < 3; i++ {
		ok, err := db.Allow(ctx, bucket, 3, time.Minute)
		if err != nil {
			t.Fatal(err)
		}
		if !ok {
			t.Fatalf("request %d denied while under the limit", i+1)
		}
	}
	ok, err := db.Allow(ctx, bucket, 3, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if ok {
		t.Fatal("request over the limit was allowed")
	}
}

func TestAllowWindowRollsOver(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	bucket := "test:" + ulid.Make().String()

	db.Allow(ctx, bucket, 1, time.Minute)
	if ok, _ := db.Allow(ctx, bucket, 1, time.Minute); ok {
		t.Fatal("over-limit request allowed in the same window")
	}

	db.now = func() time.Time { return time.Now().Add(2 * time.Minute) }
	if ok, _ := db.Allow(ctx, bucket, 1, time.Minute); !ok {
		t.Fatal("limit did not reset in the next window")
	}
}

func TestAllowBucketsAreIndependent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	a := "test:a:" + ulid.Make().String()
	b := "test:b:" + ulid.Make().String()

	db.Allow(ctx, a, 1, time.Minute)
	db.Allow(ctx, a, 1, time.Minute)
	if ok, _ := db.Allow(ctx, b, 1, time.Minute); !ok {
		t.Fatal("exhausting one bucket throttled an unrelated one")
	}
}
