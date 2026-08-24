package linking

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/oklog/ulid/v2"

	"github.com/zb8ne/authsvc/internal/oauth"
	"github.com/zb8ne/authsvc/internal/store"
)

func testDB(t *testing.T) *store.DB {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set")
	}
	ctx := context.Background()
	if err := store.Migrate(ctx, dsn); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	db, err := store.Open(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(db.Close)
	return db
}

func email() string   { return "u-" + strings.ToLower(ulid.Make().String()) + "@example.test" }
func subject() string { return "sub-" + strings.ToLower(ulid.Make().String()) }

// userState describes the local account before the OAuth login arrives.
type userState int

const (
	noUser userState = iota
	userVerified
	userUnverified
)

func (u userState) String() string {
	switch u {
	case noUser:
		return "no local user"
	case userVerified:
		return "local user, email verified"
	default:
		return "local user, email unverified"
	}
}

// setup materialises the described precondition and returns the email in play
// plus the id of the pre-existing user (empty when there is none).
func setup(t *testing.T, db *store.DB, us userState, alreadyLinked bool, provider, sub string) (string, string) {
	t.Helper()
	ctx := context.Background()
	addr := email()

	if us == noUser {
		if alreadyLinked {
			// The identity must hang off some user; use an unrelated one so the
			// "address is free" precondition still holds.
			other, err := db.CreateUser(ctx, email(), nil)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.CreateIdentity(ctx, store.Identity{
				UserID: other.ID, Provider: provider, Subject: sub, Email: addr,
			}); err != nil {
				t.Fatal(err)
			}
			return addr, other.ID
		}
		return addr, ""
	}

	u, err := db.CreateUser(ctx, addr, nil)
	if err != nil {
		t.Fatal(err)
	}
	if us == userVerified {
		if err := db.MarkEmailVerified(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
	}
	if alreadyLinked {
		if _, err := db.CreateIdentity(ctx, store.Identity{
			UserID: u.ID, Provider: provider, Subject: sub, Email: addr,
		}); err != nil {
			t.Fatal(err)
		}
	}
	return addr, u.ID
}

// The matrix the spec asks for: {provider verified, unverified} x {user exists
// verified, exists unverified, doesn't exist} x {provider already linked, not}.
func TestResolveMatrix(t *testing.T) {
	db := testDB(t)
	const provider = "google"

	type want struct {
		outcome Outcome
		err     error
		// sameUser asserts the resolved user is the pre-existing one.
		sameUser bool
	}

	cases := []struct {
		user             userState
		providerVerified bool
		alreadyLinked    bool
		want             want
	}{
		// Already linked: the (provider, subject) pair settles it every time,
		// regardless of email state. Email is never consulted on this path.
		{noUser, true, true, want{outcome: OutcomeExisting, sameUser: true}},
		{noUser, false, true, want{outcome: OutcomeExisting, sameUser: true}},
		{userVerified, true, true, want{outcome: OutcomeExisting, sameUser: true}},
		{userVerified, false, true, want{outcome: OutcomeExisting, sameUser: true}},
		{userUnverified, true, true, want{outcome: OutcomeExisting, sameUser: true}},
		{userUnverified, false, true, want{outcome: OutcomeExisting, sameUser: true}},

		// Not linked, address free: always a new account. It inherits verified
		// status only when the provider vouched for the address.
		{noUser, true, false, want{outcome: OutcomeCreated}},
		{noUser, false, false, want{outcome: OutcomeCreated}},

		// Not linked, address taken. The ONLY safe auto-link.
		{userVerified, true, false, want{outcome: OutcomeLinked, sameUser: true}},

		// Provider did not verify the address: refuse. This is the classic
		// takeover — an attacker sets an unverified provider email to a
		// victim's address.
		{userVerified, false, false, want{err: ErrManualLinkRequired}},

		// The local account never proved it owns the address, so it is not a
		// safe link target even for a genuinely verified provider login.
		{userUnverified, true, false, want{err: ErrManualLinkRequired}},
		{userUnverified, false, false, want{err: ErrManualLinkRequired}},
	}

	for _, tc := range cases {
		name := tc.user.String() +
			map[bool]string{true: " / provider verified", false: " / provider unverified"}[tc.providerVerified] +
			map[bool]string{true: " / already linked", false: " / not linked"}[tc.alreadyLinked]

		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			sub := subject()
			addr, existingID := setup(t, db, tc.user, tc.alreadyLinked, provider, sub)

			got, err := Resolve(ctx, db, provider, &oauth.Profile{
				Subject: sub, Email: addr, EmailVerified: tc.providerVerified,
			})

			if tc.want.err != nil {
				if !errors.Is(err, tc.want.err) {
					t.Fatalf("err = %v, want %v", err, tc.want.err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got.Outcome != tc.want.outcome {
				t.Errorf("outcome = %q, want %q", got.Outcome, tc.want.outcome)
			}
			if tc.want.sameUser && got.User.ID != existingID {
				t.Errorf("resolved to user %s, want the pre-existing %s", got.User.ID, existingID)
			}
			if !tc.want.sameUser && existingID != "" && got.User.ID == existingID {
				t.Errorf("resolved to the pre-existing user %s, want a new one", existingID)
			}
		})
	}
}

// The headline attack, spelled out on its own so a regression is unmistakable.
func TestUnverifiedProviderEmailCannotTakeOverAnAccount(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	victim, err := db.CreateUser(ctx, email(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.MarkEmailVerified(ctx, victim.ID); err != nil {
		t.Fatal(err)
	}
	victim, _ = db.UserByID(ctx, victim.ID)

	// Attacker points an unverified provider profile at the victim's address.
	_, err = Resolve(ctx, db, "github", &oauth.Profile{
		Subject: subject(), Email: victim.Email, EmailVerified: false,
	})
	if !errors.Is(err, ErrManualLinkRequired) {
		t.Fatalf("an unverified provider email resolved to the victim's account: err = %v", err)
	}

	ids, err := db.IdentitiesForUser(ctx, victim.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(ids) != 0 {
		t.Fatalf("an identity was attached to the victim: %+v", ids)
	}
}

// The mirror-image attack: squat the address locally without verifying it, then
// wait for the real owner to sign in with a verified provider account.
func TestUnverifiedLocalAccountCannotCaptureAVerifiedLogin(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	squatter, err := db.CreateUser(ctx, email(), nil) // never verified
	if err != nil {
		t.Fatal(err)
	}

	_, err = Resolve(ctx, db, "google", &oauth.Profile{
		Subject: subject(), Email: squatter.Email, EmailVerified: true,
	})
	if !errors.Is(err, ErrManualLinkRequired) {
		t.Fatalf("a verified login was captured by an unverified squatter: err = %v", err)
	}
}

// A provider account already known to us must resolve to its own user even if
// the email now points somewhere else entirely.
func TestKnownSubjectWinsOverAChangedEmail(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	sub := subject()

	owner, _ := db.CreateUser(ctx, email(), nil)
	db.CreateIdentity(ctx, store.Identity{
		UserID: owner.ID, Provider: "google", Subject: sub, Email: owner.Email,
	})

	// Someone else holds the address the provider now reports.
	other, _ := db.CreateUser(ctx, email(), nil)
	db.MarkEmailVerified(ctx, other.ID)

	got, err := Resolve(ctx, db, "google", &oauth.Profile{
		Subject: sub, Email: other.Email, EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.User.ID != owner.ID {
		t.Fatalf("resolved to %s, want the subject's own user %s", got.User.ID, owner.ID)
	}
}

func TestResolveRejectsEmptySubject(t *testing.T) {
	db := testDB(t)
	_, err := Resolve(context.Background(), db, "google", &oauth.Profile{
		Subject: "", Email: email(), EmailVerified: true,
	})
	if err == nil {
		t.Fatal("a profile with no subject was accepted; email would become the key")
	}
}

func TestNewUserInheritsProviderVerification(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	verified, err := Resolve(ctx, db, "google", &oauth.Profile{
		Subject: subject(), Email: email(), EmailVerified: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !verified.User.EmailVerified() {
		t.Error("a verified provider email did not produce a verified user")
	}

	unverified, err := Resolve(ctx, db, "google", &oauth.Profile{
		Subject: subject(), Email: email(), EmailVerified: false,
	})
	if err != nil {
		t.Fatal(err)
	}
	if unverified.User.EmailVerified() {
		t.Error("an unverified provider email produced a verified user")
	}
}

func TestLinkToUserAttachesIdentity(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	u, _ := db.CreateUser(ctx, email(), nil)
	sub := subject()

	if _, err := LinkToUser(ctx, db, u.ID, "github", &oauth.Profile{
		Subject: sub, Email: email(), EmailVerified: false,
	}); err != nil {
		t.Fatal(err)
	}

	ids, _ := db.IdentitiesForUser(ctx, u.ID)
	if len(ids) != 1 || ids[0].Subject != sub {
		t.Fatalf("identity not attached: %+v", ids)
	}
}

func TestLinkToUserIsIdempotent(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	u, _ := db.CreateUser(ctx, email(), nil)
	p := &oauth.Profile{Subject: subject(), Email: email()}

	if _, err := LinkToUser(ctx, db, u.ID, "github", p); err != nil {
		t.Fatal(err)
	}
	if _, err := LinkToUser(ctx, db, u.ID, "github", p); err != nil {
		t.Fatalf("re-linking the same identity errored: %v", err)
	}
	ids, _ := db.IdentitiesForUser(ctx, u.ID)
	if len(ids) != 1 {
		t.Fatalf("got %d identities, want 1", len(ids))
	}
}

// Linking must never move an identity off another account.
func TestLinkToUserRefusesToStealAnIdentity(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()

	owner, _ := db.CreateUser(ctx, email(), nil)
	attacker, _ := db.CreateUser(ctx, email(), nil)
	sub := subject()

	if _, err := LinkToUser(ctx, db, owner.ID, "github", &oauth.Profile{Subject: sub}); err != nil {
		t.Fatal(err)
	}
	_, err := LinkToUser(ctx, db, attacker.ID, "github", &oauth.Profile{Subject: sub})
	if !errors.Is(err, ErrAlreadyLinkedElsewhere) {
		t.Fatalf("err = %v, want ErrAlreadyLinkedElsewhere", err)
	}

	ids, _ := db.IdentitiesForUser(ctx, owner.ID)
	if len(ids) != 1 {
		t.Fatal("the original owner lost their identity")
	}
}

// Providers are namespaced: the same numeric subject at GitHub and Google is
// two different people.
func TestProvidersAreIsolated(t *testing.T) {
	db := testDB(t)
	ctx := context.Background()
	sub := subject()

	a, err := Resolve(ctx, db, "google", &oauth.Profile{Subject: sub, Email: email(), EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	b, err := Resolve(ctx, db, "github", &oauth.Profile{Subject: sub, Email: email(), EmailVerified: true})
	if err != nil {
		t.Fatal(err)
	}
	if a.User.ID == b.User.ID {
		t.Fatal("the same subject at two providers resolved to one user")
	}
}
