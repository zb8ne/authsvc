// Package linking resolves an OAuth profile to a user account.
//
// This is the only place in the service where a bug becomes an account
// takeover, which is why it is isolated and why every branch below is covered
// by a table-driven test.
//
// The rule, from the spec: link an OAuth login to an existing user only when
// BOTH hold:
//
//  1. the provider reports email_verified = true, AND
//  2. that email is already verified on the target user
//
// Anything looser is account takeover via unverified email. Two concrete
// attacks it stops:
//
//   - A provider that lets a user set any unclaimed email on their profile. If
//     we trusted an unverified provider email, an attacker sets it to
//     victim@corp.com and signs in as the victim.
//   - A local signup that never verified its address. If we linked a genuinely
//     verified Google login into it, the attacker is the one who registered
//     victim@corp.com locally first and now inherits the real owner's Google
//     identity — the takeover runs in the other direction.
package linking

import (
	"context"
	"errors"

	"github.com/zb8ne/authsvc/internal/oauth"
	"github.com/zb8ne/authsvc/internal/store"
)

// ErrManualLinkRequired means the provider account is genuinely new to us, but
// its email already belongs to an existing account and the conditions for a
// safe automatic link are not met.
//
// The spec says "otherwise create a new user", but users.email is UNIQUE, so a
// second account cannot hold that address. Refusing is the right resolution:
// the two remaining options are to link (which is the takeover the rule exists
// to prevent) or to silently take the address from its current owner. The user
// is told to sign in by their existing method and link from settings, which
// proves control of both sides.
var ErrManualLinkRequired = errors.New("linking: email already belongs to another account; sign in and link it from settings")

// ErrAlreadyLinkedElsewhere means this provider account is attached to a
// different user. Re-pointing it would silently move an identity between
// accounts.
var ErrAlreadyLinkedElsewhere = errors.New("linking: this provider account is already linked to another user")

type Outcome string

const (
	// OutcomeExisting: the (provider, subject) pair was already known.
	OutcomeExisting Outcome = "existing"
	// OutcomeLinked: attached to an existing user under the rule above.
	OutcomeLinked Outcome = "linked"
	// OutcomeCreated: a brand-new user.
	OutcomeCreated Outcome = "created"
)

type Result struct {
	User    *store.User
	Outcome Outcome
}

// Store is the narrow slice of persistence that resolution needs.
type Store interface {
	IdentityBySubject(ctx context.Context, provider, subject string) (*store.Identity, error)
	UserByEmail(ctx context.Context, email string) (*store.User, error)
	UserByID(ctx context.Context, id string) (*store.User, error)
	CreateIdentity(ctx context.Context, i store.Identity) (*store.Identity, error)
	CreateUserWithIdentity(ctx context.Context, email string, emailVerified bool, i store.Identity) (*store.User, *store.Identity, error)
}

// Resolve maps a provider profile to a user, creating or linking as the rule
// allows. normalizeEmail must already have been applied to p.Email.
func Resolve(ctx context.Context, s Store, provider string, p *oauth.Profile) (*Result, error) {
	if p.Subject == "" {
		// Without a stable subject there is nothing safe to key on. Falling
		// back to email here would be exactly the bug this package prevents.
		return nil, errors.New("linking: provider returned no subject")
	}

	// 1. Known identity wins outright. The provider's own id is the only
	//    stable key, and it settles the question without consulting email —
	//    which matters because a user can change their email at the provider.
	existing, err := s.IdentityBySubject(ctx, provider, p.Subject)
	if err == nil {
		u, err := s.UserByID(ctx, existing.UserID)
		if err != nil {
			return nil, err
		}
		return &Result{User: u, Outcome: OutcomeExisting}, nil
	}
	if !errors.Is(err, store.ErrNotFound) {
		return nil, err
	}

	// 2. New provider account. Does its email already belong to someone?
	var owner *store.User
	if p.Email != "" {
		owner, err = s.UserByEmail(ctx, p.Email)
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return nil, err
		}
	}

	identity := store.Identity{
		Provider: provider, Subject: p.Subject,
		Email: p.Email, EmailVerified: p.EmailVerified, RawProfile: p.Raw,
	}

	if owner == nil {
		// Nobody holds this address: a new account is unambiguous. It starts
		// verified only if the provider vouched for the address.
		u, _, err := s.CreateUserWithIdentity(ctx, p.Email, p.EmailVerified, identity)
		if err != nil {
			return nil, err
		}
		return &Result{User: u, Outcome: OutcomeCreated}, nil
	}

	// 3. The address is taken. Both halves of the rule must hold to link.
	if !p.EmailVerified || !owner.EmailVerified() {
		return nil, ErrManualLinkRequired
	}

	identity.UserID = owner.ID
	if _, err := s.CreateIdentity(ctx, identity); err != nil {
		return nil, err
	}
	return &Result{User: owner, Outcome: OutcomeLinked}, nil
}

// LinkToUser attaches a provider account to an already-authenticated user.
//
// The email rule does not apply here and deliberately so: the caller has proved
// control of the local account (a valid access token) and of the provider
// account (a completed OAuth round trip). That is strictly stronger evidence
// than a matching verified email. The only thing that can go wrong is stealing
// an identity from another account, which is what the check below prevents.
func LinkToUser(ctx context.Context, s Store, userID, provider string, p *oauth.Profile) (*store.Identity, error) {
	if p.Subject == "" {
		return nil, errors.New("linking: provider returned no subject")
	}

	existing, err := s.IdentityBySubject(ctx, provider, p.Subject)
	switch {
	case err == nil && existing.UserID == userID:
		return existing, nil // already linked to this user; nothing to do
	case err == nil:
		return nil, ErrAlreadyLinkedElsewhere
	case !errors.Is(err, store.ErrNotFound):
		return nil, err
	}

	return s.CreateIdentity(ctx, store.Identity{
		UserID: userID, Provider: provider, Subject: p.Subject,
		Email: p.Email, EmailVerified: p.EmailVerified, RawProfile: p.Raw,
	})
}
