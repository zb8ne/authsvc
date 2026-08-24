package oauth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

func TestVerifierIsRandomAndWellFormed(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 20; i++ {
		v, err := NewVerifier()
		if err != nil {
			t.Fatal(err)
		}
		// RFC 7636 requires 43-128 unreserved characters.
		if len(v) < 43 || len(v) > 128 {
			t.Fatalf("verifier length %d is outside the RFC 7636 range", len(v))
		}
		if strings.ContainsAny(v, "+/=") {
			t.Fatalf("verifier %q is not base64url without padding", v)
		}
		if seen[v] {
			t.Fatal("duplicate verifier")
		}
		seen[v] = true
	}
}

func TestChallengeIsS256OfVerifier(t *testing.T) {
	v, _ := NewVerifier()
	sum := sha256.Sum256([]byte(v))
	want := base64.RawURLEncoding.EncodeToString(sum[:])
	if got := Challenge(v); got != want {
		t.Fatalf("Challenge = %q, want %q", got, want)
	}
	// The challenge must not be reversible to the verifier.
	if strings.Contains(Challenge(v), v) {
		t.Fatal("challenge leaks the verifier")
	}
}

// GitHub's email selection carries the security decision for that provider:
// an address may only come back verified if GitHub said so.
func TestGitHubPickEmail(t *testing.T) {
	cases := []struct {
		name         string
		in           []githubEmail
		wantEmail    string
		wantVerified bool
	}{
		{
			"primary verified wins",
			[]githubEmail{
				{"secondary@x.com", false, true},
				{"primary@x.com", true, true},
			},
			"primary@x.com", true,
		},
		{
			"falls back to any verified address when the primary is not",
			[]githubEmail{
				{"primary@x.com", true, false},
				{"other@x.com", false, true},
			},
			"other@x.com", true,
		},
		{
			"an unverified primary is returned but never marked verified",
			[]githubEmail{{"primary@x.com", true, false}},
			"primary@x.com", false,
		},
		{
			"no addresses at all",
			nil,
			"", false,
		},
		{
			"nothing verified and no primary",
			[]githubEmail{{"a@x.com", false, false}},
			"", false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			email, verified := pickEmail(tc.in)
			if email != tc.wantEmail || verified != tc.wantVerified {
				t.Fatalf("got (%q, %v), want (%q, %v)", email, verified, tc.wantEmail, tc.wantVerified)
			}
			if verified {
				// Cross-check: nothing may be reported verified unless GitHub
				// flagged that exact address as verified.
				ok := false
				for _, e := range tc.in {
					if e.Email == email && e.Verified {
						ok = true
					}
				}
				if !ok {
					t.Fatalf("%q reported verified but GitHub did not say so", email)
				}
			}
		})
	}
}

func TestProviderNamesAreStable(t *testing.T) {
	// These strings are persisted in identities.provider; changing one would
	// orphan every existing link.
	if got := NewGoogle("a", "b", "c").Name(); got != "google" {
		t.Errorf("google provider name = %q", got)
	}
	if got := NewGitHub("a", "b", "c").Name(); got != "github" {
		t.Errorf("github provider name = %q", got)
	}
}

func TestAuthURLCarriesPKCEAndState(t *testing.T) {
	for _, p := range []Provider{
		NewGoogle("id", "secret", "https://auth.test/cb"),
		NewGitHub("id", "secret", "https://auth.test/cb"),
	} {
		u := p.AuthURL("the-state", "the-challenge")
		for _, want := range []string{"the-state", "the-challenge", "code_challenge_method=S256"} {
			if !strings.Contains(u, want) {
				t.Errorf("%s auth URL missing %q: %s", p.Name(), want, u)
			}
		}
	}
}

var (
	_ Provider = (*Google)(nil)
	_ Provider = (*GitHub)(nil)
)
