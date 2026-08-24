package config

import (
	"strings"
	"testing"
)

func base(t *testing.T) {
	t.Helper()
	t.Setenv("DATABASE_URL", "postgres://x/y")
	t.Setenv("ED25519_PRIVATE_KEY", "key")
	t.Setenv("ADMIN_API_KEY", "admin")
	t.Setenv("DEV", "1")
}

func TestLoadDefaults(t *testing.T) {
	base(t)
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if c.Port != "8080" {
		t.Errorf("Port = %q", c.Port)
	}
	if c.AccessTTL.Hours() != 1 {
		t.Errorf("AccessTTL = %v, want 1h per spec", c.AccessTTL)
	}
	if c.SMTP.Port != 587 {
		t.Errorf("SMTP.Port = %d", c.SMTP.Port)
	}
}

func TestLoadFailsFastOnMissing(t *testing.T) {
	t.Setenv("DEV", "1")
	t.Setenv("DATABASE_URL", "")
	t.Setenv("ED25519_PRIVATE_KEY", "")
	t.Setenv("ADMIN_API_KEY", "")
	_, err := Load()
	if err == nil {
		t.Fatal("Load succeeded with no required env set")
	}
	for _, want := range []string{"DATABASE_URL", "ED25519_PRIVATE_KEY", "ADMIN_API_KEY"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not mention %s", err, want)
		}
	}
}

func TestIssuerMustBeHTTPSInProd(t *testing.T) {
	base(t)
	t.Setenv("DEV", "")
	t.Setenv("ISSUER", "http://auth.example.com")
	if _, err := Load(); err == nil {
		t.Fatal("accepted a plaintext issuer outside DEV")
	}
	t.Setenv("ISSUER", "https://auth.example.com/")
	c, err := Load()
	if err != nil {
		t.Fatal(err)
	}
	if strings.HasSuffix(c.Issuer, "/") {
		t.Error("trailing slash not trimmed from issuer; it must match the iss claim exactly")
	}
}

func TestOAuthAppConfigured(t *testing.T) {
	if (OAuthApp{ClientID: "a"}).Configured() {
		t.Error("half-configured OAuth app reported as configured")
	}
	if !(OAuthApp{ClientID: "a", ClientSecret: "b"}).Configured() {
		t.Error("fully configured app reported as unconfigured")
	}
}
