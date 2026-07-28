package config

import "testing"

func TestLoadRejectsInsecureProductionCookie(t *testing.T) {
	t.Setenv("OPENIAM_ENV", "production")
	t.Setenv("OPENIAM_SESSION_COOKIE_SECURE", "false")

	if _, err := Load(); err == nil {
		t.Fatal("expected production configuration to reject an insecure cookie")
	}
}

func TestLoadUsesDevelopmentDefaults(t *testing.T) {
	t.Setenv("OPENIAM_ENV", "")
	t.Setenv("OPENIAM_REDIS_DATABASE", "")
	t.Setenv("OPENIAM_SESSION_COOKIE_SECURE", "")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Environment != "development" {
		t.Fatalf("expected development environment, got %q", cfg.Environment)
	}
	if cfg.Session.CookieName != "openiam_session" {
		t.Fatalf("unexpected cookie name %q", cfg.Session.CookieName)
	}
}
