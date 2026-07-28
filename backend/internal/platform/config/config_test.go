package config

import (
	"testing"
	"time"
)

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
	t.Setenv("OPENIAM_SESSION_TTL", "")
	t.Setenv("OPENIAM_LOGIN_ATTEMPT_LIMIT", "")

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
	if cfg.Session.TTL != 12*time.Hour {
		t.Fatalf("unexpected session ttl %s", cfg.Session.TTL)
	}
	if cfg.Security.LoginAttemptLimit != 5 {
		t.Fatalf("unexpected login attempt limit %d", cfg.Security.LoginAttemptLimit)
	}
	if cfg.Security.LoginLockDuration != 15*time.Minute {
		t.Fatalf("unexpected lock duration %s", cfg.Security.LoginLockDuration)
	}
}

func TestLoadParsesSecurityOverrides(t *testing.T) {
	t.Setenv("OPENIAM_SESSION_TTL", "30m")
	t.Setenv("OPENIAM_LOGIN_ATTEMPT_LIMIT", "3")
	t.Setenv("OPENIAM_LOGIN_LOCK_DURATION", "5m")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if cfg.Session.TTL != 30*time.Minute {
		t.Fatalf("unexpected session ttl %s", cfg.Session.TTL)
	}
	if cfg.Security.LoginAttemptLimit != 3 {
		t.Fatalf("unexpected login attempt limit %d", cfg.Security.LoginAttemptLimit)
	}
	if cfg.Security.LoginLockDuration != 5*time.Minute {
		t.Fatalf("unexpected lock duration %s", cfg.Security.LoginLockDuration)
	}
}

func TestLoadSMTPAndFeishu(t *testing.T) {
	t.Setenv("OPENIAM_SMTP_HOST", "smtp.openrealm.io")
	t.Setenv("OPENIAM_SMTP_PORT", "465")
	t.Setenv("OPENIAM_SMTP_TLS", "implicit")
	t.Setenv("OPENIAM_FEISHU_APP_ID", "cli_x")
	t.Setenv("OPENIAM_FEISHU_APP_SECRET", "secret")

	cfg, err := Load()
	if err != nil {
		t.Fatalf("load config: %v", err)
	}
	if !cfg.SMTP.Enabled() || cfg.SMTP.Port != 465 || cfg.SMTP.TLS != "implicit" {
		t.Fatalf("unexpected smtp config %+v", cfg.SMTP)
	}
	if !cfg.Feishu.Enabled() {
		t.Fatalf("expected feishu to be enabled, got %+v", cfg.Feishu)
	}
}

func TestLoadRejectsInvalidSMTPTLS(t *testing.T) {
	t.Setenv("OPENIAM_SMTP_HOST", "smtp.openrealm.io")
	t.Setenv("OPENIAM_SMTP_TLS", "bogus")
	if _, err := Load(); err == nil {
		t.Fatal("expected invalid TLS mode to be rejected")
	}
}
