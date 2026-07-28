package mailer

import (
	"strings"
	"testing"
)

func TestBuildMIMEPlainText(t *testing.T) {
	raw := string(buildMIME("OpenIAM", "no-reply@openrealm.io", Message{
		To:      []string{"alice@openrealm.io"},
		Subject: "欢迎加入",
		Text:    "你好",
	}))

	for _, want := range []string{
		"From: \"OpenIAM\" <no-reply@openrealm.io>",
		"To: alice@openrealm.io",
		"Subject: =?utf-8?q?",
		"Content-Type: text/plain; charset=UTF-8",
		"你好",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("expected MIME to contain %q, got:\n%s", want, raw)
		}
	}
	if strings.Contains(raw, "multipart/alternative") {
		t.Fatal("plain-only message should not be multipart")
	}
}

func TestBuildMIMEMultipart(t *testing.T) {
	raw := string(buildMIME("OpenIAM", "no-reply@openrealm.io", Message{
		To:      []string{"alice@openrealm.io"},
		Subject: "Welcome",
		Text:    "text body",
		HTML:    "<p>html body</p>",
	}))

	if !strings.Contains(raw, "multipart/alternative") {
		t.Fatal("expected multipart message when HTML is present")
	}
	if !strings.Contains(raw, "text body") || !strings.Contains(raw, "<p>html body</p>") {
		t.Fatal("expected both text and html parts")
	}
}

func TestDomainOf(t *testing.T) {
	if got := domainOf("no-reply@openrealm.io"); got != "openrealm.io" {
		t.Fatalf("unexpected domain %q", got)
	}
	if got := domainOf("invalid"); got != "openrealm.io" {
		t.Fatalf("expected fallback domain, got %q", got)
	}
}
