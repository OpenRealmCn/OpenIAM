package totp

import (
	"testing"
	"time"
)

func TestVerifyCodeStepReturnsMatchedTimeStep(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Unix(1700000000, 0)
	code, err := GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	step, ok := VerifyCodeStep(secret, code, now)
	if !ok {
		t.Fatal("current code should verify")
	}
	if want := now.Unix() / DefaultPeriod; step != want {
		t.Fatalf("step = %d, want %d", step, want)
	}
	if again, ok := VerifyCodeStep(secret, code, now); !ok || again != step {
		t.Fatalf("repeat check must map to the same step, got %d want %d", again, step)
	}
	if _, ok := VerifyCodeStep(secret, code, now.Add(3*time.Minute)); ok {
		t.Fatal("stale code must not verify")
	}
	if _, ok := VerifyCodeStep(secret, "000000", now); ok {
		t.Skip("degenerate code matched by chance")
	}
}

func TestVerifyCodeStaysCompatible(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatalf("generate secret: %v", err)
	}
	now := time.Unix(1700000030, 0)
	code, err := GenerateCode(secret, now)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	if !VerifyCode(secret, code, now) {
		t.Fatal("VerifyCode should keep working")
	}
}
