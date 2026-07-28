package crypto

import "testing"

func TestHashAndVerifyPassword(t *testing.T) {
	const password = "correct horse battery staple"

	encoded, err := HashPassword(password)
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}

	if !VerifyPassword(encoded, password) {
		t.Fatal("expected the correct password to verify")
	}
	if VerifyPassword(encoded, "wrong password") {
		t.Fatal("expected an incorrect password to fail verification")
	}
}

func TestHashPasswordProducesUniqueSalts(t *testing.T) {
	first, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	second, err := HashPassword("same-password")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if first == second {
		t.Fatal("expected unique salts to produce distinct hashes")
	}
}

func TestVerifyPasswordRejectsMalformedInput(t *testing.T) {
	cases := []string{"", "not-a-hash", "$argon2id$v=19$m=65536$abc", "$bcrypt$v=19$m=65536,t=3,p=2$abc$def"}
	for _, encoded := range cases {
		if VerifyPassword(encoded, "anything") {
			t.Fatalf("expected malformed hash %q to fail", encoded)
		}
	}
}

func TestTokenLength(t *testing.T) {
	token := Token(32)
	if len(token) != 64 {
		t.Fatalf("expected 64 hex characters, got %d", len(token))
	}
	if Token(32) == token {
		t.Fatal("expected tokens to be random")
	}
}
