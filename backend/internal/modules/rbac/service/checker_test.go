package service

import "testing"

func TestContainsPermission(t *testing.T) {
	cases := []struct {
		name  string
		codes []string
		code  string
		want  bool
	}{
		{"exact match", []string{"users:read", "roles:read"}, "users:read", true},
		{"no match", []string{"users:read"}, "users:create", false},
		{"wildcard grants everything", []string{"*:*"}, "oauth-clients:rotate-secret", true},
		{"empty set", []string{}, "users:read", false},
		{"nil set", nil, "users:read", false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := ContainsPermission(tc.codes, tc.code); got != tc.want {
				t.Fatalf("ContainsPermission(%v, %q) = %v, want %v", tc.codes, tc.code, got, tc.want)
			}
		})
	}
}
