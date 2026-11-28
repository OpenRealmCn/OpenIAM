package risk

import (
	"testing"

	"github.com/openrealm/openiam/internal/models"
)

func TestIsKnownDevice(t *testing.T) {
	withFP := []models.UserSession{{DeviceFingerprint: "fp-a"}, {DeviceFingerprint: ""}}
	noFP := []models.UserSession{{DeviceFingerprint: ""}, {DeviceFingerprint: ""}}

	cases := []struct {
		name     string
		sessions []models.UserSession
		fp       string
		want     bool
	}{
		{"matching fingerprint", withFP, "fp-a", true},
		{"different fingerprint", withFP, "fp-b", false},
		{"omitted fingerprint cannot impersonate a fingerprinted device", withFP, "", false},
		{"omitted fingerprint when history never had one", noFP, "", true},
		{"new fingerprint against fingerprint-less history", noFP, "fp-a", false},
	}
	for _, tc := range cases {
		if got := isKnownDevice(tc.sessions, tc.fp); got != tc.want {
			t.Errorf("%s: isKnownDevice(%q) = %v, want %v", tc.name, tc.fp, got, tc.want)
		}
	}
}
