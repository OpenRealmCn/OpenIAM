package totp

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestGenerateAndVerifyTOTP(t *testing.T) {
	secret, err := GenerateSecret()
	require.NoError(t, err)
	require.NotEmpty(t, secret)

	now := time.Now()
	code, err := GenerateCode(secret, now)
	require.NoError(t, err)
	require.Len(t, code, 6)

	assert.True(t, VerifyCode(secret, code, now))
	assert.True(t, VerifyCode(secret, code, now.Add(25*time.Second)))
	assert.False(t, VerifyCode(secret, "000000", now.Add(10*time.Minute)))

	uri := BuildOtpAuthURI("OpenIAM", "alice", secret)
	assert.Contains(t, uri, "otpauth://totp/")
	assert.Contains(t, uri, "secret="+secret)
}

func TestRecoveryCodes(t *testing.T) {
	plain, hashes, err := GenerateRecoveryCodes(10)
	require.NoError(t, err)
	require.Len(t, plain, 10)
	require.Len(t, hashes, 10)
	assert.Equal(t, hashes[0], HashRecoveryCode(plain[0]))
}
