package security

import (
	"crypto/rand"
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFieldCryptRoundTripAndLegacyPlaintext(t *testing.T) {
	t.Cleanup(func() { _ = SetDataEncryptionKey("") })

	sealed, err := SealField("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", sealed, "without a key values stay plaintext")

	key := make([]byte, 32)
	_, _ = rand.Read(key)
	require.NoError(t, SetDataEncryptionKey(base64.StdEncoding.EncodeToString(key)))

	sealed, err = SealField("JBSWY3DPEHPK3PXP")
	require.NoError(t, err)
	assert.True(t, IsSealed(sealed))
	assert.NotContains(t, sealed, "JBSWY3DPEHPK3PXP")

	again, err := SealField(sealed)
	require.NoError(t, err)
	assert.Equal(t, sealed, again, "sealing is idempotent")

	plain, err := OpenField(sealed)
	require.NoError(t, err)
	assert.Equal(t, "JBSWY3DPEHPK3PXP", plain)

	legacy, err := OpenField("legacy-plaintext")
	require.NoError(t, err)
	assert.Equal(t, "legacy-plaintext", legacy)

	other := make([]byte, 32)
	_, _ = rand.Read(other)
	require.NoError(t, SetDataEncryptionKey(base64.StdEncoding.EncodeToString(other)))
	_, err = OpenField(sealed)
	assert.Error(t, err, "wrong key must not decrypt")

	require.NoError(t, SetDataEncryptionKey(""))
	_, err = OpenField(sealed)
	assert.ErrorIs(t, err, ErrDataKeyMissing)

	assert.Error(t, SetDataEncryptionKey("too-short"))
}
