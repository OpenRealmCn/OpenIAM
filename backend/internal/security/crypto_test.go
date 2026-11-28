package security

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecretCipherEncryptsAndMatchesLegacyPlaintext(t *testing.T) {
	c, err := NewSecretCipher([]byte("unit-test-key"))
	require.NoError(t, err)

	cipherText, err := c.Encrypt("smtp-授权码-123")
	require.NoError(t, err)
	assert.NotContains(t, cipherText, "smtp-授权码-123", "落库值里不能出现明文")
	assert.True(t, c.IsEncrypted(cipherText))

	plain, err := c.Decrypt(cipherText)
	require.NoError(t, err)
	assert.Equal(t, "smtp-授权码-123", plain)

	// 升级前存进去的历史明文必须原样读出，否则运维改配置会炸。
	legacy, err := c.Decrypt("legacy-plain-password")
	require.NoError(t, err)
	assert.Equal(t, "legacy-plain-password", legacy)

	empty, err := c.Encrypt("")
	require.NoError(t, err)
	assert.Equal(t, "", empty)

	other, err := NewSecretCipher([]byte("different-key"))
	require.NoError(t, err)
	_, err = other.Decrypt(cipherText)
	assert.Error(t, err, "换密钥后必须解密失败而不是静默返回垃圾")
}
