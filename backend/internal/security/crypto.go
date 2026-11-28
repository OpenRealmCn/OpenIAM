package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
)

// secretPrefix 标识「已加密」的存量值；不带前缀的值按历史明文处理，读取时原样返回。
const secretPrefix = "enc:v1:"

// SecretCipher 用 AES-256-GCM 加密需要落库的敏感配置（目前是 SMTP 授权码）。
// 密钥由部署方通过 OPENIAM_ENCRYPTION_KEY 提供，未提供时用 JWT 私钥材料派生。
type SecretCipher struct {
	aead cipher.AEAD
}

// NewSecretCipher 从任意长度的口令材料派生 32 字节密钥并初始化 AES-GCM。
func NewSecretCipher(secret []byte) (*SecretCipher, error) {
	if len(secret) == 0 {
		return nil, errors.New("加密密钥为空")
	}
	sum := sha256.Sum256(secret)
	block, err := aes.NewCipher(sum[:])
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	return &SecretCipher{aead: aead}, nil
}

// Encrypt 加密明文，返回带版本前缀的密文；空串保持空串。
func (c *SecretCipher) Encrypt(plain string) (string, error) {
	if c == nil {
		return "", errors.New("加密器未初始化")
	}
	if plain == "" {
		return "", nil
	}
	nonce := make([]byte, c.aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := c.aead.Seal(nonce, nonce, []byte(plain), nil)
	return secretPrefix + base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt 解密带前缀的密文；不带前缀的历史明文原样返回，便于平滑升级。
func (c *SecretCipher) Decrypt(stored string) (string, error) {
	if stored == "" || !strings.HasPrefix(stored, secretPrefix) {
		return stored, nil
	}
	if c == nil {
		return "", errors.New("加密器未初始化，无法解密敏感配置")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, secretPrefix))
	if err != nil {
		return "", fmt.Errorf("密文编码无效: %w", err)
	}
	ns := c.aead.NonceSize()
	if len(raw) < ns {
		return "", errors.New("密文长度不足")
	}
	plain, err := c.aead.Open(nil, raw[:ns], raw[ns:], nil)
	if err != nil {
		return "", fmt.Errorf("解密失败（密钥可能已更换）: %w", err)
	}
	return string(plain), nil
}

// IsEncrypted 判断存量值是否已经是本方案加密后的密文。
func (c *SecretCipher) IsEncrypted(v string) bool {
	return strings.HasPrefix(v, secretPrefix)
}
