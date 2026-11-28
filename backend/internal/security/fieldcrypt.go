package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
)

// encPrefix 标记已加密的字段值；不带前缀的值按历史明文读取，便于存量数据平滑过渡。
const encPrefix = "enc:v1:"

var dataAEAD atomic.Pointer[cipher.AEAD]

// ErrDataKeyMissing 表示库里存在密文，但进程没有配置数据加密密钥。
var ErrDataKeyMissing = errors.New("数据库中存在已加密字段，但未配置 OPENIAM_DATA_ENCRYPTION_KEY")

// SetDataEncryptionKey 设置敏感字段（TOTP 密钥、身份源 client secret、SMTP 密码、插件密钥）的加密密钥。
// 接受 32 字节的 base64 或 hex 编码；传空字符串表示不加密。
func SetDataEncryptionKey(raw string) error {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		dataAEAD.Store(nil)
		return nil
	}
	key, err := decodeKey(raw)
	if err != nil {
		return err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return fmt.Errorf("初始化数据加密密钥失败: %w", err)
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return fmt.Errorf("初始化数据加密密钥失败: %w", err)
	}
	dataAEAD.Store(&aead)
	return nil
}

func decodeKey(raw string) ([]byte, error) {
	if b, err := hex.DecodeString(raw); err == nil && len(b) == 32 {
		return b, nil
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		if b, err := enc.DecodeString(raw); err == nil && len(b) == 32 {
			return b, nil
		}
	}
	return nil, errors.New("OPENIAM_DATA_ENCRYPTION_KEY 必须是 32 字节密钥的 base64 或 hex 编码")
}

// DataEncryptionEnabled 报告是否配置了数据加密密钥。
func DataEncryptionEnabled() bool { return dataAEAD.Load() != nil }

// IsSealed 判断字段值是否为密文。
func IsSealed(v string) bool { return strings.HasPrefix(v, encPrefix) }

// SealField 加密字段值；未配置密钥、值为空或已是密文时原样返回。
func SealField(plain string) (string, error) {
	p := dataAEAD.Load()
	if p == nil || plain == "" || IsSealed(plain) {
		return plain, nil
	}
	aead := *p
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", fmt.Errorf("生成加密随机数失败: %w", err)
	}
	out := aead.Seal(nonce, nonce, []byte(plain), nil)
	return encPrefix + base64.RawStdEncoding.EncodeToString(out), nil
}

// OpenField 解密字段值；不带前缀的历史明文原样返回。
func OpenField(stored string) (string, error) {
	if !IsSealed(stored) {
		return stored, nil
	}
	p := dataAEAD.Load()
	if p == nil {
		return "", ErrDataKeyMissing
	}
	aead := *p
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(stored, encPrefix))
	if err != nil || len(raw) < aead.NonceSize() {
		return "", errors.New("加密字段格式无效")
	}
	plain, err := aead.Open(nil, raw[:aead.NonceSize()], raw[aead.NonceSize():], nil)
	if err != nil {
		return "", errors.New("加密字段解密失败，请检查 OPENIAM_DATA_ENCRYPTION_KEY 是否正确")
	}
	return string(plain), nil
}
