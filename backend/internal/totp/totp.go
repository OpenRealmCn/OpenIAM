package totp

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base32"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const (
	DefaultDigits = 6
	DefaultPeriod = 30
)

var base32NoPad = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret 生成 20 字节随机密钥并返回无填充 Base32 编码字符串。
func GenerateSecret() (string, error) {
	buf := make([]byte, 20)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return base32NoPad.EncodeToString(buf), nil
}

// BuildOtpAuthURI 构造标准 otpauth://totp/... 绑定链接供验证器 App 扫描。
func BuildOtpAuthURI(issuer, account, secret string) string {
	if issuer == "" {
		issuer = "OpenIAM"
	}
	label := url.PathEscape(fmt.Sprintf("%s:%s", issuer, account))
	q := url.Values{}
	q.Set("secret", secret)
	q.Set("issuer", issuer)
	q.Set("algorithm", "SHA1")
	q.Set("digits", "6")
	q.Set("period", "30")
	return fmt.Sprintf("otpauth://totp/%s?%s", label, q.Encode())
}

// GenerateCode 根据 RFC 6238 计算指定时刻的 6 位 TOTP 动态口令。
func GenerateCode(secret string, at time.Time) (string, error) {
	norm := strings.ToUpper(strings.TrimSpace(strings.ReplaceAll(secret, " ", "")))
	key, err := base32NoPad.DecodeString(norm)
	if err != nil {
		return "", fmt.Errorf("invalid base32 secret: %w", err)
	}
	counter := uint64(at.Unix() / DefaultPeriod)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], counter)

	mac := hmac.New(sha1.New, key)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	offset := sum[len(sum)-1] & 0x0f
	codeInt := (int(sum[offset]&0x7f) << 24) |
		(int(sum[offset+1]&0xff) << 16) |
		(int(sum[offset+2]&0xff) << 8) |
		int(sum[offset+3]&0xff)
	return fmt.Sprintf("%06d", codeInt%1000000), nil
}

// VerifyCode 校验 TOTP 动态口令（容许前后各 1 个 30 秒时间窗口漂移）。
func VerifyCode(secret, code string, now time.Time) bool {
	_, ok := VerifyCodeStep(secret, code, now)
	return ok
}

// VerifyCodeStep 的判定与 VerifyCode 一致，但额外返回命中的时间步（Unix 秒 / 30）。
// 调用方必须把该时间步与「已用过的最大时间步」比较并前移水位：同一串动态码在其
// 有效的 90 秒窗口内可以被重复提交，只有记录用过的步长才能挡住重放。
func VerifyCodeStep(secret, code string, now time.Time) (int64, bool) {
	code = strings.TrimSpace(code)
	if len(code) != DefaultDigits {
		return 0, false
	}
	for _, offset := range []int64{-1, 0, 1} {
		t := now.Add(time.Duration(offset*DefaultPeriod) * time.Second)
		expected, err := GenerateCode(secret, t)
		if err == nil && subtle.ConstantTimeCompare([]byte(expected), []byte(code)) == 1 {
			return t.Unix() / DefaultPeriod, true
		}
	}
	return 0, false
}

// GenerateRecoveryCodes 生成 10 组 8 位一次性备用恢复码以及其 SHA-256 哈希数组。
func GenerateRecoveryCodes(n int) (plain []string, hashes []string, err error) {
	if n <= 0 {
		n = 10
	}
	const alphabet = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"
	plain = make([]string, 0, n)
	hashes = make([]string, 0, n)
	for i := 0; i < n; i++ {
		raw := make([]byte, 8)
		if _, rErr := rand.Read(raw); rErr != nil {
			return nil, nil, rErr
		}
		var b strings.Builder
		for idx, ch := range raw {
			if idx == 4 {
				b.WriteByte('-')
			}
			b.WriteByte(alphabet[int(ch)%len(alphabet)])
		}
		code := b.String()
		plain = append(plain, code)
		hashes = append(hashes, HashRecoveryCode(code))
	}
	return plain, hashes, nil
}

func HashRecoveryCode(code string) string {
	norm := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(code), "-", ""))
	sum := sha256.Sum256([]byte(norm))
	return hex.EncodeToString(sum[:])
}
