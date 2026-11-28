package security

import (
	"errors"
	"fmt"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"golang.org/x/crypto/bcrypt"
)

const bcryptCost = 10

// ScopePasswordChange 为强制改密状态下签发的受限 Access Token 的 scope 标记：
// 该令牌只能用于 POST /api/v1/auth/change-password 与退出登录。
const ScopePasswordChange = "password_change"

// PasswordChangeTokenTTL 为强制改密受限令牌的有效期。
const PasswordChangeTokenTTL = 5 * time.Minute

// ErrPasswordChangeRequired 表示账号必须先完成改密才能进行当前操作（OAuth2 令牌签发路径使用）。
var ErrPasswordChangeRequired = errors.New("account requires password change")

const (
	// InitialPasswordMinLength 为初始管理员口令的最小长度，比普通注册（8 位）更严格。
	InitialPasswordMinLength = 12
	// InitialPasswordMaxLength 与 bcrypt 的 72 字节输入上限保持一致。
	InitialPasswordMaxLength = 72
)

// legacyDefaultPasswords 为历史版本内置过或文档出现过的默认超级管理员口令，禁止再次作为初始口令使用。
var legacyDefaultPasswords = []string{
	"Admin@123456",
	"admin123456",
	"OpenIAM@123456",
}

func HashPassword(plain string) (string, error) {
	b, err := bcrypt.GenerateFromPassword([]byte(plain), bcryptCost)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func VerifyPassword(hash, plain string) bool {
	if hash == "" || plain == "" {
		return false
	}
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(plain)) == nil
}

// IsLegacyDefaultPassword 判断明文是否属于历史默认口令。
func IsLegacyDefaultPassword(plain string) bool {
	candidate := strings.TrimSpace(plain)
	for _, known := range legacyDefaultPasswords {
		if candidate == known {
			return true
		}
	}
	return false
}

// MatchesLegacyDefaultPassword 用 bcrypt 比对存量口令哈希是否仍对应历史默认口令。
// 哈希为空或不匹配时返回 false；已改过密的管理员不会命中。
func MatchesLegacyDefaultPassword(hash string) bool {
	if hash == "" {
		return false
	}
	for _, known := range legacyDefaultPasswords {
		if VerifyPassword(hash, known) {
			return true
		}
	}
	return false
}

// ValidateInitialPassword 校验空库初始化时提供的初始管理员口令是否满足策略。
// 所有错误信息只描述规则，绝不包含口令明文。
func ValidateInitialPassword(plain string) error {
	if strings.TrimSpace(plain) == "" {
		return errors.New("未提供初始管理员口令")
	}
	if utf8.RuneCountInString(plain) < InitialPasswordMinLength {
		return fmt.Errorf("口令长度不足 %d 位", InitialPasswordMinLength)
	}
	if len(plain) > InitialPasswordMaxLength {
		return fmt.Errorf("口令长度超过 %d 字节", InitialPasswordMaxLength)
	}
	var hasUpper, hasLower, hasDigit bool
	for _, r := range plain {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		}
	}
	if !hasUpper || !hasLower || !hasDigit {
		return errors.New("口令必须同时包含大写字母、小写字母与数字")
	}
	if IsLegacyDefaultPassword(plain) {
		return errors.New("口令属于历史默认口令，禁止使用")
	}
	return nil
}
