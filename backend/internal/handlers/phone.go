package handlers

import (
	"errors"
	"regexp"
	"strings"

	"github.com/openrealm/openiam/internal/security"
)

// phonePattern 限制手机号为可选前导 + 加 6~20 位数字。
var phonePattern = regexp.MustCompile(`^\+?[0-9]{6,20}$`)

// normalizePhone 去掉手机号中的空格、连字符、括号与点号，使「138 0000 0000」与「13800000000」落到同一个值，
// 唯一性约束、验证码发送与校验都以归一化后的值为准。
func normalizePhone(p string) string {
	return strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '(', ')', '.', '\t':
			return -1
		}
		return r
	}, strings.TrimSpace(p))
}

// normalizeEmail 统一邮箱大小写与首尾空白。
func normalizeEmail(e string) string {
	return strings.ToLower(strings.TrimSpace(e))
}

// otpFailureMessage 只对「次数用尽」给出具体提示，其余校验失败一律返回 fallback，
// 不区分验证码不存在与验证码错误。
func otpFailureMessage(err error, fallback string) string {
	if errors.Is(err, security.ErrTooManyAttempts) {
		return err.Error()
	}
	return fallback
}

// normalizeContactTarget 按是否包含 @ 判断联系方式类型并归一化。
func normalizeContactTarget(t string) string {
	if strings.Contains(t, "@") {
		return normalizeEmail(t)
	}
	return normalizePhone(t)
}
