package otp

import "strings"

// maskEmail 对邮箱做脱敏，避免未认证请求通过降级提示拿到用户完整邮箱。
func maskEmail(e string) string {
	parts := strings.Split(e, "@")
	if len(parts) != 2 || parts[0] == "" {
		return "***"
	}
	name := parts[0]
	if len(name) <= 2 {
		return name[:1] + "***@" + parts[1]
	}
	return name[:2] + "***@" + parts[1]
}
