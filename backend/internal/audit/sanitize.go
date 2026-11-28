package audit

import "strings"

var sensitiveKeySet = map[string]bool{
	"password":           true,
	"password_hash":      true,
	"new_password":       true,
	"old_password":       true,
	"client_secret":      true,
	"client_secret_hash": true,
	"secret":             true,
	"access_token":       true,
	"refresh_token":      true,
	"id_token":           true,
	"token":              true,
	"code_verifier":      true,
	"authorization":      true,
	"private_key":        true,
}

// sensitiveKeyFragments 覆盖插件与系统设置里形态各异的凭据字段（smtp.password、app_secret、
// access_key_secret、api_key、corpsecret、recovery_codes 等），按归一化后的子串匹配。
var sensitiveKeyFragments = []string{
	"password", "passwd", "secret", "token", "privatekey", "apikey", "accesskey",
	"credential", "recoverycode", "signkey", "signingkey", "otpcode", "cookie",
}

// isSensitiveKey 判断字段名（忽略大小写与分隔符）是否属于需要脱敏的敏感字段。
func isSensitiveKey(k string) bool {
	lower := strings.ToLower(k)
	if sensitiveKeySet[lower] {
		return true
	}
	norm := strings.NewReplacer("_", "", "-", "", ".", "", " ", "").Replace(lower)
	for _, f := range sensitiveKeyFragments {
		if strings.Contains(norm, f) {
			return true
		}
	}
	return false
}

// sanitizeValue 递归处理数组中嵌套的对象，避免敏感字段通过数组绕过脱敏。
func sanitizeValue(v any) {
	arr, ok := v.([]any)
	if !ok {
		return
	}
	for _, it := range arr {
		if m, ok := it.(map[string]any); ok {
			sanitizeMap(m)
		} else {
			sanitizeValue(it)
		}
	}
}
