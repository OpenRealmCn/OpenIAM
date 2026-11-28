package security

import (
	"errors"
	"net/url"
	"strings"
)

// ValidateClientRedirectURI 校验 OAuth 应用登记的回调地址：
//   - 必须是不含片段、用户信息与通配符的绝对地址；
//   - https 任意主机可用，http 只允许本机回环地址（RFC 8252 原生应用回环重定向）；
//   - allowCustomScheme 为 true 时允许原生应用私有协议（必须是含点号的反向域名，如 com.example.app:/cb，RFC 8252 7.1）；
//   - 一律拒绝 javascript、data、vbscript、file、blob 等可在浏览器中执行或读取本地内容的协议。
//
// 授权码与错误参数都会被拼到回调地址上，同意页再由前端跳转过去，因此这里的校验同时决定了前端跳转是否安全。
func ValidateClientRedirectURI(raw string, allowCustomScheme bool) error {
	raw = strings.TrimSpace(raw)
	if raw == "" || len(raw) > 2048 {
		return errors.New("回调地址不能为空且长度不能超过 2048")
	}
	if strings.ContainsAny(raw, "* \t\r\n\\") {
		return errors.New("回调地址不能包含通配符、空白或反斜杠")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" {
		return errors.New("回调地址必须是绝对地址")
	}
	if u.Fragment != "" || strings.Contains(raw, "#") {
		return errors.New("回调地址不能包含 # 片段")
	}
	if u.User != nil {
		return errors.New("回调地址不能包含用户信息")
	}
	scheme := strings.ToLower(u.Scheme)
	switch scheme {
	case "javascript", "data", "vbscript", "file", "blob", "about", "filesystem":
		return errors.New("回调地址协议不受支持")
	case "https":
		if u.Host == "" {
			return errors.New("回调地址缺少主机名")
		}
		return nil
	case "http":
		host := u.Hostname()
		if host == "localhost" || host == "127.0.0.1" || host == "::1" {
			return nil
		}
		return errors.New("回调地址必须使用 https（本机回环地址允许 http）")
	}
	if !allowCustomScheme {
		return errors.New("回调地址必须使用 https（本机回环地址允许 http）")
	}
	if !strings.Contains(scheme, ".") {
		return errors.New("原生应用私有协议必须使用反向域名形式（如 com.example.app）")
	}
	return nil
}
