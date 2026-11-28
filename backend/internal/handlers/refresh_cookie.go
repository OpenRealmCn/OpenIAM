package handlers

import (
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/clientip"
)

const (
	refreshCookieName = "openiam_refresh"
	refreshCookiePath = "/api/v1/auth"
)

// isSecureRequest 判断请求是否经由 HTTPS 到达（直连 TLS 或可信代理声明的 X-Forwarded-Proto）。
func isSecureRequest(c *gin.Context) bool {
	if c.Request.TLS != nil {
		return true
	}
	return clientip.IsFromTrustedProxy(c.Request) && strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
}

// setRefreshCookie 以 HttpOnly + SameSite=Strict 的 Cookie 下发 Refresh Token，脚本无法读取，可降低 XSS 窃取风险。
func setRefreshCookie(c *gin.Context, token string, ttl time.Duration) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    token,
		Path:     refreshCookiePath,
		MaxAge:   int(ttl.Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteStrictMode,
	})
}

// clearRefreshCookie 清除 Refresh Token Cookie。
func clearRefreshCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     refreshCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteStrictMode,
	})
}

// readRefreshToken 优先从 Cookie 读取 Refresh Token，其次使用请求体中的值（供非浏览器客户端使用）。
func readRefreshToken(c *gin.Context, bodyToken string) string {
	if ck, err := c.Cookie(refreshCookieName); err == nil && ck != "" {
		return ck
	}
	return strings.TrimSpace(bodyToken)
}

// deliverRefresh 通过 Cookie 下发 Refresh Token；仅当客户端显式声明 X-Token-Delivery: body 时才在响应体中返回令牌。
func (h *AuthHandler) deliverRefresh(c *gin.Context, token string, ttl time.Duration) string {
	return deliverRefreshToken(c, token, ttl)
}

const (
	oauthBindingCookieName = "openiam_oauth_binding"
	oauthBindingTTL        = 10 * time.Minute
)

// issueOAuthBindingCookie 为一次联合登录生成随机值并写入 HttpOnly Cookie，返回原值供 state 记录其摘要。
// 回调时必须由同一浏览器带回该 Cookie，阻止攻击者把自己发起的授权回调诱导受害者完成（登录 CSRF / 账号劫持）。
// 使用 SameSite=Lax：回调页由第三方站点跳转回来后再由前端同源请求，Lax 足以携带。
func issueOAuthBindingCookie(c *gin.Context) (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	v := base64.RawURLEncoding.EncodeToString(buf)
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oauthBindingCookieName,
		Value:    v,
		Path:     refreshCookiePath,
		MaxAge:   int(oauthBindingTTL.Seconds()),
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
	return v, nil
}

func readOAuthBindingCookie(c *gin.Context) string {
	v, err := c.Cookie(oauthBindingCookieName)
	if err != nil {
		return ""
	}
	return v
}

func clearOAuthBindingCookie(c *gin.Context) {
	http.SetCookie(c.Writer, &http.Cookie{
		Name:     oauthBindingCookieName,
		Value:    "",
		Path:     refreshCookiePath,
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   isSecureRequest(c),
		SameSite: http.SameSiteLaxMode,
	})
}

func deliverRefreshToken(c *gin.Context, token string, ttl time.Duration) string {
	setRefreshCookie(c, token, ttl)
	if c.GetHeader("X-Token-Delivery") == "body" {
		return token
	}
	return ""
}
