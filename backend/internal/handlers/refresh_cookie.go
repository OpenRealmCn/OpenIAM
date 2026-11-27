package handlers

import (
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
)

const (
	refreshCookieName = "openiam_refresh"
	refreshCookiePath = "/api/v1/auth"
)

// isSecureRequest 判断请求是否经由 HTTPS 到达（直连 TLS 或可信代理声明的 X-Forwarded-Proto）。
func isSecureRequest(c *gin.Context) bool {
	return c.Request.TLS != nil || strings.EqualFold(c.GetHeader("X-Forwarded-Proto"), "https")
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
	setRefreshCookie(c, token, ttl)
	if c.GetHeader("X-Token-Delivery") == "body" {
		return token
	}
	return ""
}
