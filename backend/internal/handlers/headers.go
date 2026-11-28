package handlers

import (
	"strings"
	"unicode/utf8"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/settings"
)

// truncateStr 按字节上限截断字符串并保证不切断 UTF-8 字符，避免超长请求头导致会话或风险事件写库失败。
func truncateStr(s string, limit int) string {
	if len(s) <= limit {
		return s
	}
	s = s[:limit]
	for len(s) > 0 && !utf8.ValidString(s) {
		s = s[:len(s)-1]
	}
	return s
}

func headerFingerprint(c *gin.Context) string {
	return truncateStr(strings.TrimSpace(c.GetHeader("X-Device-Fingerprint")), 128)
}

// headerGeo 仅当系统设置开启 risk.trust_geo_header（前置网关覆盖 X-Geo-Location）时才采信该头，否则忽略以防客户端伪造地点。
func headerGeo(c *gin.Context, settingsSvc *settings.Service) string {
	if settingsSvc == nil || !settingsSvc.Snapshot().RiskTrustGeoHeader {
		return ""
	}
	return truncateStr(strings.TrimSpace(c.GetHeader("X-Geo-Location")), 128)
}
