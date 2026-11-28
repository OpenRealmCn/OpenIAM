package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

func ZapLogger(logger *zap.Logger) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		if logger != nil {
			logger.Info("http_request",
				zap.Int("status", status),
				zap.String("method", c.Request.Method),
				zap.String("path", path),
				zap.Bool("has_query", query != ""),
				zap.String("ip", c.ClientIP()),
				zap.Duration("latency", latency),
			)
		}
	}
}

func CORS(allowOrigins []string) gin.HandlerFunc {
	return DynamicCORS(func() []string { return allowOrigins })
}

func DynamicCORS(getOrigins func() []string) gin.HandlerFunc {
	return func(c *gin.Context) {
		allowOrigins := getOrigins()
		origin := c.GetHeader("Origin")
		if origin != "" {
			allowed := false
			for _, o := range allowOrigins {
				if o == origin {
					allowed = true
					break
				}
			}
			if allowed {
				c.Header("Access-Control-Allow-Origin", origin)
				// 仅对白名单内的具体来源允许携带凭据（HttpOnly Refresh Cookie 依赖此头）
				c.Header("Access-Control-Allow-Credentials", "true")
			}
		} else {
			c.Header("Vary", "Origin")
		}
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type, X-OpenIAM-Domain, X-Token-Delivery")
		c.Header("Access-Control-Expose-Headers", "X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset")
		c.Header("Vary", "Origin")

		if c.Request.Method == "OPTIONS" {
			c.AbortWithStatus(204)
			return
		}
		c.Next()
	}
}
