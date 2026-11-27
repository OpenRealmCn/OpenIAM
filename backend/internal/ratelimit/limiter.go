package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/redis/go-redis/v9"
	"github.com/ulule/limiter/v3"
	mgin "github.com/ulule/limiter/v3/drivers/middleware/gin"
	smemory "github.com/ulule/limiter/v3/drivers/store/memory"
	sredis "github.com/ulule/limiter/v3/drivers/store/redis"
)

// NewIPRateLimiter 基于 ulule/limiter/v3 创建 IP 速率限制 Gin 中间件。
// 当提供 Redis 客户端时使用分布式 Redis 存储，否则自动降级为内存存储。
func NewIPRateLimiter(rdb *redis.Client, rateStr, keyPrefix string) (gin.HandlerFunc, error) {
	rate, err := limiter.NewRateFromFormatted(rateStr)
	if err != nil {
		return nil, fmt.Errorf("parse rate %q: %w", rateStr, err)
	}

	var store limiter.Store
	if rdb != nil {
		if keyPrefix == "" {
			keyPrefix = "openiam:ratelimit"
		}
		store, err = sredis.NewStoreWithOptions(rdb, limiter.StoreOptions{
			Prefix: keyPrefix,
		})
		if err != nil {
			return nil, fmt.Errorf("create redis ratelimit store: %w", err)
		}
	} else {
		store = smemory.NewStore()
	}

	instance := limiter.New(store, rate)
	middleware := mgin.NewMiddleware(
		instance,
		mgin.WithLimitReachedHandler(func(c *gin.Context) {
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    429,
				"message": "请求过于频繁，触发 IP 速率限制，请稍后再试",
			})
		}),
		mgin.WithErrorHandler(func(c *gin.Context, err error) {
			// 存储层异常时不阻断正常业务流量，但仍写响应头提示
			c.Header("X-RateLimit-Error", err.Error())
			c.Next()
		}),
		mgin.WithKeyGetter(func(c *gin.Context) string {
			return c.ClientIP()
		}),
	)

	// 包装以补充 Retry-After 头部
	return func(c *gin.Context) {
		middleware(c)
		if c.Writer.Status() == http.StatusTooManyRequests {
			if reset := c.Writer.Header().Get("X-RateLimit-Reset"); reset != "" {
				if _, err := strconv.ParseInt(reset, 10, 64); err == nil {
					c.Header("Retry-After", reset)
				}
			}
		}
	}, nil
}
