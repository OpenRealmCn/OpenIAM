package ratelimit

import (
	"fmt"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/clientip"
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
			// X-RateLimit-Reset 是 Unix 时间戳，Retry-After 需要的是秒数；必须在写响应体之前设置。
			if reset, err := strconv.ParseInt(c.Writer.Header().Get("X-RateLimit-Reset"), 10, 64); err == nil {
				if wait := reset - time.Now().Unix(); wait > 0 {
					c.Header("Retry-After", strconv.FormatInt(wait, 10))
				} else {
					c.Header("Retry-After", "1")
				}
			}
			c.AbortWithStatusJSON(http.StatusTooManyRequests, gin.H{
				"code":    429,
				"message": "请求过于频繁，触发 IP 速率限制，请稍后再试",
			})
		}),
		// 限流存储不可用时拒绝请求，而不是静默放行（认证状态同样依赖 Redis，放行并不能换来可用性）；
		// 底层错误不写进响应头。
		mgin.WithErrorHandler(func(c *gin.Context, err error) {
			_ = c.Error(err)
			c.AbortWithStatusJSON(http.StatusServiceUnavailable, gin.H{
				"code":    503,
				"message": "服务暂不可用，请稍后再试",
			})
		}),
		mgin.WithKeyGetter(func(c *gin.Context) string {
			return clientip.FromGin(c)
		}),
	)

	return middleware, nil
}

// DynamicIPRateLimiter 支持管理员在数据库配置更改开关或限流表达式后热切换中间件。
type DynamicIPRateLimiter struct {
	mu        sync.RWMutex
	rdb       *redis.Client
	keyPrefix string
	enabled   bool
	rateStr   string
	handler   gin.HandlerFunc
}

func NewDynamicIPRateLimiter(rdb *redis.Client, keyPrefix string, enabled bool, rateStr string) (*DynamicIPRateLimiter, error) {
	d := &DynamicIPRateLimiter{
		rdb:       rdb,
		keyPrefix: keyPrefix,
	}
	if err := d.Update(enabled, rateStr); err != nil {
		return nil, err
	}
	return d, nil
}

func (d *DynamicIPRateLimiter) Update(enabled bool, rateStr string) error {
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.handler != nil && d.enabled == enabled && d.rateStr == rateStr {
		return nil
	}
	d.enabled = enabled
	if !enabled {
		d.rateStr = rateStr
		d.handler = nil
		return nil
	}
	h, err := NewIPRateLimiter(d.rdb, rateStr, d.keyPrefix)
	if err != nil {
		return err
	}
	d.rateStr = rateStr
	d.handler = h
	return nil
}

func (d *DynamicIPRateLimiter) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		d.mu.RLock()
		enabled := d.enabled
		h := d.handler
		d.mu.RUnlock()

		if !enabled || h == nil {
			c.Next()
			return
		}
		h(c)
	}
}
