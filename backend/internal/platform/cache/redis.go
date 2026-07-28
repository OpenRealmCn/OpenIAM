package cache

import (
	"github.com/openrealm/openiam/backend/internal/platform/config"
	"github.com/redis/go-redis/v9"
)

func Open(cfg config.RedisConfig) *redis.Client {
	return redis.NewClient(&redis.Options{
		Addr:     cfg.Address,
		Password: cfg.Password,
		DB:       cfg.Database,
	})
}
