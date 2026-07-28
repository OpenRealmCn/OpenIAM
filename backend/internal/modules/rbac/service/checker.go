package service

import (
	"context"
	"encoding/json"
	"time"

	"github.com/openrealm/openiam/backend/internal/modules/rbac/domain"
	"github.com/openrealm/openiam/backend/internal/modules/rbac/repository"
	"github.com/redis/go-redis/v9"
)

const cacheTTL = 10 * time.Minute

type Checker struct {
	repo   *repository.Repository
	rdb    *redis.Client
	prefix string
}

func NewChecker(repo *repository.Repository, rdb *redis.Client, keyPrefix string) *Checker {
	return &Checker{repo: repo, rdb: rdb, prefix: keyPrefix}
}

func (c *Checker) cacheKey(userID uint64) string {
	return c.prefix + ":user-permissions:" + itoa(userID)
}

func (c *Checker) Permissions(ctx context.Context, userID uint64) ([]string, error) {
	if codes, ok := c.fromCache(ctx, userID); ok {
		return codes, nil
	}

	codes, err := c.repo.UserPermissionCodes(ctx, userID)
	if err != nil {
		return nil, err
	}
	if codes == nil {
		codes = []string{}
	}

	c.toCache(ctx, userID, codes)
	return codes, nil
}

func (c *Checker) HasPermission(ctx context.Context, userID uint64, code string) (bool, error) {
	codes, err := c.Permissions(ctx, userID)
	if err != nil {
		return false, err
	}
	return ContainsPermission(codes, code), nil
}

func (c *Checker) Invalidate(ctx context.Context, userID uint64) {
	c.rdb.Del(ctx, c.cacheKey(userID))
}

func ContainsPermission(codes []string, code string) bool {
	for _, c := range codes {
		if c == domain.WildcardPermission || c == code {
			return true
		}
	}
	return false
}

func (c *Checker) fromCache(ctx context.Context, userID uint64) ([]string, bool) {
	raw, err := c.rdb.Get(ctx, c.cacheKey(userID)).Result()
	if err != nil {
		return nil, false
	}
	var codes []string
	if err := json.Unmarshal([]byte(raw), &codes); err != nil {
		return nil, false
	}
	return codes, true
}

func (c *Checker) toCache(ctx context.Context, userID uint64, codes []string) {
	raw, err := json.Marshal(codes)
	if err != nil {
		return
	}
	c.rdb.Set(ctx, c.cacheKey(userID), raw, cacheTTL)
}

func itoa(v uint64) string {
	const digits = "0123456789"
	if v == 0 {
		return "0"
	}
	buf := make([]byte, 0, 20)
	for v > 0 {
		buf = append([]byte{digits[v%10]}, buf...)
		v /= 10
	}
	return string(buf)
}
