// Package ratelimit provides Redis-backed request throttling.
//
// Keys follow the conventions in docs/database/redis-keys.md:
//
//	rate-limit:login:ip:{ipHash}     1 minute    login throttling
//	rate-limit:login:user:{userHash} 15 minutes  brute-force defense
//
// Identifiers are hashed so raw IP addresses and usernames never appear in
// Redis keys.
package ratelimit

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"time"

	"github.com/redis/go-redis/v9"
)

// Default thresholds. These bound automated attempts without interfering with
// a person mistyping a password a few times.
const (
	loginIPLimit    = 20
	loginIPWindow   = time.Minute
	loginUserLimit  = 10
	loginUserWindow = 15 * time.Minute
)

// Limiter enforces fixed-window counters in Redis.
type Limiter struct {
	rdb    *redis.Client
	prefix string
}

// New returns a Limiter that namespaces its keys with the given prefix.
func New(rdb *redis.Client, keyPrefix string) *Limiter {
	return &Limiter{rdb: rdb, prefix: keyPrefix}
}

// AllowLogin reports whether a login attempt from ip for the given login
// identifier is within both the per-IP and per-account budgets. Both counters
// are incremented on every call, including successful logins, so a valid
// credential cannot be used to reset an attacker's budget.
//
// A non-nil error means the decision could not be made; callers should treat
// that as a failure rather than allowing the request.
func (l *Limiter) AllowLogin(ctx context.Context, ip, login string) (bool, error) {
	ipOK, err := l.allow(ctx, "login:ip:"+hash(ip), loginIPLimit, loginIPWindow)
	if err != nil {
		return false, err
	}

	// Always evaluate the account counter too, so an attacker rotating IPs is
	// still bounded per account.
	userOK, err := l.allow(ctx, "login:user:"+hash(normalise(login)), loginUserLimit, loginUserWindow)
	if err != nil {
		return false, err
	}

	return ipOK && userOK, nil
}

// allow increments a fixed-window counter and reports whether it is still
// within limit. The TTL is set on first use of a window.
func (l *Limiter) allow(ctx context.Context, suffix string, limit int64, window time.Duration) (bool, error) {
	key := l.prefix + ":rate-limit:" + suffix

	pipe := l.rdb.TxPipeline()
	incr := pipe.Incr(ctx, key)
	// NX so an in-flight window is never extended by later attempts.
	pipe.ExpireNX(ctx, key, window)
	if _, err := pipe.Exec(ctx); err != nil {
		return false, err
	}

	count := incr.Val()

	// Defensive: if the key somehow lost its TTL, restore it rather than
	// letting the counter persist forever and lock the principal out.
	if ttl, err := l.rdb.TTL(ctx, key).Result(); err == nil && ttl < 0 {
		_ = l.rdb.Expire(ctx, key, window).Err()
	}

	return count <= limit, nil
}

func hash(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}

func normalise(login string) string {
	return strings.ToLower(strings.TrimSpace(login))
}
