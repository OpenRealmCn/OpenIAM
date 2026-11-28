package handlers

import (
	"context"
	"errors"
	"time"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"gorm.io/gorm"
)

// revokeUserSessions 推进用户的「凭据有效起点」：重置密码、禁用账号（踢下线）时调用。
// users.tokens_valid_after 是权威来源——Redis 里的失效时间点可能因重启或淘汰丢失，
// 而库里的时间戳会长期保留。先写库再写 Redis，任何一步失败都返回错误，调用方必须让整个操作失败。
func revokeUserSessions(ctx context.Context, db *gorm.DB, stateStore *security.StateStore, userID uint64) error {
	if userID == 0 {
		return errors.New("无效的用户 ID")
	}
	if err := db.WithContext(ctx).Model(&models.User{}).
		Where("id = ?", userID).
		UpdateColumn("tokens_valid_after", time.Now().UnixMilli()).Error; err != nil {
		return err
	}
	if stateStore != nil {
		if err := stateStore.RevokeUserTokens(ctx, userID); err != nil {
			return err
		}
	}
	return nil
}

// tokensRevokedAfter 判断某个签发时刻是否早于（或等于）用户的凭据有效起点。
func tokensRevokedAfter(user models.User, issuedAtMs int64) bool {
	return user.TokensValidAfterMs != nil && *user.TokensValidAfterMs > 0 && issuedAtMs <= *user.TokensValidAfterMs
}

// remainingLoginMethods 统计用户剩下的可用登录方式数量（密码算 1 种，通行密钥与外部身份各算 1 种）。
// 任一登录方式被删除前都必须用它复核，结果为 0 时拒绝，避免用户把自己锁在账号外。
func remainingLoginMethods(hasPassword bool, passkeys, identities int64) int {
	n := 0
	if hasPassword {
		n++
	}
	if passkeys > 0 {
		n++
	}
	if identities > 0 {
		n++
	}
	return n
}
