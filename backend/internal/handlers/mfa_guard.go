package handlers

import (
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/rbac"
)

const (
	mfaMaxFailuresPerToken = 5
	mfaMaxFailuresPerUser  = 10
)

// mfaAttempt 在校验因子之前先累计尝试次数：先计数后校验，保证并发请求无法在计数生效前挤进额外的猜测。
// 超限或 Redis 异常时销毁当前挑战并直接响应，返回 ok=false。
func (h *AuthHandler) mfaAttempt(c *gin.Context, token string, userID uint64) (tokenFails, userFails int64, ok bool) {
	ctx := c.Request.Context()
	tokenFails, tErr := h.stateStore.IncrFailure(ctx, "mfa_token", token, 5*time.Minute)
	userFails, uErr := h.stateStore.IncrFailure(ctx, "mfa_user", fmt.Sprintf("%d", userID), 15*time.Minute)
	if tErr != nil || uErr != nil || tokenFails > mfaMaxFailuresPerToken || userFails > mfaMaxFailuresPerUser {
		_, _ = h.stateStore.ConsumeMFAChallenge(ctx, token)
		Fail(c, http.StatusTooManyRequests, "二步验证失败次数过多，请重新登录后再试")
		return tokenFails, userFails, false
	}
	return tokenFails, userFails, true
}

// mfaFailed 处理一次校验失败：写审计，并在本次已用满额度时销毁挑战，迫使攻击者重新通过密码校验。
func (h *AuthHandler) mfaFailed(c *gin.Context, token string, userID uint64, tokenFails, userFails int64, msg string) {
	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:      userID,
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.mfa_verify",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", userID),
		Status:       "failed",
		ErrorMessage: "invalid mfa factor",
	})
	if tokenFails >= mfaMaxFailuresPerToken || userFails >= mfaMaxFailuresPerUser {
		_, _ = h.stateStore.ConsumeMFAChallenge(c.Request.Context(), token)
		Fail(c, http.StatusTooManyRequests, "二步验证失败次数过多，请重新登录后再试")
		return
	}
	Fail(c, http.StatusUnauthorized, msg)
}
