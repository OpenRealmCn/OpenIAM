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

// mfaLocked 判断用户是否因二步验证连续失败而被临时限制；Redis 异常时按已锁定处理（fail-closed）。
func (h *AuthHandler) mfaLocked(c *gin.Context, userID uint64) bool {
	n, err := h.stateStore.FailureCount(c.Request.Context(), "mfa_user", fmt.Sprintf("%d", userID))
	return err != nil || n >= mfaMaxFailuresPerUser
}

// mfaFailed 记录一次二步验证失败：同时按 mfa_token 与用户累计，任一超限即销毁当前挑战，防止暴力猜测动态码或恢复码。
func (h *AuthHandler) mfaFailed(c *gin.Context, token string, userID uint64, msg string) {
	ctx := c.Request.Context()
	tokenFails, tErr := h.stateStore.IncrFailure(ctx, "mfa_token", token, 5*time.Minute)
	userFails, uErr := h.stateStore.IncrFailure(ctx, "mfa_user", fmt.Sprintf("%d", userID), 15*time.Minute)
	h.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:      userID,
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.mfa_verify",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", userID),
		Status:       "failed",
		ErrorMessage: "invalid mfa factor",
	})
	if tErr != nil || uErr != nil || tokenFails >= mfaMaxFailuresPerToken || userFails >= mfaMaxFailuresPerUser {
		_, _ = h.stateStore.ConsumeMFAChallenge(ctx, token)
		Fail(c, http.StatusTooManyRequests, "二步验证失败次数过多，请重新登录后再试")
		return
	}
	Fail(c, http.StatusUnauthorized, msg)
}
