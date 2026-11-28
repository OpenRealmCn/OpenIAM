package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/totp"
	"gorm.io/gorm"
)

const (
	reauthTTL           = 5 * time.Minute
	reauthMaxFailures   = 5
	reauthFailureWindow = 15 * time.Minute
)

var (
	dummyHashOnce sync.Once
	dummyHash     string
)

// burnPasswordCheck 对不存在或已禁用的账号也执行一次等价的 bcrypt 比对，消除可用于枚举账号的响应时间差。
func burnPasswordCheck(plain string) {
	dummyHashOnce.Do(func() {
		dummyHash, _ = security.HashPassword("openiam-timing-equalizer-placeholder")
	})
	if dummyHash != "" {
		_ = security.VerifyPassword(dummyHash, plain)
	}
}

// verifyTOTPFactor 校验 TOTP 动态码并记录已使用的时间步，同一动态码在有效窗口内不能被重复使用。
func verifyTOTPFactor(ctx context.Context, store *security.StateStore, userID uint64, storedSecret, code string) bool {
	secret, err := security.OpenField(storedSecret)
	if err != nil || secret == "" {
		return false
	}
	step, ok := totp.VerifyCodeStep(secret, code, time.Now())
	if !ok {
		return false
	}
	fresh, err := store.MarkTOTPStepUsed(ctx, userID, step)
	return err == nil && fresh
}

// consumeRecoveryCode 以条件更新原子消费一枚恢复码：只有在恢复码列表未被并发修改时才会成功。
func consumeRecoveryCode(db *gorm.DB, row models.UserTOTP, code string) bool {
	next, ok := consumeRecoveryCodeHash(parseRecoveryHashes(row.RecoveryCodesJSON), code)
	if !ok {
		return false
	}
	b, _ := json.Marshal(next)
	res := db.Model(&models.UserTOTP{}).
		Where("id = ? AND recovery_codes_json = ?", row.ID, row.RecoveryCodesJSON).
		Update("recovery_codes_json", string(b))
	return res.Error == nil && res.RowsAffected == 1
}

// factorAttempt 在校验密码或动态码之前先原子占用一次尝试机会（按用户累计），超限返回 false 并写出 429。
// 先计数再校验，可保证并发请求也无法突破失败上限。
func factorAttempt(c *gin.Context, store *security.StateStore, scope string, userID uint64, max int64, window time.Duration) bool {
	n, err := store.IncrFailure(c.Request.Context(), scope, fmt.Sprintf("%d", userID), window)
	if err != nil || n > max {
		Fail(c, http.StatusTooManyRequests, "验证失败次数过多，请稍后再试")
		return false
	}
	return true
}

func clearFactorAttempts(c *gin.Context, store *security.StateStore, scope string, userID uint64) {
	_ = store.ClearFailures(c.Request.Context(), scope, fmt.Sprintf("%d", userID))
}

// userCanReauth 判断用户是否具备可用于身份再确认的秘密因子（登录密码或 TOTP）。
func userCanReauth(db *gorm.DB, user models.User) bool {
	if user.PasswordHash != "" {
		return true
	}
	var n int64
	db.Model(&models.UserTOTP{}).Where("user_id = ? AND enabled = ?", user.ID, true).Count(&n)
	return n > 0
}

// requireReauth 要求当前会话在近 5 分钟内完成过身份再确认，用于添加登录因子、修改联系方式等敏感操作。
// 仅凭被盗的 Access Token 无法完成这些操作；没有任何秘密因子的账号（如纯联合登录账号）无法再确认，直接放行。
func requireReauth(c *gin.Context, db *gorm.DB, store *security.StateStore) bool {
	uid := CurrentUserID(c)
	var user models.User
	if err := db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return false
	}
	if !userCanReauth(db, user) {
		return true
	}
	if store.HasRecentReauth(c.Request.Context(), uid, c.GetString("session_id")) {
		return true
	}
	c.AbortWithStatusJSON(http.StatusForbidden, gin.H{
		"code":    http.StatusForbidden,
		"error":   "reauth_required",
		"message": "该操作需要先验证当前密码或动态验证码",
	})
	return false
}

type reauthReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// Reauth 校验当前密码或 TOTP 动态码，为当前会话记录 5 分钟有效的身份再确认标记。
func (h *AuthHandler) Reauth(c *gin.Context) {
	var req reauthReq
	if err := c.ShouldBindJSON(&req); err != nil || (req.Password == "" && strings.TrimSpace(req.Code) == "") {
		Fail(c, http.StatusBadRequest, "请输入当前密码或验证器动态码")
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	if !factorAttempt(c, h.stateStore, "reauth", uid, reauthMaxFailures, reauthFailureWindow) {
		return
	}
	ctx := c.Request.Context()
	verified := false
	method := ""
	if req.Password != "" && user.PasswordHash != "" && security.VerifyPassword(user.PasswordHash, req.Password) {
		verified, method = true, "password"
	}
	if !verified && strings.TrimSpace(req.Code) != "" {
		var row models.UserTOTP
		if h.db.Where("user_id = ? AND enabled = ?", uid, true).First(&row).Error == nil &&
			verifyTOTPFactor(ctx, h.stateStore, uid, row.Secret, req.Code) {
			verified, method = true, "totp"
		}
	}
	if !verified {
		h.auditSvc.RecordFromContext(c, audit.Entry{
			DomainCode:   rbac.DefaultDomain,
			Action:       "auth.reauth",
			ResourceType: "user",
			ResourceID:   fmt.Sprintf("%d", uid),
			Status:       "failed",
			ErrorMessage: "invalid reauth factor",
		})
		Fail(c, http.StatusBadRequest, "密码或动态验证码不正确")
		return
	}
	clearFactorAttempts(c, h.stateStore, "reauth", uid)
	if err := h.stateStore.MarkReauth(ctx, uid, c.GetString("session_id"), reauthTTL); err != nil {
		Fail(c, http.StatusInternalServerError, "记录验证状态失败")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "auth.reauth",
		ResourceType: "user",
		ResourceID:   fmt.Sprintf("%d", uid),
		After:        map[string]interface{}{"method": method},
		Status:       "success",
	})
	OK(c, gin.H{"verified": true, "expires_in": int64(reauthTTL.Seconds())})
}
