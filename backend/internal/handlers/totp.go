package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/openrealm/openiam/internal/totp"
	"gorm.io/gorm"
)

const (
	totpManageMaxFailures = 5
	totpManageWindow      = 15 * time.Minute
)

type TOTPHandler struct {
	db          *gorm.DB
	settingsSvc *settings.Service
	auditSvc    *audit.Service
	stateStore  *security.StateStore
	notifySvc   *notify.Service
}

func NewTOTPHandler(db *gorm.DB, settingsSvc *settings.Service, auditSvc *audit.Service, stateStore *security.StateStore) *TOTPHandler {
	return &TOTPHandler{db: db, settingsSvc: settingsSvc, auditSvc: auditSvc, stateStore: stateStore}
}

func parseRecoveryHashes(raw string) []string {
	if raw == "" {
		return nil
	}
	var out []string
	_ = json.Unmarshal([]byte(raw), &out)
	return out
}

func (h *TOTPHandler) Status(c *gin.Context) {
	uid := CurrentUserID(c)
	var row models.UserTOTP
	if err := h.db.Where("user_id = ?", uid).First(&row).Error; err != nil {
		OK(c, gin.H{
			"enabled":                  false,
			"verified_at":              nil,
			"remaining_recovery_codes": 0,
		})
		return
	}
	hashes := parseRecoveryHashes(row.RecoveryCodesJSON)
	OK(c, gin.H{
		"enabled":                  row.Enabled,
		"verified_at":              row.VerifiedAt,
		"remaining_recovery_codes": len(hashes),
	})
}

func (h *TOTPHandler) recordFailure(c *gin.Context, action string, uid uint64) {
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       action,
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "failed",
		ErrorMessage: "invalid factor",
	})
}

// Setup 生成新的 TOTP 密钥与 otpauth:// URI（尚未启用，需通过 VerifyBind 确认）。
// 启用验证器会改变账号的登录方式，盗用会话者可借此把真正的用户锁在门外，因此要求近期重新认证。
func (h *TOTPHandler) Setup(c *gin.Context) {
	if !requireReauth(c, h.db, h.stateStore) {
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	secret, err := totp.GenerateSecret()
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成密钥失败")
		return
	}
	sealed, err := security.SealField(secret)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成密钥失败")
		return
	}

	var row models.UserTOTP
	err = h.db.Where("user_id = ?", uid).First(&row).Error
	if err != nil {
		row = models.UserTOTP{
			UserID:            uid,
			Secret:            sealed,
			Enabled:           false,
			RecoveryCodesJSON: "[]",
		}
		if cerr := h.db.Create(&row).Error; cerr != nil {
			Fail(c, http.StatusInternalServerError, "保存密钥失败")
			return
		}
	} else {
		if row.Enabled {
			Fail(c, http.StatusBadRequest, "当前已启用验证器，如需更换请先解绑")
			return
		}
		row.Secret = sealed
		if uerr := h.db.Model(&row).Update("secret", sealed).Error; uerr != nil {
			Fail(c, http.StatusInternalServerError, "更新密钥失败")
			return
		}
	}

	issuer := h.settingsSvc.Snapshot().SiteName
	OK(c, gin.H{
		"secret":      secret,
		"otpauth_uri": totp.BuildOtpAuthURI(issuer, user.Username, secret),
	})
}

type totpCodeReq struct {
	Code string `json:"code" binding:"required"`
}

// VerifyBind 校验 6 位动态码并激活 TOTP，同时首次返回 10 组明文一次性恢复码。
func (h *TOTPHandler) VerifyBind(c *gin.Context) {
	var req totpCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入 6 位动态验证码")
		return
	}
	uid := CurrentUserID(c)
	var row models.UserTOTP
	if err := h.db.Where("user_id = ?", uid).First(&row).Error; err != nil || row.Secret == "" {
		Fail(c, http.StatusBadRequest, "请先生成验证器密钥")
		return
	}
	if row.Enabled {
		Fail(c, http.StatusBadRequest, "验证器已启用")
		return
	}
	if !factorAttempt(c, h.stateStore, "totp_manage", uid, totpManageMaxFailures, totpManageWindow) {
		return
	}
	if !verifyTOTPFactor(c.Request.Context(), h.stateStore, uid, row.Secret, req.Code) {
		h.recordFailure(c, "user.totp.bind", uid)
		Fail(c, http.StatusBadRequest, "动态验证码不正确或已过期")
		return
	}
	clearFactorAttempts(c, h.stateStore, "totp_manage", uid)

	plain, hashes, err := totp.GenerateRecoveryCodes(10)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成恢复码失败")
		return
	}
	hashesJSON, _ := json.Marshal(hashes)
	now := time.Now()
	// 以 secret 未变化为条件激活，防止并发的 Setup 替换密钥后旧动态码仍激活新密钥
	res := h.db.Model(&models.UserTOTP{}).
		Where("id = ? AND secret = ? AND enabled = ?", row.ID, row.Secret, false).
		Updates(map[string]interface{}{
			"enabled":             true,
			"verified_at":         &now,
			"recovery_codes_json": string(hashesJSON),
		})
	if res.Error != nil || res.RowsAffected != 1 {
		Fail(c, http.StatusConflict, "验证器密钥已变更，请重新扫码绑定")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.totp.bind",
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "success",
	})
	notifySecurity(c, h.notifySvc, uid, "已开启两步验证", "你的账号已开启身份验证器两步验证，之后用密码登录时需要输入动态验证码。")
	OK(c, gin.H{
		"enabled":        true,
		"recovery_codes": plain,
	})
}

type unbindTOTPReq struct {
	Password string `json:"password"`
	Code     string `json:"code" binding:"required"`
}

// Unbind 解绑 TOTP：必须提供当前动态码或一枚恢复码（证明仍持有第二因子）；账号设有密码时还必须同时提供密码。
// 仅凭被盗会话或仅凭密码都不能关闭二步验证。
func (h *TOTPHandler) Unbind(c *gin.Context) {
	var req unbindTOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请提供验证器动态码或恢复码进行确认")
		return
	}
	uid := CurrentUserID(c)
	var user models.User
	if err := h.db.First(&user, uid).Error; err != nil {
		Fail(c, http.StatusNotFound, "用户不存在")
		return
	}
	var row models.UserTOTP
	if err := h.db.Where("user_id = ? AND enabled = ?", uid, true).First(&row).Error; err != nil {
		Fail(c, http.StatusBadRequest, "当前未开启两步验证")
		return
	}
	if !factorAttempt(c, h.stateStore, "totp_manage", uid, totpManageMaxFailures, totpManageWindow) {
		return
	}

	verified := true
	if user.PasswordHash != "" && (req.Password == "" || !security.VerifyPassword(user.PasswordHash, req.Password)) {
		verified = false
	}
	code := strings.TrimSpace(req.Code)
	if verified {
		verified = verifyTOTPFactor(c.Request.Context(), h.stateStore, uid, row.Secret, code) ||
			consumeRecoveryCode(h.db, row, code)
	}
	if !verified {
		h.recordFailure(c, "user.totp.unbind", uid)
		Fail(c, http.StatusBadRequest, "密码或动态验证码校验失败")
		return
	}
	clearFactorAttempts(c, h.stateStore, "totp_manage", uid)

	if err := h.db.Delete(&models.UserTOTP{}, row.ID).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "关闭两步验证失败，请稍后重试")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.totp.unbind",
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "success",
	})
	notifySecurity(c, h.notifySvc, uid, "已关闭两步验证", "你的账号已关闭身份验证器两步验证，账号安全性有所降低。")
	OK(c, gin.H{"enabled": false})
}

// RegenerateRecoveryCodes 校验当前动态码后重新签发 10 组备用恢复码。
func (h *TOTPHandler) RegenerateRecoveryCodes(c *gin.Context) {
	var req totpCodeReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请输入 6 位动态验证码")
		return
	}
	uid := CurrentUserID(c)
	var row models.UserTOTP
	if err := h.db.Where("user_id = ? AND enabled = ?", uid, true).First(&row).Error; err != nil {
		Fail(c, http.StatusBadRequest, "请先绑定并启用验证器")
		return
	}
	if !factorAttempt(c, h.stateStore, "totp_manage", uid, totpManageMaxFailures, totpManageWindow) {
		return
	}
	if !verifyTOTPFactor(c.Request.Context(), h.stateStore, uid, row.Secret, req.Code) {
		h.recordFailure(c, "user.totp.recovery_regenerate", uid)
		Fail(c, http.StatusBadRequest, "动态验证码不正确")
		return
	}
	clearFactorAttempts(c, h.stateStore, "totp_manage", uid)
	plain, hashes, err := totp.GenerateRecoveryCodes(10)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成恢复码失败")
		return
	}
	hashesJSON, _ := json.Marshal(hashes)
	if err := h.db.Model(&row).Update("recovery_codes_json", string(hashesJSON)).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "保存恢复码失败")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.totp.recovery_regenerate",
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "success",
	})
	notifySecurity(c, h.notifySvc, uid, "恢复码已重新生成", "你的两步验证恢复码已重新生成，之前的恢复码全部失效。")
	OK(c, gin.H{"recovery_codes": plain})
}

func consumeRecoveryCodeHash(hashes []string, code string) ([]string, bool) {
	targetHash := totp.HashRecoveryCode(code)
	for i, h := range hashes {
		if h == targetHash {
			next := make([]string, 0, len(hashes)-1)
			next = append(next, hashes[:i]...)
			next = append(next, hashes[i+1:]...)
			return next, true
		}
	}
	return hashes, false
}
