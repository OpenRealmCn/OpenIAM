package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/openrealm/openiam/internal/totp"
	"gorm.io/gorm"
)

type TOTPHandler struct {
	db          *gorm.DB
	settingsSvc *settings.Service
	auditSvc    *audit.Service
}

func NewTOTPHandler(db *gorm.DB, settingsSvc *settings.Service, auditSvc *audit.Service) *TOTPHandler {
	return &TOTPHandler{db: db, settingsSvc: settingsSvc, auditSvc: auditSvc}
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

// Setup 生成新的 TOTP 密钥与 otpauth:// URI（尚未启用，需通过 VerifyBind 确认）。
func (h *TOTPHandler) Setup(c *gin.Context) {
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

	var row models.UserTOTP
	err = h.db.Where("user_id = ?", uid).First(&row).Error
	if err != nil {
		row = models.UserTOTP{
			UserID:            uid,
			Secret:            secret,
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
		row.Secret = secret
		if uerr := h.db.Model(&row).Update("secret", secret).Error; uerr != nil {
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
	if !totp.VerifyCode(row.Secret, req.Code, time.Now()) {
		Fail(c, http.StatusBadRequest, "动态验证码不正确或已过期")
		return
	}

	plain, hashes, err := totp.GenerateRecoveryCodes(10)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成恢复码失败")
		return
	}
	hashesJSON, _ := json.Marshal(hashes)
	now := time.Now()
	if err := h.db.Model(&row).Updates(map[string]interface{}{
		"enabled":             true,
		"verified_at":         &now,
		"recovery_codes_json": string(hashesJSON),
	}).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "激活验证器失败")
		return
	}

	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.totp.bind",
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "success",
	})
	OK(c, gin.H{
		"enabled":        true,
		"recovery_codes": plain,
	})
}

type unbindTOTPReq struct {
	Password string `json:"password"`
	Code     string `json:"code"`
}

// Unbind 验证当前密码或 TOTP/恢复码后解绑 TOTP。
func (h *TOTPHandler) Unbind(c *gin.Context) {
	var req unbindTOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "请提供密码或验证器动态码进行确认")
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
		Fail(c, http.StatusBadRequest, "当前尚未启用 TOTP 验证器")
		return
	}

	verified := false
	if req.Password != "" && user.PasswordHash != "" && security.VerifyPassword(user.PasswordHash, req.Password) {
		verified = true
	}
	if !verified && req.Code != "" {
		if totp.VerifyCode(row.Secret, req.Code, time.Now()) {
			verified = true
		} else if _, ok := consumeRecoveryCodeHash(parseRecoveryHashes(row.RecoveryCodesJSON), req.Code); ok {
			verified = true
		}
	}
	if !verified {
		Fail(c, http.StatusBadRequest, "密码或动态验证码校验失败")
		return
	}

	if err := h.db.Delete(&row).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "解绑 TOTP 失败")
		return
	}
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.totp.unbind",
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "success",
	})
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
	if !totp.VerifyCode(row.Secret, req.Code, time.Now()) {
		Fail(c, http.StatusBadRequest, "动态验证码不正确")
		return
	}
	plain, hashes, err := totp.GenerateRecoveryCodes(10)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "生成恢复码失败")
		return
	}
	hashesJSON, _ := json.Marshal(hashes)
	_ = h.db.Model(&row).Update("recovery_codes_json", string(hashesJSON)).Error
	h.auditSvc.RecordFromContext(c, audit.Entry{
		DomainCode:   rbac.DefaultDomain,
		Action:       "user.totp.recovery_regenerate",
		ResourceType: "user_totp",
		ResourceID:   fmt.Sprintf("%d", uid),
		Status:       "success",
	})
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
