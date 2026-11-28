package handlers

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
)

// enforcePasswordPolicy 按当前站点密码策略校验新密码；不通过时直接写入 400 响应并返回 false。
func enforcePasswordPolicy(c *gin.Context, svc *settings.Service, plain string) bool {
	minLen, complexity := 8, false
	if svc != nil {
		snap := svc.Snapshot()
		minLen, complexity = snap.PasswordMinLength, snap.PasswordRequireComplexity
	}
	if err := security.ValidatePasswordPolicy(plain, minLen, complexity); err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return false
	}
	return true
}

func (h *AuthHandler) checkPasswordPolicy(c *gin.Context, plain string) bool {
	return enforcePasswordPolicy(c, h.settingsSvc, plain)
}
