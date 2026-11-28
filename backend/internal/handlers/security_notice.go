package handlers

import (
	"fmt"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/settings"
)

// notifySecurity 向账号本人发送安全事件提醒，正文末尾附上操作时间与来源 IP。svc 为空时静默跳过。
func notifySecurity(c *gin.Context, svc *notify.Service, userID uint64, title, what string) {
	if svc == nil || userID == 0 {
		return
	}
	content := fmt.Sprintf("%s\n\n时间：%s\nIP 地址：%s", what, time.Now().Format("2006-01-02 15:04"), clientip.FromGin(c))
	svc.NotifySecurityEvent(c.Request.Context(), userID, title, content, models.JSONMap{"event": title})
}

// SetNotifyService 注入通知服务，用于在两步验证变更时提醒账号本人。
func (h *TOTPHandler) SetNotifyService(svc *notify.Service) { h.notifySvc = svc }

// SetNotifyService 注入通知服务，用于在通行密钥变更时提醒账号本人。
func (h *PasskeyHandler) SetNotifyService(svc *notify.Service) { h.notifySvc = svc }

// SetDeps 注入通知与设置服务，用于管理员重置操作的用户提醒和密码策略校验。
func (h *UserHandler) SetDeps(notifySvc *notify.Service, settingsSvc *settings.Service) {
	h.notifySvc = notifySvc
	h.settingsSvc = settingsSvc
}
