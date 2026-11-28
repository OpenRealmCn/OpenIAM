package handlers

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/otp"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type OTPHandler struct {
	db          *gorm.DB
	otpSvc      *otp.Service
	settingsSvc *settings.Service
	pluginMgr   *plugins.Manager
}

func NewOTPHandler(db *gorm.DB, otpSvc *otp.Service, settingsSvc *settings.Service, pluginMgr *plugins.Manager) *OTPHandler {
	return &OTPHandler{db: db, otpSvc: otpSvc, settingsSvc: settingsSvc, pluginMgr: pluginMgr}
}

type sendOTPReq struct {
	Scene        string `json:"scene"`                      // login | register
	Channel      string `json:"channel" binding:"required"` // sms | email
	Target       string `json:"target"`                     // 手机号或邮箱
	CaptchaToken string `json:"captcha_token"`
}

// genericOTPSent 是公开场景的统一响应：无论目标是否对应账号、是否真正投递，调用方看到的结果都一致，防止账号枚举。
func genericOTPSent(channel string) gin.H {
	return gin.H{"sent": true, "channel": channel, "degraded": false, "message": "验证码已发送，10 分钟内有效。如未收到，请确认地址填写正确", "ttl_minutes": 10}
}

func (h *OTPHandler) Send(c *gin.Context) {
	if h.otpSvc == nil {
		Fail(c, http.StatusServiceUnavailable, "验证码服务暂不可用，请稍后重试")
		return
	}
	var req sendOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误")
		return
	}
	scene := strings.TrimSpace(req.Scene)
	if scene == "" {
		scene = "login"
	}
	// 公开接口仅允许登录与注册场景；二步验证与换绑手机的验证码必须走已认证的专用接口
	if scene != "login" && scene != "register" {
		Fail(c, http.StatusBadRequest, "不支持的验证码场景")
		return
	}
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if channel != "email" && channel != "sms" {
		Fail(c, http.StatusBadRequest, "不支持的验证码通道")
		return
	}
	if h.pluginMgr != nil {
		if err := h.pluginMgr.VerifyCaptchaForScene(c.Request.Context(), "otp", req.CaptchaToken); err != nil {
			Fail(c, http.StatusBadRequest, err.Error())
			return
		}
	}

	var target string
	if channel == "email" {
		target = normalizeEmail(req.Target)
		if addr, err := mail.ParseAddress(target); err != nil || !strings.EqualFold(addr.Address, target) {
			Fail(c, http.StatusBadRequest, "请输入有效的邮箱地址")
			return
		}
	} else {
		target = normalizePhone(req.Target)
		if !phonePattern.MatchString(target) {
			Fail(c, http.StatusBadRequest, "请输入有效的手机号")
			return
		}
	}

	if scene == "register" {
		if h.settingsSvc == nil {
			Fail(c, http.StatusInternalServerError, "服务暂不可用，请稍后重试")
			return
		}
		snap := h.settingsSvc.Snapshot()
		if !snap.AllowPublicRegister {
			Fail(c, http.StatusForbidden, "系统管理员已关闭自助注册功能")
			return
		}
		verifyMode := snap.RegisterVerifyMode
		channelAllowed := (channel == "email" && (verifyMode == "email" || verifyMode == "either" || verifyMode == "both")) ||
			(channel == "sms" && (verifyMode == "sms" || verifyMode == "either" || verifyMode == "both"))
		if !channelAllowed {
			Fail(c, http.StatusBadRequest, "当前系统未启用该注册验证码通道")
			return
		}
	}

	// 先按目标频控，再判断账号是否存在：存在与不存在的地址触发相同的冷却与配额，避免据此枚举账号
	if err := h.otpSvc.CheckRate(c.Request.Context(), scene, target, clientip.FromGin(c)); err != nil {
		Fail(c, http.StatusTooManyRequests, err.Error())
		return
	}

	var userPtr *models.User
	if scene == "register" {
		// 已被占用的地址不发送验证码，但返回与成功一致的响应；注册接口会先校验验证码再检查唯一性
		var dup int64
		if channel == "email" {
			h.db.Model(&models.User{}).Where("email <> '' AND LOWER(email) = ?", target).Count(&dup)
		} else {
			h.db.Model(&models.User{}).Where("phone <> '' AND phone = ?", target).Count(&dup)
		}
		if dup > 0 {
			OK(c, genericOTPSent(channel))
			return
		}
	} else {
		var u models.User
		var err error
		if channel == "email" {
			err = h.db.Where("email <> '' AND LOWER(email) = ? AND status = ?", target, "active").First(&u).Error
		} else {
			err = h.db.Where("phone <> '' AND phone = ? AND status = ?", target, "active").First(&u).Error
		}
		if err != nil {
			OK(c, genericOTPSent(channel))
			return
		}
		// 已开启两步验证的账号不能用验证码登录，提前不发，避免白白消耗短信并让用户空等
		var totpCount int64
		h.db.Model(&models.UserTOTP{}).Where("user_id = ? AND enabled = ?", u.ID, true).Count(&totpCount)
		if totpCount > 0 {
			OK(c, genericOTPSent(channel))
			return
		}
		userPtr = &u
	}

	if _, err := h.otpSvc.SendCode(c.Request.Context(), otp.SendRequest{
		Scene:       scene,
		Channel:     channel,
		Target:      target,
		User:        userPtr,
		ClientIP:    clientip.FromGin(c),
		RateChecked: true,
	}); err != nil && scene == "register" {
		// 注册场景的目标此前不存在账号，返回真实失败原因不会泄露账号信息
		Fail(c, http.StatusBadGateway, err.Error())
		return
	}
	OK(c, genericOTPSent(channel))
}

func (h *OTPHandler) Stats(c *gin.Context) {
	type channelAgg struct {
		Channel string `json:"channel"`
		Status  string `json:"status"`
		Count   int64  `json:"count"`
		Cost    int64  `json:"cost"`
	}
	var rows []channelAgg
	_ = h.db.Model(&models.NotificationDelivery{}).
		Select("channel, status, count(*) as count, coalesce(sum(cost_cents),0) as cost").
		Group("channel, status").
		Scan(&rows).Error
	OK(c, gin.H{"summary": rows})
}

type RiskHandler struct {
	db       *gorm.DB
	enforcer *rbac.Enforcer
}

func NewRiskHandler(db *gorm.DB, enforcer *rbac.Enforcer) *RiskHandler {
	return &RiskHandler{db: db, enforcer: enforcer}
}

func (h *RiskHandler) ListMy(c *gin.Context) {
	var items []models.RiskEvent
	if err := h.db.Where("user_id = ?", CurrentUserID(c)).Order("id DESC").Limit(50).Find(&items).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询安全记录失败")
		return
	}
	OK(c, items)
}

func (h *RiskHandler) List(c *gin.Context) {
	domain, all := scopedDomain(c, h.enforcer)
	q := h.db.Model(&models.RiskEvent{})
	if level := strings.TrimSpace(c.Query("risk_level")); level != "" {
		q = q.Where("risk_level = ?", level)
	}
	if !all {
		userIDs := domainUserIDs(h.enforcer, domain)
		if len(userIDs) == 0 {
			OK(c, []models.RiskEvent{})
			return
		}
		q = q.Where("user_id IN ?", userIDs)
	}
	var items []models.RiskEvent
	if err := q.Order("id DESC").Limit(200).Find(&items).Error; err != nil {
		Fail(c, http.StatusInternalServerError, "查询风险事件失败")
		return
	}
	OK(c, items)
}
