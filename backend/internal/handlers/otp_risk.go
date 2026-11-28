package handlers

import (
	"net/http"
	"net/mail"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/otp"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type OTPHandler struct {
	db          *gorm.DB
	otpSvc      *otp.Service
	settingsSvc *settings.Service
}

func NewOTPHandler(db *gorm.DB, otpSvc *otp.Service, settingsSvc *settings.Service) *OTPHandler {
	return &OTPHandler{db: db, otpSvc: otpSvc, settingsSvc: settingsSvc}
}

type sendOTPReq struct {
	Scene        string `json:"scene"`                      // login | register
	Channel      string `json:"channel" binding:"required"` // sms | email
	Target       string `json:"target"`                     // 手机号或邮箱
	CaptchaToken string `json:"captcha_token"`
}

func (h *OTPHandler) Send(c *gin.Context) {
	var req sendOTPReq
	if err := c.ShouldBindJSON(&req); err != nil {
		Fail(c, http.StatusBadRequest, "参数错误: "+err.Error())
		return
	}
	scene := strings.TrimSpace(req.Scene)
	if scene == "" {
		scene = "login"
	}
	// 公开接口仅允许登录与注册场景；二步验证验证码必须走携带 mfa_token 的 /auth/mfa/send-code
	if scene != "login" && scene != "register" {
		Fail(c, http.StatusBadRequest, "不支持的验证码场景")
		return
	}
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if channel != "email" && channel != "sms" {
		Fail(c, http.StatusBadRequest, "不支持的验证码通道")
		return
	}
	target := strings.TrimSpace(req.Target)

	var userPtr *models.User
	if scene == "register" {
		if h.settingsSvc == nil {
			Fail(c, http.StatusInternalServerError, "系统设置服务未初始化")
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
		if channel == "email" {
			target = strings.ToLower(target)
			if addr, err := mail.ParseAddress(target); err != nil || !strings.EqualFold(addr.Address, target) {
				Fail(c, http.StatusBadRequest, "请输入有效的邮箱地址")
				return
			}
			var dup int64
			h.db.Model(&models.User{}).Where("email <> '' AND LOWER(email) = ?", target).Count(&dup)
			if dup > 0 {
				Fail(c, http.StatusConflict, "该邮箱已被注册")
				return
			}
		} else {
			if !phonePattern.MatchString(target) {
				Fail(c, http.StatusBadRequest, "请输入有效的手机号")
				return
			}
			var dup int64
			h.db.Model(&models.User{}).Where("phone <> '' AND phone = ?", target).Count(&dup)
			if dup > 0 {
				Fail(c, http.StatusConflict, "该手机号已被注册")
				return
			}
		}
	} else {
		if target == "" {
			Fail(c, http.StatusBadRequest, "请输入手机号或邮箱")
			return
		}
		var u models.User
		if err := h.db.Where("((email <> '' AND LOWER(email) = ?) OR (phone <> '' AND phone = ?)) AND status = ?", strings.ToLower(target), target, "active").First(&u).Error; err == nil {
			userPtr = &u
		}
		if userPtr == nil {
			// 账号不存在时不真正发送，返回与成功一致的响应：避免被滥用为任意地址的验证码发送器，并防止账号枚举
			OK(c, gin.H{"sent": true, "channel": channel, "degraded": false, "message": "验证码已发送，请注意查收", "ttl_minutes": 10})
			return
		}
	}

	res, err := h.otpSvc.SendCode(c.Request.Context(), otp.SendRequest{
		Scene:        scene,
		Channel:      channel,
		Target:       target,
		User:         userPtr,
		ClientIP:     clientip.FromGin(c),
		CaptchaToken: req.CaptchaToken,
	})
	if err != nil {
		Fail(c, http.StatusBadRequest, err.Error())
		return
	}
	OK(c, res)
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
