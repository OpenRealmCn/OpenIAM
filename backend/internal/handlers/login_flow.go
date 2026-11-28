package handlers

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/openrealm/openiam/internal/audit"
	"github.com/openrealm/openiam/internal/clientip"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/rbac"
	"github.com/openrealm/openiam/internal/risk"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

// loginIssuer 汇总签发登录会话所需的依赖。密码、验证码、通行密钥与联合登录在主因子通过后
// 都必须经过同一套风控、二步验证、强制改密与会话签发逻辑，避免某条登录路径绕过安全检查。
type loginIssuer struct {
	db          *gorm.DB
	jwtMgr      *security.JWTManager
	stateStore  *security.StateStore
	enforcer    *rbac.Enforcer
	auditSvc    *audit.Service
	settingsSvc *settings.Service
	riskEngine  *risk.Engine
}

func (h *AuthHandler) issuer() *loginIssuer {
	return &loginIssuer{
		db:          h.db,
		jwtMgr:      h.jwtMgr,
		stateStore:  h.stateStore,
		enforcer:    h.enforcer,
		auditSvc:    h.auditSvc,
		settingsSvc: h.settingsSvc,
		riskEngine:  h.riskEngine,
	}
}

type gateOptions struct {
	// Channel 为主认证方式（password / otp / passkey / federated），写入二步验证会话与审计。
	Channel string
	// RequireTOTP 表示账号已启用 TOTP 时必须完成二步验证；通行密钥本身即强认证因子，可不再要求。
	RequireTOTP bool
	// AllowRiskChallenge 表示风控判定为 challenge_mfa 时发起二步验证；为 false 时只执行 block 阻断。
	AllowRiskChallenge bool
}

type mfaChallengeState struct {
	UserID      uint64   `json:"user_id"`
	Methods     []string `json:"methods"`
	Channel     string   `json:"channel,omitempty"`
	RiskLevel   string   `json:"risk_level"`
	RiskReasons []string `json:"risk_reasons"`
	Extra       gin.H    `json:"extra,omitempty"`
}

func (li *loginIssuer) totpEnabled(userID uint64) bool {
	var n int64
	li.db.Model(&models.UserTOTP{}).Where("user_id = ? AND enabled = ?", userID, true).Count(&n)
	return n > 0
}

// usableEmail 判断邮箱是否可作为验证码接收地址（排除联合登录自动生成的占位邮箱）。
func usableEmail(email string) bool {
	return email != "" && !strings.HasSuffix(strings.ToLower(email), ".oauth.openiam.local")
}

// gate 在主认证因子通过后执行风控评估与二步验证判定。
// 返回 true 表示已向客户端写出响应（被阻断或需要二次验证），调用方应直接返回。
func (li *loginIssuer) gate(c *gin.Context, user models.User, opts gateOptions, extra gin.H) bool {
	ctx := c.Request.Context()
	var riskEval *risk.Evaluation
	if li.riskEngine != nil {
		riskEval = li.riskEngine.EvaluateLogin(
			ctx,
			user,
			clientip.FromGin(c),
			truncateStr(c.GetHeader("User-Agent"), 512),
			headerFingerprint(c),
			headerGeo(c, li.settingsSvc),
			time.Now(),
		)
		if riskEval.Action == "block" {
			Fail(c, http.StatusForbidden, "当前登录环境存在高风险，已被系统安全策略阻断")
			return true
		}
	}

	hasTOTP := li.totpEnabled(user.ID)
	riskChallenge := opts.AllowRiskChallenge && riskEval != nil && riskEval.Action == "challenge_mfa"
	if !(opts.RequireTOTP && hasTOTP) && !riskChallenge {
		return false
	}

	// 已启用 TOTP 的账号只接受 TOTP 或恢复码：若允许邮件/短信验证码替代，掌握邮箱即可绕过 TOTP。
	methods := make([]string, 0, 3)
	if hasTOTP {
		methods = append(methods, "totp", "recovery_code")
	} else {
		if usableEmail(user.Email) && li.settingsSvc.Snapshot().SMTPEnabled {
			methods = append(methods, "email_otp")
		}
		if user.Phone != "" {
			methods = append(methods, "sms_otp")
		}
	}
	if len(methods) == 0 {
		Fail(c, http.StatusForbidden, "当前登录存在安全风险，且账号未绑定可用的二次验证方式，已被阻断，请联系管理员")
		return true
	}

	riskLevel := "low"
	var riskReasons []string
	if riskEval != nil {
		riskLevel = riskEval.Level
		riskReasons = riskEval.Reasons
	}
	mfaToken := "mfa_" + uuid.NewString()
	payload, _ := json.Marshal(mfaChallengeState{
		UserID:      user.ID,
		Methods:     methods,
		Channel:     opts.Channel,
		RiskLevel:   riskLevel,
		RiskReasons: riskReasons,
		Extra:       extra,
	})
	if err := li.stateStore.SaveMFAChallenge(ctx, mfaToken, payload, 5*time.Minute); err != nil {
		Fail(c, http.StatusInternalServerError, "创建二次验证会话失败")
		return true
	}
	emailHint := ""
	if usableEmail(user.Email) {
		emailHint = maskEmail(user.Email)
	}
	OK(c, gin.H{
		"mfa_required": true,
		"mfa_token":    mfaToken,
		"methods":      methods,
		"risk_level":   riskLevel,
		"email_hint":   emailHint,
		"phone_hint":   maskPhone(user.Phone),
	})
	return true
}

// finish 完成登录：记录登录时间，强制改密账号只签发受限令牌，其余签发带会话的正式令牌。
func (li *loginIssuer) finish(c *gin.Context, user models.User, action string, after map[string]interface{}, extra gin.H) {
	now := time.Now()
	_ = li.db.Model(&user).Updates(map[string]interface{}{
		"last_login_at": &now,
		"last_login_ip": clientip.FromGin(c),
	}).Error

	if after == nil {
		after = map[string]interface{}{}
	}

	// 强制改密状态：只签发短期受限令牌，不下发 Refresh Token；
	// 该令牌仅能用于修改密码与退出登录，其余接口由 AuthMiddleware 统一返回 403 password_change_required。
	if user.MustChangePassword {
		accessToken, _, _, err := li.jwtMgr.GenerateAccessToken(
			user.ID, user.Username, user.Email,
			security.ScopePasswordChange, "", security.PasswordChangeTokenTTL,
		)
		if err != nil {
			Fail(c, http.StatusInternalServerError, "签发令牌失败")
			return
		}
		clearRefreshCookie(c)
		after["must_change_password"] = true
		li.auditSvc.RecordFromContext(c, audit.Entry{
			ActorID:       user.ID,
			ActorUsername: user.Username,
			DomainCode:    rbac.DefaultDomain,
			Action:        action,
			ResourceType:  "user",
			ResourceID:    fmt.Sprintf("%d", user.ID),
			After:         after,
			Status:        "success",
		})
		resp := gin.H{
			"access_token":         accessToken,
			"expires_in":           int64(security.PasswordChangeTokenTTL.Seconds()),
			"must_change_password": true,
			"user":                 user,
		}
		for k, v := range extra {
			resp[k] = v
		}
		OK(c, resp)
		return
	}

	accessToken, refreshToken, _, expiresIn, err := createSessionAndTokens(c, li.db, li.jwtMgr, li.stateStore, li.settingsSvc, user)
	if err != nil {
		Fail(c, http.StatusInternalServerError, "签发令牌与保存会话失败")
		return
	}
	rolesMap, _ := li.enforcer.GetAllUserRoles(user.ID)
	li.auditSvc.RecordFromContext(c, audit.Entry{
		ActorID:       user.ID,
		ActorUsername: user.Username,
		DomainCode:    rbac.DefaultDomain,
		Action:        action,
		ResourceType:  "user",
		ResourceID:    fmt.Sprintf("%d", user.ID),
		After:         after,
		Status:        "success",
	})
	resp := gin.H{
		"access_token":  accessToken,
		"refresh_token": deliverRefreshToken(c, refreshToken, li.settingsSvc.Snapshot().JWTRefreshTTL),
		"expires_in":    expiresIn,
		"user":          user,
		"roles":         rolesMap,
	}
	for k, v := range extra {
		resp[k] = v
	}
	OK(c, resp)
}
