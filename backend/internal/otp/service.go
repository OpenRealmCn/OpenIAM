package otp

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"html"
	"math/big"
	"strings"
	"time"

	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/notify"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

type Service struct {
	db          *gorm.DB
	stateStore  *security.StateStore
	settingsSvc *settings.Service
	mailerSvc   *mailer.Service
	notifySvc   *notify.Service
	pluginMgr   *plugins.Manager
}

func NewService(
	db *gorm.DB,
	stateStore *security.StateStore,
	settingsSvc *settings.Service,
	mailerSvc *mailer.Service,
	notifySvc *notify.Service,
	pluginMgr *plugins.Manager,
) *Service {
	return &Service{
		db:          db,
		stateStore:  stateStore,
		settingsSvc: settingsSvc,
		mailerSvc:   mailerSvc,
		notifySvc:   notifySvc,
		pluginMgr:   pluginMgr,
	}
}

type SendRequest struct {
	Scene        string // login | mfa | verify
	Channel      string // sms | email
	Target       string // 手机号或邮箱（或备用识别用户）
	User         *models.User
	ClientIP     string
	CaptchaToken string
}

type SendResult struct {
	Sent       bool   `json:"sent"`
	Channel    string `json:"channel"`
	Degraded   bool   `json:"degraded"`
	Message    string `json:"message"`
	TTLMinutes int    `json:"ttl_minutes"`
}

func generateCode() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1000000))
	if err != nil {
		return "000000"
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// SendCode 发送短信或邮件一次性验证码，内置人机验证检查、频控防刷、短信成本预算告警与异常自动降级。
func (s *Service) SendCode(ctx context.Context, req SendRequest) (*SendResult, error) {
	if s.pluginMgr != nil {
		if err := s.pluginMgr.VerifyCaptchaForScene(ctx, "otp", req.CaptchaToken); err != nil {
			return nil, err
		}
	}

	snap := s.settingsSvc.Snapshot()
	channel := strings.ToLower(strings.TrimSpace(req.Channel))
	if channel != "sms" && channel != "email" {
		return nil, errors.New("不支持的验证码通道")
	}

	target := strings.TrimSpace(req.Target)
	if req.User != nil {
		if channel == "sms" && target == "" {
			target = req.User.Phone
		} else if channel == "email" && target == "" {
			target = req.User.Email
		}
	}
	if target == "" {
		return nil, errors.New("接收手机号或邮箱不能为空")
	}

	// 1. Redis 防刷频控
	rateKey := strings.ToLower(req.Scene + ":" + target)
	if err := s.stateStore.CheckAndIncrOTPRate(
		ctx, rateKey, req.ClientIP,
		snap.OTPCooldownSeconds, snap.OTPMaxPerHourTarget, snap.OTPMaxPerIPHour,
	); err != nil {
		return nil, err
	}

	code := generateCode()
	const ttlMin = 10
	scopeKey := strings.ToLower(req.Scene + ":" + target)
	uid := uint64(0)
	username := "用户"
	emailAddr := ""
	if req.User != nil {
		uid = req.User.ID
		username = req.User.Username
		emailAddr = req.User.Email
	} else if channel == "email" {
		emailAddr = target
	}

	vars := map[string]string{
		"site_name":   snap.SiteName,
		"username":    username,
		"code":        code,
		"ttl_minutes": fmt.Sprintf("%d", ttlMin),
	}

	degraded := false
	actualChannel := channel
	providerName := "smtp"
	var costCents int64

	if channel == "sms" {
		if s.notifySvc.IsRecipientBounceBlocked(ctx, "sms", target) {
			return nil, errors.New("该手机号近期退信次数过多，已被系统暂停发送")
		}
		todayCost := s.stateStore.GetDailySMSCost(ctx)
		budgetExceeded := snap.OTPSMSDailyBudgetCents > 0 && todayCost >= int64(snap.OTPSMSDailyBudgetCents)

		var smsErr error
		if budgetExceeded {
			smsErr = errors.New("今日短信发送折算费用已达日预算上限")
		} else {
			providerName, smsErr = s.dispatchSMS(ctx, target, code, vars)
		}

		if smsErr != nil {
			_ = s.notifySvc.RecordDelivery(ctx, &models.NotificationDelivery{
				TemplateCode: "otp_verify_sms",
				Channel:      "sms",
				Recipient:    target,
				UserID:       uid,
				Subject:      "短信验证码",
				Status:       "failed",
				ProviderName: providerName,
				ErrorMessage: smsErr.Error(),
			})
			// 若开启了降级开关且有可用邮箱，则自动降级为邮件通道
			if snap.OTPFallbackToEmail && emailAddr != "" && snap.SMTPEnabled {
				if eErr := s.dispatchEmail(ctx, uid, emailAddr, code, vars, "degraded"); eErr != nil {
					return nil, fmt.Errorf("短信发送失败（%s），且降级邮件发送失败（%s）", smsErr.Error(), eErr.Error())
				}
				degraded = true
				actualChannel = "email"
				scopeKey = strings.ToLower(req.Scene + ":" + target) // 仍按原请求目标匹配或通过用户关联核销
			} else {
				return nil, fmt.Errorf("短信发送失败: %s", smsErr.Error())
			}
		} else {
			costCents = int64(snap.OTPSMSCostCents)
			newTotal, _ := s.stateStore.IncrDailySMSCost(ctx, costCents)
			_ = s.notifySvc.RecordDelivery(ctx, &models.NotificationDelivery{
				TemplateCode: "otp_verify_sms",
				Channel:      "sms",
				Recipient:    target,
				UserID:       uid,
				Subject:      "短信验证码",
				Status:       "sent",
				ProviderName: providerName,
				CostCents:    costCents,
			})
			// 触发短信成本日预算告警
			if snap.OTPSMSDailyBudgetCents > 0 && newTotal >= int64(snap.OTPSMSDailyBudgetCents) && s.stateStore.MarkSMSAlertSentToday(ctx) {
				s.notifySvc.NotifySuperAdmins(ctx, "warning", "短信日预算成本告警",
					fmt.Sprintf("今日短信累计折算费用已达 %.2f 元（预算阈值 %.2f 元），请及时关注是否存在刷量风险。",
						float64(newTotal)/100.0, float64(snap.OTPSMSDailyBudgetCents)/100.0),
					models.JSONMap{"daily_cost_cents": newTotal, "budget_cents": snap.OTPSMSDailyBudgetCents},
				)
			}
		}
	} else {
		if err := s.dispatchEmail(ctx, uid, target, code, vars, "sent"); err != nil {
			return nil, err
		}
	}

	if err := s.stateStore.SaveOTP(ctx, scopeKey, security.OTPRecord{
		Code:    code,
		Channel: actualChannel,
		UserID:  uid,
	}, ttlMin*time.Minute); err != nil {
		return nil, errors.New("保存验证码状态失败")
	}

	msg := "验证码已发送，请注意查收"
	if degraded {
		msg = fmt.Sprintf("短信通道暂不可用，已自动降级通过邮箱（%s）为您发送验证码", maskEmail(emailAddr))
	}
	return &SendResult{
		Sent:       true,
		Channel:    actualChannel,
		Degraded:   degraded,
		Message:    msg,
		TTLMinutes: ttlMin,
	}, nil
}

func (s *Service) dispatchSMS(ctx context.Context, phone, code string, vars map[string]string) (string, error) {
	if s.pluginMgr == nil {
		return "", errors.New("未初始化插件管理器")
	}
	list, err := s.pluginMgr.ActiveBySlot(plugins.SlotSMS)
	if err != nil || len(list) == 0 {
		return "none", errors.New("未启用任何短信插件通道")
	}

	content := fmt.Sprintf("【%s】您的验证码为 %s，%s 分钟内有效，请勿泄露。", vars["site_name"], code, vars["ttl_minutes"])
	if _, rendered, _, tErr := s.notifySvc.RenderTemplate(ctx, "otp_verify_sms", vars); tErr == nil && rendered != "" {
		content = rendered
	}

	var lastErr error
	lastProvider := list[0].Name
	for _, inst := range list {
		lastProvider = inst.Name
		drv, ok := s.pluginMgr.GetDriver(inst.PluginType)
		if !ok {
			continue
		}
		smsProv, ok2 := drv.(plugins.SMSProvider)
		if !ok2 {
			continue
		}
		if err := smsProv.SendSMS(ctx, inst.Config, phone, content, code); err == nil {
			return inst.Name, nil
		} else {
			lastErr = err
		}
	}
	if lastErr == nil {
		lastErr = errors.New("没有可用的短信通道驱动")
	}
	return lastProvider, lastErr
}

func (s *Service) dispatchEmail(ctx context.Context, uid uint64, emailAddr, code string, vars map[string]string, status string) error {
	if s.notifySvc.IsRecipientBounceBlocked(ctx, "email", emailAddr) {
		return errors.New("该邮箱因连续退信已被保护拦截，请联系管理员解除")
	}
	subject := fmt.Sprintf("【%s】您的安全验证码：%s", vars["site_name"], code)
	body := fmt.Sprintf("您好 %s：\n\n您的一次性验证码为：%s（有效期 %s 分钟）。", vars["username"], code, vars["ttl_minutes"])
	if sSubj, sBody, _, err := s.notifySvc.RenderTemplate(ctx, "otp_verify", vars); err == nil {
		subject, body = sSubj, sBody
	}
	htmlBody := "<pre style=\"font-family:sans-serif;white-space:pre-wrap;line-height:1.6\">" + html.EscapeString(body) + "</pre>"
	sendErr := s.mailerSvc.SendMail(ctx, emailAddr, subject, htmlBody)
	if sendErr != nil {
		_ = s.notifySvc.RecordDelivery(ctx, &models.NotificationDelivery{
			TemplateCode: "otp_verify",
			Channel:      "email",
			Recipient:    emailAddr,
			UserID:       uid,
			Subject:      subject,
			Status:       "failed",
			ProviderName: "smtp",
			ErrorMessage: sendErr.Error(),
		})
		return fmt.Errorf("邮件发送失败: %s", sendErr.Error())
	}
	_ = s.notifySvc.RecordDelivery(ctx, &models.NotificationDelivery{
		TemplateCode: "otp_verify",
		Channel:      "email",
		Recipient:    emailAddr,
		UserID:       uid,
		Subject:      subject,
		Status:       status,
		ProviderName: "smtp",
	})
	return nil
}

// VerifyCode 校验并原子消费短信/邮件 OTP 验证码（最多允许输错 5 次）。
func (s *Service) VerifyCode(ctx context.Context, scene, target, code string) (*security.OTPRecord, error) {
	scopeKey := strings.ToLower(strings.TrimSpace(scene) + ":" + strings.TrimSpace(target))
	return s.stateStore.VerifyAndConsumeOTP(ctx, scopeKey, strings.TrimSpace(code), 5)
}
