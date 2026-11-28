package notify

import (
	"context"
	"errors"
	"fmt"
	"html"
	"strings"
	"time"

	"github.com/openrealm/openiam/internal/mailer"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/plugins"
	"github.com/openrealm/openiam/internal/rbac"
	"gorm.io/gorm"
)

const (
	CategorySystemMessage = "system_message" // 系统消息（面向特定用户的安全提醒/权限变更/私信）
	CategoryAnnouncement  = "announcement"   // 系统公告（面向全体用户的平台公告 user_id=0）
	CategorySystemNotice  = "system_notice"  // 系统通知（面向管理员/运维的告警、预算、退信等）
)

type Service struct {
	db        *gorm.DB
	mailerSvc *mailer.Service
	enforcer  *rbac.Enforcer
	pluginMgr *plugins.Manager
}

func NewService(db *gorm.DB, mailerSvc *mailer.Service, enforcer *rbac.Enforcer, pluginMgr *plugins.Manager) *Service {
	return &Service{
		db:        db,
		mailerSvc: mailerSvc,
		enforcer:  enforcer,
		pluginMgr: pluginMgr,
	}
}

// EnsureDefaultTemplates 幂等初始化邮件、短信与站内信常用中文模板。
func (s *Service) EnsureDefaultTemplates() error {
	defaults := []models.NotificationTemplate{
		{
			Code:      "otp_verify",
			Name:      "一次性验证码通知",
			Channel:   "email",
			Subject:   "【{{site_name}}】您的安全验证码：{{code}}",
			Body:      "您好 {{username}}：\n\n您正在执行身份验证操作，本次一次性验证码为：{{code}}（有效期 {{ttl_minutes}} 分钟）。\n如非本人操作，请立即忽略并修改您的登录密码。",
			Variables: models.StringSlice{"site_name", "username", "code", "ttl_minutes"},
			Enabled:   true,
		},
		{
			Code:      "otp_verify_sms",
			Name:      "一次性短信验证码",
			Channel:   "sms",
			Subject:   "短信验证码",
			Body:      "【{{site_name}}】您的验证码为 {{code}}，{{ttl_minutes}} 分钟内有效，请勿泄露给他人。",
			Variables: models.StringSlice{"site_name", "code", "ttl_minutes"},
			Enabled:   true,
		},
		{
			Code:      "password_reset",
			Name:      "密码重置验证码邮件",
			Channel:   "email",
			Subject:   "【{{site_name}}】重置密码安全验证",
			Body:      "您好 {{username}}：\n\n您的密码重置验证码为：{{code}}，有效期 {{ttl_minutes}} 分钟。",
			Variables: models.StringSlice{"site_name", "username", "code", "ttl_minutes"},
			Enabled:   true,
		},
		{
			Code:      "risk_alert",
			Name:      "高风险登录提醒",
			Channel:   "in_app",
			Subject:   "检测到异常登录风险（{{risk_level}}）",
			Body:      "系统于 {{time}} 检测到账号 {{username}} 从 {{ip}}（{{location}}，设备 {{device}}）发起登录，风险评分 {{score}}，触发因子：{{reasons}}。",
			Variables: models.StringSlice{"time", "username", "ip", "location", "device", "score", "risk_level", "reasons"},
			Enabled:   true,
		},
		{
			Code:      "jit_granted",
			Name:      "临时权限授予通知",
			Channel:   "in_app",
			Subject:   "已为您授予临时权限",
			Body:      "您已被授予域 {{domain}} 下的临时角色「{{role}}」，将在 {{expires_at}} 自动回收。授权说明：{{reason}}",
			Variables: models.StringSlice{"domain", "role", "expires_at", "reason"},
			Enabled:   true,
		},
		{
			Code:      "jit_revoked",
			Name:      "临时权限回收通知",
			Channel:   "in_app",
			Subject:   "临时权限已到期/撤销回收",
			Body:      "您在域 {{domain}} 下的临时角色「{{role}}」已被回收失效。",
			Variables: models.StringSlice{"domain", "role"},
			Enabled:   true,
		},
		{
			Code:      "sms_cost_alert",
			Name:      "短信日预算告警",
			Channel:   "in_app",
			Subject:   "短信发送日成本超出预算阈值",
			Body:      "今日短信渠道累计折算费用已达 {{cost_yuan}} 元，超出预算阈值 {{budget_yuan}} 元，请检查是否存在刷量或开启更严格的人机验证。",
			Variables: models.StringSlice{"cost_yuan", "budget_yuan"},
			Enabled:   true,
		},
	}
	for _, tpl := range defaults {
		var existing models.NotificationTemplate
		if err := s.db.Where("code = ?", tpl.Code).First(&existing).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if cerr := s.db.Create(&tpl).Error; cerr != nil {
					return cerr
				}
			}
		}
	}
	return nil
}

// RenderText 对模板中的 {{key}} 占位符进行安全替换；escapeHTML 为 true 时先对变量值做 HTML 转义。
func RenderText(tplText string, vars map[string]string, escapeHTML bool) string {
	out := tplText
	for k, v := range vars {
		val := v
		if escapeHTML {
			val = html.EscapeString(val)
		}
		out = strings.ReplaceAll(out, "{{"+k+"}}", val)
	}
	return out
}

func (s *Service) RenderTemplate(ctx context.Context, code string, vars map[string]string) (subject, body string, tpl *models.NotificationTemplate, err error) {
	var row models.NotificationTemplate
	if err := s.db.WithContext(ctx).Where("code = ? AND enabled = ?", code, true).First(&row).Error; err != nil {
		return "", "", nil, err
	}
	subj := RenderText(row.Subject, vars, false)
	content := RenderText(row.Body, vars, false)
	return subj, content, &row, nil
}

// SendInApp 发送站内通知（支持系统消息、全员公告、系统通知三大类）。
func (s *Service) SendInApp(ctx context.Context, userID uint64, category, level, title, content string, meta models.JSONMap, createdBy uint64, expiresAt *time.Time) (*models.Notification, error) {
	if category == "" {
		category = CategorySystemMessage
	}
	if level == "" {
		level = "info"
	}
	row := &models.Notification{
		UserID:    userID,
		Category:  category,
		Level:     level,
		Title:     strings.TrimSpace(title),
		Content:   strings.TrimSpace(content),
		Metadata:  meta,
		CreatedBy: createdBy,
		ExpiresAt: expiresAt,
	}
	if err := s.db.WithContext(ctx).Create(row).Error; err != nil {
		return nil, err
	}
	if (level == "security" || level == "error" || level == "warning") && s.pluginMgr != nil {
		go s.pluginMgr.PushNotificationWebhooks(context.Background(), row.Title, row.Content, row.Level)
	}
	return row, nil
}

// NotifySuperAdmins 向全体平台超级管理员发送系统通知（system_notice）。
func (s *Service) NotifySuperAdmins(ctx context.Context, level, title, content string, meta models.JSONMap) {
	if s.enforcer == nil {
		return
	}
	adminIDs, err := s.enforcer.GetUsersForRoleInDomain(rbac.SuperAdminRole, rbac.DefaultDomain)
	if err != nil {
		return
	}
	for _, id := range adminIDs {
		_, _ = s.SendInApp(ctx, id, CategorySystemNotice, level, title, content, meta, 0, nil)
	}
}

// IsRecipientBounceBlocked 判断某个收件人是否因连续硬退信超过 3 次而被自动抑制发送。
func (s *Service) IsRecipientBounceBlocked(ctx context.Context, channel, recipient string) bool {
	if recipient == "" {
		return false
	}
	var count int64
	s.db.WithContext(ctx).Model(&models.NotificationDelivery{}).
		Where("channel = ? AND recipient = ? AND status = ?", channel, strings.ToLower(strings.TrimSpace(recipient)), "bounced").
		Count(&count)
	return count >= 3
}

// RecordDelivery 持久化单条发送记录，供发件审计、成本统计与退信追踪。
func (s *Service) RecordDelivery(ctx context.Context, d *models.NotificationDelivery) error {
	if d.Recipient != "" {
		d.Recipient = strings.TrimSpace(d.Recipient)
	}
	return s.db.WithContext(ctx).Create(d).Error
}

// MarkBounced 将指定发送记录标记为退信状态，并向超级管理员发出系统通知告警。
func (s *Service) MarkBounced(ctx context.Context, deliveryID uint64, reason string) (*models.NotificationDelivery, error) {
	var row models.NotificationDelivery
	if err := s.db.WithContext(ctx).First(&row, deliveryID).Error; err != nil {
		return nil, err
	}
	now := time.Now()
	reason = strings.TrimSpace(reason)
	if reason == "" {
		reason = "收件方服务器退信"
	}
	if err := s.db.WithContext(ctx).Model(&row).Updates(map[string]interface{}{
		"status":        "bounced",
		"bounce_reason": reason,
		"bounced_at":    &now,
	}).Error; err != nil {
		return nil, err
	}
	row.Status = "bounced"
	row.BounceReason = reason
	row.BouncedAt = &now

	s.NotifySuperAdmins(ctx, "warning", "消息投递退信告警",
		fmt.Sprintf("通道 [%s] 向 %s 投递的消息（ID=%d）已发生退信：%s", row.Channel, row.Recipient, row.ID, reason),
		models.JSONMap{"delivery_id": row.ID, "recipient": row.Recipient, "channel": row.Channel},
	)
	return &row, nil
}
