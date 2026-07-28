package service

import (
	"context"
	"fmt"

	"github.com/openrealm/openiam/backend/internal/modules/identity/domain"
	"github.com/openrealm/openiam/backend/internal/platform/mailer"
	"go.uber.org/zap"
)

type Notifier interface {
	NotifyUserCreated(ctx context.Context, user *domain.User)
}

type EmailNotifier struct {
	mailer   mailer.Mailer
	fromName string
	log      *zap.Logger
}

func NewEmailNotifier(m mailer.Mailer, fromName string, log *zap.Logger) *EmailNotifier {
	return &EmailNotifier{mailer: m, fromName: fromName, log: log}
}

func (n *EmailNotifier) NotifyUserCreated(ctx context.Context, user *domain.User) {
	if user.Email == "" {
		return
	}

	name := user.DisplayName
	if name == "" {
		name = user.Username
	}

	msg := mailer.Message{
		To:      []string{user.Email},
		Subject: "你的 OpenRealm 账号已创建",
		Text: fmt.Sprintf(
			"你好 %s，\n\n管理员已为你创建 OpenIAM 账号（%s）。\n请使用企业身份登录 OpenIAM 控制台。\n\n— OpenRealm 身份平台",
			name, user.Username,
		),
		HTML: fmt.Sprintf(
			`<div style="font-family:Arial,sans-serif;color:#111">`+
				`<h2 style="margin:0 0 12px">欢迎加入 OpenRealm</h2>`+
				`<p>你好 %s，管理员已为你创建 OpenIAM 账号 <code>%s</code>。</p>`+
				`<p>请使用企业身份登录 OpenIAM 控制台。</p>`+
				`<p style="color:#666;font-size:12px">— OpenRealm 身份平台</p></div>`,
			name, user.Username,
		),
	}

	if err := n.mailer.Send(ctx, msg); err != nil {
		n.log.Warn("send welcome email failed",
			zap.String("email", user.Email),
			zap.Error(err),
		)
	}
}
