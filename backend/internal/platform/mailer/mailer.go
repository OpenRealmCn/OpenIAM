package mailer

import (
	"context"

	"github.com/openrealm/openiam/backend/internal/platform/config"
	"go.uber.org/zap"
)

type Message struct {
	To      []string
	Subject string
	Text    string
	HTML    string
}

type Mailer interface {
	Send(ctx context.Context, msg Message) error
}

func New(cfg config.SMTPConfig, log *zap.Logger) Mailer {
	if !cfg.Enabled() {
		log.Info("SMTP not configured; emails will be logged instead of sent")
		return &LogMailer{log: log}
	}
	return &SMTPMailer{cfg: cfg, log: log}
}
