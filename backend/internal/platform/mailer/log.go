package mailer

import (
	"context"

	"go.uber.org/zap"
)

type LogMailer struct {
	log *zap.Logger
}

func (m *LogMailer) Send(_ context.Context, msg Message) error {
	m.log.Info("email dispatched (log mailer)",
		zap.Strings("to", msg.To),
		zap.String("subject", msg.Subject),
	)
	return nil
}
