package mailer

import (
	"context"
	"crypto/tls"
	"net"
	"net/smtp"
	"strconv"
	"time"

	"github.com/openrealm/openiam/backend/internal/platform/config"
	"go.uber.org/zap"
)

type SMTPMailer struct {
	cfg config.SMTPConfig
	log *zap.Logger
}

func (m *SMTPMailer) Send(ctx context.Context, msg Message) error {
	addr := net.JoinHostPort(m.cfg.Host, strconv.Itoa(m.cfg.Port))
	dialer := &net.Dialer{Timeout: 15 * time.Second}

	client, err := m.connect(dialer, addr)
	if err != nil {
		return err
	}
	defer func() { _ = client.Close() }()

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := client.Auth(auth); err != nil {
			return err
		}
	}

	if err := client.Mail(m.cfg.FromAddress); err != nil {
		return err
	}
	for _, to := range msg.To {
		if err := client.Rcpt(to); err != nil {
			return err
		}
	}

	writer, err := client.Data()
	if err != nil {
		return err
	}
	if _, err := writer.Write(buildMIME(m.cfg.FromName, m.cfg.FromAddress, msg)); err != nil {
		return err
	}
	if err := writer.Close(); err != nil {
		return err
	}

	if err := client.Quit(); err != nil {
		m.log.Warn("smtp quit", zap.Error(err))
	}

	m.log.Info("email sent",
		zap.Strings("to", msg.To),
		zap.String("subject", msg.Subject),
	)
	return nil
}

func (m *SMTPMailer) connect(dialer *net.Dialer, addr string) (*smtp.Client, error) {
	tlsConfig := &tls.Config{ServerName: m.cfg.Host, MinVersion: tls.VersionTLS12}

	if m.cfg.TLS == "implicit" {
		conn, err := tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		if err != nil {
			return nil, err
		}
		return smtp.NewClient(conn, m.cfg.Host)
	}

	conn, err := dialer.Dial("tcp", addr)
	if err != nil {
		return nil, err
	}
	client, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return nil, err
	}

	if m.cfg.TLS == "starttls" {
		if ok, _ := client.Extension("STARTTLS"); ok {
			if err := client.StartTLS(tlsConfig); err != nil {
				_ = client.Close()
				return nil, err
			}
		}
	}

	return client, nil
}
