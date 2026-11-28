package mailer

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"html"
	"mime"
	"net"
	"net/mail"
	"net/smtp"
	"strings"
	"time"

	"github.com/openrealm/openiam/internal/settings"
)

// Service 基于数据库动态 SMTP 设置提供生产级邮件发送能力（支持 STARTTLS、隐式 TLS 与明文模式）。
type Service struct {
	settingsSvc *settings.Service
}

func NewService(settingsSvc *settings.Service) *Service {
	return &Service{settingsSvc: settingsSvc}
}

func sanitizeHeader(v string) string {
	v = strings.ReplaceAll(v, "\r", "")
	v = strings.ReplaceAll(v, "\n", "")
	return strings.TrimSpace(v)
}

func validateRecipient(addr string) (string, error) {
	cleaned := sanitizeHeader(addr)
	parsed, err := mail.ParseAddress(cleaned)
	if err != nil || parsed.Address == "" {
		return "", fmt.Errorf("无效的收件人邮箱地址: %q", addr)
	}
	return parsed.Address, nil
}

// SendMail 发送 HTML 邮件，使用当前数据库中生效的 SMTP 配置。
func (s *Service) SendMail(ctx context.Context, to, subject, htmlBody string) error {
	snap := s.settingsSvc.Snapshot()
	if !snap.SMTPEnabled {
		return errors.New("系统尚未启用 SMTP 邮件服务，请先在「系统设置 -> 邮件服务」中开启并配置")
	}
	if strings.TrimSpace(snap.SMTPHost) == "" || snap.SMTPPort <= 0 {
		return errors.New("SMTP 服务器地址或端口未配置")
	}
	fromEmail := strings.TrimSpace(snap.SMTPFromEmail)
	if fromEmail == "" {
		fromEmail = strings.TrimSpace(snap.SMTPUsername)
	}
	if fromEmail == "" {
		return errors.New("发件人邮箱（smtp.from_email）未配置")
	}
	if _, err := mail.ParseAddress(fromEmail); err != nil {
		return fmt.Errorf("发件人邮箱格式无效: %w", err)
	}
	rcpt, err := validateRecipient(to)
	if err != nil {
		return err
	}

	fromName := sanitizeHeader(snap.SMTPFromName)
	if fromName == "" {
		fromName = sanitizeHeader(snap.SiteName)
	}
	if fromName == "" {
		fromName = "OpenIAM"
	}

	encodedSubject := mime.QEncoding.Encode("UTF-8", sanitizeHeader(subject))
	encodedFrom := fmt.Sprintf("%s <%s>", mime.QEncoding.Encode("UTF-8", fromName), fromEmail)

	var msg strings.Builder
	msg.WriteString("From: " + encodedFrom + "\r\n")
	msg.WriteString("To: " + rcpt + "\r\n")
	msg.WriteString("Subject: " + encodedSubject + "\r\n")
	msg.WriteString("MIME-Version: 1.0\r\n")
	msg.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	msg.WriteString("\r\n")
	msg.WriteString(htmlBody)

	addr := net.JoinHostPort(snap.SMTPHost, fmt.Sprintf("%d", snap.SMTPPort))
	dialer := &net.Dialer{Timeout: 10 * time.Second}
	tlsConfig := &tls.Config{
		ServerName: snap.SMTPHost,
		MinVersion: tls.VersionTLS12,
	}

	var conn net.Conn
	enc := strings.ToLower(strings.TrimSpace(snap.SMTPEncryption))
	if enc == "tls" || enc == "ssl" {
		tlsDialer := &tls.Dialer{NetDialer: dialer, Config: tlsConfig}
		conn, err = tlsDialer.DialContext(ctx, "tcp", addr)
	} else {
		conn, err = dialer.DialContext(ctx, "tcp", addr)
	}
	if err != nil {
		return fmt.Errorf("连接 SMTP 服务器 %s 失败: %w", addr, err)
	}
	defer func() { _ = conn.Close() }()

	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(20 * time.Second))
	}

	client, err := smtp.NewClient(conn, snap.SMTPHost)
	if err != nil {
		return fmt.Errorf("初始化 SMTP 会话失败: %w", err)
	}
	defer func() { _ = client.Close() }()

	// STARTTLS 模式下服务器不宣告 STARTTLS 时必须中止：中间人可以剥离该扩展，迫使验证码明文发送。
	// 明文投递只能通过显式选择 none 开启。
	if enc == "starttls" || enc == "" {
		ok, _ := client.Extension("STARTTLS")
		if !ok {
			return errors.New("SMTP 服务器未提供 STARTTLS，已拒绝明文发送；如确为内网中继请将加密方式设为 none")
		}
		if err := client.StartTLS(tlsConfig); err != nil {
			return fmt.Errorf("STARTTLS 握手失败: %w", err)
		}
	}

	if snap.SMTPUsername != "" {
		auth := smtp.PlainAuth("", snap.SMTPUsername, snap.SMTPPassword, snap.SMTPHost)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("SMTP 身份验证失败: %w", err)
		}
	}

	if err := client.Mail(fromEmail); err != nil {
		return fmt.Errorf("设置发件人失败: %w", err)
	}
	if err := client.Rcpt(rcpt); err != nil {
		return fmt.Errorf("设置收件人失败: %w", err)
	}

	w, err := client.Data()
	if err != nil {
		return fmt.Errorf("写入邮件数据失败: %w", err)
	}
	if _, err := w.Write([]byte(msg.String())); err != nil {
		_ = w.Close()
		return fmt.Errorf("发送邮件内容失败: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("提交邮件失败: %w", err)
	}
	_ = client.Quit()
	return nil
}

// SendTestEmail 发送 SMTP 连通性测试邮件。
func (s *Service) SendTestEmail(ctx context.Context, to string) error {
	siteName := html.EscapeString(s.settingsSvc.Snapshot().SiteName)
	body := fmt.Sprintf(`
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #e5e7eb; border-radius: 12px;">
  <h2 style="margin-top: 0; color: #1976d2;">%s — SMTP 邮件服务测试</h2>
  <p style="color: #374151; line-height: 1.6;">您好，这是一封来自 <strong>%s</strong> 的测试邮件。</p>
  <p style="color: #374151; line-height: 1.6;">如果您收到此邮件，说明当前 SMTP 发信配置已正常工作。</p>
  <p style="color: #9ca3af; font-size: 12px; margin-top: 24px;">发送时间：%s</p>
</div>`, siteName, siteName, time.Now().Format("2006-01-02 15:04:05"))
	return s.SendMail(ctx, to, fmt.Sprintf("[%s] SMTP 邮件服务测试", s.settingsSvc.Snapshot().SiteName), body)
}

// SendPasswordResetCode 发送 6 位重置密码验证码邮件。
func (s *Service) SendPasswordResetCode(ctx context.Context, to, username, code string, ttlMinutes int) error {
	siteName := html.EscapeString(s.settingsSvc.Snapshot().SiteName)
	safeUser := html.EscapeString(username)
	safeCode := html.EscapeString(code)
	body := fmt.Sprintf(`
<div style="font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; max-width: 520px; margin: 0 auto; padding: 24px; border: 1px solid #e5e7eb; border-radius: 12px;">
  <h2 style="margin-top: 0; color: #1976d2;">%s — 重置密码验证码</h2>
  <p style="color: #374151; line-height: 1.6;">您好 <strong>%s</strong>，您正在申请重置账号密码，本次一次性验证码为：</p>
  <div style="margin: 20px 0; padding: 14px; background: #f3f4f6; border-radius: 8px; text-align: center; font-size: 28px; font-weight: 700; letter-spacing: 6px; color: #111827;">%s</div>
  <p style="color: #6b7280; font-size: 13px;">验证码 %d 分钟内有效，请勿泄露给他人。如非本人操作，请忽略此邮件。</p>
</div>`, siteName, safeUser, safeCode, ttlMinutes)
	return s.SendMail(ctx, to, fmt.Sprintf("[%s] 重置密码验证码", s.settingsSvc.Snapshot().SiteName), body)
}
