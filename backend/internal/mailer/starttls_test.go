package mailer

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"testing"

	"github.com/glebarez/sqlite"
	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/settings"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// startSMTPWithoutSTARTTLS 起一个不声明 STARTTLS 的最小 SMTP 服务端，
// 用来复现「配置了 starttls 却静默降级成明文发信」的漏洞。
func startSMTPWithoutSTARTTLS(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	t.Cleanup(func() { _ = ln.Close() })

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer func() { _ = c.Close() }()
				reader := bufio.NewReader(c)
				_, _ = c.Write([]byte("220 fake ESMTP ready\r\n"))
				for {
					line, err := reader.ReadString('\n')
					if err != nil {
						return
					}
					upper := strings.ToUpper(line)
					switch {
					case strings.HasPrefix(upper, "EHLO"), strings.HasPrefix(upper, "HELO"):
						// 故意只声明一个能力，不提供 STARTTLS
						_, _ = c.Write([]byte("250-fake\r\n250 OK\r\n"))
					default:
						_, _ = c.Write([]byte("250 OK\r\n"))
					}
				}
			}(conn)
		}
	}()

	return ln.Addr().(*net.TCPAddr).Port
}

func newMailerForTest(t *testing.T, port int, overrides map[string]string) *Service {
	t.Helper()
	dsn := fmt.Sprintf("file:mailer_%s?mode=memory&cache=shared", strings.ReplaceAll(t.Name(), "/", "_"))
	db, err := gorm.Open(sqlite.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	require.NoError(t, err)
	require.NoError(t, db.AutoMigrate(&models.SystemSetting{}))

	settingsSvc, err := settings.NewService(db)
	require.NoError(t, err)

	updates := map[string]string{
		settings.KeySMTPEnabled:    "true",
		settings.KeySMTPHost:       "127.0.0.1",
		settings.KeySMTPPort:       strconv.Itoa(port),
		settings.KeySMTPFromEmail:  "noreply@example.com",
		settings.KeySMTPEncryption: "starttls",
		settings.KeyEnvironment:    "development",
	}
	for k, v := range overrides {
		updates[k] = v
	}
	_, _, err = settingsSvc.UpdateBatch(updates, 0)
	require.NoError(t, err)

	return NewService(settingsSvc)
}

func TestSendMailFailsWhenServerDoesNotOfferSTARTTLS(t *testing.T) {
	port := startSMTPWithoutSTARTTLS(t)
	svc := newMailerForTest(t, port, nil)

	err := svc.SendMail(context.Background(), "user@example.com", "测试", "<p>hi</p>")
	require.Error(t, err, "服务器不提供 STARTTLS 时必须中止发送，而不是降级成明文")
	assert.Contains(t, err.Error(), "STARTTLS")
}

func TestSendMailRefusesPlaintextInProductionEvenWhenAllowed(t *testing.T) {
	port := startSMTPWithoutSTARTTLS(t)
	svc := newMailerForTest(t, port, map[string]string{
		settings.KeySMTPEncryption:             "none",
		settings.KeySMTPAllowInsecurePlaintext: "true",
		settings.KeyEnvironment:                "production",
	})

	err := svc.SendMail(context.Background(), "user@example.com", "测试", "<p>hi</p>")
	require.Error(t, err, "生产环境即使显式允许也不得明文发信")
	assert.Contains(t, err.Error(), "明文")
}
