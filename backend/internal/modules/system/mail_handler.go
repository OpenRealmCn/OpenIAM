package system

import (
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/openrealm/openiam/backend/internal/platform/mailer"
	"github.com/openrealm/openiam/backend/internal/platform/response"
)

type MailHandler struct {
	mailer mailer.Mailer
}

func NewMailHandler(m mailer.Mailer) *MailHandler {
	return &MailHandler{mailer: m}
}

type SendTestRequest struct {
	To string `json:"to" binding:"required"`
}

func (h *MailHandler) SendTest(c *gin.Context) {
	var req SendTestRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, "VALIDATION_FAILED", "A recipient address is required")
		return
	}

	msg := mailer.Message{
		To:      []string{req.To},
		Subject: "OpenIAM SMTP 测试邮件",
		Text:    "这是一封来自 OpenIAM 的测试邮件。如果你收到它，说明 SMTP 发信配置正常。",
		HTML:    `<div style="font-family:Arial,sans-serif"><h2 style="margin:0 0 12px">SMTP 配置正常</h2><p>这是一封来自 OpenIAM 的测试邮件。</p></div>`,
	}

	if err := h.mailer.Send(c.Request.Context(), msg); err != nil {
		response.Error(c, http.StatusBadGateway, "MAIL_SEND_FAILED", "Unable to send the test email")
		return
	}

	response.Data(c, http.StatusOK, gin.H{"sent": true, "to": req.To})
}
