package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"

	"github.com/openrealm/openiam/internal/models"
	"go.uber.org/zap"
)

// SMSProvider 定义短信通道插件需实现的发送能力。
type SMSProvider interface {
	PluginDriver
	SendSMS(ctx context.Context, cfg models.JSONMap, phone, content, code string) error
}

// ConsoleSMSDriver 用于开发联调与零成本兜底验证的日志输出型短信通道。
type ConsoleSMSDriver struct{}

func NewConsoleSMSDriver() *ConsoleSMSDriver { return &ConsoleSMSDriver{} }

func (d *ConsoleSMSDriver) Slot() string { return SlotSMS }
func (d *ConsoleSMSDriver) Type() string { return "console_sms" }

func (d *ConsoleSMSDriver) Metadata() DriverMetadata {
	return DriverMetadata{
		Slot:        SlotSMS,
		Type:        d.Type(),
		DisplayName: "内置控制台短信通道",
		Description: "将短信验证码输出至服务端运行日志，适用于本地联调与离线演练环境。",
		Fields: []ConfigField{
			{Key: "sign_name", Label: "短信签名", Type: "text", Default: "OpenIAM", Description: "日志中展示的短信签名标识。"},
			{Key: "simulate_failure", Label: "模拟故障（触发降级演练）", Type: "bool", Default: "false", Description: "开启后发送将主动报错，用于测试短信降级至邮箱与告警逻辑。"},
		},
	}
}

func (d *ConsoleSMSDriver) ValidateConfig(cfg models.JSONMap) error { return nil }
func (d *ConsoleSMSDriver) HealthCheck(ctx context.Context, cfg models.JSONMap) error {
	if strings.EqualFold(cfgStr(cfg, "simulate_failure", "false"), "true") {
		return errors.New("当前配置为模拟故障状态")
	}
	return nil
}

func (d *ConsoleSMSDriver) SendSMS(ctx context.Context, cfg models.JSONMap, phone, content, code string) error {
	if strings.EqualFold(cfgStr(cfg, "simulate_failure", "false"), "true") {
		return errors.New("短信网关模拟发送失败")
	}
	zap.L().Info("console_sms dispatched",
		zap.String("sign", cfgStr(cfg, "sign_name", "OpenIAM")),
		zap.String("phone", phone),
		zap.String("content", content),
	)
	return nil
}

// WebhookSMSDriver 通用 HTTP POST Webhook 短信网关适配器。
type WebhookSMSDriver struct{}

func NewWebhookSMSDriver() *WebhookSMSDriver { return &WebhookSMSDriver{} }

func (d *WebhookSMSDriver) Slot() string { return SlotSMS }
func (d *WebhookSMSDriver) Type() string { return "webhook_sms" }

func (d *WebhookSMSDriver) Metadata() DriverMetadata {
	return DriverMetadata{
		Slot:        SlotSMS,
		Type:        d.Type(),
		DisplayName: "通用 HTTP Webhook 短信网关",
		Description: "通过自定义 HTTPS 接口推送短信发送请求（JSON 格式：phone、content、code）。",
		Fields: []ConfigField{
			{Key: "endpoint", Label: "Webhook 接收地址", Type: "url", Required: true, Placeholder: "https://sms-gateway.example.com/send"},
			{Key: "auth_token", Label: "Bearer 鉴权令牌", Type: "password", Placeholder: "可选，写入 Authorization: Bearer <token>"},
		},
	}
}

func (d *WebhookSMSDriver) ValidateConfig(cfg models.JSONMap) error {
	return ValidateExternalURL(cfgStr(cfg, "endpoint", ""))
}

func (d *WebhookSMSDriver) HealthCheck(ctx context.Context, cfg models.JSONMap) error {
	return d.ValidateConfig(cfg)
}

func (d *WebhookSMSDriver) SendSMS(ctx context.Context, cfg models.JSONMap, phone, content, code string) error {
	endpoint := cfgStr(cfg, "endpoint", "")
	if err := ValidateExternalURL(endpoint); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]string{
		"phone":   phone,
		"content": content,
		"code":    code,
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if tok := cfgStr(cfg, "auth_token", ""); tok != "" {
		req.Header.Set("Authorization", "Bearer "+tok)
	}
	resp, err := NewSafeHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("短信网关返回状态码 %d", resp.StatusCode)
	}
	return nil
}

// AliyunSMSDriver 阿里云短信网关插件适配器（支持配置校验与签名参数检查）。
type AliyunSMSDriver struct{}

func NewAliyunSMSDriver() *AliyunSMSDriver { return &AliyunSMSDriver{} }

func (d *AliyunSMSDriver) Slot() string { return SlotSMS }
func (d *AliyunSMSDriver) Type() string { return "aliyun_sms" }

func (d *AliyunSMSDriver) Metadata() DriverMetadata {
	return DriverMetadata{
		Slot:        SlotSMS,
		Type:        d.Type(),
		DisplayName: "阿里云短信服务（Aliyun SMS）",
		Description: "接入阿里云短信服务（支持 AccessKey、签名与模板编码配置）。",
		Fields: []ConfigField{
			{Key: "access_key_id", Label: "AccessKey ID", Type: "text", Required: true},
			{Key: "access_key_secret", Label: "AccessKey Secret", Type: "password", Required: true},
			{Key: "sign_name", Label: "短信签名名称", Type: "text", Required: true},
			{Key: "template_code", Label: "短信模板 CODE", Type: "text", Required: true, Placeholder: "SMS_123456789"},
			{Key: "endpoint", Label: "接口端点", Type: "url", Default: "https://dysmsapi.aliyuncs.com"},
		},
	}
}

func (d *AliyunSMSDriver) ValidateConfig(cfg models.JSONMap) error {
	if cfgStr(cfg, "access_key_id", "") == "" || cfgStr(cfg, "access_key_secret", "") == "" {
		return errors.New("AccessKey ID 与 AccessKey Secret 不能为空")
	}
	if cfgStr(cfg, "sign_name", "") == "" || cfgStr(cfg, "template_code", "") == "" {
		return errors.New("短信签名名称与模板 CODE 不能为空")
	}
	return ValidateExternalURL(cfgStr(cfg, "endpoint", "https://dysmsapi.aliyuncs.com"))
}

func (d *AliyunSMSDriver) HealthCheck(ctx context.Context, cfg models.JSONMap) error {
	return d.ValidateConfig(cfg)
}

func (d *AliyunSMSDriver) SendSMS(ctx context.Context, cfg models.JSONMap, phone, content, code string) error {
	if err := d.ValidateConfig(cfg); err != nil {
		return err
	}
	endpoint := strings.TrimRight(cfgStr(cfg, "endpoint", "https://dysmsapi.aliyuncs.com"), "/")
	payload, _ := json.Marshal(map[string]string{
		"PhoneNumbers":  phone,
		"SignName":      cfgStr(cfg, "sign_name", ""),
		"TemplateCode":  cfgStr(cfg, "template_code", ""),
		"TemplateParam": fmt.Sprintf(`{"code":"%s"}`, code),
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint+"/", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := NewSafeHTTPClient().Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("阿里云短信接口返回状态码 %d", resp.StatusCode)
	}
	return nil
}
