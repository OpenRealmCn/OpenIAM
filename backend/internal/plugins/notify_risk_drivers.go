package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"

	"github.com/openrealm/openiam/internal/models"
)

// WebhookNotifyDriver 用于向飞书/钉钉/企业微信或自定义系统推送系统告警与通知。
type WebhookNotifyDriver struct{}

func NewWebhookNotifyDriver() *WebhookNotifyDriver { return &WebhookNotifyDriver{} }

func (d *WebhookNotifyDriver) Slot() string { return SlotNotification }
func (d *WebhookNotifyDriver) Type() string { return "webhook_notify" }

func (d *WebhookNotifyDriver) Metadata() DriverMetadata {
	return DriverMetadata{
		Slot:        SlotNotification,
		Type:        d.Type(),
		DisplayName: "Webhook 告警通知扩展",
		Description: "当发生高风险登录或短信成本预算告警时，同步推送消息至飞书/钉钉/企业微信或运维 Webhook。",
		Fields: []ConfigField{
			{Key: "webhook_url", Label: "Webhook URL", Type: "url", Required: true, Placeholder: "https://open.feishu.cn/open-apis/bot/v2/hook/..."},
			{Key: "secret", Label: "签名密钥（可选）", Type: "password"},
		},
	}
}

func (d *WebhookNotifyDriver) ValidateConfig(cfg models.JSONMap) error {
	return ValidateExternalURL(cfgStr(cfg, "webhook_url", ""))
}

func (d *WebhookNotifyDriver) HealthCheck(ctx context.Context, cfg models.JSONMap) error {
	return d.ValidateConfig(cfg)
}

func (d *WebhookNotifyDriver) Push(ctx context.Context, cfg models.JSONMap, title, content, level string) error {
	target := cfgStr(cfg, "webhook_url", "")
	if err := ValidateExternalURL(target); err != nil {
		return err
	}
	body, _ := json.Marshal(map[string]interface{}{
		"msg_type": "text",
		"title":    title,
		"level":    level,
		"content":  map[string]string{"text": fmt.Sprintf("[%s] %s\n%s", level, title, content)},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, target, bytes.NewReader(body))
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
		return fmt.Errorf("Webhook 返回状态码 %d", resp.StatusCode)
	}
	return nil
}

// LocalIPReputationRiskDriver 内置 IP 信誉与频次评估风控插件。
type LocalIPReputationRiskDriver struct{}

func NewLocalIPReputationRiskDriver() *LocalIPReputationRiskDriver {
	return &LocalIPReputationRiskDriver{}
}

func (d *LocalIPReputationRiskDriver) Slot() string { return SlotRisk }
func (d *LocalIPReputationRiskDriver) Type() string { return "ip_reputation_local" }

func (d *LocalIPReputationRiskDriver) Metadata() DriverMetadata {
	return DriverMetadata{
		Slot:        SlotRisk,
		Type:        d.Type(),
		DisplayName: "内置 IP 信誉与失败频次评分",
		Description: "结合黑名单、来源 IP 近期失败次数及内网/公网特征计算 IP 信誉风险分。",
		Fields: []ConfigField{
			{Key: "block_threshold", Label: "IP 近期失败高危阈值", Type: "number", Default: "10", Description: "单个 IP 1 小时内登录失败超过此次数将叠加高危信誉分。"},
		},
	}
}

func (d *LocalIPReputationRiskDriver) ValidateConfig(cfg models.JSONMap) error { return nil }
func (d *LocalIPReputationRiskDriver) HealthCheck(ctx context.Context, cfg models.JSONMap) error {
	return nil
}

// PushNotificationWebhooks 向所有已启用的 notification 插槽插件异步推送外部告警。
func (m *Manager) PushNotificationWebhooks(ctx context.Context, title, content, level string) {
	list, err := m.ActiveBySlot(SlotNotification)
	if err != nil || len(list) == 0 {
		return
	}
	for _, inst := range list {
		if inst.PluginType == "webhook_notify" {
			drv := NewWebhookNotifyDriver()
			_ = drv.Push(ctx, inst.Config, title, content, level)
		}
	}
}
