package plugins

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/openrealm/openiam/internal/models"
	"github.com/openrealm/openiam/internal/security"
	"github.com/openrealm/openiam/internal/settings"
	"gorm.io/gorm"
)

const (
	SlotCaptcha      = "captcha"
	SlotSMS          = "sms"
	SlotNotification = "notification"
	SlotRisk         = "risk"
	SlotOAuth        = "oauth"
)

type ConfigFieldOption struct {
	Value string `json:"value"`
	Label string `json:"label"`
}

// ConfigField 描述插件实例在前端管理面板动态渲染的表单字段。
type ConfigField struct {
	Key         string              `json:"key"`
	Label       string              `json:"label"`
	Type        string              `json:"type"` // text | password | url | select | number | bool
	Required    bool                `json:"required"`
	Default     string              `json:"default,omitempty"`
	Placeholder string              `json:"placeholder,omitempty"`
	Description string              `json:"description,omitempty"`
	Options     []ConfigFieldOption `json:"options,omitempty"`
}

// DriverMetadata 描述某类插件驱动的元信息与支持配置项。
type DriverMetadata struct {
	Slot        string        `json:"slot"`
	Type        string        `json:"type"`
	DisplayName string        `json:"display_name"`
	Description string        `json:"description"`
	Fields      []ConfigField `json:"fields"`
}

// PluginDriver 定义统一插件体系中的各插槽驱动契约。
type PluginDriver interface {
	Slot() string
	Type() string
	Metadata() DriverMetadata
	ValidateConfig(cfg models.JSONMap) error
	HealthCheck(ctx context.Context, cfg models.JSONMap) error
}

// Manager 统一管理已注册插件驱动以及数据库中持久化的插件实例。
type Manager struct {
	db          *gorm.DB
	stateStore  *security.StateStore
	settingsSvc *settings.Service
	mu          sync.RWMutex
	drivers     map[string]PluginDriver
}

func NewManager(db *gorm.DB, stateStore *security.StateStore, settingsSvc *settings.Service) *Manager {
	m := &Manager{
		db:          db,
		stateStore:  stateStore,
		settingsSvc: settingsSvc,
		drivers:     make(map[string]PluginDriver),
	}
	m.Register(NewCapCaptchaDriver())
	m.Register(NewConsoleSMSDriver())
	m.Register(NewWebhookSMSDriver())
	m.Register(NewAliyunSMSDriver())
	m.Register(NewWebhookNotifyDriver())
	m.Register(NewLocalIPReputationRiskDriver())
	return m
}

func (m *Manager) Register(d PluginDriver) {
	if d == nil {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.drivers[d.Type()] = d
}

func (m *Manager) GetDriver(pluginType string) (PluginDriver, bool) {
	m.mu.RLock()
	defer m.mu.RUnlock()
	d, ok := m.drivers[pluginType]
	return d, ok
}

func (m *Manager) ListDrivers(slot string) []DriverMetadata {
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]DriverMetadata, 0, len(m.drivers))
	for _, d := range m.drivers {
		if slot == "" || d.Slot() == slot {
			out = append(out, d.Metadata())
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Slot != out[j].Slot {
			return out[i].Slot < out[j].Slot
		}
		return out[i].Type < out[j].Type
	})
	return out
}

// EnsureDefaults 幂等初始化默认插件插槽实例（默认禁用，供管理员一键开启或切换模式）。
func (m *Manager) EnsureDefaults() error {
	defaults := []models.PluginInstance{
		{
			Name:        "cap-default",
			Slot:        SlotCaptcha,
			PluginType:  "cap_captcha",
			DisplayName: "Cap 人机验证（trycap.dev）",
			Config: models.JSONMap{
				"mode":            "local",
				"challenge_count": "16",
				"difficulty":      "4",
				"remote_endpoint": "",
				"remote_secret":   "",
			},
			Enabled:      false,
			Priority:     10,
			HealthStatus: "healthy",
		},
		{
			Name:        "console-sms-default",
			Slot:        SlotSMS,
			PluginType:  "console_sms",
			DisplayName: "内置日志短信通道",
			Config: models.JSONMap{
				"sign_name": "OpenIAM",
			},
			Enabled:      false,
			Priority:     100,
			HealthStatus: "healthy",
		},
		{
			Name:         "ip-reputation-default",
			Slot:         SlotRisk,
			PluginType:   "ip_reputation_local",
			DisplayName:  "内置 IP 信誉与行为风控",
			Config:       models.JSONMap{"block_threshold": "10"},
			Enabled:      true,
			Priority:     10,
			HealthStatus: "healthy",
		},
	}
	for _, item := range defaults {
		var existing models.PluginInstance
		if err := m.db.Where("name = ?", item.Name).First(&existing).Error; err != nil {
			if errors.Is(err, gorm.ErrRecordNotFound) {
				if cerr := m.db.Create(&item).Error; cerr != nil {
					return cerr
				}
			}
		}
	}
	return nil
}

// SanitizeInstance 对外输出前移除密码类敏感配置字段，返回脱敏后的副本。
func (m *Manager) SanitizeInstance(inst models.PluginInstance) models.PluginInstance {
	drv, ok := m.GetDriver(inst.PluginType)
	if !ok || inst.Config == nil {
		return inst
	}
	secretFields := make(map[string]bool)
	for _, f := range drv.Metadata().Fields {
		if f.Type == "password" {
			secretFields[f.Key] = true
		}
	}
	clean := make(models.JSONMap, len(inst.Config)+1)
	for k, v := range inst.Config {
		if secretFields[k] {
			if s, ok2 := v.(string); ok2 && s != "" {
				clean[k] = ""
				clean["has_"+k] = true
			}
			continue
		}
		clean[k] = v
	}
	inst.Config = clean
	return inst
}

func (m *Manager) ListInstances(slot string) ([]models.PluginInstance, error) {
	q := m.db.Model(&models.PluginInstance{}).Order("slot ASC, priority ASC, id ASC")
	if slot != "" {
		q = q.Where("slot = ?", slot)
	}
	var rows []models.PluginInstance
	if err := q.Find(&rows).Error; err != nil {
		return nil, err
	}
	for i := range rows {
		rows[i] = m.SanitizeInstance(rows[i])
	}
	return rows, nil
}

func (m *Manager) ActiveBySlot(slot string) ([]models.PluginInstance, error) {
	var rows []models.PluginInstance
	err := m.db.Where("slot = ? AND enabled = ?", slot, true).Order("priority ASC, id ASC").Find(&rows).Error
	return rows, err
}

func (m *Manager) CreateInstance(inst *models.PluginInstance) error {
	drv, ok := m.GetDriver(inst.PluginType)
	if !ok {
		return fmt.Errorf("未知插件驱动类型: %s", inst.PluginType)
	}
	if inst.Slot != "" && inst.Slot != drv.Slot() {
		return fmt.Errorf("插件 %s 只能安装到 %s 插槽", inst.PluginType, drv.Slot())
	}
	inst.Slot = drv.Slot()
	if inst.Config == nil {
		inst.Config = models.JSONMap{}
	}
	if err := drv.ValidateConfig(inst.Config); err != nil {
		return err
	}
	return m.db.Create(inst).Error
}

func (m *Manager) UpdateInstance(id uint64, displayName string, cfg models.JSONMap, enabled *bool, priority *int) (*models.PluginInstance, error) {
	var inst models.PluginInstance
	if err := m.db.First(&inst, id).Error; err != nil {
		return nil, err
	}
	drv, ok := m.GetDriver(inst.PluginType)
	if !ok {
		return nil, fmt.Errorf("未知插件驱动: %s", inst.PluginType)
	}
	if displayName != "" {
		inst.DisplayName = strings.TrimSpace(displayName)
	}
	if priority != nil {
		inst.Priority = *priority
	}
	if enabled != nil {
		inst.Enabled = *enabled
	}
	if cfg != nil {
		merged := make(models.JSONMap, len(inst.Config)+len(cfg))
		for k, v := range inst.Config {
			merged[k] = v
		}
		secretKeys := make(map[string]bool)
		for _, f := range drv.Metadata().Fields {
			if f.Type == "password" {
				secretKeys[f.Key] = true
			}
		}
		for k, v := range cfg {
			if strings.HasPrefix(k, "has_") {
				continue
			}
			// 密码类字段留空则保留原值
			if secretKeys[k] {
				if s, ok2 := v.(string); ok2 && strings.TrimSpace(s) == "" {
					continue
				}
			}
			merged[k] = v
		}
		inst.Config = merged
	}
	if err := drv.ValidateConfig(inst.Config); err != nil {
		return nil, err
	}
	if err := m.db.Save(&inst).Error; err != nil {
		return nil, err
	}
	sanitized := m.SanitizeInstance(inst)
	return &sanitized, nil
}

func (m *Manager) TestInstance(ctx context.Context, id uint64) (string, error) {
	var inst models.PluginInstance
	if err := m.db.First(&inst, id).Error; err != nil {
		return "", err
	}
	drv, ok := m.GetDriver(inst.PluginType)
	if !ok {
		return "", fmt.Errorf("未知插件驱动: %s", inst.PluginType)
	}
	err := drv.HealthCheck(ctx, inst.Config)
	now := time.Now()
	status := "healthy"
	if err != nil {
		status = "unhealthy"
	}
	_ = m.db.Model(&inst).Updates(map[string]interface{}{
		"health_status":   status,
		"last_checked_at": &now,
	}).Error
	if err != nil {
		return status, err
	}
	return status, nil
}

func cfgStr(cfg models.JSONMap, key, fallback string) string {
	if cfg == nil {
		return fallback
	}
	v, ok := cfg[key]
	if !ok || v == nil {
		return fallback
	}
	switch t := v.(type) {
	case string:
		if strings.TrimSpace(t) == "" {
			return fallback
		}
		return strings.TrimSpace(t)
	default:
		return fmt.Sprintf("%v", t)
	}
}
